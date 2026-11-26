//! Periodic DNS resolution of hostname backends.
//!
//! For every `[[upstream]]` that has a `dns` table, each hostname backend is
//! looked up on its own schedule and the answer is handed to
//! [`SharedState::set_dns`], which expands the backend into one pool member per
//! address and rebuilds the snapshot. Everything that makes that safe lives
//! there (unchanged answers are free, survivors keep their identity and
//! in-flight requests); this module only decides *when* to look and *what to
//! trust*:
//!
//! * lookups run concurrently and never block each other or the data plane;
//! * a failed or empty answer keeps the last good one (and retries sooner than
//!   the normal interval), so a DNS outage cannot empty a pool;
//! * answers are sorted and capped at `max_addrs`, so every Velox instance picks
//!   the same members from an oversized record set.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use velox_core::SharedState;
use velox_telemetry::Metrics;

/// Retry delay after a failed or empty lookup (capped by the refresh interval).
const RETRY: Duration = Duration::from_secs(5);

/// Looks up the addresses of a host name.
pub trait Resolver: Send + Sync + 'static {
    /// Resolve `host` (port included for resolvers that care) to its addresses.
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>>;
}

/// The operating system's resolver (`getaddrinfo` on Tokio's blocking pool).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>> {
        Box::pin(async move { Ok(tokio::net::lookup_host((host, port)).await?.map(|sa| sa.ip()).collect()) })
    }
}

struct Outcome {
    key: (String, String),
    upstream: String,
    result: Result<Vec<IpAddr>, String>,
    interval: Duration,
    max_addrs: usize,
    ipv6: bool,
}

/// Re-resolves hostname backends on their configured interval.
pub struct DnsRefresher {
    state: Arc<SharedState>,
    resolver: Arc<dyn Resolver>,
    metrics: Option<Arc<Metrics>>,
    cancel: CancellationToken,
}

impl std::fmt::Debug for DnsRefresher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsRefresher").finish_non_exhaustive()
    }
}

impl DnsRefresher {
    /// A refresher using the system resolver; it stops when `cancel` fires.
    pub fn new(state: Arc<SharedState>, cancel: CancellationToken) -> Self {
        Self { state, resolver: Arc::new(SystemResolver), metrics: None, cancel }
    }

    /// Use a different resolver (tests, or a custom discovery backend).
    #[must_use]
    pub fn with_resolver(mut self, resolver: Arc<dyn Resolver>) -> Self {
        self.resolver = resolver;
        self
    }

    /// Report lookups and changes to `metrics`.
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Spawn on the current runtime.
    pub fn spawn(self) -> JoinHandle<()> {
        tokio::spawn(self.run())
    }

    async fn run(self) {
        let (tx, mut rx) = mpsc::unbounded_channel::<Outcome>();
        let mut due: HashMap<(String, String), Instant> = HashMap::new();
        let mut running: HashSet<(String, String)> = HashSet::new();
        let mut tick = tokio::time::interval(Duration::from_millis(200));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = self.cancel.cancelled() => return,
                _ = tick.tick() => self.schedule(&tx, &mut due, &mut running),
                Some(done) = rx.recv() => self.finish(done, &mut due, &mut running),
            }
        }
    }

    /// Start a lookup for every hostname backend that is due.
    fn schedule(
        &self,
        tx: &mpsc::UnboundedSender<Outcome>,
        due: &mut HashMap<(String, String), Instant>,
        running: &mut HashSet<(String, String)>,
    ) {
        let snap = self.state.load();
        let now = Instant::now();
        let mut live = HashSet::new();
        for u in &snap.config.upstreams {
            let Some(dns) = &u.dns else { continue };
            for b in &u.backends {
                let Some(host) = b.addr.hostname() else { continue };
                let key = (u.name.clone(), b.addr.to_string());
                live.insert(key.clone());
                if running.contains(&key) || due.get(&key).is_some_and(|t| *t > now) {
                    continue;
                }
                let port = match &b.addr {
                    velox_core::config::BackendAddr::Tcp { port, .. }
                    | velox_core::config::BackendAddr::Tls { port, .. } => *port,
                    velox_core::config::BackendAddr::Unix(_) => continue,
                };
                running.insert(key.clone());
                let (resolver, tx, host) = (Arc::clone(&self.resolver), tx.clone(), host.to_owned());
                let (upstream, interval, max_addrs, ipv6, timeout) =
                    (u.name.clone(), dns.refresh_interval, dns.max_addrs, dns.ipv6, dns.timeout);
                tokio::spawn(async move {
                    let result = match tokio::time::timeout(timeout, resolver.resolve(&host, port)).await {
                        Ok(Ok(ips)) => Ok(ips),
                        Ok(Err(e)) => Err(e.to_string()),
                        Err(_) => Err("lookup timed out".to_owned()),
                    };
                    let _ = tx.send(Outcome { key, upstream, result, interval, max_addrs, ipv6 });
                });
            }
        }
        // Forget schedules of backends that left the configuration.
        due.retain(|k, _| live.contains(k));
    }

    fn finish(
        &self,
        done: Outcome,
        due: &mut HashMap<(String, String), Instant>,
        running: &mut HashSet<(String, String)>,
    ) {
        running.remove(&done.key);
        let count = |result: &str| {
            if let Some(m) = &self.metrics {
                m.dns_resolution(&done.upstream, result);
            }
        };
        let retry = done.interval.min(RETRY);
        let next = |delay: Duration| Instant::now() + delay;
        let mut ips = match done.result {
            Ok(ips) => ips,
            Err(e) => {
                count("error");
                tracing::warn!(upstream = %done.upstream, backend = %done.key.1, error = %e, "DNS lookup failed; keeping the previous answer");
                due.insert(done.key, next(retry));
                return;
            }
        };
        if !done.ipv6 {
            ips.retain(IpAddr::is_ipv4);
        }
        ips.sort_unstable();
        ips.dedup();
        ips.truncate(done.max_addrs);
        if ips.is_empty() {
            count("empty");
            tracing::warn!(upstream = %done.upstream, backend = %done.key.1, "DNS lookup returned no usable addresses; keeping the previous answer");
            due.insert(done.key, next(retry));
            return;
        }
        count("ok");
        match self.state.set_dns(&done.upstream, &done.key.1, ips) {
            Ok(Some(snap)) => {
                if let Some(m) = &self.metrics {
                    m.dns_changed(&done.upstream);
                }
                let members = snap.upstreams.get(&done.upstream).map_or(0, |g| g.backends.len());
                tracing::info!(upstream = %done.upstream, backend = %done.key.1, members, "DNS answer changed; pool updated");
            }
            Ok(None) => {}
            Err(e) => tracing::error!(upstream = %done.upstream, error = %e, "could not apply DNS answer"),
        }
        due.insert(done.key, next(done.interval));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use velox_core::Config;

    /// A resolver whose answers the test scripts.
    #[derive(Default)]
    struct Script {
        answers: Mutex<HashMap<String, io::Result<Vec<IpAddr>>>>,
        calls: Mutex<Vec<String>>,
        delay: Mutex<Option<Duration>>,
    }

    impl Script {
        fn set(&self, host: &str, ips: &[&str]) {
            self.answers.lock().unwrap().insert(host.to_owned(), Ok(ips.iter().map(|s| s.parse().unwrap()).collect()));
        }
        fn fail(&self, host: &str) {
            self.answers.lock().unwrap().insert(host.to_owned(), Err(io::Error::other("SERVFAIL")));
        }
        fn calls(&self, host: &str) -> usize {
            self.calls.lock().unwrap().iter().filter(|h| *h == host).count()
        }
    }

    impl Resolver for Script {
        fn resolve<'a>(
            &'a self,
            host: &'a str,
            _port: u16,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(host.to_owned());
                let delay = *self.delay.lock().unwrap();
                if let Some(d) = delay {
                    tokio::time::sleep(d).await;
                }
                match self.answers.lock().unwrap().get(host) {
                    Some(Ok(v)) => Ok(v.clone()),
                    Some(Err(e)) => Err(io::Error::new(e.kind(), e.to_string())),
                    None => Err(io::Error::new(io::ErrorKind::NotFound, "NXDOMAIN")),
                }
            })
        }
    }

    fn state(dns: &str) -> Arc<SharedState> {
        SharedState::new(
            Config::from_toml_str(&format!(
                "[server]\nhttp_addr = \"127.0.0.1:1\"\n[[upstream]]\nname = \"app\"\ndns = {dns}\n\
                 backends = [{{ addr = \"svc.internal:8080\" }}, {{ addr = \"10.9.9.9:80\" }}]\n[[route]]\nupstream = \"app\"\n"
            ))
            .unwrap(),
        )
        .unwrap()
    }

    fn members(s: &SharedState) -> Vec<String> {
        s.load().upstreams["app"].backends.iter().map(|b| b.name.to_string()).collect()
    }

    async fn until(what: &str, mut f: impl FnMut() -> bool) {
        for _ in 0..400 {
            if f() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for {what}");
    }

    #[tokio::test]
    async fn expands_updates_and_keeps_survivors_across_refreshes() {
        let s = state("{ refresh_interval = \"1s\" }");
        let script = Arc::new(Script::default());
        script.set("svc.internal", &["10.0.0.2", "10.0.0.1"]);
        let metrics = Arc::new(Metrics::new().unwrap());
        let cancel = CancellationToken::new();
        let task = DnsRefresher::new(Arc::clone(&s), cancel.clone())
            .with_resolver(script.clone())
            .with_metrics(Arc::clone(&metrics))
            .spawn();

        until("first answer applied", || members(&s).len() == 3).await;
        assert_eq!(members(&s), ["10.0.0.1:8080", "10.0.0.2:8080", "10.9.9.9:80"]);
        let survivor = Arc::clone(&s.load().upstreams["app"].backends[0]);
        survivor.set_draining(true);
        let _inflight = survivor.track();
        let gen = s.load().generation;

        // Same answer on the next refresh: no churn. Literal backends are never looked up.
        until("a second lookup", || script.calls("svc.internal") >= 2).await;
        assert_eq!(s.load().generation, gen, "unchanged DNS does not rebuild the snapshot");
        assert_eq!(script.calls("10.9.9.9"), 0);

        // Scale up, then down: members follow, survivors keep their state.
        script.set("svc.internal", &["10.0.0.1", "10.0.0.3", "10.0.0.4"]);
        until("scale-out applied", || members(&s).contains(&"10.0.0.4:8080".to_owned())).await;
        assert_eq!(members(&s), ["10.0.0.1:8080", "10.0.0.3:8080", "10.0.0.4:8080", "10.9.9.9:80"]);
        let now = &s.load().upstreams["app"].backends[0];
        assert!(Arc::ptr_eq(&survivor, now) && now.is_draining() && now.active() == 1);

        let text = metrics.render().unwrap();
        assert!(text.contains("velox_dns_resolutions_total{result=\"ok\",upstream=\"app\"}"), "{text}");
        assert!(text.contains("velox_dns_changes_total{upstream=\"app\"} 2"), "{text}");
        cancel.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn failures_and_empty_answers_keep_the_last_good_pool() {
        let s = state("{ refresh_interval = \"1s\" }");
        let script = Arc::new(Script::default());
        script.set("svc.internal", &["10.0.0.1"]);
        let metrics = Arc::new(Metrics::new().unwrap());
        let cancel = CancellationToken::new();
        let task = DnsRefresher::new(Arc::clone(&s), cancel.clone())
            .with_resolver(script.clone())
            .with_metrics(Arc::clone(&metrics))
            .spawn();
        until("initial answer", || members(&s)[0] == "10.0.0.1:8080").await;
        let gen = s.load().generation;

        script.fail("svc.internal");
        until("a failed lookup", || metrics.render().unwrap().contains("result=\"error\"")).await;
        script.set("svc.internal", &[]);
        until("an empty lookup", || metrics.render().unwrap().contains("result=\"empty\"")).await;
        assert_eq!(members(&s), ["10.0.0.1:8080", "10.9.9.9:80"], "a DNS outage never empties the pool");
        assert_eq!(s.load().generation, gen);

        // Recovery is picked up on the (shorter) retry schedule.
        script.set("svc.internal", &["10.0.0.7"]);
        until("recovery", || members(&s)[0] == "10.0.0.7:8080").await;
        cancel.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn answers_are_filtered_sorted_and_capped_deterministically() {
        let s = state("{ refresh_interval = \"1s\", max_addrs = 2, ipv6 = false }");
        let script = Arc::new(Script::default());
        script.set("svc.internal", &["10.0.0.9", "2001:db8::1", "10.0.0.3", "10.0.0.3", "10.0.0.5"]);
        let cancel = CancellationToken::new();
        let task = DnsRefresher::new(Arc::clone(&s), cancel.clone()).with_resolver(script).spawn();
        until("answer applied", || members(&s).len() == 3).await;
        assert_eq!(members(&s), ["10.0.0.3:8080", "10.0.0.5:8080", "10.9.9.9:80"], "IPv6 dropped, lowest two kept");
        cancel.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn a_slow_lookup_neither_blocks_others_nor_piles_up() {
        let s = SharedState::new(
            Config::from_toml_str(
                "[server]\nhttp_addr = \"127.0.0.1:1\"\n[[upstream]]\nname = \"app\"\ndns = { refresh_interval = \"1s\", timeout = \"300ms\" }\n\
                 backends = [{ addr = \"slow.internal:80\" }, { addr = \"fast.internal:80\" }]\n[[route]]\nupstream = \"app\"\n",
            )
            .unwrap(),
        )
        .unwrap();
        let script = Arc::new(Script::default());
        script.set("fast.internal", &["10.1.1.1"]);
        script.set("slow.internal", &["10.2.2.2"]);
        *script.delay.lock().unwrap() = Some(Duration::from_secs(30)); // every lookup would hang…
        let cancel = CancellationToken::new();
        let task = DnsRefresher::new(Arc::clone(&s), cancel.clone()).with_resolver(script.clone()).spawn();
        tokio::time::sleep(Duration::from_millis(1200)).await;
        // …and times out instead of wedging: the pool is untouched, and each host was
        // asked once per attempt, never in parallel with itself.
        assert_eq!(members(&s), ["slow.internal:80", "fast.internal:80"]);
        assert!(script.calls("slow.internal") <= 3, "{}", script.calls("slow.internal"));
        cancel.cancel();
        task.await.unwrap();
    }
}
