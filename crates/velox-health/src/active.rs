//! Active health checking.
//!
//! A supervisor reconciles the set of per-backend probe tasks with the live
//! configuration every second, so added/removed backends and changed probe
//! settings take effect without a restart. Each task probes with
//! `interval ± jitter` and flips the backend's health only after
//! `unhealthy_threshold` consecutive failures or `healthy_threshold`
//! consecutive successes (hysteresis prevents flapping).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use velox_core::config::{BackendAddr, HealthConfig, HealthKind};
use velox_core::{Backend, SharedState};

/// Why a probe failed.
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    /// Connect or I/O error.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// The probe exceeded its deadline.
    #[error("probe timed out")]
    Timeout,
    /// The response was not parseable HTTP.
    #[error("malformed HTTP response")]
    Malformed,
    /// Status outside the accepted range.
    #[error("unexpected status {0}")]
    Status(u16),
}

/// Supervises background probe tasks.
#[derive(Debug)]
pub struct HealthChecker {
    state: Arc<SharedState>,
    cancel: CancellationToken,
}

type TaskKey = (String, String);

impl HealthChecker {
    /// Create a checker over `state`; tasks stop when `cancel` fires.
    pub fn new(state: Arc<SharedState>, cancel: CancellationToken) -> Self {
        Self { state, cancel }
    }

    /// Spawn the supervisor on the current runtime.
    pub fn spawn(self) -> JoinHandle<()> {
        tokio::spawn(self.supervise())
    }

    async fn supervise(self) {
        let mut tasks: HashMap<TaskKey, (std::sync::Weak<Backend>, JoinHandle<()>)> = HashMap::new();
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = self.cancel.cancelled() => break,
                _ = tick.tick() => {}
            }
            let snap = self.state.load();
            let mut live: HashMap<TaskKey, Arc<Backend>> = HashMap::new();
            for group in snap.upstreams.values() {
                if group.config.health.is_none() {
                    continue;
                }
                for b in &group.backends {
                    live.insert((group.name.to_string(), b.name.to_string()), Arc::clone(b));
                }
            }
            tasks.retain(|key, (weak, handle)| {
                let keep = live.get(key).is_some_and(|b| weak.upgrade().is_some_and(|w| Arc::ptr_eq(&w, b)));
                if !keep {
                    handle.abort();
                }
                keep && !handle.is_finished()
            });
            for (key, backend) in live {
                if tasks.contains_key(&key) {
                    continue;
                }
                let weak = Arc::downgrade(&backend);
                let handle =
                    tokio::spawn(probe_loop(Arc::clone(&self.state), key.0.clone(), backend, self.cancel.clone()));
                tasks.insert(key, (weak, handle));
            }
        }
        for (_, (_, h)) in tasks {
            h.abort();
        }
    }
}

async fn probe_loop(state: Arc<SharedState>, upstream: String, backend: Arc<Backend>, cancel: CancellationToken) {
    let mut ok_streak = 0u32;
    let mut fail_streak = 0u32;
    loop {
        // Re-read the settings every cycle so reloads apply immediately.
        let snap = state.load();
        let Some(group) = snap.upstreams.get(&upstream) else { return };
        let Some(cfg) = group.config.health.clone() else { return };
        if !group.backends.iter().any(|b| Arc::ptr_eq(b, &backend)) {
            return;
        }
        drop(snap);

        let result = probe(&backend.addr, &cfg).await;
        match &result {
            Ok(()) => {
                ok_streak += 1;
                fail_streak = 0;
                if !backend.is_healthy() && ok_streak >= cfg.healthy_threshold {
                    backend.set_healthy(true);
                    // A passing active probe is stronger evidence than the
                    // failures that triggered passive ejection: end it now
                    // instead of idling recovered capacity for the full window.
                    backend.clear_ejection();
                    tracing::info!(upstream = %upstream, backend = &*backend.name, "backend is healthy again");
                }
            }
            Err(e) => {
                fail_streak += 1;
                ok_streak = 0;
                if backend.is_healthy() && fail_streak >= cfg.unhealthy_threshold {
                    backend.set_healthy(false);
                    tracing::warn!(upstream = %upstream, backend = &*backend.name, error = %e, "backend marked unhealthy");
                }
            }
        }
        let sleep = jittered(cfg.interval, cfg.jitter);
        tokio::select! {
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(sleep) => {}
        }
    }
}

/// `interval` scaled by a random factor in `[1 - jitter, 1 + jitter]`.
pub fn jittered(interval: Duration, jitter: f64) -> Duration {
    let jitter = jitter.clamp(0.0, 1.0);
    let factor = 1.0 + jitter * (fastrand::f64() * 2.0 - 1.0);
    interval.mul_f64(factor.max(0.0))
}

/// Run a single probe against `addr` according to `cfg`.
pub async fn probe(addr: &BackendAddr, cfg: &HealthConfig) -> Result<(), ProbeError> {
    tokio::time::timeout(cfg.timeout, probe_inner(addr, cfg)).await.map_err(|_| ProbeError::Timeout)?
}

async fn probe_inner(addr: &BackendAddr, cfg: &HealthConfig) -> Result<(), ProbeError> {
    match addr {
        BackendAddr::Tcp { host, port } => {
            let stream = TcpStream::connect((BackendAddr::connect_host(host), *port)).await?;
            match cfg.kind {
                HealthKind::Tcp => Ok(()),
                HealthKind::Http => http_probe(stream, cfg).await,
            }
        }
        BackendAddr::Unix(path) => {
            let stream = UnixStream::connect(path).await?;
            match cfg.kind {
                HealthKind::Tcp => Ok(()),
                HealthKind::Http => http_probe(stream, cfg).await,
            }
        }
    }
}

async fn http_probe<S>(mut stream: S, cfg: &HealthConfig) -> Result<(), ProbeError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: velox-health/1\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        cfg.path, cfg.host
    );
    stream.write_all(req.as_bytes()).await?;
    // Only the status line matters; never read an unbounded body.
    let mut buf = [0u8; 256];
    let mut filled = 0;
    while filled < buf.len() && !buf[..filled].contains(&b'\n') {
        let n = stream.read(&mut buf[filled..]).await?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    let line = std::str::from_utf8(&buf[..filled]).map_err(|_| ProbeError::Malformed)?;
    let status_line = line.lines().next().ok_or(ProbeError::Malformed)?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().ok_or(ProbeError::Malformed)?;
    if !version.starts_with("HTTP/1.") {
        return Err(ProbeError::Malformed);
    }
    let status: u16 = parts.next().and_then(|s| s.parse().ok()).ok_or(ProbeError::Malformed)?;
    if (cfg.status_min..=cfg.status_max).contains(&status) {
        Ok(())
    } else {
        Err(ProbeError::Status(status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU16, Ordering};
    use tokio::net::TcpListener;
    use velox_core::Config;

    /// A tiny server whose status code can be flipped at runtime.
    async fn mock(status: Arc<AtomicU16>) -> std::net::SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else { return };
                let status = status.load(Ordering::Relaxed);
                tokio::spawn(async move {
                    let mut b = [0u8; 512];
                    let _ = s.read(&mut b).await;
                    let _ = s
                        .write_all(
                            format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes(),
                        )
                        .await;
                });
            }
        });
        addr
    }

    fn cfg(addr: std::net::SocketAddr, health: &str) -> Config {
        Config::from_toml_str(&format!(
            "[server]\nhttp_addr = \"127.0.0.1:1\"\n[[upstream]]\nname = \"a\"\nbackends = [{{ addr = \"{addr}\" }}]\n[upstream.health]\n{health}"
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn http_probe_accepts_and_rejects_by_status() {
        let status = Arc::new(AtomicU16::new(200));
        let addr = mock(Arc::clone(&status)).await;
        let a = BackendAddr::Tcp { host: "127.0.0.1".into(), port: addr.port() };
        let c = HealthConfig { path: "/h".into(), ..HealthConfig::default() };
        assert!(probe(&a, &c).await.is_ok());
        status.store(503, Ordering::Relaxed);
        assert!(matches!(probe(&a, &c).await, Err(ProbeError::Status(503))));
    }

    #[tokio::test]
    async fn tcp_probe_and_dead_port() {
        let status = Arc::new(AtomicU16::new(500));
        let addr = mock(status).await;
        let a = BackendAddr::Tcp { host: "127.0.0.1".into(), port: addr.port() };
        let tcp = HealthConfig { kind: HealthKind::Tcp, ..HealthConfig::default() };
        assert!(probe(&a, &tcp).await.is_ok(), "tcp probe ignores HTTP status");
        let dead = BackendAddr::Tcp { host: "127.0.0.1".into(), port: 1 };
        assert!(probe(&dead, &tcp).await.is_err());
    }

    #[tokio::test]
    async fn hung_backend_times_out() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _held = l.accept().await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let a = BackendAddr::Tcp { host: "127.0.0.1".into(), port };
        let c = HealthConfig { timeout: Duration::from_millis(100), ..HealthConfig::default() };
        assert!(matches!(probe(&a, &c).await, Err(ProbeError::Timeout)));
    }

    #[test]
    fn jitter_stays_within_bounds() {
        for _ in 0..1000 {
            let d = jittered(Duration::from_secs(10), 0.2);
            assert!(d >= Duration::from_secs(8) && d <= Duration::from_secs(12), "{d:?}");
        }
        assert_eq!(jittered(Duration::from_secs(5), 0.0), Duration::from_secs(5));
    }

    #[tokio::test]
    async fn checker_marks_down_then_recovers_with_hysteresis() {
        let status = Arc::new(AtomicU16::new(200));
        let addr = mock(Arc::clone(&status)).await;
        let state = SharedState::new(cfg(
            addr,
            "interval = \"50ms\"\ntimeout = \"200ms\"\njitter = 0.0\nhealthy_threshold = 2\nunhealthy_threshold = 2\npath = \"/h\"\n",
        ))
        .unwrap();
        let cancel = CancellationToken::new();
        let handle = HealthChecker::new(Arc::clone(&state), cancel.clone()).spawn();
        let backend = Arc::clone(&state.load().upstreams["a"].backends[0]);

        status.store(503, Ordering::Relaxed);
        wait_until(|| !backend.is_healthy()).await;
        status.store(200, Ordering::Relaxed);
        wait_until(|| backend.is_healthy()).await;

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn recovery_clears_passive_ejection() {
        let status = Arc::new(AtomicU16::new(200));
        let addr = mock(Arc::clone(&status)).await;
        let state = SharedState::new(cfg(
            addr,
            "interval = \"50ms\"\ntimeout = \"200ms\"\njitter = 0.0\nhealthy_threshold = 1\nunhealthy_threshold = 1\n",
        ))
        .unwrap();
        let backend = Arc::clone(&state.load().upstreams["a"].backends[0]);
        // Failed health (e.g. while down) *and* passively ejected for a long time.
        backend.set_healthy(false);
        backend.eject_until(velox_core::clock::now_ms() + 600_000);
        let cancel = CancellationToken::new();
        let handle = HealthChecker::new(Arc::clone(&state), cancel.clone()).spawn();
        wait_until(|| backend.is_available()).await;
        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn checker_follows_config_reloads() {
        let status = Arc::new(AtomicU16::new(503));
        let addr = mock(Arc::clone(&status)).await;
        let fast =
            "interval = \"50ms\"\ntimeout = \"200ms\"\njitter = 0.0\nunhealthy_threshold = 1\nhealthy_threshold = 1\n";
        let state = SharedState::new(cfg(addr, fast)).unwrap();
        let cancel = CancellationToken::new();
        let handle = HealthChecker::new(Arc::clone(&state), cancel.clone()).spawn();
        let backend = Arc::clone(&state.load().upstreams["a"].backends[0]);
        wait_until(|| !backend.is_healthy()).await;

        // Reload with the same backend: identity (and its state) is preserved
        // and probing continues against it.
        state.apply(cfg(addr, fast)).unwrap();
        status.store(200, Ordering::Relaxed);
        wait_until(|| backend.is_healthy()).await;

        // Removing health checks stops probing: a manual flip is not undone.
        let mut no_health = (*state.load().config).clone();
        no_health.upstreams[0].health = None;
        state.apply(no_health).unwrap();
        tokio::time::sleep(Duration::from_millis(700)).await;
        backend.set_healthy(false);
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(!backend.is_healthy());

        cancel.cancel();
        handle.await.unwrap();
    }

    async fn wait_until(mut f: impl FnMut() -> bool) {
        for _ in 0..200 {
            if f() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("condition not reached in time");
    }
}
