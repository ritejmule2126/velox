//! Lock-free, atomically swappable runtime state.

use crate::config::Config;
use crate::error::ConfigError;
use crate::router::{Route, Router};
use crate::upstream::{DnsTable, UpstreamGroup};
use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

/// An immutable, fully built view of the configuration.
///
/// Requests load one `Arc<Snapshot>` and use it for their whole lifetime, so a
/// reload can never be observed half-applied and never disturbs in-flight work.
#[derive(Debug)]
pub struct Snapshot {
    /// Monotonic version, incremented on every successful swap.
    pub generation: u64,
    /// The source configuration.
    pub config: Arc<Config>,
    /// Compiled routing table.
    pub router: Router,
    /// Upstream pools by name.
    pub upstreams: HashMap<String, Arc<UpstreamGroup>>,
}

impl Snapshot {
    /// Validate `config` and build a snapshot, carrying over runtime state
    /// (health, drain flags, in-flight counters) of unchanged backends.
    pub fn build(config: Config, prev: Option<&Snapshot>, generation: u64) -> Result<Self, ConfigError> {
        Self::build_with_dns(config, prev, generation, &DnsTable::new())
    }

    /// [`Snapshot::build`] with resolved DNS answers for hostname backends.
    pub fn build_with_dns(
        config: Config,
        prev: Option<&Snapshot>,
        generation: u64,
        dns: &DnsTable,
    ) -> Result<Self, ConfigError> {
        config.validate()?;
        let upstreams: HashMap<String, Arc<UpstreamGroup>> = config
            .upstreams
            .iter()
            .map(|u| {
                let old = prev.and_then(|p| p.upstreams.get(&u.name)).map(AsRef::as_ref);
                (u.name.clone(), Arc::new(UpstreamGroup::build_with_dns(u, old, dns)))
            })
            .collect();
        let mut entries = Vec::with_capacity(config.routes.len());
        for (i, rc) in config.routes.iter().enumerate() {
            let group = upstreams
                .get(&rc.upstream)
                .cloned()
                .ok_or_else(|| ConfigError::Invalid(vec![format!("route {i}: unknown upstream `{}`", rc.upstream)]))?;
            let route = Route::compile(config.route_id(i), rc, config.rate_limit.as_ref(), group);
            entries.push((rc.hosts.clone(), Arc::new(route)));
        }
        Ok(Self { generation, router: Router::build(entries), upstreams, config: Arc::new(config) })
    }
}

/// Shared handle to the live [`Snapshot`].
#[derive(Debug)]
pub struct SharedState {
    current: ArcSwap<Snapshot>,
    dns: ArcSwap<DnsTable>,
    generation: AtomicU64,
    writer: Mutex<()>,
}

impl SharedState {
    /// Build the initial state from `config`.
    pub fn new(config: Config) -> Result<Arc<Self>, ConfigError> {
        let snap = Snapshot::build(config, None, 1)?;
        Ok(Arc::new(Self {
            current: ArcSwap::from_pointee(snap),
            dns: ArcSwap::from_pointee(DnsTable::new()),
            generation: AtomicU64::new(1),
            writer: Mutex::new(()),
        }))
    }

    /// The current snapshot (one atomic reference-count bump).
    pub fn load(&self) -> Arc<Snapshot> {
        self.current.load_full()
    }

    /// Validate and atomically install a new configuration.
    ///
    /// On error the previous snapshot stays live.
    pub fn apply(&self, config: Config) -> Result<Arc<Snapshot>, ConfigError> {
        self.update(|c| *c = config)
    }

    /// Read-modify-write the configuration under a writer lock.
    ///
    /// The closure edits a clone of the live config; the result is validated,
    /// built (reusing backend runtime state) and swapped in.
    pub fn update<F>(&self, edit: F) -> Result<Arc<Snapshot>, ConfigError>
    where
        F: FnOnce(&mut Config),
    {
        self.try_update(|c| {
            edit(c);
            Ok::<(), ConfigError>(())
        })
    }

    /// Like [`SharedState::update`] but the edit itself may fail (for example
    /// "no such route"); nothing is swapped in that case.
    pub fn try_update<F, E>(&self, edit: F) -> Result<Arc<Snapshot>, E>
    where
        F: FnOnce(&mut Config) -> Result<(), E>,
        E: From<ConfigError>,
    {
        let _guard = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let prev = self.current.load_full();
        let mut cfg = (*prev.config).clone();
        edit(&mut cfg)?;
        let generation = self.generation.load(Ordering::Relaxed) + 1;
        let snap = Arc::new(Snapshot::build_with_dns(cfg, Some(&prev), generation, &self.dns.load())?);
        self.generation.store(generation, Ordering::Relaxed);
        self.current.store(Arc::clone(&snap));
        Ok(snap)
    }

    /// The resolved DNS answers currently in effect.
    pub fn dns(&self) -> Arc<DnsTable> {
        self.dns.load_full()
    }

    /// Record a fresh DNS answer for backend `addr` of `upstream` and rebuild the
    /// snapshot so the pool reflects it.
    ///
    /// Returns `Ok(None)` (and does nothing) if the answer is unchanged. Members
    /// whose address survives keep their identity — health, ejection, drain flag
    /// and in-flight requests — exactly as across a configuration reload, and
    /// requests already running on a retired member simply finish.
    pub fn set_dns(
        &self,
        upstream: &str,
        addr: &str,
        mut ips: Vec<std::net::IpAddr>,
    ) -> Result<Option<Arc<Snapshot>>, ConfigError> {
        ips.sort_unstable();
        ips.dedup();
        let _guard = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let key = (upstream.to_owned(), addr.to_owned());
        let old = self.dns.load_full();
        if old.get(&key).is_some_and(|cur| **cur == *ips) {
            return Ok(None);
        }
        let prev = self.current.load_full();
        // Drop answers for backends the live config no longer has.
        let mut table: DnsTable = old
            .iter()
            .filter(|((u, a), _)| {
                prev.config
                    .upstreams
                    .iter()
                    .any(|g| g.name == *u && g.backends.iter().any(|b| b.addr.to_string() == *a))
            })
            .map(|(k, v)| (k.clone(), Arc::clone(v)))
            .collect();
        table.insert(key, Arc::from(ips));
        let generation = self.generation.load(Ordering::Relaxed) + 1;
        let snap = Arc::new(Snapshot::build_with_dns((*prev.config).clone(), Some(&prev), generation, &table)?);
        self.generation.store(generation, Ordering::Relaxed);
        self.dns.store(Arc::new(table));
        self.current.store(Arc::clone(&snap));
        Ok(Some(snap))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(backend_port: u16) -> Config {
        Config::from_toml_str(&format!(
            r#"
            [server]
            http_addr = "127.0.0.1:8080"
            [[upstream]]
            name = "app"
            backends = [{{ addr = "127.0.0.1:{backend_port}" }}, {{ addr = "127.0.0.1:9" }}]
            [[route]]
            upstream = "app"
        "#
        ))
        .unwrap()
    }

    #[test]
    fn apply_swaps_atomically_and_bumps_generation() {
        let s = SharedState::new(cfg(1)).unwrap();
        let before = s.load();
        let after = s.apply(cfg(2)).unwrap();
        assert_eq!(after.generation, before.generation + 1);
        assert_eq!(s.load().generation, after.generation);
        // Old readers keep a consistent view.
        assert_eq!(before.upstreams["app"].backends[0].name.as_ref(), "127.0.0.1:1");
    }

    #[test]
    fn invalid_config_leaves_state_untouched() {
        let s = SharedState::new(cfg(1)).unwrap();
        let mut bad = cfg(2);
        bad.routes[0].upstream = "missing".into();
        assert!(s.apply(bad).is_err());
        assert_eq!(s.load().generation, 1);
    }

    #[test]
    fn runtime_state_survives_reload_for_unchanged_backends() {
        let s = SharedState::new(cfg(1)).unwrap();
        let b = Arc::clone(&s.load().upstreams["app"].backends[1]);
        b.set_draining(true);
        let _inflight = b.track();
        s.apply(cfg(2)).unwrap();
        let after = s.load();
        let same = &after.upstreams["app"].backends[1];
        assert!(Arc::ptr_eq(&b, same), "unchanged backend keeps identity");
        assert!(same.is_draining());
        assert_eq!(same.active(), 1);
        assert!(!Arc::ptr_eq(&b, &after.upstreams["app"].backends[0]));
    }

    #[test]
    fn update_closure_is_validated() {
        let s = SharedState::new(cfg(1)).unwrap();
        assert!(s.update(|c| c.routes.clear()).is_ok());
        assert!(s.update(|c| c.upstreams.clear()).is_ok());
        assert!(s.update(|c| c.server.http_addr = None).is_err());
    }

    #[test]
    fn try_update_propagates_edit_errors_without_swapping() {
        let s = SharedState::new(cfg(1)).unwrap();
        let r = s.try_update(|_| Err(ConfigError::Invalid(vec!["nope".into()])));
        assert!(matches!(r, Err(ConfigError::Invalid(ref m)) if m[0] == "nope"));
        assert_eq!(s.load().generation, 1);
        let r = s.try_update(|c| {
            c.routes.clear();
            Ok::<(), ConfigError>(())
        });
        assert!(r.is_ok());
        assert_eq!(s.load().generation, 2);
    }

    #[test]
    fn concurrent_readers_never_see_torn_state() {
        let s = SharedState::new(cfg(1)).unwrap();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let readers: Vec<_> = (0..4)
            .map(|_| {
                let s = Arc::clone(&s);
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        let snap = s.load();
                        let route = snap.router.find("h", "/").unwrap();
                        assert!(snap.upstreams.contains_key(&*route.upstream.name));
                    }
                })
            })
            .collect();
        for i in 0..200u16 {
            s.apply(cfg(1000 + i)).unwrap();
        }
        stop.store(true, Ordering::Relaxed);
        for r in readers {
            r.join().unwrap();
        }
    }

    // ---- DNS expansion ----

    fn dns_cfg(extra_upstream: &str, backends: &str) -> Config {
        Config::from_toml_str(&format!(
            r#"
            [server]
            http_addr = "127.0.0.1:8080"
            [[upstream]]
            name = "app"
            max_inflight = 7
            {extra_upstream}
            backends = [{backends}]
            [[route]]
            upstream = "app"
        "#
        ))
        .unwrap()
    }

    fn names(s: &SharedState) -> Vec<String> {
        s.load().upstreams["app"].backends.iter().map(|b| b.name.to_string()).collect()
    }

    fn ips(list: &[&str]) -> Vec<std::net::IpAddr> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn hostname_backends_expand_to_one_member_per_resolved_address() {
        let s = SharedState::new(dns_cfg(
            "dns = {}",
            r#"{ addr = "svc.internal:8080", weight = 3, max_inflight = 2 }, { addr = "10.9.9.9:80" }"#,
        ))
        .unwrap();
        // Before the first answer: the single hostname member, resolved by the OS per connection.
        assert_eq!(names(&s), ["svc.internal:8080", "10.9.9.9:80"]);
        let gen0 = s.load().generation;

        let snap = s
            .set_dns("app", "svc.internal:8080", ips(&["10.0.0.2", "10.0.0.1", "2001:db8::5", "10.0.0.1"]))
            .unwrap()
            .unwrap();
        assert_eq!(snap.generation, gen0 + 1);
        // Sorted and de-duplicated; literals are left alone; IPv6 is bracketed.
        assert_eq!(names(&s), ["10.0.0.1:8080", "10.0.0.2:8080", "[2001:db8::5]:8080", "10.9.9.9:80"]);
        let g = s.load().upstreams["app"].clone();
        for b in &g.backends[..3] {
            assert_eq!(
                (b.weight, b.max_inflight(), b.sni.as_deref()),
                (3, Some(2), Some("svc.internal")),
                "{}",
                b.name
            );
        }
        assert_eq!(
            (g.backends[3].sni.as_deref(), g.backends[3].max_inflight()),
            (None, Some(7)),
            "literal keeps its own settings"
        );
        assert_eq!(g.total_weight, 3 * 3 + 1);
    }

    #[test]
    fn an_unchanged_answer_is_a_no_op_and_a_changed_one_preserves_survivors() {
        let s = SharedState::new(dns_cfg("dns = {}", r#"{ addr = "svc.internal:8080" }"#)).unwrap();
        s.set_dns("app", "svc.internal:8080", ips(&["10.0.0.1", "10.0.0.2"])).unwrap().unwrap();
        let gen = s.load().generation;
        assert!(
            s.set_dns("app", "svc.internal:8080", ips(&["10.0.0.2", "10.0.0.1"])).unwrap().is_none(),
            "same set, any order"
        );
        assert_eq!(s.load().generation, gen, "no churn when nothing changed");

        let before = s.load().upstreams["app"].clone();
        let (keep, gone) = (Arc::clone(&before.backends[0]), Arc::clone(&before.backends[1]));
        keep.set_draining(true);
        let _inflight_on_survivor = keep.track();
        let _inflight_on_retired = gone.track();

        s.set_dns("app", "svc.internal:8080", ips(&["10.0.0.1", "10.0.0.3"])).unwrap().unwrap();
        let after = s.load().upstreams["app"].clone();
        assert_eq!(names(&s), ["10.0.0.1:8080", "10.0.0.3:8080"]);
        assert!(Arc::ptr_eq(&keep, &after.backends[0]), "a surviving address keeps its identity");
        assert!(after.backends[0].is_draining() && after.backends[0].active() == 1, "…and its state");
        assert!(!Arc::ptr_eq(&gone, &after.backends[1]), "the new address is a new member");
        assert_eq!(after.backends[1].active(), 0);
        // The retired member is out of the pool but its in-flight request is intact.
        assert_eq!(gone.active(), 1);
        assert_ne!(before.build_id, after.build_id, "caches keyed on the group can tell it was rebuilt");
    }

    #[test]
    fn answers_survive_reloads_and_stale_entries_are_pruned() {
        let s =
            SharedState::new(dns_cfg("dns = {}", r#"{ addr = "a.internal:80" }, { addr = "b.internal:80" }"#)).unwrap();
        s.set_dns("app", "a.internal:80", ips(&["10.0.0.1", "10.0.0.2"])).unwrap();
        s.set_dns("app", "b.internal:80", ips(&["10.1.0.1"])).unwrap();
        let before = s.load().upstreams["app"].backends.clone();
        // An unrelated reload (new weight on nothing, new retries) keeps the expansion and the members.
        let mut cfg = (*s.load().config).clone();
        cfg.upstreams[0].retries = 2;
        s.apply(cfg).unwrap();
        assert_eq!(names(&s), ["10.0.0.1:80", "10.0.0.2:80", "10.1.0.1:80"]);
        for (a, b) in before.iter().zip(&s.load().upstreams["app"].backends) {
            assert!(Arc::ptr_eq(a, b), "{}", a.name);
        }
        // Removing a hostname from the config prunes its answer on the next update.
        let mut cfg = (*s.load().config).clone();
        cfg.upstreams[0].backends.retain(|b| b.addr.to_string() != "b.internal:80");
        s.apply(cfg).unwrap();
        s.set_dns("app", "a.internal:80", ips(&["10.0.0.1"])).unwrap();
        assert_eq!(s.dns().len(), 1, "only the live backend's answer remains");
    }

    #[test]
    fn dns_is_ignored_without_the_dns_table_and_empty_answers_fall_back() {
        // No `dns` on the upstream: hostname backends stay as configured.
        let s = SharedState::new(dns_cfg("", r#"{ addr = "svc.internal:8080" }"#)).unwrap();
        s.set_dns("app", "svc.internal:8080", ips(&["10.0.0.1"])).unwrap();
        assert_eq!(names(&s), ["svc.internal:8080"]);
        // An empty answer never leaves the pool empty: the hostname member returns.
        let s = SharedState::new(dns_cfg("dns = {}", r#"{ addr = "svc.internal:8080" }"#)).unwrap();
        s.set_dns("app", "svc.internal:8080", ips(&["10.0.0.1"])).unwrap();
        s.set_dns("app", "svc.internal:8080", vec![]).unwrap();
        assert_eq!(names(&s), ["svc.internal:8080"]);
    }

    #[test]
    fn tls_hostname_backends_keep_tls_and_remember_the_name_for_sni() {
        let s = SharedState::new(dns_cfg("dns = {}", r#"{ addr = "https://pay.internal:8443" }"#)).unwrap();
        s.set_dns("app", "https://pay.internal:8443", ips(&["10.2.0.1"])).unwrap();
        let g = s.load().upstreams["app"].clone();
        assert_eq!(g.backends[0].name.as_ref(), "https://10.2.0.1:8443");
        assert!(g.has_tls && g.backends[0].tls);
        assert_eq!(g.backends[0].sni.as_deref(), Some("pay.internal"));
        assert_eq!(g.backends[0].authority.as_str(), "10.2.0.1:8443");
    }
}
