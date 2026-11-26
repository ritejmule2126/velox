//! Lock-free, atomically swappable runtime state.

use crate::config::Config;
use crate::error::ConfigError;
use crate::router::{Route, Router};
use crate::upstream::UpstreamGroup;
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
        config.validate()?;
        let upstreams: HashMap<String, Arc<UpstreamGroup>> = config
            .upstreams
            .iter()
            .map(|u| {
                let old = prev.and_then(|p| p.upstreams.get(&u.name)).map(AsRef::as_ref);
                (u.name.clone(), Arc::new(UpstreamGroup::build(u, old)))
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
    generation: AtomicU64,
    writer: Mutex<()>,
}

impl SharedState {
    /// Build the initial state from `config`.
    pub fn new(config: Config) -> Result<Arc<Self>, ConfigError> {
        let snap = Snapshot::build(config, None, 1)?;
        Ok(Arc::new(Self {
            current: ArcSwap::from_pointee(snap),
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
        let snap = Arc::new(Snapshot::build(cfg, Some(&prev), generation)?);
        self.generation.store(generation, Ordering::Relaxed);
        self.current.store(Arc::clone(&snap));
        Ok(snap)
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
}
