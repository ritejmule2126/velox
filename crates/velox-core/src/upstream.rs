//! Runtime state of upstream pools: backends, hash ring and per-group counters.

use crate::clock::now_ms;
use crate::config::{Algorithm, BackendAddr, BackendConfig, UpstreamConfig};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

/// Deterministic 64-bit hash (FNV-1a with a SplitMix64 finaliser).
///
/// Stable across processes and releases, which consistent hashing needs.
pub fn hash64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h ^= h >> 30;
    h = h.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    h ^= h >> 27;
    h = h.wrapping_mul(0x94d0_49bb_1331_11eb);
    h ^ (h >> 31)
}

/// Host suffix marking a URI authority that encodes a Unix socket path.
pub const UDS_HOST_SUFFIX: &str = ".velox-uds";

/// Encode a Unix socket path into a syntactically valid URI authority
/// (`<hex>.velox-uds`), so pooled-connection keys stay per-socket.
pub fn uds_authority(path: &std::path::Path) -> String {
    use std::fmt::Write as _;
    let bytes = path.as_os_str().as_encoded_bytes();
    let mut out = String::with_capacity(bytes.len() * 2 + UDS_HOST_SUFFIX.len());
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out.push_str(UDS_HOST_SUFFIX);
    out
}

/// Inverse of [`uds_authority`]; `None` if `host` is not an encoded socket.
pub fn uds_path_from_host(host: &str) -> Option<std::path::PathBuf> {
    let hex = host.strip_suffix(UDS_HOST_SUFFIX)?;
    if hex.len() % 2 != 0 {
        return None;
    }
    let bytes: Option<Vec<u8>> =
        (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok()).collect();
    let bytes = bytes?;
    Some(std::path::PathBuf::from(std::str::from_utf8(&bytes).ok()?))
}

/// A single backend with lock-free runtime state.
#[derive(Debug)]
pub struct Backend {
    /// Where it lives.
    pub addr: BackendAddr,
    /// `addr` rendered once (used as metric label / admin key).
    pub name: Arc<str>,
    /// Relative weight.
    pub weight: u32,
    /// URI authority used to address this backend through the client pool.
    pub authority: http::uri::Authority,
    /// Spoken to over TLS (`https://` address).
    pub tls: bool,
    /// Circuit-breaker cap on in-flight requests (0 = unlimited). Atomic so a
    /// reload can change it on a backend that keeps its runtime state.
    max_inflight: AtomicU32,
    healthy: AtomicBool,
    draining: AtomicBool,
    active: AtomicI64,
    ejected_until_ms: AtomicU64,
    consecutive_failures: AtomicU32,
    ejections: AtomicU32,
    total_requests: AtomicU64,
    total_failures: AtomicU64,
}

impl Backend {
    /// Build a backend that starts healthy (no inherited in-flight cap).
    pub fn new(cfg: &BackendConfig) -> Self {
        Self::with_default_limit(cfg, None)
    }

    /// Build a backend whose in-flight cap is its own `max_inflight`, else
    /// `default_limit` (the upstream's).
    pub fn with_default_limit(cfg: &BackendConfig, default_limit: Option<u32>) -> Self {
        let authority = match &cfg.addr {
            BackendAddr::Tcp { host, port } | BackendAddr::Tls { host, port } => format!("{host}:{port}"),
            BackendAddr::Unix(path) => uds_authority(path),
        };
        Self {
            name: Arc::from(cfg.addr.to_string()),
            addr: cfg.addr.clone(),
            weight: cfg.weight,
            authority: authority.parse().unwrap_or_else(|_| http::uri::Authority::from_static("invalid.velox-backend")),
            tls: matches!(cfg.addr, BackendAddr::Tls { .. }),
            max_inflight: AtomicU32::new(cfg.max_inflight.or(default_limit).unwrap_or(0)),
            healthy: AtomicBool::new(true),
            draining: AtomicBool::new(false),
            active: AtomicI64::new(0),
            ejected_until_ms: AtomicU64::new(0),
            consecutive_failures: AtomicU32::new(0),
            ejections: AtomicU32::new(0),
            total_requests: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
        }
    }

    /// Eligible for new requests: healthy, not draining, not ejected.
    pub fn is_available(&self) -> bool {
        self.is_available_at(now_ms())
    }

    /// [`Backend::is_available`] against a caller-supplied clock reading
    /// (lets a balancer read the clock once per pick).
    pub fn is_available_at(&self, now: u64) -> bool {
        self.healthy.load(Ordering::Relaxed) && !self.draining.load(Ordering::Relaxed) && !self.is_ejected(now)
    }

    /// Whether the passive outlier window is still open at `now`.
    pub fn is_ejected(&self, now: u64) -> bool {
        self.ejected_until_ms.load(Ordering::Relaxed) > now
    }

    /// Result of the active health checker.
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    /// Set by the active health checker.
    pub fn set_healthy(&self, v: bool) {
        self.healthy.store(v, Ordering::Relaxed);
    }

    /// Operator-controlled drain flag (no new requests; in-flight finish).
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }

    /// Start or stop draining this backend.
    pub fn set_draining(&self, v: bool) {
        self.draining.store(v, Ordering::Relaxed);
    }

    /// In-flight requests (never negative).
    pub fn active(&self) -> u64 {
        u64::try_from(self.active.load(Ordering::Relaxed)).unwrap_or(0)
    }

    /// The in-flight cap, if any.
    pub fn max_inflight(&self) -> Option<u32> {
        Some(self.max_inflight.load(Ordering::Relaxed)).filter(|&m| m != 0)
    }

    /// Change the in-flight cap (`None` = unlimited).
    pub fn set_max_inflight(&self, limit: Option<u32>) {
        self.max_inflight.store(limit.unwrap_or(0), Ordering::Relaxed);
    }

    /// Has the in-flight cap been reached? (A racy hint for the balancer;
    /// [`Backend::try_track`] is the exact check.)
    pub fn is_saturated(&self) -> bool {
        let max = self.max_inflight.load(Ordering::Relaxed);
        max != 0 && self.active.load(Ordering::Relaxed) >= i64::from(max)
    }

    /// Mark a request in flight, but only if the cap allows it. The check and
    /// the increment are one atomic step, so concurrent requests can never
    /// overshoot the cap.
    pub fn try_track(self: &Arc<Self>) -> Option<ActiveGuard> {
        let max = i64::from(self.max_inflight.load(Ordering::Relaxed));
        if max == 0 {
            return Some(self.track());
        }
        let mut cur = self.active.load(Ordering::Relaxed);
        loop {
            if cur >= max {
                return None;
            }
            match self.active.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => break,
                Err(seen) => cur = seen,
            }
        }
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        Some(ActiveGuard(Arc::clone(self)))
    }

    /// Mark a request in flight until the returned guard drops (ignores the cap).
    pub fn track(self: &Arc<Self>) -> ActiveGuard {
        self.active.fetch_add(1, Ordering::Relaxed);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        ActiveGuard(Arc::clone(self))
    }

    /// Consecutive gateway failures observed by the outlier detector.
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures.load(Ordering::Relaxed)
    }

    /// Record a gateway failure; returns the new consecutive count.
    pub fn record_failure(&self) -> u32 {
        self.total_failures.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Record a success: clears the failure streak and decays ejection back-off.
    pub fn record_success(&self) {
        if self.consecutive_failures.swap(0, Ordering::Relaxed) > 0 {
            return;
        }
        // Healthy streak: slowly forgive past ejections.
        let e = self.ejections.load(Ordering::Relaxed);
        if e > 0 {
            self.ejections.store(e - 1, Ordering::Relaxed);
        }
    }

    /// Eject until `until_ms`, resetting the failure streak. Returns the
    /// number of times this backend has been ejected (for back-off).
    pub fn eject_until(&self, until_ms: u64) -> u32 {
        self.ejected_until_ms.store(until_ms, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.ejections.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// End any passive ejection immediately (ejection history is kept).
    pub fn clear_ejection(&self) {
        self.ejected_until_ms.store(0, Ordering::Relaxed);
    }

    /// How many ejections are currently counted against this backend.
    pub fn ejection_count(&self) -> u32 {
        self.ejections.load(Ordering::Relaxed)
    }

    /// Remaining ejection time in ms (0 if not ejected).
    pub fn ejected_for_ms(&self) -> u64 {
        self.ejected_until_ms.load(Ordering::Relaxed).saturating_sub(now_ms())
    }

    /// Lifetime request count.
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    /// Lifetime failure count.
    pub fn total_failures(&self) -> u64 {
        self.total_failures.load(Ordering::Relaxed)
    }
}

/// RAII marker for an in-flight request on a backend.
#[derive(Debug)]
pub struct ActiveGuard(Arc<Backend>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A Ketama-style consistent-hash ring of backend indices.
#[derive(Debug, Clone, Default)]
pub struct HashRing {
    points: Vec<(u64, u32)>,
}

impl HashRing {
    /// Virtual nodes per unit of weight.
    pub const VNODES_PER_WEIGHT: u32 = 100;

    /// Build a ring from `backends` (identity is the address string).
    pub fn new(backends: &[Arc<Backend>]) -> Self {
        let mut points = Vec::new();
        for (idx, b) in backends.iter().enumerate() {
            let n = b.weight.saturating_mul(Self::VNODES_PER_WEIGHT);
            let idx = u32::try_from(idx).unwrap_or(u32::MAX);
            for v in 0..n {
                let key = format!("{}#{v}", b.name);
                points.push((hash64(key.as_bytes()), idx));
            }
        }
        points.sort_unstable();
        Self { points }
    }

    /// Iterate backend indices clockwise starting at `key`'s position.
    pub fn walk(&self, key: u64) -> impl Iterator<Item = usize> + '_ {
        let start = self.points.partition_point(|&(h, _)| h < key);
        let len = self.points.len();
        (0..len).map(move |i| self.points[(start + i) % len].1 as usize)
    }

    /// Number of virtual nodes.
    pub fn len(&self) -> usize {
        self.points.len()
    }

    /// `true` when the ring has no points.
    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }
}

/// A named pool of backends plus balancer state.
#[derive(Debug)]
pub struct UpstreamGroup {
    /// Pool name.
    pub name: Arc<str>,
    /// The configuration this group was built from.
    pub config: UpstreamConfig,
    /// Members, in configuration order.
    pub backends: Vec<Arc<Backend>>,
    /// Consistent-hash ring (only for `consistent_hash`).
    pub ring: Option<HashRing>,
    /// Round-robin cursor.
    pub rr_cursor: AtomicU64,
    /// Sum of backend weights.
    pub total_weight: u64,
    /// Running sums of the weights (`cum_weights[i]` = weights of `0..=i`), so
    /// a weighted slot maps to its backend with a binary search.
    pub cum_weights: Vec<u64>,
    /// `true` when every backend has the same weight (slot → index is `% n`).
    pub uniform_weights: bool,
    /// `true` when at least one backend is reached over TLS (`https://`).
    pub has_tls: bool,
}

impl UpstreamGroup {
    /// Build a group, reusing runtime state of identical backends in `prev`.
    pub fn build(cfg: &UpstreamConfig, prev: Option<&UpstreamGroup>) -> Self {
        let backends: Vec<Arc<Backend>> = cfg
            .backends
            .iter()
            .map(|bc| {
                match prev.and_then(|p| p.backends.iter().find(|b| b.addr == bc.addr && b.weight == bc.weight)) {
                    Some(b) => {
                        // Runtime state survives a reload; the cap is configuration.
                        b.set_max_inflight(bc.max_inflight.or(cfg.max_inflight));
                        Arc::clone(b)
                    }
                    None => Arc::new(Backend::with_default_limit(bc, cfg.max_inflight)),
                }
            })
            .collect();
        let ring = (cfg.algorithm == Algorithm::ConsistentHash).then(|| HashRing::new(&backends));
        let total_weight = backends.iter().map(|b| u64::from(b.weight)).sum();
        let cum_weights: Vec<u64> = backends
            .iter()
            .scan(0u64, |acc, b| {
                *acc += u64::from(b.weight);
                Some(*acc)
            })
            .collect();
        let uniform_weights = backends.windows(2).all(|w| w[0].weight == w[1].weight);
        let has_tls = backends.iter().any(|b| b.tls);
        Self {
            name: Arc::from(cfg.name.as_str()),
            config: cfg.clone(),
            backends,
            ring,
            rr_cursor: AtomicU64::new(0),
            total_weight,
            cum_weights,
            uniform_weights,
            has_tls,
        }
    }

    /// Number of backends currently eligible for traffic.
    pub fn available_count(&self) -> usize {
        self.backends.iter().filter(|b| b.is_available()).count()
    }

    /// Is some backend otherwise eligible for traffic but at its in-flight cap?
    /// (Distinguishes "everything is saturated" from "everything is down".)
    pub fn any_saturated(&self) -> bool {
        let now = now_ms();
        self.backends.iter().any(|b| b.is_available_at(now) && b.is_saturated())
    }

    /// Find a backend by its display name (`host:port` / `unix:/path`).
    pub fn find(&self, name: &str) -> Option<&Arc<Backend>> {
        self.backends.iter().find(|b| &*b.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BackendConfig;

    fn backends(n: usize) -> Vec<Arc<Backend>> {
        (0..n)
            .map(|i| {
                Arc::new(Backend::new(&BackendConfig {
                    addr: format!("10.0.0.{i}:80").parse().unwrap(),
                    weight: 1,
                    max_inflight: None,
                }))
            })
            .collect()
    }

    #[test]
    fn availability_rules() {
        let b = &backends(1)[0];
        assert!(b.is_available());
        b.set_healthy(false);
        assert!(!b.is_available());
        b.set_healthy(true);
        b.set_draining(true);
        assert!(!b.is_available());
        b.set_draining(false);
        b.eject_until(crate::clock::now_ms() + 60_000);
        assert!(!b.is_available());
        b.clear_ejection();
        assert!(b.is_available());
    }

    #[test]
    fn active_guard_counts() {
        let b = Arc::clone(&backends(1)[0]);
        let g1 = b.track();
        let g2 = b.track();
        assert_eq!(b.active(), 2);
        drop(g1);
        assert_eq!(b.active(), 1);
        drop(g2);
        assert_eq!(b.active(), 0);
    }

    #[test]
    fn ring_distribution_is_roughly_even_and_stable() {
        let bs = backends(5);
        let ring = HashRing::new(&bs);
        let mut counts = [0usize; 5];
        for k in 0..50_000u64 {
            let idx = ring.walk(hash64(&k.to_le_bytes())).next().unwrap();
            counts[idx] += 1;
        }
        for c in counts {
            assert!((7_000..13_000).contains(&c), "skewed: {counts:?}");
        }
        // Stability: removing one backend only remaps that backend's keys.
        let ring4 = HashRing::new(&bs[..4]);
        let mut moved = 0;
        for k in 0..20_000u64 {
            let h = hash64(&k.to_le_bytes());
            let a = ring.walk(h).next().unwrap();
            let b = ring4.walk(h).next().unwrap();
            if a != b {
                assert_eq!(a, 4, "key moved although its backend survived");
                moved += 1;
            }
        }
        assert!(moved > 0);
    }

    #[test]
    fn uds_authority_round_trips_and_parses_as_uri_authority() {
        let p = std::path::Path::new("/run/app/web.sock");
        let a = uds_authority(p);
        assert!(a.parse::<http::uri::Authority>().is_ok());
        assert_eq!(uds_path_from_host(&a).as_deref(), Some(p));
        assert!(uds_path_from_host("example.com").is_none());
        assert!(uds_path_from_host("zz.velox-uds").is_none());
        let b = Backend::new(&BackendConfig {
            addr: "unix:/run/app/web.sock".parse().unwrap(),
            weight: 1,
            max_inflight: None,
        });
        assert_eq!(b.authority.as_str(), a);
        let t = Backend::new(&BackendConfig { addr: "[::1]:8080".parse().unwrap(), weight: 1, max_inflight: None });
        assert_eq!(t.authority.as_str(), "[::1]:8080");
    }

    #[test]
    fn weight_tables_are_consistent() {
        let g = |ws: &[u32]| {
            let cfg = velox_test_cfg(ws);
            UpstreamGroup::build(&cfg, None)
        };
        let a = g(&[1, 1, 1]);
        assert!(a.uniform_weights);
        assert_eq!(a.cum_weights, [1, 2, 3]);
        let b = g(&[5, 3, 1]);
        assert!(!b.uniform_weights);
        assert_eq!(b.cum_weights, [5, 8, 9]);
        assert_eq!(b.total_weight, 9);
        assert!(g(&[4, 4]).uniform_weights);
        assert!(g(&[]).uniform_weights && g(&[]).cum_weights.is_empty());
    }

    fn velox_test_cfg(ws: &[u32]) -> UpstreamConfig {
        UpstreamConfig {
            name: "t".into(),
            algorithm: Algorithm::RoundRobin,
            hash_on: crate::config::HashOn::Ip,
            protocol: crate::config::UpstreamProtocol::Http1,
            retries: 0,
            backends: ws
                .iter()
                .enumerate()
                .map(|(i, w)| BackendConfig {
                    addr: format!("10.0.0.{i}:80").parse().unwrap(),
                    weight: *w,
                    max_inflight: None,
                })
                .collect(),
            health: None,
            outlier: Default::default(),
            pool: Default::default(),
            max_inflight: None,
            tls: None,
        }
    }

    #[test]
    fn hash_is_deterministic() {
        assert_eq!(hash64(b"velox"), hash64(b"velox"));
        assert_ne!(hash64(b"velox"), hash64(b"Velox"));
    }

    fn capped(max: Option<u32>) -> Arc<Backend> {
        Arc::new(Backend::new(&BackendConfig { addr: "10.0.0.1:80".parse().unwrap(), weight: 1, max_inflight: max }))
    }

    #[test]
    fn try_track_enforces_the_cap_exactly_and_releases_on_drop() {
        let b = capped(Some(2));
        assert_eq!(b.max_inflight(), Some(2));
        let (g1, g2) = (b.try_track().unwrap(), b.try_track().unwrap());
        assert!(b.is_saturated() && b.try_track().is_none());
        assert_eq!((b.active(), b.total_requests()), (2, 2), "a refused request is not counted");
        drop(g1);
        assert!(!b.is_saturated());
        let g3 = b.try_track().unwrap();
        assert_eq!(b.active(), 2);
        drop((g2, g3));
        assert_eq!(b.active(), 0);
        // No cap: never saturated.
        let free = capped(None);
        let guards: Vec<_> = (0..500).map(|_| free.try_track().unwrap()).collect();
        assert!(!free.is_saturated() && free.max_inflight().is_none());
        drop(guards);
    }

    #[test]
    fn concurrent_try_track_never_overshoots_the_cap() {
        let b = capped(Some(8));
        let admitted = Arc::new(AtomicU32::new(0));
        let barrier = Arc::new(std::sync::Barrier::new(16));
        let done = Arc::new(std::sync::Barrier::new(16));
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let (b, admitted, barrier, done) =
                    (Arc::clone(&b), Arc::clone(&admitted), Arc::clone(&barrier), Arc::clone(&done));
                std::thread::spawn(move || {
                    barrier.wait();
                    let mut held = Vec::new();
                    for _ in 0..1000 {
                        if let Some(g) = b.try_track() {
                            admitted.fetch_add(1, Ordering::SeqCst);
                            assert!(b.active() <= 8, "cap overshoot: {}", b.active());
                            held.push(g);
                        }
                    }
                    done.wait(); // nobody releases until every thread has tried
                    held.len()
                })
            })
            .collect();
        let held: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(held, 8, "exactly the cap is held while nobody releases");
        assert_eq!(b.active(), 0);
    }

    #[test]
    fn caps_are_inherited_overridden_and_updated_on_reload() {
        let mut cfg = velox_test_cfg(&[1, 1]);
        cfg.max_inflight = Some(5);
        cfg.backends[1].max_inflight = Some(2);
        let g1 = UpstreamGroup::build(&cfg, None);
        assert_eq!(g1.backends[0].max_inflight(), Some(5), "inherits the upstream default");
        assert_eq!(g1.backends[1].max_inflight(), Some(2), "backend overrides it");
        // Reload keeps the Backend (and its counters) but applies the new cap.
        let held = g1.backends[0].try_track().unwrap();
        cfg.max_inflight = Some(1);
        cfg.backends[1].max_inflight = None;
        let g2 = UpstreamGroup::build(&cfg, Some(&g1));
        assert!(Arc::ptr_eq(&g1.backends[0], &g2.backends[0]), "runtime state survives reloads");
        assert_eq!((g2.backends[0].max_inflight(), g2.backends[1].max_inflight()), (Some(1), Some(1)));
        assert!(g2.backends[0].is_saturated() && g2.any_saturated());
        drop(held);
        assert!(!g2.any_saturated());
        cfg.max_inflight = None;
        let g3 = UpstreamGroup::build(&cfg, Some(&g2));
        assert_eq!(g3.backends[0].max_inflight(), None);
    }
}
