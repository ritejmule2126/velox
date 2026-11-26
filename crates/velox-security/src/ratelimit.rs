//! Lock-free token-bucket rate limiting (GCRA formulation).
//!
//! GCRA — the *generic cell rate algorithm* — is the token bucket expressed as
//! a single "theoretical arrival time" per key. One `AtomicU64` per bucket
//! updated with compare-and-swap means no locks on the check path; the key
//! map is a sharded [`DashMap`].

use dashmap::DashMap;
use http::HeaderMap;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use velox_core::config::{KeySource, RateLimitConfig};

/// What a bucket is keyed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateKey {
    /// A client address (IPv6 collapsed to its /64).
    Ip(IpAddr),
    /// A keyed (SipHash, per-process random seed) digest of a header value.
    Header(u64),
    /// Shared bucket used once the key table is full.
    Overflow,
}

/// Outcome of a rate-limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The request may proceed.
    Allowed,
    /// The bucket is empty; retry after the given delay.
    Limited {
        /// How long until a token becomes available.
        retry_after: Duration,
    },
}

/// Collapse IPv6 to /64 (and v4-mapped to v4) so one host cannot mint
/// unlimited keys from its address block.
fn normalise_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return IpAddr::V4(v4);
            }
            let mut o = v6.octets();
            o[8..].fill(0);
            IpAddr::V6(o.into())
        }
        v4 => v4,
    }
}

/// A rate limiter for one policy.
#[derive(Debug)]
pub struct RateLimiter {
    /// Nanoseconds between tokens (the emission interval `T`).
    interval_ns: u64,
    /// `(burst - 1) * T`: how far ahead of "now" a bucket may run.
    tolerance_ns: u64,
    epoch: Instant,
    buckets: DashMap<RateKey, AtomicU64>,
    max_keys: usize,
    hasher: RandomState,
    last_sweep_ns: AtomicU64,
}

impl RateLimiter {
    /// Default cap on tracked keys before the shared overflow bucket is used.
    pub const DEFAULT_MAX_KEYS: usize = 200_000;

    /// Build a limiter for `requests_per_second` with a bucket of `burst`.
    pub fn new(requests_per_second: f64, burst: u32) -> Self {
        Self::with_max_keys(requests_per_second, burst, Self::DEFAULT_MAX_KEYS)
    }

    /// Like [`RateLimiter::new`] with an explicit key-table cap.
    pub fn with_max_keys(requests_per_second: f64, burst: u32, max_keys: usize) -> Self {
        let rate = if requests_per_second.is_finite() && requests_per_second > 0.0 { requests_per_second } else { 1.0 };
        let interval_ns = ((1e9 / rate) as u64).max(1);
        let burst = u64::from(burst.max(1));
        Self {
            interval_ns,
            tolerance_ns: interval_ns.saturating_mul(burst - 1),
            epoch: Instant::now(),
            buckets: DashMap::new(),
            max_keys,
            hasher: RandomState::new(),
            last_sweep_ns: AtomicU64::new(0),
        }
    }

    /// Digest a header value into a key that attackers cannot pre-image.
    pub fn header_key(&self, value: &[u8]) -> RateKey {
        RateKey::Header(self.hasher.hash_one(value))
    }

    /// Check (and consume a token for) `key` now.
    pub fn check(&self, key: RateKey) -> Decision {
        let now = u64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.check_at(key, now)
    }

    /// Deterministic variant of [`RateLimiter::check`] taking the clock value
    /// (nanoseconds since the limiter was created).
    pub fn check_at(&self, key: RateKey, now_ns: u64) -> Decision {
        let key = match key {
            RateKey::Ip(ip) => RateKey::Ip(normalise_ip(ip)),
            other => other,
        };
        if let Some(bucket) = self.buckets.get(&key) {
            return self.gcra(&bucket, now_ns);
        }
        let key = if self.buckets.len() >= self.max_keys {
            self.maybe_sweep(now_ns);
            if self.buckets.len() >= self.max_keys {
                RateKey::Overflow
            } else {
                key
            }
        } else {
            key
        };
        let bucket = self.buckets.entry(key).or_insert_with(|| AtomicU64::new(0));
        self.gcra(&bucket, now_ns)
    }

    fn gcra(&self, tat: &AtomicU64, now: u64) -> Decision {
        let mut current = tat.load(Ordering::Relaxed);
        loop {
            let base = current.max(now);
            let backlog = base - now;
            if backlog > self.tolerance_ns {
                return Decision::Limited { retry_after: Duration::from_nanos(backlog - self.tolerance_ns) };
            }
            let next = base.saturating_add(self.interval_ns);
            match tat.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return Decision::Allowed,
                Err(actual) => current = actual,
            }
        }
    }

    fn maybe_sweep(&self, now_ns: u64) {
        let last = self.last_sweep_ns.load(Ordering::Relaxed);
        if now_ns.saturating_sub(last) < 1_000_000_000 {
            return;
        }
        if self.last_sweep_ns.compare_exchange(last, now_ns, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
            self.sweep_at(now_ns);
        }
    }

    /// Drop buckets that have fully refilled (they carry no information).
    pub fn sweep(&self) -> usize {
        let now = u64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.sweep_at(now)
    }

    fn sweep_at(&self, now_ns: u64) -> usize {
        let before = self.buckets.len();
        self.buckets.retain(|_, tat| tat.load(Ordering::Relaxed) > now_ns);
        before.saturating_sub(self.buckets.len())
    }

    /// Number of tracked keys.
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    /// `true` when no keys are tracked.
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }
}

/// Derive the bucket key for a request according to `source`.
pub fn rate_key(limiter: &RateLimiter, source: &KeySource, headers: &HeaderMap, client_ip: IpAddr) -> RateKey {
    match source {
        KeySource::Ip => RateKey::Ip(client_ip),
        KeySource::Header(name) => {
            headers.get(name.as_str()).map_or(RateKey::Ip(client_ip), |v| limiter.header_key(v.as_bytes()))
        }
    }
}

/// Per-route limiter registry that follows configuration changes.
///
/// A limiter is rebuilt only when its `(rate, burst)` changes, so counters
/// survive unrelated reloads.
#[derive(Debug, Default)]
pub struct RateLimiters {
    map: DashMap<Arc<str>, (u64, u32, Arc<RateLimiter>)>,
}

impl RateLimiters {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// The limiter for `route_id` under `policy`, creating or replacing it
    /// when the policy changed.
    pub fn get(&self, route_id: &Arc<str>, policy: &RateLimitConfig) -> Arc<RateLimiter> {
        let rate_bits = policy.requests_per_second.to_bits();
        if let Some(e) = self.map.get(route_id) {
            if e.0 == rate_bits && e.1 == policy.burst {
                return Arc::clone(&e.2);
            }
        }
        let limiter = Arc::new(RateLimiter::new(policy.requests_per_second, policy.burst));
        self.map.insert(Arc::clone(route_id), (rate_bits, policy.burst, Arc::clone(&limiter)));
        limiter
    }

    /// Forget limiters of routes that no longer exist and sweep the rest.
    pub fn retain_routes<'a>(&self, live: impl Iterator<Item = &'a str>) {
        let live: std::collections::HashSet<&str> = live.collect();
        self.map.retain(|k, _| live.contains(&**k));
        for e in &self.map {
            e.2.sweep();
        }
    }

    /// Number of registered limiters.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// `true` if no limiter is registered.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> RateKey {
        RateKey::Ip(s.parse().unwrap())
    }

    const SEC: u64 = 1_000_000_000;

    #[test]
    fn burst_then_limited_then_refills() {
        let rl = RateLimiter::new(10.0, 5); // 100ms per token
        let k = ip("1.2.3.4");
        for i in 0..5 {
            assert_eq!(rl.check_at(k, SEC), Decision::Allowed, "burst token {i}");
        }
        match rl.check_at(k, SEC) {
            Decision::Limited { retry_after } => {
                assert!(retry_after > Duration::ZERO && retry_after <= Duration::from_millis(100), "{retry_after:?}");
            }
            Decision::Allowed => panic!("6th request must be limited"),
        }
        // 100ms later exactly one token is back.
        assert_eq!(rl.check_at(k, SEC + 100_000_000), Decision::Allowed);
        assert!(matches!(rl.check_at(k, SEC + 100_000_000), Decision::Limited { .. }));
        // A long idle period refills to (but not beyond) the burst size.
        let later = 100 * SEC;
        for _ in 0..5 {
            assert_eq!(rl.check_at(k, later), Decision::Allowed);
        }
        assert!(matches!(rl.check_at(k, later), Decision::Limited { .. }));
    }

    #[test]
    fn sustained_rate_is_enforced() {
        let rl = RateLimiter::new(100.0, 1);
        let k = ip("9.9.9.9");
        let mut allowed = 0;
        // 1 second of traffic at 1000 req/s.
        for i in 0..1000u64 {
            if rl.check_at(k, SEC + i * 1_000_000) == Decision::Allowed {
                allowed += 1;
            }
        }
        assert!((95..=105).contains(&allowed), "allowed {allowed}");
    }

    #[test]
    fn keys_are_independent() {
        let rl = RateLimiter::new(1.0, 1);
        assert_eq!(rl.check_at(ip("1.1.1.1"), SEC), Decision::Allowed);
        assert!(matches!(rl.check_at(ip("1.1.1.1"), SEC), Decision::Limited { .. }));
        assert_eq!(rl.check_at(ip("2.2.2.2"), SEC), Decision::Allowed);
    }

    #[test]
    fn ipv6_collapses_to_slash_64() {
        let rl = RateLimiter::new(1.0, 1);
        assert_eq!(rl.check_at(ip("2001:db8:1:2::1"), SEC), Decision::Allowed);
        assert!(matches!(rl.check_at(ip("2001:db8:1:2:ffff::9"), SEC), Decision::Limited { .. }));
        assert_eq!(rl.check_at(ip("2001:db8:1:3::1"), SEC), Decision::Allowed);
        // v4-mapped addresses share a bucket with plain v4.
        assert_eq!(rl.check_at(ip("5.6.7.8"), SEC), Decision::Allowed);
        assert!(matches!(rl.check_at(ip("::ffff:5.6.7.8"), SEC), Decision::Limited { .. }));
    }

    #[test]
    fn key_table_is_bounded_with_overflow_bucket() {
        let rl = RateLimiter::with_max_keys(1.0, 1, 3);
        for i in 0..3 {
            assert_eq!(rl.check_at(ip(&format!("10.0.0.{i}")), SEC), Decision::Allowed);
        }
        // Table full of *active* keys: new keys share the overflow bucket.
        assert_eq!(rl.check_at(ip("10.9.9.1"), SEC), Decision::Allowed);
        assert!(matches!(rl.check_at(ip("10.9.9.2"), SEC), Decision::Limited { .. }));
        assert!(rl.len() <= 4);
    }

    #[test]
    fn sweep_removes_fully_refilled_buckets() {
        let rl = RateLimiter::new(10.0, 1);
        rl.check_at(ip("1.1.1.1"), SEC);
        rl.check_at(ip("2.2.2.2"), SEC);
        assert_eq!(rl.sweep_at(SEC), 0);
        assert_eq!(rl.sweep_at(10 * SEC), 2);
        assert!(rl.is_empty());
    }

    #[test]
    fn header_keys_are_stable_within_a_limiter() {
        let rl = RateLimiter::new(1.0, 1);
        assert_eq!(rl.header_key(b"abc"), rl.header_key(b"abc"));
        assert_ne!(rl.header_key(b"abc"), rl.header_key(b"abd"));
    }

    #[test]
    fn rate_key_selection() {
        let rl = RateLimiter::new(1.0, 1);
        let mut h = HeaderMap::new();
        let ipaddr: IpAddr = "1.2.3.4".parse().unwrap();
        let src = KeySource::Header("x-api-key".into());
        assert_eq!(rate_key(&rl, &src, &h, ipaddr), RateKey::Ip(ipaddr), "falls back to IP");
        h.insert("x-api-key", "secret".parse().unwrap());
        assert_eq!(rate_key(&rl, &src, &h, ipaddr), rl.header_key(b"secret"));
        assert_eq!(rate_key(&rl, &KeySource::Ip, &h, ipaddr), RateKey::Ip(ipaddr));
    }

    #[test]
    fn concurrent_checks_never_exceed_burst() {
        let rl = Arc::new(RateLimiter::new(0.001, 100)); // effectively no refill during the test
        let allowed = Arc::new(AtomicU64::new(0));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let rl = Arc::clone(&rl);
                let allowed = Arc::clone(&allowed);
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        if rl.check_at(ip("7.7.7.7"), SEC) == Decision::Allowed {
                            allowed.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(allowed.load(Ordering::Relaxed), 100);
    }

    #[test]
    fn registry_replaces_only_on_policy_change() {
        let reg = RateLimiters::new();
        let id: Arc<str> = Arc::from("r");
        let mut p = RateLimitConfig::default();
        let a = reg.get(&id, &p);
        assert!(Arc::ptr_eq(&a, &reg.get(&id, &p)));
        p.burst += 1;
        assert!(!Arc::ptr_eq(&a, &reg.get(&id, &p)));
        reg.retain_routes(std::iter::empty());
        assert!(reg.is_empty());
    }
}
