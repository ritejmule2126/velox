//! Token-bucket rate limiting (GCRA formulation) with bounded memory.
//!
//! GCRA — the *generic cell rate algorithm* — is the token bucket expressed as
//! a single "theoretical arrival time" (TAT) per key. Each bucket is one
//! `AtomicU64` updated with compare-and-swap, so the **check path takes only a
//! shared read lock on one of 64 shards** and never blocks other readers.
//!
//! # Bounded memory without a shared "overflow" bucket
//!
//! The table is capped. When a shard is full, inserting a new key evicts one
//! entry *from that shard only*: first any fully-refilled (expired) bucket,
//! otherwise — after a bounded clock sweep of [`CLOCK_BUDGET`] candidates —
//! the bucket closest to full. Evicting a bucket can only make its key *more*
//! permissive (it restarts with a fresh burst), so a flood of fabricated keys
//! can never push **new legitimate users** into a shared, already-exhausted
//! bucket (the failure mode of a global overflow bucket). The trade-off is
//! documented and deliberate: an attacker able to mint hundreds of thousands
//! of source keys can reset *other abusers'* penalty state, but cannot deny
//! service to anyone.

use dashmap::DashMap;
use hashbrown::HashTable;
use http::HeaderMap;
use std::collections::hash_map::RandomState;
use std::collections::VecDeque;
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};
use velox_core::config::{KeySource, RateLimitConfig};

/// Candidates examined per eviction before settling for the least-recently
/// refilled one.
pub const CLOCK_BUDGET: usize = 8;

/// Number of independent shards (a power of two).
const DEFAULT_SHARDS: usize = 64;

/// What a bucket is keyed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateKey {
    /// A client address (IPv6 collapsed to its /64).
    Ip(IpAddr),
    /// A keyed (SipHash, per-process random seed) digest of a header value.
    Header(u64),
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

#[derive(Debug)]
struct Entry {
    hash: u64,
    key: RateKey,
    tat: AtomicU64,
}

#[derive(Debug, Default)]
struct ShardInner {
    table: HashTable<Entry>,
    /// One record per live entry, oldest first (the clock hand).
    order: VecDeque<(u64, RateKey)>,
}

/// A shard, padded to its own cache line pair to avoid false sharing.
#[derive(Debug, Default)]
#[repr(align(128))]
struct Shard(RwLock<ShardInner>);

impl Shard {
    fn read(&self) -> RwLockReadGuard<'_, ShardInner> {
        self.0.read().unwrap_or_else(PoisonError::into_inner)
    }
    fn write(&self) -> RwLockWriteGuard<'_, ShardInner> {
        self.0.write().unwrap_or_else(PoisonError::into_inner)
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
    shards: Box<[Shard]>,
    shard_mask: usize,
    cap_per_shard: usize,
    hasher: RandomState,
}

impl RateLimiter {
    /// Default cap on tracked keys.
    pub const DEFAULT_MAX_KEYS: usize = 200_000;

    /// Build a limiter for `requests_per_second` with a bucket of `burst`.
    pub fn new(requests_per_second: f64, burst: u32) -> Self {
        Self::with_max_keys(requests_per_second, burst, Self::DEFAULT_MAX_KEYS)
    }

    /// Like [`RateLimiter::new`] with an explicit key-table cap.
    pub fn with_max_keys(requests_per_second: f64, burst: u32, max_keys: usize) -> Self {
        Self::with_shards(requests_per_second, burst, max_keys, DEFAULT_SHARDS)
    }

    /// Full control: `shards` is rounded up to a power of two; the cap applies
    /// per shard as `ceil(max_keys / shards)`.
    pub fn with_shards(requests_per_second: f64, burst: u32, max_keys: usize, shards: usize) -> Self {
        let rate = if requests_per_second.is_finite() && requests_per_second > 0.0 { requests_per_second } else { 1.0 };
        let interval_ns = ((1e9 / rate) as u64).max(1);
        let burst = u64::from(burst.max(1));
        let n = shards.max(1).next_power_of_two();
        Self {
            interval_ns,
            tolerance_ns: interval_ns.saturating_mul(burst - 1),
            epoch: Instant::now(),
            shards: (0..n).map(|_| Shard::default()).collect(),
            shard_mask: n - 1,
            cap_per_shard: max_keys.div_ceil(n).max(1),
            hasher: RandomState::new(),
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
        let hash = self.hasher.hash_one(key);
        // High bits pick the shard; hashbrown uses the low bits for slots and
        // the top seven for control bytes, so this keeps all three independent.
        let shard = &self.shards[(hash >> 40) as usize & self.shard_mask];
        if let Some(e) = shard.read().table.find(hash, |e| e.key == key) {
            return self.gcra(&e.tat, now_ns);
        }
        let mut inner = shard.write();
        if let Some(e) = inner.table.find(hash, |e| e.key == key) {
            return self.gcra(&e.tat, now_ns); // lost an insertion race
        }
        if inner.table.len() >= self.cap_per_shard {
            Self::evict_one(&mut inner, now_ns);
        }
        // A brand-new bucket always admits its first request.
        let tat = now_ns.saturating_add(self.interval_ns);
        inner.table.insert_unique(hash, Entry { hash, key, tat: AtomicU64::new(tat) }, |e| e.hash);
        inner.order.push_back((hash, key));
        Decision::Allowed
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

    /// Remove one entry from this shard (precondition: the shard is full).
    ///
    /// Clock sweep: walk the oldest records; an expired bucket is evicted on
    /// sight. Otherwise examined buckets get a second chance (re-queued) and,
    /// once the budget is spent, the one closest to refilling is evicted.
    fn evict_one(inner: &mut ShardInner, now: u64) {
        let mut seen: [Option<(u64, RateKey, u64)>; CLOCK_BUDGET] = [None; CLOCK_BUDGET];
        let mut n = 0;
        while n < CLOCK_BUDGET {
            let Some((hash, key)) = inner.order.pop_front() else { break };
            let Ok(entry) = inner.table.find_entry(hash, |e| e.key == key) else {
                continue; // no live entry for this record
            };
            let tat = entry.get().tat.load(Ordering::Relaxed);
            if tat <= now {
                entry.remove();
                // Survivors keep their relative order at the back of the queue.
                for (h, k, _) in seen.iter().take(n).flatten() {
                    inner.order.push_back((*h, *k));
                }
                return;
            }
            seen[n] = Some((hash, key, tat));
            n += 1;
        }
        let victim = seen
            .iter()
            .take(n)
            .enumerate()
            .filter_map(|(i, s)| s.map(|(_, _, tat)| (i, tat)))
            .min_by_key(|&(_, tat)| tat)
            .map(|(i, _)| i);
        for (i, rec) in seen.iter().take(n).enumerate() {
            let Some((h, k, _)) = *rec else { continue };
            if Some(i) == victim {
                if let Ok(e) = inner.table.find_entry(h, |e| e.key == k) {
                    e.remove();
                }
            } else {
                inner.order.push_back((h, k));
            }
        }
    }

    /// Drop buckets that have fully refilled (they carry no information).
    pub fn sweep(&self) -> usize {
        let now = u64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.sweep_at(now)
    }

    fn sweep_at(&self, now_ns: u64) -> usize {
        let mut removed = 0;
        for shard in &*self.shards {
            let mut inner = shard.write();
            let before = inner.table.len();
            inner.table.retain(|e| e.tat.load(Ordering::Relaxed) > now_ns);
            removed += before - inner.table.len();
            let ShardInner { table, order } = &mut *inner;
            order.retain(|(h, k)| table.find(*h, |e| e.key == *k).is_some());
        }
        removed
    }

    /// Number of tracked keys.
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.read().table.len()).sum()
    }

    /// `true` when no keys are tracked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Hard upper bound on [`RateLimiter::len`].
    pub fn capacity(&self) -> usize {
        self.cap_per_shard * self.shards.len()
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
    fn flood_of_fabricated_keys_cannot_poison_new_legitimate_users() {
        // Regression: the old design sent every key beyond the cap into ONE
        // shared bucket, so after a 200k-key flood every new user got 429.
        let rl = RateLimiter::with_max_keys(1.0, 1, 640); // 64 shards × 10
        let flood = |n: u32| {
            for i in 0..n {
                let ip = std::net::Ipv4Addr::from(0x0a00_0000 + i);
                rl.check_at(RateKey::Ip(IpAddr::V4(ip)), SEC);
            }
        };
        flood(50_000);
        assert!(rl.len() <= rl.capacity(), "memory stays bounded: {} > {}", rl.len(), rl.capacity());
        for i in 0..200u32 {
            let legit = RateKey::Ip(IpAddr::V4(std::net::Ipv4Addr::from(0xc000_0200 + i)));
            assert_eq!(rl.check_at(legit, SEC), Decision::Allowed, "new user #{i} must not be throttled by the flood");
            flood(500); // the attack continues between legitimate arrivals
        }
        assert!(rl.len() <= rl.capacity());
    }

    #[test]
    fn eviction_prefers_expired_buckets_and_keeps_active_ones() {
        let rl = RateLimiter::with_shards(1.0, 1, 4, 1); // one shard, cap 4
        let (c, d, a, b) = (ip("10.0.0.3"), ip("10.0.0.4"), ip("10.0.0.1"), ip("10.0.0.2"));
        // c and d were used long ago (fully refilled by t=10s); a and b are hot.
        assert_eq!(rl.check_at(c, 0), Decision::Allowed);
        assert_eq!(rl.check_at(d, 0), Decision::Allowed);
        assert_eq!(rl.check_at(a, 10 * SEC), Decision::Allowed);
        assert_eq!(rl.check_at(b, 10 * SEC), Decision::Allowed);
        assert_eq!(rl.len(), 4);
        // Two newcomers each evict one *expired* entry…
        assert_eq!(rl.check_at(ip("10.0.0.5"), 10 * SEC), Decision::Allowed);
        assert_eq!(rl.check_at(ip("10.0.0.6"), 10 * SEC), Decision::Allowed);
        // …so the hot buckets' penalty state survived.
        assert!(matches!(rl.check_at(a, 10 * SEC), Decision::Limited { .. }), "a must still be limited");
        assert!(matches!(rl.check_at(b, 10 * SEC), Decision::Limited { .. }), "b must still be limited");
        assert_eq!(rl.len(), 4);
    }

    #[test]
    fn full_table_of_active_keys_evicts_the_closest_to_full_not_the_newcomer() {
        let rl = RateLimiter::with_shards(1.0, 3, 3, 1);
        // Three hot keys with different loads (higher TAT = hotter).
        let (cold, warm, hot) = (ip("10.0.0.1"), ip("10.0.0.2"), ip("10.0.0.3"));
        rl.check_at(cold, 10 * SEC);
        for _ in 0..2 {
            rl.check_at(warm, 10 * SEC);
        }
        for _ in 0..3 {
            rl.check_at(hot, 10 * SEC);
        }
        // A newcomer is admitted by evicting the least-loaded bucket (`cold`).
        assert_eq!(rl.check_at(ip("10.0.0.9"), 10 * SEC), Decision::Allowed);
        assert!(matches!(rl.check_at(hot, 10 * SEC), Decision::Limited { .. }), "hot key stays limited");
        assert_eq!(rl.len(), 3);
        // `cold` lost its state (more permissive), which is the safe direction.
        assert_eq!(rl.check_at(cold, 10 * SEC), Decision::Allowed);
    }

    #[test]
    fn insertion_order_records_never_grow_unbounded() {
        let rl = RateLimiter::with_shards(1.0, 1, 8, 1);
        for i in 0..20_000u32 {
            rl.check_at(RateKey::Ip(IpAddr::V4(std::net::Ipv4Addr::from(i))), SEC + u64::from(i));
        }
        let inner = rl.shards[0].read();
        assert_eq!(inner.table.len(), inner.order.len(), "exactly one clock record per live bucket");
        assert!(inner.table.len() <= 8);
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
