//! Load-balancing algorithms.
//!
//! Selection is allocation-free and lock-free: it reads atomics on
//! [`Backend`]s and bumps one atomic cursor. Every algorithm honours
//! availability (health, drain, outlier ejection) and an `exclude` bitmask so
//! retries land on a *different* backend.

use std::net::IpAddr;
use velox_core::clock::now_ms;
use velox_core::config::{Algorithm, HashOn};
use velox_core::upstream::hash64;
use velox_core::{Backend, UpstreamGroup};

/// Per-request inputs to selection.
#[derive(Debug, Clone, Copy, Default)]
pub struct PickCtx {
    /// Hash of the consistent-hash key (see [`hash_key`]).
    pub hash: u64,
    /// Bit `i` set ⇒ backend `i` was already tried (only the first 128 are tracked).
    pub exclude: u128,
}

impl PickCtx {
    /// Mark backend `idx` as tried.
    pub fn exclude(&mut self, idx: usize) {
        if idx < 128 {
            self.exclude |= 1u128 << idx;
        }
    }
}

/// A backend the balancer may choose: not already tried, healthy, not drained
/// or ejected, and below its `max_inflight` circuit-breaker cap. (The cap
/// check here is a cheap hint; [`Backend::try_track`] makes the exact decision
/// when the request commits to the backend.)
fn usable(b: &Backend, idx: usize, ctx: &PickCtx, now: u64) -> bool {
    (idx >= 128 || ctx.exclude & (1u128 << idx) == 0) && b.is_available_at(now) && !b.is_saturated()
}

/// Compute the consistent-hash key for a request.
pub fn hash_key(on: &HashOn, client_ip: IpAddr, path: &str, header: Option<&[u8]>) -> u64 {
    match on {
        HashOn::Ip => match client_ip {
            IpAddr::V4(v4) => hash64(&v4.octets()),
            IpAddr::V6(v6) => hash64(&v6.octets()),
        },
        HashOn::Path => hash64(path.as_bytes()),
        HashOn::Header(_) => match header {
            Some(v) => hash64(v),
            None => hash_key(&HashOn::Ip, client_ip, path, None),
        },
    }
}

/// Pick a backend index from `group`, or `None` if nothing is usable.
pub fn pick(group: &UpstreamGroup, ctx: &PickCtx) -> Option<usize> {
    let now = now_ms();
    match group.config.algorithm {
        Algorithm::RoundRobin => round_robin(group, ctx, now),
        Algorithm::LeastConn => least_conn(group, ctx, now),
        Algorithm::P2c => p2c(group, ctx, now),
        Algorithm::ConsistentHash => consistent_hash(group, ctx, now),
    }
}

fn round_robin(group: &UpstreamGroup, ctx: &PickCtx, now: u64) -> Option<usize> {
    let n = group.backends.len();
    if n == 0 || group.total_weight == 0 {
        return None;
    }
    let cursor = group.rr_cursor.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // O(1) for equal weights; O(log n) otherwise (binary search over the
    // precomputed prefix sums). Never loops over the backends to find a slot.
    let start = if group.uniform_weights {
        (cursor % n as u64) as usize
    } else {
        let slot = cursor % group.total_weight;
        group.cum_weights.partition_point(|&c| c <= slot).min(n - 1)
    };
    // Fast path: the slot's owner is usable. Otherwise walk forward.
    if usable(&group.backends[start], start, ctx, now) {
        return Some(start);
    }
    (1..n).map(|off| (start + off) % n).find(|&i| usable(&group.backends[i], i, ctx, now))
}

/// Weight-normalised load: lower is better. Cross-multiplied to stay in integers.
fn load_score(b: &Backend) -> u64 {
    (b.active() + 1).saturating_mul(1 << 20) / u64::from(b.weight.max(1))
}

fn least_conn(group: &UpstreamGroup, ctx: &PickCtx, now: u64) -> Option<usize> {
    let n = group.backends.len();
    if n == 0 {
        return None;
    }
    let offset = fastrand::usize(..n);
    let mut best: Option<(usize, u64)> = None;
    for k in 0..n {
        let i = (offset + k) % n;
        let b = &group.backends[i];
        if !usable(b, i, ctx, now) {
            continue;
        }
        let score = load_score(b);
        if best.is_none_or(|(_, s)| score < s) {
            best = Some((i, score));
        }
    }
    best.map(|(i, _)| i)
}

fn p2c(group: &UpstreamGroup, ctx: &PickCtx, now: u64) -> Option<usize> {
    let n = group.backends.len();
    match n {
        0 => return None,
        1 => return usable(&group.backends[0], 0, ctx, now).then_some(0),
        _ => {}
    }
    // Healthy pool: two distinct random indices, O(1). Rejection sampling over
    // *usable* candidates keeps the distribution identical to sampling from
    // the usable subset, so degraded pools stay correct too.
    for _ in 0..3 {
        let a = fastrand::usize(..n);
        let mut b = fastrand::usize(..n - 1);
        if b >= a {
            b += 1; // distinct without a retry loop
        }
        if usable(&group.backends[a], a, ctx, now) && usable(&group.backends[b], b, ctx, now) {
            return Some(if load_score(&group.backends[b]) < load_score(&group.backends[a]) { b } else { a });
        }
    }
    p2c_degraded(group, ctx, now)
}

/// Exact power-of-two-choices over the usable subset (O(n); only reached when
/// several backends are unhealthy, drained, ejected or already tried).
fn p2c_degraded(group: &UpstreamGroup, ctx: &PickCtx, now: u64) -> Option<usize> {
    let n = group.backends.len();
    let usable_count = (0..n).filter(|&i| usable(&group.backends[i], i, ctx, now)).count();
    match usable_count {
        0 => return None,
        1 => return (0..n).find(|&i| usable(&group.backends[i], i, ctx, now)),
        _ => {}
    }
    let r1 = fastrand::usize(..usable_count);
    let mut r2 = fastrand::usize(..usable_count - 1);
    if r2 >= r1 {
        r2 += 1;
    }
    let nth = |rank: usize| (0..n).filter(|&i| usable(&group.backends[i], i, ctx, now)).nth(rank);
    let (a, b) = (nth(r1)?, nth(r2)?);
    Some(if load_score(&group.backends[b]) < load_score(&group.backends[a]) { b } else { a })
}

fn consistent_hash(group: &UpstreamGroup, ctx: &PickCtx, now: u64) -> Option<usize> {
    group.ring.as_ref()?.walk(ctx.hash).find(|&i| usable(&group.backends[i], i, ctx, now))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use velox_core::{Config, SharedState};

    fn group(algo: &str, weights: &[u32]) -> Arc<UpstreamGroup> {
        let backends: Vec<String> =
            weights.iter().enumerate().map(|(i, w)| format!("{{ addr = \"10.0.0.{i}:80\", weight = {w} }}")).collect();
        let text = format!(
            "[server]\nhttp_addr = \"127.0.0.1:1\"\n[[upstream]]\nname = \"a\"\nalgorithm = \"{algo}\"\nbackends = [{}]\n",
            backends.join(",")
        );
        let s = SharedState::new(Config::from_toml_str(&text).unwrap()).unwrap();
        Arc::clone(&s.load().upstreams["a"])
    }

    fn histogram(g: &UpstreamGroup, n: usize) -> HashMap<usize, usize> {
        let mut h = HashMap::new();
        for _ in 0..n {
            let i = pick(g, &PickCtx::default()).unwrap();
            *h.entry(i).or_insert(0) += 1;
        }
        h
    }

    #[test]
    fn round_robin_cycles_evenly() {
        let g = group("round_robin", &[1, 1, 1]);
        let h = histogram(&g, 3000);
        assert!(h.values().all(|&c| c == 1000), "{h:?}");
        let order: Vec<_> = (0..6).map(|_| pick(&g, &PickCtx::default()).unwrap()).collect();
        assert_eq!(order[..3], order[3..], "strict rotation");
    }

    #[test]
    fn round_robin_honours_weights_exactly() {
        let g = group("round_robin", &[5, 3, 1]);
        let h = histogram(&g, 9000);
        assert_eq!((h[&0], h[&1], h[&2]), (5000, 3000, 1000), "{h:?}");
    }

    #[test]
    fn round_robin_skips_unavailable_and_excluded() {
        let g = group("round_robin", &[1, 1, 1]);
        g.backends[1].set_draining(true);
        let h = histogram(&g, 1000);
        assert!(!h.contains_key(&1));
        let mut ctx = PickCtx::default();
        ctx.exclude(0);
        for _ in 0..100 {
            assert_eq!(pick(&g, &ctx), Some(2));
        }
        ctx.exclude(2);
        assert_eq!(pick(&g, &ctx), None);
    }

    #[test]
    fn least_conn_prefers_idle_and_normalises_by_weight() {
        let g = group("least_conn", &[1, 1, 1]);
        let _a = g.backends[0].track();
        let _b = g.backends[0].track();
        let _c = g.backends[1].track();
        for _ in 0..200 {
            assert_eq!(pick(&g, &PickCtx::default()), Some(2));
        }
        // weight 4 with 3 in flight (score 4/4) beats weight 1 with 1 in flight (score 2/1)
        let g = group("least_conn", &[4, 1]);
        let _held: Vec<_> = (0..3).map(|_| g.backends[0].track()).collect();
        let _one = g.backends[1].track();
        for _ in 0..200 {
            assert_eq!(pick(&g, &PickCtx::default()), Some(0));
        }
    }

    #[test]
    fn least_conn_spreads_ties() {
        let g = group("least_conn", &[1, 1, 1, 1]);
        let h = histogram(&g, 4000);
        assert_eq!(h.len(), 4, "ties must not pile onto backend 0: {h:?}");
    }

    #[test]
    fn p2c_never_picks_the_most_loaded_of_three_and_favours_light_ones() {
        let g = group("p2c", &[1, 1, 1]);
        let _heavy: Vec<_> = (0..50).map(|_| g.backends[0].track()).collect();
        let h = histogram(&g, 6000);
        // Backend 0 only wins if paired with itself, which cannot happen.
        assert!(!h.contains_key(&0), "{h:?}");
        assert!(h[&1] > 2000 && h[&2] > 2000, "{h:?}");
    }

    #[test]
    fn p2c_with_even_load_is_uniform_and_handles_small_pools() {
        let g = group("p2c", &[1, 1, 1, 1]);
        let h = histogram(&g, 8000);
        for c in h.values() {
            assert!((1600..2400).contains(c), "{h:?}");
        }
        let one = group("p2c", &[1, 1]);
        one.backends[0].set_healthy(false);
        assert_eq!(pick(&one, &PickCtx::default()), Some(1));
        one.backends[1].set_healthy(false);
        assert_eq!(pick(&one, &PickCtx::default()), None);
    }

    #[test]
    fn consistent_hash_is_sticky_and_fails_over_minimally() {
        let g = group("consistent_hash", &[1, 1, 1, 1, 1]);
        let key = |k: u32| PickCtx { hash: hash64(&k.to_le_bytes()), exclude: 0 };
        let before: Vec<usize> = (0..2000).map(|k| pick(&g, &key(k)).unwrap()).collect();
        let again: Vec<usize> = (0..2000).map(|k| pick(&g, &key(k)).unwrap()).collect();
        assert_eq!(before, again, "same key → same backend");

        g.backends[2].set_healthy(false);
        let mut moved = 0;
        for k in 0..2000u32 {
            let now = pick(&g, &key(k)).unwrap();
            assert_ne!(now, 2);
            if before[k as usize] != now {
                assert_eq!(before[k as usize], 2, "only the failed node's keys may move");
                moved += 1;
            }
        }
        assert!(moved > 200 && moved < 700, "~1/5 of keys moved, got {moved}");
    }

    #[test]
    fn hash_key_variants() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(hash_key(&HashOn::Ip, ip, "/a", None), hash_key(&HashOn::Ip, ip, "/b", None));
        assert_ne!(hash_key(&HashOn::Path, ip, "/a", None), hash_key(&HashOn::Path, ip, "/b", None));
        let h = HashOn::Header("x-user".into());
        assert_eq!(hash_key(&h, ip, "/", Some(b"u1")), hash_key(&h, ip, "/z", Some(b"u1")));
        assert_eq!(hash_key(&h, ip, "/", None), hash_key(&HashOn::Ip, ip, "/", None), "falls back to ip");
    }

    #[test]
    fn round_robin_with_unequal_weights_survives_unavailable_owners() {
        let g = group("round_robin", &[3, 1, 2]);
        g.backends[0].set_draining(true); // owner of slots 0..3 is gone
        let h = histogram(&g, 6000);
        assert!(!h.contains_key(&0));
        assert_eq!(h.values().sum::<usize>(), 6000, "every request still lands somewhere: {h:?}");
        g.backends[1].set_healthy(false);
        g.backends[2].set_healthy(false);
        assert_eq!(pick(&g, &PickCtx::default()), None);
    }

    #[test]
    fn round_robin_slot_mapping_matches_the_linear_definition() {
        for weights in [&[1u32, 1, 1, 1][..], &[7, 1, 1], &[2, 9, 4, 1, 1], &[1000, 1]] {
            let g = group("round_robin", weights);
            let total: u64 = weights.iter().map(|&w| u64::from(w)).sum();
            for slot in 0..total * 2 {
                // reference: walk the weights
                let mut s = slot % total;
                let mut expect = 0;
                for (i, &w) in weights.iter().enumerate() {
                    if s < u64::from(w) {
                        expect = i;
                        break;
                    }
                    s -= u64::from(w);
                }
                let got = if g.uniform_weights {
                    (slot % weights.len() as u64) as usize
                } else {
                    g.cum_weights.partition_point(|&c| c <= slot % total)
                };
                assert_eq!(got, expect, "weights {weights:?} slot {slot}");
            }
        }
    }

    #[test]
    fn p2c_stays_correct_when_most_of_the_pool_is_down() {
        let g = group("p2c", &[1; 16]);
        for b in &g.backends[..14] {
            b.set_healthy(false); // only 14 and 15 usable
        }
        let _busy: Vec<_> = (0..20).map(|_| g.backends[14].track()).collect();
        let h = histogram(&g, 4000);
        assert_eq!(h.len(), 1, "only the two live backends are ever candidates: {h:?}");
        assert_eq!(h[&15], 4000, "with two candidates P2C always takes the lighter one: {h:?}");
        // exclusion is honoured on the degraded path as well
        let mut ctx = PickCtx::default();
        ctx.exclude(15);
        assert_eq!(pick(&g, &ctx), Some(14));
        ctx.exclude(14);
        assert_eq!(pick(&g, &ctx), None);
    }

    #[test]
    fn p2c_distinct_pair_sampling_is_unbiased() {
        // With all loads equal every backend must be equally likely.
        let g = group("p2c", &[1; 5]);
        let h = histogram(&g, 50_000);
        for i in 0..5 {
            assert!((8_000..12_000).contains(&h[&i]), "backend {i}: {h:?}");
        }
    }

    #[test]
    fn nothing_available_returns_none_for_every_algorithm() {
        for algo in ["round_robin", "least_conn", "p2c", "consistent_hash"] {
            let g = group(algo, &[1, 1]);
            g.backends.iter().for_each(|b| b.set_healthy(false));
            assert_eq!(pick(&g, &PickCtx::default()), None, "{algo}");
        }
    }

    fn capped_group(algo: &str, n: usize, cap: u32) -> Arc<UpstreamGroup> {
        let backends: Vec<String> = (0..n).map(|i| format!("{{ addr = \"10.0.0.{i}:80\" }}")).collect();
        let text = format!(
            "[server]\nhttp_addr = \"127.0.0.1:1\"\n[[upstream]]\nname = \"a\"\nalgorithm = \"{algo}\"\n\
             max_inflight = {cap}\nbackends = [{}]\n",
            backends.join(",")
        );
        let s = SharedState::new(Config::from_toml_str(&text).unwrap()).unwrap();
        Arc::clone(&s.load().upstreams["a"])
    }

    #[test]
    fn every_algorithm_skips_saturated_backends_and_reports_total_saturation() {
        for algo in ["round_robin", "least_conn", "p2c", "consistent_hash"] {
            let g = capped_group(algo, 4, 1);
            let ctx = PickCtx { hash: 12345, exclude: 0 };
            // Fill backend 0: it must never be picked while at its cap.
            let held0 = g.backends[0].try_track().unwrap();
            for _ in 0..500 {
                let i = pick(&g, &PickCtx { hash: fastrand::u64(..), exclude: 0 }).unwrap();
                assert_ne!(i, 0, "{algo}: picked a saturated backend");
            }
            // Fill the rest: nothing is pickable, and the group says why.
            let held: Vec<_> = (1..4).map(|i| g.backends[i].try_track().unwrap()).collect();
            assert_eq!(pick(&g, &ctx), None, "{algo}");
            assert!(g.any_saturated(), "{algo}");
            // Capacity returns as soon as a request finishes.
            drop(held0);
            for _ in 0..50 {
                assert_eq!(pick(&g, &ctx), Some(0), "{algo}");
            }
            drop(held);
            assert!(!g.any_saturated());
        }
    }

    #[test]
    fn saturation_is_not_confused_with_being_down() {
        let g = capped_group("round_robin", 2, 1);
        g.backends[0].set_healthy(false);
        let _held = g.backends[1].try_track().unwrap();
        assert!(g.any_saturated(), "backend 1 is up but full");
        g.backends[1].set_healthy(false);
        assert!(!g.any_saturated(), "nothing is up at all: that is an outage, not saturation");
        assert_eq!(pick(&g, &PickCtx::default()), None);
    }
}
