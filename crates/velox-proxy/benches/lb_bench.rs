//! Load-balancer selection and rate-limiter micro-benchmarks.
//!
//! Run with `cargo bench -p velox-proxy`.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::sync::Arc;
use velox_core::upstream::hash64;
use velox_core::{Config, SharedState, UpstreamGroup};
use velox_proxy::lb::{pick, PickCtx};

fn group(algo: &str, n: usize) -> Arc<UpstreamGroup> {
    let backends: Vec<String> = (0..n).map(|i| format!("{{ addr = \"10.0.{}.{}:80\" }}", i / 250, i % 250)).collect();
    let text = format!(
        "[server]\nhttp_addr = \"127.0.0.1:1\"\n[[upstream]]\nname = \"a\"\nalgorithm = \"{algo}\"\nbackends = [{}]\n",
        backends.join(",")
    );
    let state = SharedState::new(Config::from_toml_str(&text).unwrap()).unwrap();
    Arc::clone(&state.load().upstreams["a"])
}

fn selection(c: &mut Criterion) {
    let mut g = c.benchmark_group("lb/pick");
    for algo in ["round_robin", "least_conn", "p2c", "consistent_hash"] {
        for n in [4usize, 32, 128] {
            let grp = group(algo, n);
            let mut key = 0u64;
            g.bench_with_input(BenchmarkId::new(algo, n), &grp, |b, grp| {
                b.iter(|| {
                    key = key.wrapping_add(0x9e37_79b9);
                    let ctx = PickCtx { hash: hash64(&key.to_le_bytes()), exclude: 0 };
                    black_box(pick(grp, &ctx))
                });
            });
        }
    }
    g.finish();
}

fn rate_limit(c: &mut Criterion) {
    use velox_security::{RateKey, RateLimiter};
    let rl = RateLimiter::new(1e9, 1_000_000);
    let keys: Vec<RateKey> =
        (0..1024u32).map(|i| RateKey::Ip(std::net::IpAddr::from(std::net::Ipv4Addr::from(i)))).collect();
    let mut i = 0usize;
    c.bench_function("ratelimit/check_1024_keys", |b| {
        b.iter(|| {
            i = (i + 1) % keys.len();
            black_box(rl.check(keys[i]))
        });
    });
}

criterion_group!(benches, selection, rate_limit);
criterion_main!(benches);
