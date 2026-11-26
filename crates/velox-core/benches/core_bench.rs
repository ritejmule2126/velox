//! Micro-benchmarks for the hot-path pieces of `velox-core`.
//!
//! Run with `cargo bench -p velox-core`.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use http::{HeaderMap, HeaderValue};
use velox_core::sanitize::{apply_forwarded_headers, parse_request_head, strip_hop_by_hop, H1Guard, H1Limits};
use velox_core::{Config, SharedState};

const REQUEST: &[u8] = b"GET /api/v1/users/42?expand=profile HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: bench/1.0\r\nAccept: application/json\r\nAccept-Encoding: gzip, br\r\nAuthorization: Bearer abcdefghijklmnopqrstuvwxyz\r\nX-Request-Id: 7c1b6e1a\r\nConnection: keep-alive\r\n\r\n";

fn sanitize(c: &mut Criterion) {
    let limits = H1Limits::default();
    let mut g = c.benchmark_group("sanitize");
    g.throughput(Throughput::Bytes(REQUEST.len() as u64));
    g.bench_function("parse_request_head", |b| {
        b.iter(|| parse_request_head(black_box(REQUEST), &limits).unwrap());
    });
    g.bench_function("h1_guard_feed_one_request", |b| {
        let mut guard = H1Guard::new(limits);
        b.iter(|| guard.feed(black_box(REQUEST)).map(|r| r.len).unwrap());
    });
    g.finish();

    let mut headers = HeaderMap::new();
    for (k, v) in [
        ("connection", "keep-alive, x-trace"),
        ("keep-alive", "timeout=5"),
        ("x-trace", "1"),
        ("te", "trailers"),
        ("host", "example.com"),
        ("accept", "*/*"),
    ] {
        headers.append(http::HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_static(v));
    }
    c.bench_function("sanitize/strip_hop_by_hop", |b| {
        b.iter_batched(|| headers.clone(), |mut h| strip_hop_by_hop(&mut h), criterion::BatchSize::SmallInput);
    });
    let peer = "203.0.113.5".parse().unwrap();
    c.bench_function("sanitize/apply_forwarded_headers", |b| {
        b.iter_batched(
            || headers.clone(),
            |mut h| apply_forwarded_headers(&mut h, peer, &[], "https", Some("example.com")),
            criterion::BatchSize::SmallInput,
        );
    });
}

fn routing(c: &mut Criterion) {
    let mut toml = String::from("[server]\nhttp_addr = \"127.0.0.1:8080\"\n[[upstream]]\nname = \"u\"\nbackends = [{ addr = \"127.0.0.1:1\" }]\n");
    for i in 0..500 {
        toml.push_str(&format!("[[route]]\nhosts = [\"svc{i}.example.com\"]\nupstream = \"u\"\n"));
    }
    toml.push_str("[[route]]\nhosts = [\"*.wild.example.com\"]\npath_prefix = \"/api\"\nupstream = \"u\"\n");
    let state = SharedState::new(Config::from_toml_str(&toml).unwrap()).unwrap();
    c.bench_function("router/exact_host_of_500", |b| {
        b.iter(|| {
            let snap = state.load();
            black_box(snap.router.find(black_box("svc321.example.com"), "/x").is_some())
        });
    });
    c.bench_function("router/wildcard_host_with_prefix", |b| {
        b.iter(|| {
            let snap = state.load();
            black_box(snap.router.find(black_box("a.wild.example.com"), "/api/v1").is_some())
        });
    });
    c.bench_function("state/load_snapshot", |b| b.iter(|| black_box(state.load().generation)));
}

criterion_group!(benches, sanitize, routing);
criterion_main!(benches);
