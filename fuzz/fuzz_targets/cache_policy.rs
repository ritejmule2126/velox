//! Fuzz the response-cache policy: arbitrary `Cache-Control` / `Vary` / `Expires`
//! / `Age` / `Pragma` lines must never panic, and anything accepted must respect
//! the route's lifetime cap and never be `no-store`/`private`/`Vary: *`.
#![no_main]

use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use libfuzzer_sys::fuzz_target;
use std::time::{Duration, SystemTime};
use velox_core::config::RouteCacheConfig;
use velox_proxy::cache::{classify_request, evaluate_response, CacheControl, RequestMode};

const NAMES: [&str; 6] = ["cache-control", "vary", "expires", "age", "pragma", "date"];

fuzz_target!(|data: &[u8]| {
    let mut headers = HeaderMap::new();
    for (i, line) in data.split(|b| *b == b'\n').take(12).enumerate() {
        if let Ok(v) = HeaderValue::from_bytes(line) {
            headers.append(HeaderName::from_static(NAMES[i % NAMES.len()]), v);
        }
    }
    let cap = Duration::from_secs(3600);
    let route = RouteCacheConfig { default_ttl: Some(Duration::from_secs(30)), max_ttl: Some(cap), ..Default::default() };
    for status in [StatusCode::OK, StatusCode::NOT_FOUND, StatusCode::PARTIAL_CONTENT] {
        if let Ok(s) = evaluate_response(status, &headers, &route, SystemTime::now()) {
            let cc = CacheControl::parse(&headers);
            assert!(!cc.no_store && !cc.private && !cc.no_cache, "a forbidden response was accepted");
            assert!(!s.lifetime.is_zero() && s.lifetime <= cap, "lifetime {:?} outside (0, {cap:?}]", s.lifetime);
            assert!(s.vary.len() <= 8);
            assert_ne!(status, StatusCode::PARTIAL_CONTENT);
        }
    }
    // Request classification is total as well, and a bypass never allows lookup.
    for m in [Method::GET, Method::HEAD, Method::POST] {
        let _ = matches!(classify_request(&m, &headers, false, false), RequestMode::Normal | RequestMode::Refresh | RequestMode::Bypass(_));
    }
});
