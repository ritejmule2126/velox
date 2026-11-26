//! Fuzz W3C `traceparent` parsing and propagation: arbitrary header bytes must
//! never panic, accepted values must round-trip, and propagation must always
//! leave exactly one valid `traceparent`.
#![no_main]

use http::{HeaderMap, HeaderValue};
use libfuzzer_sys::fuzz_target;
use velox_core::trace::{parse_traceparent, propagate, TRACEPARENT, TRACESTATE};

fuzz_target!(|data: &[u8]| {
    if let Some(p) = parse_traceparent(data) {
        assert_ne!(p.trace_id, [0; 16]);
        assert_ne!(p.span_id, [0; 8]);
        assert_eq!(parse_traceparent(p.to_header().as_bytes()), Some(p), "accepted values re-encode");
    }
    // Feed it as one or several header lines, with a tracestate beside it.
    let mut headers = HeaderMap::new();
    for line in data.split(|b| *b == b'\n').take(4) {
        if let Ok(v) = HeaderValue::from_bytes(line) {
            headers.append(TRACEPARENT, v);
        }
    }
    headers.insert(TRACESTATE, HeaderValue::from_static("vendor=opaque"));
    let out = propagate(&mut headers);
    assert_eq!(headers.get_all(TRACEPARENT).iter().count(), 1);
    assert_eq!(parse_traceparent(headers[TRACEPARENT].as_bytes()), Some(out.context));
    assert!(out.continued || !headers.contains_key(TRACESTATE), "tracestate never travels without a valid parent");
});
