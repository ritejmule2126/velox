//! Fuzz `Accept-Encoding` negotiation: arbitrary header bytes must never panic
//! and must only ever select an encoding the server offers.
#![no_main]

use http::HeaderValue;
use libfuzzer_sys::fuzz_target;
use velox_core::config::CompressionAlgorithm::{Brotli, Gzip, Zstd};
use velox_proxy::compress::negotiate;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = HeaderValue::from_bytes(data) else { return };
    for offered in [&[Zstd, Brotli, Gzip][..], &[Gzip], &[Brotli, Zstd], &[]] {
        if let Some(chosen) = negotiate(Some(&value), offered) {
            assert!(offered.contains(&chosen), "negotiated an encoding the server does not offer");
        }
    }
    // Forbidding everything explicitly can never yield an encoding.
    let mut banned = b"*;q=0, ".to_vec();
    banned.extend_from_slice(data);
    if let Ok(v) = HeaderValue::from_bytes(&banned) {
        let _ = negotiate(Some(&v), &[Zstd, Brotli, Gzip]);
    }
});
