//! Fuzz edge JWT verification.
//!
//! Two angles: the raw bytes as a token (structure / encoding / size handling),
//! and the bytes split into a header and a payload that are then *correctly
//! signed*, so the fuzzer reaches the claim checks that only run after the
//! signature passes. Invariants: never panic; anything accepted carries a valid
//! signature, an `exp`, and an object payload.
#![no_main]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use libfuzzer_sys::fuzz_target;
use std::time::SystemTime;
use velox_core::config::{JwtAlgorithm, JwtConfig};
use velox_security::jwt::{verify_token, KeySet};

const SECRET: &[u8] = b"fuzzing-secret-fuzzing-secret-0123456789";

fuzz_target!(|data: &[u8]| {
    let cfg = JwtConfig {
        algorithms: vec![JwtAlgorithm::HS256],
        issuer: Some("https://issuer.test".into()),
        audience: vec!["api".into()],
        ..JwtConfig::default()
    };
    let Ok(keys) = KeySet::hmac(SECRET) else { return };
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, SECRET);
    let now = SystemTime::now();

    // 1. The bytes as a token.
    if let Ok(token) = std::str::from_utf8(data) {
        if let Ok(claims) = verify_token(&cfg, &keys, token, now) {
            let (signing_input, sig) = token.rsplit_once('.').expect("an accepted token has three parts");
            let expected = ring::hmac::sign(&key, signing_input.as_bytes());
            assert_eq!(URL_SAFE_NO_PAD.decode(sig).expect("valid base64url"), expected.as_ref(), "accepted without a valid signature");
            assert!(claims.contains_key("exp"));
        }
    }

    // 2. The bytes as header + payload under a *valid* signature.
    let (header, payload) = data.split_at(data.len() / 2);
    let signing_input = format!("{}.{}", URL_SAFE_NO_PAD.encode(header), URL_SAFE_NO_PAD.encode(payload));
    let sig = ring::hmac::sign(&key, signing_input.as_bytes());
    let token = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()));
    if let Ok(claims) = verify_token(&cfg, &keys, &token, now) {
        // Whatever got through must be a JSON object that names the right issuer and audience.
        assert_eq!(claims.get("iss").and_then(|v| v.as_str()), Some("https://issuer.test"));
        assert!(claims.contains_key("exp") && claims.contains_key("aud"));
    }
});
