//! Fuzz host validation and typed header handling (HTTP/2 and HTTP/3 path).
#![no_main]

use http::{HeaderMap, HeaderName, HeaderValue, Uri, Version};
use libfuzzer_sys::fuzz_target;
use velox_core::sanitize::{
    apply_forwarded_headers, host_without_port, is_websocket_upgrade, strip_hop_by_hop, validate_host,
    validate_request_headers,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if validate_host(s).is_ok() {
            // Accepted hosts must be routable text with no separators or controls.
            assert!(!s.contains(['/', '\\', '@', ' ', '?', '#']));
            let _ = host_without_port(s);
        }
        // Treat the input as `name: value` lines.
        let mut headers = HeaderMap::new();
        for line in s.lines().take(64) {
            if let Some((k, v)) = line.split_once(':') {
                if let (Ok(k), Ok(v)) = (HeaderName::from_bytes(k.trim().as_bytes()), HeaderValue::from_str(v.trim())) {
                    headers.append(k, v);
                }
            }
        }
        let uri: Uri = "/x".parse().expect("static uri");
        for v in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
            let _ = validate_request_headers(v, &headers, &uri);
        }
        let _ = is_websocket_upgrade(&headers);
        apply_forwarded_headers(&mut headers, "203.0.113.7".parse().expect("ip"), &[], "https", Some("example.com"));
        strip_hop_by_hop(&mut headers);
        for n in ["connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade", "proxy-connection"] {
            assert!(!headers.contains_key(n), "hop-by-hop header {n} survived");
        }
    }
});
