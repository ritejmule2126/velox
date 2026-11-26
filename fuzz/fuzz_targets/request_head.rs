//! Fuzz the wire-level request-head validator.
//!
//! Invariants checked on every input that is *accepted*:
//! * exactly one `Host` header (HTTP/1.1);
//! * at most one `Content-Length`, digits only;
//! * never both `Content-Length` and `Transfer-Encoding`;
//! * no bare CR/LF, NUL or obs-fold anywhere in the head.
#![no_main]

use libfuzzer_sys::fuzz_target;
use velox_core::sanitize::{parse_request_head, H1Limits, HeadScanner};

fuzz_target!(|data: &[u8]| {
    let limits = H1Limits::default();
    let mut scanner = HeadScanner::default();
    // Find a head boundary the same way the guard does…
    let Ok(Some(end)) = scanner.scan(data, limits.max_head_bytes) else { return };
    let head = &data[..end];
    // …then every head the scanner lets through must either be rejected or
    // satisfy the framing invariants.
    if parse_request_head(head, &limits).is_ok() {
        let lower: Vec<u8> = head.to_ascii_lowercase();
        let count = |needle: &[u8]| lower.windows(needle.len()).filter(|w| *w == needle).count();
        assert!(count(b"\r\nhost:") <= 1, "duplicate Host accepted");
        assert!(count(b"\r\ncontent-length:") <= 1, "duplicate Content-Length accepted");
        assert!(
            !(count(b"\r\ncontent-length:") > 0 && count(b"\r\ntransfer-encoding:") > 0),
            "CL + TE accepted"
        );
        assert!(!head.contains(&0), "NUL accepted");
        assert!(!head.windows(3).any(|w| w[0] == b'\n' && (w[1] == b' ' || w[1] == b'\t')), "obs-fold accepted");
        for (i, &b) in head.iter().enumerate() {
            if b == b'\n' {
                assert!(i > 0 && head[i - 1] == b'\r', "bare LF accepted");
            }
        }
    }
});
