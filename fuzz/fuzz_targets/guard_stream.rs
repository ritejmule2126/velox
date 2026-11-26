//! Fuzz the stateful HTTP/1 guard with arbitrarily segmented input.
//!
//! Invariants: it never panics, and for any input the verdict (accept /
//! reject) and the released byte stream are identical no matter how the bytes
//! are split across reads.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use velox_core::sanitize::{H1Guard, H1Limits};

#[derive(Debug, Arbitrary)]
struct Input {
    data: Vec<u8>,
    split: u8,
}

fn run(data: &[u8], split: usize) -> (bool, Vec<u8>) {
    let mut guard = H1Guard::new(H1Limits::default());
    let mut released = Vec::new();
    for chunk in data.chunks(split.max(1)) {
        match guard.feed(chunk) {
            Ok(rel) => {
                released.extend_from_slice(&rel.carried);
                released.extend_from_slice(&chunk[rel.skip..rel.len]);
            }
            Err(_) => return (false, released),
        }
    }
    (true, released)
}

fuzz_target!(|input: Input| {
    let whole = run(&input.data, input.data.len().max(1));
    let split = run(&input.data, usize::from(input.split).max(1));
    assert_eq!(whole.0, split.0, "verdict depends on segmentation");
    if whole.0 {
        // Released bytes are always a prefix of the input (a trailing partial
        // head may still be withheld).
        assert!(input.data.starts_with(&whole.1));
        assert_eq!(whole.1, split.1, "released stream depends on segmentation");
    }
});
