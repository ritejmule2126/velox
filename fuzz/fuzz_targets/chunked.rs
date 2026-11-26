//! Fuzz the chunked-body framing validator.
#![no_main]

use libfuzzer_sys::fuzz_target;
use velox_core::sanitize::ChunkedDecoder;

fuzz_target!(|data: &[u8]| {
    let mut whole = ChunkedDecoder::new(4096);
    let a = whole.feed(data);
    // Byte-at-a-time must agree with all-at-once.
    let mut dripped = ChunkedDecoder::new(4096);
    let mut consumed = 0;
    let mut finished = false;
    let mut errored = false;
    for b in data {
        match dripped.feed(std::slice::from_ref(b)) {
            Ok((n, done)) => {
                consumed += n;
                if done {
                    finished = true;
                    break;
                }
            }
            Err(_) => {
                errored = true;
                break;
            }
        }
    }
    match a {
        Ok((n, done)) => {
            assert!(!errored);
            assert_eq!((n, done), (consumed, finished));
        }
        Err(_) => assert!(errored),
    }
});
