//! Fuzz the PROXY protocol v1/v2 parser: it sees attacker-controlled bytes
//! before any TLS or HTTP, so it must be total and exact.
#![no_main]

use libfuzzer_sys::fuzz_target;
use velox_proxy::proxy_protocol::{encode_v1, encode_v2, parse, Parsed, MAX_HEADER_LEN};

fuzz_target!(|data: &[u8]| {
    if let Parsed::Header { len, header } = parse(data) {
        assert!(len <= data.len() && len <= MAX_HEADER_LEN, "header length out of bounds");
        // A header is exactly its own bytes: no proper prefix is complete or invalid…
        for cut in 0..len.min(64) {
            assert_eq!(parse(&data[..cut]), Parsed::Incomplete, "prefix {cut} of a {len}-byte header");
        }
        // …and whatever follows must not change the answer.
        let mut longer = data[..len].to_vec();
        longer.extend_from_slice(b"GET / HTTP/1.1\r\n");
        assert_eq!(parse(&longer), Parsed::Header { len, header });
        // Addresses survive a re-encode in either version.
        if let (Some(c), Some(s)) = (header.client, header.server) {
            for wire in [encode_v1(c, s), encode_v2(c, s, &[])] {
                match parse(&wire) {
                    Parsed::Header { header: again, .. } => {
                        assert_eq!((again.client, again.server), (Some(c), Some(s)));
                    }
                    other => panic!("re-encoded header rejected: {other:?}"),
                }
            }
        }
    }
});
