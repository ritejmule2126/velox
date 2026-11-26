//! Tests for the strict parsing layer, organised by attack class.

use super::*;
use http::{header::HeaderValue, HeaderMap, Method, Uri, Version};
use proptest::prelude::*;
use std::net::IpAddr;

fn vrh(v: Version, h: &HeaderMap, u: &Uri) -> Result<(), Violation> {
    validate_request_headers(v, h, u, false)
}

fn limits() -> H1Limits {
    H1Limits::default()
}

fn feed_all(guard: &mut H1Guard, data: &[u8]) -> Result<(), GuardError> {
    guard.feed(data).map(|_| ())
}

/// Feed `chunks`, returning every byte the guard released, in order.
fn released_stream(guard: &mut H1Guard, chunks: &[&[u8]]) -> Result<Vec<u8>, GuardError> {
    let mut out = Vec::new();
    for c in chunks {
        let r = guard.feed(c)?;
        out.extend_from_slice(r.carried);
        out.extend_from_slice(&c[r.skip..r.len]);
    }
    Ok(out)
}

fn head(raw: &str) -> Result<HeadInfo, Violation> {
    parse_request_head(raw.as_bytes(), &limits())
}

fn guard_err(raw: &[u8]) -> Violation {
    let mut g = H1Guard::new(limits());
    feed_all(&mut g, raw).expect_err("must be rejected").violation
}

const OK: &str = "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n";

#[test]
fn accepts_plain_get() {
    let info = head(OK).unwrap();
    assert_eq!(info.framing, BodyFraming::None);
    assert!(!info.upgrade);
}

#[test]
fn accepts_content_length_and_chunked_bodies() {
    let info = head("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\n").unwrap();
    assert_eq!(info.framing, BodyFraming::Length(5));
    let info = head("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: Chunked\r\n\r\n").unwrap();
    assert_eq!(info.framing, BodyFraming::Chunked);
}

// ---------- classic smuggling vectors ----------

#[test]
fn rejects_cl_te() {
    let r = head("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n");
    assert_eq!(r, Err(Violation::ContentLengthWithTransferEncoding));
}

#[test]
fn rejects_te_cl() {
    let r = head("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n");
    assert_eq!(r, Err(Violation::ContentLengthWithTransferEncoding));
}

#[test]
fn rejects_te_te_obfuscations() {
    let variants = [
        "Transfer-Encoding: xchunked",
        "Transfer-Encoding: chunked, identity",
        "Transfer-Encoding: identity, chunked",
        "Transfer-Encoding: chunked, chunked",
        "Transfer-Encoding: chunk",
        "Transfer-Encoding: \u{b}chunked",
        "Transfer-Encoding: chunked;q=1",
        "Transfer-Encoding: \"chunked\"",
        "Transfer-Encoding:\tchunked\u{1}",
    ];
    for v in variants {
        let raw = format!("POST / HTTP/1.1\r\nHost: a\r\n{v}\r\n\r\n");
        assert!(head(&raw).is_err() || guard_err_bytes(raw.as_bytes()), "accepted: {v:?}");
    }
}

fn guard_err_bytes(raw: &[u8]) -> bool {
    let mut g = H1Guard::new(limits());
    g.feed(raw).is_err()
}

#[test]
fn rejects_duplicate_transfer_encoding_headers() {
    let r = head("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n");
    assert_eq!(r, Err(Violation::TransferEncoding));
}

#[test]
fn rejects_duplicate_or_malformed_content_length() {
    for v in [
        "Content-Length: 5\r\nContent-Length: 5",
        "Content-Length: 5\r\nContent-Length: 6",
        "Content-Length: 5, 5",
        "Content-Length: +5",
        "Content-Length: -1",
        "Content-Length: 0x10",
        "Content-Length: 5 5",
        "Content-Length: ",
        "Content-Length: 99999999999999999999999",
        "Content-Length: 1e3",
    ] {
        let raw = format!("POST / HTTP/1.1\r\nHost: a\r\n{v}\r\n\r\n");
        assert_eq!(head(&raw), Err(Violation::ContentLength), "{v}");
    }
}

#[test]
fn unsupported_but_clean_coding_is_501() {
    let r = head("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n");
    assert_eq!(r, Err(Violation::UnsupportedTransferCoding));
    assert_eq!(Violation::UnsupportedTransferCoding.status(), http::StatusCode::NOT_IMPLEMENTED);
}

#[test]
fn rejects_underscore_framing_header_aliases() {
    for n in ["Transfer_Encoding", "Content_Length", "transfer_encoding", "CONTENT_LENGTH"] {
        let raw = format!("POST / HTTP/1.1\r\nHost: a\r\n{n}: chunked\r\n\r\n");
        assert_eq!(head(&raw), Err(Violation::AmbiguousHeaderName), "{n}");
    }
    // Unrelated underscore headers are fine.
    assert!(head("GET / HTTP/1.1\r\nHost: a\r\nX_Custom: 1\r\n\r\n").is_ok());
}

#[test]
fn rejects_connection_nominating_framing_headers() {
    for t in ["Content-Length", "host", "Transfer-Encoding", "close, content-length"] {
        let raw = format!("POST / HTTP/1.1\r\nHost: a\r\nConnection: {t}\r\nContent-Length: 1\r\n\r\n");
        assert_eq!(head(&raw), Err(Violation::ConnectionNominatesFraming), "{t}");
    }
}

// ---------- obs-fold, NUL, control characters, line endings ----------

#[test]
fn rejects_obs_fold() {
    assert_eq!(guard_err(b"GET / HTTP/1.1\r\nHost: a\r\nX: 1\r\n  folded\r\n\r\n"), Violation::ObsFold);
    assert_eq!(guard_err(b"GET / HTTP/1.1\r\nHost: a\r\nX: 1\r\n\tfolded\r\n\r\n"), Violation::ObsFold);
    // The classic TE-obfuscation fold.
    assert_eq!(guard_err(b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding:\r\n chunked\r\n\r\n"), Violation::ObsFold);
}

#[test]
fn rejects_nul_and_control_bytes() {
    assert_eq!(guard_err(b"GET / HTTP/1.1\r\nHost: a\r\nX: a\0b\r\n\r\n"), Violation::ControlCharacter);
    assert_eq!(guard_err(b"GET /\0 HTTP/1.1\r\nHost: a\r\n\r\n"), Violation::ControlCharacter);
    assert_eq!(guard_err(b"GET / HTTP/1.1\r\nHost: a\r\nX: \x07\r\n\r\n"), Violation::ControlCharacter);
    assert_eq!(guard_err(b"GET / HTTP/1.1\r\nHost: a\r\nX: \x7f\r\n\r\n"), Violation::ControlCharacter);
    // Horizontal tab inside a value is legal.
    assert!(guard_ok(b"GET / HTTP/1.1\r\nHost: a\r\nX: a\tb\r\n\r\n"));
}

fn guard_ok(raw: &[u8]) -> bool {
    H1Guard::new(limits()).feed(raw).is_ok()
}

#[test]
fn rejects_bare_lf_and_bare_cr() {
    assert_eq!(guard_err(b"GET / HTTP/1.1\nHost: a\n\n"), Violation::BareLineEnding);
    assert_eq!(guard_err(b"GET / HTTP/1.1\r\nHost: a\nX: 1\r\n\r\n"), Violation::BareLineEnding);
    assert_eq!(guard_err(b"GET / HTTP/1.1\r\nHost: a\rX: 1\r\n\r\n"), Violation::BareLineEnding);
    // CR at the very end of one read, junk at the start of the next.
    let mut g = H1Guard::new(limits());
    g.feed(b"GET / HTTP/1.1\r\nHost: a\r").unwrap();
    assert_eq!(g.feed(b"X").unwrap_err().violation, Violation::BareLineEnding);
}

#[test]
fn rejects_leading_blank_line() {
    assert_eq!(guard_err(b"\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n"), Violation::Malformed);
}

#[test]
fn rejects_space_before_colon_and_bad_names() {
    assert!(head("GET / HTTP/1.1\r\nHost: a\r\nX-Foo : 1\r\n\r\n").is_err());
    assert!(head("GET / HTTP/1.1\r\nHost: a\r\nX Foo: 1\r\n\r\n").is_err());
    assert!(head("GET / HTTP/1.1\r\nHost: a\r\n: novalue\r\n\r\n").is_err());
}

// ---------- host, target, method, version ----------

#[test]
fn host_rules() {
    assert_eq!(head("GET / HTTP/1.1\r\n\r\n"), Err(Violation::Host));
    assert_eq!(head("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"), Err(Violation::Host));
    assert!(head("GET / HTTP/1.0\r\n\r\n").is_ok());
    for bad in [
        "", "a b", "a@b", "a/b", "a\\b", "a?b", "a#b", "[::1", "::1", "a:", "a:99999", "a:b", "-a.com", "a..b", "a_b c",
    ] {
        let raw = format!("GET / HTTP/1.1\r\nHost: {bad}\r\n\r\n");
        assert!(head(&raw).is_err(), "accepted host {bad:?}");
    }
    for good in
        ["example.com", "example.com:8080", "[::1]:443", "[2001:db8::1]", "127.0.0.1:80", "a.b-c.d-e", "example.com."]
    {
        let raw = format!("GET / HTTP/1.1\r\nHost: {good}\r\n\r\n");
        assert!(head(&raw).is_ok(), "rejected host {good:?}");
    }
}

#[test]
fn target_method_version_rules() {
    assert_eq!(head("GET http://evil/ HTTP/1.1\r\nHost: a\r\n\r\n"), Err(Violation::Target));
    assert_eq!(head("GET x HTTP/1.1\r\nHost: a\r\n\r\n"), Err(Violation::Target));
    assert_eq!(head("CONNECT a:443 HTTP/1.1\r\nHost: a\r\n\r\n"), Err(Violation::Method));
    assert_eq!(head("TRACE / HTTP/1.1\r\nHost: a\r\n\r\n"), Err(Violation::Method));
    assert!(head("OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n").is_ok());
    assert_eq!(head("GET * HTTP/1.1\r\nHost: a\r\n\r\n"), Err(Violation::Target));
    assert!(head("GET / HTTP/2.0\r\nHost: a\r\n\r\n").is_err());
    let long = format!("GET /{} HTTP/1.1\r\nHost: a\r\n\r\n", "a".repeat(9000));
    assert_eq!(head(&long), Err(Violation::UriTooLong));
}

#[test]
fn te_on_http10_rejected() {
    assert_eq!(head("POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n"), Err(Violation::TransferEncoding));
}

#[test]
fn size_and_count_limits() {
    let mut raw = String::from("GET / HTTP/1.1\r\nHost: a\r\n");
    for i in 0..101 {
        raw.push_str(&format!("X-{i}: v\r\n"));
    }
    raw.push_str("\r\n");
    assert_eq!(head(&raw), Err(Violation::TooManyHeaders));

    let big = format!("GET / HTTP/1.1\r\nHost: a\r\nX: {}\r\n\r\n", "a".repeat(20_000));
    assert_eq!(guard_err(big.as_bytes()), Violation::HeadTooLarge);

    // Slow drip never grows past the limit either.
    let mut g = H1Guard::new(H1Limits { max_head_bytes: 64, ..limits() });
    let mut err = None;
    for _ in 0..200 {
        if let Err(e) = g.feed(b"a") {
            err = Some(e.violation);
            break;
        }
    }
    assert_eq!(err, Some(Violation::HeadTooLarge));
}

// ---------- upgrade ----------

#[test]
fn websocket_upgrade_detection() {
    let ok =
        head("GET /ws HTTP/1.1\r\nHost: a\r\nConnection: keep-alive, Upgrade\r\nUpgrade: WebSocket\r\n\r\n").unwrap();
    assert!(ok.upgrade);
    // h2c upgrade is not honoured (and so does not disable inspection).
    let h2c = head("GET / HTTP/1.1\r\nHost: a\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n\r\n").unwrap();
    assert!(!h2c.upgrade);
    assert_eq!(
        head("POST /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nContent-Length: 3\r\n\r\n"),
        Err(Violation::UpgradeWithBody)
    );
}

#[test]
fn guard_stops_inspecting_after_websocket_upgrade() {
    let mut g = H1Guard::new(limits());
    g.feed(b"GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").unwrap();
    assert!(g.is_passthrough());
    g.feed(b"\x81\x05hello\r\n\0\0garbage not http").unwrap();
}

// ---------- guard: pipelining, bodies, chunked ----------

#[test]
fn guard_tracks_pipelined_messages_across_arbitrary_splits() {
    let stream: Vec<u8> = [
        &b"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello"[..],
        b"POST /b HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n5;ext=1\r\nhello\r\n0\r\nX-T: 1\r\n\r\n",
        b"GET /c HTTP/1.1\r\nHost: a\r\n\r\n",
    ]
    .concat();
    for chunk in [1usize, 2, 3, 7, 13, 64, stream.len()] {
        let mut g = H1Guard::new(limits());
        for part in stream.chunks(chunk) {
            g.feed(part).unwrap_or_else(|e| panic!("chunk={chunk}: {e:?}"));
        }
    }
}

#[test]
fn guard_catches_smuggled_request_hidden_in_body_position() {
    // Declared CL=0, then a second, malformed (CL.TE) request follows.
    let raw = b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\nPOST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n";
    assert_eq!(guard_err(raw), Violation::ContentLengthWithTransferEncoding);
    // A second request smuggled *after* the declared body is still inspected.
    let raw = b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n\r\nxGET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n";
    assert_eq!(guard_err(raw), Violation::Host);
}

#[test]
fn partial_heads_are_withheld_until_the_whole_head_validates() {
    let mut g = H1Guard::new(limits());
    let r = g.feed(b"GET /a HTTP/1.1\r\nHost: ex").unwrap();
    assert_eq!((r.carried.len(), r.len), (0, 0), "nothing of an unfinished head is released");
    assert!(g.has_partial_head());
    let r = g.feed(b"ample.com\r\n\r\nGET /b HTTP/1.1\r\nHo").unwrap();
    assert_eq!(r.carried, b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n");
    assert!(r.partial_head);
    assert_eq!((r.skip, r.len), (13, 13), "the rest of the chunk is the next, still-partial head");
    assert!(g.has_partial_head(), "second head is withheld again");
}

#[test]
fn violation_in_a_later_segment_releases_none_of_the_poisoned_head() {
    let mut g = H1Guard::new(limits());
    // First segment looks innocent; the CL+TE conflict only appears in the second.
    let first = g.feed(b"POST /admin HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nX-Pad: ").unwrap();
    assert_eq!(first.len, 0);
    let err = g.feed(b"1\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap_err();
    assert_eq!(err.violation, Violation::ContentLengthWithTransferEncoding);
}

#[test]
fn released_bytes_equal_input_for_valid_streams_under_any_segmentation() {
    let stream: Vec<u8> = [
        &b"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello"[..],
        b"GET /b HTTP/1.1\r\nHost: a\r\nX-Long: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n",
        b"POST /c HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
        b"GET /d HTTP/1.1\r\nHost: a\r\n\r\n",
    ]
    .concat();
    for seg in [1usize, 2, 5, 11, 29, 100, stream.len()] {
        let chunks: Vec<&[u8]> = stream.chunks(seg).collect();
        let out = released_stream(&mut H1Guard::new(limits()), &chunks).unwrap();
        assert_eq!(out, stream, "segmentation {seg}");
    }
}

#[test]
fn chunked_framing_violations() {
    let pre = b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n";
    for (body, label) in [
        (&b"zz\r\n"[..], "non-hex size"),
        (b"-1\r\n", "negative size"),
        (b"\r\n", "empty size"),
        (b"3\r\nabcXX", "missing chunk terminator"),
        (b"3\nabc\r\n", "bare LF after size"),
        (b"10000000000000000\r\n", "size overflow (17 digits)"),
        (b"3 \r\nabc\r\n", "space in size"),
        (b"0\r\nContent-Length: 5\r\n\r\n", "CL trailer"),
        (b"0\r\nTransfer-Encoding: chunked\r\n\r\n", "TE trailer"),
        (b"0\r\nHost: evil\r\n\r\n", "Host trailer"),
        (b"0\r\nX: a\nY: b\r\n\r\n", "bare LF in trailer"),
        (b"0\r\n X: folded\r\n\r\n", "folded trailer"),
    ] {
        let mut g = H1Guard::new(limits());
        g.feed(pre).unwrap();
        let err = g.feed(body).expect_err(label);
        assert_eq!(err.violation, Violation::Chunk, "{label}");
        assert!(!err.at_message_boundary, "{label}");
    }
}

#[test]
fn chunked_decoder_stops_at_message_end() {
    let mut d = ChunkedDecoder::new(1024);
    let data = b"3\r\nabc\r\n0\r\n\r\nGET / HTTP/1.1\r\n";
    let (n, done) = d.feed(data).unwrap();
    assert!(done);
    assert_eq!(&data[n..], b"GET / HTTP/1.1\r\n");
}

// ---------- typed validation (all protocols) ----------

fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
        h.append(http::HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap());
    }
    h
}

#[test]
fn typed_h2_rejects_connection_specific_headers() {
    let uri: Uri = "https://example.com/".parse().unwrap();
    for (k, v) in [
        ("connection", "close"),
        ("keep-alive", "1"),
        ("upgrade", "websocket"),
        ("transfer-encoding", "chunked"),
        ("te", "gzip"),
    ] {
        let h = hm(&[(k, v)]);
        assert_eq!(vrh(Version::HTTP_2, &h, &uri), Err(Violation::ConnectionSpecificHeader), "{k}");
    }
    assert!(vrh(Version::HTTP_2, &hm(&[("te", "trailers")]), &uri).is_ok());
    assert!(vrh(Version::HTTP_3, &hm(&[]), &uri).is_ok());
}

#[test]
fn typed_rejects_authority_host_mismatch_and_cl_te() {
    let uri: Uri = "https://example.com/".parse().unwrap();
    assert_eq!(vrh(Version::HTTP_2, &hm(&[("host", "evil.com")]), &uri), Err(Violation::Host));
    assert!(vrh(Version::HTTP_2, &hm(&[("host", "EXAMPLE.com")]), &uri).is_ok());
    let origin: Uri = "/p".parse().unwrap();
    assert_eq!(
        vrh(
            Version::HTTP_11,
            &hm(&[("host", "a"), ("content-length", "1"), ("transfer-encoding", "chunked")]),
            &origin
        ),
        Err(Violation::ContentLengthWithTransferEncoding)
    );
    assert_eq!(
        vrh(Version::HTTP_11, &hm(&[("host", "a"), ("content-length", "1"), ("content-length", "1")]), &origin),
        Err(Violation::ContentLength)
    );
    assert_eq!(vrh(Version::HTTP_11, &hm(&[]), &origin), Err(Violation::Host));
    assert_eq!(vrh(Version::HTTP_11, &hm(&[("host", "a"), ("host", "b")]), &origin), Err(Violation::Host));
}

#[test]
fn hop_by_hop_stripping() {
    let mut h = hm(&[
        ("connection", "keep-alive, X-Secret, content-length"),
        ("keep-alive", "timeout=5"),
        ("x-secret", "1"),
        ("proxy-authorization", "x"),
        ("proxy-authenticate", "x"),
        ("te", "trailers"),
        ("trailer", "x"),
        ("transfer-encoding", "chunked"),
        ("upgrade", "websocket"),
        ("content-length", "5"),
        ("host", "a"),
        ("x-keep", "yes"),
    ]);
    strip_hop_by_hop(&mut h);
    let mut names: Vec<_> = h.keys().map(|k| k.as_str().to_owned()).collect();
    names.sort();
    assert_eq!(names, ["content-length", "host", "x-keep"]);
}

#[test]
fn websocket_upgrade_helper() {
    assert!(is_websocket_upgrade(&hm(&[("connection", "Upgrade"), ("upgrade", "websocket")])));
    assert!(!is_websocket_upgrade(&hm(&[("connection", "close"), ("upgrade", "websocket")])));
    assert!(!is_websocket_upgrade(&hm(&[("connection", "upgrade"), ("upgrade", "h2c")])));
}

// ---------- forwarded headers ----------

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn untrusted_peer_cannot_spoof_forwarding_headers() {
    let mut h = hm(&[
        ("x-forwarded-for", "6.6.6.6"),
        ("x-real-ip", "6.6.6.6"),
        ("x-forwarded-proto", "https"),
        ("x-forwarded-host", "evil"),
        ("forwarded", "for=6.6.6.6"),
    ]);
    let client = apply_forwarded_headers(&mut h, ip("203.0.113.9"), &[], "http", Some("example.com"));
    assert_eq!(client, ip("203.0.113.9"));
    assert_eq!(h["x-forwarded-for"], "203.0.113.9");
    assert_eq!(h["x-real-ip"], "203.0.113.9");
    assert_eq!(h["x-forwarded-proto"], "http");
    assert_eq!(h["x-forwarded-host"], "example.com");
    assert_eq!(h["forwarded"], "for=203.0.113.9;proto=http;host=\"example.com\"");
}

#[test]
fn trusted_proxy_chain_is_extended_and_client_resolved() {
    let trusted: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
    let mut h = hm(&[
        ("x-forwarded-for", "198.51.100.7, 10.1.1.1"),
        ("x-forwarded-proto", "https"),
        ("forwarded", "for=198.51.100.7;proto=https"),
    ]);
    let client = apply_forwarded_headers(&mut h, ip("10.2.2.2"), &trusted, "http", Some("example.com"));
    assert_eq!(client, ip("198.51.100.7"));
    assert_eq!(h["x-forwarded-for"], "198.51.100.7, 10.1.1.1, 10.2.2.2");
    assert_eq!(h["x-real-ip"], "198.51.100.7");
    assert_eq!(h["x-forwarded-proto"], "https");
    assert_eq!(h["forwarded"], "for=198.51.100.7;proto=https, for=10.2.2.2;proto=https;host=\"example.com\"");
}

#[test]
fn garbage_xff_from_trusted_peer_is_discarded() {
    let trusted: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
    let mut h = hm(&[("x-forwarded-for", "1.2.3.4, <script>")]);
    let client = apply_forwarded_headers(&mut h, ip("10.0.0.1"), &trusted, "https", None);
    assert_eq!(client, ip("10.0.0.1"));
    assert_eq!(h["x-forwarded-for"], "10.0.0.1");
}

#[test]
fn ipv6_is_quoted_in_forwarded() {
    let mut h = HeaderMap::new();
    apply_forwarded_headers(&mut h, ip("2001:db8::1"), &[], "https", None);
    assert_eq!(h["forwarded"], "for=\"[2001:db8::1]\";proto=https");
}

#[test]
fn request_id_reuse_and_generation() {
    assert_eq!(request_id_from(&hm(&[("x-request-id", "abc-123")])), "abc-123");
    let generated = request_id_from(&hm(&[("x-request-id", "bad id with spaces")]));
    assert_eq!(generated.len(), 32);
    assert!(generated.as_bytes().iter().all(u8::is_ascii_hexdigit));
    assert_ne!(generated, request_id_from(&HeaderMap::new()));
    assert_eq!(request_id_from(&hm(&[("x-request-id", &"a".repeat(200))])).len(), 32);
}

#[test]
fn host_helpers() {
    assert_eq!(host_without_port("example.com:8080"), "example.com");
    assert_eq!(host_without_port("[::1]:8080"), "::1");
    assert_eq!(host_without_port("example.com."), "example.com");
    assert!(validate_host_pattern("*.example.com", false).is_ok());
    assert!(validate_host_pattern("*example.com", false).is_err());
    assert!(validate_host_pattern("", false).is_err());
    let _ = Method::GET;
}

// ---------- property tests ----------

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    /// The guard never panics, whatever the bytes and however they are split.
    #[test]
    fn guard_never_panics(data in proptest::collection::vec(any::<u8>(), 0..2048), split in 1usize..64) {
        let mut g = H1Guard::new(limits());
        for part in data.chunks(split) {
            if g.feed(part).is_err() { break; }
        }
    }

    /// Splitting a stream anywhere never changes the verdict.
    #[test]
    fn verdict_is_independent_of_segmentation(
        te_ws in "[ \t]{0,2}",
        te_val in prop_oneof![Just("chunked"), Just("Chunked"), Just("xchunked"), Just("chunked, chunked"), Just("identity")],
        with_cl in any::<bool>(),
        split in 1usize..40,
    ) {
        let mut raw = format!("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding:{te_ws}{te_val}{te_ws}\r\n");
        if with_cl { raw.push_str("Content-Length: 3\r\n"); }
        raw.push_str("\r\n");
        let whole = H1Guard::new(limits()).feed(raw.as_bytes()).is_ok();
        let mut g = H1Guard::new(limits());
        let mut ok = true;
        for part in raw.as_bytes().chunks(split) {
            if g.feed(part).is_err() { ok = false; break; }
        }
        prop_assert_eq!(whole, ok);
    }

    /// CL + TE in any case, order or whitespace is always rejected.
    #[test]
    fn cl_plus_te_always_rejected(
        cl_name in "[cC][oO][nN][tT][eE][nN][tT]-[lL][eE][nN][gG][tT][hH]",
        te_name in "[tT][rR][aA][nN][sS][fF][eE][rR]-[eE][nN][cC][oO][dD][iI][nN][gG]",
        ws in "[ \t]{0,3}",
        te_first in any::<bool>(),
        n in 0u32..1000,
    ) {
        let cl = format!("{cl_name}:{ws}{n}\r\n");
        let te = format!("{te_name}:{ws}chunked\r\n");
        let (a, b) = if te_first { (te, cl) } else { (cl, te) };
        let raw = format!("POST / HTTP/1.1\r\nHost: a\r\n{a}{b}\r\n");
        prop_assert!(parse_request_head(raw.as_bytes(), &limits()).is_err());
    }

    /// Anything accepted has exactly one Host and at most one numeric CL.
    #[test]
    fn accepted_heads_are_unambiguous(data in proptest::collection::vec(any::<u8>(), 0..300)) {
        let mut raw = b"GET / HTTP/1.1\r\n".to_vec();
        raw.extend_from_slice(&data);
        raw.extend_from_slice(b"\r\n\r\n");
        if let Ok(info) = parse_request_head(&raw, &limits()) {
            let text = String::from_utf8_lossy(&raw).to_ascii_lowercase();
            prop_assert_eq!(text.matches("\r\nhost:").count(), 1);
            prop_assert!(text.matches("\r\ncontent-length:").count() <= 1);
            prop_assert!(!(text.contains("\r\ncontent-length:") && text.contains("\r\ntransfer-encoding:")));
            let _ = info;
        }
    }

    /// `validate_host` never panics.
    #[test]
    fn validate_host_total(s in ".{0,300}") {
        let _ = validate_host(&s);
    }
}

// ---------- deterministic mutation fuzzing over the smuggling corpus ----------

const SEEDS: [&[u8]; 10] = [
    include_bytes!("../../../../fuzz/seeds/cl_te.seed"),
    include_bytes!("../../../../fuzz/seeds/te_cl.seed"),
    include_bytes!("../../../../fuzz/seeds/te_te_xchunked.seed"),
    include_bytes!("../../../../fuzz/seeds/obs_fold.seed"),
    include_bytes!("../../../../fuzz/seeds/nul.seed"),
    include_bytes!("../../../../fuzz/seeds/bare_lf.seed"),
    include_bytes!("../../../../fuzz/seeds/dup_host.seed"),
    include_bytes!("../../../../fuzz/seeds/underscore_te.seed"),
    include_bytes!("../../../../fuzz/seeds/trailer_cl.seed"),
    include_bytes!("../../../../fuzz/seeds/ws_upgrade.seed"),
];

fn mutate(rng: &mut fastrand::Rng, base: &[u8]) -> Vec<u8> {
    const INTERESTING: &[u8] = b"\r\n\0 \t:,;_-\x0b\x0c\x7f\xff";
    let mut v = base.to_vec();
    for _ in 0..rng.usize(1..6) {
        if v.is_empty() {
            v.push(b'G');
        }
        let i = rng.usize(..v.len());
        match rng.u8(..7) {
            0 => v[i] = rng.u8(..),
            1 => v.insert(i, INTERESTING[rng.usize(..INTERESTING.len())]),
            2 => {
                v.remove(i);
            }
            3 => v[i] = INTERESTING[rng.usize(..INTERESTING.len())],
            4 => {
                // duplicate a random slice (repeats headers / lines)
                let j = rng.usize(i..v.len());
                let dup = v[i..=j].to_vec();
                v.splice(i..i, dup);
            }
            5 => v[i] ^= 0x20, // case flip
            _ => {
                // splice in a chunk of another seed
                let other = SEEDS[rng.usize(..SEEDS.len())];
                let a = rng.usize(..other.len());
                let b = rng.usize(a..other.len());
                v.splice(i..i, other[a..b].iter().copied());
            }
        }
    }
    v
}

/// Everything an accepted request head must satisfy.
fn assert_head_invariants(head: &[u8]) {
    let lower = head.to_ascii_lowercase();
    let count = |needle: &[u8]| lower.windows(needle.len()).filter(|w| *w == needle).count();
    assert!(count(b"\r\nhost:") <= 1, "duplicate Host accepted: {head:?}");
    assert!(count(b"\r\ncontent-length:") <= 1, "duplicate CL accepted: {head:?}");
    assert!(!(count(b"\r\ncontent-length:") > 0 && count(b"\r\ntransfer-encoding:") > 0), "CL+TE accepted: {head:?}");
    assert!(count(b"\r\ntransfer-encoding:") <= 1, "duplicate TE accepted: {head:?}");
    assert!(!head.contains(&0), "NUL accepted: {head:?}");
    for (i, &b) in head.iter().enumerate() {
        match b {
            b'\n' => assert!(i > 0 && head[i - 1] == b'\r', "bare LF accepted: {head:?}"),
            b'\r' => assert!(head.get(i + 1) == Some(&b'\n'), "bare CR accepted: {head:?}"),
            b' ' | b'\t' if i > 0 && head[i - 1] == b'\n' => panic!("obs-fold accepted: {head:?}"),
            0x01..=0x08 | 0x0b | 0x0c | 0x0e..=0x1f | 0x7f => panic!("control byte accepted: {head:?}"),
            _ => {}
        }
    }
    // A Transfer-Encoding header, if present, must be exactly `chunked`.
    if let Some(pos) = lower.windows(21).position(|w| w == b"\r\ntransfer-encoding:") {
        let rest = &head[pos + 21..];
        let end = rest.windows(2).position(|w| w == b"\r\n").unwrap();
        assert!(rest[..end].trim_ascii().eq_ignore_ascii_case(b"chunked"), "odd TE accepted: {head:?}");
    }
}

#[test]
fn mutation_fuzzing_never_breaks_the_head_invariants_or_panics() {
    let mut rng = fastrand::Rng::with_seed(0x5eed_cafe);
    let limits = limits();
    let (mut accepted, mut rejected) = (0u32, 0u32);
    for _ in 0..150_000 {
        let base = SEEDS[rng.usize(..SEEDS.len())];
        let input = mutate(&mut rng, base);

        // Head-level invariants.
        let mut scanner = HeadScanner::default();
        if let Ok(Some(end)) = scanner.scan(&input, limits.max_head_bytes) {
            match parse_request_head(&input[..end], &limits) {
                Ok(_) => {
                    accepted += 1;
                    assert_head_invariants(&input[..end]);
                }
                Err(_) => rejected += 1,
            }
        }

        // Stream-level invariants: verdict and released bytes are
        // independent of how the bytes are segmented.
        let split = rng.usize(1..40);
        let whole = released_stream(&mut H1Guard::new(limits), &[&input]);
        let chunks: Vec<&[u8]> = input.chunks(split).collect();
        let parts = released_stream(&mut H1Guard::new(limits), &chunks);
        assert_eq!(whole.is_ok(), parts.is_ok(), "verdict depends on segmentation (split {split}): {input:?}");
        if let (Ok(w), Ok(p)) = (whole, parts) {
            assert_eq!(w, p, "released bytes depend on segmentation: {input:?}");
            assert!(input.starts_with(&w));
        }
    }
    assert!(accepted > 500, "mutations should still produce valid heads (accepted {accepted})");
    assert!(rejected > 5_000, "and plenty of invalid ones (rejected {rejected})");
}

#[test]
fn chunked_decoder_is_segmentation_independent_under_mutation() {
    let mut rng = fastrand::Rng::with_seed(7);
    let base: &[u8] = b"4\r\nWiki\r\n5;ext=1\r\npedia\r\n0\r\nX-Trailer: v\r\n\r\nNEXT";
    for _ in 0..60_000 {
        let input = mutate(&mut rng, base);
        let mut whole = ChunkedDecoder::new(4096);
        let a = whole.feed(&input);
        let mut dripped = ChunkedDecoder::new(4096);
        let (mut consumed, mut done_b, mut err_b) = (0, false, false);
        for b in &input {
            match dripped.feed(std::slice::from_ref(b)) {
                Ok((n, d)) => {
                    consumed += n;
                    if d {
                        done_b = true;
                        break;
                    }
                }
                Err(_) => {
                    err_b = true;
                    break;
                }
            }
        }
        match a {
            Ok((n, d)) => assert_eq!((n, d, false), (consumed, done_b, err_b), "{input:?}"),
            Err(_) => assert!(err_b, "{input:?}"),
        }
    }
}

#[test]
fn underscores_in_host_are_rejected_unless_explicitly_allowed() {
    let strict = limits();
    let lenient = H1Limits { allow_underscores_in_host: true, ..limits() };
    let raw = "GET / HTTP/1.1\r\nHost: my_service:8080\r\n\r\n";
    assert_eq!(parse_request_head(raw.as_bytes(), &strict), Err(Violation::Host));
    assert!(parse_request_head(raw.as_bytes(), &lenient).is_ok());
    // Everything else about the label stays strict even when `_` is allowed.
    for bad in ["-a_b.com", "a_b-.com", "a b_c", "a_b..c", "[::1]_"] {
        let raw = format!("GET / HTTP/1.1\r\nHost: {bad}\r\n\r\n");
        assert!(parse_request_head(raw.as_bytes(), &lenient).is_err(), "{bad}");
    }
    // Typed (h2/h3) path and config patterns honour the same switch.
    let uri: Uri = "https://svc_one/".parse().unwrap();
    let h = HeaderMap::new();
    assert_eq!(validate_request_headers(Version::HTTP_2, &h, &uri, false), Err(Violation::Host));
    assert!(validate_request_headers(Version::HTTP_2, &h, &uri, true).is_ok());
    assert!(validate_host_pattern("svc_one", false).is_err());
    assert!(validate_host_pattern("*.svc_one", true).is_ok());
    assert!(validate_host_with("svc_one", true).is_ok());
    assert_eq!(validate_host("svc_one"), Err(Violation::Host));
}

// ---------- fast paths must be observationally identical ----------

#[test]
fn swar_word_check_is_exact_for_every_byte_value_in_every_lane() {
    use super::h1::word_is_plain_for_tests as plain;
    for lane in 0..8 {
        for b in 0u8..=255 {
            let mut w = [b'a'; 8];
            w[lane] = b;
            let expect = !(b < 0x20 || b == 0x7f);
            assert_eq!(plain(u64::from_le_bytes(w)), expect, "byte {b:#04x} in lane {lane}");
        }
    }
    assert!(plain(u64::from_le_bytes(*b"Host: ex")));
    assert!(plain(u64::from_le_bytes([0x80, 0xff, b' ', b'~', b'!', 0xc3, 0xa9, b'a'])));
    assert!(!plain(u64::from_le_bytes(*b"abc\tdefg")), "tab takes the exact path");
}

#[test]
fn fast_scanner_matches_the_bytewise_reference_on_mutated_and_random_input() {
    let mut rng = fastrand::Rng::with_seed(0xfa57);
    let mut compared = 0u32;
    for round in 0..80_000u32 {
        let input: Vec<u8> = if round % 4 == 0 {
            (0..rng.usize(0..300)).map(|_| rng.u8(..)).collect()
        } else {
            let seed = SEEDS[rng.usize(..SEEDS.len())];
            mutate(&mut rng, seed)
        };
        for max in [64usize, 100, 16 * 1024] {
            let (mut fast, mut slow) = (HeadScanner::default(), HeadScanner::default());
            // Feed the same bytes in random-sized chunks to exercise carried state.
            let mut rest = &input[..];
            loop {
                let n = rng.usize(1..40).min(rest.len());
                let (chunk, tail) = rest.split_at(n);
                let (a, b) = (fast.scan(chunk, max), slow.scan_reference(chunk, max));
                assert_eq!(a, b, "result differs (max {max}) on {chunk:?} of {input:?}");
                assert_eq!(fast.state(), slow.state(), "state differs after {chunk:?}");
                compared += 1;
                rest = tail;
                if rest.is_empty() || !matches!(a, Ok(None)) {
                    break;
                }
            }
        }
    }
    assert!(compared > 200_000);
}

#[test]
fn guard_reuses_its_buffers_across_keep_alive_requests() {
    let mut g = H1Guard::new(limits());
    let head = b"GET /keepalive HTTP/1.1\r\nHost: a\r\n\r\n";
    // Heads split across reads force the withheld-head path every time.
    let mut cap_after_warmup = 0;
    for round in 0..200 {
        let (a, b) = head.split_at(10 + round % 7);
        assert_eq!(g.feed(a).unwrap().len, 0);
        let rel = g.feed(b).unwrap();
        assert_eq!(rel.carried, head.as_slice());
        if round == 20 {
            cap_after_warmup = g.head_capacity_for_tests();
        }
    }
    assert!(cap_after_warmup > 0);
    assert_eq!(g.head_capacity_for_tests(), cap_after_warmup, "no regrowth after warm-up");
    // A pathological, huge head must not pin its memory for the connection's lifetime.
    let big = format!("GET / HTTP/1.1\r\nHost: a\r\nX: {}\r\n\r\n", "a".repeat(15_000));
    let mut g = H1Guard::new(H1Limits { max_head_bytes: 64 * 1024, ..limits() });
    for chunk in big.as_bytes().chunks(4_000) {
        g.feed(chunk).unwrap();
    }
    g.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
    assert!(g.head_capacity_for_tests() <= 16 * 1024, "{}", g.head_capacity_for_tests());
}

#[test]
fn single_read_heads_never_touch_the_carry_path() {
    let mut g = H1Guard::new(limits());
    for _ in 0..50 {
        let rel = g.feed(OK.as_bytes()).unwrap();
        assert!(rel.carried.is_empty(), "no copy when the whole head arrives in one read");
        assert_eq!((rel.skip, rel.len, rel.partial_head), (0, OK.len(), false));
    }
}

#[test]
fn hop_by_hop_stripping_handles_many_and_odd_connection_values() {
    // More Connection header lines than the inline slots, with a nominated
    // header hidden in the overflow, odd casing, junk tokens and empty tokens.
    let mut h = HeaderMap::new();
    for v in ["keep-alive", "X-One", "x-two", ",,  ,", "bad token!", "X-Three, X-FOUR", "x-five"] {
        h.append("connection", HeaderValue::from_str(v).unwrap());
    }
    for k in ["x-one", "x-two", "x-three", "x-four", "x-five", "x-keep", "content-length", "host"] {
        h.insert(http::HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_static("1"));
    }
    h.insert("connection-ish", HeaderValue::from_static("untouched"));
    strip_hop_by_hop(&mut h);
    let mut left: Vec<_> = h.keys().map(|k| k.as_str().to_owned()).collect();
    left.sort();
    assert_eq!(left, ["connection-ish", "content-length", "host", "x-keep"]);
    // Idempotent, and a no-op without a Connection header.
    strip_hop_by_hop(&mut h);
    assert_eq!(h.len(), 4);
    // A Connection value that is not valid UTF-8 cannot nominate anything, and is still removed.
    let mut h = HeaderMap::new();
    h.insert("connection", HeaderValue::from_bytes(b"x-secret\xff").unwrap());
    h.insert("x-secret", HeaderValue::from_static("s"));
    strip_hop_by_hop(&mut h);
    assert!(!h.contains_key("connection"));
}

#[test]
fn forwarded_headers_with_long_existing_chains_spill_correctly() {
    // > 256 bytes of existing X-Forwarded-For / Forwarded forces the heap spill path.
    let trusted: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
    let chain: Vec<String> = (1..=30).map(|i| format!("10.1.1.{i}")).collect();
    let xff = format!("198.51.100.7, {}", chain.join(", "));
    let fwd: String = (0..14).map(|i| format!("for=10.9.9.{i};proto=https")).collect::<Vec<_>>().join(", ");
    let mut h = hm(&[("x-forwarded-for", &xff), ("forwarded", &fwd)]);
    let client = apply_forwarded_headers(&mut h, ip("10.2.2.2"), &trusted, "http", Some("example.com"));
    assert_eq!(client, ip("198.51.100.7"));
    assert_eq!(h["x-forwarded-for"].to_str().unwrap(), format!("{xff}, 10.2.2.2"));
    let f = h["forwarded"].to_str().unwrap();
    assert!(f.starts_with(&fwd) && f.ends_with("for=10.2.2.2;proto=http;host=\"example.com\""), "{f}");
    assert!(f.len() > 256);
}
