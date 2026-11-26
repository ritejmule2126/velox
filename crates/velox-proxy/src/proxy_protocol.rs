//! PROXY protocol v1 and v2 (HAProxy spec) for listeners behind a TCP load
//! balancer (AWS NLB, HAProxy, …).
//!
//! The header carries the real client address, which the load balancer would
//! otherwise hide behind its own. It arrives *before* any TLS or HTTP bytes, so
//! it is consumed first, with these guarantees:
//!
//! * Only peers listed in `server.proxy_protocol_trusted` may send one; anyone
//!   else is refused ([`is_trusted`]). A client can therefore never forge its
//!   address by sending its own header.
//! * The header is mandatory on a PROXY-protocol listener: a connection that
//!   starts with anything else is dropped, never interpreted as HTTP.
//! * [`parse`] is a pure function over bytes (bounded: 107 bytes for v1, 1 KiB
//!   of payload for v2), and [`read_header`] consumes *exactly* the header, so
//!   the TLS `ClientHello` or HTTP request behind it is left untouched.
//! * It is bounded in time by the caller-supplied timeout.

use ipnet::IpNet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// The 12-byte v2 signature.
pub const V2_SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
/// The longest legal v1 line, CRLF included.
pub const V1_MAX_LEN: usize = 107;
/// The largest v2 payload (addresses + TLVs) accepted. NLB / PrivateLink add a
/// few dozen bytes of TLVs; anything near this limit is not legitimate.
pub const V2_MAX_PAYLOAD: usize = 1024;
const V2_HEADER_LEN: usize = 16;
/// The longest header [`parse`] will ever accept.
pub const MAX_HEADER_LEN: usize = V2_HEADER_LEN + V2_MAX_PAYLOAD;
const MAX_TOTAL: usize = MAX_HEADER_LEN;

/// What a PROXY header told us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyHeader {
    /// Protocol version (1 or 2).
    pub version: u8,
    /// The original client, or `None` for `LOCAL` (v2) / `UNKNOWN` (v1) /
    /// non-IP families — meaning "use the TCP peer", as a health check does.
    pub client: Option<SocketAddr>,
    /// The address the client connected to on the load balancer.
    pub server: Option<SocketAddr>,
}

/// Result of [`parse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parsed {
    /// A complete, valid header occupying the first `len` bytes.
    Header {
        /// Bytes the header occupies.
        len: usize,
        /// Its contents.
        header: ProxyHeader,
    },
    /// The input is a proper prefix of a header that may still become valid.
    Incomplete,
    /// This cannot be a PROXY header (or is malformed / over a limit).
    Invalid(&'static str),
}

/// Parse a PROXY protocol header at the start of `buf`.
///
/// Pure and total: never panics, never reads past `buf`.
pub fn parse(buf: &[u8]) -> Parsed {
    if buf.is_empty() {
        return Parsed::Incomplete;
    }
    let n = buf.len().min(V2_SIGNATURE.len());
    if buf[..n] == V2_SIGNATURE[..n] {
        return if buf.len() < V2_HEADER_LEN { Parsed::Incomplete } else { parse_v2(buf) };
    }
    const V1: &[u8; 6] = b"PROXY ";
    let n = buf.len().min(V1.len());
    if buf[..n] == V1[..n] {
        return if buf.len() < V1.len() { Parsed::Incomplete } else { parse_v1(buf) };
    }
    Parsed::Invalid("not a PROXY protocol header")
}

fn parse_v1(buf: &[u8]) -> Parsed {
    let window = &buf[..buf.len().min(V1_MAX_LEN)];
    let Some(end) = window.windows(2).position(|w| w == b"\r\n") else {
        return if buf.len() >= V1_MAX_LEN { Parsed::Invalid("PROXY v1 line too long") } else { Parsed::Incomplete };
    };
    let total = end + 2;
    let Ok(line) = std::str::from_utf8(&buf[..end]) else {
        return Parsed::Invalid("PROXY v1 line is not ASCII");
    };
    let mut parts = line.split(' ');
    let _proxy = parts.next(); // "PROXY", checked by the caller
    let invalid = Parsed::Invalid("malformed PROXY v1 line");
    match parts.next() {
        // The address block of an UNKNOWN line (if any) is to be ignored.
        Some("UNKNOWN") => {
            Parsed::Header { len: total, header: ProxyHeader { version: 1, client: None, server: None } }
        }
        Some(family @ ("TCP4" | "TCP6")) => {
            let (Some(src), Some(dst), Some(sport), Some(dport), None) =
                (parts.next(), parts.next(), parts.next(), parts.next(), parts.next())
            else {
                return invalid;
            };
            let ip = |s: &str| -> Option<IpAddr> {
                match family {
                    "TCP4" => s.parse::<Ipv4Addr>().ok().map(IpAddr::V4),
                    _ => s.parse::<Ipv6Addr>().ok().map(IpAddr::V6),
                }
            };
            let port = |s: &str| -> Option<u16> {
                (!s.is_empty() && s.len() <= 5 && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse().ok())?
            };
            match (ip(src), ip(dst), port(sport), port(dport)) {
                (Some(s), Some(d), Some(sp), Some(dp)) => Parsed::Header {
                    len: total,
                    header: ProxyHeader {
                        version: 1,
                        client: Some(SocketAddr::new(s, sp)),
                        server: Some(SocketAddr::new(d, dp)),
                    },
                },
                _ => invalid,
            }
        }
        _ => invalid,
    }
}

fn parse_v2(buf: &[u8]) -> Parsed {
    let (ver_cmd, fam) = (buf[12], buf[13]);
    if ver_cmd >> 4 != 2 {
        return Parsed::Invalid("unsupported PROXY protocol version");
    }
    let payload_len = usize::from(u16::from_be_bytes([buf[14], buf[15]]));
    if payload_len > V2_MAX_PAYLOAD {
        return Parsed::Invalid("PROXY v2 payload too large");
    }
    let total = V2_HEADER_LEN + payload_len;
    if buf.len() < total {
        return Parsed::Incomplete;
    }
    let payload = &buf[V2_HEADER_LEN..total];
    let header = |client, server| Parsed::Header { len: total, header: ProxyHeader { version: 2, client, server } };
    match ver_cmd & 0x0f {
        // LOCAL: a health check from the load balancer itself. The address
        // block (if any) is to be ignored.
        0 => header(None, None),
        1 => match (fam >> 4, fam & 0x0f) {
            (0, _) | (3, _) => header(None, None), // UNSPEC / AF_UNIX: no IP to use
            (1, 1) if payload.len() >= 12 => {
                let ip = |o: &[u8]| IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3]));
                let port = |o: &[u8]| u16::from_be_bytes([o[0], o[1]]);
                header(
                    Some(SocketAddr::new(ip(&payload[0..4]), port(&payload[8..10]))),
                    Some(SocketAddr::new(ip(&payload[4..8]), port(&payload[10..12]))),
                )
            }
            (2, 1) if payload.len() >= 36 => {
                let ip = |o: &[u8]| {
                    let mut b = [0u8; 16];
                    b.copy_from_slice(o);
                    IpAddr::V6(Ipv6Addr::from(b))
                };
                let port = |o: &[u8]| u16::from_be_bytes([o[0], o[1]]);
                header(
                    Some(SocketAddr::new(ip(&payload[0..16]), port(&payload[32..34]))),
                    Some(SocketAddr::new(ip(&payload[16..32]), port(&payload[34..36]))),
                )
            }
            (1 | 2, 1) => Parsed::Invalid("PROXY v2 address block too short"),
            _ => Parsed::Invalid("unsupported PROXY v2 address family or transport"),
        },
        _ => Parsed::Invalid("unknown PROXY v2 command"),
    }
}

/// Is `peer` allowed to send a PROXY header?
pub fn is_trusted(peer: IpAddr, trusted: &[IpNet]) -> bool {
    trusted.iter().any(|n| n.contains(&peer))
}

/// Why reading a PROXY header failed.
#[derive(Debug, thiserror::Error)]
pub enum HeaderError {
    /// The header did not arrive within the deadline.
    #[error("PROXY header not received in time")]
    Timeout,
    /// The peer closed the connection before finishing the header.
    #[error("connection closed before the PROXY header was complete")]
    Eof,
    /// I/O error while reading.
    #[error("i/o error reading the PROXY header: {0}")]
    Io(#[from] io::Error),
    /// Not a valid PROXY header.
    #[error("invalid PROXY header: {0}")]
    Invalid(&'static str),
}

impl HeaderError {
    /// A low-cardinality label for metrics.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Eof => "eof",
            Self::Io(_) => "io",
            Self::Invalid(_) => "invalid",
        }
    }
}

/// Read one PROXY header from `stream`, consuming exactly its bytes.
///
/// Whatever follows (a TLS `ClientHello`, an HTTP request) stays unread in the
/// socket. Uses `peek` to decide how much of the stream belongs to the header,
/// so a header split across many segments, or followed immediately by more
/// data in the same segment, is handled identically.
pub async fn read_header(stream: &mut TcpStream, timeout: Duration) -> Result<ProxyHeader, HeaderError> {
    tokio::time::timeout(timeout, read_header_inner(stream)).await.map_err(|_| HeaderError::Timeout)?
}

async fn read_header_inner(stream: &mut TcpStream) -> Result<ProxyHeader, HeaderError> {
    let mut consumed: Vec<u8> = Vec::with_capacity(128);
    let mut peeked = [0u8; MAX_TOTAL];
    loop {
        let n = stream.peek(&mut peeked).await?;
        if n == 0 {
            return Err(HeaderError::Eof);
        }
        let mut candidate = Vec::with_capacity(consumed.len() + n);
        candidate.extend_from_slice(&consumed);
        candidate.extend_from_slice(&peeked[..n]);
        match parse(&candidate) {
            Parsed::Header { len, header } => {
                // `consumed` was an incomplete prefix, so the header ends inside
                // what we just peeked: take exactly the remainder.
                let rest = len.saturating_sub(consumed.len()).min(n);
                stream.read_exact(&mut peeked[..rest]).await.map_err(eof_as_closed)?;
                return Ok(header);
            }
            // Every peeked byte is part of a still-possible header: take them
            // and wait for more.
            Parsed::Incomplete => {
                stream.read_exact(&mut peeked[..n]).await.map_err(eof_as_closed)?;
                consumed.extend_from_slice(&peeked[..n]);
            }
            Parsed::Invalid(why) => return Err(HeaderError::Invalid(why)),
        }
    }
}

fn eof_as_closed(e: io::Error) -> HeaderError {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        HeaderError::Eof
    } else {
        HeaderError::Io(e)
    }
}

/// Encode a v1 header (`TCP4` / `TCP6`; mixed families become `UNKNOWN`).
pub fn encode_v1(client: SocketAddr, server: SocketAddr) -> Vec<u8> {
    match (client, server) {
        (SocketAddr::V4(c), SocketAddr::V4(s)) => {
            format!("PROXY TCP4 {} {} {} {}\r\n", c.ip(), s.ip(), c.port(), s.port())
        }
        (SocketAddr::V6(c), SocketAddr::V6(s)) => {
            format!("PROXY TCP6 {} {} {} {}\r\n", c.ip(), s.ip(), c.port(), s.port())
        }
        _ => "PROXY UNKNOWN\r\n".to_owned(),
    }
    .into_bytes()
}

/// Encode a v2 `PROXY` header with `tlvs` appended verbatim (mixed families
/// become an `UNSPEC` header).
pub fn encode_v2(client: SocketAddr, server: SocketAddr, tlvs: &[u8]) -> Vec<u8> {
    let mut out = V2_SIGNATURE.to_vec();
    out.push(0x21); // version 2, PROXY
    let mut payload = Vec::new();
    match (client, server) {
        (SocketAddr::V4(c), SocketAddr::V4(s)) => {
            out.push(0x11);
            payload.extend_from_slice(&c.ip().octets());
            payload.extend_from_slice(&s.ip().octets());
            payload.extend_from_slice(&c.port().to_be_bytes());
            payload.extend_from_slice(&s.port().to_be_bytes());
        }
        (SocketAddr::V6(c), SocketAddr::V6(s)) => {
            out.push(0x21);
            payload.extend_from_slice(&c.ip().octets());
            payload.extend_from_slice(&s.ip().octets());
            payload.extend_from_slice(&c.port().to_be_bytes());
            payload.extend_from_slice(&s.port().to_be_bytes());
        }
        _ => out.push(0x00),
    }
    payload.extend_from_slice(tlvs);
    out.extend_from_slice(&u16::try_from(payload.len()).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

/// A v2 `LOCAL` header (what a load balancer sends for its own health checks).
pub fn encode_v2_local() -> Vec<u8> {
    let mut out = V2_SIGNATURE.to_vec();
    out.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn header_of(p: Parsed) -> (usize, ProxyHeader) {
        match p {
            Parsed::Header { len, header } => (len, header),
            other => panic!("expected a header, got {other:?}"),
        }
    }

    #[test]
    fn v1_tcp4_tcp6_and_unknown() {
        let line = b"PROXY TCP4 203.0.113.7 10.0.0.5 51234 443\r\nGET / HTTP/1.1\r\n";
        let (len, h) = header_of(parse(line));
        assert_eq!(len, 43);
        assert_eq!(&line[len..len + 3], b"GET", "bytes after the header are left alone");
        assert_eq!(h.client, Some(sa("203.0.113.7:51234")));
        assert_eq!(h.server, Some(sa("10.0.0.5:443")));
        assert_eq!(h.version, 1);

        let (_, h) = header_of(parse(b"PROXY TCP6 2001:db8::1 2001:db8::2 1 65535\r\n"));
        assert_eq!(h.client, Some(sa("[2001:db8::1]:1")));
        assert_eq!(h.server, Some(sa("[2001:db8::2]:65535")));

        // UNKNOWN ignores whatever follows on the line.
        let (len, h) = header_of(parse(b"PROXY UNKNOWN ff:ff:ff:ff\r\nrest"));
        assert_eq!((len, h.client), (27, None));
        assert_eq!(header_of(parse(b"PROXY UNKNOWN\r\n")).1.client, None);
    }

    #[test]
    fn v1_rejects_malformed_lines() {
        for bad in [
            &b"PROXY TCP4 1.2.3.4 5.6.7.8 80\r\n"[..],      // missing port
            b"PROXY TCP4 1.2.3.4 5.6.7.8 80 443 extra\r\n", // trailing junk
            b"PROXY TCP4 1.2.3.4  5.6.7.8 80 443\r\n",      // double space
            b"PROXY TCP4 ::1 ::1 80 443\r\n",               // family mismatch
            b"PROXY TCP6 1.2.3.4 5.6.7.8 80 443\r\n",       // family mismatch
            b"PROXY TCP4 001.2.3.4 5.6.7.8 80 443\r\n",     // leading zeros
            b"PROXY TCP4 1.2.3.4 5.6.7.8 +80 443\r\n",      // signed port
            b"PROXY TCP4 1.2.3.4 5.6.7.8 70000 443\r\n",    // port out of range
            b"PROXY TCP4 1.2.3.4 5.6.7.8 8\xff 443\r\n",    // not ASCII
            b"PROXY UDP4 1.2.3.4 5.6.7.8 80 443\r\n",       // unsupported protocol
            b"PROXY \r\n",
            b"PROXY  TCP4 1.2.3.4 5.6.7.8 80 443\r\n",
        ] {
            assert!(matches!(parse(bad), Parsed::Invalid(_)), "{:?}", String::from_utf8_lossy(bad));
        }
        // A line without CRLF that has reached the maximum length can never become valid.
        let long = format!("PROXY TCP4 {}", "1".repeat(200));
        assert!(matches!(parse(long.as_bytes()), Parsed::Invalid(_)));
        // A bare LF is not a terminator.
        assert!(matches!(parse(b"PROXY TCP4 1.2.3.4 5.6.7.8 80 443\n"), Parsed::Incomplete));
    }

    #[test]
    fn v2_ipv4_ipv6_local_and_tlvs() {
        let (client, server) = (sa("198.51.100.9:40000"), sa("10.0.0.1:443"));
        let wire = encode_v2(client, server, &[]);
        assert_eq!(wire.len(), 16 + 12);
        let (len, h) = header_of(parse(&wire));
        assert_eq!((len, h.client, h.server, h.version), (28, Some(client), Some(server), 2));

        let (c6, s6) = (sa("[2001:db8::7]:1234"), sa("[2001:db8::1]:443"));
        let (len, h) = header_of(parse(&encode_v2(c6, s6, &[])));
        assert_eq!((len, h.client, h.server), (16 + 36, Some(c6), Some(s6)));

        // NLB-style TLVs after the addresses are skipped, and trailing app data is not consumed.
        let tlvs = [0xEA, 0x00, 0x05, b'v', b'p', b'c', b'e', b'-'];
        let mut wire = encode_v2(client, server, &tlvs);
        let header_len = wire.len();
        wire.extend_from_slice(b"\x16\x03\x01 ClientHello...");
        let (len, h) = header_of(parse(&wire));
        assert_eq!((len, h.client), (header_len, Some(client)));

        // LOCAL: use the TCP peer.
        let (len, h) = header_of(parse(&encode_v2_local()));
        assert_eq!((len, h.client, h.server), (16, None, None));
        // LOCAL may still carry (ignored) address bytes.
        let mut local = V2_SIGNATURE.to_vec();
        local.extend_from_slice(&[0x20, 0x11, 0x00, 0x0c]);
        local.extend_from_slice(&[0; 12]);
        assert_eq!(header_of(parse(&local)), (28, ProxyHeader { version: 2, client: None, server: None }));
        // UNSPEC and AF_UNIX carry no usable address.
        assert_eq!(header_of(parse(&encode_v2(c6, client, &[]))).1.client, None, "UNSPEC");
    }

    #[test]
    fn v2_rejects_bad_headers() {
        let good = encode_v2(sa("1.2.3.4:5"), sa("6.7.8.9:10"), &[]);
        let mut v = good.clone();
        v[12] = 0x11; // version 1 nibble
        assert!(matches!(parse(&v), Parsed::Invalid(_)));
        let mut v = good.clone();
        v[12] = 0x22; // unknown command
        assert!(matches!(parse(&v), Parsed::Invalid(_)));
        let mut v = good.clone();
        v[13] = 0x12; // DGRAM
        assert!(matches!(parse(&v), Parsed::Invalid(_)));
        let mut v = good.clone();
        v[13] = 0x41; // unknown family
        assert!(matches!(parse(&v), Parsed::Invalid(_)));
        // Payload shorter than the family requires.
        let mut short = V2_SIGNATURE.to_vec();
        short.extend_from_slice(&[0x21, 0x11, 0x00, 0x04, 1, 2, 3, 4]);
        assert!(matches!(parse(&short), Parsed::Invalid(_)));
        // Oversized payload is refused before we wait for it.
        let mut huge = V2_SIGNATURE.to_vec();
        huge.extend_from_slice(&[0x21, 0x11, 0xff, 0xff]);
        assert!(matches!(parse(&huge), Parsed::Invalid(_)));
    }

    #[test]
    fn every_proper_prefix_of_a_valid_header_is_incomplete() {
        let wires = [
            encode_v1(sa("203.0.113.7:51234"), sa("10.0.0.5:443")),
            encode_v1(sa("[2001:db8::1]:1"), sa("[2001:db8::2]:2")),
            encode_v2(sa("198.51.100.9:40000"), sa("10.0.0.1:443"), &[0xEA, 0, 1, 7]),
            encode_v2(sa("[2001:db8::7]:1234"), sa("[2001:db8::1]:443"), &[]),
            encode_v2_local(),
            b"PROXY UNKNOWN\r\n".to_vec(),
        ];
        for wire in wires {
            for cut in 0..wire.len() {
                assert_eq!(
                    parse(&wire[..cut]),
                    Parsed::Incomplete,
                    "prefix {cut} of {:?}",
                    String::from_utf8_lossy(&wire)
                );
            }
            assert!(matches!(parse(&wire), Parsed::Header { len, .. } if len == wire.len()));
        }
    }

    #[test]
    fn non_proxy_input_is_invalid_immediately() {
        for bad in [&b"GET / HTTP/1.1\r\n"[..], b"\x16\x03\x01\x02\x00", b"PROXX ", b"\r\n\r\nX", b"\x00"] {
            assert!(matches!(parse(bad), Parsed::Invalid(_)), "{bad:?}");
        }
        assert_eq!(parse(b""), Parsed::Incomplete);
    }

    #[test]
    fn trust_list_matching() {
        let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap(), "2001:db8::/32".parse().unwrap()];
        assert!(is_trusted("10.1.2.3".parse().unwrap(), &trusted));
        assert!(is_trusted("2001:db8::9".parse().unwrap(), &trusted));
        assert!(!is_trusted("11.0.0.1".parse().unwrap(), &trusted));
        assert!(!is_trusted("10.1.2.3".parse().unwrap(), &[]), "an empty list trusts nobody");
    }

    proptest! {
        #[test]
        fn parse_never_panics_and_respects_its_bounds(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
            if let Parsed::Header { len, .. } = parse(&bytes) {
                prop_assert!(len <= bytes.len() && len <= MAX_TOTAL);
            }
        }

        #[test]
        fn v1_and_v2_round_trip_any_address(
            a in any::<[u8; 4]>(), b in any::<[u8; 4]>(), pa in any::<u16>(), pb in any::<u16>(),
            a6 in any::<[u8; 16]>(), b6 in any::<[u8; 16]>(),
            tlv in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let (c4, s4) = (SocketAddr::from((a, pa)), SocketAddr::from((b, pb)));
            let (c6, s6) = (SocketAddr::from((a6, pa)), SocketAddr::from((b6, pb)));
            for (c, s) in [(c4, s4), (c6, s6)] {
                for wire in [encode_v1(c, s), encode_v2(c, s, &tlv)] {
                    let mut with_tail = wire.clone();
                    with_tail.extend_from_slice(b"tail");
                    match parse(&with_tail) {
                        Parsed::Header { len, header } => {
                            prop_assert_eq!(len, wire.len());
                            prop_assert_eq!((header.client, header.server), (Some(c), Some(s)));
                        }
                        other => prop_assert!(false, "{other:?}"),
                    }
                }
            }
        }
    }

    /// The invariants the `proxy_protocol` fuzz target asserts, replayed on
    /// mutated headers so a violation is caught by `cargo test`, not a nightly run.
    #[test]
    fn fuzz_invariants_hold_under_mutation() {
        let seeds = [
            encode_v1(sa("203.0.113.7:51234"), sa("10.0.0.5:443")),
            encode_v1(sa("[2001:db8::1]:1"), sa("[2001:db8::2]:2")),
            b"PROXY UNKNOWN\r\n".to_vec(),
            encode_v2(sa("198.51.100.9:40000"), sa("10.0.0.1:443"), &[0xEA, 0, 2, 9, 9]),
            encode_v2(sa("[2001:db8::7]:1234"), sa("[2001:db8::1]:443"), &[]),
            encode_v2_local(),
        ];
        let mut x: u64 = 0xDEAD_BEEF_CAFE_F00D;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut headers_seen = 0;
        for seed in &seeds {
            for _ in 0..20_000 {
                let mut data = seed.clone();
                for _ in 0..(next() % 4) {
                    let i = (next() as usize) % data.len();
                    match next() % 3 {
                        0 => data[i] ^= 1 << (next() % 8),
                        1 => data[i] = (next() & 0xff) as u8,
                        _ => data.truncate(i.max(1)),
                    }
                }
                let Parsed::Header { len, header } = parse(&data) else { continue };
                headers_seen += 1;
                assert!(len <= data.len() && len <= MAX_HEADER_LEN);
                for cut in 0..len {
                    assert_eq!(parse(&data[..cut]), Parsed::Incomplete, "prefix {cut} of {len}: {:?}", &data[..len]);
                }
                let mut longer = data[..len].to_vec();
                longer.extend_from_slice(b"GET / HTTP/1.1\r\n");
                assert_eq!(parse(&longer), Parsed::Header { len, header });
                if let (Some(c), Some(s)) = (header.client, header.server) {
                    for wire in [encode_v1(c, s), encode_v2(c, s, &[])] {
                        let Parsed::Header { header: again, .. } = parse(&wire) else { panic!("re-encode rejected") };
                        assert_eq!((again.client, again.server), (Some(c), Some(s)));
                    }
                }
            }
        }
        assert!(headers_seen > 10_000, "the mutator should leave many headers valid ({headers_seen})");
    }

    // ---- reading from a real socket ----

    async fn pair() -> (TcpStream, TcpStream) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (c, s) = tokio::join!(TcpStream::connect(addr), l.accept());
        (c.unwrap(), s.unwrap().0)
    }

    #[tokio::test]
    async fn read_header_consumes_exactly_the_header() {
        use tokio::io::AsyncWriteExt;
        for wire in [
            encode_v1(sa("203.0.113.7:51234"), sa("10.0.0.5:443")),
            encode_v2(sa("198.51.100.9:40000"), sa("10.0.0.1:443"), &[0xEA, 0, 3, 1, 2, 3]),
        ] {
            let (mut client, mut server) = pair().await;
            // Header and the first application bytes in a single segment.
            let mut all = wire.clone();
            all.extend_from_slice(b"GET /after HTTP/1.1\r\n\r\n");
            client.write_all(&all).await.unwrap();
            let h = read_header(&mut server, Duration::from_secs(2)).await.unwrap();
            assert!(h.client.is_some());
            let mut rest = [0u8; 23];
            server.read_exact(&mut rest).await.unwrap();
            assert_eq!(&rest, b"GET /after HTTP/1.1\r\n\r\n", "application bytes must be untouched");
        }
    }

    #[tokio::test]
    async fn read_header_handles_one_byte_at_a_time_and_stalls() {
        use tokio::io::AsyncWriteExt;
        let wire = encode_v2(sa("198.51.100.9:40000"), sa("10.0.0.1:443"), &[]);
        let (mut client, mut server) = pair().await;
        client.set_nodelay(true).unwrap();
        let writer = tokio::spawn(async move {
            for b in wire {
                client.write_all(&[b]).await.unwrap();
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            client.write_all(b"APP").await.unwrap();
            client
        });
        let h = read_header(&mut server, Duration::from_secs(5)).await.unwrap();
        assert_eq!(h.client, Some(sa("198.51.100.9:40000")));
        let mut app = [0u8; 3];
        server.read_exact(&mut app).await.unwrap();
        assert_eq!(&app, b"APP");
        let _client = writer.await.unwrap();

        // A header that never completes times out…
        let (mut client, mut server) = pair().await;
        client.write_all(b"PROXY TCP4 1.2.3.4").await.unwrap();
        let err = read_header(&mut server, Duration::from_millis(150)).await.unwrap_err();
        assert!(matches!(err, HeaderError::Timeout), "{err}");
        // …a hang-up mid-header is reported as such…
        let (mut client, mut server) = pair().await;
        client.write_all(b"PROXY TCP4 1.2.3.4").await.unwrap();
        drop(client);
        let err = read_header(&mut server, Duration::from_secs(2)).await.unwrap_err();
        assert!(matches!(err, HeaderError::Eof), "{err}");
        // …and plain HTTP is refused outright rather than mistaken for a header.
        let (mut client, mut server) = pair().await;
        client.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
        let err = read_header(&mut server, Duration::from_secs(2)).await.unwrap_err();
        assert!(matches!(err, HeaderError::Invalid(_)) && err.reason() == "invalid", "{err}");
    }
}
