//! W3C Trace Context (`traceparent` / `tracestate`) propagation.
//!
//! When enabled, every proxied request carries a valid `traceparent` to the
//! backend: an inbound one is *continued* (same trace id and flags, a fresh
//! span id for Velox's hop), a missing or malformed one is *replaced* by a newly
//! minted trace. The format is `00-<32 hex trace-id>-<16 hex span-id>-<2 hex flags>`
//! (<https://www.w3.org/TR/trace-context/>), parsed strictly:
//!
//! * lowercase hex only, exactly the right field widths;
//! * an all-zero trace id or span id is invalid, as is version `ff`;
//! * a version later than `00` is accepted if its first four fields parse (the
//!   spec's forward-compatibility rule), and is re-emitted as version `00`;
//! * several `traceparent` header lines are ambiguous, so the context restarts;
//! * `tracestate` only travels with a *valid* `traceparent`, and only if it is
//!   plain printable ASCII within the spec's size bounds.

use http::{HeaderMap, HeaderName, HeaderValue};

/// The `traceparent` header.
pub const TRACEPARENT: HeaderName = HeaderName::from_static("traceparent");
/// The `tracestate` header.
pub const TRACESTATE: HeaderName = HeaderName::from_static("tracestate");

/// Largest `tracestate` (all lines together) we forward. The spec asks
/// implementations to propagate at least 512 bytes; beyond that we drop it
/// rather than let a client inflate every upstream request.
const MAX_TRACESTATE: usize = 512;

/// A parsed `traceparent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceParent {
    /// 16-byte trace id (never all zero).
    pub trace_id: [u8; 16],
    /// 8-byte parent / span id (never all zero).
    pub span_id: [u8; 8],
    /// Trace flags (bit 0 = sampled).
    pub flags: u8,
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None, // uppercase is not allowed by the spec
    }
}

fn hex_bytes<const N: usize>(s: &[u8]) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    // `s.len() == 2 * N` was checked above, so both indices are in range.
    for (i, o) in out.iter_mut().enumerate() {
        *o = (hex_val(s[2 * i])? << 4) | hex_val(s[2 * i + 1])?;
    }
    Some(out)
}

/// Parse one `traceparent` value.
pub fn parse_traceparent(v: &[u8]) -> Option<TraceParent> {
    // version(2) - trace-id(32) - parent-id(16) - flags(2) = 55 bytes.
    if v.len() < 55 || v[2] != b'-' || v[35] != b'-' || v[52] != b'-' {
        return None;
    }
    let version: [u8; 1] = hex_bytes(&v[0..2])?;
    match version[0] {
        0xff => return None,
        0x00 if v.len() != 55 => return None,
        // Future versions may append fields, but only after a '-'.
        _ if v.len() > 55 && v[55] != b'-' => return None,
        _ => {}
    }
    let trace_id: [u8; 16] = hex_bytes(&v[3..35])?;
    let span_id: [u8; 8] = hex_bytes(&v[36..52])?;
    let flags: [u8; 1] = hex_bytes(&v[53..55])?;
    if trace_id == [0; 16] || span_id == [0; 8] {
        return None;
    }
    Some(TraceParent { trace_id, span_id, flags: flags[0] })
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn push_hex(out: &mut Vec<u8>, bytes: &[u8]) {
    for b in bytes {
        out.push(HEX[usize::from(b >> 4)]);
        out.push(HEX[usize::from(b & 0x0f)]);
    }
}

impl TraceParent {
    /// The wire form, always version `00`.
    pub fn to_header(&self) -> HeaderValue {
        let mut out = Vec::with_capacity(55);
        out.extend_from_slice(b"00-");
        push_hex(&mut out, &self.trace_id);
        out.push(b'-');
        push_hex(&mut out, &self.span_id);
        out.push(b'-');
        push_hex(&mut out, &[self.flags]);
        // Only ASCII hex and dashes: always a valid header value.
        HeaderValue::from_bytes(&out)
            .unwrap_or_else(|_| HeaderValue::from_static("00-00000000000000000000000000000000-0000000000000000-00"))
    }

    /// The trace id as 32 lowercase hex characters (for logs).
    pub fn trace_id_hex(&self) -> String {
        let mut out = Vec::with_capacity(32);
        push_hex(&mut out, &self.trace_id);
        String::from_utf8(out).unwrap_or_default()
    }
}

fn nonzero_u64() -> u64 {
    loop {
        let v = fastrand::u64(..);
        if v != 0 {
            return v;
        }
    }
}

fn fresh_span() -> [u8; 8] {
    nonzero_u64().to_be_bytes()
}

fn fresh_trace() -> [u8; 16] {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&nonzero_u64().to_be_bytes());
    id[8..].copy_from_slice(&fastrand::u64(..).to_be_bytes());
    id
}

/// The outgoing trace context for one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outgoing {
    /// What Velox's hop sends upstream (the new span's `traceparent`).
    pub context: TraceParent,
    /// `true` if the inbound request carried a valid context that we continued.
    pub continued: bool,
}

/// Rewrite the trace-context headers of an upstream request in place.
///
/// Returns the context Velox sent, so callers can log the trace id.
pub fn propagate(headers: &mut HeaderMap) -> Outgoing {
    let mut lines = headers.get_all(TRACEPARENT).iter();
    let inbound = match (lines.next(), lines.next()) {
        (Some(only), None) => parse_traceparent(only.as_bytes()),
        _ => None, // absent, or ambiguous (several lines)
    };
    let out = match inbound {
        Some(p) => Outgoing { context: TraceParent { span_id: fresh_span(), ..p }, continued: true },
        None => Outgoing {
            context: TraceParent { trace_id: fresh_trace(), span_id: fresh_span(), flags: 0x01 },
            continued: false,
        },
    };
    headers.insert(TRACEPARENT, out.context.to_header());
    // `tracestate` is only meaningful alongside the traceparent it belongs to.
    let state_ok = out.continued && {
        let (mut total, mut ok) = (0usize, true);
        for v in headers.get_all(TRACESTATE) {
            total += v.len() + 1;
            ok &= v.as_bytes().iter().all(|b| (0x20..0x7f).contains(b));
        }
        ok && total <= MAX_TRACESTATE
    };
    if !state_ok {
        headers.remove(TRACESTATE);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
    const SPAN: &str = "00f067aa0ba902b7";

    fn tp(s: &str) -> Option<TraceParent> {
        parse_traceparent(s.as_bytes())
    }

    #[test]
    fn parses_the_spec_example_and_round_trips() {
        let p = tp(&format!("00-{TRACE}-{SPAN}-01")).unwrap();
        assert_eq!((p.flags, p.trace_id_hex().as_str()), (1, TRACE));
        assert_eq!(p.to_header(), format!("00-{TRACE}-{SPAN}-01").as_str());
        assert_eq!(tp(&format!("00-{TRACE}-{SPAN}-00")).unwrap().flags, 0);
        // Unknown flag bits are preserved, not interpreted.
        assert_eq!(tp(&format!("00-{TRACE}-{SPAN}-ff")).unwrap().flags, 0xff);
    }

    #[test]
    fn rejects_everything_the_spec_rejects() {
        for bad in [
            "".to_owned(),
            "garbage".to_owned(),
            format!("00-{TRACE}-{SPAN}"),                     // no flags
            format!("00-{TRACE}-{SPAN}-0"),                   // short flags
            format!("00-{TRACE}-{SPAN}-001"),                 // long flags
            format!("00-{TRACE}-{SPAN}-01-extra"),            // v00 must be exact
            format!("ff-{TRACE}-{SPAN}-01"),                  // forbidden version
            format!("00-{}-{SPAN}-01", "0".repeat(32)),       // zero trace id
            format!("00-{TRACE}-{}-01", "0".repeat(16)),      // zero span id
            format!("00-{}-{SPAN}-01", TRACE.to_uppercase()), // uppercase
            format!("00-{}g-{SPAN}-01", &TRACE[..31]),        // non-hex
            format!("00_{TRACE}-{SPAN}-01"),                  // wrong separator
            format!("00-{}-{SPAN}-01", &TRACE[..30]),         // short trace id
            format!(" 00-{TRACE}-{SPAN}-01"),                 // leading space
            format!("00-{TRACE}-{SPAN}-01 "),                 // trailing space
            format!("01-{TRACE}-{SPAN}-01x"),                 // future version, junk tail
        ] {
            assert!(tp(&bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn future_versions_are_accepted_by_their_first_four_fields_and_re_emitted_as_00() {
        let p = tp(&format!("01-{TRACE}-{SPAN}-01")).unwrap();
        assert!(p.to_header().to_str().unwrap().starts_with("00-"));
        let p = tp(&format!("cc-{TRACE}-{SPAN}-01-future-field")).unwrap();
        assert_eq!(p.trace_id_hex(), TRACE);
    }

    fn headers(pairs: &[(&'static str, String)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn a_valid_inbound_context_is_continued_with_a_new_span() {
        let mut h = headers(&[
            ("traceparent", format!("00-{TRACE}-{SPAN}-01")),
            ("tracestate", "vendor=opaque,other=1".to_owned()),
        ]);
        let out = propagate(&mut h);
        assert!(out.continued);
        let sent = parse_traceparent(h[TRACEPARENT].as_bytes()).unwrap();
        assert_eq!(sent, out.context);
        assert_eq!(sent.trace_id_hex(), TRACE, "same trace");
        assert_ne!(hex_of(&sent.span_id), SPAN, "a new span for our hop");
        assert_eq!(sent.flags, 1, "sampling decision preserved");
        assert_eq!(h[TRACESTATE], "vendor=opaque,other=1");
        // The sampled-off decision also survives.
        let mut h = headers(&[("traceparent", format!("00-{TRACE}-{SPAN}-00"))]);
        assert_eq!(propagate(&mut h).context.flags, 0);
    }

    fn hex_of(b: &[u8]) -> String {
        let mut v = Vec::new();
        push_hex(&mut v, b);
        String::from_utf8(v).unwrap()
    }

    #[test]
    fn missing_or_invalid_context_starts_a_fresh_trace_and_drops_tracestate() {
        let cases: Vec<Vec<(&'static str, String)>> = vec![
            vec![],
            vec![("traceparent", "nonsense".to_owned()), ("tracestate", "a=b".to_owned())],
            vec![("traceparent", format!("00-{}-{SPAN}-01", "0".repeat(32))), ("tracestate", "a=b".to_owned())],
            // No traceparent at all: a lone tracestate is orphaned and dropped.
            vec![("tracestate", "a=b".to_owned())],
            // Two lines are ambiguous.
            vec![
                ("traceparent", format!("00-{TRACE}-{SPAN}-01")),
                ("traceparent", format!("00-{TRACE}-{SPAN}-00")),
                ("tracestate", "a=b".to_owned()),
            ],
        ];
        for pairs in cases {
            let mut h = headers(&pairs);
            let out = propagate(&mut h);
            assert!(!out.continued, "{pairs:?}");
            let sent = parse_traceparent(h[TRACEPARENT].as_bytes()).expect("always a valid traceparent");
            assert_eq!(sent.flags, 1, "a new trace is sampled");
            assert_ne!(sent.trace_id_hex(), TRACE);
            assert_eq!(h.get_all(TRACEPARENT).iter().count(), 1);
            assert!(!h.contains_key(TRACESTATE), "{pairs:?}");
        }
    }

    #[test]
    fn oversized_or_unprintable_tracestate_is_dropped_but_the_trace_continues() {
        let mut h = headers(&[("traceparent", format!("00-{TRACE}-{SPAN}-01")), ("tracestate", "k=v,".repeat(200))]);
        assert!(propagate(&mut h).continued);
        assert!(!h.contains_key(TRACESTATE));
        let mut h = headers(&[("traceparent", format!("00-{TRACE}-{SPAN}-01"))]);
        // obs-text: legal in a header value, not in tracestate.
        h.insert(TRACESTATE, HeaderValue::from_bytes(b"a=\xffb").unwrap());
        assert!(propagate(&mut h).continued);
        assert!(!h.contains_key(TRACESTATE));
    }

    #[test]
    fn minted_ids_are_never_zero_and_do_not_repeat() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..2000 {
            let mut h = HeaderMap::new();
            let p = propagate(&mut h).context;
            assert_ne!(p.trace_id, [0; 16]);
            assert_ne!(p.span_id, [0; 8]);
            assert!(seen.insert(p.trace_id));
        }
    }

    proptest! {
        #[test]
        fn parsing_arbitrary_bytes_never_panics_and_accepted_values_re_encode(bytes in proptest::collection::vec(any::<u8>(), 0..120)) {
            if let Some(p) = parse_traceparent(&bytes) {
                prop_assert_eq!(parse_traceparent(p.to_header().as_bytes()), Some(p));
            }
        }

        #[test]
        fn propagation_always_yields_exactly_one_valid_traceparent(
            line in "[ -~]{0,80}", extra in proptest::collection::vec("[ -~]{0,80}", 0..3)
        ) {
            let mut h = HeaderMap::new();
            h.append(TRACEPARENT, HeaderValue::from_str(&line).unwrap());
            for e in &extra { h.append(TRACEPARENT, HeaderValue::from_str(e).unwrap()); }
            propagate(&mut h);
            prop_assert_eq!(h.get_all(TRACEPARENT).iter().count(), 1);
            prop_assert!(parse_traceparent(h[TRACEPARENT].as_bytes()).is_some());
        }
    }
}
