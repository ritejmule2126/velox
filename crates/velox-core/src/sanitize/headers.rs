//! Typed header validation and rewriting shared by every protocol.

use super::violation::Violation;
use http::header::{
    HeaderMap, HeaderName, HeaderValue, CONNECTION, CONTENT_LENGTH, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE,
    TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use http::{Uri, Version};
use ipnet::IpNet;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv6Addr};

/// The `X-Request-Id` header name.
pub const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
const X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");
const FORWARDED: HeaderName = HeaderName::from_static("forwarded");
const PROXY_CONNECTION: HeaderName = HeaderName::from_static("proxy-connection");
const KEEP_ALIVE: HeaderName = HeaderName::from_static("keep-alive");

/// RFC 1123 label: letters, digits and hyphens, not starting or ending with
/// a hyphen, 1–63 octets. Underscores are *not* hostname characters; they are
/// only tolerated when the operator opts in (`allow_underscore`), e.g. for
/// container service names.
fn valid_label(label: &str, allow_underscore: bool) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || (allow_underscore && b == b'_'))
}

fn valid_hostname(name: &str, allow_underscore: bool) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty() && name.len() <= 253 && name.split('.').all(|l| valid_label(l, allow_underscore))
}

fn valid_port(p: &str) -> bool {
    !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u16>().is_ok()
}

/// Validate a `Host` / `:authority` value: `reg-name | IPv4 | [IPv6]` with an
/// optional numeric port. Rejects userinfo, whitespace, path characters and
/// underscores (strict RFC 1123 labels).
pub fn validate_host(h: &str) -> Result<(), Violation> {
    validate_host_with(h, false)
}

/// [`validate_host`] with an explicit policy for `_` in labels.
pub fn validate_host_with(h: &str, allow_underscore: bool) -> Result<(), Violation> {
    if h.is_empty() || h.len() > 255 {
        return Err(Violation::Host);
    }
    let ok = if let Some(rest) = h.strip_prefix('[') {
        match rest.split_once(']') {
            Some((ip, after)) => {
                ip.parse::<Ipv6Addr>().is_ok() && (after.is_empty() || after.strip_prefix(':').is_some_and(valid_port))
            }
            None => false,
        }
    } else {
        match h.rsplit_once(':') {
            Some((host, port)) => valid_hostname(host, allow_underscore) && valid_port(port),
            None => valid_hostname(h, allow_underscore),
        }
    };
    if ok {
        Ok(())
    } else {
        Err(Violation::Host)
    }
}

/// Validate a route/SNI host pattern: exact name or `*.suffix`.
pub fn validate_host_pattern(p: &str, allow_underscore: bool) -> Result<(), String> {
    let body = p.strip_prefix("*.").unwrap_or(p);
    if valid_hostname(body, allow_underscore) {
        Ok(())
    } else {
        Err("must be a host name or `*.suffix`".to_owned())
    }
}

/// The host part of a (validated) authority, without port or IPv6 brackets
/// retained, and without a trailing dot.
pub fn host_without_port(authority: &str) -> &str {
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split_once(']').map_or(rest, |(ip, _)| ip)
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, _)| h)
    };
    host.strip_suffix('.').unwrap_or(host)
}

fn digits_only(v: &[u8]) -> bool {
    !v.is_empty() && v.len() <= 19 && v.iter().all(u8::is_ascii_digit)
}

/// Defence-in-depth validation of a parsed request, for all HTTP versions.
///
/// For HTTP/1 the byte-level guard has already run; this additionally covers
/// HTTP/2 and HTTP/3 where `hyper`/`h3` hand us typed headers.
pub fn validate_request_headers(
    version: Version,
    headers: &HeaderMap,
    uri: &Uri,
    allow_underscore_host: bool,
) -> Result<(), Violation> {
    let modern = matches!(version, Version::HTTP_2 | Version::HTTP_3);

    // --- host / :authority ---
    if headers.get_all(HOST).iter().count() > 1 {
        return Err(Violation::Host);
    }
    let host_hdr = match headers.get(HOST) {
        Some(v) => Some(v.to_str().map_err(|_| Violation::Host)?),
        None => None,
    };
    let authority = uri.authority().map(http::uri::Authority::as_str);
    match (host_hdr, authority) {
        (Some(h), Some(a)) => {
            validate_host_with(h, allow_underscore_host)?;
            validate_host_with(a, allow_underscore_host)?;
            if !h.eq_ignore_ascii_case(a) {
                return Err(Violation::Host);
            }
        }
        (Some(v), None) | (None, Some(v)) => validate_host_with(v, allow_underscore_host)?,
        (None, None) => {
            if version == Version::HTTP_11 || modern {
                return Err(Violation::Host);
            }
        }
    }

    // --- target form ---
    let path = uri.path();
    if !(path.starts_with('/') || path == "*") {
        return Err(Violation::Target);
    }

    // --- framing ---
    let cl_count = headers.get_all(CONTENT_LENGTH).iter().count();
    let te_count = headers.get_all(TRANSFER_ENCODING).iter().count();
    if cl_count > 1 {
        return Err(Violation::ContentLength);
    }
    if let Some(v) = headers.get(CONTENT_LENGTH) {
        if !digits_only(v.as_bytes()) {
            return Err(Violation::ContentLength);
        }
    }
    if cl_count > 0 && te_count > 0 {
        return Err(Violation::ContentLengthWithTransferEncoding);
    }
    if te_count > 0 {
        if modern {
            return Err(Violation::ConnectionSpecificHeader);
        }
        let ok = te_count == 1
            && headers
                .get(TRANSFER_ENCODING)
                .is_some_and(|v| v.as_bytes().trim_ascii().eq_ignore_ascii_case(b"chunked"));
        if !ok {
            return Err(Violation::TransferEncoding);
        }
    }
    if modern {
        for name in [CONNECTION, KEEP_ALIVE, PROXY_CONNECTION, UPGRADE] {
            if headers.contains_key(&name) {
                return Err(Violation::ConnectionSpecificHeader);
            }
        }
        if let Some(te) = headers.get(TE) {
            if !te.as_bytes().trim_ascii().eq_ignore_ascii_case(b"trailers") {
                return Err(Violation::ConnectionSpecificHeader);
            }
        }
    }
    Ok(())
}

fn connection_tokens(headers: &HeaderMap) -> impl Iterator<Item = &str> {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

/// `true` for a WebSocket upgrade: `Connection: upgrade` plus
/// `Upgrade: websocket`. Other upgrade protocols (e.g. `h2c`) are not honoured.
pub fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    connection_tokens(headers).any(|t| t.eq_ignore_ascii_case("upgrade"))
        && headers.get(UPGRADE).is_some_and(|v| v.as_bytes().trim_ascii().eq_ignore_ascii_case(b"websocket"))
}

/// Remove hop-by-hop headers (RFC 9110 §7.6.1) plus any header nominated by
/// `Connection`. Framing headers are never removable via `Connection`.
///
/// Allocation-free: nominated names are removed straight from the borrowed
/// token text rather than being parsed into owned `HeaderName`s.
pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    if let http::header::Entry::Occupied(entry) = headers.entry(CONNECTION) {
        // Draining the values releases the borrow on `headers` so the
        // nominated headers can be removed while we still read the tokens.
        let (_, values) = entry.remove_entry_mult();
        let mut inline: [Option<HeaderValue>; 4] = [None, None, None, None];
        let mut spill: Vec<HeaderValue> = Vec::new(); // empty Vec does not allocate
        for (i, v) in values.enumerate() {
            match inline.get_mut(i) {
                Some(slot) => *slot = Some(v),
                None => spill.push(v),
            }
        }
        for v in inline.iter().flatten().chain(spill.iter()) {
            remove_nominated(headers, v);
        }
    }
    for name in
        [KEEP_ALIVE, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE, PROXY_CONNECTION]
    {
        headers.remove(name);
    }
}

fn remove_nominated(headers: &mut HeaderMap, connection_value: &HeaderValue) {
    let Ok(text) = connection_value.to_str() else { return };
    for token in text.split(',').map(str::trim) {
        if token.is_empty() || token.eq_ignore_ascii_case("content-length") || token.eq_ignore_ascii_case("host") {
            continue;
        }
        // `remove` on a `&str` key looks the name up without allocating and
        // simply finds nothing for tokens that are not valid header names.
        headers.remove(token);
    }
}

fn is_trusted(ip: IpAddr, trusted: &[IpNet]) -> bool {
    trusted.iter().any(|n| n.contains(&ip))
}

/// Is the whole `X-Forwarded-For` chain present and made of valid IPs?
/// (Any invalid hop voids the chain; more than 64 hops is refused.)
fn xff_valid(headers: &HeaderMap) -> bool {
    let mut n = 0usize;
    for v in headers.get_all(X_FORWARDED_FOR) {
        let Ok(s) = v.to_str() else { return false };
        for part in s.split(',') {
            if part.trim().parse::<IpAddr>().is_err() {
                return false;
            }
            n += 1;
            if n > 64 {
                return false;
            }
        }
    }
    n > 0
}

/// Walk a *validated* chain right-to-left past trusted hops.
fn client_from_valid_chain(headers: &HeaderMap, trusted: &[IpNet]) -> Option<IpAddr> {
    let mut leftmost = None;
    for v in headers.get_all(X_FORWARDED_FOR).iter().rev() {
        for part in v.to_str().ok()?.rsplit(',') {
            let ip: IpAddr = part.trim().parse().ok()?;
            if !is_trusted(ip, trusted) {
                return Some(ip);
            }
            leftmost = Some(ip);
        }
    }
    leftmost // every hop was trusted: the leftmost is the best we have
}

/// Determine the real client IP: the TCP peer unless the peer is a trusted
/// proxy, in which case walk `X-Forwarded-For` right-to-left past trusted hops.
pub fn resolve_client_ip(headers: &HeaderMap, peer: IpAddr, trusted: &[IpNet]) -> IpAddr {
    if !is_trusted(peer, trusted) || !xff_valid(headers) {
        return peer;
    }
    client_from_valid_chain(headers, trusted).unwrap_or(peer)
}

/// A small formatting buffer: 256 bytes inline, spilling to the heap only for
/// unusually long values. Lets header values be built without intermediate
/// `String`s.
struct SmallBuf {
    inline: [u8; 256],
    len: usize,
    spill: Vec<u8>,
}

impl SmallBuf {
    fn new() -> Self {
        Self { inline: [0; 256], len: 0, spill: Vec::new() }
    }

    fn push(&mut self, bytes: &[u8]) {
        if self.spill.is_empty() && self.len + bytes.len() <= self.inline.len() {
            self.inline[self.len..self.len + bytes.len()].copy_from_slice(bytes);
            self.len += bytes.len();
        } else {
            if self.spill.is_empty() {
                self.spill.extend_from_slice(&self.inline[..self.len]);
            }
            self.spill.extend_from_slice(bytes);
        }
    }

    fn as_bytes(&self) -> &[u8] {
        if self.spill.is_empty() {
            &self.inline[..self.len]
        } else {
            &self.spill
        }
    }

    fn is_empty(&self) -> bool {
        self.as_bytes().is_empty()
    }

    fn to_value(&self) -> Option<HeaderValue> {
        HeaderValue::from_bytes(self.as_bytes()).ok()
    }
}

impl std::fmt::Write for SmallBuf {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.push(s.as_bytes());
        Ok(())
    }
}

fn forwarded_values_safe(headers: &HeaderMap) -> bool {
    headers.get_all(FORWARDED).iter().all(|v| v.len() <= 2048 && v.as_bytes().iter().all(|b| (0x20..0x7f).contains(b)))
}

/// The protocol a *trusted* proxy says the client used: the first
/// (client-most) token of `X-Forwarded-Proto`, else the first element of
/// `Forwarded` (RFC 7239) that carries `proto=`. Anything but `http`/`https`
/// is ignored. The caller must already have established that the peer is
/// trusted.
fn forwarded_proto(headers: &HeaderMap) -> Option<&'static str> {
    fn scheme(v: &[u8]) -> Option<&'static str> {
        let v = v.trim_ascii();
        if v.eq_ignore_ascii_case(b"https") {
            Some("https")
        } else if v.eq_ignore_ascii_case(b"http") {
            Some("http")
        } else {
            None
        }
    }
    if let Some(v) = headers.get(X_FORWARDED_PROTO) {
        return scheme(v.as_bytes().split(|&b| b == b',').next().unwrap_or(&[]));
    }
    let first = headers.get(FORWARDED)?.as_bytes().split(|&b| b == b',').next()?;
    first.split(|&b| b == b';').find_map(|pair| {
        let pair = pair.trim_ascii();
        let eq = pair.iter().position(|&b| b == b'=')?;
        let (k, v) = pair.split_at(eq);
        if !k.trim_ascii().eq_ignore_ascii_case(b"proto") {
            return None;
        }
        let v = v[1..].trim_ascii();
        let v = v.strip_prefix(b"\"").and_then(|q| q.strip_suffix(b"\"")).unwrap_or(v);
        scheme(v)
    })
}

/// Is this request already HTTPS according to a proxy we trust?
///
/// True only when `peer` is in `trusted` *and* says (via `X-Forwarded-Proto`
/// or `Forwarded: proto=`) that the client connection used HTTPS. Used to stop
/// `redirect_https` from looping behind a TLS-terminating load balancer.
pub fn is_https_via_trusted_proxy(headers: &HeaderMap, peer: IpAddr, trusted: &[IpNet]) -> bool {
    is_trusted(peer, trusted) && forwarded_proto(headers) == Some("https")
}

/// Rewrite `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`,
/// `X-Real-IP` and `Forwarded` (RFC 7239) for the upstream request.
///
/// Headers from untrusted peers are discarded (anti-spoofing); from trusted
/// proxies they are extended. `client` must come from [`resolve_client_ip`].
/// Values are formatted into stack buffers, so each header costs one
/// allocation (its `HeaderValue`) and nothing else; `host`, already a
/// `HeaderValue`, is shared by reference count.
pub fn apply_forwarded_headers_hv(
    headers: &mut HeaderMap,
    peer: IpAddr,
    trusted: &[IpNet],
    proto: &'static str,
    host: Option<&HeaderValue>,
    client: IpAddr,
) {
    let peer_trusted = is_trusted(peer, trusted);
    let chain_ok = peer_trusted && xff_valid(headers);

    // Honour an upstream proxy's proto/host only when it is trusted *and* sane.
    let kept_proto: Option<&'static str> = if peer_trusted { forwarded_proto(headers) } else { None };
    let keep_host = peer_trusted
        && headers.get(X_FORWARDED_HOST).and_then(|v| v.to_str().ok()).is_some_and(|v| validate_host(v).is_ok());

    // X-Forwarded-For: existing chain (if trusted and valid) + this hop.
    let mut xff = SmallBuf::new();
    if chain_ok {
        for v in headers.get_all(X_FORWARDED_FOR) {
            for part in v.to_str().unwrap_or("").split(',') {
                xff.push(part.trim().as_bytes());
                xff.push(b", ");
            }
        }
    }
    let _ = write!(xff, "{peer}");

    // Forwarded (RFC 7239): existing elements + ours.
    let mut fwd = SmallBuf::new();
    if peer_trusted && forwarded_values_safe(headers) {
        for v in headers.get_all(FORWARDED) {
            let s = v.as_bytes().trim_ascii();
            if !s.is_empty() {
                if !fwd.is_empty() {
                    fwd.push(b", ");
                }
                fwd.push(s);
            }
        }
        if !fwd.is_empty() {
            fwd.push(b", ");
        }
    }
    match peer {
        IpAddr::V4(v4) => {
            let _ = write!(fwd, "for={v4}");
        }
        IpAddr::V6(v6) => {
            let _ = write!(fwd, "for=\"[{v6}]\"");
        }
    }
    let _ = write!(fwd, ";proto={}", kept_proto.unwrap_or(proto));
    if let Some(h) = host.and_then(|h| h.to_str().ok()) {
        let _ = write!(fwd, ";host=\"{h}\"");
    }

    let mut real_ip = SmallBuf::new();
    let _ = write!(real_ip, "{client}");
    for (name, buf) in [(X_FORWARDED_FOR, &xff), (X_REAL_IP, &real_ip), (FORWARDED, &fwd)] {
        match buf.to_value() {
            Some(v) => {
                headers.insert(name, v);
            }
            None => {
                headers.remove(name);
            }
        }
    }
    // Always normalised: a trusted `https, http` list becomes plain `https`.
    headers.insert(X_FORWARDED_PROTO, HeaderValue::from_static(kept_proto.unwrap_or(proto)));
    if !keep_host {
        match host {
            Some(h) => {
                headers.insert(X_FORWARDED_HOST, h.clone());
            }
            None => {
                headers.remove(X_FORWARDED_HOST);
            }
        }
    }
}

/// Convenience wrapper over [`apply_forwarded_headers_hv`] taking a `&str`
/// host and resolving the client IP itself. Returns the resolved client IP.
pub fn apply_forwarded_headers(
    headers: &mut HeaderMap,
    peer: IpAddr,
    trusted: &[IpNet],
    proto: &'static str,
    host: Option<&str>,
) -> IpAddr {
    let client = resolve_client_ip(headers, peer, trusted);
    let host = host.and_then(|h| HeaderValue::from_str(h).ok());
    apply_forwarded_headers_hv(headers, peer, trusted, proto, host.as_ref(), client);
    client
}

/// The inbound `X-Request-Id` if it is a safe token, otherwise a fresh one.
///
/// Returns a ready-to-use [`HeaderValue`]: reusing an inbound id is a
/// reference-count bump, and a generated id costs a single small allocation.
pub fn request_id_from(headers: &HeaderMap) -> HeaderValue {
    if let Some(v) = headers.get(X_REQUEST_ID) {
        let b = v.as_bytes();
        let ok = !b.is_empty()
            && b.len() <= 128
            && b.iter()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b':' | b'/' | b'=' | b'+'));
        if ok {
            return v.clone();
        }
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut n = fastrand::u128(..);
    let mut buf = [0u8; 32];
    for slot in buf.iter_mut().rev() {
        *slot = HEX[(n & 0xf) as usize];
        n >>= 4;
    }
    HeaderValue::from_bytes(&buf).unwrap_or_else(|_| HeaderValue::from_static("0"))
}
