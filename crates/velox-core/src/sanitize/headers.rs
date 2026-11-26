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

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn valid_hostname(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty() && name.len() <= 253 && name.split('.').all(valid_label)
}

fn valid_port(p: &str) -> bool {
    !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u16>().is_ok()
}

/// Validate a `Host` / `:authority` value: `reg-name | IPv4 | [IPv6]` with an
/// optional numeric port. Rejects userinfo, whitespace, path characters, etc.
pub fn validate_host(h: &str) -> Result<(), Violation> {
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
            Some((host, port)) => valid_hostname(host) && valid_port(port),
            None => valid_hostname(h),
        }
    };
    if ok {
        Ok(())
    } else {
        Err(Violation::Host)
    }
}

/// Validate a route/SNI host pattern: exact name or `*.suffix`.
pub fn validate_host_pattern(p: &str) -> Result<(), String> {
    let body = p.strip_prefix("*.").unwrap_or(p);
    if valid_hostname(body) {
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
pub fn validate_request_headers(version: Version, headers: &HeaderMap, uri: &Uri) -> Result<(), Violation> {
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
            validate_host(h)?;
            validate_host(a)?;
            if !h.eq_ignore_ascii_case(a) {
                return Err(Violation::Host);
            }
        }
        (Some(v), None) | (None, Some(v)) => validate_host(v)?,
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
pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    if headers.contains_key(CONNECTION) {
        let nominated: Vec<HeaderName> = connection_tokens(headers)
            .filter_map(|t| HeaderName::from_bytes(t.as_bytes()).ok())
            .filter(|n| n != CONTENT_LENGTH && n != HOST)
            .collect();
        for n in nominated {
            headers.remove(n);
        }
    }
    for name in [
        CONNECTION,
        KEEP_ALIVE,
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
        PROXY_CONNECTION,
    ] {
        headers.remove(name);
    }
}

fn is_trusted(ip: IpAddr, trusted: &[IpNet]) -> bool {
    trusted.iter().any(|n| n.contains(&ip))
}

/// Parse the whole `X-Forwarded-For` chain; any invalid hop voids the chain.
fn parse_xff(headers: &HeaderMap) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for v in headers.get_all(X_FORWARDED_FOR) {
        let Ok(s) = v.to_str() else { return Vec::new() };
        for part in s.split(',') {
            match part.trim().parse::<IpAddr>() {
                Ok(ip) => out.push(ip),
                Err(_) => return Vec::new(),
            }
            if out.len() > 64 {
                return Vec::new();
            }
        }
    }
    out
}

/// Determine the real client IP: the TCP peer unless the peer is a trusted
/// proxy, in which case walk `X-Forwarded-For` right-to-left past trusted hops.
pub fn resolve_client_ip(headers: &HeaderMap, peer: IpAddr, trusted: &[IpNet]) -> IpAddr {
    if !is_trusted(peer, trusted) {
        return peer;
    }
    let chain = parse_xff(headers);
    chain.iter().rev().find(|ip| !is_trusted(**ip, trusted)).copied().or_else(|| chain.first().copied()).unwrap_or(peer)
}

fn set_header(headers: &mut HeaderMap, name: HeaderName, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        headers.insert(name, v);
    }
}

fn forwarded_for_token(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("\"[{v6}]\""),
    }
}

/// Rewrite `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`,
/// `X-Real-IP` and `Forwarded` (RFC 7239) for the upstream request.
///
/// Headers from untrusted peers are discarded (anti-spoofing); from trusted
/// proxies they are extended. Returns the resolved client IP.
pub fn apply_forwarded_headers(
    headers: &mut HeaderMap,
    peer: IpAddr,
    trusted: &[IpNet],
    proto: &'static str,
    host: Option<&str>,
) -> IpAddr {
    let peer_trusted = is_trusted(peer, trusted);
    let client = resolve_client_ip(headers, peer, trusted);
    let mut chain = if peer_trusted { parse_xff(headers) } else { Vec::new() };
    chain.push(peer);

    let keep_proto = peer_trusted
        && headers
            .get(X_FORWARDED_PROTO)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("http") || v.eq_ignore_ascii_case("https"));
    let keep_host = peer_trusted
        && headers.get(X_FORWARDED_HOST).and_then(|v| v.to_str().ok()).is_some_and(|v| validate_host(v).is_ok());
    let proto_for_element = if keep_proto {
        headers.get(X_FORWARDED_PROTO).and_then(|v| v.to_str().ok()).map_or(proto, |v| {
            if v.eq_ignore_ascii_case("https") {
                "https"
            } else {
                "http"
            }
        })
    } else {
        proto
    };

    let mut element = String::with_capacity(96);
    let _ = write!(element, "for={};proto={}", forwarded_for_token(peer), proto_for_element);
    if let Some(h) = host {
        let _ = write!(element, ";host=\"{h}\"");
    }
    let existing_forwarded = if peer_trusted {
        let mut parts = Vec::new();
        for v in headers.get_all(FORWARDED) {
            match v.to_str() {
                Ok(s) if s.len() <= 2048 && s.bytes().all(|b| (0x20..0x7f).contains(&b)) => {
                    parts.push(s.trim().to_owned())
                }
                _ => {
                    parts.clear();
                    break;
                }
            }
        }
        parts.join(", ")
    } else {
        String::new()
    };

    for n in [X_FORWARDED_FOR, X_REAL_IP, FORWARDED] {
        headers.remove(n);
    }
    if !keep_proto {
        headers.remove(X_FORWARDED_PROTO);
    }
    if !keep_host {
        headers.remove(X_FORWARDED_HOST);
    }

    let mut xff = String::with_capacity(chain.len() * 16);
    for (i, ip) in chain.iter().enumerate() {
        if i > 0 {
            xff.push_str(", ");
        }
        let _ = write!(xff, "{ip}");
    }
    set_header(headers, X_FORWARDED_FOR, &xff);
    set_header(headers, X_REAL_IP, &client.to_string());
    if !keep_proto {
        set_header(headers, X_FORWARDED_PROTO, proto);
    }
    if !keep_host {
        if let Some(h) = host {
            set_header(headers, X_FORWARDED_HOST, h);
        }
    }
    let forwarded = if existing_forwarded.is_empty() { element } else { format!("{existing_forwarded}, {element}") };
    set_header(headers, FORWARDED, &forwarded);
    client
}

/// Return the inbound `X-Request-Id` if it is safe, otherwise mint a new one.
pub fn request_id_from(headers: &HeaderMap) -> String {
    if let Some(v) = headers.get(X_REQUEST_ID).and_then(|v| v.to_str().ok()) {
        let ok = !v.is_empty()
            && v.len() <= 128
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'/' | b'=' | b'+'));
        if ok {
            return v.to_owned();
        }
    }
    format!("{:032x}", fastrand::u128(..))
}
