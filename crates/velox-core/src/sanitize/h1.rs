//! Wire-level HTTP/1.x request validation.
//!
//! This module is *sans-IO*: it inspects raw bytes **before** `hyper` parses
//! (and normalises) them, so ambiguous framing — the root cause of request
//! smuggling — is rejected rather than silently "fixed".
//!
//! * [`HeadScanner`] finds the end of a request head while enforcing strict
//!   CRLF discipline (no bare CR/LF, no NUL/control bytes, no obs-fold).
//! * [`parse_request_head`] runs `httparse` plus Velox's own policy checks.
//! * [`ChunkedDecoder`] validates chunked framing without buffering.
//! * [`H1Guard`] ties these together into a per-connection state machine that
//!   tracks message boundaries across keep-alive and pipelining.

use super::violation::Violation;
use super::{validate_host_with, MAX_PARSE_HEADERS};

/// Limits enforced while scanning an HTTP/1 request head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H1Limits {
    /// Maximum bytes in request line + headers (including the final CRLFCRLF).
    pub max_head_bytes: usize,
    /// Maximum number of headers.
    pub max_headers: usize,
    /// Maximum request-target length.
    pub max_uri_bytes: usize,
    /// Tolerate `_` in `Host` labels (off by default: not an RFC 1123 character).
    pub allow_underscores_in_host: bool,
}

impl Default for H1Limits {
    fn default() -> Self {
        Self { max_head_bytes: 16 * 1024, max_headers: 100, max_uri_bytes: 8 * 1024, allow_underscores_in_host: false }
    }
}

/// How the request body is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    /// No body.
    None,
    /// Exactly this many bytes.
    Length(u64),
    /// `Transfer-Encoding: chunked`.
    Chunked,
}

/// Facts extracted from a validated request head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadInfo {
    /// Body delimitation.
    pub framing: BodyFraming,
    /// `true` for a WebSocket upgrade (`Connection: upgrade` + `Upgrade: websocket`).
    pub upgrade: bool,
    /// HTTP minor version (0 or 1).
    pub version_minor: u8,
}

/// Incremental finder for the end of a request head with strict line-ending
/// rules. State survives across calls so it runs in O(bytes) overall.
#[derive(Debug, Default, Clone)]
pub struct HeadScanner {
    prev: u8,
    run: u8,
    len: usize,
}

/// `true` if none of the eight bytes in `w` is a control character
/// (`< 0x20`) or `0x7f` — i.e. all eight are "boring" header text.
///
/// Classic SWAR zero/less-than detection (exact for existence). Bytes >= 0x80
/// (obs-text) and printable ASCII, including space, pass; tab does not (it is
/// handled by the byte-wise path, where it is rare).
#[inline]
fn word_is_plain(w: u64) -> bool {
    const ONES: u64 = 0x0101_0101_0101_0101;
    const HIGH: u64 = 0x8080_8080_8080_8080;
    let below_space = w.wrapping_sub(ONES * 0x20) & !w & HIGH;
    let x = w ^ (ONES * 0x7f);
    let is_del = x.wrapping_sub(ONES) & !x & HIGH;
    (below_space | is_del) == 0
}

/// Test-only handle on [`word_is_plain`].
#[cfg(test)]
pub(crate) fn word_is_plain_for_tests(w: u64) -> bool {
    word_is_plain(w)
}

impl HeadScanner {
    /// Forget all state (call between messages).
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// One byte of the strict state machine.
    #[inline]
    fn step(&mut self, b: u8, max_head_bytes: usize) -> Result<bool, Violation> {
        self.len += 1;
        if self.len > max_head_bytes {
            return Err(Violation::HeadTooLarge);
        }
        let p = self.prev;
        if self.len == 1 && (b == b'\r' || b == b'\n') {
            return Err(Violation::Malformed);
        }
        if p == b'\r' && b != b'\n' {
            return Err(Violation::BareLineEnding);
        }
        match b {
            b'\n' if p != b'\r' => return Err(Violation::BareLineEnding),
            b' ' | b'\t' if p == b'\n' => return Err(Violation::ObsFold),
            b'\r' | b'\n' | b' ' | b'\t' => {}
            0x00..=0x1f | 0x7f => return Err(Violation::ControlCharacter),
            _ => {}
        }
        self.prev = b;
        let mut end = false;
        self.run = match (self.run, b) {
            (1, b'\n') => 2,
            (2, b'\r') => 3,
            (3, b'\n') => {
                end = true;
                0
            }
            (_, b'\r') => 1,
            _ => 0,
        };
        Ok(end)
    }

    /// Scan `data`; returns `Some(n)` when the head ends after `data[..n]`.
    ///
    /// Runs of plain header text are skipped eight bytes at a time; anything
    /// that could matter (CR, LF, tab, control bytes, a position right after a
    /// line break) goes through the exact byte-wise state machine.
    pub fn scan(&mut self, data: &[u8], max_head_bytes: usize) -> Result<Option<usize>, Violation> {
        let mut i = 0;
        while i < data.len() {
            if self.len > 0 && self.prev != b'\r' && self.prev != b'\n' && self.len + 8 <= max_head_bytes {
                if let Some(chunk) = data.get(i..i + 8).and_then(|c| <[u8; 8]>::try_from(c).ok()) {
                    if word_is_plain(u64::from_le_bytes(chunk)) {
                        self.len += 8;
                        self.prev = chunk[7];
                        self.run = 0;
                        i += 8;
                        continue;
                    }
                }
            }
            if self.step(data[i], max_head_bytes)? {
                return Ok(Some(i + 1));
            }
            i += 1;
        }
        Ok(None)
    }

    /// The original byte-at-a-time scanner, kept as a test oracle.
    #[cfg(test)]
    pub(crate) fn scan_reference(&mut self, data: &[u8], max_head_bytes: usize) -> Result<Option<usize>, Violation> {
        for (i, &b) in data.iter().enumerate() {
            if self.step(b, max_head_bytes)? {
                return Ok(Some(i + 1));
            }
        }
        Ok(None)
    }

    /// Internal state, for equivalence tests.
    #[cfg(test)]
    pub(crate) fn state(&self) -> (u8, u8, usize) {
        (self.prev, self.run, self.len)
    }
}

fn map_httparse(e: httparse::Error) -> Violation {
    match e {
        httparse::Error::TooManyHeaders => Violation::TooManyHeaders,
        httparse::Error::Version => Violation::Version,
        _ => Violation::Malformed,
    }
}

fn trim_ows(mut v: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = v {
        v = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = v {
        v = rest;
    }
    v
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

/// `name` equals `target` once `_` is read as `-` (and ignoring ASCII case).
fn eq_underscore_variant(name: &str, target: &str) -> bool {
    name.len() == target.len()
        && name.bytes().zip(target.bytes()).all(|(a, b)| a.eq_ignore_ascii_case(&b) || (a == b'_' && b == b'-'))
}

fn parse_content_length(v: &[u8]) -> Result<u64, Violation> {
    let v = trim_ows(v);
    if v.is_empty() || v.len() > 19 || !v.iter().all(u8::is_ascii_digit) {
        return Err(Violation::ContentLength);
    }
    let mut n: u64 = 0;
    for &d in v {
        n = n.checked_mul(10).and_then(|n| n.checked_add(u64::from(d - b'0'))).ok_or(Violation::ContentLength)?;
    }
    Ok(n)
}

/// Accept exactly `chunked` (case-insensitive); classify everything else.
fn check_transfer_encoding(v: &[u8]) -> Result<(), Violation> {
    let v = trim_ows(v);
    if v.eq_ignore_ascii_case(b"chunked") {
        return Ok(());
    }
    // A syntactically clean coding list we merely do not support → 501;
    // anything with odd bytes (TE.TE obfuscation) → 400.
    let clean = !v.is_empty() && v.iter().all(|&b| is_tchar(b) || b == b',' || b == b' ');
    if clean {
        Err(Violation::UnsupportedTransferCoding)
    } else {
        Err(Violation::TransferEncoding)
    }
}

/// Validate one complete request head (`head` ends right after CRLFCRLF).
///
/// Enforces: single `Host` (HTTP/1.1), strictly numeric single
/// `Content-Length`, `Transfer-Encoding` of exactly `chunked`, no CL+TE,
/// no ambiguous header names, origin-form targets, no `CONNECT`/`TRACE`.
pub fn parse_request_head(head: &[u8], limits: &H1Limits) -> Result<HeadInfo, Violation> {
    let mut storage = [httparse::EMPTY_HEADER; MAX_PARSE_HEADERS];
    let mut req = httparse::Request::new(&mut storage);
    let consumed = match req.parse(head).map_err(map_httparse)? {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => return Err(Violation::Malformed),
    };
    if consumed != head.len() {
        return Err(Violation::Malformed);
    }
    let version_minor = match req.version {
        Some(0) => 0,
        Some(1) => 1,
        _ => return Err(Violation::Version),
    };
    let method = req.method.ok_or(Violation::Malformed)?;
    if method.eq_ignore_ascii_case("CONNECT") || method.eq_ignore_ascii_case("TRACE") {
        return Err(Violation::Method);
    }
    let path = req.path.ok_or(Violation::Malformed)?;
    if path.len() > limits.max_uri_bytes {
        return Err(Violation::UriTooLong);
    }
    let origin_form = path.starts_with('/');
    let asterisk = path == "*" && method == "OPTIONS";
    if !(origin_form || asterisk) {
        return Err(Violation::Target);
    }
    if req.headers.len() > limits.max_headers {
        return Err(Violation::TooManyHeaders);
    }

    let mut host_count = 0usize;
    let mut content_length: Option<u64> = None;
    let mut cl_count = 0usize;
    let mut te_count = 0usize;
    let mut connection_upgrade = false;
    let mut upgrade_websocket = false;

    for h in req.headers.iter() {
        let name = h.name;
        let value = h.value;
        for framing in ["content-length", "transfer-encoding", "host", "connection", "upgrade", "te"] {
            if name.contains('_') && eq_underscore_variant(name, framing) {
                return Err(Violation::AmbiguousHeaderName);
            }
        }
        if name.eq_ignore_ascii_case("host") {
            host_count += 1;
            let s = std::str::from_utf8(trim_ows(value)).map_err(|_| Violation::Host)?;
            validate_host_with(s, limits.allow_underscores_in_host)?;
        } else if name.eq_ignore_ascii_case("content-length") {
            cl_count += 1;
            content_length = Some(parse_content_length(value)?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            te_count += 1;
            check_transfer_encoding(value)?;
        } else if name.eq_ignore_ascii_case("connection") {
            for token in trim_ows(value).split(|&b| b == b',') {
                let token = trim_ows(token);
                if token.eq_ignore_ascii_case(b"upgrade") {
                    connection_upgrade = true;
                } else if token.eq_ignore_ascii_case(b"content-length")
                    || token.eq_ignore_ascii_case(b"host")
                    || token.eq_ignore_ascii_case(b"transfer-encoding")
                {
                    return Err(Violation::ConnectionNominatesFraming);
                }
            }
        } else if name.eq_ignore_ascii_case("upgrade") {
            upgrade_websocket = trim_ows(value).eq_ignore_ascii_case(b"websocket");
        }
    }

    if cl_count > 1 {
        return Err(Violation::ContentLength);
    }
    if te_count > 1 {
        return Err(Violation::TransferEncoding);
    }
    if cl_count > 0 && te_count > 0 {
        return Err(Violation::ContentLengthWithTransferEncoding);
    }
    if te_count > 0 && version_minor == 0 {
        return Err(Violation::TransferEncoding);
    }
    if host_count > 1 || (version_minor == 1 && host_count == 0) {
        return Err(Violation::Host);
    }
    let framing = if te_count > 0 {
        BodyFraming::Chunked
    } else {
        match content_length {
            Some(n) if n > 0 => BodyFraming::Length(n),
            _ => BodyFraming::None,
        }
    };
    let upgrade = connection_upgrade && upgrade_websocket;
    if upgrade && framing != BodyFraming::None {
        return Err(Violation::UpgradeWithBody);
    }
    Ok(HeadInfo { framing, upgrade, version_minor })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkState {
    SizeStart,
    Size { value: u64, digits: u8 },
    Ext { len: u16, value: u64 },
    SizeLf { value: u64 },
    Data(u64),
    DataCr,
    DataLf,
    TrailerLineStart,
    TrailerName,
    TrailerValue,
    TrailerLf { empty: bool },
    Done,
}

/// Streaming validator for `Transfer-Encoding: chunked` framing.
///
/// Rejects non-hex sizes, oversized size fields, bare LFs, missing chunk
/// terminators and trailers that try to smuggle framing headers.
#[derive(Debug, Clone)]
pub struct ChunkedDecoder {
    state: ChunkState,
    name: [u8; 24],
    name_len: usize,
    trailer_bytes: usize,
    max_trailer_bytes: usize,
}

impl ChunkedDecoder {
    /// Create a decoder; trailers may total at most `max_trailer_bytes`.
    pub fn new(max_trailer_bytes: usize) -> Self {
        Self { state: ChunkState::SizeStart, name: [0; 24], name_len: 0, trailer_bytes: 0, max_trailer_bytes }
    }

    /// Consume bytes; returns `(consumed, finished)`. Stops exactly at the end
    /// of the message so the caller can treat the remainder as the next head.
    pub fn feed(&mut self, data: &[u8]) -> Result<(usize, bool), Violation> {
        let mut i = 0;
        while i < data.len() {
            if let ChunkState::Data(rem) = self.state {
                let take = usize::try_from(rem).unwrap_or(usize::MAX).min(data.len() - i);
                i += take;
                let left = rem - take as u64;
                self.state = if left == 0 { ChunkState::DataCr } else { ChunkState::Data(left) };
                continue;
            }
            let b = data[i];
            i += 1;
            self.step(b)?;
            if self.state == ChunkState::Done {
                return Ok((i, true));
            }
        }
        Ok((i, false))
    }

    fn step(&mut self, b: u8) -> Result<(), Violation> {
        use ChunkState as S;
        let bad = Violation::Chunk;
        self.state = match self.state {
            S::SizeStart => S::Size { value: u64::from(hex(b).ok_or(bad)?), digits: 1 },
            S::Size { value, digits } => match b {
                b'\r' => S::SizeLf { value },
                b';' => S::Ext { len: 0, value },
                _ => {
                    let d = hex(b).ok_or(bad)?;
                    if digits >= 16 {
                        return Err(bad);
                    }
                    S::Size { value: value.checked_mul(16).ok_or(bad)? | u64::from(d), digits: digits + 1 }
                }
            },
            S::Ext { len, value } => match b {
                b'\r' => S::SizeLf { value },
                0x00..=0x08 | 0x0a..=0x1f | 0x7f => return Err(bad),
                _ if len >= 1024 => return Err(bad),
                _ => S::Ext { len: len + 1, value },
            },
            S::SizeLf { value } => {
                if b != b'\n' {
                    return Err(bad);
                }
                if value == 0 {
                    S::TrailerLineStart
                } else {
                    S::Data(value)
                }
            }
            S::Data(_) => return Err(bad), // handled in `feed`
            S::DataCr => {
                if b != b'\r' {
                    return Err(bad);
                }
                S::DataLf
            }
            S::DataLf => {
                if b != b'\n' {
                    return Err(bad);
                }
                S::SizeStart
            }
            S::TrailerLineStart => {
                self.count_trailer_byte()?;
                match b {
                    b'\r' => S::TrailerLf { empty: true },
                    _ if is_tchar(b) => {
                        self.name[0] = b.to_ascii_lowercase();
                        self.name_len = 1;
                        S::TrailerName
                    }
                    _ => return Err(bad),
                }
            }
            S::TrailerName => {
                self.count_trailer_byte()?;
                match b {
                    b':' => {
                        let n = &self.name[..self.name_len.min(self.name.len())];
                        if self.name_len <= self.name.len()
                            && matches!(n, b"content-length" | b"transfer-encoding" | b"host")
                        {
                            return Err(bad);
                        }
                        S::TrailerValue
                    }
                    _ if is_tchar(b) => {
                        if self.name_len < self.name.len() {
                            self.name[self.name_len] = b.to_ascii_lowercase();
                        }
                        self.name_len += 1;
                        S::TrailerName
                    }
                    _ => return Err(bad),
                }
            }
            S::TrailerValue => {
                self.count_trailer_byte()?;
                match b {
                    b'\r' => S::TrailerLf { empty: false },
                    b'\t' => S::TrailerValue,
                    0x00..=0x1f | 0x7f => return Err(bad),
                    _ => S::TrailerValue,
                }
            }
            S::TrailerLf { empty } => {
                self.count_trailer_byte()?;
                if b != b'\n' {
                    return Err(bad);
                }
                if empty {
                    S::Done
                } else {
                    S::TrailerLineStart
                }
            }
            S::Done => S::Done,
        };
        Ok(())
    }

    fn count_trailer_byte(&mut self) -> Result<(), Violation> {
        self.trailer_bytes += 1;
        if self.trailer_bytes > self.max_trailer_bytes {
            Err(Violation::Chunk)
        } else {
            Ok(())
        }
    }
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// A violation found by [`H1Guard`].
///
/// When a violation is reported, **nothing** from the offending chunk is
/// released to the HTTP layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardError {
    /// What was wrong.
    pub violation: Violation,
    /// `true` if the stream was between messages (a clean `400` can still be
    /// sent); `false` if the problem is inside a request body.
    pub at_message_boundary: bool,
}

/// The part of the input that has been validated and may be forwarded.
///
/// The bytes to deliver are `carried` followed by `data[skip..len]` of the
/// chunk passed to [`H1Guard::feed`] (`data[..skip]` is already inside
/// `carried`). Anything after `len` is a request head still being received;
/// the guard keeps a copy and releases it (as `carried` in a later call) only
/// once the *complete* head has been validated.
///
/// `carried` borrows a buffer owned (and reused) by the guard, so a head that
/// spans several reads costs no allocation after the first one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Release<'a> {
    /// Previously withheld head bytes that are now cleared for delivery.
    pub carried: &'a [u8],
    /// `true` while a request head is still incomplete after this chunk.
    pub partial_head: bool,
    /// Leading bytes of the current chunk already contained in `carried`.
    pub skip: usize,
    /// End (exclusive) of the part of the current chunk cleared for delivery.
    pub len: usize,
}

#[derive(Debug, Clone)]
enum GuardState {
    Head,
    Body(u64),
    Chunked(ChunkedDecoder),
    Passthrough,
}

/// Per-connection HTTP/1 request-stream validator.
///
/// Feed it every byte read from the client; it tracks message boundaries
/// (Content-Length and chunked bodies, pipelining, keep-alive) and returns a
/// [`GuardError`] at the first ambiguity. Request heads are **withheld until
/// complete and valid**, so no byte of a rejected request ever reaches the
/// HTTP library. After a WebSocket upgrade it stops inspecting the (now
/// non-HTTP) byte stream.
#[derive(Debug, Clone)]
pub struct H1Guard {
    limits: H1Limits,
    state: GuardState,
    scanner: HeadScanner,
    /// A request head still being received (withheld from the HTTP layer).
    head: Vec<u8>,
    /// The last completed withheld head, lent out through [`Release`].
    carry: Vec<u8>,
}

/// Buffers that grew beyond this are released instead of kept for reuse.
const BUFFER_RETAIN_MAX: usize = 16 * 1024;

impl H1Guard {
    /// Create a guard enforcing `limits`.
    pub fn new(limits: H1Limits) -> Self {
        Self { limits, state: GuardState::Head, scanner: HeadScanner::default(), head: Vec::new(), carry: Vec::new() }
    }

    /// Capacity of the withheld-head buffer (for reuse tests).
    #[cfg(test)]
    pub(crate) fn head_capacity_for_tests(&self) -> usize {
        self.head.capacity().max(self.carry.capacity())
    }

    /// `true` between messages with no partial request buffered.
    pub fn is_idle(&self) -> bool {
        matches!(self.state, GuardState::Head) && self.head.is_empty()
    }

    /// `true` while a request head is partially received (and withheld).
    pub fn has_partial_head(&self) -> bool {
        matches!(self.state, GuardState::Head) && !self.head.is_empty()
    }

    /// `true` once the connection has been upgraded and is no longer inspected.
    pub fn is_passthrough(&self) -> bool {
        matches!(self.state, GuardState::Passthrough)
    }

    /// Inspect bytes received from the client.
    pub fn feed<'a>(&'a mut self, data: &[u8]) -> Result<Release<'a>, GuardError> {
        // Whatever the previous call lent out is no longer borrowed.
        self.carry.clear();
        if self.carry.capacity() > BUFFER_RETAIN_MAX {
            self.carry = Vec::new();
        }
        let mut i = 0usize;
        let mut released = 0usize;
        let mut carried_head = false;
        let mut skip = 0usize;
        while i < data.len() {
            match &mut self.state {
                GuardState::Passthrough => {
                    i = data.len();
                    released = i;
                }
                GuardState::Head => {
                    let at_boundary = |violation| GuardError { violation, at_message_boundary: true };
                    match self.scanner.scan(&data[i..], self.limits.max_head_bytes).map_err(at_boundary)? {
                        None => {
                            // Incomplete head: withhold it until it can be judged.
                            self.head.extend_from_slice(&data[i..]);
                            return Ok(self.release(carried_head, skip, released, true));
                        }
                        Some(n) => {
                            let parsed = if self.head.is_empty() {
                                parse_request_head(&data[i..i + n], &self.limits)
                            } else {
                                self.head.extend_from_slice(&data[i..i + n]);
                                let r = parse_request_head(&self.head, &self.limits);
                                // Hand the completed head to `carry` and recycle the old
                                // `carry` allocation as the next withheld-head buffer.
                                std::mem::swap(&mut self.head, &mut self.carry);
                                self.head.clear();
                                if self.head.capacity() > BUFFER_RETAIN_MAX {
                                    self.head = Vec::new();
                                }
                                carried_head = true;
                                skip = n;
                                r
                            };
                            self.scanner.reset();
                            let info = parsed.map_err(at_boundary)?;
                            i += n;
                            released = i;
                            self.state = match (info.upgrade, info.framing) {
                                (true, _) => GuardState::Passthrough,
                                (false, BodyFraming::None) => GuardState::Head,
                                (false, BodyFraming::Length(n)) => GuardState::Body(n),
                                (false, BodyFraming::Chunked) => {
                                    GuardState::Chunked(ChunkedDecoder::new(self.limits.max_head_bytes))
                                }
                            };
                        }
                    }
                }
                GuardState::Body(remaining) => {
                    let take = ((data.len() - i) as u64).min(*remaining);
                    *remaining -= take;
                    let done = *remaining == 0;
                    i += usize::try_from(take).unwrap_or(data.len() - i);
                    released = i;
                    if done {
                        self.state = GuardState::Head;
                    }
                }
                GuardState::Chunked(dec) => {
                    let (n, done) = dec
                        .feed(&data[i..])
                        .map_err(|violation| GuardError { violation, at_message_boundary: false })?;
                    i += n;
                    released = i;
                    if done {
                        self.state = GuardState::Head;
                    }
                }
            }
        }
        let partial = self.has_partial_head();
        Ok(self.release(carried_head, skip, released, partial))
    }

    fn release(&self, carried_head: bool, skip: usize, len: usize, partial_head: bool) -> Release<'_> {
        Release { carried: if carried_head { &self.carry } else { &[] }, partial_head, skip, len }
    }
}
