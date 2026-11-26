//! Streaming response compression (`zstd`, `br`, `gzip`).
//!
//! Opt-in (`[compression] enabled = true`, or `compress = true` on a route).
//! The pieces:
//!
//! * [`negotiate`] — RFC 9110 `Accept-Encoding` negotiation with `q` values,
//!   `*`, and server preference as the tie-break.
//! * [`plan`] — decides whether a response is compressible and, if so,
//!   rewrites its headers: `Content-Encoding`, `Vary: Accept-Encoding`, no
//!   `Content-Length`, strong `ETag` → weak, no `Accept-Ranges`.
//! * [`CompressBody`] — a streaming body adapter. It compresses frame by frame
//!   in bounded slices (never buffering the whole response) and **flushes
//!   whenever the upstream pauses**, so a slowly produced stream (NDJSON logs,
//!   long polling) is delivered promptly instead of waiting for the encoder's
//!   internal buffer to fill.
//!
//! Never compressed: bodies that are already encoded, smaller than `min_size`,
//! of a type not listed in `content_types`, `text/event-stream` (SSE),
//! `application/grpc*`, `Cache-Control: no-transform`, partial (`206` /
//! `Content-Range`) and bodyless (`1xx`, `204`, `304`, `HEAD`) responses.

use crate::body::ProxyBody;
use crate::error::BoxError;
use bytes::Bytes;
use http::header::{
    HeaderValue, ACCEPT_RANGES, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG,
    VARY,
};
use http::{HeaderMap, StatusCode};
use http_body::{Body, Frame, SizeHint};
use pin_project_lite::pin_project;
use std::future::Future;
use std::io::{self, Write};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock, PoisonError};
use std::task::{Context, Poll};
use tokio::sync::oneshot;
use velox_core::config::{CompressionAlgorithm, CompressionConfig, CompressionLevel};
use velox_telemetry::Metrics;

/// Uncompressed bytes fed to the encoder per step (bounds the CPU of one step).
/// Raised to `offload_threshold` when that is larger.
const INPUT_SLICE: usize = 64 * 1024;
/// Emit a frame once this much compressed output is buffered.
const EMIT_THRESHOLD: usize = 16 * 1024;
/// Force the encoder to emit what it holds after this much input, whatever the
/// upstream is doing. Encoders (brotli especially) otherwise keep a whole block
/// internally, which for a large response would mean buffering most of it.
const FLUSH_EVERY: usize = 256 * 1024;
/// Most `Accept-Encoding` list members we look at.
const MAX_ACCEPT_ENTRIES: usize = 64;

// ---------------------------------------------------------------- negotiation

/// Parse a `qvalue` (`0`, `0.5`, `1`, `1.000`) into thousandths.
fn parse_q(s: &str) -> Option<u16> {
    let s = s.trim();
    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    if frac.len() > 3 || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let frac_val: u16 = if frac.is_empty() { 0 } else { frac.parse::<u16>().ok()? * 10u16.pow(3 - frac.len() as u32) };
    match whole {
        "0" => Some(frac_val),
        "1" if frac_val == 0 => Some(1000),
        _ => None,
    }
}

/// Pick the response encoding for an `Accept-Encoding` header.
///
/// `offered` is the server's preference order. The client's highest `q` wins;
/// equal `q` falls back to the server's order. `q=0` forbids an encoding, `*`
/// covers any encoding not named, and an absent header means "identity only".
pub fn negotiate(accept: Option<&HeaderValue>, offered: &[CompressionAlgorithm]) -> Option<CompressionAlgorithm> {
    let accept = accept?.to_str().ok()?;
    let mut explicit: [Option<u16>; 3] = [None; 3];
    let mut wildcard: Option<u16> = None;
    for item in accept.split(',').take(MAX_ACCEPT_ENTRIES) {
        let mut parts = item.split(';');
        let token = parts.next().unwrap_or("").trim();
        let mut q = Some(1000u16);
        for param in parts {
            if let Some((k, v)) = param.split_once('=') {
                if k.trim().eq_ignore_ascii_case("q") {
                    q = parse_q(v);
                }
            }
        }
        let Some(q) = q else { continue }; // malformed weight: ignore the entry
        let slot = if token.eq_ignore_ascii_case("zstd") {
            &mut explicit[0]
        } else if token.eq_ignore_ascii_case("br") {
            &mut explicit[1]
        } else if token.eq_ignore_ascii_case("gzip") || token.eq_ignore_ascii_case("x-gzip") {
            &mut explicit[2]
        } else if token == "*" {
            &mut wildcard
        } else {
            continue;
        };
        *slot = Some(slot.map_or(q, |old| old.max(q)));
    }
    let mut best: Option<(CompressionAlgorithm, u16)> = None;
    for &algo in offered {
        let idx = match algo {
            CompressionAlgorithm::Zstd => 0,
            CompressionAlgorithm::Brotli => 1,
            CompressionAlgorithm::Gzip => 2,
        };
        let q = explicit[idx].or(wildcard).unwrap_or(0);
        if q > 0 && best.is_none_or(|(_, bq)| q > bq) {
            best = Some((algo, q));
        }
    }
    best.map(|(a, _)| a)
}

// ---------------------------------------------------------------- eligibility

fn content_type_matches(patterns: &[String], content_type: &str) -> bool {
    let essence = content_type.split(';').next().unwrap_or("").trim();
    let Some((ty, sub)) = essence.split_once('/') else { return false };
    // Streaming protocols that must reach the client frame by frame, unbuffered.
    let is_grpc = ty.eq_ignore_ascii_case("application")
        && sub.as_bytes().get(..4).is_some_and(|p| p.eq_ignore_ascii_case(b"grpc"));
    if essence.eq_ignore_ascii_case("text/event-stream") || is_grpc {
        return false;
    }
    patterns.iter().any(|p| {
        let Some((pt, ps)) = p.split_once('/') else { return false };
        if !pt.eq_ignore_ascii_case(ty) {
            return false;
        }
        match ps.split_once('*') {
            None => ps.eq_ignore_ascii_case(sub),
            Some((prefix, suffix)) => {
                sub.len() >= prefix.len() + suffix.len()
                    && sub.is_char_boundary(prefix.len())
                    && sub[..prefix.len()].eq_ignore_ascii_case(prefix)
                    && sub.is_char_boundary(sub.len() - suffix.len())
                    && sub[sub.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
            }
        }
    })
}

fn declared_length(h: &HeaderMap) -> Option<u64> {
    h.get(CONTENT_LENGTH)?.to_str().ok()?.trim().parse().ok()
}

fn has_token(h: &HeaderMap, name: http::header::HeaderName, token: &str) -> bool {
    h.get_all(name).iter().filter_map(|v| v.to_str().ok()).any(|v| {
        v.split(',').any(|t| {
            let t = t.split('=').next().unwrap_or("").trim();
            t.eq_ignore_ascii_case(token)
        })
    })
}

fn add_vary(h: &mut HeaderMap) {
    let covered = h
        .get_all(VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.split(',').any(|t| matches!(t.trim(), "*") || t.trim().eq_ignore_ascii_case("accept-encoding")));
    if !covered {
        h.append(VARY, HeaderValue::from_static("Accept-Encoding"));
    }
}

/// Decide whether to compress a response and rewrite its headers accordingly.
///
/// Returns the encoding to apply to the body, or `None` to leave it alone.
/// `Vary: Accept-Encoding` is added to every response that *could* have been
/// compressed (right type, size and status) — even when this client did not
/// accept any encoding — so shared caches never serve the wrong variant.
///
/// `admit` is asked, after the response has proven compressible and an encoding
/// was negotiated but **before** any header is rewritten, whether resources are
/// available to compress it (an [`EncoderPermit`], typically). Returning `None`
/// leaves the response a plain pass-through: the headers never claim an
/// encoding that will not happen.
pub fn plan<P>(
    cfg: &CompressionConfig,
    accept: Option<&HeaderValue>,
    is_head: bool,
    status: StatusCode,
    headers: &mut HeaderMap,
    admit: impl FnOnce(CompressionAlgorithm) -> Option<P>,
) -> Option<(CompressionAlgorithm, P)> {
    // No body, or not the whole representation: nothing to encode, no variant.
    if status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
        || status == StatusCode::PARTIAL_CONTENT
        || headers.contains_key(CONTENT_RANGE)
    {
        return None;
    }
    // Already encoded (possibly by the backend): pass through untouched.
    if headers.get_all(CONTENT_ENCODING).iter().any(|v| !v.as_bytes().trim_ascii().eq_ignore_ascii_case(b"identity")) {
        return None;
    }
    let compressible_type = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| content_type_matches(&cfg.content_types, ct));
    if !compressible_type || has_token(headers, CACHE_CONTROL, "no-transform") {
        return None;
    }
    if declared_length(headers).is_some_and(|n| n < cfg.min_size) {
        return None;
    }
    // This representation varies with the request from here on.
    add_vary(headers);
    if is_head {
        return None; // headers describe a GET we do not execute; leave them honest
    }
    let algo = negotiate(accept, &cfg.algorithms)?;
    let admitted = admit(algo)?;

    headers.remove(CONTENT_LENGTH);
    headers.remove(ACCEPT_RANGES);
    headers.insert(CONTENT_ENCODING, HeaderValue::from_static(algo.token()));
    // A different byte sequence needs a different validator: strong → weak.
    if let Some(etag) = headers.get(ETAG) {
        let b = etag.as_bytes();
        if !b.starts_with(b"W/") {
            let mut weak = Vec::with_capacity(b.len() + 2);
            weak.extend_from_slice(b"W/");
            weak.extend_from_slice(b);
            if let Ok(v) = HeaderValue::from_bytes(&weak) {
                headers.insert(ETAG, v);
            }
        }
    }
    Some((algo, admitted))
}

// ------------------------------------------------------------------- encoders

enum Encoder {
    Gzip(flate2::write::GzEncoder<Vec<u8>>),
    Brotli(Box<brotli::CompressorWriter<Vec<u8>>>),
    Zstd(Box<zstd::stream::write::Encoder<'static, Vec<u8>>>),
}

impl Encoder {
    fn new(algo: CompressionAlgorithm, level: CompressionLevel) -> io::Result<Self> {
        let out = Vec::with_capacity(EMIT_THRESHOLD + 1024);
        Ok(match algo {
            CompressionAlgorithm::Gzip => {
                let l = match level {
                    CompressionLevel::Fast => 1,
                    CompressionLevel::Default => 6,
                    CompressionLevel::Best => 9,
                };
                Self::Gzip(flate2::write::GzEncoder::new(out, flate2::Compression::new(l)))
            }
            CompressionAlgorithm::Brotli => {
                let q = match level {
                    CompressionLevel::Fast => 3,
                    CompressionLevel::Default => 5,
                    CompressionLevel::Best => 8,
                };
                Self::Brotli(Box::new(brotli::CompressorWriter::new(out, 4096, q, 20)))
            }
            CompressionAlgorithm::Zstd => {
                let l = match level {
                    CompressionLevel::Fast => 1,
                    CompressionLevel::Default => 3,
                    CompressionLevel::Best => 9,
                };
                Self::Zstd(Box::new(zstd::stream::write::Encoder::new(out, l)?))
            }
        })
    }

    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            Self::Gzip(e) => e.write_all(data),
            Self::Brotli(e) => e.write_all(data),
            Self::Zstd(e) => e.write_all(data),
        }
    }

    /// Force everything written so far into the output buffer.
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Gzip(e) => e.flush(),
            Self::Brotli(e) => e.flush(),
            Self::Zstd(e) => e.flush(),
        }
    }

    fn sink(&mut self) -> &mut Vec<u8> {
        match self {
            Self::Gzip(e) => e.get_mut(),
            Self::Brotli(e) => e.get_mut(),
            Self::Zstd(e) => e.get_mut(),
        }
    }

    fn buffered(&mut self) -> usize {
        self.sink().len()
    }

    fn take_output(&mut self) -> Bytes {
        let sink = self.sink();
        let out = std::mem::replace(sink, Vec::with_capacity(EMIT_THRESHOLD + 1024));
        Bytes::from(out)
    }

    /// Finish the stream; returns the remaining output.
    fn finish(self) -> io::Result<Bytes> {
        Ok(Bytes::from(match self {
            Self::Gzip(e) => e.finish()?,
            // `into_inner` writes the stream terminator and returns the sink
            // (including everything not yet taken).
            Self::Brotli(e) => (*e).into_inner(),
            Self::Zstd(e) => e.finish()?,
        }))
    }
}

// --------------------------------------------------------- runtime and limits

/// What a worker hands back after compressing one slice.
struct JobDone {
    encoder: Encoder,
    result: io::Result<()>,
    flushed: bool,
}

type Job = Box<dyn FnOnce() + Send + 'static>;

/// A small, fixed set of OS threads dedicated to compression.
///
/// Compression of a large slice is milliseconds of pure CPU; running it on a
/// Tokio worker would stall every other connection scheduled there. Jobs run
/// here instead, and the response's task simply waits for its result.
///
/// The pool is deliberately separate from Tokio's blocking pool, which also
/// serves DNS lookups and file I/O and must not be starved by compression. Its
/// queue is bounded in practice by the encoder cap: one response has at most
/// one job outstanding, and a response only exists while it holds a permit.
struct EncoderPool {
    threads: usize,
    tx: OnceLock<Option<mpsc::Sender<Job>>>,
}

impl EncoderPool {
    fn new(threads: usize) -> Self {
        let auto = std::thread::available_parallelism().map_or(2, std::num::NonZeroUsize::get).clamp(2, 16);
        Self { threads: if threads == 0 { auto } else { threads }, tx: OnceLock::new() }
    }

    /// Queue `job`; if no worker thread could be started the job is handed back
    /// so the caller can run it inline (degraded, but correct).
    fn submit(&self, job: Job) -> Result<(), Job> {
        match self.tx.get_or_init(|| self.start()) {
            Some(tx) => tx.send(job).map_err(|e| e.0),
            None => Err(job),
        }
    }

    fn start(&self) -> Option<mpsc::Sender<Job>> {
        let (tx, rx) = mpsc::channel::<Job>();
        let rx = Arc::new(Mutex::new(rx));
        let mut started = 0;
        for i in 0..self.threads {
            let rx = Arc::clone(&rx);
            let spawned = std::thread::Builder::new().name(format!("velox-compress-{i}")).spawn(move || loop {
                // Only the thread waiting for work holds the lock; it is released
                // before the job runs.
                let job = rx.lock().unwrap_or_else(PoisonError::into_inner).recv();
                match job {
                    Ok(job) => job(),
                    Err(_) => return, // the pool was dropped
                }
            });
            if spawned.is_ok() {
                started += 1;
            }
        }
        (started > 0).then_some(tx)
    }
}

/// Process-wide compression state: the encoder cap and the worker pool.
pub struct Compressor {
    active: AtomicUsize,
    pool: EncoderPool,
    metrics: Arc<Metrics>,
}

impl std::fmt::Debug for Compressor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Compressor").field("active", &self.active.load(Ordering::Relaxed)).finish_non_exhaustive()
    }
}

/// Proof that one encoder may exist; releases its slot on drop.
#[derive(Debug)]
pub struct EncoderPermit(Arc<Compressor>);

impl Drop for EncoderPermit {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
        self.0.metrics.compression_encoders(-1);
    }
}

impl Compressor {
    /// Create the runtime; worker threads start lazily on the first large slice.
    /// `worker_threads = 0` picks the CPU count (2..=16).
    pub fn new(metrics: Arc<Metrics>, worker_threads: usize) -> Arc<Self> {
        Arc::new(Self { active: AtomicUsize::new(0), pool: EncoderPool::new(worker_threads), metrics })
    }

    /// Claim an encoder slot if fewer than `cap` are live. Atomic: concurrent
    /// callers can never take the cap over its limit. Counts a skip when full.
    pub fn try_acquire(self: &Arc<Self>, cap: usize) -> Option<EncoderPermit> {
        let mut cur = self.active.load(Ordering::Relaxed);
        loop {
            if cur >= cap {
                self.metrics.compression_skipped("saturated");
                return None;
            }
            match self.active.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => break,
                Err(seen) => cur = seen,
            }
        }
        self.metrics.compression_encoders(1);
        Some(EncoderPermit(Arc::clone(self)))
    }

    /// Live encoders.
    pub fn active(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    /// Wrap `body` in a compressor for an encoding [`plan`] admitted.
    ///
    /// If the encoder cannot be created (never expected: it only allocates), the
    /// client gets a body error rather than an uncompressed payload under a
    /// `Content-Encoding` header that says otherwise.
    pub fn wrap(
        self: &Arc<Self>,
        body: ProxyBody,
        algo: CompressionAlgorithm,
        permit: EncoderPermit,
        cfg: &CompressionConfig,
    ) -> ProxyBody {
        match CompressBody::new(body, algo, cfg, Arc::clone(self), permit) {
            Ok(b) => ProxyBody::boxed(b),
            Err(e) => ProxyBody::boxed(FailedBody(Some(e))),
        }
    }
}

// ----------------------------------------------------------------- the body

/// Reports bytes through the compressor when the response ends (or is dropped
/// mid-stream by a disconnecting client).
struct Stats {
    metrics: Arc<Metrics>,
    encoding: &'static str,
    bytes_in: u64,
    bytes_out: u64,
}

impl Drop for Stats {
    fn drop(&mut self) {
        self.metrics.compressed(self.encoding, self.bytes_in, self.bytes_out);
    }
}

pin_project! {
    /// Compresses `B` on the fly. See the [module docs](self).
    pub struct CompressBody<B> {
        #[pin] inner: B,
        // `None` while a slice is being compressed on a worker thread, and
        // once the stream is finished.
        encoder: Option<Encoder>,
        // The worker's answer for the slice in flight.
        job: Option<oneshot::Receiver<JobDone>>,
        // Uncompressed data of the current inner frame not yet fed to the encoder.
        input: Bytes,
        inner_done: bool,
        // The compressed stream is over (finished or failed): only trailers remain.
        done: bool,
        // Data written to the encoder since the last flush.
        dirty: bool,
        // Input fed since the last flush.
        since_flush: usize,
        trailers: Option<HeaderMap>,
        slice: usize,
        offload_min: usize,
        runtime: Arc<Compressor>,
        // Held for the life of the stream; released the moment it ends.
        permit: Option<EncoderPermit>,
        stats: Stats,
    }
}

impl<B> CompressBody<B>
where
    B: Body<Data = Bytes>,
{
    /// Wrap `inner`, compressing with `algo` per `cfg`.
    pub fn new(
        inner: B,
        algo: CompressionAlgorithm,
        cfg: &CompressionConfig,
        runtime: Arc<Compressor>,
        permit: EncoderPermit,
    ) -> io::Result<Self> {
        let metrics = Arc::clone(&runtime.metrics);
        Ok(Self {
            inner,
            encoder: Some(Encoder::new(algo, cfg.level)?),
            job: None,
            input: Bytes::new(),
            inner_done: false,
            done: false,
            dirty: false,
            since_flush: 0,
            trailers: None,
            slice: INPUT_SLICE.max(cfg.offload_threshold),
            offload_min: cfg.offload_threshold,
            runtime,
            permit: Some(permit),
            stats: Stats { metrics, encoding: algo.token(), bytes_in: 0, bytes_out: 0 },
        })
    }
}

impl<B> Body for CompressBody<B>
where
    B: Body<Data = Bytes>,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    #[allow(clippy::too_many_lines)]
    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let mut this = self.project();
        // End the compressed stream with `err` (or cleanly) and free the encoder slot.
        macro_rules! fail {
            ($err:expr) => {{
                *this.done = true;
                *this.encoder = None;
                *this.job = None;
                *this.permit = None;
                return Poll::Ready(Some(Err($err)));
            }};
        }
        loop {
            // 0. A slice compressing on a worker thread: wait for it (no busy loop;
            //    the task is woken when the worker is done).
            if let Some(rx) = this.job.as_mut() {
                match Pin::new(rx).poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(done)) => {
                        *this.job = None;
                        *this.encoder = Some(done.encoder);
                        if let Err(e) = done.result {
                            fail!(Box::new(e));
                        }
                        if done.flushed {
                            *this.since_flush = 0;
                            *this.dirty = false;
                        }
                    }
                    Poll::Ready(Err(_)) => fail!("compression worker failed".into()),
                }
            }

            // Past the end of the compressed stream: only trailers remain.
            if *this.done {
                return Poll::Ready(this.trailers.take().map(|t| Ok(Frame::trailers(t))));
            }
            let Some(encoder) = this.encoder.as_mut() else {
                *this.done = true;
                continue;
            };

            // Emit what is already buffered once it is worth a frame.
            if encoder.buffered() >= EMIT_THRESHOLD {
                let out = encoder.take_output();
                this.stats.bytes_out += out.len() as u64;
                return Poll::Ready(Some(Ok(Frame::data(out))));
            }

            // 1. Feed buffered input in bounded slices.
            if !this.input.is_empty() {
                let n = this.input.len().min(*this.slice);
                let slice = this.input.split_to(n);
                this.stats.bytes_in += n as u64;
                *this.dirty = true;
                *this.since_flush += n;
                let flush = *this.since_flush >= FLUSH_EVERY;
                if n >= *this.offload_min {
                    // Big slice: compress it off the event loop. Only this
                    // response waits; every other connection keeps running.
                    let Some(mut enc) = this.encoder.take() else { continue };
                    let (tx, rx) = oneshot::channel();
                    let job: Job = Box::new(move || {
                        let mut result = enc.write(&slice);
                        if flush && result.is_ok() {
                            result = enc.flush();
                        }
                        let _ = tx.send(JobDone { encoder: enc, result, flushed: flush });
                    });
                    this.runtime.metrics.compression_offloaded();
                    if let Err(job) = this.runtime.pool.submit(job) {
                        job(); // no worker threads at all: degrade to inline
                    }
                    *this.job = Some(rx);
                    continue;
                }
                // Small slice: cheaper to do here than to hop threads.
                let mut result = encoder.write(&slice);
                if flush && result.is_ok() {
                    result = encoder.flush();
                }
                if let Err(e) = result {
                    fail!(Box::new(e));
                }
                if flush {
                    *this.since_flush = 0;
                    *this.dirty = false;
                }
                continue;
            }

            // 2. The upstream is exhausted: terminate the stream.
            if *this.inner_done {
                let Some(encoder) = this.encoder.take() else { continue };
                *this.done = true;
                *this.permit = None;
                return match encoder.finish() {
                    Ok(tail) => {
                        this.stats.bytes_out += tail.len() as u64;
                        if tail.is_empty() {
                            continue;
                        }
                        Poll::Ready(Some(Ok(Frame::data(tail))))
                    }
                    Err(e) => Poll::Ready(Some(Err(Box::new(e)))),
                };
            }

            // 3. Pull the next upstream frame.
            match this.inner.as_mut().poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => *this.input = data,
                    Err(frame) => {
                        if let Ok(t) = frame.into_trailers() {
                            *this.trailers = Some(t);
                        }
                    }
                },
                Poll::Ready(Some(Err(e))) => {
                    *this.inner_done = true;
                    fail!(e.into());
                }
                Poll::Ready(None) => *this.inner_done = true,
                Poll::Pending => {
                    // The upstream has nothing more right now. Push out what we
                    // have so a slow stream is not held back by encoder buffering.
                    if *this.dirty {
                        if let Err(e) = encoder.flush() {
                            fail!(Box::new(e));
                        }
                        *this.dirty = false;
                        *this.since_flush = 0;
                    }
                    if encoder.buffered() == 0 {
                        return Poll::Pending;
                    }
                    let out = encoder.take_output();
                    this.stats.bytes_out += out.len() as u64;
                    return Poll::Ready(Some(Ok(Frame::data(out))));
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done && self.trailers.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default() // the compressed length is unknowable up front
    }
}

/// A body whose first poll yields an error (encoder initialisation failed).
struct FailedBody(Option<io::Error>);

impl Body for FailedBody {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        Poll::Ready(self.0.take().map(|e| Err(Box::new(e) as BoxError)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::ChannelBody;
    use http_body_util::BodyExt;
    use std::io::Read;
    use std::time::Duration;

    const ALL: [CompressionAlgorithm; 3] =
        [CompressionAlgorithm::Zstd, CompressionAlgorithm::Brotli, CompressionAlgorithm::Gzip];

    fn hv(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).unwrap()
    }

    fn pick(accept: &str, offered: &[CompressionAlgorithm]) -> Option<&'static str> {
        negotiate(Some(&hv(accept)), offered).map(CompressionAlgorithm::token)
    }

    #[test]
    fn negotiation_follows_rfc_9110() {
        // The client's best q wins; server order breaks ties.
        assert_eq!(pick("gzip, br, zstd", &ALL), Some("zstd"));
        assert_eq!(pick("gzip, br", &ALL), Some("br"));
        assert_eq!(pick("gzip;q=1.0, br;q=0.5", &ALL), Some("gzip"));
        assert_eq!(pick("br;q=0.4, gzip;q=0.8, zstd;q=0.1", &ALL), Some("gzip"));
        assert_eq!(pick("gzip", &ALL), Some("gzip"));
        assert_eq!(pick("GZip", &ALL), Some("gzip"), "tokens are case-insensitive");
        assert_eq!(pick("x-gzip", &ALL), Some("gzip"));
        // q=0 forbids; `*` covers the unnamed ones.
        assert_eq!(pick("zstd;q=0, br;q=0, gzip", &ALL), Some("gzip"));
        assert_eq!(pick("zstd;q=0, br;q=0, gzip;q=0", &ALL), None);
        assert_eq!(pick("*", &ALL), Some("zstd"));
        assert_eq!(pick("*;q=0.1, gzip", &ALL), Some("gzip"));
        assert_eq!(pick("gzip;q=0, *", &ALL), Some("zstd"));
        assert_eq!(pick("*;q=0", &ALL), None);
        // Only what the server offers can win.
        assert_eq!(pick("zstd, br, gzip", &[CompressionAlgorithm::Gzip]), Some("gzip"));
        assert_eq!(pick("zstd, br", &[CompressionAlgorithm::Gzip]), None);
        assert_eq!(pick("*", &[]), None);
        // Server preference: brotli first beats the client's equal-q zstd.
        assert_eq!(pick("zstd, br", &[CompressionAlgorithm::Brotli, CompressionAlgorithm::Zstd]), Some("br"));
        // No header / identity only / junk: no compression.
        assert_eq!(negotiate(None, &ALL), None);
        for none in ["identity", "", "compress, deflate", "gzip;q=banana", "gzip;q=2", "gzip;q=1.2345", ";;;", ","] {
            assert_eq!(pick(none, &ALL), None, "{none:?}");
        }
        // Whitespace and odd parameters are tolerated.
        assert_eq!(pick("  gzip ; q = 0.5 ,  br ; level=3 ; q=0.7", &ALL), Some("br"));
        assert_eq!(pick("gzip;q=0.001, br;q=0.000", &ALL), Some("gzip"));
        // Absurdly long lists are bounded, not quadratic.
        let long = format!("{}gzip", "x,".repeat(10_000));
        assert_eq!(pick(&long, &ALL), None, "entries past the cap are ignored");
    }

    fn cfg() -> CompressionConfig {
        CompressionConfig { enabled: true, min_size: 100, ..Default::default() }
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, hv(v));
        }
        h
    }

    fn run(accept: &str, status: u16, pairs: &[(&'static str, &str)]) -> (Option<&'static str>, HeaderMap) {
        let mut h = headers(pairs);
        let r = plan(&cfg(), Some(&hv(accept)), false, StatusCode::from_u16(status).unwrap(), &mut h, |_| Some(()))
            .map(|(a, ())| a.token());
        (r, h)
    }

    #[test]
    fn eligible_responses_are_rewritten_correctly() {
        let (enc, h) = run(
            "gzip, br",
            200,
            &[
                ("content-type", "application/json; charset=utf-8"),
                ("content-length", "5000"),
                ("etag", "\"abc\""),
                ("accept-ranges", "bytes"),
            ],
        );
        assert_eq!(enc, Some("br"));
        assert_eq!(h[CONTENT_ENCODING], "br");
        assert!(!h.contains_key(CONTENT_LENGTH), "the length changes: Content-Length must go");
        assert!(!h.contains_key(ACCEPT_RANGES));
        assert_eq!(h[ETAG], "W/\"abc\"", "strong validators become weak");
        assert_eq!(h[VARY], "Accept-Encoding");
        // A weak ETag stays as it is; an unknown length is fine (streaming).
        let (enc, h) = run("gzip", 200, &[("content-type", "text/html"), ("etag", "W/\"x\"")]);
        assert_eq!((enc, h[ETAG].to_str().unwrap()), (Some("gzip"), "W/\"x\""));
        // Error pages are compressed too.
        assert_eq!(run("gzip", 503, &[("content-type", "text/plain")]).0, Some("gzip"));
        // Type wildcards: text/*, application/*+json, application/*+xml.
        for ct in [
            "text/css",
            "TEXT/HTML",
            "application/ld+json",
            "application/vnd.api+json",
            "application/soap+xml",
            "image/svg+xml",
            "application/x-ndjson",
        ] {
            assert_eq!(run("gzip", 200, &[("content-type", ct)]).0, Some("gzip"), "{ct}");
        }
    }

    #[test]
    fn vary_is_appended_once_and_respects_existing_values() {
        let (_, h) = run("gzip", 200, &[("content-type", "text/plain"), ("vary", "Origin")]);
        let vary: Vec<_> = h.get_all(VARY).iter().map(|v| v.to_str().unwrap()).collect();
        assert_eq!(vary, ["Origin", "Accept-Encoding"]);
        let (_, h) = run("gzip", 200, &[("content-type", "text/plain"), ("vary", "origin, accept-encoding")]);
        assert_eq!(h.get_all(VARY).iter().count(), 1, "already varies on it");
        let (_, h) = run("gzip", 200, &[("content-type", "text/plain"), ("vary", "*")]);
        assert_eq!(h.get_all(VARY).iter().count(), 1, "`Vary: *` already says everything");
    }

    #[test]
    fn ineligible_responses_are_left_untouched() {
        let before = |pairs: &[(&'static str, &str)]| headers(pairs);
        for (label, status, pairs) in [
            ("already encoded", 200, vec![("content-type", "text/html"), ("content-encoding", "gzip")]),
            ("encoded by a chain", 200, vec![("content-type", "text/html"), ("content-encoding", "br")]),
            ("too small", 200, vec![("content-type", "text/html"), ("content-length", "99")]),
            ("binary type", 200, vec![("content-type", "image/png"), ("content-length", "5000")]),
            ("no content type", 200, vec![("content-length", "5000")]),
            ("SSE", 200, vec![("content-type", "text/event-stream")]),
            ("SSE with params", 200, vec![("content-type", "text/event-stream; charset=utf-8")]),
            ("gRPC", 200, vec![("content-type", "application/grpc+proto")]),
            ("no-transform", 200, vec![("content-type", "text/html"), ("cache-control", "public, No-Transform")]),
            ("206 partial", 206, vec![("content-type", "text/html")]),
            ("Content-Range", 200, vec![("content-type", "text/html"), ("content-range", "bytes 0-9/100")]),
            ("204", 204, vec![("content-type", "text/html")]),
            ("304", 304, vec![("content-type", "text/html")]),
            ("101", 101, vec![("content-type", "text/html")]),
        ] {
            let original = before(&pairs);
            let (enc, h) = run("gzip, br, zstd", status, &pairs);
            assert_eq!(enc, None, "{label}");
            assert_eq!(h, original, "{label}: headers must not change (not even Vary)");
        }
        // identity is not "already encoded".
        assert_eq!(
            run("gzip", 200, &[("content-type", "text/html"), ("content-encoding", "identity")]).0,
            Some("gzip")
        );
    }

    #[test]
    fn a_compressible_response_varies_even_when_this_client_gets_identity() {
        // No Accept-Encoding / unacceptable: the body is untouched, but caches must
        // still be told the response depends on the header.
        for accept in [None, Some("identity"), Some("br;q=0")] {
            let mut h = headers(&[("content-type", "text/html"), ("content-length", "5000"), ("etag", "\"v1\"")]);
            let accept = accept.map(hv);
            let enc = plan(&cfg(), accept.as_ref(), false, StatusCode::OK, &mut h, |_| Some(()));
            assert_eq!(enc, None);
            assert_eq!(h[VARY], "Accept-Encoding");
            assert_eq!(h[CONTENT_LENGTH], "5000");
            assert_eq!(h[ETAG], "\"v1\"", "the identity variant keeps its strong validator");
            assert!(!h.contains_key(CONTENT_ENCODING));
        }
        // HEAD: describes the identity variant honestly, still varies.
        let mut h = headers(&[("content-type", "text/html"), ("content-length", "5000")]);
        assert!(plan(&cfg(), Some(&hv("gzip")), true, StatusCode::OK, &mut h, |_| Some(())).is_none());
        assert_eq!((h[VARY].to_str().unwrap(), h[CONTENT_LENGTH].to_str().unwrap()), ("Accept-Encoding", "5000"));
    }

    #[test]
    fn custom_content_types_and_min_size_apply() {
        let mut c = cfg();
        c.content_types = vec!["image/png".into()];
        c.min_size = 10;
        let mut h = headers(&[("content-type", "image/png"), ("content-length", "10")]);
        assert!(plan(&c, Some(&hv("gzip")), false, StatusCode::OK, &mut h, |_| Some(())).is_some());
        let mut h = headers(&[("content-type", "text/html"), ("content-length", "5000")]);
        assert!(
            plan(&c, Some(&hv("gzip")), false, StatusCode::OK, &mut h, |_| Some(())).is_none(),
            "no longer in the list"
        );
        assert!(!h.contains_key(VARY));
        // Empty list ⇒ nothing is compressible.
        c.content_types.clear();
        let mut h = headers(&[("content-type", "text/html")]);
        assert!(plan(&c, Some(&hv("gzip")), false, StatusCode::OK, &mut h, |_| Some(())).is_none());
    }

    // ---- the body adapter ----

    fn decode(algo: CompressionAlgorithm, data: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        match algo {
            CompressionAlgorithm::Gzip => {
                flate2::read::GzDecoder::new(data).read_to_end(&mut out)?;
            }
            CompressionAlgorithm::Brotli => {
                brotli::Decompressor::new(data, 4096).read_to_end(&mut out)?;
            }
            CompressionAlgorithm::Zstd => {
                zstd::stream::read::Decoder::new(data)?.read_to_end(&mut out)?;
            }
        }
        Ok(out)
    }

    /// Whatever a streaming decoder can produce from an incomplete stream.
    fn decode_prefix(algo: CompressionAlgorithm, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        let mut reader: Box<dyn Read + '_> = match algo {
            CompressionAlgorithm::Gzip => Box::new(flate2::read::GzDecoder::new(data)),
            CompressionAlgorithm::Brotli => Box::new(brotli::Decompressor::new(data, 4096)),
            CompressionAlgorithm::Zstd => Box::new(zstd::stream::read::Decoder::new(data).unwrap()),
        };
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
        out
    }

    /// A `CompressBody` with its own runtime, as the proxy would build one.
    fn comp<B: Body<Data = Bytes>>(
        inner: B,
        algo: CompressionAlgorithm,
        level: CompressionLevel,
        m: Arc<Metrics>,
    ) -> io::Result<CompressBody<B>> {
        let rt = Compressor::new(m, 2);
        let permit = rt.try_acquire(1_000).expect("slot");
        let c = CompressionConfig { level, ..cfg() };
        CompressBody::new(inner, algo, &c, rt, permit)
    }

    fn metrics() -> Arc<Metrics> {
        Arc::new(Metrics::new().unwrap())
    }

    /// Text-like data that compresses well but not absurdly: random words from a
    /// 256-word vocabulary (deterministic).
    fn sample(len: usize) -> Vec<u8> {
        let vocab: Vec<String> =
            (0..256u32).map(|i| format!("w{:x}{}", i.wrapping_mul(2_654_435_761) % 9973, i % 7)).collect();
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut out = Vec::with_capacity(len + 16);
        while out.len() < len {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            out.extend_from_slice(vocab[(x % 256) as usize].as_bytes());
            out.push(if x.is_multiple_of(11) { b'\n' } else { b' ' });
        }
        out.truncate(len);
        out
    }

    async fn collect_frames(
        mut body: impl Body<Data = Bytes, Error = BoxError> + Unpin,
    ) -> (Vec<u8>, usize, Option<HeaderMap>) {
        let (mut out, mut frames, mut trailers) = (Vec::new(), 0, None);
        while let Some(f) = body.frame().await {
            let f = f.unwrap();
            match f.into_data() {
                Ok(d) => {
                    frames += 1;
                    out.extend_from_slice(&d);
                }
                Err(f) => trailers = f.into_trailers().ok(),
            }
        }
        (out, frames, trailers)
    }

    #[tokio::test]
    async fn every_encoding_round_trips_across_sizes_levels_and_frame_shapes() {
        for algo in ALL {
            for level in [CompressionLevel::Fast, CompressionLevel::Default, CompressionLevel::Best] {
                for len in [1usize, 100, 4096, 100_000, 3 * 1024 * 1024] {
                    // The big case only needs one level (it is the slow one).
                    if len > 1024 * 1024 && level != CompressionLevel::Default {
                        continue;
                    }
                    let data = sample(len);
                    // One giant frame, and the same data in awkward small pieces.
                    for pieces in [1usize, 7, 1000] {
                        if len > 1024 * 1024 && pieces == 1000 {
                            continue;
                        }
                        let chunk = data.len().div_ceil(pieces).max(1);
                        let frames: Vec<Result<Frame<Bytes>, BoxError>> =
                            data.chunks(chunk).map(|c| Ok(Frame::data(Bytes::copy_from_slice(c)))).collect();
                        let src = http_body_util::StreamBody::new(futures_util::stream::iter(frames));
                        let body = comp(src, algo, level, metrics()).unwrap();
                        let (compressed, nframes, _) = collect_frames(Box::pin(body)).await;
                        assert_eq!(
                            decode(algo, &compressed).unwrap(),
                            data,
                            "{algo:?} {level:?} len={len} pieces={pieces}"
                        );
                        if len >= 100_000 {
                            assert!(
                                compressed.len() < data.len() / 2,
                                "{algo:?} actually compresses: {} → {}",
                                data.len(),
                                compressed.len()
                            );
                        }
                        if len >= 3 * 1024 * 1024 {
                            assert!(nframes > 1, "{algo:?} {level:?} pieces={pieces}: large bodies stream out in several frames, not one blob ({} compressed bytes)", compressed.len());
                        }
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn an_empty_body_is_still_a_valid_compressed_stream() {
        for algo in ALL {
            let body = comp(http_body_util::Empty::<Bytes>::new(), algo, CompressionLevel::Default, metrics()).unwrap();
            let (compressed, _, _) = collect_frames(Box::pin(body)).await;
            assert_eq!(decode(algo, &compressed).unwrap(), b"", "{algo:?}");
        }
    }

    #[tokio::test]
    async fn a_slow_stream_is_flushed_when_the_upstream_pauses() {
        for algo in ALL {
            let (tx, chan) = ChannelBody::new(None);
            let mut body = Box::pin(comp(chan, algo, CompressionLevel::Default, metrics()).unwrap());
            tx.send(Ok(Frame::data(Bytes::from_static(b"{\"event\":1}\n")))).await.unwrap();
            // The upstream goes quiet. The client must still get event 1 promptly.
            let first = tokio::time::timeout(Duration::from_secs(2), body.frame())
                .await
                .unwrap_or_else(|_| panic!("{algo:?}: first event was held back by encoder buffering"))
                .unwrap()
                .unwrap()
                .into_data()
                .unwrap();
            assert_eq!(decode_prefix(algo, &first), b"{\"event\":1}\n", "{algo:?}");
            // And the stream continues and terminates properly.
            tx.send(Ok(Frame::data(Bytes::from_static(b"{\"event\":2}\n")))).await.unwrap();
            let second = tokio::time::timeout(Duration::from_secs(2), body.frame())
                .await
                .unwrap()
                .unwrap()
                .unwrap()
                .into_data()
                .unwrap();
            drop(tx);
            let mut all = first.to_vec();
            all.extend_from_slice(&second);
            let (rest, _, _) = collect_frames(body).await;
            all.extend_from_slice(&rest);
            assert_eq!(decode(algo, &all).unwrap(), b"{\"event\":1}\n{\"event\":2}\n", "{algo:?}");
        }
    }

    #[tokio::test]
    async fn trailers_survive_and_upstream_errors_propagate() {
        let mut trailers = HeaderMap::new();
        trailers.insert("x-checksum", hv("abc"));
        let frames: Vec<Result<Frame<Bytes>, BoxError>> =
            vec![Ok(Frame::data(Bytes::from_static(b"hello hello hello"))), Ok(Frame::trailers(trailers.clone()))];
        let body = comp(
            http_body_util::StreamBody::new(futures_util::stream::iter(frames)),
            CompressionAlgorithm::Gzip,
            CompressionLevel::Default,
            metrics(),
        )
        .unwrap();
        let (data, _, t) = collect_frames(Box::pin(body)).await;
        assert_eq!(decode(CompressionAlgorithm::Gzip, &data).unwrap(), b"hello hello hello");
        assert_eq!(t, Some(trailers), "trailers are delivered after the compressed data");

        let frames: Vec<Result<Frame<Bytes>, BoxError>> =
            vec![Ok(Frame::data(Bytes::from_static(b"partial"))), Err("backend died".into())];
        let mut body = Box::pin(
            comp(
                http_body_util::StreamBody::new(futures_util::stream::iter(frames)),
                CompressionAlgorithm::Zstd,
                CompressionLevel::Default,
                metrics(),
            )
            .unwrap(),
        );
        let mut saw_error = false;
        while let Some(f) = body.frame().await {
            if f.is_err() {
                saw_error = true;
            }
        }
        assert!(saw_error, "a truncated upstream must not look like a clean end of stream");
    }

    #[tokio::test]
    async fn compression_is_accounted_in_metrics() {
        let m = metrics();
        let data = sample(50_000);
        let body = comp(
            http_body_util::Full::new(Bytes::from(data.clone())),
            CompressionAlgorithm::Gzip,
            CompressionLevel::Default,
            Arc::clone(&m),
        )
        .unwrap();
        let (compressed, _, _) = collect_frames(Box::pin(body)).await;
        let text = m.render().unwrap();
        assert!(text.contains("velox_compression_responses_total{encoding=\"gzip\"} 1"), "{text}");
        assert!(
            text.contains(&format!(
                "velox_compression_bytes_total{{direction=\"in\",encoding=\"gzip\"}} {}",
                data.len()
            )),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "velox_compression_bytes_total{{direction=\"out\",encoding=\"gzip\"}} {}",
                compressed.len()
            )),
            "{text}"
        );
    }

    // ---- the runtime: encoder cap and off-thread compression ----

    #[test]
    fn the_encoder_cap_is_exact_under_contention_and_slots_are_released() {
        let rt = Compressor::new(metrics(), 2);
        let barrier = Arc::new(std::sync::Barrier::new(16));
        let done = Arc::new(std::sync::Barrier::new(16));
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let (rt, barrier, done) = (Arc::clone(&rt), Arc::clone(&barrier), Arc::clone(&done));
                std::thread::spawn(move || {
                    barrier.wait();
                    let mut held = Vec::new();
                    for _ in 0..500 {
                        if let Some(p) = rt.try_acquire(10) {
                            assert!(rt.active() <= 10, "cap overshoot: {}", rt.active());
                            held.push(p);
                        }
                    }
                    done.wait();
                    held.len()
                })
            })
            .collect();
        let total: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(total, 10, "exactly `cap` permits were granted while nobody released");
        assert_eq!(rt.active(), 0, "every permit was returned on drop");
        assert!(rt.try_acquire(1).is_some());
        let text = rt.metrics.render().unwrap();
        assert!(text.contains("velox_compression_skipped_total{reason=\"saturated\"}"), "{text}");
        assert!(text.contains("velox_compression_encoders_active 0"), "{text}");
    }

    #[test]
    fn a_saturated_runtime_leaves_the_response_headers_alone() {
        let rt = Compressor::new(metrics(), 2);
        let _held = rt.try_acquire(1).unwrap();
        let mut h = headers(&[("content-type", "text/html"), ("content-length", "5000"), ("etag", "\"v1\"")]);
        let r = plan(&cfg(), Some(&hv("gzip")), false, StatusCode::OK, &mut h, |_| rt.try_acquire(1));
        assert!(r.is_none(), "no slot ⇒ no compression");
        // The headers must not claim an encoding that is not going to happen…
        assert!(!h.contains_key(CONTENT_ENCODING));
        assert_eq!((h[CONTENT_LENGTH].to_str().unwrap(), h[ETAG].to_str().unwrap()), ("5000", "\"v1\""));
        // …but the response still varies on the request, for caches.
        assert_eq!(h[VARY], "Accept-Encoding");
    }

    #[tokio::test]
    async fn the_slot_is_released_when_the_stream_ends_not_when_the_body_is_dropped() {
        let rt = Compressor::new(metrics(), 2);
        let permit = rt.try_acquire(1).unwrap();
        let body = CompressBody::new(
            http_body_util::Full::new(Bytes::from(sample(10_000))),
            CompressionAlgorithm::Gzip,
            &cfg(),
            Arc::clone(&rt),
            permit,
        )
        .unwrap();
        let mut body = Box::pin(body);
        assert_eq!(rt.active(), 1);
        while let Some(f) = body.frame().await {
            f.unwrap();
        }
        assert_eq!(rt.active(), 0, "encoder state is gone once the stream ended, though the body value lives on");
        // A client that disconnects mid-stream also frees the slot (drop).
        let permit = rt.try_acquire(1).unwrap();
        let (tx, chan) = ChannelBody::new(None);
        let body = CompressBody::new(chan, CompressionAlgorithm::Zstd, &cfg(), Arc::clone(&rt), permit).unwrap();
        tx.send(Ok(Frame::data(Bytes::from_static(b"some data")))).await.unwrap();
        let mut body = Box::pin(body);
        let _ = body.frame().await;
        assert_eq!(rt.active(), 1);
        drop(body);
        assert_eq!(rt.active(), 0);
    }

    #[tokio::test]
    async fn large_bodies_are_compressed_off_the_event_loop() {
        // A single-threaded runtime makes any stall visible to every other task.
        let m = metrics();
        let rt = Compressor::new(Arc::clone(&m), 2);
        let c = CompressionConfig { level: CompressionLevel::Best, ..cfg() };
        let data = sample(8 * 1024 * 1024);
        let permit = rt.try_acquire(10).unwrap();
        let body = CompressBody::new(
            http_body_util::Full::new(Bytes::from(data.clone())),
            CompressionAlgorithm::Gzip,
            &c,
            Arc::clone(&rt),
            permit,
        )
        .unwrap();

        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ticker = {
            let finished = Arc::clone(&finished);
            tokio::spawn(async move {
                let (mut worst, mut last, mut ticks) = (Duration::ZERO, std::time::Instant::now(), 0u32);
                while !finished.load(Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    let now = std::time::Instant::now();
                    worst = worst.max(now - last);
                    last = now;
                    ticks += 1;
                }
                (worst, ticks)
            })
        };
        let t0 = std::time::Instant::now();
        let (compressed, _, _) = collect_frames(Box::pin(body)).await;
        let elapsed = t0.elapsed();
        finished.store(true, Ordering::Relaxed);
        let (worst, ticks) = ticker.await.unwrap();

        assert_eq!(decode(CompressionAlgorithm::Gzip, &compressed).unwrap(), data);
        assert!(
            ticks >= 5,
            "other tasks must keep running while the response compresses ({ticks} ticks in {elapsed:?})"
        );
        assert!(
            worst < Duration::from_millis(150),
            "the event loop stalled for {worst:?} during an {elapsed:?} compression"
        );
        assert!(m.render().unwrap().contains("velox_compression_offload_jobs_total"), "slices ran on the pool");
        assert!(!m.render().unwrap().contains("velox_compression_offload_jobs_total 0"));
    }

    #[tokio::test]
    async fn small_slices_stay_inline_and_the_pool_is_optional() {
        // Below the threshold nothing is handed to a worker.
        let m = metrics();
        let rt = Compressor::new(Arc::clone(&m), 2);
        let c = CompressionConfig { offload_threshold: 64 * 1024, ..cfg() };
        let data = sample(20_000);
        let body = CompressBody::new(
            http_body_util::Full::new(Bytes::from(data.clone())),
            CompressionAlgorithm::Brotli,
            &c,
            Arc::clone(&rt),
            rt.try_acquire(5).unwrap(),
        )
        .unwrap();
        let (out, _, _) = collect_frames(Box::pin(body)).await;
        assert_eq!(decode(CompressionAlgorithm::Brotli, &out).unwrap(), data);
        assert!(m.render().unwrap().contains("velox_compression_offload_jobs_total 0"), "{}", m.render().unwrap());

        // If no worker thread can be started, large slices degrade to inline
        // compression instead of failing the response.
        let no_threads = Arc::new(Compressor {
            active: AtomicUsize::new(0),
            pool: EncoderPool { threads: 0, tx: OnceLock::new() },
            metrics: metrics(),
        });
        let big = sample(300_000);
        let body = CompressBody::new(
            http_body_util::Full::new(Bytes::from(big.clone())),
            CompressionAlgorithm::Zstd,
            &cfg(),
            Arc::clone(&no_threads),
            no_threads.try_acquire(5).unwrap(),
        )
        .unwrap();
        let (out, _, _) = collect_frames(Box::pin(body)).await;
        assert_eq!(decode(CompressionAlgorithm::Zstd, &out).unwrap(), big);
    }

    #[tokio::test]
    async fn a_failed_worker_surfaces_as_a_body_error_and_frees_the_slot() {
        let rt = Compressor::new(metrics(), 2);
        let permit = rt.try_acquire(1).unwrap();
        let mut body = Box::pin(
            CompressBody::new(
                http_body_util::Full::new(Bytes::from(sample(200_000))),
                CompressionAlgorithm::Gzip,
                &cfg(),
                Arc::clone(&rt),
                permit,
            )
            .unwrap(),
        );
        // Simulate the worker vanishing: replace the in-flight job's receiver by one whose sender is gone.
        let _ = body.frame().await; // runs the first slice normally
        let (tx, rx) = oneshot::channel::<JobDone>();
        drop(tx);
        // Reach into the pinned body (same module) to install the dead receiver.
        body.as_mut().project().job.replace(rx);
        let mut errored = false;
        while let Some(f) = body.frame().await {
            if f.is_err() {
                errored = true;
                break;
            }
        }
        assert!(errored, "a dead worker must fail the response, not hang or truncate silently");
        assert_eq!(rt.active(), 0, "and the encoder slot is returned");
    }
}
