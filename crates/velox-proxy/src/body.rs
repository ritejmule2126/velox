//! Body adaptors: byte limits, idle timeouts, keep-alive guards and the
//! channel body used to bridge HTTP/3 request streams.

use crate::error::BoxError;
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::BodyExt;
use pin_project_lite::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{Instant, Sleep};

/// The body type flowing through the proxy.
///
/// `Empty` and `Full` carry no heap allocation, so body-less requests (the
/// common `GET`) and small canned responses never touch the allocator; only
/// genuinely streaming bodies are boxed.
pub enum ProxyBody {
    /// No content.
    Empty,
    /// One in-memory chunk, yielded once.
    Full(Option<Bytes>),
    /// A streaming body behind a trait object.
    Boxed(UnsyncBoxBody<Bytes, BoxError>),
}

impl ProxyBody {
    /// Box an arbitrary body.
    pub fn boxed<B>(body: B) -> Self
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        Self::Boxed(body.map_err(Into::into).boxed_unsync())
    }

    /// A complete in-memory body (empty input becomes [`ProxyBody::Empty`]).
    pub fn full(data: Bytes) -> Self {
        if data.is_empty() {
            Self::Empty
        } else {
            Self::Full(Some(data))
        }
    }
}

impl std::fmt::Debug for ProxyBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("ProxyBody::Empty"),
            Self::Full(b) => write!(f, "ProxyBody::Full({} bytes)", b.as_ref().map_or(0, Bytes::len)),
            Self::Boxed(_) => f.write_str("ProxyBody::Boxed(..)"),
        }
    }
}

impl Body for ProxyBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        match self.get_mut() {
            Self::Empty => Poll::Ready(None),
            Self::Full(slot) => Poll::Ready(slot.take().map(|b| Ok(Frame::data(b)))),
            Self::Boxed(b) => Pin::new(b).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Empty => true,
            Self::Full(slot) => slot.is_none(),
            Self::Boxed(b) => b.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Empty => SizeHint::with_exact(0),
            Self::Full(slot) => SizeHint::with_exact(slot.as_ref().map_or(0, Bytes::len) as u64),
            Self::Boxed(b) => b.size_hint(),
        }
    }
}

/// Reasons a client request body failed, recorded out-of-band so the handler
/// can pick the right status without digging through error chains.
#[derive(Debug, Default)]
pub struct BodyFault(AtomicU8);

/// What went wrong with a request body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// More bytes than allowed.
    TooLarge,
    /// The client stopped sending.
    IdleTimeout,
    /// The client's stream failed or was reset.
    ClientRead,
}

impl BodyFault {
    /// A fresh, shareable fault slot.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn set(&self, f: Fault) {
        self.0.store(
            match f {
                Fault::TooLarge => 1,
                Fault::IdleTimeout => 2,
                Fault::ClientRead => 3,
            },
            Ordering::Release,
        );
    }

    fn set_if_unset(&self, f: Fault) {
        let code = match f {
            Fault::TooLarge => 1,
            Fault::IdleTimeout => 2,
            Fault::ClientRead => 3,
        };
        let _ = self.0.compare_exchange(0, code, Ordering::AcqRel, Ordering::Acquire);
    }

    /// The recorded fault, if any.
    pub fn get(&self) -> Option<Fault> {
        match self.0.load(Ordering::Acquire) {
            1 => Some(Fault::TooLarge),
            2 => Some(Fault::IdleTimeout),
            3 => Some(Fault::ClientRead),
            _ => None,
        }
    }
}

/// Error surfaced by [`LimitBody`] / [`IdleBody`].
#[derive(Debug, thiserror::Error)]
pub enum BodyError {
    /// Byte limit exceeded.
    #[error("body exceeds the configured limit")]
    TooLarge,
    /// No frame arrived within the idle window.
    #[error("body idle timeout")]
    IdleTimeout,
}

/// A request body disagreed with its declared `Content-Length`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LengthMismatch {
    /// More bytes arrived than declared.
    #[error("body is longer than its Content-Length")]
    TooMuch,
    /// The stream ended before the declared length.
    #[error("body ended before its Content-Length")]
    TooLittle,
}

/// Map a body error to the fault the handler should report: a stall is a
/// `408`, anything else from the client side a `400`.
fn classify(e: &BoxError) -> Fault {
    match e.downcast_ref::<BodyError>() {
        Some(BodyError::IdleTimeout) => Fault::IdleTimeout,
        _ => Fault::ClientRead,
    }
}

pin_project! {
    /// Caps the total bytes of a body.
    pub struct LimitBody<B> {
        #[pin] inner: B,
        remaining: u64,
        fault: Arc<BodyFault>,
    }
}

impl<B> LimitBody<B> {
    /// Allow at most `limit` bytes; trips `fault` when exceeded.
    pub fn new(inner: B, limit: u64, fault: Arc<BodyFault>) -> Self {
        Self { inner, remaining: limit, fault }
    }
}

impl<B> Body for LimitBody<B>
where
    B: Body<Data = Bytes>,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.project();
        match this.inner.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let len = data.len() as u64;
                    if len > *this.remaining {
                        this.fault.set(Fault::TooLarge);
                        return Poll::Ready(Some(Err(Box::new(BodyError::TooLarge))));
                    }
                    *this.remaining -= len;
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                let e: BoxError = e.into();
                this.fault.set_if_unset(classify(&e));
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

pin_project! {
    /// Fails the body if no frame arrives within `idle`, and holds a guard
    /// payload (in-flight counters, …) until the body finishes or is dropped.
    pub struct IdleBody<B, G> {
        #[pin] inner: B,
        #[pin] sleep: Sleep,
        idle: Duration,
        fault: Option<Arc<BodyFault>>,
        _guard: G,
    }
}

impl<B> IdleBody<B, ()> {
    /// Wrap `inner`; optionally record the timeout in `fault`.
    pub fn new(inner: B, idle: Duration, fault: Option<Arc<BodyFault>>) -> Self {
        Self::with_guard(inner, idle, fault, ())
    }
}

impl<B, G> IdleBody<B, G> {
    /// Like [`IdleBody::new`], also tying `guard`'s lifetime to the body.
    pub fn with_guard(inner: B, idle: Duration, fault: Option<Arc<BodyFault>>, guard: G) -> Self {
        Self { inner, sleep: tokio::time::sleep(idle), idle, fault, _guard: guard }
    }
}

impl<B, G> Body for IdleBody<B, G>
where
    B: Body<Data = Bytes>,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let mut this = self.project();
        match this.inner.poll_frame(cx) {
            Poll::Ready(item) => {
                this.sleep.as_mut().reset(Instant::now() + *this.idle);
                Poll::Ready(item.map(|r| {
                    r.map_err(|e| {
                        let e: BoxError = e.into();
                        if let Some(f) = this.fault {
                            f.set_if_unset(classify(&e));
                        }
                        e
                    })
                }))
            }
            Poll::Pending => match this.sleep.poll(cx) {
                Poll::Ready(()) => {
                    if let Some(f) = this.fault {
                        f.set(Fault::IdleTimeout);
                    }
                    Poll::Ready(Some(Err(Box::new(BodyError::IdleTimeout))))
                }
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

pin_project! {
    /// Holds `guard` (in-flight counters, connection activity…) until the body
    /// finishes or is dropped.
    pub struct KeepAlive<B, G> {
        #[pin] inner: B,
        _guard: G,
    }
}

impl<B, G> KeepAlive<B, G> {
    /// Tie `guard`'s lifetime to the body.
    pub fn new(inner: B, guard: G) -> Self {
        Self { inner, _guard: guard }
    }
}

impl<B: Body, G> Body for KeepAlive<B, G> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<B::Data>, B::Error>>> {
        self.project().inner.poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// A body fed through a bounded channel (used for HTTP/3 request streams).
#[derive(Debug)]
pub struct ChannelBody {
    rx: mpsc::Receiver<Result<Frame<Bytes>, BoxError>>,
    hint: SizeHint,
}

impl ChannelBody {
    /// Create a body and its sender. `content_length` seeds the size hint.
    pub fn new(content_length: Option<u64>) -> (mpsc::Sender<Result<Frame<Bytes>, BoxError>>, Self) {
        let (tx, rx) = mpsc::channel(4);
        let hint = content_length.map_or_else(SizeHint::new, SizeHint::with_exact);
        (tx, Self { rx, hint })
    }
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        self.rx.poll_recv(cx)
    }

    fn size_hint(&self) -> SizeHint {
        self.hint
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full, StreamBody};

    #[tokio::test]
    async fn limit_body_trips_and_records_fault() {
        let fault = BodyFault::new();
        let ok = LimitBody::new(Full::new(Bytes::from_static(b"hello")).map_err(|e| match e {}), 5, Arc::clone(&fault));
        assert_eq!(ok.collect().await.unwrap().to_bytes(), "hello");
        assert_eq!(fault.get(), None);

        let big =
            LimitBody::new(Full::new(Bytes::from_static(b"hello!")).map_err(|e| match e {}), 5, Arc::clone(&fault));
        assert!(big.collect().await.is_err());
        assert_eq!(fault.get(), Some(Fault::TooLarge));
    }

    #[tokio::test(start_paused = true)]
    async fn idle_body_times_out_between_frames() {
        let (tx, body) = ChannelBody::new(None);
        let fault = BodyFault::new();
        let mut body = Box::pin(IdleBody::new(body, Duration::from_secs(5), Some(Arc::clone(&fault))));
        tx.send(Ok(Frame::data(Bytes::from_static(b"a")))).await.unwrap();
        assert!(body.frame().await.unwrap().is_ok());
        let res = body.frame().await.unwrap();
        assert!(res.is_err(), "no frame within 5s must fail");
        assert_eq!(fault.get(), Some(Fault::IdleTimeout));
        drop(tx);
    }

    #[tokio::test]
    async fn channel_body_streams_and_ends() {
        let (tx, body) = ChannelBody::new(Some(3));
        assert_eq!(body.size_hint().exact(), Some(3));
        tokio::spawn(async move {
            tx.send(Ok(Frame::data(Bytes::from_static(b"ab")))).await.unwrap();
            tx.send(Ok(Frame::data(Bytes::from_static(b"c")))).await.unwrap();
        });
        assert_eq!(body.collect().await.unwrap().to_bytes(), "abc");
    }

    #[tokio::test]
    async fn proxy_body_variants_behave_like_bodies() {
        let e = ProxyBody::Empty;
        assert!(e.is_end_stream() && e.size_hint().exact() == Some(0));
        assert!(e.collect().await.unwrap().to_bytes().is_empty());
        let f = ProxyBody::full(Bytes::from_static(b"abc"));
        assert_eq!(f.size_hint().exact(), Some(3));
        assert!(!f.is_end_stream());
        assert_eq!(f.collect().await.unwrap().to_bytes(), "abc");
        assert!(matches!(ProxyBody::full(Bytes::new()), ProxyBody::Empty), "no allocation for empty");
        let b = ProxyBody::boxed(Full::new(Bytes::from_static(b"xyz")).map_err(|e| match e {}));
        assert_eq!(b.size_hint().exact(), Some(3));
        assert_eq!(b.collect().await.unwrap().to_bytes(), "xyz");
    }

    #[tokio::test(start_paused = true)]
    async fn idle_body_holds_its_guard_until_it_is_dropped() {
        let flag = Arc::new(());
        let body = IdleBody::with_guard(
            ProxyBody::full(Bytes::from_static(b"x")),
            Duration::from_secs(5),
            None,
            Arc::clone(&flag),
        );
        assert_eq!(Arc::strong_count(&flag), 2);
        assert_eq!(body.collect().await.unwrap().to_bytes(), "x");
        assert_eq!(Arc::strong_count(&flag), 1, "guard released once the body is gone");
    }

    #[tokio::test]
    async fn keepalive_holds_guard_until_drop() {
        let flag = Arc::new(());
        let inner = StreamBody::new(futures_util::stream::empty::<Result<Frame<Bytes>, BoxError>>());
        let body = KeepAlive::new(inner, Arc::clone(&flag));
        assert_eq!(Arc::strong_count(&flag), 2);
        drop(body);
        assert_eq!(Arc::strong_count(&flag), 1);
    }
}
