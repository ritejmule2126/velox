//! Body adaptors: byte limits, idle timeouts, keep-alive guards and the
//! channel body used to bridge HTTP/3 request streams.

use crate::error::BoxError;
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use pin_project_lite::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{Instant, Sleep};

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
                this.fault.set_if_unset(Fault::ClientRead);
                Poll::Ready(Some(Err(e.into())))
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
    /// Fails the body if no frame arrives within `idle`.
    pub struct IdleBody<B> {
        #[pin] inner: B,
        #[pin] sleep: Sleep,
        idle: Duration,
        fault: Option<Arc<BodyFault>>,
    }
}

impl<B> IdleBody<B> {
    /// Wrap `inner`; optionally record the timeout in `fault`.
    pub fn new(inner: B, idle: Duration, fault: Option<Arc<BodyFault>>) -> Self {
        Self { inner, sleep: tokio::time::sleep(idle), idle, fault }
    }
}

impl<B> Body for IdleBody<B>
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
                Poll::Ready(item.map(|r| r.map_err(Into::into)))
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
    async fn keepalive_holds_guard_until_drop() {
        let flag = Arc::new(());
        let inner = StreamBody::new(futures_util::stream::empty::<Result<Frame<Bytes>, BoxError>>());
        let body = KeepAlive::new(inner, Arc::clone(&flag));
        assert_eq!(Arc::strong_count(&flag), 2);
        drop(body);
        assert_eq!(Arc::strong_count(&flag), 1);
    }
}
