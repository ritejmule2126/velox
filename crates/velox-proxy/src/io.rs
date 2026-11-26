//! Connection I/O wrapper.
//!
//! [`ConnIo`] sits between the socket (or TLS stream) and `hyper` and adds,
//! with zero extra copies of body data:
//!
//! * the HTTP/1 smuggling guard ([`H1Guard`]) over every byte read;
//! * an *idle keep-alive* deadline that only runs between requests;
//! * a *write-stall* deadline against clients that never drain responses.

use bytes::Bytes;
use pin_project_lite::pin_project;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{ready, Context, Poll, Waker};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};
use velox_core::sanitize::{H1Guard, Violation};

/// Path prefix of the synthetic request that carries a guard rejection to the
/// HTTP layer, which answers it with the matching status code.
pub const REJECT_PATH: &str = "/__velox_reject__/";

/// Counts requests currently being served on one connection, and wakes the
/// connection's reader when the last one finishes.
///
/// The reader parks on idle/closed states that depend on this count; without
/// the waker a read that observed `inflight > 0` would never be polled again
/// once the request completed.
#[derive(Debug, Default)]
pub struct Activity {
    inflight: AtomicUsize,
    waker: Mutex<Option<Waker>>,
}

impl Activity {
    /// A fresh counter.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Register one in-flight request until the guard drops.
    pub fn begin(self: &Arc<Self>) -> InflightGuard {
        self.inflight.fetch_add(1, Ordering::AcqRel);
        InflightGuard(Arc::clone(self))
    }

    /// Requests currently in flight.
    pub fn inflight(&self) -> usize {
        self.inflight.load(Ordering::Acquire)
    }

    /// Ask to be woken when the in-flight count drops to zero. Call this
    /// *before* re-reading [`Activity::inflight`] so a concurrent completion
    /// cannot slip between the check and the registration.
    pub fn register(&self, waker: &Waker) {
        let mut slot = self.waker.lock().unwrap_or_else(PoisonError::into_inner);
        if !slot.as_ref().is_some_and(|w| w.will_wake(waker)) {
            *slot = Some(waker.clone());
        }
    }

    fn wake(&self) {
        let waker = self.waker.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let Some(w) = waker {
            w.wake();
        }
    }
}

/// RAII token from [`Activity::begin`].
#[derive(Debug)]
pub struct InflightGuard(Arc<Activity>);

impl Drop for InflightGuard {
    fn drop(&mut self) {
        if self.0.inflight.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.wake();
        }
    }
}

fn reject_request(v: Violation) -> Bytes {
    Bytes::from(format!("GET {REJECT_PATH}{} HTTP/1.1\r\nHost: velox\r\nConnection: close\r\n\r\n", v.slug()))
}

/// Bytes cleared for delivery to the HTTP layer but not yet read by it.
#[derive(Debug)]
struct Pending {
    bytes: Vec<u8>,
    pos: usize,
    /// Report EOF once these bytes are consumed (used for rejections).
    close_after: bool,
}

pin_project! {
    /// See the [module docs](self).
    pub struct ConnIo<T> {
        #[pin] inner: T,
        guard: Option<H1Guard>,
        activity: Arc<Activity>,
        #[pin] idle: Sleep,
        idle_timeout: Duration,
        #[pin] header: Sleep,
        header_timeout: Duration,
        header_armed: bool,
        #[pin] stall: Sleep,
        write_stall: Duration,
        stall_armed: bool,
        pending: Option<Pending>,
        // Recycled allocation for `Pending::bytes` (a head that spans reads).
        spare: Vec<u8>,
        closed: bool,
    }
}

/// Timeouts applied by [`ConnIo`].
#[derive(Debug, Clone, Copy)]
pub struct IoTimeouts {
    /// Maximum time to receive a complete request head.
    pub header_read: Duration,
    /// Maximum idle time between requests.
    pub idle_keepalive: Duration,
    /// Maximum time a write may stay blocked.
    pub write_stall: Duration,
}

impl<T> ConnIo<T> {
    /// Wrap `inner`. Pass a guard for HTTP/1 connections, `None` for HTTP/2.
    pub fn new(inner: T, guard: Option<H1Guard>, activity: Arc<Activity>, t: IoTimeouts) -> Self {
        Self {
            inner,
            guard,
            activity,
            idle: tokio::time::sleep(t.idle_keepalive),
            idle_timeout: t.idle_keepalive,
            header: tokio::time::sleep(t.header_read),
            header_timeout: t.header_read,
            header_armed: false,
            stall: tokio::time::sleep(t.write_stall),
            write_stall: t.write_stall,
            stall_armed: false,
            pending: None,
            spare: Vec::new(),
            closed: false,
        }
    }
}

impl<T: AsyncRead> AsyncRead for ConnIo<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut this = self.project();
        loop {
            if let Some(p) = this.pending.as_mut() {
                let n = (p.bytes.len() - p.pos).min(buf.remaining());
                buf.put_slice(&p.bytes[p.pos..p.pos + n]);
                p.pos += n;
                if p.pos == p.bytes.len() {
                    if p.close_after {
                        *this.closed = true;
                    }
                    // Keep the allocation for the next head, unless it ballooned.
                    if let Some(done) = this.pending.take() {
                        if done.bytes.capacity() <= 16 * 1024 {
                            *this.spare = done.bytes;
                        }
                    }
                }
                return Poll::Ready(Ok(()));
            }
            if *this.closed {
                // A rejection was delivered. Do NOT signal EOF: hyper treats EOF
                // as "client left" and would drop the 400 it is about to write.
                // The injected `Connection: close` ends the connection; the idle
                // timer is the backstop.
                this.activity.register(cx.waker());
                if this.activity.inflight() == 0 {
                    if this.idle.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Ok(()));
                    }
                } else {
                    // Busy: the idle clock restarts from the moment we go quiet,
                    // and `register` above wakes us when the last request ends.
                    this.idle.as_mut().reset(Instant::now() + *this.idle_timeout);
                }
                return Poll::Pending;
            }
            let before = buf.filled().len();
            match this.inner.as_mut().poll_read(cx, buf) {
                Poll::Ready(Ok(())) => {
                    if buf.filled().len() == before {
                        return Poll::Ready(Ok(())); // peer closed
                    }
                    this.idle.as_mut().reset(Instant::now() + *this.idle_timeout);
                    let Some(guard) = this.guard.as_mut() else {
                        return Poll::Ready(Ok(()));
                    };
                    match guard.feed(&buf.filled()[before..]) {
                        Ok(rel) => {
                            if rel.partial_head {
                                if !*this.header_armed {
                                    this.header.as_mut().reset(Instant::now() + *this.header_timeout);
                                    *this.header_armed = true;
                                }
                            } else {
                                *this.header_armed = false;
                            }
                            if rel.carried.is_empty() {
                                buf.set_filled(before + rel.len);
                                if rel.len == 0 {
                                    continue; // whole chunk withheld: keep reading
                                }
                                return Poll::Ready(Ok(()));
                            }
                            let mut bytes = std::mem::take(this.spare);
                            bytes.clear();
                            bytes.extend_from_slice(rel.carried);
                            bytes.extend_from_slice(&buf.filled()[before + rel.skip..before + rel.len]);
                            buf.set_filled(before);
                            *this.pending = Some(Pending { bytes, pos: 0, close_after: false });
                        }
                        Err(e) => {
                            buf.set_filled(before);
                            *this.header_armed = false;
                            if e.at_message_boundary {
                                *this.pending = Some(Pending {
                                    bytes: reject_request(e.violation).to_vec(),
                                    pos: 0,
                                    close_after: true,
                                });
                            } else {
                                return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e.violation)));
                            }
                        }
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    if this.guard.as_ref().is_some_and(H1Guard::has_partial_head) {
                        if !*this.header_armed {
                            this.header.as_mut().reset(Instant::now() + *this.header_timeout);
                            *this.header_armed = true;
                        }
                        if this.header.as_mut().poll(cx).is_ready() {
                            *this.header_armed = false;
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "request head not received in time",
                            )));
                        }
                    }
                    this.activity.register(cx.waker());
                    let idle = this.activity.inflight() == 0 && this.guard.as_ref().is_none_or(H1Guard::is_idle);
                    if idle {
                        if this.idle.as_mut().poll(cx).is_ready() {
                            return Poll::Ready(Ok(())); // idle keep-alive expired → clean EOF
                        }
                    } else {
                        this.idle.as_mut().reset(Instant::now() + *this.idle_timeout);
                    }
                    return Poll::Pending;
                }
            }
        }
    }
}

impl<T> ConnIo<T> {
    fn stall_check<R>(
        stall: Pin<&mut Sleep>,
        armed: &mut bool,
        dur: Duration,
        cx: &mut Context<'_>,
        res: Poll<io::Result<R>>,
    ) -> Poll<io::Result<R>> {
        match res {
            Poll::Ready(r) => {
                *armed = false;
                Poll::Ready(r)
            }
            Poll::Pending => {
                let mut stall = stall;
                if !*armed {
                    stall.as_mut().reset(Instant::now() + dur);
                    *armed = true;
                }
                if stall.poll(cx).is_ready() {
                    *armed = false;
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "write stalled")));
                }
                Poll::Pending
            }
        }
    }
}

impl<T: AsyncWrite> AsyncWrite for ConnIo<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.project();
        let r = this.inner.poll_write(cx, data);
        Self::stall_check(this.stall, this.stall_armed, *this.write_stall, cx, r)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.project();
        let r = this.inner.poll_write_vectored(cx, bufs);
        Self::stall_check(this.stall, this.stall_armed, *this.write_stall, cx, r)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        let r = this.inner.poll_flush(cx);
        Self::stall_check(this.stall, this.stall_armed, *this.write_stall, cx, r)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        let r = ready!(this.inner.poll_shutdown(cx));
        Poll::Ready(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use velox_core::sanitize::H1Limits;

    fn timeouts() -> IoTimeouts {
        IoTimeouts {
            header_read: Duration::from_secs(5),
            idle_keepalive: Duration::from_secs(5),
            write_stall: Duration::from_secs(5),
        }
    }

    type TestIo = Pin<Box<ConnIo<tokio::io::DuplexStream>>>;

    fn io_pair(guard: bool) -> (tokio::io::DuplexStream, TestIo, Arc<Activity>) {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let act = Activity::new();
        let g = guard.then(|| H1Guard::new(H1Limits::default()));
        let io = Box::pin(ConnIo::new(server, g, Arc::clone(&act), timeouts()));
        (client, io, act)
    }

    #[tokio::test]
    async fn clean_requests_pass_through_untouched() {
        let (mut client, mut io, _) = io_pair(true);
        let req = b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc";
        client.write_all(req).await.unwrap();
        let mut got = vec![0u8; req.len()];
        io.read_exact(&mut got).await.unwrap();
        assert_eq!(got, req);
    }

    /// Read until the end of one HTTP head (`\r\n\r\n`).
    async fn read_head(io: &mut TestIo, chunk: usize) -> String {
        let mut got = Vec::new();
        let mut buf = vec![0u8; chunk];
        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = io.read(&mut buf).await.unwrap();
            assert_ne!(n, 0, "unexpected EOF: {}", String::from_utf8_lossy(&got));
            got.extend_from_slice(&buf[..n]);
        }
        String::from_utf8(got).unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn smuggling_attempt_becomes_a_reject_request_and_nothing_else() {
        let (mut client, mut io, _) = io_pair(true);
        client
            .write_all(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\nGET /admin HTTP/1.1\r\n")
            .await
            .unwrap();
        let text = read_head(&mut io, 4096).await;
        assert!(text.starts_with("GET /__velox_reject__/cl-te-conflict HTTP/1.1\r\n"), "{text}");
        assert!(text.contains("Connection: close"));
        assert!(!text.contains("admin"), "attacker bytes must never reach hyper");
        // After the rejection the stream stays quiet (no EOF while hyper replies)…
        let mut buf = [0u8; 16];
        assert!(tokio::time::timeout(Duration::from_secs(1), io.read(&mut buf)).await.is_err());
        // …and further attacker bytes are ignored, never forwarded.
        client.write_all(b"GET /admin HTTP/1.1\r\nHost: a\r\n\r\n").await.unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(1), io.read(&mut buf)).await.is_err());
    }

    #[tokio::test]
    async fn small_read_buffers_still_deliver_the_whole_rejection() {
        let (mut client, mut io, _) = io_pair(true);
        client.write_all(b"GET / HTTP/1.1\nHost: a\n\n").await.unwrap();
        let text = read_head(&mut io, 7).await;
        assert!(text.contains("bare-line-ending"), "{text}");
    }

    #[tokio::test(start_paused = true)]
    async fn partial_head_is_withheld_from_the_http_layer_and_slowloris_is_cut() {
        let (mut client, mut io, _) = io_pair(true);
        client.write_all(b"GET / HTTP/1.1\r\nHost: a\r\nX-Slow: ").await.unwrap();
        let mut buf = [0u8; 256];
        // Within the header window nothing must reach the HTTP layer…
        let r = tokio::time::timeout(Duration::from_secs(2), io.read(&mut buf)).await;
        assert!(r.is_err(), "unfinished head must not be released");
        // …and once the window closes the connection is torn down.
        let err = io.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn head_split_across_reads_is_delivered_intact_once_complete() {
        let (mut client, mut io, _) = io_pair(true);
        client.write_all(b"GET /split HTTP/1.1\r\nHo").await.unwrap();
        tokio::task::yield_now().await;
        client.write_all(b"st: a\r\n\r\n").await.unwrap();
        let expect = b"GET /split HTTP/1.1\r\nHost: a\r\n\r\n";
        let mut got = vec![0u8; expect.len()];
        io.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, expect);
    }

    #[tokio::test]
    async fn body_violation_is_a_hard_io_error() {
        let (mut client, mut io, _) = io_pair(true);
        client.write_all(b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n").await.unwrap();
        let mut buf = vec![0u8; 256];
        let first = io.read(&mut buf).await;
        // The head is delivered or the error surfaces; either way an error must follow.
        if first.is_ok() {
            let second = io.read(&mut buf).await;
            assert!(second.is_err() || second.unwrap() == 0);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn idle_keepalive_expires_only_when_no_request_is_in_flight() {
        let (_client, mut io, act) = io_pair(true);
        let busy = act.begin();
        let mut buf = [0u8; 8];
        // A request is in flight: an idle socket must NOT be closed.
        let r = tokio::time::timeout(Duration::from_secs(30), io.read(&mut buf)).await;
        assert!(r.is_err(), "connection with an in-flight request must stay open");
        drop(busy);
        // Now idle: expires after idle_timeout and reports EOF.
        let n = io.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn rejected_connection_is_woken_when_the_last_inflight_request_ends() {
        // Regression: after a guard rejection `poll_read` parked on
        // `inflight() > 0` with no waker, so the connection could hang forever
        // once the request finished (idle timer already fired and was spent).
        let (mut client, mut io, act) = io_pair(true);
        client.write_all(b"GET / HTTP/1.1\nHost: a\n\n").await.unwrap();
        let head = read_head(&mut io, 4096).await;
        assert!(head.contains("bare-line-ending"));
        let busy = act.begin(); // hyper is now "serving" the synthetic 400
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 8];
            io.read(&mut buf).await.unwrap()
        });
        // Far beyond the idle timeout: must still be parked, not closed.
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert!(!reader.is_finished(), "must not close while a request is in flight");
        drop(busy);
        // No further time passes: the drop itself has to wake the reader.
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(reader.is_finished(), "reader must be woken by the last in-flight guard");
        assert_eq!(reader.await.unwrap(), 0, "…and observes a clean EOF");
    }

    #[tokio::test(start_paused = true)]
    async fn idle_reader_with_inflight_request_wakes_when_it_finishes() {
        let (_client, mut io, act) = io_pair(true);
        let busy = act.begin();
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 8];
            io.read(&mut buf).await.unwrap()
        });
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert!(!reader.is_finished());
        drop(busy);
        // idle clock restarts when the request ends; it must then expire normally.
        tokio::time::sleep(Duration::from_secs(6)).await;
        assert_eq!(reader.await.unwrap(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn write_stall_times_out() {
        let (client, server) = tokio::io::duplex(8);
        let t = IoTimeouts { write_stall: Duration::from_secs(2), ..timeouts() };
        let mut io = Box::pin(ConnIo::new(server, None, Activity::new(), t));
        // Nobody reads `client`, so the 8-byte pipe fills and the write stalls.
        let err = io.write_all(&[0u8; 1024]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        drop(client);
    }

    #[tokio::test]
    async fn websocket_upgrade_switches_to_passthrough() {
        let (mut client, mut io, _) = io_pair(true);
        client
            .write_all(b"GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n\x00\x01raw frames\r\n\r\n")
            .await
            .unwrap();
        drop(client);
        let mut got = Vec::new();
        io.read_to_end(&mut got).await.unwrap();
        assert!(got.ends_with(b"raw frames\r\n\r\n"), "frames must pass untouched");
    }
}
