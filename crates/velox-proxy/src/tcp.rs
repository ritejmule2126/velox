//! TCP front-end: plain HTTP/1.1 and TLS with ALPN-selected HTTP/2 or HTTP/1.1.

use crate::error::{BoxError, ProxyBody};
use crate::handler::{ConnMeta, Proxy};
use crate::io::{Activity, ConnIo, IoTimeouts};
use crate::proxy_protocol;
use crate::socket;
use http_body::Body as _;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use velox_core::sanitize::{H1Guard, H1Limits};
use velox_core::Config;
use velox_telemetry::Protocol;

/// How a TCP listener treats accepted sockets.
#[derive(Clone)]
pub enum Mode {
    /// Cleartext HTTP/1.1.
    Plain,
    /// TLS with ALPN `h2` / `http/1.1`.
    Tls(TlsAcceptor),
}

/// Accept connections until the drain signal fires.
///
/// With `proxy_protocol`, every connection must open with a PROXY v1/v2 header
/// from a `server.proxy_protocol_trusted` peer; the client address it carries
/// replaces the TCP peer for limits, logs, rate limiting and `X-Forwarded-*`.
pub async fn accept_loop(listener: Arc<TcpListener>, mode: Mode, proxy: Arc<Proxy>, proxy_protocol: bool) {
    let sd = proxy.shutdown().clone();
    let mut backoff = Duration::from_millis(10);
    loop {
        let accepted = tokio::select! {
            biased;
            () = sd.drain.cancelled() => break,
            r = listener.accept() => r,
        };
        let (stream, peer) = match accepted {
            Ok(x) => {
                backoff = Duration::from_millis(10);
                x
            }
            Err(e) => {
                // EMFILE and friends: back off instead of spinning.
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(1));
                continue;
            }
        };
        let snap = proxy.state().load();
        let limits = &snap.config.limits;
        if proxy_protocol {
            // Only the load balancer may speak first; everyone else is turned
            // away before a single byte is read.
            if !proxy_protocol::is_trusted(peer.ip(), &snap.config.server.proxy_protocol_trusted) {
                tracing::debug!(%peer, "connection on a PROXY-protocol listener from an untrusted peer");
                proxy.metrics().proxy_protocol_error("untrusted_peer");
                continue;
            }
            // Bound the not-yet-identified connections by the global cap only:
            // all of them share the load balancer's address.
            let Ok(pending) = proxy.conn_limiter().try_acquire(peer.ip(), limits.max_connections, 0) else {
                proxy.metrics().connection_rejected();
                continue;
            };
            socket::tune_accepted(&stream, snap.config.server.tcp_nodelay);
            let header_timeout = snap.config.timeouts.header_read;
            drop(snap);
            let proxy = Arc::clone(&proxy);
            let mode = mode.clone();
            sd.tasks.spawn(async move {
                let mut stream = stream;
                let client = match proxy_protocol::read_header(&mut stream, header_timeout).await {
                    // `LOCAL` / `UNKNOWN`: the load balancer's own probe.
                    Ok(h) => h.client.unwrap_or(peer),
                    Err(e) => {
                        tracing::debug!(%peer, error = %e, "PROXY header rejected");
                        proxy.metrics().proxy_protocol_error(e.reason());
                        return;
                    }
                };
                drop(pending);
                let snap = proxy.state().load();
                let limits = &snap.config.limits;
                let permit = match proxy.conn_limiter().try_acquire(
                    client.ip(),
                    limits.max_connections,
                    limits.max_connections_per_ip,
                ) {
                    Ok(p) => p,
                    Err(why) => {
                        tracing::debug!(%client, reason = %why, "connection refused");
                        proxy.metrics().connection_rejected();
                        return;
                    }
                };
                drop(snap);
                let _permit = permit;
                serve(stream, client, mode, proxy).await;
            });
            continue;
        }
        let permit =
            match proxy.conn_limiter().try_acquire(peer.ip(), limits.max_connections, limits.max_connections_per_ip) {
                Ok(p) => p,
                Err(why) => {
                    tracing::debug!(%peer, reason = %why, "connection refused");
                    proxy.metrics().connection_rejected();
                    continue; // dropping the stream closes it
                }
            };
        socket::tune_accepted(&stream, snap.config.server.tcp_nodelay);
        let proxy = Arc::clone(&proxy);
        let mode = mode.clone();
        sd.tasks.spawn(async move {
            let _permit = permit;
            serve(stream, peer, mode, proxy).await;
        });
    }
}

async fn serve(stream: TcpStream, peer: SocketAddr, mode: Mode, proxy: Arc<Proxy>) {
    let snap = proxy.state().load();
    let cfg = Arc::clone(&snap.config);
    drop(snap);
    match mode {
        Mode::Plain => serve_h1(stream, peer, false, &proxy, &cfg).await,
        Mode::Tls(acceptor) => {
            let handshake = tokio::time::timeout(cfg.timeouts.tls_handshake, acceptor.accept(stream)).await;
            let tls = match handshake {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    proxy.metrics().tls_handshake_error("tcp", classify_tls_error(&e));
                    tracing::debug!(%peer, error = %e, "TLS handshake failed");
                    return;
                }
                Err(_) => {
                    proxy.metrics().tls_handshake_error("tcp", "timeout");
                    return;
                }
            };
            let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
            if h2 {
                serve_h2(tls, peer, &proxy, &cfg).await;
            } else {
                serve_h1(tls, peer, true, &proxy, &cfg).await;
            }
        }
    }
}

/// Bucket a handshake error into a low-cardinality metric label.
pub fn classify_tls_error(e: &std::io::Error) -> &'static str {
    let text = e.to_string().to_ascii_lowercase();
    if text.contains("unexpected eof") || text.contains("close_notify") || e.kind() == std::io::ErrorKind::UnexpectedEof
    {
        "eof"
    } else if text.contains("certificate") {
        "certificate"
    } else if text.contains("protocol version") || text.contains("handshake failure") || text.contains("no cipher") {
        "negotiation"
    } else if text.contains("alert") {
        "alert"
    } else if e.kind() == std::io::ErrorKind::ConnectionReset {
        "reset"
    } else {
        "other"
    }
}

fn io_timeouts(cfg: &Config) -> IoTimeouts {
    IoTimeouts {
        header_read: cfg.timeouts.header_read,
        idle_keepalive: cfg.timeouts.idle_keepalive,
        write_stall: cfg.timeouts.write_stall,
    }
}

fn to_proxy_request(req: hyper::Request<Incoming>) -> hyper::Request<ProxyBody> {
    // Body-less requests (the common GET) skip the trait-object allocation.
    req.map(|b| if b.is_end_stream() { ProxyBody::Empty } else { ProxyBody::boxed(b) })
}

async fn serve_h1<T>(io: T, peer: SocketAddr, tls: bool, proxy: &Arc<Proxy>, cfg: &Config)
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let _open = proxy.metrics().connection_opened(Protocol::H1);
    let activity = Activity::new();
    let guard = H1Guard::new(H1Limits {
        max_head_bytes: cfg.limits.max_header_bytes,
        max_headers: cfg.limits.max_headers,
        max_uri_bytes: cfg.limits.max_uri_bytes,
        allow_underscores_in_host: cfg.security.allow_underscores_in_host,
    });
    let io = TokioIo::new(Box::pin(ConnIo::new(io, Some(guard), Arc::clone(&activity), io_timeouts(cfg))));
    let meta = ConnMeta { peer, protocol: Protocol::H1, tls };
    let svc_proxy = Arc::clone(proxy);
    let svc = service_fn(move |req: hyper::Request<Incoming>| {
        let proxy = Arc::clone(&svc_proxy);
        let activity = Arc::clone(&activity);
        async move { Ok::<_, Infallible>(proxy.handle(to_proxy_request(req), meta, Some(&activity)).await) }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .keep_alive(true)
        .half_close(false)
        .max_buf_size(cfg.limits.max_header_bytes.max(16 * 1024));
    let conn = builder.serve_connection(io, svc).with_upgrades();
    drive(conn, proxy, peer).await;
}

async fn serve_h2<T>(io: T, peer: SocketAddr, proxy: &Arc<Proxy>, cfg: &Config)
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let _open = proxy.metrics().connection_opened(Protocol::H2);
    let activity = Activity::new();
    let io = TokioIo::new(Box::pin(ConnIo::new(io, None, Arc::clone(&activity), io_timeouts(cfg))));
    let meta = ConnMeta { peer, protocol: Protocol::H2, tls: true };
    let svc_proxy = Arc::clone(proxy);
    let svc = service_fn(move |req: hyper::Request<Incoming>| {
        let proxy = Arc::clone(&svc_proxy);
        let activity = Arc::clone(&activity);
        async move { Ok::<_, Infallible>(proxy.handle(to_proxy_request(req), meta, Some(&activity)).await) }
    });
    let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    builder
        .timer(TokioTimer::new())
        .max_concurrent_streams(cfg.limits.max_streams_per_connection)
        .max_header_list_size(u32::try_from(cfg.limits.max_header_bytes).unwrap_or(u32::MAX))
        // Rapid-Reset (CVE-2023-44487) and friends: bound reset-stream churn.
        .max_pending_accept_reset_streams(Some(64))
        .max_local_error_reset_streams(Some(256))
        .keep_alive_interval(Some(Duration::from_secs(20)))
        .keep_alive_timeout(Duration::from_secs(10));
    let conn = builder.serve_connection(io, svc);
    drive(conn, proxy, peer).await;
}

/// Minimal surface of hyper's connection futures that we need.
trait Graceful: std::future::Future<Output = Result<(), hyper::Error>> {
    fn start_graceful(self: std::pin::Pin<&mut Self>);
}

impl<T, S> Graceful for hyper::server::conn::http1::UpgradeableConnection<T, S>
where
    T: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    S: hyper::service::HttpService<Incoming>,
    S::Error: Into<BoxError>,
    S::ResBody: 'static,
    <S::ResBody as hyper::body::Body>::Error: Into<BoxError>,
{
    fn start_graceful(self: std::pin::Pin<&mut Self>) {
        self.graceful_shutdown();
    }
}

impl<T, S, E> Graceful for hyper::server::conn::http2::Connection<T, S, E>
where
    T: hyper::rt::Read + hyper::rt::Write + Unpin + 'static,
    S: hyper::service::HttpService<Incoming>,
    S::Error: Into<BoxError>,
    S::ResBody: 'static,
    <S::ResBody as hyper::body::Body>::Error: Into<BoxError>,
    E: hyper::rt::bounds::Http2ServerConnExec<S::Future, S::ResBody>,
{
    fn start_graceful(self: std::pin::Pin<&mut Self>) {
        self.graceful_shutdown();
    }
}

/// Run a connection to completion, honouring drain (graceful) and kill.
async fn drive<C: Graceful>(conn: C, proxy: &Arc<Proxy>, peer: SocketAddr) {
    let sd = proxy.shutdown();
    tokio::pin!(conn);
    let result = tokio::select! {
        r = conn.as_mut() => Some(r),
        () = sd.drain.cancelled() => {
            conn.as_mut().start_graceful();
            tokio::select! {
                r = conn.as_mut() => Some(r),
                () = sd.kill.cancelled() => None,
            }
        }
    };
    if let Some(Err(e)) = result {
        tracing::debug!(%peer, error = %e, "connection ended with error");
    }
}
