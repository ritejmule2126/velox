//! HTTP/3 front-end (QUIC over UDP) on `quinn` + `h3`.

use crate::body::{BodyError, ChannelBody, LengthMismatch};
use crate::error::{empty, BoxError, ProxyBody};
use crate::handler::{ConnMeta, Proxy};
use crate::socket;
use bytes::{Buf, Bytes};
use http::{Method, Request, Response};
use http_body::Frame;
use http_body_util::BodyExt;
use quinn::crypto::rustls::QuicServerConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use velox_core::Config;
use velox_security::SniResolver;
use velox_telemetry::Protocol;

/// Above this many open connections, unvalidated clients must prove their
/// address with a Retry round trip (QUIC amplification / spoofing defence).
const RETRY_ABOVE: usize = 512;

/// Errors starting the HTTP/3 endpoint.
#[derive(Debug, thiserror::Error)]
pub enum H3Error {
    /// TLS material or configuration was unusable.
    #[error("QUIC TLS configuration error: {0}")]
    Tls(String),
    /// Socket or endpoint setup failed.
    #[error("QUIC endpoint error: {0}")]
    Io(#[from] std::io::Error),
}

/// Build and bind the QUIC endpoint.
pub fn bind_endpoint(addr: SocketAddr, cfg: &Config, resolver: Arc<SniResolver>) -> Result<quinn::Endpoint, H3Error> {
    let tls = velox_security::tls::quic_server_config(resolver).map_err(|e| H3Error::Tls(e.to_string()))?;
    let quic = QuicServerConfig::try_from(tls).map_err(|e| H3Error::Tls(e.to_string()))?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(quic));
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(quinn::VarInt::from_u32(cfg.limits.max_streams_per_connection))
        .max_concurrent_uni_streams(quinn::VarInt::from_u32(16))
        .datagram_receive_buffer_size(None);
    if let Ok(idle) = quinn::IdleTimeout::try_from(cfg.timeouts.idle_keepalive) {
        transport.max_idle_timeout(Some(idle));
    }
    server.transport_config(Arc::new(transport));
    let socket = socket::bind_udp(addr, cfg.server.reuse_port)?;
    let endpoint =
        quinn::Endpoint::new(quinn::EndpointConfig::default(), Some(server), socket, Arc::new(quinn::TokioRuntime))?;
    Ok(endpoint)
}

/// Accept QUIC connections until drain starts.
pub async fn accept_loop(endpoint: quinn::Endpoint, proxy: Arc<Proxy>) {
    let sd = proxy.shutdown().clone();
    loop {
        let incoming = tokio::select! {
            biased;
            () = sd.drain.cancelled() => break,
            i = endpoint.accept() => match i { Some(i) => i, None => break },
        };
        let peer = incoming.remote_address();
        let snap = proxy.state().load();
        let limits = &snap.config.limits;
        let permit =
            match proxy.conn_limiter().try_acquire(peer.ip(), limits.max_connections, limits.max_connections_per_ip) {
                Ok(p) => p,
                Err(_) => {
                    proxy.metrics().connection_rejected();
                    incoming.refuse();
                    continue;
                }
            };
        if !incoming.remote_address_validated() && endpoint.open_connections() > RETRY_ABOVE {
            // Under load, make the client prove it owns its source address.
            let _ = incoming.retry();
            continue;
        }
        let handshake_timeout = snap.config.timeouts.tls_handshake;
        drop(snap);
        let proxy = Arc::clone(&proxy);
        sd.tasks.spawn(async move {
            let _permit = permit;
            let connecting = match incoming.accept() {
                Ok(c) => c,
                Err(e) => {
                    proxy.metrics().tls_handshake_error("quic", "accept");
                    tracing::debug!(%peer, error = %e, "QUIC accept failed");
                    return;
                }
            };
            let conn = match tokio::time::timeout(handshake_timeout, connecting).await {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    proxy.metrics().tls_handshake_error("quic", classify(&e));
                    tracing::debug!(%peer, error = %e, "QUIC handshake failed");
                    return;
                }
                Err(_) => {
                    proxy.metrics().tls_handshake_error("quic", "timeout");
                    return;
                }
            };
            serve_connection(conn, peer, proxy).await;
        });
    }
}

fn classify(e: &quinn::ConnectionError) -> &'static str {
    match e {
        quinn::ConnectionError::TimedOut => "timeout",
        quinn::ConnectionError::TransportError(_) => "transport",
        quinn::ConnectionError::ConnectionClosed(_) | quinn::ConnectionError::ApplicationClosed(_) => "closed",
        quinn::ConnectionError::Reset => "reset",
        _ => "other",
    }
}

async fn serve_connection(conn: quinn::Connection, peer: SocketAddr, proxy: Arc<Proxy>) {
    let _open = proxy.metrics().connection_opened(Protocol::H3);
    let cfg = proxy.state().load().config.clone();
    let mut h3 = match h3::server::builder()
        .max_field_section_size(cfg.limits.max_header_bytes as u64)
        .build::<_, Bytes>(h3_quinn::Connection::new(conn.clone()))
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(%peer, error = %e, "HTTP/3 setup failed");
            return;
        }
    };
    let sd = proxy.shutdown().clone();
    let mut draining = false;
    loop {
        let next = tokio::select! {
            r = h3.accept() => r,
            () = sd.drain.cancelled(), if !draining => {
                draining = true;
                if let Err(e) = h3.shutdown(0).await {
                    tracing::debug!(%peer, error = %e, "HTTP/3 GOAWAY failed");
                }
                continue;
            }
            () = sd.kill.cancelled() => break,
        };
        match next {
            Ok(Some(resolver)) => {
                let proxy = Arc::clone(&proxy);
                sd.tasks.spawn(async move {
                    if let Err(e) = serve_request(resolver, peer, &proxy).await {
                        tracing::debug!(%peer, error = %e, "HTTP/3 request ended with error");
                    }
                });
            }
            Ok(None) => break,
            Err(e) => {
                tracing::debug!(%peer, error = %e, "HTTP/3 connection error");
                break;
            }
        }
    }
    conn.close(quinn::VarInt::from_u32(0), b"bye");
}

/// How long a request that declared no `Content-Length` waits for its first
/// body event (data, trailers or FIN) before it is treated as a streaming
/// upload. A body-less `GET` delivers its FIN together with the headers, so in
/// practice this is one scheduler hop.
const FIRST_EVENT_GRACE: Duration = Duration::from_millis(50);

/// What the body pump learned first about a request with unknown length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirstEvent {
    /// The stream ended without data or trailers: no body at all.
    Empty,
    /// Data or trailers are coming.
    Body,
}

type RecvHalf = h3::server::RequestStream<h3_quinn::RecvStream, Bytes>;
type BodyTx = mpsc::Sender<Result<Frame<Bytes>, BoxError>>;

/// Owns the receive half of a request stream and feeds the handler's body.
///
/// Enforces `Content-Length` against the bytes that actually arrive (too many
/// *or* too few is an error, never a silent truncation), forwards trailers —
/// including on trailers-only requests, where the very first `recv_data()` is
/// `None` — and reports stalls as [`BodyError::IdleTimeout`] so the handler
/// answers `408`.
async fn pump_request_body(
    mut recv: RecvHalf,
    tx: BodyTx,
    declared: Option<u64>,
    idle: Duration,
    first: oneshot::Sender<FirstEvent>,
) {
    use h3::error::Code;
    let mut first = Some(first);
    let announce = |first: &mut Option<oneshot::Sender<FirstEvent>>, ev| {
        if let Some(f) = first.take() {
            let _ = f.send(ev);
        }
    };
    let mut received: u64 = 0;
    loop {
        match tokio::time::timeout(idle, recv.recv_data()).await {
            Ok(Ok(Some(mut buf))) => {
                let chunk = buf.copy_to_bytes(buf.remaining());
                received += chunk.len() as u64;
                if declared.is_some_and(|d| received > d) {
                    let _ = tx.send(Err(Box::new(LengthMismatch::TooMuch))).await;
                    recv.stop_sending(Code::H3_MESSAGE_ERROR);
                    return;
                }
                announce(&mut first, FirstEvent::Body);
                if tx.send(Ok(Frame::data(chunk))).await.is_err() {
                    // The handler stopped reading (e.g. it already answered).
                    recv.stop_sending(Code::H3_NO_ERROR);
                    return;
                }
            }
            Ok(Ok(None)) => break,
            Ok(Err(e)) => {
                let _ = tx.send(Err(Box::new(e))).await;
                return;
            }
            Err(_) => {
                let _ = tx.send(Err(Box::new(BodyError::IdleTimeout))).await;
                recv.stop_sending(Code::H3_REQUEST_INCOMPLETE);
                return;
            }
        }
    }
    // The data is finished; trailers (if any) come next. Always ask: a
    // trailers-only request has no data frames at all.
    let trailers = match tokio::time::timeout(idle, recv.recv_trailers()).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            let _ = tx.send(Err(Box::new(e))).await;
            return;
        }
        Err(_) => {
            let _ = tx.send(Err(Box::new(BodyError::IdleTimeout))).await;
            return;
        }
    };
    if declared.is_some_and(|d| received < d) {
        let _ = tx.send(Err(Box::new(LengthMismatch::TooLittle))).await;
        return;
    }
    match trailers {
        Some(t) => {
            announce(&mut first, FirstEvent::Body);
            let _ = tx.send(Ok(Frame::trailers(t))).await;
        }
        None => announce(&mut first, FirstEvent::Empty),
    }
}

/// Serve one HTTP/3 request stream.
///
/// If the request head does not arrive within `timeouts.header_read` there is
/// no resolved stream to write a response on (the `h3` crate only hands us the
/// stream together with a parsed head), so the stream is reset instead. Every
/// later failure, including stalled bodies, produces a real HTTP response.
async fn serve_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    peer: SocketAddr,
    proxy: &Arc<Proxy>,
) -> Result<(), BoxError> {
    let cfg = proxy.state().load().config.clone();
    let (req, stream) = tokio::time::timeout(cfg.timeouts.header_read, resolver.resolve_request())
        .await
        .map_err(|_| "request headers not received in time (stream reset)")??;
    let (mut send, recv) = stream.split();
    let (parts, ()) = req.into_parts();
    let is_head = parts.method == Method::HEAD;
    let declared = parts
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());

    // The pump starts immediately and never blocks the handler: routing, rate
    // limiting and size checks proceed while the body streams in.
    let (tx, channel_body) = ChannelBody::new(declared);
    let (first_tx, first_rx) = oneshot::channel();
    proxy.shutdown().tasks.spawn(pump_request_body(recv, tx, declared, cfg.timeouts.request_body_idle, first_tx));
    let body: ProxyBody = match declared {
        Some(0) => empty(),
        Some(_) => ProxyBody::boxed(channel_body),
        None => match tokio::time::timeout(FIRST_EVENT_GRACE, first_rx).await {
            Ok(Ok(FirstEvent::Empty)) => empty(),
            _ => ProxyBody::boxed(channel_body),
        },
    };

    let request = Request::from_parts(parts, body);
    let meta = ConnMeta { peer, protocol: Protocol::H3, tls: true };
    let response = proxy.handle(request, meta, None).await;
    write_response(&mut send, response, is_head, cfg.timeouts.write_stall).await
}

async fn write_response(
    send: &mut h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    response: Response<ProxyBody>,
    is_head: bool,
    stall: Duration,
) -> Result<(), BoxError> {
    let (parts, mut body) = response.into_parts();
    send.send_response(Response::from_parts(parts, ())).await?;
    if !is_head {
        loop {
            let frame = match body.frame().await {
                None => break,
                Some(Ok(f)) => f,
                Some(Err(e)) => {
                    send.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
                    return Err(e);
                }
            };
            match frame.into_data() {
                Ok(data) => {
                    tokio::time::timeout(stall, send.send_data(data))
                        .await
                        .map_err(|_| "client stopped reading the response")??;
                }
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        send.send_trailers(trailers).await?;
                    }
                }
            }
        }
    }
    send.finish().await?;
    Ok(())
}
