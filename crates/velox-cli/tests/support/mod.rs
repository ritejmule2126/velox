//! Shared helpers for the end-to-end tests: mock backends, TLS clients for
//! HTTP/1.1, HTTP/2 and HTTP/3, and a tiny admin-API client.
#![allow(dead_code, missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderMap, Method, Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, ServerName};
use serde_json::Value;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

pub type Handler =
    Arc<dyn Fn(Request<Incoming>) -> Pin<Box<dyn Future<Output = Response<Full<Bytes>>> + Send>> + Send + Sync>;

/// Wrap an async closure as a backend handler.
pub fn handler<F, Fut>(f: F) -> Handler
where
    F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response<Full<Bytes>>> + Send + 'static,
{
    Arc::new(move |req| Box::pin(f(req)))
}

pub fn text(body: impl Into<String>) -> Response<Full<Bytes>> {
    Response::new(Full::new(Bytes::from(body.into())))
}

/// A controllable mock HTTP/1.1 backend.
pub struct Mock {
    pub addr: SocketAddr,
    pub hits: Arc<AtomicUsize>,
    cancel: CancellationToken,
}

impl Mock {
    pub async fn start(h: Handler) -> Self {
        Self::start_on("127.0.0.1:0".parse().unwrap(), h).await
    }

    pub async fn start_on(addr: SocketAddr, h: Handler) -> Self {
        let listener = TcpListener::bind(addr).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let cancel = CancellationToken::new();
        let (hits2, cancel2) = (Arc::clone(&hits), cancel.clone());
        tokio::spawn(async move {
            loop {
                let stream = tokio::select! {
                    () = cancel2.cancelled() => return,
                    r = listener.accept() => match r { Ok((s, _)) => s, Err(_) => return },
                };
                let (h, hits, cancel) = (Arc::clone(&h), Arc::clone(&hits2), cancel2.clone());
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let (h, hits) = (Arc::clone(&h), Arc::clone(&hits));
                        async move {
                            hits.fetch_add(1, Ordering::SeqCst);
                            Ok::<_, Infallible>(h(req).await)
                        }
                    });
                    let conn = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc);
                    tokio::select! {
                        _ = conn => {}
                        () = cancel.cancelled() => {}
                    }
                });
            }
        });
        Self { addr, hits, cancel }
    }

    /// Stop listening and drop every open connection.
    pub fn stop(&self) {
        self.cancel.cancel();
    }

    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

/// A free local TCP port (bind to :0, read, release).
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Generate a self-signed `localhost` certificate; returns PEM paths and the DER.
pub fn write_cert(dir: &Path) -> (PathBuf, PathBuf, CertificateDer<'static>) {
    let g = rcgen::generate_simple_self_signed(vec!["localhost".to_owned(), "127.0.0.1".to_owned()]).unwrap();
    let (cert, key) = (dir.join("server.crt"), dir.join("server.key"));
    std::fs::write(&cert, g.cert.pem()).unwrap();
    std::fs::write(&key, g.key_pair.serialize_pem()).unwrap();
    (cert, key, g.cert.der().clone())
}

pub fn client_tls(der: &CertificateDer<'static>, alpn: &[&[u8]]) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der.clone()).unwrap();
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Arc::new(cfg)
}

pub struct Reply {
    pub status: StatusCode,
    pub version: Version,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl Reply {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

async fn tls_stream(
    addr: SocketAddr,
    der: &CertificateDer<'static>,
    alpn: &[&[u8]],
) -> (tokio_rustls::client::TlsStream<TcpStream>, Option<Vec<u8>>) {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let connector = tokio_rustls::TlsConnector::from(client_tls(der, alpn));
    let tls = connector.connect(ServerName::try_from("localhost").unwrap(), tcp).await.unwrap();
    let negotiated = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    (tls, negotiated)
}

pub fn build(method: Method, path: &str, body: Bytes) -> Request<Full<Bytes>> {
    let mut b = Request::builder().method(method).uri(format!("https://localhost{path}"));
    if !body.is_empty() {
        b = b.header("content-length", body.len().to_string());
    }
    b.body(Full::new(body)).unwrap()
}

/// One request over TLS with ALPN `http/1.1`.
pub async fn https1(addr: SocketAddr, der: &CertificateDer<'static>, method: Method, path: &str, body: Bytes) -> Reply {
    let (tls, alpn) = tls_stream(addr, der, &[b"http/1.1"]).await;
    assert_eq!(alpn.as_deref(), Some(&b"http/1.1"[..]));
    let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.unwrap();
    tokio::spawn(conn);
    // HTTP/1.1 requests use origin-form targets (absolute-form is refused by design).
    let mut b = Request::builder().method(method).uri(path).header("host", "localhost");
    if !body.is_empty() {
        b = b.header("content-length", body.len().to_string());
    }
    let resp = send.send_request(b.body(Full::new(body)).unwrap()).await.unwrap();
    collect(resp).await
}

/// What a strict server must do with an absolute-form request target.
pub async fn https1_absolute_form(addr: SocketAddr, der: &CertificateDer<'static>) -> StatusCode {
    let (tls, _) = tls_stream(addr, der, &[b"http/1.1"]).await;
    let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.unwrap();
    tokio::spawn(conn);
    let req = build(Method::GET, "/abs", Bytes::new());
    send.send_request(req).await.unwrap().status()
}

/// One request over TLS with ALPN `h2`.
pub async fn https2(addr: SocketAddr, der: &CertificateDer<'static>, method: Method, path: &str, body: Bytes) -> Reply {
    let (tls, alpn) = tls_stream(addr, der, &[b"h2"]).await;
    assert_eq!(alpn.as_deref(), Some(&b"h2"[..]), "server must negotiate h2");
    let (mut send, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls)).await.unwrap();
    tokio::spawn(conn);
    let resp = send.send_request(build(method, path, body)).await.unwrap();
    collect(resp).await
}

async fn collect(resp: Response<Incoming>) -> Reply {
    let (parts, body) = resp.into_parts();
    Reply {
        status: parts.status,
        version: parts.version,
        headers: parts.headers,
        body: body.collect().await.unwrap().to_bytes(),
    }
}

/// An open HTTP/2 connection for multiplexing tests.
pub async fn h2_connection(
    addr: SocketAddr,
    der: &CertificateDer<'static>,
) -> hyper::client::conn::http2::SendRequest<Full<Bytes>> {
    let (tls, _) = tls_stream(addr, der, &[b"h2"]).await;
    let (send, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls)).await.unwrap();
    tokio::spawn(conn);
    send
}

/// One request over HTTP/3 (QUIC).
pub async fn http3(addr: SocketAddr, der: &CertificateDer<'static>, method: Method, path: &str, body: Bytes) -> Reply {
    let tls = client_tls(der, &[b"h3"]);
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
    let conn = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn.clone())).await.unwrap();
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let mut b = Request::builder().method(method).uri(format!("https://localhost{path}"));
    if !body.is_empty() {
        b = b.header("content-length", body.len().to_string());
    }
    let mut stream = send.send_request(b.body(()).unwrap()).await.unwrap();
    if !body.is_empty() {
        stream.send_data(body).await.unwrap();
    }
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    let mut out = BytesMut::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        out.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    let (parts, ()) = resp.into_parts();
    conn.close(0u32.into(), b"done");
    driver_task.abort();
    endpoint.wait_idle().await;
    Reply { status: parts.status, version: parts.version, headers: parts.headers, body: out.freeze() }
}

/// Plain HTTP/1.1 request over a fresh TCP connection (`Connection: close`).
pub async fn plain(addr: SocketAddr, path: &str, extra_headers: &str) -> (u16, String, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: example.test\r\n{extra_headers}Connection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out)).await;
    let text = String::from_utf8_lossy(&out).into_owned();
    let status = text.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let (head, body) =
        text.split_once("\r\n\r\n").map_or((text.clone(), String::new()), |(h, b)| (h.to_owned(), b.to_owned()));
    (status, head, body)
}

/// Call the admin API (JSON in/out).
pub async fn admin(addr: SocketAddr, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let payload = body.map(|b| b.to_string()).unwrap_or_default();
    let ct = if payload.is_empty() { String::new() } else { "Content-Type: application/json\r\n".to_owned() };
    s.write_all(
        format!(
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\n{ct}Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    let status = out.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let body = out.split_once("\r\n\r\n").map_or("", |(_, b)| b);
    (status, serde_json::from_str(body).unwrap_or(Value::String(body.to_owned())))
}

/// Poll `f` until it returns true (or panic after `secs`).
pub async fn eventually<F, Fut>(secs: u64, what: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    while std::time::Instant::now() < deadline {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}
