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

/// A low-level HTTP/3 client for tests that need to control the stream.
pub struct H3Client {
    pub send: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    conn: quinn::Connection,
    endpoint: quinn::Endpoint,
    driver: tokio::task::JoinHandle<()>,
}

pub async fn h3_client(addr: SocketAddr, der: &CertificateDer<'static>) -> H3Client {
    let tls = client_tls(der, &[b"h3"]);
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
    let conn = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn.clone())).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    H3Client { send, conn, endpoint, driver }
}

impl H3Client {
    pub async fn close(self) {
        self.conn.close(0u32.into(), b"done");
        self.driver.abort();
        self.endpoint.wait_idle().await;
    }
}

/// Read a whole HTTP/3 response (status + body).
pub async fn h3_read_response<S>(stream: &mut h3::client::RequestStream<S, Bytes>) -> (StatusCode, Bytes)
where
    S: h3::quic::RecvStream,
{
    let resp = stream.recv_response().await.unwrap();
    let mut out = BytesMut::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        out.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    (resp.status(), out.freeze())
}

/// A cleartext HTTP/2 (h2c) backend that reports the request's trailers.
pub async fn h2c_trailer_backend() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits2 = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let hits = Arc::clone(&hits2);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let hits = Arc::clone(&hits);
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        let collected = req.into_body().collect().await.unwrap();
                        let trailers = collected.trailers().cloned().unwrap_or_default();
                        let mut out = format!("body={}\n", collected.to_bytes().len());
                        for (k, v) in &trailers {
                            out.push_str(&format!("trailer {k}={}\n", v.to_str().unwrap_or("?")));
                        }
                        Ok::<_, Infallible>(text(out))
                    }
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    (addr, hits)
}

// ---------------- HTTPS backends ----------------

/// A named self-signed certificate (`<name>.crt` / `<name>.key`).
pub fn write_named_cert(dir: &Path, name: &str, sans: &[&str]) -> (PathBuf, PathBuf, CertificateDer<'static>) {
    let g = rcgen::generate_simple_self_signed(sans.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>()).unwrap();
    let (cert, key) = (dir.join(format!("{name}.crt")), dir.join(format!("{name}.key")));
    std::fs::write(&cert, g.cert.pem()).unwrap();
    std::fs::write(&key, g.key_pair.serialize_pem()).unwrap();
    (cert, key, g.cert.der().clone())
}

/// What a TLS backend should demand and offer.
#[derive(Default)]
pub struct TlsBackendOpts {
    /// ALPN protocols offered (`h2`, `http/1.1`).
    pub alpn: Vec<&'static [u8]>,
    /// Require a client certificate chaining to one of these (mTLS).
    pub client_roots: Vec<CertificateDer<'static>>,
}

/// An HTTPS mock backend that records what its clients presented.
pub struct TlsBackend {
    pub addr: SocketAddr,
    pub hits: Arc<AtomicUsize>,
    /// DER of the client certificate presented on each successful handshake.
    pub client_certs: Arc<std::sync::Mutex<Vec<Option<Vec<u8>>>>>,
    /// SNI seen on each successful handshake.
    pub snis: Arc<std::sync::Mutex<Vec<Option<String>>>>,
    pub failed_handshakes: Arc<AtomicUsize>,
}

/// Serve `handler` over TLS with the given certificate. The response carries
/// `x-alpn` (negotiated protocol) so tests can assert on it.
pub async fn tls_backend(handler: Handler, cert: &Path, key: &Path, opts: TlsBackendOpts) -> TlsBackend {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::PrivateKeyDer;
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(cert).unwrap().map(|c| c.unwrap()).collect();
    let key = PrivateKeyDer::from_pem_file(key).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .unwrap();
    let builder = if opts.client_roots.is_empty() {
        builder.with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        for r in &opts.client_roots {
            roots.add(r.clone()).unwrap();
        }
        let verifier =
            rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider).build().unwrap();
        builder.with_client_cert_verifier(verifier)
    };
    let mut cfg = builder.with_single_cert(chain, key).unwrap();
    cfg.alpn_protocols = opts.alpn.iter().map(|a| a.to_vec()).collect();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let out = TlsBackend {
        addr,
        hits: Arc::default(),
        client_certs: Arc::default(),
        snis: Arc::default(),
        failed_handshakes: Arc::default(),
    };
    let (hits, certs, snis, failed) = (
        Arc::clone(&out.hits),
        Arc::clone(&out.client_certs),
        Arc::clone(&out.snis),
        Arc::clone(&out.failed_handshakes),
    );
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            let (acceptor, handler, hits, certs, snis, failed) = (
                acceptor.clone(),
                Arc::clone(&handler),
                Arc::clone(&hits),
                Arc::clone(&certs),
                Arc::clone(&snis),
                Arc::clone(&failed),
            );
            tokio::spawn(async move {
                let tls = match acceptor.accept(tcp).await {
                    Ok(t) => t,
                    Err(_) => {
                        failed.fetch_add(1, Ordering::SeqCst);
                        return;
                    }
                };
                let (_, session) = tls.get_ref();
                let alpn = session.alpn_protocol().map(|a| String::from_utf8_lossy(a).into_owned());
                certs.lock().unwrap().push(session.peer_certificates().and_then(|c| c.first()).map(|c| c.to_vec()));
                snis.lock().unwrap().push(session.server_name().map(str::to_owned));
                let h2 = alpn.as_deref() == Some("h2");
                let alpn = alpn.unwrap_or_else(|| "none".to_owned());
                let svc = service_fn(move |req: Request<Incoming>| {
                    let (handler, hits, alpn) = (Arc::clone(&handler), Arc::clone(&hits), alpn.clone());
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        let mut resp = handler(req).await;
                        resp.headers_mut().insert("x-alpn", alpn.parse().unwrap());
                        Ok::<_, Infallible>(resp)
                    }
                });
                if h2 {
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls), svc)
                        .await;
                } else {
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tls), svc).await;
                }
            });
        }
    });
    out
}
