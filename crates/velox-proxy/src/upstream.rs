//! Pooled upstream connections (HTTP/1.1 and HTTP/2) over TCP, TLS and Unix
//! sockets.

use crate::error::ProxyBody;
use dashmap::DashMap;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use pin_project_lite::pin_project;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UnixStream};
use tokio_rustls::client::TlsStream;
use velox_core::clock::now_ms;
use velox_core::config::{BackendAddr, PoolConfig, UpstreamProtocol, UpstreamTlsConfig};
use velox_core::upstream::uds_path_from_host;
use velox_core::UpstreamGroup;
use velox_security::upstream_tls::{server_name, UpstreamTlsRegistry};
use velox_security::TlsError;
use velox_telemetry::Metrics;

/// A connected upstream socket.
#[derive(Debug)]
pub enum UpstreamStream {
    /// TCP.
    Tcp(TcpStream),
    /// Unix domain socket.
    Unix(UnixStream),
    /// TCP wrapped in a completed TLS client session.
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for UpstreamStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Self::Unix(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UpstreamStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write(cx, data),
            Self::Unix(s) => Pin::new(s).poll_write(cx, data),
            Self::Tls(s) => Pin::new(s).poll_write(cx, data),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            Self::Unix(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Self::Unix(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Connect to a backend with a deadline (shared by the L7 pool and L4 proxy).
pub async fn connect_backend(addr: &BackendAddr, timeout: Duration, nodelay: bool) -> io::Result<UpstreamStream> {
    tokio::time::timeout(timeout, connect_inner(addr, nodelay))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream connect timed out"))?
}

async fn connect_inner(addr: &BackendAddr, nodelay: bool) -> io::Result<UpstreamStream> {
    match addr {
        BackendAddr::Unix(path) => Ok(UpstreamStream::Unix(UnixStream::connect(path).await?)),
        // TLS is layered on by the pool connector; the socket itself is plain TCP.
        BackendAddr::Tcp { host, port } | BackendAddr::Tls { host, port } => {
            let host = BackendAddr::connect_host(host);
            let stream = if let Ok(ip) = host.parse::<IpAddr>() {
                TcpStream::connect(SocketAddr::new(ip, *port)).await?
            } else {
                let mut last = io::Error::new(io::ErrorKind::NotFound, "name resolved to no addresses");
                let mut connected = None;
                for sa in tokio::net::lookup_host((host, *port)).await? {
                    match TcpStream::connect(sa).await {
                        Ok(s) => {
                            connected = Some(s);
                            break;
                        }
                        Err(e) => last = e,
                    }
                }
                connected.ok_or(last)?
            };
            stream.set_nodelay(nodelay)?;
            Ok(UpstreamStream::Tcp(stream))
        }
    }
}

pin_project! {
    /// A pooled connection handed to `hyper-util`.
    pub struct UpstreamConn {
        #[pin] io: TokioIo<UpstreamStream>,
    }
}

impl Read for UpstreamConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: ReadBufCursor<'_>) -> Poll<io::Result<()>> {
        self.project().io.poll_read(cx, buf)
    }
}

impl Write for UpstreamConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.project().io.poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().io.poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().io.poll_shutdown(cx)
    }
}

impl Connection for UpstreamConn {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

/// TLS parameters a pooled client uses for its `https://` backends.
#[derive(Debug, Clone)]
struct TlsSetup {
    config: Arc<rustls::ClientConfig>,
    settings: Option<UpstreamTlsConfig>,
}

/// Resolves a pool URI (`http(s)://<authority>/…`) into a connection.
#[derive(Debug, Clone)]
pub struct Connector {
    connect_timeout: Duration,
    nodelay: bool,
    upstream: Arc<str>,
    tls: Option<TlsSetup>,
    metrics: Arc<Metrics>,
}

impl Connector {
    async fn handshake(&self, host: &str, tcp: TcpStream) -> io::Result<UpstreamStream> {
        let setup = self
            .tls
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "https backend without TLS configuration"))?;
        let name = server_name(setup.settings.as_ref(), host)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(&setup.config));
        match tokio::time::timeout(self.connect_timeout, connector.connect(name, tcp)).await {
            Ok(Ok(stream)) => Ok(UpstreamStream::Tls(Box::new(stream))),
            Ok(Err(e)) => {
                self.metrics.upstream_tls_error(&self.upstream, crate::tcp::classify_tls_error(&e));
                Err(e)
            }
            Err(_) => {
                self.metrics.upstream_tls_error(&self.upstream, "timeout");
                Err(io::Error::new(io::ErrorKind::TimedOut, "upstream TLS handshake timed out"))
            }
        }
    }
}

impl tower_service::Service<http::Uri> for Connector {
    type Response = UpstreamConn;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<UpstreamConn>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            let host =
                uri.host().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "upstream URI has no host"))?;
            let tls = uri.scheme() == Some(&http::uri::Scheme::HTTPS);
            let addr = match uds_path_from_host(host) {
                Some(path) => BackendAddr::Unix(path),
                None => BackendAddr::Tcp {
                    host: host.to_owned(),
                    port: uri.port_u16().unwrap_or(if tls { 443 } else { 80 }),
                },
            };
            let stream = connect_backend(&addr, this.connect_timeout, this.nodelay).await?;
            let stream = match (tls, stream) {
                (true, UpstreamStream::Tcp(tcp)) => this.handshake(host, tcp).await?,
                (true, _) => return Err(io::Error::new(io::ErrorKind::InvalidInput, "TLS needs a TCP backend")),
                (false, plain) => plain,
            };
            Ok(UpstreamConn { io: TokioIo::new(stream) })
        })
    }
}

/// The pooled HTTP client type.
pub type UpstreamClient = Client<Connector, ProxyBody>;

/// Re-check interval (ms) for an upstream's TLS files.
fn recheck_ms(group: &UpstreamGroup) -> u64 {
    let d =
        group.config.tls.as_ref().map_or_else(|| UpstreamTlsConfig::default().reload_interval, |t| t.reload_interval);
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// The settings a pooled client was built from.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ClientKey {
    protocol: UpstreamProtocol,
    pool_idle: Duration,
    pool_max_idle: usize,
    connect: Duration,
    nodelay: bool,
    has_tls: bool,
    tls: Option<UpstreamTlsConfig>,
}

impl ClientKey {
    fn of(group: &UpstreamGroup, connect: Duration, nodelay: bool) -> Self {
        let PoolConfig { idle_timeout, max_idle_per_backend } = group.config.pool.clone();
        Self {
            protocol: group.config.protocol,
            pool_idle: idle_timeout,
            pool_max_idle: max_idle_per_backend,
            connect,
            nodelay,
            has_tls: group.has_tls,
            tls: group.config.tls.clone(),
        }
    }

    /// Allocation-free equivalent of `*self == ClientKey::of(..)` (hot path).
    fn matches(&self, group: &UpstreamGroup, connect: Duration, nodelay: bool) -> bool {
        let pool = &group.config.pool;
        self.protocol == group.config.protocol
            && self.pool_idle == pool.idle_timeout
            && self.pool_max_idle == pool.max_idle_per_backend
            && self.connect == connect
            && self.nodelay == nodelay
            && self.has_tls == group.has_tls
            && self.tls == group.config.tls
    }
}

struct ClientEntry {
    key: ClientKey,
    client: UpstreamClient,
    /// The TLS configuration baked into `client` (identity is compared to
    /// detect certificate rotation).
    tls: Option<Arc<rustls::ClientConfig>>,
    next_tls_check_ms: AtomicU64,
}

/// Per-upstream clients, rebuilt when their pool or TLS settings change.
pub struct UpstreamClients {
    map: DashMap<Arc<str>, ClientEntry>,
    tls: UpstreamTlsRegistry,
    metrics: Arc<Metrics>,
}

impl std::fmt::Debug for UpstreamClients {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamClients").field("clients", &self.map.len()).finish()
    }
}

impl UpstreamClients {
    /// An empty cache; `metrics` receives upstream TLS handshake errors.
    pub fn new(metrics: Arc<Metrics>) -> Self {
        Self { map: DashMap::new(), tls: UpstreamTlsRegistry::new(), metrics }
    }

    /// The client for `group`, creating or replacing it if settings changed.
    ///
    /// Connections idle in a replaced client are closed once its in-flight
    /// requests finish. For groups with `https://` backends the TLS files are
    /// re-checked every few seconds, so a rotated CA bundle or mTLS client
    /// certificate is picked up by new connections without a reload.
    pub fn get(&self, group: &UpstreamGroup, connect: Duration, nodelay: bool) -> Result<UpstreamClient, TlsError> {
        let mut current_tls = None;
        if let Some(e) = self.map.get(&group.name) {
            if e.key.matches(group, connect, nodelay) {
                let due = group.has_tls && now_ms() >= e.next_tls_check_ms.load(Ordering::Relaxed);
                if !due {
                    return Ok(e.client.clone());
                }
                let fresh = self.tls.client_config(group.config.tls.as_ref(), group.config.protocol.is_h2())?;
                e.next_tls_check_ms.store(now_ms().saturating_add(recheck_ms(group)), Ordering::Relaxed);
                if e.tls.as_ref().is_some_and(|t| Arc::ptr_eq(t, &fresh)) {
                    return Ok(e.client.clone());
                }
                current_tls = Some(fresh);
            }
        }
        let tls = match current_tls {
            Some(t) => Some(t),
            None if group.has_tls => {
                Some(self.tls.client_config(group.config.tls.as_ref(), group.config.protocol.is_h2())?)
            }
            None => None,
        };
        let key = ClientKey::of(group, connect, nodelay);
        let mut builder = Client::builder(TokioExecutor::new());
        builder
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(key.pool_idle)
            .pool_max_idle_per_host(key.pool_max_idle);
        if key.protocol.is_h2() {
            builder.http2_only(true);
        }
        let connector = Connector {
            connect_timeout: connect,
            nodelay,
            upstream: Arc::clone(&group.name),
            tls: tls.as_ref().map(|config| TlsSetup { config: Arc::clone(config), settings: group.config.tls.clone() }),
            metrics: Arc::clone(&self.metrics),
        };
        let client = builder.build(connector);
        self.map.insert(
            Arc::clone(&group.name),
            ClientEntry {
                key,
                client: client.clone(),
                tls,
                next_tls_check_ms: AtomicU64::new(now_ms().saturating_add(recheck_ms(group))),
            },
        );
        Ok(client)
    }

    /// Drop clients (and TLS configurations) of upstreams that no longer exist.
    pub fn retain<'a>(&self, live: impl Iterator<Item = &'a UpstreamGroup>) {
        let live: Vec<&UpstreamGroup> = live.collect();
        self.map.retain(|k, _| live.iter().any(|g| *g.name == **k));
        let defaults = UpstreamTlsConfig::default();
        self.tls.retain(
            live.iter()
                .filter(|g| g.has_tls)
                .map(|g| (g.config.tls.as_ref().unwrap_or(&defaults), g.config.protocol.is_h2())),
        );
    }
}
