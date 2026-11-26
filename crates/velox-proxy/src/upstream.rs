//! Pooled upstream connections (HTTP/1.1 and HTTP/2 prior-knowledge) over TCP
//! and Unix sockets.

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
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UnixStream};
use velox_core::config::{BackendAddr, PoolConfig, UpstreamProtocol};
use velox_core::upstream::uds_path_from_host;
use velox_core::UpstreamGroup;

/// A connected upstream socket.
#[derive(Debug)]
pub enum UpstreamStream {
    /// TCP.
    Tcp(TcpStream),
    /// Unix domain socket.
    Unix(UnixStream),
}

impl AsyncRead for UpstreamStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Self::Unix(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UpstreamStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write(cx, data),
            Self::Unix(s) => Pin::new(s).poll_write(cx, data),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            Self::Unix(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Self::Unix(s) => Pin::new(s).poll_shutdown(cx),
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
        BackendAddr::Tcp { host, port } => {
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

/// Resolves a pool URI (`http://<authority>/…`) into a connection.
#[derive(Debug, Clone)]
pub struct Connector {
    connect_timeout: Duration,
    nodelay: bool,
}

impl tower_service::Service<http::Uri> for Connector {
    type Response = UpstreamConn;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<UpstreamConn>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let (timeout, nodelay) = (self.connect_timeout, self.nodelay);
        Box::pin(async move {
            let host =
                uri.host().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "upstream URI has no host"))?;
            let addr = match uds_path_from_host(host) {
                Some(path) => BackendAddr::Unix(path),
                None => BackendAddr::Tcp { host: host.to_owned(), port: uri.port_u16().unwrap_or(80) },
            };
            let stream = connect_backend(&addr, timeout, nodelay).await?;
            Ok(UpstreamConn { io: TokioIo::new(stream) })
        })
    }
}

/// The pooled HTTP client type.
pub type UpstreamClient = Client<Connector, ProxyBody>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClientKey {
    protocol: UpstreamProtocol,
    pool_idle: Duration,
    pool_max_idle: usize,
    connect: Duration,
    nodelay: bool,
}

/// Per-upstream clients, rebuilt only when their pool settings change.
#[derive(Default)]
pub struct UpstreamClients {
    map: DashMap<Arc<str>, (ClientKey, UpstreamClient)>,
}

impl std::fmt::Debug for UpstreamClients {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamClients").field("clients", &self.map.len()).finish()
    }
}

impl UpstreamClients {
    /// The client for `group`, creating or replacing it if settings changed.
    ///
    /// Connections idle in a replaced client are closed once its in-flight
    /// requests finish.
    pub fn get(&self, group: &UpstreamGroup, connect: Duration, nodelay: bool) -> UpstreamClient {
        let PoolConfig { idle_timeout, max_idle_per_backend } = group.config.pool.clone();
        let key = ClientKey {
            protocol: group.config.protocol,
            pool_idle: idle_timeout,
            pool_max_idle: max_idle_per_backend,
            connect,
            nodelay,
        };
        if let Some(e) = self.map.get(&group.name) {
            if e.0 == key {
                return e.1.clone();
            }
        }
        let mut builder = Client::builder(TokioExecutor::new());
        builder
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(idle_timeout)
            .pool_max_idle_per_host(max_idle_per_backend);
        if key.protocol == UpstreamProtocol::H2c {
            builder.http2_only(true);
        }
        let client = builder.build(Connector { connect_timeout: connect, nodelay });
        self.map.insert(Arc::clone(&group.name), (key, client.clone()));
        client
    }

    /// Drop clients of upstreams that no longer exist.
    pub fn retain<'a>(&self, live: impl Iterator<Item = &'a str>) {
        let live: std::collections::HashSet<&str> = live.collect();
        self.map.retain(|k, _| live.contains(&**k));
    }
}
