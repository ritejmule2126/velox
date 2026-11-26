//! Starts every listener and ties their lifetime to the shared [`Shutdown`](crate::shutdown::Shutdown).

use crate::handler::Proxy;
use crate::{h3, l4, socket, tcp};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use velox_core::Config;
use velox_security::SniResolver;

/// Failures while starting listeners.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    /// A socket could not be bound.
    #[error("cannot bind {addr}: {source}")]
    Bind {
        /// Address that failed.
        addr: SocketAddr,
        /// Underlying error.
        source: std::io::Error,
    },
    /// TLS is required but no certificate source is available.
    #[error("https_addr is configured but no TLS certificates are available")]
    NoTls,
    /// TLS configuration failed.
    #[error("TLS setup failed: {0}")]
    Tls(#[from] velox_security::TlsError),
    /// HTTP/3 setup failed.
    #[error(transparent)]
    H3(#[from] h3::H3Error),
}

/// Handles and bound addresses of a running data plane.
#[derive(Debug)]
pub struct Running {
    /// Cleartext HTTP/1.1 address.
    pub http_addr: Option<SocketAddr>,
    /// TLS (HTTP/2 + HTTP/1.1) address.
    pub https_addr: Option<SocketAddr>,
    /// QUIC (HTTP/3) UDP address.
    pub h3_addr: Option<SocketAddr>,
    /// Addresses of the L4 listeners, in configuration order.
    pub tcp_proxy_addrs: Vec<SocketAddr>,
    endpoint: Option<quinn::Endpoint>,
    proxy: Arc<Proxy>,
}

fn bind_tokio(addr: SocketAddr, cfg: &Config, reuse_port: bool) -> Result<TcpListener, StartError> {
    let std =
        socket::bind_tcp(addr, cfg.server.backlog, reuse_port).map_err(|source| StartError::Bind { addr, source })?;
    TcpListener::from_std(std).map_err(|source| StartError::Bind { addr, source })
}

/// Bind `addr` with `accept_workers` accept loops (SO_REUSEPORT when enabled).
fn bind_workers(addr: SocketAddr, cfg: &Config) -> Result<(SocketAddr, Vec<Arc<TcpListener>>), StartError> {
    let workers = cfg.server.accept_workers.max(1);
    let reuse = cfg.server.reuse_port && workers > 1;
    let first = bind_tokio(addr, cfg, reuse)?;
    let bound = first.local_addr().map_err(|source| StartError::Bind { addr, source })?;
    let mut listeners = vec![Arc::new(first)];
    if reuse {
        for _ in 1..workers {
            listeners.push(Arc::new(bind_tokio(bound, cfg, true)?));
        }
    }
    Ok((bound, listeners))
}

fn spawn_accept(
    listeners: &[Arc<TcpListener>],
    workers: usize,
    mode: &tcp::Mode,
    proxy: &Arc<Proxy>,
    proxy_protocol: bool,
) {
    let tasks = &proxy.shutdown().tasks;
    // One loop per distinct listener; if a single listener is shared, run
    // `workers` loops over it.
    let per_listener = if listeners.len() == 1 { workers.max(1) } else { 1 };
    for l in listeners {
        for _ in 0..per_listener {
            tasks.spawn(tcp::accept_loop(Arc::clone(l), mode.clone(), Arc::clone(proxy), proxy_protocol));
        }
    }
}

/// Bind every configured listener and start serving.
///
/// `tls` supplies certificates for the HTTPS and HTTP/3 listeners.
pub async fn start(proxy: Arc<Proxy>, tls: Option<Arc<SniResolver>>) -> Result<Running, StartError> {
    let cfg = Arc::clone(&proxy.state().load().config);
    let workers = cfg.server.accept_workers.max(1);

    let mut running = Running {
        http_addr: None,
        https_addr: None,
        h3_addr: None,
        tcp_proxy_addrs: Vec::new(),
        endpoint: None,
        proxy: Arc::clone(&proxy),
    };

    if let Some(addr) = cfg.server.http_addr {
        let (bound, listeners) = bind_workers(addr, &cfg)?;
        running.http_addr = Some(bound);
        spawn_accept(&listeners, workers, &tcp::Mode::Plain, &proxy, cfg.server.proxy_protocol);
    }

    if let Some(addr) = cfg.server.https_addr {
        let resolver = tls.clone().filter(|r| r.has_certificates()).ok_or(StartError::NoTls)?;
        let acceptor = TlsAcceptor::from(velox_security::tls::tcp_server_config(Arc::clone(&resolver))?);
        let (bound, listeners) = bind_workers(addr, &cfg)?;
        running.https_addr = Some(bound);
        proxy.set_bound_ports(Some(bound.port()), None);
        spawn_accept(&listeners, workers, &tcp::Mode::Tls(acceptor), &proxy, cfg.server.proxy_protocol);

        if cfg.server.h3 {
            let udp_addr = cfg.server.h3_addr.unwrap_or_else(|| {
                // Same port as TCP (the common `:443` + `:443/udp` pairing).
                SocketAddr::new(addr.ip(), bound.port())
            });
            let endpoint = h3::bind_endpoint(udp_addr, &cfg, resolver)?;
            let udp_bound = endpoint.local_addr().map_err(|source| StartError::Bind { addr: udp_addr, source })?;
            running.h3_addr = Some(udp_bound);
            proxy.set_bound_ports(None, Some(udp_bound.port()));
            proxy.metrics().set_h3_enabled(true);
            proxy.shutdown().tasks.spawn(h3::accept_loop(endpoint.clone(), Arc::clone(&proxy)));
            running.endpoint = Some(endpoint);
        }
    }

    for t in &cfg.tcp_proxies {
        let listener = bind_tokio(t.listen, &cfg, false)?;
        running
            .tcp_proxy_addrs
            .push(listener.local_addr().map_err(|source| StartError::Bind { addr: t.listen, source })?);
        proxy.shutdown().tasks.spawn(l4::run(t.clone(), listener, Arc::clone(&proxy)));
    }

    // Periodic cleanup of per-route limiters and stale pooled clients.
    let hk = Arc::clone(&proxy);
    let drain = proxy.shutdown().drain.clone();
    proxy.shutdown().tasks.spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            tokio::select! {
                () = drain.cancelled() => break,
                _ = tick.tick() => hk.housekeeping(),
            }
        }
    });

    Ok(running)
}

impl Running {
    /// Stop accepting, drain in-flight requests (up to `server.drain_timeout`),
    /// then force-close stragglers. Returns `true` if the drain was clean.
    pub async fn shutdown(self) -> bool {
        let timeout = self.proxy.state().load().config.server.drain_timeout;
        let clean = self.proxy.shutdown().graceful(timeout).await;
        if let Some(ep) = &self.endpoint {
            ep.close(quinn::VarInt::from_u32(0), b"shutdown");
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), ep.wait_idle()).await;
        }
        clean
    }
}
