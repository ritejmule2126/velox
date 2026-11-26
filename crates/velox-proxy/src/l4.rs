//! Raw TCP (L4) load balancing.

use crate::handler::Proxy;
use crate::lb::{self, PickCtx};
use crate::socket;
use crate::upstream::connect_backend;
use pin_project_lite::pin_project;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use velox_core::clock::now_ms;
use velox_core::config::TcpProxyConfig;
use velox_health::{record_outcome, Outcome};

pin_project! {
    /// Records the time of the last successful read or write.
    struct Touch<T> {
        #[pin] inner: T,
        last: Arc<AtomicU64>,
    }
}

impl<T: AsyncRead> AsyncRead for Touch<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        let r = this.inner.poll_read(cx, buf);
        if matches!(r, Poll::Ready(Ok(()))) {
            this.last.store(now_ms(), Ordering::Relaxed);
        }
        r
    }
}

impl<T: AsyncWrite> AsyncWrite for Touch<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.project();
        let r = this.inner.poll_write(cx, data);
        if matches!(r, Poll::Ready(Ok(_))) {
            this.last.store(now_ms(), Ordering::Relaxed);
        }
        r
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

/// Accept and forward connections for one `[[tcp_proxy]]`.
pub async fn run(cfg: TcpProxyConfig, listener: TcpListener, proxy: Arc<Proxy>) {
    let sd = proxy.shutdown().clone();
    loop {
        let accepted = tokio::select! {
            biased;
            () = sd.drain.cancelled() => break,
            r = listener.accept() => r,
        };
        let (client, peer) = match accepted {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, listen = %cfg.listen, "L4 accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let snap = proxy.state().load();
        let limits = &snap.config.limits;
        let Ok(permit) =
            proxy.conn_limiter().try_acquire(peer.ip(), limits.max_connections, limits.max_connections_per_ip)
        else {
            proxy.metrics().connection_rejected();
            continue;
        };
        socket::tune_accepted(&client, snap.config.server.tcp_nodelay);
        drop(snap);
        let (proxy, cfg) = (Arc::clone(&proxy), cfg.clone());
        sd.tasks.spawn(async move {
            let _permit = permit;
            forward(client, peer, &cfg, &proxy).await;
        });
    }
}

async fn forward(client: TcpStream, peer: SocketAddr, cfg: &TcpProxyConfig, proxy: &Arc<Proxy>) {
    let snap = proxy.state().load();
    let Some(group) = snap.upstreams.get(&cfg.upstream).cloned() else {
        tracing::warn!(upstream = %cfg.upstream, "L4 upstream no longer exists");
        return;
    };
    let connect_timeout = snap.config.timeouts.upstream_connect;
    let nodelay = snap.config.server.tcp_nodelay;
    drop(snap);

    let mut ctx = PickCtx { hash: lb::hash_key(&group.config.hash_on, peer.ip(), "", None), exclude: 0 };
    for _ in 0..=group.config.retries {
        let Some(idx) = lb::pick(&group, &ctx) else { break };
        ctx.exclude(idx);
        let backend = Arc::clone(&group.backends[idx]);
        let upstream = match connect_backend(&backend.addr, connect_timeout, nodelay).await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(backend = &*backend.name, error = %e, "L4 connect failed");
                if record_outcome(&group, &backend, Outcome::TransportError) {
                    proxy.metrics().backend_ejected(&group.name, &backend.name);
                }
                continue;
            }
        };
        record_outcome(&group, &backend, Outcome::Response { status: 200 });
        let _active = backend.track();
        let last = Arc::new(AtomicU64::new(now_ms()));
        let mut client = Touch { inner: client, last: Arc::clone(&last) };
        let mut upstream = Touch { inner: upstream, last: Arc::clone(&last) };
        let idle = cfg.idle_timeout;
        let idle_watch = async {
            match idle {
                None => std::future::pending::<()>().await,
                Some(limit) => loop {
                    tokio::time::sleep(limit.min(Duration::from_secs(1))).await;
                    if now_ms().saturating_sub(last.load(Ordering::Relaxed))
                        >= u64::try_from(limit.as_millis()).unwrap_or(u64::MAX)
                    {
                        break;
                    }
                },
            }
        };
        let kill = proxy.shutdown().kill.clone();
        tokio::select! {
            r = tokio::io::copy_bidirectional(&mut client, &mut upstream) => {
                if let Err(e) = r {
                    tracing::debug!(error = %e, "L4 connection ended with error");
                }
            }
            () = idle_watch => tracing::debug!("L4 connection closed after idling"),
            () = kill.cancelled() => {}
        }
        return;
    }
}
