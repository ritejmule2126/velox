//! The admin HTTP listener.

use crate::api::AdminApi;
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

/// Failures starting an admin listener.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// The address could not be bound.
    #[error("cannot bind admin address {addr}: {source}")]
    Bind {
        /// Address that failed.
        addr: SocketAddr,
        /// Underlying error.
        source: std::io::Error,
    },
    /// Refused to bind a non-loopback admin address.
    #[error("admin address {0} is not a loopback address")]
    NotLoopback(SocketAddr),
}

type Router = Arc<
    dyn Fn(
            SocketAddr,
            Request<Incoming>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response<Full<Bytes>>> + Send>>
        + Send
        + Sync,
>;

async fn run(listener: TcpListener, router: Router, cancel: CancellationToken) {
    let tracker = TaskTracker::new();
    loop {
        let (stream, peer) = tokio::select! {
            () = cancel.cancelled() => break,
            r = listener.accept() => match r {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!(error = %e, "admin accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        let router = Arc::clone(&router);
        let cancel = cancel.clone();
        tracker.spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let router = Arc::clone(&router);
                async move { Ok::<_, Infallible>(router(peer, req).await) }
            });
            let conn = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(5))
                .max_buf_size(16 * 1024)
                .serve_connection(TokioIo::new(stream), svc);
            tokio::pin!(conn);
            tokio::select! {
                _ = conn.as_mut() => {}
                () = cancel.cancelled() => {
                    conn.as_mut().graceful_shutdown();
                    let _ = tokio::time::timeout(Duration::from_secs(2), conn.as_mut()).await;
                }
            }
        });
    }
    tracker.close();
    let _ = tokio::time::timeout(Duration::from_secs(3), tracker.wait()).await;
}

/// Start the full admin API on a loopback `addr`. Returns the bound address.
pub async fn serve(
    addr: SocketAddr,
    api: Arc<AdminApi>,
    cancel: CancellationToken,
) -> Result<(SocketAddr, JoinHandle<()>), ServeError> {
    if !addr.ip().is_loopback() {
        return Err(ServeError::NotLoopback(addr));
    }
    let listener = TcpListener::bind(addr).await.map_err(|source| ServeError::Bind { addr, source })?;
    let bound = listener.local_addr().map_err(|source| ServeError::Bind { addr, source })?;
    let router: Router = Arc::new(move |peer, req| {
        let api = Arc::clone(&api);
        Box::pin(async move { api.handle(peer, req).await })
    });
    Ok((bound, tokio::spawn(run(listener, router, cancel))))
}

/// Start a listener that serves **only** `GET /metrics` (and `/healthz`),
/// which may be bound to a non-loopback address for Prometheus scraping.
pub async fn serve_metrics(
    addr: SocketAddr,
    api: Arc<AdminApi>,
    cancel: CancellationToken,
) -> Result<(SocketAddr, JoinHandle<()>), ServeError> {
    let listener = TcpListener::bind(addr).await.map_err(|source| ServeError::Bind { addr, source })?;
    let bound = listener.local_addr().map_err(|source| ServeError::Bind { addr, source })?;
    let router: Router = Arc::new(move |_peer, req| {
        let api = Arc::clone(&api);
        Box::pin(async move {
            match (req.method(), req.uri().path()) {
                (&Method::GET, "/metrics") => api.render_metrics(),
                (&Method::GET, "/healthz") => Response::new(Full::new(Bytes::from_static(b"ok\n"))),
                _ => {
                    let mut r = Response::new(Full::new(Bytes::from_static(b"not found\n")));
                    *r.status_mut() = StatusCode::NOT_FOUND;
                    r
                }
            }
        })
    });
    Ok((bound, tokio::spawn(run(listener, router, cancel))))
}
