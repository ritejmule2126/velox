//! Active health checking.
//!
//! A supervisor reconciles the set of per-backend probe tasks with the live
//! configuration every second, so added/removed backends and changed probe
//! settings take effect without a restart. Each task probes with
//! `interval ± jitter` and flips the backend's health only after
//! `unhealthy_threshold` consecutive failures or `healthy_threshold`
//! consecutive successes (hysteresis prevents flapping).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use velox_core::config::{BackendAddr, HealthConfig, HealthKind, UpstreamTlsConfig};
use velox_core::{Backend, SharedState};
use velox_security::upstream_tls::{server_name, UpstreamTlsRegistry};

/// Why a probe failed.
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    /// Connect or I/O error.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// The probe exceeded its deadline.
    #[error("probe timed out")]
    Timeout,
    /// The response was not parseable HTTP.
    #[error("malformed HTTP response")]
    Malformed,
    /// Status outside the accepted range.
    #[error("unexpected status {0}")]
    Status(u16),
    /// The TLS configuration for an `https://` backend is unusable.
    #[error("TLS configuration: {0}")]
    TlsConfig(String),
    /// The backend did not speak the expected protocol (for example it did not
    /// negotiate `h2` via ALPN).
    #[error("protocol mismatch: {0}")]
    Protocol(&'static str),
}

/// TLS settings for probing an `https://` backend.
#[derive(Debug, Clone)]
pub struct TlsProbe {
    /// The client configuration (trust roots, optional client certificate, ALPN).
    pub config: Arc<rustls::ClientConfig>,
    /// The upstream's `tls` table (for the SNI / verification name override).
    pub settings: Option<UpstreamTlsConfig>,
    /// The host name a DNS-expanded member was resolved from: the default
    /// SNI / certificate name when `settings` does not override it.
    pub sni: Option<Arc<str>>,
}

/// Supervises background probe tasks.
#[derive(Debug)]
pub struct HealthChecker {
    state: Arc<SharedState>,
    cancel: CancellationToken,
    tls: Arc<UpstreamTlsRegistry>,
}

type TaskKey = (String, String);

impl HealthChecker {
    /// Create a checker over `state`; tasks stop when `cancel` fires.
    pub fn new(state: Arc<SharedState>, cancel: CancellationToken) -> Self {
        Self { state, cancel, tls: Arc::new(UpstreamTlsRegistry::new()) }
    }

    /// Spawn the supervisor on the current runtime.
    pub fn spawn(self) -> JoinHandle<()> {
        tokio::spawn(self.supervise())
    }

    async fn supervise(self) {
        let mut tasks: HashMap<TaskKey, (std::sync::Weak<Backend>, JoinHandle<()>)> = HashMap::new();
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = self.cancel.cancelled() => break,
                _ = tick.tick() => {}
            }
            let snap = self.state.load();
            let mut live: HashMap<TaskKey, Arc<Backend>> = HashMap::new();
            for group in snap.upstreams.values() {
                if group.config.health.is_none() {
                    continue;
                }
                for b in &group.backends {
                    live.insert((group.name.to_string(), b.name.to_string()), Arc::clone(b));
                }
            }
            tasks.retain(|key, (weak, handle)| {
                let keep = live.get(key).is_some_and(|b| weak.upgrade().is_some_and(|w| Arc::ptr_eq(&w, b)));
                if !keep {
                    handle.abort();
                }
                keep && !handle.is_finished()
            });
            for (key, backend) in live {
                if tasks.contains_key(&key) {
                    continue;
                }
                let weak = Arc::downgrade(&backend);
                let handle = tokio::spawn(probe_loop(
                    Arc::clone(&self.state),
                    key.0.clone(),
                    backend,
                    self.cancel.clone(),
                    Arc::clone(&self.tls),
                ));
                tasks.insert(key, (weak, handle));
            }
        }
        for (_, (_, h)) in tasks {
            h.abort();
        }
    }
}

async fn probe_loop(
    state: Arc<SharedState>,
    upstream: String,
    backend: Arc<Backend>,
    cancel: CancellationToken,
    tls: Arc<UpstreamTlsRegistry>,
) {
    let mut ok_streak = 0u32;
    let mut fail_streak = 0u32;
    loop {
        // Re-read the settings every cycle so reloads apply immediately.
        let snap = state.load();
        let Some(group) = snap.upstreams.get(&upstream) else { return };
        let Some(cfg) = group.config.health.clone() else { return };
        if !group.backends.iter().any(|b| Arc::ptr_eq(b, &backend)) {
            return;
        }
        let tls_settings = group.config.tls.clone();
        let h2 = group.config.protocol.is_h2();
        drop(snap);

        // Resolved every cycle so rotated CA / client certificates apply.
        let tls_probe: Result<Option<TlsProbe>, ProbeError> = match &backend.addr {
            BackendAddr::Tls { .. } => tls
                .client_config(tls_settings.as_ref(), h2)
                .map(|config| Some(TlsProbe { config, settings: tls_settings, sni: backend.sni.clone() }))
                .map_err(|e| ProbeError::TlsConfig(e.to_string())),
            _ => Ok(None),
        };
        let result = match tls_probe {
            Ok(t) => probe_protocol(&backend.addr, &cfg, t.as_ref(), h2).await,
            Err(e) => Err(e),
        };
        match &result {
            Ok(()) => {
                ok_streak += 1;
                fail_streak = 0;
                if !backend.is_healthy() && ok_streak >= cfg.healthy_threshold {
                    backend.set_healthy(true);
                    // A passing active probe is stronger evidence than the
                    // failures that triggered passive ejection: end it now
                    // instead of idling recovered capacity for the full window.
                    backend.clear_ejection();
                    tracing::info!(upstream = %upstream, backend = &*backend.name, "backend is healthy again");
                }
            }
            Err(e) => {
                fail_streak += 1;
                ok_streak = 0;
                if backend.is_healthy() && fail_streak >= cfg.unhealthy_threshold {
                    backend.set_healthy(false);
                    tracing::warn!(upstream = %upstream, backend = &*backend.name, error = %e, "backend marked unhealthy");
                }
            }
        }
        let sleep = jittered(cfg.interval, cfg.jitter);
        tokio::select! {
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(sleep) => {}
        }
    }
}

/// `interval` scaled by a random factor in `[1 - jitter, 1 + jitter]`.
pub fn jittered(interval: Duration, jitter: f64) -> Duration {
    let jitter = jitter.clamp(0.0, 1.0);
    let factor = 1.0 + jitter * (fastrand::f64() * 2.0 - 1.0);
    interval.mul_f64(factor.max(0.0))
}

/// Run a single probe against a cleartext or Unix-socket `addr`.
///
/// `https://` backends need [`probe_with`] and a [`TlsProbe`].
pub async fn probe(addr: &BackendAddr, cfg: &HealthConfig) -> Result<(), ProbeError> {
    probe_with(addr, cfg, None).await
}

/// Run a single probe against `addr`, completing a TLS handshake first when
/// `addr` is `https://` (a `tcp` probe then proves the TLS service is up, not
/// merely that the port accepts connections).
pub async fn probe_with(addr: &BackendAddr, cfg: &HealthConfig, tls: Option<&TlsProbe>) -> Result<(), ProbeError> {
    probe_protocol(addr, cfg, tls, false).await
}

/// Like [`probe_with`], speaking HTTP/2 when `http2` is set: prior knowledge on
/// cleartext and Unix-socket backends (`h2c`), ALPN `h2` over TLS (which is
/// verified: a backend that negotiates anything else fails the probe). Only
/// affects `kind = "http"`; a `tcp` probe sends nothing either way.
pub async fn probe_protocol(
    addr: &BackendAddr,
    cfg: &HealthConfig,
    tls: Option<&TlsProbe>,
    http2: bool,
) -> Result<(), ProbeError> {
    tokio::time::timeout(cfg.timeout, probe_inner(addr, cfg, tls, http2)).await.map_err(|_| ProbeError::Timeout)?
}

async fn probe_inner(
    addr: &BackendAddr,
    cfg: &HealthConfig,
    tls: Option<&TlsProbe>,
    http2: bool,
) -> Result<(), ProbeError> {
    match addr {
        BackendAddr::Tcp { host, port } => {
            let stream = TcpStream::connect((BackendAddr::connect_host(host), *port)).await?;
            match cfg.kind {
                HealthKind::Tcp => Ok(()),
                HealthKind::Http if http2 => h2_probe(stream, cfg, false).await,
                HealthKind::Http => http_probe(stream, cfg).await,
            }
        }
        BackendAddr::Tls { host, port } => {
            let tls = tls.ok_or_else(|| ProbeError::TlsConfig("no TLS configuration supplied".into()))?;
            let stream = TcpStream::connect((BackendAddr::connect_host(host), *port)).await?;
            let name = server_name(tls.settings.as_ref(), tls.sni.as_deref().unwrap_or(host))
                .map_err(|e| ProbeError::TlsConfig(e.to_string()))?;
            let stream = tokio_rustls::TlsConnector::from(Arc::clone(&tls.config)).connect(name, stream).await?;
            let negotiated_h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
            match cfg.kind {
                HealthKind::Tcp => Ok(()),
                HealthKind::Http if http2 => {
                    if !negotiated_h2 {
                        return Err(ProbeError::Protocol("backend did not negotiate h2 via ALPN"));
                    }
                    h2_probe(stream, cfg, true).await
                }
                HealthKind::Http => http_probe(stream, cfg).await,
            }
        }
        BackendAddr::Unix(path) => {
            let stream = UnixStream::connect(path).await?;
            match cfg.kind {
                HealthKind::Tcp => Ok(()),
                HealthKind::Http if http2 => h2_probe(stream, cfg, false).await,
                HealthKind::Http => http_probe(stream, cfg).await,
            }
        }
    }
}

async fn http_probe<S>(mut stream: S, cfg: &HealthConfig) -> Result<(), ProbeError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: velox-health/1\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        cfg.path, cfg.host
    );
    stream.write_all(req.as_bytes()).await?;
    // Only the status line matters; never read an unbounded body.
    let mut buf = [0u8; 256];
    let mut filled = 0;
    while filled < buf.len() && !buf[..filled].contains(&b'\n') {
        let n = stream.read(&mut buf[filled..]).await?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    let line = std::str::from_utf8(&buf[..filled]).map_err(|_| ProbeError::Malformed)?;
    let status_line = line.lines().next().ok_or(ProbeError::Malformed)?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().ok_or(ProbeError::Malformed)?;
    if !version.starts_with("HTTP/1.") {
        return Err(ProbeError::Malformed);
    }
    let status: u16 = parts.next().and_then(|s| s.parse().ok()).ok_or(ProbeError::Malformed)?;
    if (cfg.status_min..=cfg.status_max).contains(&status) {
        Ok(())
    } else {
        Err(ProbeError::Status(status))
    }
}

/// One `GET` over HTTP/2. The response *body* is never read: the status alone
/// decides, and tearing the connection down resets the stream.
async fn h2_probe<S>(stream: S, cfg: &HealthConfig, tls: bool) -> Result<(), ProbeError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use hyper_util::rt::{TokioExecutor, TokioIo};
    let scheme = if tls { "https" } else { "http" };
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri(format!("{scheme}://{}{}", cfg.host, cfg.path))
        .header("user-agent", "velox-health/1")
        .header("accept", "*/*")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .map_err(|_| ProbeError::Malformed)?;
    let (mut sender, connection) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
        .await
        .map_err(|_| ProbeError::Protocol("HTTP/2 handshake failed"))?;
    // The connection task is aborted on every exit path, so a probe never leaks one.
    let driver = AbortOnDrop(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let response = sender.send_request(request).await.map_err(|_| ProbeError::Malformed)?;
    let status = response.status().as_u16();
    drop(driver);
    if (cfg.status_min..=cfg.status_max).contains(&status) {
        Ok(())
    } else {
        Err(ProbeError::Status(status))
    }
}

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU16, Ordering};
    use tokio::net::TcpListener;
    use velox_core::Config;

    /// A tiny server whose status code can be flipped at runtime.
    async fn mock(status: Arc<AtomicU16>) -> std::net::SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else { return };
                let status = status.load(Ordering::Relaxed);
                tokio::spawn(async move {
                    let mut b = [0u8; 512];
                    let _ = s.read(&mut b).await;
                    let _ = s
                        .write_all(
                            format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes(),
                        )
                        .await;
                });
            }
        });
        addr
    }

    fn cfg(addr: std::net::SocketAddr, health: &str) -> Config {
        Config::from_toml_str(&format!(
            "[server]\nhttp_addr = \"127.0.0.1:1\"\n[[upstream]]\nname = \"a\"\nbackends = [{{ addr = \"{addr}\" }}]\n[upstream.health]\n{health}"
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn http_probe_accepts_and_rejects_by_status() {
        let status = Arc::new(AtomicU16::new(200));
        let addr = mock(Arc::clone(&status)).await;
        let a = BackendAddr::Tcp { host: "127.0.0.1".into(), port: addr.port() };
        let c = HealthConfig { path: "/h".into(), ..HealthConfig::default() };
        assert!(probe(&a, &c).await.is_ok());
        status.store(503, Ordering::Relaxed);
        assert!(matches!(probe(&a, &c).await, Err(ProbeError::Status(503))));
    }

    #[tokio::test]
    async fn tcp_probe_and_dead_port() {
        let status = Arc::new(AtomicU16::new(500));
        let addr = mock(status).await;
        let a = BackendAddr::Tcp { host: "127.0.0.1".into(), port: addr.port() };
        let tcp = HealthConfig { kind: HealthKind::Tcp, ..HealthConfig::default() };
        assert!(probe(&a, &tcp).await.is_ok(), "tcp probe ignores HTTP status");
        let dead = BackendAddr::Tcp { host: "127.0.0.1".into(), port: 1 };
        assert!(probe(&dead, &tcp).await.is_err());
    }

    #[tokio::test]
    async fn hung_backend_times_out() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _held = l.accept().await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let a = BackendAddr::Tcp { host: "127.0.0.1".into(), port };
        let c = HealthConfig { timeout: Duration::from_millis(100), ..HealthConfig::default() };
        assert!(matches!(probe(&a, &c).await, Err(ProbeError::Timeout)));
    }

    #[test]
    fn jitter_stays_within_bounds() {
        for _ in 0..1000 {
            let d = jittered(Duration::from_secs(10), 0.2);
            assert!(d >= Duration::from_secs(8) && d <= Duration::from_secs(12), "{d:?}");
        }
        assert_eq!(jittered(Duration::from_secs(5), 0.0), Duration::from_secs(5));
    }

    #[tokio::test]
    async fn checker_marks_down_then_recovers_with_hysteresis() {
        let status = Arc::new(AtomicU16::new(200));
        let addr = mock(Arc::clone(&status)).await;
        let state = SharedState::new(cfg(
            addr,
            "interval = \"50ms\"\ntimeout = \"200ms\"\njitter = 0.0\nhealthy_threshold = 2\nunhealthy_threshold = 2\npath = \"/h\"\n",
        ))
        .unwrap();
        let cancel = CancellationToken::new();
        let handle = HealthChecker::new(Arc::clone(&state), cancel.clone()).spawn();
        let backend = Arc::clone(&state.load().upstreams["a"].backends[0]);

        status.store(503, Ordering::Relaxed);
        wait_until(|| !backend.is_healthy()).await;
        status.store(200, Ordering::Relaxed);
        wait_until(|| backend.is_healthy()).await;

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn recovery_clears_passive_ejection() {
        let status = Arc::new(AtomicU16::new(200));
        let addr = mock(Arc::clone(&status)).await;
        let state = SharedState::new(cfg(
            addr,
            "interval = \"50ms\"\ntimeout = \"200ms\"\njitter = 0.0\nhealthy_threshold = 1\nunhealthy_threshold = 1\n",
        ))
        .unwrap();
        let backend = Arc::clone(&state.load().upstreams["a"].backends[0]);
        // Failed health (e.g. while down) *and* passively ejected for a long time.
        backend.set_healthy(false);
        backend.eject_until(velox_core::clock::now_ms() + 600_000);
        let cancel = CancellationToken::new();
        let handle = HealthChecker::new(Arc::clone(&state), cancel.clone()).spawn();
        wait_until(|| backend.is_available()).await;
        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn checker_follows_config_reloads() {
        let status = Arc::new(AtomicU16::new(503));
        let addr = mock(Arc::clone(&status)).await;
        let fast =
            "interval = \"50ms\"\ntimeout = \"200ms\"\njitter = 0.0\nunhealthy_threshold = 1\nhealthy_threshold = 1\n";
        let state = SharedState::new(cfg(addr, fast)).unwrap();
        let cancel = CancellationToken::new();
        let handle = HealthChecker::new(Arc::clone(&state), cancel.clone()).spawn();
        let backend = Arc::clone(&state.load().upstreams["a"].backends[0]);
        wait_until(|| !backend.is_healthy()).await;

        // Reload with the same backend: identity (and its state) is preserved
        // and probing continues against it.
        state.apply(cfg(addr, fast)).unwrap();
        status.store(200, Ordering::Relaxed);
        wait_until(|| backend.is_healthy()).await;

        // Removing health checks stops probing: a manual flip is not undone.
        let mut no_health = (*state.load().config).clone();
        no_health.upstreams[0].health = None;
        state.apply(no_health).unwrap();
        tokio::time::sleep(Duration::from_millis(700)).await;
        backend.set_healthy(false);
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(!backend.is_healthy());

        cancel.cancel();
        handle.await.unwrap();
    }

    async fn wait_until(mut f: impl FnMut() -> bool) {
        for _ in 0..200 {
            if f() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("condition not reached in time");
    }

    // ---- HTTP/2 probes ----

    /// An `h2c` (prior knowledge) server answering with `status`; counts requests.
    async fn h2c_mock(status: Arc<AtomicU16>) -> (std::net::SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        use hyper_util::rt::{TokioExecutor, TokioIo};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let h = Arc::clone(&hits);
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = listener.accept().await else { return };
                let (status, hits) = (Arc::clone(&status), Arc::clone(&h));
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req: http::Request<hyper::body::Incoming>| {
                        let (status, hits) = (Arc::clone(&status), Arc::clone(&hits));
                        async move {
                            hits.fetch_add(1, Ordering::SeqCst);
                            assert_eq!(req.version(), http::Version::HTTP_2);
                            assert_eq!(req.uri().path(), "/h2health");
                            let mut r =
                                http::Response::new(http_body_util::Full::new(bytes::Bytes::from_static(b"ok")));
                            *r.status_mut() = http::StatusCode::from_u16(status.load(Ordering::Relaxed)).unwrap();
                            Ok::<_, std::convert::Infallible>(r)
                        }
                    });
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(s), svc)
                        .await;
                });
            }
        });
        (addr, hits)
    }

    fn h2_cfg() -> HealthConfig {
        HealthConfig {
            path: "/h2health".into(),
            host: "svc.test".into(),
            timeout: Duration::from_secs(2),
            ..HealthConfig::default()
        }
    }

    #[tokio::test]
    async fn h2c_probe_checks_the_status_of_a_real_http2_request() {
        let status = Arc::new(AtomicU16::new(200));
        let (addr, hits) = h2c_mock(Arc::clone(&status)).await;
        let a = BackendAddr::Tcp { host: "127.0.0.1".into(), port: addr.port() };
        assert!(probe_protocol(&a, &h2_cfg(), None, true).await.is_ok());
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        status.store(503, Ordering::Relaxed);
        assert!(matches!(probe_protocol(&a, &h2_cfg(), None, true).await, Err(ProbeError::Status(503))));
        status.store(302, Ordering::Relaxed);
        assert!(probe_protocol(&a, &h2_cfg(), None, true).await.is_ok(), "status_min..=status_max applies");
        // A TCP probe against the same backend still just connects.
        let tcp = HealthConfig { kind: HealthKind::Tcp, ..h2_cfg() };
        assert!(probe_protocol(&a, &tcp, None, true).await.is_ok());
        // Many probes do not leak connections or tasks: the server sees them all close.
        for _ in 0..20 {
            let _ = probe_protocol(&a, &h2_cfg(), None, true).await;
        }
        assert_eq!(hits.load(Ordering::SeqCst), 23);
    }

    #[tokio::test]
    async fn protocol_mismatches_fail_the_probe_instead_of_passing_it() {
        // An HTTP/1.1-only backend cannot answer an h2 probe…
        let status = Arc::new(AtomicU16::new(200));
        let h1 = mock(Arc::clone(&status)).await;
        let a1 = BackendAddr::Tcp { host: "127.0.0.1".into(), port: h1.port() };
        let c = HealthConfig { timeout: Duration::from_millis(800), ..h2_cfg() };
        assert!(probe_protocol(&a1, &c, None, true).await.is_err(), "h1 server must not look healthy to an h2 probe");
        // …and an h2c-only backend cannot answer an HTTP/1 probe.
        let (h2, _) = h2c_mock(Arc::clone(&status)).await;
        let a2 = BackendAddr::Tcp { host: "127.0.0.1".into(), port: h2.port() };
        assert!(probe_protocol(&a2, &c, None, false).await.is_err());
    }

    #[tokio::test]
    async fn h2_probe_over_tls_requires_alpn_h2() {
        use rustls::pki_types::pem::PemObject;
        use velox_security::upstream_tls::UpstreamTlsRegistry;
        let dir = tempfile::tempdir().unwrap();
        let g = rcgen::generate_simple_self_signed(vec!["localhost".to_owned(), "127.0.0.1".to_owned()]).unwrap();
        let (cert_path, key_path) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
        std::fs::write(&cert_path, g.cert.pem()).unwrap();
        std::fs::write(&key_path, g.key_pair.serialize_pem()).unwrap();

        // A TLS server whose ALPN list is chosen per test.
        let serve = |alpn: Vec<Vec<u8>>| {
            let chain = vec![g.cert.der().clone()];
            let key = rustls::pki_types::PrivateKeyDer::from_pem_file(&key_path).unwrap();
            async move {
                let mut cfg =
                    rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                        .with_safe_default_protocol_versions()
                        .unwrap()
                        .with_no_client_auth()
                        .with_single_cert(chain, key)
                        .unwrap();
                cfg.alpn_protocols = alpn;
                let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                tokio::spawn(async move {
                    use hyper_util::rt::{TokioExecutor, TokioIo};
                    loop {
                        let Ok((s, _)) = listener.accept().await else { return };
                        let acceptor = acceptor.clone();
                        tokio::spawn(async move {
                            let Ok(tls) = acceptor.accept(s).await else { return };
                            let svc = hyper::service::service_fn(|_req: http::Request<hyper::body::Incoming>| async {
                                Ok::<_, std::convert::Infallible>(http::Response::new(http_body_util::Full::new(
                                    bytes::Bytes::from_static(b"ok"),
                                )))
                            });
                            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                                .serve_connection(TokioIo::new(tls), svc)
                                .await;
                        });
                    }
                });
                addr
            }
        };
        let settings = velox_core::config::UpstreamTlsConfig { ca_file: Some(cert_path.clone()), ..Default::default() };
        let registry = UpstreamTlsRegistry::new();
        let probe_tls = |h2: bool| TlsProbe {
            config: registry.client_config(Some(&settings), h2).unwrap(),
            settings: Some(settings.clone()),
            sni: None,
        };

        // Backend that really speaks h2 over TLS: healthy.
        let good = serve(vec![b"h2".to_vec()]).await;
        let a = BackendAddr::Tls { host: "127.0.0.1".into(), port: good.port() };
        assert!(probe_protocol(&a, &h2_cfg(), Some(&probe_tls(true)), true).await.is_ok());

        // A backend that negotiates something else is reported as a protocol
        // mismatch, not silently probed with the wrong protocol.
        let h1_only = serve(vec![b"http/1.1".to_vec()]).await;
        let a = BackendAddr::Tls { host: "127.0.0.1".into(), port: h1_only.port() };
        // (offer h2 so the handshake completes, the server picks nothing in common → no ALPN)
        let err = probe_protocol(&a, &h2_cfg(), Some(&probe_tls(true)), true).await.unwrap_err();
        assert!(matches!(err, ProbeError::Protocol(_) | ProbeError::Io(_)), "{err}");
        // A tcp probe on the same TLS service only needs the handshake to work
        // for the ALPN set it offers.
        let tcp = HealthConfig { kind: HealthKind::Tcp, ..h2_cfg() };
        assert!(probe_protocol(
            &BackendAddr::Tls { host: "127.0.0.1".into(), port: good.port() },
            &tcp,
            Some(&probe_tls(true)),
            true
        )
        .await
        .is_ok());
    }
}
