//! The protocol-independent request pipeline.
//!
//! HTTP/1.1, HTTP/2 and HTTP/3 front-ends all normalise their requests into
//! `Request<ProxyBody>` and call [`Proxy::handle`]. Every failure is a
//! [`ProxyError`] mapped to a clean 4xx/5xx; nothing on this path unwraps.

use crate::body::{BodyFault, Fault, IdleBody, KeepAlive, LimitBody};
use crate::error::{empty, full, simple_response, ProxyBody, ProxyError};
use crate::io::{Activity, REJECT_PATH};
use crate::lb::{self, PickCtx};
use crate::shutdown::Shutdown;
use crate::upstream::UpstreamClients;
use arc_swap::ArcSwap;
use bytes::Bytes;
use http::header::{ALT_SVC, CONNECTION, CONTENT_LENGTH, HOST, LOCATION, UPGRADE};
use http::uri::PathAndQuery;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri, Version};
use http_body::Body;
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::Instrument;
use velox_core::config::{Algorithm, Config};
use velox_core::sanitize::{
    apply_forwarded_headers, host_without_port, is_websocket_upgrade, request_id_from, resolve_client_ip,
    strip_hop_by_hop, validate_request_headers, Violation, X_REQUEST_ID,
};
use velox_core::Snapshot;
use velox_health::{record_outcome, Outcome};
use velox_security::ratelimit::{rate_key, Decision, RateLimiters};
use velox_security::{ChallengeStore, ConnectionLimiter, ResponsePolicy};
use velox_telemetry::{Metrics, Protocol};

/// Facts about the client connection a request arrived on.
#[derive(Debug, Clone, Copy)]
pub struct ConnMeta {
    /// Remote socket address.
    pub peer: SocketAddr,
    /// Client-facing protocol.
    pub protocol: Protocol,
    /// Whether the connection is TLS/QUIC protected.
    pub tls: bool,
}

#[derive(Debug)]
struct Derived {
    response: ResponsePolicy,
    alt_svc: Option<HeaderValue>,
    https_port: Option<u16>,
}

impl Derived {
    /// `bound_*` are the ports actually bound (they differ from the config
    /// when it asks for port 0).
    fn build(cfg: &Config, bound_https: u16, bound_h3: u16) -> Self {
        let pick = |bound: u16, configured: Option<u16>| if bound != 0 { Some(bound) } else { configured };
        let https_port = pick(bound_https, cfg.server.https_addr.map(|a| a.port()));
        let h3_port = pick(bound_h3, cfg.server.h3_addr.or(cfg.server.https_addr).map(|a| a.port()));
        let alt_svc = (cfg.server.h3 && cfg.server.https_addr.is_some())
            .then_some(h3_port)
            .flatten()
            .and_then(|p| HeaderValue::from_str(&format!("h3=\":{p}\"; ma={}", cfg.server.alt_svc_max_age)).ok());
        Self { response: ResponsePolicy::from_config(cfg), alt_svc, https_port }
    }
}

/// Per-request facts collected for logs.
#[derive(Debug, Default)]
struct Trace {
    route: Option<Arc<str>>,
    upstream: Option<Arc<str>>,
    backend: Option<Arc<str>>,
    client_ip: Option<IpAddr>,
    error: Option<String>,
}

enum ReqBody {
    Replay(Bytes),
    Stream(Option<ProxyBody>),
}

/// The shared proxy engine.
pub struct Proxy {
    state: Arc<velox_core::SharedState>,
    metrics: Arc<Metrics>,
    limiters: RateLimiters,
    conn_limiter: Arc<ConnectionLimiter>,
    challenges: Arc<ChallengeStore>,
    clients: UpstreamClients,
    derived: ArcSwap<(u64, Arc<Derived>)>,
    bound_https: AtomicU16,
    bound_h3: AtomicU16,
    shutdown: Shutdown,
}

impl std::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proxy").finish_non_exhaustive()
    }
}

fn is_idempotent(m: &Method) -> bool {
    matches!(*m, Method::GET | Method::HEAD | Method::OPTIONS | Method::PUT | Method::DELETE | Method::TRACE)
}

fn content_length(h: &HeaderMap) -> Option<u64> {
    h.get(CONTENT_LENGTH)?.to_str().ok()?.parse().ok()
}

impl Proxy {
    /// Build the engine around shared state.
    pub fn new(
        state: Arc<velox_core::SharedState>,
        metrics: Arc<Metrics>,
        challenges: Arc<ChallengeStore>,
        shutdown: Shutdown,
    ) -> Arc<Self> {
        let derived = Arc::new(Derived::build(&state.load().config, 0, 0));
        let generation = state.load().generation;
        Arc::new(Self {
            state,
            metrics,
            limiters: RateLimiters::new(),
            conn_limiter: ConnectionLimiter::new(),
            challenges,
            clients: UpstreamClients::default(),
            derived: ArcSwap::from_pointee((generation, derived)),
            bound_https: AtomicU16::new(0),
            bound_h3: AtomicU16::new(0),
            shutdown,
        })
    }

    /// Record the ports actually bound (used for `Alt-Svc` and redirects).
    pub fn set_bound_ports(&self, https: Option<u16>, h3: Option<u16>) {
        if let Some(p) = https {
            self.bound_https.store(p, Ordering::Relaxed);
        }
        if let Some(p) = h3 {
            self.bound_h3.store(p, Ordering::Relaxed);
        }
        // Force the derived values to be rebuilt on the next request.
        let cur = self.derived.load();
        self.derived.store(Arc::new((0, Arc::clone(&cur.1))));
    }

    /// The live configuration state.
    pub fn state(&self) -> &Arc<velox_core::SharedState> {
        &self.state
    }

    /// The metrics registry.
    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// The connection limiter shared by all listeners.
    pub fn conn_limiter(&self) -> &Arc<ConnectionLimiter> {
        &self.conn_limiter
    }

    /// The shutdown handle.
    pub fn shutdown(&self) -> &Shutdown {
        &self.shutdown
    }

    /// Drop per-route limiters and pooled clients that no longer apply.
    pub fn housekeeping(&self) {
        let snap = self.state.load();
        self.limiters.retain_routes(
            (0..snap.config.routes.len())
                .map(|i| snap.config.route_id(i))
                .collect::<Vec<_>>()
                .iter()
                .map(String::as_str),
        );
        self.clients.retain(snap.upstreams.keys().map(String::as_str));
    }

    fn derived(&self, snap: &Snapshot) -> Arc<Derived> {
        let cur = self.derived.load();
        if cur.0 == snap.generation {
            return Arc::clone(&cur.1);
        }
        let d = Arc::new(Derived::build(
            &snap.config,
            self.bound_https.load(Ordering::Relaxed),
            self.bound_h3.load(Ordering::Relaxed),
        ));
        self.derived.store(Arc::new((snap.generation, Arc::clone(&d))));
        d
    }

    /// Serve one request. Always returns a response.
    pub async fn handle(
        &self,
        req: Request<ProxyBody>,
        conn: ConnMeta,
        activity: Option<&Arc<Activity>>,
    ) -> Response<ProxyBody> {
        let started = Instant::now();
        let inflight = activity.map(Activity::begin);
        let snap = self.state.load();
        let derived = self.derived(&snap);
        let request_id = request_id_from(req.headers());
        let method = req.method().clone();
        let uri = req.uri().clone();
        let mut trace = Trace::default();

        let span = tracing::info_span!("request", request_id = %request_id);
        let result = self.handle_inner(&snap, &derived, req, conn, &request_id, &mut trace).instrument(span).await;
        let mut resp = match result {
            Ok(r) => r,
            Err(e) => {
                if e.status().is_server_error() {
                    tracing::warn!(request_id = %request_id, error = %e, "request failed");
                }
                trace.error = Some(e.to_string());
                e.into_response()
            }
        };

        let headers = resp.headers_mut();
        if let Ok(v) = HeaderValue::from_str(&request_id) {
            headers.insert(X_REQUEST_ID, v);
        }
        derived.response.apply(headers, conn.tls);
        if conn.tls && conn.protocol != Protocol::H3 {
            if let Some(alt) = &derived.alt_svc {
                headers.entry(ALT_SVC).or_insert_with(|| alt.clone());
            }
        }
        let elapsed = started.elapsed();
        let status = resp.status().as_u16();
        self.metrics.observe_request(conn.protocol, status, elapsed.as_secs_f64());
        if snap.config.telemetry.access_log {
            tracing::info!(
                target: "velox::access",
                request_id = %request_id,
                method = %method,
                host = uri.authority().map(http::uri::Authority::as_str),
                path = uri.path(),
                status,
                duration_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
                protocol = conn.protocol.as_str(),
                client_ip = %trace.client_ip.unwrap_or_else(|| conn.peer.ip()),
                route = trace.route.as_deref(),
                upstream = trace.upstream.as_deref(),
                backend = trace.backend.as_deref(),
                error = trace.error.as_deref(),
                "request"
            );
        }
        match inflight {
            Some(g) => resp.map(|b| KeepAlive::new(b, g).boxed_unsync()),
            None => resp,
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn handle_inner(
        &self,
        snap: &Arc<Snapshot>,
        derived: &Derived,
        mut req: Request<ProxyBody>,
        conn: ConnMeta,
        request_id: &str,
        trace: &mut Trace,
    ) -> Result<Response<ProxyBody>, ProxyError> {
        let cfg = &snap.config;

        // ---- strict validation (defence in depth; wire-level checks ran earlier) ----
        if let Some(slug) = req.uri().path().strip_prefix(REJECT_PATH) {
            let v = Violation::from_slug(slug).unwrap_or(Violation::Malformed);
            self.metrics.rejected(v.slug());
            return Err(v.into());
        }
        if let Err(v) = validate_request_headers(req.version(), req.headers(), req.uri()) {
            self.metrics.rejected(v.slug());
            return Err(v.into());
        }
        if req.headers().len() > cfg.limits.max_headers {
            self.metrics.rejected(Violation::TooManyHeaders.slug());
            return Err(Violation::TooManyHeaders.into());
        }

        let authority: String = match (req.uri().authority(), req.headers().get(HOST)) {
            (Some(a), _) => a.as_str().to_owned(),
            (None, Some(h)) => h.to_str().map_err(|_| Violation::Host)?.to_owned(),
            (None, None) => String::new(), // HTTP/1.0 without Host
        };
        let host = host_without_port(&authority).to_owned();

        // ---- ACME HTTP-01 on the plain listener ----
        if !conn.tls {
            if let Some(body) = self.challenges.respond(req.uri().path()) {
                let mut r = simple_response(StatusCode::OK, body.trim_end());
                *r.body_mut() = full(Bytes::from(body));
                return Ok(r);
            }
        }

        // ---- route ----
        let route = Arc::clone(snap.router.find(&host, req.uri().path()).ok_or(ProxyError::NoRoute)?);
        trace.route = Some(Arc::clone(&route.id));
        trace.upstream = Some(Arc::clone(&route.upstream.name));
        let group = Arc::clone(&route.upstream);

        if route.redirect_https && !conn.tls {
            return Ok(redirect_to_https(&host, derived.https_port, req.uri()));
        }

        // ---- client identity + rate limit ----
        let client_ip = resolve_client_ip(req.headers(), conn.peer.ip(), &cfg.security.trusted_proxies);
        trace.client_ip = Some(client_ip);
        if let Some(policy) = &route.rate_limit {
            let limiter = self.limiters.get(&route.id, policy);
            let key = rate_key(&limiter, &policy.key, req.headers(), client_ip);
            if let Decision::Limited { retry_after } = limiter.check(key) {
                self.metrics.rate_limited(&route.id);
                return Err(ProxyError::RateLimited { retry_after });
            }
        }

        // ---- body limits ----
        let max_body = cfg.limits.max_request_body_bytes;
        if max_body > 0 && content_length(req.headers()).is_some_and(|n| n > max_body) {
            return Err(ProxyError::BodyTooLarge);
        }
        let ws = req.version() == Version::HTTP_11 && is_websocket_upgrade(req.headers());
        let client_upgrade = ws.then(|| hyper::upgrade::on(&mut req));
        let ws_proto = ws.then(|| req.headers().get(UPGRADE).cloned()).flatten();
        let (mut parts, body) = req.into_parts();

        let fault = BodyFault::new();
        let known_empty = body.is_end_stream() || body.size_hint().exact() == Some(0);
        let limited: ProxyBody = if known_empty {
            body
        } else {
            let body =
                if max_body > 0 { LimitBody::new(body, max_body, Arc::clone(&fault)).boxed_unsync() } else { body };
            IdleBody::new(body, cfg.timeouts.request_body_idle, Some(Arc::clone(&fault))).boxed_unsync()
        };
        let fault_to_error = |fault: &BodyFault| match fault.get() {
            Some(Fault::TooLarge) => ProxyError::BodyTooLarge,
            Some(Fault::IdleTimeout) => ProxyError::ClientTimeout,
            _ => ProxyError::Rejected(Violation::Malformed),
        };
        let retries = group.config.retries;
        let size = limited.size_hint().exact();
        let mut req_body = if known_empty {
            ReqBody::Replay(Bytes::new())
        } else if retries > 0 && size.is_some_and(|n| n <= cfg.limits.retry_body_buffer_bytes) {
            match limited.collect().await {
                Ok(c) => ReqBody::Replay(c.to_bytes()),
                Err(_) => return Err(fault_to_error(&fault)),
            }
        } else {
            ReqBody::Stream(Some(limited))
        };
        let replayable = matches!(req_body, ReqBody::Replay(_));

        // ---- forwarded headers ----
        let mut headers = std::mem::take(&mut parts.headers);
        strip_hop_by_hop(&mut headers);
        if ws {
            headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
            if let Some(u) = ws_proto {
                headers.insert(UPGRADE, u);
            }
        }
        let scheme = if conn.tls { "https" } else { "http" };
        apply_forwarded_headers(
            &mut headers,
            conn.peer.ip(),
            &cfg.security.trusted_proxies,
            scheme,
            (!authority.is_empty()).then_some(authority.as_str()),
        );
        for (k, v) in &route.request_headers {
            headers.insert(k.clone(), v.clone());
        }
        if let Ok(v) = HeaderValue::from_str(request_id) {
            headers.insert(X_REQUEST_ID, v);
        }
        if !headers.contains_key(HOST) && !authority.is_empty() {
            if let Ok(v) = HeaderValue::from_str(&authority) {
                headers.insert(HOST, v);
            }
        }

        // ---- upstream target ----
        let path = parts.uri.path();
        let new_path = route.rewrite_path(path);
        let path_and_query: PathAndQuery = if new_path.len() == path.len() {
            parts.uri.path_and_query().cloned().unwrap_or_else(|| PathAndQuery::from_static("/"))
        } else {
            let pq = match parts.uri.query() {
                Some(q) => format!("{new_path}?{q}"),
                None => new_path.to_owned(),
            };
            pq.parse().map_err(|_| ProxyError::Internal("bad rewritten path".into()))?
        };
        let hash = if group.config.algorithm == Algorithm::ConsistentHash {
            let header = match &group.config.hash_on {
                velox_core::config::HashOn::Header(name) => headers.get(name.as_str()).map(HeaderValue::as_bytes),
                _ => None,
            };
            lb::hash_key(&group.config.hash_on, client_ip, parts.uri.path(), header)
        } else {
            0
        };

        // ---- attempt loop (failover across backends) ----
        let max_attempts = 1 + if replayable { retries } else { 0 };
        let idempotent = is_idempotent(&parts.method);
        let client = self.clients.get(&group, cfg.timeouts.upstream_connect, cfg.server.tcp_nodelay);
        let response_timeout = route.timeout.unwrap_or(cfg.timeouts.upstream_response);
        let mut ctx = PickCtx { hash, exclude: 0 };
        let mut last_err: Option<ProxyError> = None;
        for attempt in 0..max_attempts {
            let Some(idx) = lb::pick(&group, &ctx) else { break };
            ctx.exclude(idx);
            let backend = Arc::clone(&group.backends[idx]);
            trace.backend = Some(Arc::clone(&backend.name));
            let active = backend.track();

            let body = match &mut req_body {
                ReqBody::Replay(b) => full(b.clone()),
                ReqBody::Stream(slot) => slot.take().unwrap_or_else(empty),
            };
            let uri = Uri::builder()
                .scheme("http")
                .authority(backend.authority.clone())
                .path_and_query(path_and_query.clone())
                .build()
                .map_err(|e| ProxyError::Internal(e.to_string()))?;
            let mut ureq = Request::new(body);
            *ureq.method_mut() = parts.method.clone();
            *ureq.uri_mut() = uri;
            *ureq.version_mut() = Version::HTTP_11;
            *ureq.headers_mut() =
                if attempt + 1 == max_attempts { std::mem::take(&mut headers) } else { headers.clone() };

            let t0 = Instant::now();
            let result = tokio::time::timeout(response_timeout, client.request(ureq)).await;
            let secs = t0.elapsed().as_secs_f64();
            let (err, connect_failed) = match result {
                Ok(Ok(resp)) => {
                    let status = resp.status().as_u16();
                    self.metrics.observe_upstream(&group.name, Some(status), secs);
                    if record_outcome(&group, &backend, Outcome::Response { status }) {
                        self.metrics.backend_ejected(&group.name, &backend.name);
                    }
                    return self.finish_response(resp, active, ws, client_upgrade, cfg);
                }
                Ok(Err(e)) => {
                    if matches!(fault.get(), Some(Fault::TooLarge | Fault::IdleTimeout | Fault::ClientRead)) {
                        // The *client* failed; the backend is blameless.
                        return Err(fault_to_error(&fault));
                    }
                    (ProxyError::UpstreamConnect(e.to_string()), e.is_connect())
                }
                Err(_) => (ProxyError::UpstreamTimeout, false),
            };
            self.metrics.observe_upstream(&group.name, None, secs);
            if record_outcome(&group, &backend, Outcome::TransportError) {
                self.metrics.backend_ejected(&group.name, &backend.name);
            }
            last_err = Some(err);
            drop(active);
            if !(connect_failed || idempotent) {
                break;
            }
        }
        Err(last_err.unwrap_or(ProxyError::NoHealthyUpstream))
    }

    fn finish_response(
        &self,
        mut resp: Response<hyper::body::Incoming>,
        active: velox_core::upstream::ActiveGuard,
        ws: bool,
        client_upgrade: Option<hyper::upgrade::OnUpgrade>,
        cfg: &Config,
    ) -> Result<Response<ProxyBody>, ProxyError> {
        if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            let accepted = ws
                && resp
                    .headers()
                    .get(UPGRADE)
                    .is_some_and(|v| v.as_bytes().trim_ascii().eq_ignore_ascii_case(b"websocket"));
            let Some(client_upgrade) = client_upgrade.filter(|_| accepted) else {
                return Err(ProxyError::BadGateway("unexpected 101 Switching Protocols".into()));
            };
            let upstream_upgrade = hyper::upgrade::on(&mut resp);
            let (mut parts, _) = resp.into_parts();
            parts.headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
            let kill = self.shutdown.kill.clone();
            self.shutdown.tasks.spawn(async move {
                let _active = active;
                let (client_io, upstream_io) = match tokio::try_join!(client_upgrade, upstream_upgrade) {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::debug!(error = %e, "websocket upgrade did not complete");
                        return;
                    }
                };
                let mut client_io = TokioIo::new(client_io);
                let mut upstream_io = TokioIo::new(upstream_io);
                tokio::select! {
                    r = tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io) => {
                        if let Err(e) = r {
                            tracing::debug!(error = %e, "websocket tunnel closed with error");
                        }
                    }
                    () = kill.cancelled() => {}
                }
            });
            return Ok(Response::from_parts(parts, empty()));
        }

        let (mut parts, body) = resp.into_parts();
        strip_hop_by_hop(&mut parts.headers);
        if ws {
            // The upgrade was declined: the guard stopped inspecting this
            // connection, so it must not be reused for further requests.
            parts.headers.insert(CONNECTION, HeaderValue::from_static("close"));
        }
        let body = IdleBody::new(body, cfg.timeouts.upstream_body_idle, None).boxed_unsync();
        Ok(Response::from_parts(parts, KeepAlive::new(body, active).boxed_unsync()))
    }
}

fn redirect_to_https(host: &str, https_port: Option<u16>, uri: &Uri) -> Response<ProxyBody> {
    let host = if host.contains(':') { format!("[{host}]") } else { host.to_owned() };
    let port = match https_port {
        Some(p) if p != 443 => format!(":{p}"),
        _ => String::new(),
    };
    let pq = uri.path_and_query().map_or("/", PathAndQuery::as_str);
    let mut resp = simple_response(StatusCode::PERMANENT_REDIRECT, "redirecting to https");
    if let Ok(v) = HeaderValue::from_str(&format!("https://{host}{port}{pq}")) {
        resp.headers_mut().insert(LOCATION, v);
    }
    resp
}
