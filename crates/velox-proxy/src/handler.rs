//! The protocol-independent request pipeline.
//!
//! HTTP/1.1, HTTP/2 and HTTP/3 front-ends all normalise their requests into
//! `Request<ProxyBody>` and call [`Proxy::handle`]. Every failure is a
//! [`ProxyError`] mapped to a clean 4xx/5xx; nothing on this path unwraps.

use crate::body::{BodyFault, Fault, IdleBody, LimitBody};
use crate::cache::{self, Cache, FillTicket, KeyMeta, Offer, RequestMode};
use crate::compress;
use crate::error::{full, simple_response, ProxyBody, ProxyError};
use crate::io::{Activity, InflightGuard, REJECT_PATH};
use crate::lb::{self, PickCtx};
use crate::shutdown::Shutdown;
use crate::upstream::UpstreamClients;
use arc_swap::ArcSwap;
use bytes::Bytes;
use http::header::{ACCEPT_ENCODING, ALT_SVC, CONNECTION, CONTENT_LENGTH, HOST, LOCATION, UPGRADE};
use http::uri::{PathAndQuery, Scheme};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri, Version};
use http_body::Body;
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use tracing::Instrument;
use velox_core::cache_admin::{CacheAdmin, CacheStats, PurgeRequest};
use velox_core::config::{Algorithm, CacheConfig, CompressionConfig, Config};
use velox_core::cors::{self, CorsPolicy};
use velox_core::router::Route;
use velox_core::sanitize::{
    apply_forwarded_headers_hv, host_without_port, is_https_via_trusted_proxy, is_websocket_upgrade, request_id_from,
    resolve_client_ip, strip_hop_by_hop, validate_request_headers, Violation, X_REQUEST_ID,
};
use velox_core::trace::{self, TraceParent};
use velox_core::upstream::ActiveGuard;
use velox_core::{Snapshot, UpstreamGroup};
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

/// Per-request facts collected for logs (borrowed from the snapshot, so
/// recording them costs nothing).
#[derive(Debug, Default)]
struct Trace<'s> {
    route: Option<&'s str>,
    upstream: Option<&'s str>,
    backend: Option<&'s str>,
    client_ip: Option<IpAddr>,
    error: Option<String>,
    /// The trace context sent upstream (when `telemetry.traceparent` is on).
    trace: Option<TraceParent>,
    /// The route's CORS policy and the request's `Origin`, applied to the
    /// response — including Velox's own error responses.
    cors: Option<(&'s CorsPolicy, Option<HeaderValue>)>,
}

/// What response compression needs to know about the request.
struct CompressCtx<'a> {
    cfg: &'a CompressionConfig,
    accept: Option<HeaderValue>,
    head: bool,
}

/// Per-request context `finish_response` needs from the request side.
struct ResponseCtx<'a> {
    /// The request was a WebSocket upgrade.
    ws: bool,
    client_upgrade: Option<hyper::upgrade::OnUpgrade>,
    compress: Option<CompressCtx<'a>>,
    cache: CacheCtx,
}

/// What the response cache wants done with this request's response.
#[derive(Default)]
struct CacheCtx {
    /// Value for `X-Velox-Cache` (`miss`, `bypass`), if the route caches.
    tag: Option<&'static str>,
    /// Offer the response for storage.
    fill: Option<FillTicket>,
    /// A successful unsafe request invalidates this URL.
    invalidate: Option<(Arc<Cache>, Arc<str>)>,
}

/// The request's `Accept-Encoding` as one value (several header lines are joined).
fn accept_encoding(h: &HeaderMap) -> Option<HeaderValue> {
    let mut lines = h.get_all(ACCEPT_ENCODING).iter();
    let first = lines.next()?;
    let Some(second) = lines.next() else { return Some(first.clone()) };
    let mut joined = Vec::from(first.as_bytes());
    for v in std::iter::once(second).chain(lines) {
        joined.extend_from_slice(b", ");
        joined.extend_from_slice(v.as_bytes());
    }
    HeaderValue::from_bytes(&joined).ok()
}

enum ReqBody {
    /// Fully buffered: can be sent again on another backend.
    Replay(Bytes),
    /// Streams once.
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
    compressor: Arc<compress::Compressor>,
    cache: OnceLock<Arc<Cache>>,
    derived: ArcSwap<(u64, Arc<Derived>)>,
    bound_https: AtomicU16,
    bound_h3: AtomicU16,
    shutdown: Shutdown,
}

impl CacheAdmin for Proxy {
    fn purge(&self, request: &PurgeRequest) -> usize {
        let Some(cache) = self.cache.get() else { return 0 };
        let removed = cache.purge_matching(request);
        self.metrics.cache_purged(removed as u64);
        let stats = cache.stats();
        self.metrics.cache_size(stats.entries, stats.bytes);
        removed
    }

    fn stats(&self) -> CacheStats {
        self.cache.get().map(|c| c.stats()).unwrap_or_default()
    }
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

fn fault_to_error(fault: Option<&BodyFault>) -> ProxyError {
    match fault.and_then(BodyFault::get) {
        Some(Fault::TooLarge) => ProxyError::BodyTooLarge,
        Some(Fault::IdleTimeout) => ProxyError::ClientTimeout,
        _ => ProxyError::Rejected(Violation::Malformed),
    }
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
        let worker_threads = state.load().config.compression.worker_threads;
        Arc::new(Self {
            state,
            clients: UpstreamClients::new(Arc::clone(&metrics)),
            compressor: compress::Compressor::new(Arc::clone(&metrics), worker_threads),
            cache: OnceLock::new(),
            metrics,
            limiters: RateLimiters::new(),
            conn_limiter: ConnectionLimiter::new(),
            challenges,
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

    /// The response cache, created on first use (so a proxy that never caches
    /// allocates nothing).
    fn cache(&self, cfg: &CacheConfig) -> &Arc<Cache> {
        self.cache.get_or_init(|| Arc::new(Cache::new(cfg.shards)))
    }

    /// Compress `body` if the route wants it and the response is eligible.
    fn apply_compression(
        &self,
        compress: Option<&CompressCtx<'_>>,
        ended: bool,
        parts: &mut http::response::Parts,
        mut body: ProxyBody,
    ) -> ProxyBody {
        // A body that is already complete (`Content-Length: 0`, …) has nothing to
        // compress; `HEAD` still gets its `Vary`.
        if let Some(c) = compress.filter(|c| !ended || c.head) {
            // Admission happens inside `plan`, before any header is touched: a
            // response that cannot get an encoder slot goes out as it came.
            let admitted = compress::plan(c.cfg, c.accept.as_ref(), c.head, parts.status, &mut parts.headers, |_| {
                self.compressor.try_acquire(c.cfg.max_concurrent_encoders)
            });
            if let Some((algo, permit)) = admitted {
                body = self.compressor.wrap(body, algo, permit, c.cfg);
            }
        }
        body
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
        self.clients.retain(snap.upstreams.values().map(|g| &**g));
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
        let mut inflight = activity.map(Activity::begin);
        let snap = self.state.load();
        let derived = self.derived(&snap);
        let request_id = request_id_from(req.headers());
        // Only pay for log context when an access-log line will be written.
        let access_log =
            snap.config.telemetry.access_log && tracing::enabled!(target: "velox::access", tracing::Level::INFO);
        let log_req = access_log.then(|| (req.method().clone(), req.uri().clone()));
        let mut trace = Trace::default();

        let work = self.handle_inner(&snap, &derived, req, conn, &request_id, &mut trace, &mut inflight);
        // No span (and no field formatting) unless something would record it.
        let result = if tracing::enabled!(tracing::Level::INFO) {
            work.instrument(tracing::info_span!("request", request_id = request_id.to_str().unwrap_or(""))).await
        } else {
            work.await
        };
        let rid = request_id.to_str().unwrap_or("");
        let mut resp = match result {
            Ok(r) => r,
            Err(e) => {
                if e.status().is_server_error() {
                    tracing::warn!(request_id = rid, error = %e, "request failed");
                }
                if access_log {
                    trace.error = Some(e.to_string());
                }
                e.into_response()
            }
        };

        if let Some((policy, origin)) = &trace.cors {
            policy.apply_response(origin.as_ref(), resp.headers_mut());
        }
        let headers = resp.headers_mut();
        headers.insert(X_REQUEST_ID, request_id.clone());
        derived.response.apply(headers, conn.tls);
        if conn.tls && conn.protocol != Protocol::H3 {
            if let Some(alt) = &derived.alt_svc {
                headers.entry(ALT_SVC).or_insert_with(|| alt.clone());
            }
        }
        let elapsed = started.elapsed();
        let status = resp.status().as_u16();
        self.metrics.observe_request(conn.protocol, status, elapsed.as_secs_f64());
        if let Some((method, uri)) = log_req {
            tracing::info!(
                target: "velox::access",
                request_id = rid,
                method = %method,
                host = uri.authority().map(http::uri::Authority::as_str),
                path = uri.path(),
                status,
                duration_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
                protocol = conn.protocol.as_str(),
                client_ip = %trace.client_ip.unwrap_or_else(|| conn.peer.ip()),
                trace_id = trace.trace.as_ref().map(TraceParent::trace_id_hex),
                route = trace.route,
                upstream = trace.upstream,
                backend = trace.backend,
                error = trace.error.as_deref(),
                "request"
            );
        }
        // `inflight` moves into the response body when streaming; a canned
        // response (already complete) simply releases it here.
        drop(inflight.take());
        resp
    }

    #[allow(clippy::too_many_lines, clippy::too_many_arguments)]
    async fn handle_inner<'s>(
        &self,
        snap: &'s Snapshot,
        derived: &Derived,
        mut req: Request<ProxyBody>,
        conn: ConnMeta,
        request_id: &HeaderValue,
        trace: &mut Trace<'s>,
        inflight: &mut Option<InflightGuard>,
    ) -> Result<Response<ProxyBody>, ProxyError> {
        let cfg: &'s Config = &snap.config;

        // ---- strict validation (defence in depth; wire-level checks ran earlier) ----
        if let Some(slug) = req.uri().path().strip_prefix(REJECT_PATH) {
            let v = Violation::from_slug(slug).unwrap_or(Violation::Malformed);
            self.metrics.rejected(v.slug());
            return Err(v.into());
        }
        if let Err(v) =
            validate_request_headers(req.version(), req.headers(), req.uri(), cfg.security.allow_underscores_in_host)
        {
            self.metrics.rejected(v.slug());
            return Err(v.into());
        }
        if req.headers().len() > cfg.limits.max_headers {
            self.metrics.rejected(Violation::TooManyHeaders.slug());
            return Err(Violation::TooManyHeaders.into());
        }

        // The Host as a ref-counted header value: for HTTP/1 this is a clone of
        // the inbound header (no allocation); only HTTP/2/3 build one from :authority.
        let host_hv: Option<HeaderValue> = match (req.headers().get(HOST), req.uri().authority()) {
            (Some(h), _) => Some(h.clone()),
            (None, Some(a)) => Some(HeaderValue::from_str(a.as_str()).map_err(|_| Violation::Host)?),
            (None, None) => None, // HTTP/1.0 without Host
        };
        let authority: &str = host_hv.as_ref().and_then(|h| h.to_str().ok()).unwrap_or("");
        let host = host_without_port(authority);

        // ---- ACME HTTP-01 on the plain listener ----
        if !conn.tls {
            if let Some(body) = self.challenges.respond(req.uri().path()) {
                let mut r = simple_response(StatusCode::OK, body.trim_end());
                *r.body_mut() = full(Bytes::from(body));
                return Ok(r);
            }
        }

        // ---- route (borrowed from the snapshot: no Arc traffic) ----
        let route: &'s Route = snap.router.find(host, req.uri().path()).ok_or(ProxyError::NoRoute)?;
        let group: &'s UpstreamGroup = &route.upstream;
        trace.route = Some(&route.id);
        trace.upstream = Some(&group.name);

        // A TLS-terminating load balancer in front of us has already done the
        // upgrade: redirecting its plain-HTTP hop again would loop forever.
        if route.redirect_https
            && !conn.tls
            && !is_https_via_trusted_proxy(req.headers(), conn.peer.ip(), &cfg.security.trusted_proxies)
        {
            return redirect_to_https(route.canonical_host.as_deref().unwrap_or(host), derived.https_port, req.uri());
        }

        // CORS: remember the policy so every response (even a 429 or 502 that
        // Velox generates) carries it; preflights are answered below.
        if let Some(policy) = &route.cors {
            trace.cors = Some((policy, req.headers().get(cors::ORIGIN).cloned()));
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

        // ---- CORS preflight: answered here, never forwarded ----
        if let Some(policy) = &route.cors {
            let h = req.headers();
            if req.method() == Method::OPTIONS {
                if let (Some(origin), Some(method)) = (h.get(cors::ORIGIN), h.get(cors::REQUEST_METHOD)) {
                    let answer = policy.preflight(origin, method, h.get(cors::REQUEST_HEADERS));
                    trace.cors = None; // the preflight answer is complete as it is
                    return match answer {
                        Ok(headers) => {
                            let mut resp = Response::new(ProxyBody::Empty);
                            *resp.status_mut() = StatusCode::NO_CONTENT;
                            *resp.headers_mut() = headers;
                            Ok(resp)
                        }
                        Err(why) => {
                            self.metrics.cors_denied(&route.id, why.reason());
                            Err(ProxyError::CorsDenied)
                        }
                    };
                }
            }
        }

        let compress = route.compress.unwrap_or(cfg.compression.enabled).then(|| CompressCtx {
            cfg: &cfg.compression,
            accept: accept_encoding(req.headers()),
            head: req.method() == Method::HEAD,
        });

        // ---- response cache ----
        let mut cache_ctx = CacheCtx::default();
        if let Some(rc) = &route.cache {
            let cache = self.cache(&cfg.cache);
            let has_body = !(req.body().is_end_stream() || req.body().size_hint().exact() == Some(0));
            let mode = cache::classify_request(req.method(), req.headers(), has_body, rc.allow_cookies);
            let target = if rc.ignore_query {
                req.uri().path()
            } else {
                req.uri().path_and_query().map_or("/", PathAndQuery::as_str)
            };
            let meta = Arc::new(KeyMeta::new(&route.id, host, conn.tls, target));
            if let Some(key) = meta.key() {
                match mode {
                    RequestMode::Normal => {
                        if let Some(entry) = cache.get(&key, req.headers(), Instant::now()) {
                            self.metrics.cache_hit(&route.id);
                            let hit = cache::serve_hit(&entry, req.headers(), Instant::now());
                            let body = if req.method() == Method::HEAD || hit.status == StatusCode::NOT_MODIFIED {
                                ProxyBody::Empty
                            } else {
                                ProxyBody::full(hit.body)
                            };
                            let mut resp = Response::new(ProxyBody::Empty);
                            *resp.status_mut() = hit.status;
                            *resp.headers_mut() = hit.headers;
                            let (mut parts, _) = resp.into_parts();
                            parts.headers.insert(cache::X_CACHE, HeaderValue::from_static("hit"));
                            let ended = body.is_end_stream();
                            let body = self.apply_compression(compress.as_ref(), ended, &mut parts, body);
                            return Ok(Response::from_parts(parts, body));
                        }
                        self.metrics.cache_miss(&route.id);
                    }
                    RequestMode::Refresh => {
                        cache.count_miss();
                        self.metrics.cache_miss(&route.id);
                    }
                    RequestMode::Bypass(why) => {
                        self.metrics.cache_bypassed(why);
                        cache_ctx.tag = Some("bypass");
                        // A successful write to this URL makes what we hold stale.
                        if matches!(*req.method(), Method::POST | Method::PUT | Method::PATCH | Method::DELETE) {
                            cache_ctx.invalidate = Some((Arc::clone(cache), Arc::clone(&key)));
                        }
                    }
                }
                if !matches!(mode, RequestMode::Bypass(_)) {
                    cache_ctx.tag = Some("miss");
                    // Only a `GET` is stored (a `HEAD` is answered from one).
                    if req.method() == Method::GET {
                        cache_ctx.fill = Some(FillTicket {
                            cache: Arc::clone(cache),
                            metrics: Arc::clone(&self.metrics),
                            key,
                            meta,
                            route: rc.clone(),
                            request_headers: req.headers().clone(),
                            max_bytes: cfg.cache.max_bytes,
                            max_entry_bytes: cfg.cache.max_entry_bytes,
                        });
                    }
                }
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

        let idle = cfg.timeouts.request_body_idle;
        let known_empty = body.is_end_stream() || body.size_hint().exact() == Some(0);
        // Bodies that are already complete need no fault tracking, no timers, no boxing.
        let fault = (!known_empty).then(BodyFault::new);
        let limited: ProxyBody = match &fault {
            None => ProxyBody::Empty,
            Some(f) if max_body > 0 => ProxyBody::boxed(IdleBody::new(
                LimitBody::new(body, max_body, Arc::clone(f)),
                idle,
                Some(Arc::clone(f)),
            )),
            Some(f) => ProxyBody::boxed(IdleBody::new(body, idle, Some(Arc::clone(f)))),
        };
        let retries = group.config.retries;
        let size = limited.size_hint().exact();
        let mut req_body = if known_empty {
            ReqBody::Replay(Bytes::new())
        } else if retries > 0 && size.is_some_and(|n| n <= cfg.limits.retry_body_buffer_bytes) {
            match limited.collect().await {
                Ok(c) => ReqBody::Replay(c.to_bytes()),
                Err(_) => return Err(fault_to_error(fault.as_deref())),
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
        apply_forwarded_headers_hv(
            &mut headers,
            conn.peer.ip(),
            &cfg.security.trusted_proxies,
            if conn.tls { "https" } else { "http" },
            host_hv.as_ref(),
            client_ip,
        );
        if cfg.telemetry.traceparent {
            trace.trace = Some(trace::propagate(&mut headers).context);
        }
        for (k, v) in &route.request_headers {
            headers.insert(k.clone(), v.clone());
        }
        headers.insert(X_REQUEST_ID, request_id.clone());
        if !headers.contains_key(HOST) {
            if let Some(h) = &host_hv {
                headers.insert(HOST, h.clone());
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
        //
        // One deadline covers *every* attempt: `retries = 2` can never turn a
        // 30 s upstream timeout into 90 s of client-visible latency.
        let response_timeout = route.timeout.unwrap_or(cfg.timeouts.upstream_response);
        let deadline = tokio::time::Instant::now() + response_timeout;
        let max_attempts = 1 + if replayable { retries } else { 0 };
        let idempotent = is_idempotent(&parts.method);
        let client = self
            .clients
            .get(group, cfg.timeouts.upstream_connect, cfg.server.tcp_nodelay)
            .map_err(|e| ProxyError::BadGateway(format!("upstream TLS configuration: {e}")))?;
        let mut ctx = PickCtx { hash, exclude: 0 };
        let mut last_err: Option<ProxyError> = None;
        let mut saturated = false;
        let (mut method, mut pq, mut hdrs) = (Some(parts.method), Some(path_and_query), Some(headers));
        for attempt in 0..max_attempts {
            if attempt > 0 && tokio::time::Instant::now() >= deadline {
                last_err = Some(ProxyError::UpstreamTimeout);
                break;
            }
            // Choose a backend and commit to it atomically against its
            // `max_inflight` cap. `pick` already skips backends that look full;
            // `try_track` catches the race where another request took the last
            // slot in between, and we simply move on to the next candidate.
            let admitted = loop {
                let Some(idx) = lb::pick(group, &ctx) else { break None };
                ctx.exclude(idx);
                match group.backends[idx].try_track() {
                    Some(active) => break Some((idx, active)),
                    None => saturated = true,
                }
            };
            let Some((idx, active)) = admitted else { break };
            let backend = &group.backends[idx];
            trace.backend = Some(&backend.name);

            // Clone request parts only when a retry is actually possible;
            // otherwise they are moved (the single-attempt fast path).
            let may_retry = attempt + 1 < max_attempts
                && (group.backends.len() > 128 || group.backends.len() > ctx.exclude.count_ones() as usize);
            let (m, p, h) = if may_retry {
                (method.clone(), pq.clone(), hdrs.clone())
            } else {
                (method.take(), pq.take(), hdrs.take())
            };
            let (Some(m), Some(p), Some(h)) = (m, p, h) else { break };

            let body = match &mut req_body {
                ReqBody::Replay(b) => ProxyBody::full(b.clone()),
                ReqBody::Stream(slot) => slot.take().unwrap_or(ProxyBody::Empty),
            };
            let uri = Uri::builder()
                .scheme(if backend.tls { Scheme::HTTPS } else { Scheme::HTTP })
                .authority(backend.authority.clone())
                .path_and_query(p)
                .build()
                .map_err(|e| ProxyError::Internal(e.to_string()))?;
            let mut ureq = Request::new(body);
            *ureq.method_mut() = m;
            *ureq.uri_mut() = uri;
            *ureq.version_mut() = Version::HTTP_11;
            *ureq.headers_mut() = h;

            let t0 = Instant::now();
            let result = tokio::time::timeout_at(deadline, client.request(ureq)).await;
            let secs = t0.elapsed().as_secs_f64();
            let (err, connect_failed) = match result {
                Ok(Ok(resp)) => {
                    let status = resp.status().as_u16();
                    self.metrics.observe_upstream(&group.name, Some(status), secs);
                    if record_outcome(group, backend, Outcome::Response { status }) {
                        self.metrics.backend_ejected(&group.name, &backend.name);
                    }
                    return self.finish_response(
                        resp,
                        active,
                        inflight.take(),
                        ResponseCtx { ws, client_upgrade, compress, cache: std::mem::take(&mut cache_ctx) },
                        cfg,
                    );
                }
                Ok(Err(e)) => {
                    if matches!(
                        fault.as_deref().and_then(BodyFault::get),
                        Some(Fault::TooLarge | Fault::IdleTimeout | Fault::ClientRead)
                    ) {
                        // The *client* failed; the backend is blameless.
                        return Err(fault_to_error(fault.as_deref()));
                    }
                    (ProxyError::UpstreamConnect(e.to_string()), e.is_connect())
                }
                Err(_) => (ProxyError::UpstreamTimeout, false),
            };
            self.metrics.observe_upstream(&group.name, None, secs);
            if record_outcome(group, backend, Outcome::TransportError) {
                self.metrics.backend_ejected(&group.name, &backend.name);
            }
            last_err = Some(err);
            drop(active);
            if !(connect_failed || idempotent) {
                break;
            }
        }
        Err(last_err.unwrap_or_else(|| {
            // No backend was usable at all. Distinguish "all full" (shed load,
            // the pool is fine) from "all down" (an outage).
            if saturated || group.any_saturated() {
                self.metrics.upstream_saturated(&group.name);
                ProxyError::UpstreamSaturated
            } else {
                ProxyError::NoHealthyUpstream
            }
        }))
    }

    fn finish_response(
        &self,
        mut resp: Response<hyper::body::Incoming>,
        active: ActiveGuard,
        inflight: Option<InflightGuard>,
        ctx: ResponseCtx<'_>,
        cfg: &Config,
    ) -> Result<Response<ProxyBody>, ProxyError> {
        let ResponseCtx { ws, client_upgrade, compress, cache: cache_ctx } = ctx;
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
            parts.version = Version::HTTP_11;
            parts.headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
            drop(inflight); // a tunnel is not an in-flight HTTP request
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
            return Ok(Response::from_parts(parts, ProxyBody::Empty));
        }

        let (mut parts, body) = resp.into_parts();
        // A legacy backend may answer `HTTP/1.0`; that is a statement about the
        // *backend* hop only (it means "close-delimited, no chunking"), not
        // something to leak to the client. Status, headers and body framing are
        // untouched: hyper re-frames the body for the client connection itself
        // (chunked for HTTP/1.1, and back down to 1.0 semantics for 1.0 clients).
        parts.version = Version::HTTP_11;
        strip_hop_by_hop(&mut parts.headers);
        if ws {
            // The upgrade was declined: the guard stopped inspecting this
            // connection, so it must not be reused for further requests.
            parts.headers.insert(CONNECTION, HeaderValue::from_static("close"));
        }
        if let Some((cache, key)) = &cache_ctx.invalidate {
            if parts.status.as_u16() < 400 {
                let removed = cache.invalidate(key);
                if removed > 0 {
                    self.metrics.cache_purged(removed as u64);
                    let stats = cache.stats();
                    self.metrics.cache_size(stats.entries, stats.bytes);
                }
            }
        }
        let ended = body.is_end_stream();
        // One wrapper, one box: idle timeout + both in-flight guards.
        let body = IdleBody::with_guard(body, cfg.timeouts.upstream_body_idle, None, (active, inflight));
        let mut body = ProxyBody::boxed(body);
        let mut tag = cache_ctx.tag;
        // The cache sees the response as the backend produced it — before
        // compression, which is applied per client on the way out (hit or miss).
        if let Some(ticket) = cache_ctx.fill {
            let (offer, filled) = ticket.offer(parts.status, &parts.headers, body);
            body = filled;
            if let Offer::Pass(why) = offer {
                self.metrics.cache_bypassed(why);
                tag = Some("pass");
            }
        }
        let body = self.apply_compression(compress.as_ref(), ended, &mut parts, body);
        if let Some(tag) = tag {
            parts.headers.insert(cache::X_CACHE, HeaderValue::from_static(tag));
        }
        Ok(Response::from_parts(parts, body))
    }
}

/// Build the 308 to HTTPS.
///
/// * An empty host (HTTP/1.0 without `Host`) is refused: there is nothing safe
///   to put in `Location`.
/// * The `*` target of `OPTIONS *` becomes `/`.
/// * `host` is either a validated, route-constrained request host or the
///   route's configured `canonical_host`; it never contains CR/LF or `/`.
fn redirect_to_https(host: &str, https_port: Option<u16>, uri: &Uri) -> Result<Response<ProxyBody>, ProxyError> {
    if host.is_empty() {
        return Err(Violation::Host.into());
    }
    let host = if host.contains(':') { format!("[{host}]") } else { host.to_owned() };
    let port = match https_port {
        Some(p) if p != 443 => format!(":{p}"),
        _ => String::new(),
    };
    let pq = match uri.path_and_query().map(PathAndQuery::as_str) {
        None | Some("*") => "/",
        Some(p) => p,
    };
    let location = HeaderValue::from_str(&format!("https://{host}{port}{pq}"))
        .map_err(|_| ProxyError::Rejected(Violation::Target))?;
    let mut resp = simple_response(StatusCode::PERMANENT_REDIRECT, "redirecting to https");
    resp.headers_mut().insert(LOCATION, location);
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc(r: &Response<ProxyBody>) -> &str {
        r.headers()[LOCATION].to_str().unwrap()
    }

    #[test]
    fn redirect_rules() {
        let uri: Uri = "/a/b?x=1".parse().unwrap();
        let r = redirect_to_https("example.com", Some(8443), &uri).unwrap();
        assert_eq!((r.status().as_u16(), loc(&r)), (308, "https://example.com:8443/a/b?x=1"));
        let r = redirect_to_https("example.com", Some(443), &uri).unwrap();
        assert_eq!(loc(&r), "https://example.com/a/b?x=1");
        let r = redirect_to_https("::1", None, &uri).unwrap();
        assert_eq!(loc(&r), "https://[::1]/a/b?x=1");
        // `OPTIONS *` must not produce `https://host*`.
        let star: Uri = "*".parse().unwrap();
        let r = redirect_to_https("example.com", None, &star).unwrap();
        assert_eq!(loc(&r), "https://example.com/");
        // No host → nothing safe to redirect to.
        assert!(matches!(redirect_to_https("", None, &uri), Err(ProxyError::Rejected(Violation::Host))));
        // Header injection attempts never make it into Location.
        assert!(redirect_to_https("evil\r\nSet-Cookie: x", None, &uri).is_err());
    }
}
