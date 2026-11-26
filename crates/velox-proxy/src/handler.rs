//! The protocol-independent request pipeline.
//!
//! HTTP/1.1, HTTP/2 and HTTP/3 front-ends all normalise their requests into
//! `Request<ProxyBody>` and call [`Proxy::handle`]. Every failure is a
//! [`ProxyError`] mapped to a clean 4xx/5xx; nothing on this path unwraps.

use crate::body::{BodyFault, Fault, IdleBody, LimitBody};
use crate::cache::{self, Cache, Claim, Entry, FillTicket, KeyMeta, Lookup, Offer, RequestMode};
use crate::compress;
use crate::error::{full, simple_response, ProxyBody, ProxyError};
use crate::io::{Activity, InflightGuard, REJECT_PATH};
use crate::lb::{self, PickCtx};
use crate::shutdown::Shutdown;
use crate::upstream::UpstreamClients;
use arc_swap::ArcSwap;
use bytes::Bytes;
use http::header::{
    ACCEPT_ENCODING, ALT_SVC, AUTHORIZATION, CACHE_CONTROL, CONNECTION, CONTENT_LENGTH, COOKIE, HOST,
    IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE, LOCATION, PRAGMA, RANGE, UPGRADE,
};
use http::uri::{PathAndQuery, Scheme};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri, Version};
use http_body::Body;
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Instant, SystemTime};
use tracing::Instrument;
use velox_core::cache_admin::{CacheAdmin, CacheStats, PurgeRequest};
use velox_core::config::{Algorithm, CacheConfig, CompressionConfig, Config, RouteCacheConfig};
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

/// Headers carrying the verified client certificate's identity to the backend.
pub const X_CLIENT_CERT_SUBJECT: HeaderName = HeaderName::from_static("x-client-cert-subject");
/// See [`X_CLIENT_CERT_SUBJECT`].
pub const X_CLIENT_CERT_SERIAL: HeaderName = HeaderName::from_static("x-client-cert-serial");

/// The verified client certificate of the connection a request arrived on,
/// attached as a request extension by the front-ends (TCP/TLS and QUIC).
#[derive(Debug, Clone)]
pub struct ClientCertInfo(pub Arc<velox_security::client_cert::ClientCert>);

/// What the response cache wants done with this request's response.
#[derive(Default)]
struct CacheCtx {
    /// Value for `X-Velox-Cache` (`miss`, `bypass`), if the route caches.
    tag: Option<&'static str>,
    /// Offer the response for storage.
    fill: Option<FillTicket>,
    /// A successful unsafe request invalidates this URL.
    invalidate: Option<(Arc<Cache>, Arc<str>)>,
    /// An expired entry that may be served if the backend fails (`stale-if-error`).
    stale: Option<StaleFallback>,
}

/// What it takes to answer from an expired entry when the backend is failing.
struct StaleFallback {
    entry: Arc<Entry>,
    request_headers: HeaderMap,
    head: bool,
    route: Arc<str>,
}

/// The parts of a request the cache stage reads. (`ProxyBody` is `Send` but not
/// `Sync`, so a `&Request<ProxyBody>` cannot be held across an `await`; these
/// borrows can.)
struct ReqView<'a> {
    method: &'a Method,
    headers: &'a HeaderMap,
    uri: &'a Uri,
    has_body: bool,
    internal: bool,
    /// The connection presented a verified client certificate.
    authenticated: bool,
}

/// Marks the internal request a background revalidation sends through the
/// normal pipeline: it skips client-facing gates (rate limit, ACLs, …), is never
/// answered from the cache, and its response fills the cache like any miss.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Revalidation;

/// Everything a background revalidation needs; owned by its task.
struct RevalidationJob {
    cache: Arc<Cache>,
    key: Arc<str>,
    meta: Arc<KeyMeta>,
    stale: Arc<Entry>,
    rc: RouteCacheConfig,
    route: Arc<str>,
    request_headers: HeaderMap,
    target: PathAndQuery,
    authority: HeaderValue,
    conn: ConnMeta,
    max_bytes: u64,
    /// Keeps the object "in flight" until the refresh is stored or abandoned.
    _leader: cache::FlightLeader,
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
    jwt: velox_security::JwtRegistry,
    /// A handle to ourselves, so background work (revalidation) can be spawned.
    me: Weak<Proxy>,
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
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            state,
            clients: UpstreamClients::new(Arc::clone(&metrics)),
            compressor: compress::Compressor::new(Arc::clone(&metrics), worker_threads),
            cache: OnceLock::new(),
            jwt: velox_security::JwtRegistry::new(),
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

    /// The response for a cache `entry`, evaluated against the request's
    /// conditionals and compressed per client like any other.
    fn cached_response(
        &self,
        entry: &Entry,
        request_headers: &HeaderMap,
        head: bool,
        compress: Option<&CompressCtx<'_>>,
        tag: &'static str,
    ) -> Response<ProxyBody> {
        let hit = cache::serve_hit(entry, request_headers, Instant::now());
        let body =
            if head || hit.status == StatusCode::NOT_MODIFIED { ProxyBody::Empty } else { ProxyBody::full(hit.body) };
        let mut resp = Response::new(ProxyBody::Empty);
        *resp.status_mut() = hit.status;
        *resp.headers_mut() = hit.headers;
        let (mut parts, _) = resp.into_parts();
        parts.headers.insert(cache::X_CACHE, HeaderValue::from_static(tag));
        let ended = body.is_end_stream();
        let body = self.apply_compression(compress, ended, &mut parts, body);
        Response::from_parts(parts, body)
    }

    /// The cache's part of a request: answer from it if possible, otherwise
    /// decide how the fetch should feed it. `None` means "go to the backend"
    /// (with `out` describing what to do with the response).
    ///
    /// * fresh entry → answered (`HIT`);
    /// * expired inside its `stale-while-revalidate` window → answered at once
    ///   (`REVALIDATING`) while one background request refreshes it;
    /// * expired inside its `stale-if-error` window → remembered in `out`, used
    ///   only if the backend then fails (`STALE`);
    /// * a miss while another request is already fetching the same object →
    ///   wait for it (bounded) and share the result.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn cache_stage(
        &self,
        rc: &RouteCacheConfig,
        route: &Route,
        cfg: &Config,
        authority: &str,
        host: &str,
        req: &ReqView<'_>,
        conn: ConnMeta,
        compress: Option<&CompressCtx<'_>>,
        out: &mut CacheCtx,
    ) -> Option<Response<ProxyBody>> {
        let cache = self.cache(&cfg.cache);
        let (internal, has_body) = (req.internal, req.has_body);
        // A revalidation always goes to the backend, and fills the cache.
        let mode = if internal {
            RequestMode::Refresh
        } else if req.authenticated {
            // The backend sees who is asking and may personalise: never share.
            RequestMode::Bypass("client-cert")
        } else {
            cache::classify_request(req.method, req.headers, has_body, rc.allow_cookies)
        };
        let target =
            if rc.ignore_query { req.uri.path() } else { req.uri.path_and_query().map_or("/", PathAndQuery::as_str) };
        let meta = Arc::new(KeyMeta::new(&route.id, host, conn.tls, target));
        let key = meta.key()?;
        let mut leader = None;
        match mode {
            RequestMode::Bypass(why) => {
                self.metrics.cache_bypassed(why);
                out.tag = Some(cache::tag::BYPASS);
                // A successful write to this URL makes what we hold stale.
                if matches!(*req.method, Method::POST | Method::PUT | Method::PATCH | Method::DELETE) {
                    out.invalidate = Some((Arc::clone(cache), Arc::clone(&key)));
                }
                return None;
            }
            RequestMode::Normal => {
                let head = *req.method == Method::HEAD;
                match cache.lookup(&key, req.headers, Instant::now()) {
                    Lookup::Fresh(entry) => {
                        cache.count_hit();
                        self.metrics.cache_hit(&route.id);
                        return Some(self.cached_response(&entry, req.headers, head, compress, cache::tag::HIT));
                    }
                    Lookup::Stale { entry, while_revalidate, if_error } => {
                        if while_revalidate {
                            // Serve now; refresh once, in the background.
                            self.start_revalidation(cache, &key, &meta, &entry, rc, route, cfg, authority, req, conn);
                            cache.count_stale();
                            self.metrics.cache_stale_served(&route.id, "swr");
                            return Some(self.cached_response(
                                &entry,
                                req.headers,
                                head,
                                compress,
                                cache::tag::REVALIDATING,
                            ));
                        }
                        if if_error {
                            out.stale = Some(StaleFallback {
                                entry,
                                request_headers: req.headers.clone(),
                                head,
                                route: Arc::clone(&route.id),
                            });
                        }
                        cache.count_miss();
                        self.metrics.cache_miss(&route.id);
                    }
                    Lookup::Miss => {
                        cache.count_miss();
                        self.metrics.cache_miss(&route.id);
                    }
                }
                // Collapse concurrent misses on this object into one fetch.
                if rc.coalesce && *req.method == Method::GET {
                    match cache.claim(cache.flight_key(&key, req.headers)) {
                        Claim::Leader(guard) => leader = Some(guard),
                        Claim::Follower(rx) => {
                            if cache::wait_for_flight(rx, rc.coalesce_timeout).await {
                                if let Lookup::Fresh(entry) = cache.lookup(&key, req.headers, Instant::now()) {
                                    cache.count_coalesced();
                                    self.metrics.cache_coalesced(&route.id);
                                    return Some(self.cached_response(
                                        &entry,
                                        req.headers,
                                        false,
                                        compress,
                                        cache::tag::HIT,
                                    ));
                                }
                                // The leader's response was not cacheable (or not for
                                // our variant), or it failed: fetch for ourselves.
                            } else {
                                self.metrics.cache_coalesce_timeout(&route.id);
                            }
                        }
                    }
                }
            }
            RequestMode::Refresh => {
                if !internal {
                    cache.count_miss();
                    self.metrics.cache_miss(&route.id);
                }
            }
        }
        out.tag = Some(cache::tag::MISS);
        // Only a `GET` is stored (a `HEAD` is answered from one).
        if *req.method == Method::GET {
            out.fill = Some(FillTicket {
                cache: Arc::clone(cache),
                metrics: Arc::clone(&self.metrics),
                key,
                meta,
                route: rc.clone(),
                request_headers: req.headers.clone(),
                max_bytes: cfg.cache.max_bytes,
                max_entry_bytes: cfg.cache.max_entry_bytes,
                leader,
            });
        }
        None
    }

    /// Start the one background refresh of a stale object (if none is running).
    #[allow(clippy::too_many_arguments)]
    fn start_revalidation(
        &self,
        cache: &Arc<Cache>,
        key: &Arc<str>,
        meta: &Arc<KeyMeta>,
        entry: &Arc<Entry>,
        rc: &RouteCacheConfig,
        route: &Route,
        cfg: &Config,
        authority: &str,
        req: &ReqView<'_>,
        conn: ConnMeta,
    ) {
        let Claim::Leader(leader) = cache.claim(cache.flight_key(key, req.headers)) else {
            return; // someone is already refreshing it
        };
        let (Some(me), Ok(authority), Some(target)) =
            (self.me.upgrade(), HeaderValue::from_str(authority), req.uri.path_and_query().cloned())
        else {
            return;
        };
        let job = RevalidationJob {
            cache: Arc::clone(cache),
            key: Arc::clone(key),
            meta: Arc::clone(meta),
            stale: Arc::clone(entry),
            rc: rc.clone(),
            route: Arc::clone(&route.id),
            request_headers: req.headers.clone(),
            target,
            authority,
            conn,
            max_bytes: cfg.cache.max_bytes,
            _leader: leader,
        };
        self.shutdown.tasks.spawn(async move { me.run_revalidation(job).await });
    }

    /// Refresh a stale entry: a conditional `GET` through the normal pipeline.
    /// `304` revives the stored body; a new `200` replaces it; anything else
    /// leaves the stale entry for its remaining window.
    async fn run_revalidation(self: Arc<Self>, job: RevalidationJob) {
        let mut headers = job.request_headers.clone();
        // The refresh speaks for the object, not for the client that triggered it.
        for name in [COOKIE, AUTHORIZATION, RANGE, IF_RANGE, IF_NONE_MATCH, IF_MODIFIED_SINCE, CACHE_CONTROL, PRAGMA] {
            headers.remove(name);
        }
        if !headers.contains_key(HOST) {
            headers.insert(HOST, job.authority.clone());
        }
        let (etag, last_modified) = job.stale.validators();
        if let Some(e) = etag {
            headers.insert(IF_NONE_MATCH, e.clone());
        }
        if let Some(lm) = last_modified {
            headers.insert(IF_MODIFIED_SINCE, lm);
        }
        let mut req = Request::new(ProxyBody::Empty);
        let Ok(uri) = Uri::builder().path_and_query(job.target.clone()).build() else { return };
        *req.uri_mut() = uri;
        *req.headers_mut() = headers;
        req.extensions_mut().insert(Revalidation);

        let resp = self.handle(req, job.conn, None).await;
        let wait = self.state.load().config.timeouts.upstream_response.saturating_mul(2);
        let result = if resp.status() == StatusCode::NOT_MODIFIED {
            let refreshed =
                job.cache.refresh_not_modified(&job.key, &job.meta, &job.stale, resp.headers(), &job.rc, job.max_bytes);
            if refreshed {
                "not_modified"
            } else {
                "error"
            }
        } else {
            let ok = resp.status().is_success() || resp.status() == StatusCode::NOT_FOUND;
            // Drive the body to its end so the fill completes and is stored.
            let drained = tokio::time::timeout(wait, resp.into_body().collect()).await.is_ok_and(|r| r.is_ok());
            if ok && drained {
                "updated"
            } else {
                "error"
            }
        };
        self.metrics.cache_revalidation(&job.route, result);
        let stats = job.cache.stats();
        self.metrics.cache_size(stats.entries, stats.bytes);
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
        self.jwt.retain(snap.config.routes.iter().filter_map(|r| r.jwt.as_ref()));
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
        // A background revalidation is Velox talking to itself on a client's
        // behalf: no client-facing gates apply and nothing is compressed for it.
        let internal = req.extensions().get::<Revalidation>().is_some();

        // CORS: remember the policy so every response (even a 429 or 502 that
        // Velox generates) carries it; preflights are answered below.
        if let Some(policy) = &route.cors {
            trace.cors = Some((policy, req.headers().get(cors::ORIGIN).cloned()));
        }

        // ---- client identity + access lists ----
        // Resolved first (after PROXY protocol / trusted proxies) so a refused
        // address gets nothing — not even a redirect — and costs no rate-limit state.
        let client_ip = resolve_client_ip(req.headers(), conn.peer.ip(), &cfg.security.trusted_proxies);
        trace.client_ip = Some(client_ip);
        if !internal {
            let refusal = snap
                .acl
                .check(client_ip)
                .map_err(|d| ("global", d))
                .and_then(|()| route.acl.check(client_ip).map_err(|d| ("route", d)));
            if let Err((scope, why)) = refusal {
                self.metrics.acl_denied(&route.id, scope, why.reason());
                return Err(ProxyError::Forbidden);
            }
        }

        // A TLS-terminating load balancer in front of us has already done the
        // upgrade: redirecting its plain-HTTP hop again would loop forever.
        if route.redirect_https
            && !conn.tls
            && !is_https_via_trusted_proxy(req.headers(), conn.peer.ip(), &cfg.security.trusted_proxies)
        {
            return redirect_to_https(route.canonical_host.as_deref().unwrap_or(host), derived.https_port, req.uri());
        }

        // ---- rate limit ----
        if let Some(policy) = route.rate_limit.as_ref().filter(|_| !internal) {
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

        // ---- edge JWT verification ----
        if let Some(jwt) = route.jwt.as_ref().filter(|_| !internal) {
            // Claims reach the backend only from a verified token: whatever the
            // client put in `X-Jwt-*` is discarded first.
            let spoofed: Vec<HeaderName> =
                req.headers().keys().filter(|k| k.as_str().starts_with("x-jwt-")).cloned().collect();
            for name in spoofed {
                req.headers_mut().remove(name);
            }
            match self.jwt.verify(jwt, req.headers(), SystemTime::now()) {
                Ok(Some(claims)) => {
                    for claim in &jwt.forward_claims {
                        let value = claims.get(claim).and_then(velox_security::jwt::claim_header_text);
                        let header = HeaderName::from_bytes(format!("x-jwt-{}", claim.to_ascii_lowercase()).as_bytes());
                        if let (Some(text), Ok(name)) = (value, header) {
                            if let Ok(v) = HeaderValue::from_str(&text) {
                                req.headers_mut().insert(name, v);
                            }
                        }
                    }
                }
                Ok(None) => {} // no token, and the route does not require one
                Err(why) => {
                    self.metrics.jwt_rejected(&route.id, why.reason());
                    tracing::debug!(route = &*route.id, reason = why.reason(), "token refused");
                    return Err(match why {
                        velox_security::jwt::JwtError::Missing => ProxyError::Unauthorized { invalid: false },
                        velox_security::jwt::JwtError::Unavailable => ProxyError::AuthUnavailable,
                        _ => ProxyError::Unauthorized { invalid: true },
                    });
                }
            }
        }

        let compress = (route.compress.unwrap_or(cfg.compression.enabled) && !internal).then(|| CompressCtx {
            cfg: &cfg.compression,
            accept: accept_encoding(req.headers()),
            head: req.method() == Method::HEAD,
        });

        // ---- response cache ----
        let mut cache_ctx = CacheCtx::default();
        if let Some(rc) = &route.cache {
            let view = ReqView {
                method: req.method(),
                headers: req.headers(),
                uri: req.uri(),
                has_body: !(req.body().is_end_stream() || req.body().size_hint().exact() == Some(0)),
                internal,
                authenticated: req.extensions().get::<ClientCertInfo>().is_some(),
            };
            let answer =
                self.cache_stage(rc, route, cfg, authority, host, &view, conn, compress.as_ref(), &mut cache_ctx).await;
            if let Some(resp) = answer {
                return Ok(resp);
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
        let client_cert = req.extensions().get::<ClientCertInfo>().cloned();
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
        // Client-certificate identity: believed only from our own verified
        // handshake, or from a trusted proxy that performed one for us. Anyone
        // else's `X-Client-Cert-*` is discarded before the backend can see it.
        let peer_trusted = cfg.security.trusted_proxies.iter().any(|n| n.contains(&conn.peer.ip()));
        if client_cert.is_some() || !peer_trusted {
            headers.remove(X_CLIENT_CERT_SUBJECT);
            headers.remove(X_CLIENT_CERT_SERIAL);
        }
        if let Some(cert) = &client_cert {
            if let (Ok(subject), Ok(serial)) =
                (HeaderValue::from_str(&cert.0.subject), HeaderValue::from_str(&cert.0.serial))
            {
                headers.insert(X_CLIENT_CERT_SUBJECT, subject);
                headers.insert(X_CLIENT_CERT_SERIAL, serial);
            }
        }
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
                    // `stale-if-error`: a failing backend is answered from the expired copy.
                    if matches!(status, 500 | 502 | 503 | 504) {
                        if let Some(stale) = cache_ctx.stale.take() {
                            return Ok(self.stale_if_error(stale, compress.as_ref()));
                        }
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
        let failure = last_err.unwrap_or_else(|| {
            // No backend was usable at all. Distinguish "all full" (shed load,
            // the pool is fine) from "all down" (an outage).
            if saturated || group.any_saturated() {
                self.metrics.upstream_saturated(&group.name);
                ProxyError::UpstreamSaturated
            } else {
                ProxyError::NoHealthyUpstream
            }
        });
        // Every attempt failed. If an expired copy may be served in that case
        // (`stale-if-error`), do so rather than surface the error.
        if let Some(stale) = cache_ctx.stale.take() {
            return Ok(self.stale_if_error(stale, compress.as_ref()));
        }
        Err(failure)
    }

    /// Answer from an expired entry because the backend is failing.
    fn stale_if_error(&self, stale: StaleFallback, compress: Option<&CompressCtx<'_>>) -> Response<ProxyBody> {
        if let Some(cache) = self.cache.get() {
            cache.count_stale();
        }
        self.metrics.cache_stale_served(&stale.route, "sie");
        self.cached_response(&stale.entry, &stale.request_headers, stale.head, compress, cache::tag::STALE)
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
                tag = Some(cache::tag::PASS);
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
