//! Request routing and handlers for the admin API.

use crate::views::{RouteView, UpstreamView};
use bytes::Bytes;
use http::{header, HeaderMap, Method, Request, Response, StatusCode};
use http_body::Body;
use http_body_util::{BodyExt, Full, Limited};
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use velox_core::config::{RouteConfig, UpstreamConfig};
use velox_core::{Config, ConfigError, SharedState};
use velox_telemetry::Metrics;

const MAX_BODY: usize = 1024 * 1024;

/// Re-reads the configuration source (normally `velox.toml`) and applies it.
pub trait Reloader: Send + Sync + 'static {
    /// Reload and swap in the new configuration; returns the new generation.
    fn reload(&self) -> Result<u64, String>;
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self { status, message: message.into() }
    }
}

impl From<ConfigError> for ApiError {
    fn from(e: ConfigError) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, e.to_string())
    }
}

type ApiResult = Result<Response<Full<Bytes>>, ApiError>;

/// The admin API application.
pub struct AdminApi {
    state: Arc<SharedState>,
    metrics: Arc<Metrics>,
    reloader: Arc<dyn Reloader>,
    token: Option<String>,
    started: Instant,
}

impl std::fmt::Debug for AdminApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminApi").field("auth", &self.token.is_some()).finish_non_exhaustive()
    }
}

fn json<T: Serialize>(status: StatusCode, value: &T) -> ApiResult {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut resp = Response::new(Full::new(Bytes::from(bytes)));
    *resp.status_mut() = status;
    resp.headers_mut().insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json"));
    Ok(resp)
}

fn plain(status: StatusCode, content_type: &'static str, body: String) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::from(body)));
    *resp.status_mut() = status;
    resp.headers_mut().insert(header::CONTENT_TYPE, header::HeaderValue::from_static(content_type));
    resp
}

/// Decode `%XX` escapes in a path segment.
pub(crate) fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Constant-time equality for secrets.
fn secure_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        diff |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    diff == 0
}

fn is_loopback_host(host: &str) -> bool {
    let h = host.trim_start_matches('[');
    let name = h.split(']').next().unwrap_or(h);
    let name = if host.starts_with('[') { name } else { name.rsplit_once(':').map_or(name, |(n, _)| n) };
    matches!(name, "localhost" | "127.0.0.1" | "::1")
        || name.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

impl AdminApi {
    /// Build the API. `token`, when set, must be presented as a bearer token.
    pub fn new(
        state: Arc<SharedState>,
        metrics: Arc<Metrics>,
        reloader: Arc<dyn Reloader>,
        token: Option<String>,
    ) -> Arc<Self> {
        Arc::new(Self { state, metrics, reloader, token: token.filter(|t| !t.is_empty()), started: Instant::now() })
    }

    /// Handle one request from `peer`.
    pub async fn handle<B>(&self, peer: SocketAddr, req: Request<B>) -> Response<Full<Bytes>>
    where
        B: Body<Data = Bytes> + Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        match self.dispatch(peer, req).await {
            Ok(r) => r,
            Err(e) => {
                let body = serde_json::json!({ "error": e.message });
                json(e.status, &body).unwrap_or_else(|_| plain(e.status, "text/plain", e.message))
            }
        }
    }

    fn authorize(&self, peer: SocketAddr, headers: &HeaderMap, method: &Method) -> Result<(), ApiError> {
        if !peer.ip().is_loopback() {
            return Err(ApiError::new(StatusCode::FORBIDDEN, "admin API is localhost-only"));
        }
        let host = headers.get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("");
        if !is_loopback_host(host) {
            return Err(ApiError::new(StatusCode::FORBIDDEN, "unexpected Host header"));
        }
        // Browsers always attach these to cross-site requests; CLI tools never do.
        if headers.contains_key(header::ORIGIN)
            || headers.get("sec-fetch-site").is_some_and(|v| v.as_bytes() != b"none")
        {
            return Err(ApiError::new(StatusCode::FORBIDDEN, "browser-originated requests are not accepted"));
        }
        if let Some(token) = &self.token {
            let presented = headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .unwrap_or("");
            if !secure_eq(presented.as_bytes(), token.as_bytes()) {
                return Err(ApiError::new(StatusCode::UNAUTHORIZED, "missing or invalid bearer token"));
            }
        }
        let _ = method;
        Ok(())
    }

    async fn read_json<B, T>(headers: &HeaderMap, body: B) -> Result<T, ApiError>
    where
        B: Body<Data = Bytes> + Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        T: serde::de::DeserializeOwned,
    {
        let ct = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
        if !ct.starts_with("application/json") {
            return Err(ApiError::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Content-Type must be application/json"));
        }
        let collected = tokio::time::timeout(Duration::from_secs(5), Limited::new(body, MAX_BODY).collect())
            .await
            .map_err(|_| ApiError::new(StatusCode::REQUEST_TIMEOUT, "request body timed out"))?
            .map_err(|_| ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "request body too large or unreadable"))?;
        serde_json::from_slice(&collected.to_bytes())
            .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, format!("invalid JSON: {e}")))
    }

    #[allow(clippy::too_many_lines)]
    async fn dispatch<B>(&self, peer: SocketAddr, req: Request<B>) -> ApiResult
    where
        B: Body<Data = Bytes> + Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let (parts, body) = req.into_parts();
        self.authorize(peer, &parts.headers, &parts.method)?;
        let path = parts.uri.path().to_owned();
        let segs: Vec<String> = path
            .trim_matches('/')
            .split('/')
            .map(|s| percent_decode(s).ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "bad percent-encoding")))
            .collect::<Result<_, _>>()?;
        let segs: Vec<&str> = segs.iter().map(String::as_str).collect();
        let method = &parts.method;

        match (method, segs.as_slice()) {
            (&Method::GET, ["healthz"]) => Ok(plain(StatusCode::OK, "text/plain", "ok\n".into())),
            (&Method::GET, ["metrics"]) => self.metrics_response(),
            (&Method::GET, ["admin", "v1", "status"]) => {
                let snap = self.state.load();
                json(
                    StatusCode::OK,
                    &serde_json::json!({
                        "version": env!("CARGO_PKG_VERSION"),
                        "config_generation": snap.generation,
                        "uptime_seconds": self.started.elapsed().as_secs(),
                        "routes": snap.config.routes.len(),
                        "upstreams": snap.upstreams.len(),
                    }),
                )
            }
            (&Method::GET, ["admin", "v1", "config"]) => json(StatusCode::OK, &*self.state.load().config),
            (&Method::POST, ["admin", "v1", "reload"]) => match self.reloader.reload() {
                Ok(generation) => {
                    self.metrics.config_reload(true);
                    json(StatusCode::OK, &serde_json::json!({ "reloaded": true, "config_generation": generation }))
                }
                Err(e) => {
                    self.metrics.config_reload(false);
                    Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, e))
                }
            },

            // ---- upstreams ----
            (&Method::GET, ["admin", "v1", "upstreams"]) => {
                let snap = self.state.load();
                let mut views: Vec<UpstreamView> = snap.upstreams.values().map(|g| UpstreamView::from(&**g)).collect();
                views.sort_by(|a, b| a.name.cmp(&b.name));
                json(StatusCode::OK, &views)
            }
            (&Method::GET, ["admin", "v1", "upstreams", name]) => {
                let snap = self.state.load();
                let g = snap.upstreams.get(*name).ok_or_else(|| not_found("upstream"))?;
                json(StatusCode::OK, &UpstreamView::from(&**g))
            }
            (&Method::PUT, ["admin", "v1", "upstreams", name]) => {
                let up: UpstreamConfig = Self::read_json(&parts.headers, body).await?;
                if up.name != *name {
                    return Err(ApiError::new(StatusCode::BAD_REQUEST, "name in body must match the URL"));
                }
                let snap = self.mutate(|c| {
                    match c.upstreams.iter_mut().find(|u| u.name == up.name) {
                        Some(slot) => *slot = up,
                        None => c.upstreams.push(up),
                    }
                    Ok(())
                })?;
                tracing::info!(upstream = *name, generation = snap.generation, "upstream updated via admin API");
                let g = snap.upstreams.get(*name).ok_or_else(|| not_found("upstream"))?;
                json(StatusCode::OK, &UpstreamView::from(&**g))
            }
            (&Method::DELETE, ["admin", "v1", "upstreams", name]) => {
                let snap = self.mutate(|c| {
                    if c.routes.iter().any(|r| r.upstream == *name) || c.tcp_proxies.iter().any(|t| t.upstream == *name)
                    {
                        return Err(ApiError::new(
                            StatusCode::CONFLICT,
                            "upstream is still referenced by a route or tcp_proxy",
                        ));
                    }
                    let before = c.upstreams.len();
                    c.upstreams.retain(|u| u.name != *name);
                    if c.upstreams.len() == before {
                        return Err(not_found("upstream"));
                    }
                    Ok(())
                })?;
                json(StatusCode::OK, &serde_json::json!({ "deleted": name, "config_generation": snap.generation }))
            }
            (&Method::POST, ["admin", "v1", "upstreams", name, "backends", addr, action]) => {
                let snap = self.state.load();
                let g = snap.upstreams.get(*name).ok_or_else(|| not_found("upstream"))?;
                let b = g.find(addr).ok_or_else(|| not_found("backend"))?;
                match *action {
                    "drain" => b.set_draining(true),
                    "undrain" => b.set_draining(false),
                    "reset" => {
                        b.clear_ejection();
                        b.set_healthy(true);
                    }
                    _ => return Err(not_found("action")),
                }
                tracing::info!(
                    upstream = *name,
                    backend = *addr,
                    action = *action,
                    "backend state changed via admin API"
                );
                json(StatusCode::OK, &crate::views::BackendView::from(&**b))
            }

            // ---- routes ----
            (&Method::GET, ["admin", "v1", "routes"]) => {
                let snap = self.state.load();
                let views: Vec<RouteView> = snap
                    .config
                    .routes
                    .iter()
                    .enumerate()
                    .map(|(i, r)| RouteView { id: snap.config.route_id(i), route: r.clone() })
                    .collect();
                json(StatusCode::OK, &views)
            }
            (&Method::PUT, ["admin", "v1", "routes"]) => {
                let routes: Vec<RouteConfig> = Self::read_json(&parts.headers, body).await?;
                let snap = self.mutate(|c| {
                    c.routes = routes;
                    Ok(())
                })?;
                json(
                    StatusCode::OK,
                    &serde_json::json!({ "routes": snap.config.routes.len(), "config_generation": snap.generation }),
                )
            }
            (&Method::POST, ["admin", "v1", "routes"]) => {
                let route: RouteConfig = Self::read_json(&parts.headers, body).await?;
                let snap = self.mutate(|c| {
                    c.routes.push(route);
                    Ok(())
                })?;
                json(
                    StatusCode::CREATED,
                    &serde_json::json!({ "routes": snap.config.routes.len(), "config_generation": snap.generation }),
                )
            }
            (&Method::PUT, ["admin", "v1", "routes", id]) => {
                let mut route: RouteConfig = Self::read_json(&parts.headers, body).await?;
                let snap = self.mutate(|c| {
                    let idx = (0..c.routes.len()).find(|&i| c.route_id(i) == *id).ok_or_else(|| not_found("route"))?;
                    route.name.get_or_insert_with(|| (*id).to_owned());
                    c.routes[idx] = route;
                    Ok(())
                })?;
                json(StatusCode::OK, &serde_json::json!({ "updated": id, "config_generation": snap.generation }))
            }
            (&Method::DELETE, ["admin", "v1", "routes", id]) => {
                let snap = self.mutate(|c| {
                    let idx = (0..c.routes.len()).find(|&i| c.route_id(i) == *id).ok_or_else(|| not_found("route"))?;
                    c.routes.remove(idx);
                    Ok(())
                })?;
                json(StatusCode::OK, &serde_json::json!({ "deleted": id, "config_generation": snap.generation }))
            }
            _ => Err(not_found("endpoint")),
        }
    }

    fn mutate<F>(&self, edit: F) -> Result<Arc<velox_core::Snapshot>, ApiError>
    where
        F: FnOnce(&mut Config) -> Result<(), ApiError>,
    {
        let result = self.state.try_update(edit);
        self.metrics.config_reload(result.is_ok());
        result
    }

    /// The `/metrics` response (Prometheus text format); never fails.
    pub fn render_metrics(&self) -> Response<Full<Bytes>> {
        self.metrics_response().unwrap_or_else(|e| plain(e.status, "text/plain", format!("{}\n", e.message)))
    }

    fn metrics_response(&self) -> ApiResult {
        self.metrics.collect_snapshot(&self.state.load());
        let text =
            self.metrics.render().map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        Ok(plain(StatusCode::OK, "text/plain; version=0.0.4; charset=utf-8", text))
    }
}

fn not_found(what: &str) -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, format!("{what} not found"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("127.0.0.1%3A8080").as_deref(), Some("127.0.0.1:8080"));
        assert_eq!(percent_decode("unix%3A%2Frun%2Fa.sock").as_deref(), Some("unix:/run/a.sock"));
        assert_eq!(percent_decode("plain").as_deref(), Some("plain"));
        assert!(percent_decode("bad%zz").is_none());
        assert!(percent_decode("trunc%4").is_none());
    }

    #[test]
    fn constant_time_compare() {
        assert!(secure_eq(b"secret", b"secret"));
        assert!(!secure_eq(b"secret", b"secreT"));
        assert!(!secure_eq(b"secret", b"secret2"));
        assert!(!secure_eq(b"", b"x"));
    }

    #[test]
    fn loopback_host_detection() {
        for ok in ["localhost", "localhost:9901", "127.0.0.1:9901", "[::1]:9901", "127.0.0.2"] {
            assert!(is_loopback_host(ok), "{ok}");
        }
        for bad in ["evil.com", "evil.com:9901", "10.0.0.1", "localhost.evil.com", ""] {
            assert!(!is_loopback_host(bad), "{bad}");
        }
    }
}
