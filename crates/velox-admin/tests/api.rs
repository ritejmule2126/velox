//! Admin API behaviour, including its security gates.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use velox_admin::{AdminApi, Reloader};
use velox_core::{Config, SharedState};
use velox_telemetry::Metrics;

const CFG: &str = r#"
[server]
http_addr = "127.0.0.1:8080"
[[upstream]]
name = "app"
backends = [{ addr = "127.0.0.1:3001" }, { addr = "127.0.0.1:3002" }]
[[upstream]]
name = "other"
backends = [{ addr = "127.0.0.1:3003" }]
[[route]]
name = "web"
hosts = ["example.test"]
upstream = "app"
[[route]]
path_prefix = "/other"
upstream = "other"
"#;

struct FakeReloader {
    state: Arc<SharedState>,
    calls: AtomicU64,
}

impl Reloader for FakeReloader {
    fn reload(&self) -> Result<u64, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let cfg = Config::from_toml_str(CFG).map_err(|e| e.to_string())?;
        self.state.apply(cfg).map(|s| s.generation).map_err(|e| e.to_string())
    }
}

struct Fixture {
    api: Arc<AdminApi>,
    state: Arc<SharedState>,
    reloader: Arc<FakeReloader>,
}

fn fixture(token: Option<&str>) -> Fixture {
    let state = SharedState::new(Config::from_toml_str(CFG).unwrap()).unwrap();
    let reloader = Arc::new(FakeReloader { state: Arc::clone(&state), calls: AtomicU64::new(0) });
    let api = AdminApi::new(
        Arc::clone(&state),
        Arc::new(Metrics::new().unwrap()),
        Arc::clone(&reloader) as Arc<dyn Reloader>,
        token.map(str::to_owned),
    );
    Fixture { api, state, reloader }
}

const LOCAL: &str = "127.0.0.1:50000";

async fn call(f: &Fixture, method: Method, path: &str, body: Option<Value>) -> (StatusCode, Value, String) {
    request(f, LOCAL, method, path, body, &[("host", "127.0.0.1:9901")]).await
}

async fn request(
    f: &Fixture,
    peer: &str,
    method: Method,
    path: &str,
    body: Option<Value>,
    headers: &[(&str, &str)],
) -> (StatusCode, Value, String) {
    let mut b = Request::builder().method(method).uri(path);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let req = match body {
        Some(v) => b.header("content-type", "application/json").body(Full::new(Bytes::from(v.to_string()))).unwrap(),
        None => b.body(Full::new(Bytes::new())).unwrap(),
    };
    let resp = f.api.handle(peer.parse::<SocketAddr>().unwrap(), req).await;
    let status = resp.status();
    let text = String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    let json = serde_json::from_str(&text).unwrap_or(Value::Null);
    (status, json, text)
}

#[tokio::test]
async fn security_gates() {
    let f = fixture(None);
    // non-loopback peer
    let (s, _, _) = request(&f, "10.0.0.5:1234", Method::GET, "/admin/v1/status", None, &[("host", "127.0.0.1")]).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // DNS-rebinding style Host
    let (s, _, _) = request(&f, LOCAL, Method::GET, "/admin/v1/status", None, &[("host", "evil.example:9901")]).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // browser-originated
    for h in [("origin", "https://evil.example"), ("sec-fetch-site", "cross-site")] {
        let (s, _, _) = request(&f, LOCAL, Method::POST, "/admin/v1/reload", None, &[("host", "localhost"), h]).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{h:?}");
    }
    assert_eq!(f.reloader.calls.load(Ordering::SeqCst), 0);
    // JSON content type is mandatory for bodies
    let req = Request::builder()
        .method(Method::POST)
        .uri("/admin/v1/routes")
        .header("host", "localhost")
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from("{}")))
        .unwrap();
    assert_eq!(f.api.handle(LOCAL.parse().unwrap(), req).await.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn bearer_token_is_enforced_when_configured() {
    let f = fixture(Some("s3cret"));
    let (s, _, _) = call(&f, Method::GET, "/admin/v1/status", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _, _) = request(
        &f,
        LOCAL,
        Method::GET,
        "/admin/v1/status",
        None,
        &[("host", "localhost"), ("authorization", "Bearer wrong")],
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, body, _) = request(
        &f,
        LOCAL,
        Method::GET,
        "/admin/v1/status",
        None,
        &[("host", "localhost"), ("authorization", "Bearer s3cret")],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["config_generation"], 1);
}

#[tokio::test]
async fn inspect_upstreams_and_drain_backends() {
    let f = fixture(None);
    let (s, body, _) = call(&f, Method::GET, "/admin/v1/upstreams", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 2);
    assert_eq!(body[0]["name"], "app");
    assert_eq!(body[0]["backends"][0]["available"], true);

    let (s, body, _) = call(&f, Method::POST, "/admin/v1/upstreams/app/backends/127.0.0.1%3A3001/drain", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["draining"], true);
    assert_eq!(body["available"], false);
    assert!(f.state.load().upstreams["app"].backends[0].is_draining());

    let (_, body, _) = call(&f, Method::GET, "/admin/v1/upstreams/app", None).await;
    assert_eq!(body["backends"][0]["draining"], true);

    let (s, body, _) = call(&f, Method::POST, "/admin/v1/upstreams/app/backends/127.0.0.1%3A3001/undrain", None).await;
    assert_eq!((s, &body["available"]), (StatusCode::OK, &json!(true)));

    let (s, _, _) = call(&f, Method::POST, "/admin/v1/upstreams/app/backends/127.0.0.1%3A9/drain", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _, _) = call(&f, Method::POST, "/admin/v1/upstreams/nope/backends/x/drain", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _, _) = call(&f, Method::POST, "/admin/v1/upstreams/app/backends/127.0.0.1%3A3001/explode", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn reset_clears_ejection_and_health() {
    let f = fixture(None);
    let b = Arc::clone(&f.state.load().upstreams["app"].backends[1]);
    b.set_healthy(false);
    b.eject_until(velox_core::clock::now_ms() + 60_000);
    let (s, body, _) = call(&f, Method::POST, "/admin/v1/upstreams/app/backends/127.0.0.1%3A3002/reset", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["available"], true);
}

#[tokio::test]
async fn route_crud_updates_the_live_snapshot_atomically() {
    let f = fixture(None);
    let (_, body, _) = call(&f, Method::GET, "/admin/v1/routes", None).await;
    assert_eq!(body[0]["id"], "web");
    assert_eq!(body[1]["id"], "route-1");

    // add
    let (s, _, _) = call(
        &f,
        Method::POST,
        "/admin/v1/routes",
        Some(json!({ "name": "api", "hosts": ["api.test"], "upstream": "other" })),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    let snap = f.state.load();
    assert_eq!(snap.generation, 2);
    assert_eq!(snap.router.find("api.test", "/").unwrap().upstream.name.as_ref(), "other");

    // replace one
    let (s, _, _) =
        call(&f, Method::PUT, "/admin/v1/routes/api", Some(json!({ "hosts": ["api.test"], "upstream": "app" }))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(f.state.load().router.find("api.test", "/").unwrap().upstream.name.as_ref(), "app");
    assert_eq!(f.state.load().config.routes[2].name.as_deref(), Some("api"), "id is preserved");

    // delete
    let (s, _, _) = call(&f, Method::DELETE, "/admin/v1/routes/api", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(f.state.load().router.find("api.test", "/").is_none(), "deleted route no longer matches");
    let (s, _, _) = call(&f, Method::DELETE, "/admin/v1/routes/api", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // replace all
    let (s, body, _) = call(&f, Method::PUT, "/admin/v1/routes", Some(json!([{ "upstream": "other" }]))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["routes"], 1);
    assert_eq!(f.state.load().router.len(), 1);
}

#[tokio::test]
async fn invalid_changes_are_rejected_and_do_not_disturb_the_live_config() {
    let f = fixture(None);
    let gen = f.state.load().generation;
    let (s, body, _) = call(&f, Method::POST, "/admin/v1/routes", Some(json!({ "upstream": "does-not-exist" }))).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body["error"].as_str().unwrap().contains("unknown upstream"));
    let (s, _, _) =
        call(&f, Method::POST, "/admin/v1/routes", Some(json!({ "upstream": "app", "bogus_field": 1 }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _, _) = call(&f, Method::PUT, "/admin/v1/routes/missing", Some(json!({ "upstream": "app" }))).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(f.state.load().generation, gen);
}

#[tokio::test]
async fn upstream_upsert_and_guarded_delete() {
    let f = fixture(None);
    // add a brand-new upstream
    let up = json!({ "name": "fresh", "algorithm": "p2c", "backends": [{ "addr": "127.0.0.1:4000", "weight": 3 }] });
    let (s, body, _) = call(&f, Method::PUT, "/admin/v1/upstreams/fresh", Some(up.clone())).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(body["algorithm"], "p2c");
    // name mismatch
    let (s, _, _) = call(&f, Method::PUT, "/admin/v1/upstreams/other-name", Some(up)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // referenced upstream cannot be removed
    let (s, _, _) = call(&f, Method::DELETE, "/admin/v1/upstreams/app", None).await;
    assert_eq!(s, StatusCode::CONFLICT);
    // unreferenced one can
    let (s, _, _) = call(&f, Method::DELETE, "/admin/v1/upstreams/fresh", None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = call(&f, Method::DELETE, "/admin/v1/upstreams/fresh", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // changing backends of a live upstream keeps unchanged backends' runtime state
    let kept = Arc::clone(&f.state.load().upstreams["app"].backends[1]);
    kept.set_draining(true);
    let new_app = json!({ "name": "app", "backends": [{ "addr": "127.0.0.1:3002" }, { "addr": "127.0.0.1:3009" }] });
    let (s, _, _) = call(&f, Method::PUT, "/admin/v1/upstreams/app", Some(new_app)).await;
    assert_eq!(s, StatusCode::OK);
    let after = f.state.load();
    assert!(Arc::ptr_eq(&kept, &after.upstreams["app"].backends[0]), "same backend keeps its state");
    assert!(after.upstreams["app"].backends[0].is_draining());
}

#[tokio::test]
async fn reload_and_observability_endpoints() {
    let f = fixture(None);
    let (s, body, _) = call(&f, Method::POST, "/admin/v1/reload", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["config_generation"], 2);
    assert_eq!(f.reloader.calls.load(Ordering::SeqCst), 1);

    let (s, body, _) = call(&f, Method::GET, "/admin/v1/config", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["upstream"][0]["name"], "app");

    let (s, _, text) = call(&f, Method::GET, "/metrics", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(text.contains("velox_config_generation 2"), "{text}");
    assert!(text.contains("velox_upstream_backend_healthy{backend=\"127.0.0.1:3001\",upstream=\"app\"} 1"), "{text}");
    assert!(text.contains("velox_config_reloads_total{result=\"ok\"} 1"), "{text}");

    let (s, _, text) = call(&f, Method::GET, "/healthz", None).await;
    assert_eq!((s, text.as_str()), (StatusCode::OK, "ok\n"));
    let (s, _, _) = call(&f, Method::GET, "/nope", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn real_listener_refuses_non_loopback_and_serves_loopback() {
    use tokio_util::sync::CancellationToken;
    let f = fixture(None);
    let cancel = CancellationToken::new();
    let err = velox_admin::serve("0.0.0.0:0".parse().unwrap(), Arc::clone(&f.api), cancel.clone()).await.unwrap_err();
    assert!(err.to_string().contains("loopback"));

    let (addr, handle) =
        velox_admin::serve("127.0.0.1:0".parse().unwrap(), Arc::clone(&f.api), cancel.clone()).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
    c.write_all(format!("GET /admin/v1/status HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut out = String::new();
    c.read_to_string(&mut out).await.unwrap();
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert!(out.contains("config_generation"));
    cancel.cancel();
    handle.await.unwrap();

    // The metrics-only listener may be public but exposes nothing else.
    let cancel = CancellationToken::new();
    let (maddr, handle) =
        velox_admin::serve_metrics("127.0.0.1:0".parse().unwrap(), Arc::clone(&f.api), cancel.clone()).await.unwrap();
    for (path, expect) in [("/metrics", "200"), ("/admin/v1/config", "404")] {
        let mut c = tokio::net::TcpStream::connect(maddr).await.unwrap();
        c.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        let mut out = String::new();
        c.read_to_string(&mut out).await.unwrap();
        assert!(out.contains(&format!(" {expect} ")), "{path}: {out}");
    }
    cancel.cancel();
    handle.await.unwrap();
}

// ---------------- response cache endpoints ----------------

use std::sync::Mutex;
use velox_core::cache_admin::{CacheAdmin, CacheStats, PurgeRequest};

#[derive(Default)]
struct FakeCache {
    purges: Mutex<Vec<PurgeRequest>>,
}

impl CacheAdmin for FakeCache {
    fn purge(&self, request: &PurgeRequest) -> usize {
        self.purges.lock().unwrap().push(request.clone());
        7
    }
    fn stats(&self) -> CacheStats {
        CacheStats {
            entries: 3,
            bytes: 4096,
            max_bytes: 1 << 20,
            hits: 10,
            misses: 4,
            evictions: 1,
            stale_served: 2,
            coalesced: 5,
        }
    }
}

fn cache_fixture() -> (Fixture, Arc<FakeCache>) {
    let f = fixture(None);
    let cache = Arc::new(FakeCache::default());
    let api = AdminApi::with_cache(
        Arc::clone(&f.state),
        Arc::new(Metrics::new().unwrap()),
        Arc::clone(&f.reloader) as Arc<dyn Reloader>,
        None,
        Some(Arc::clone(&cache) as Arc<dyn CacheAdmin>),
    );
    (Fixture { api, ..f }, cache)
}

#[tokio::test]
async fn cache_endpoints_report_stats_and_forward_purges() {
    let (f, cache) = cache_fixture();
    let (status, v, _) = call(&f, Method::GET, "/admin/v1/cache", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        (v["entries"].as_u64(), v["hits"].as_u64(), v["max_bytes"].as_u64()),
        (Some(3), Some(10), Some(1 << 20))
    );

    let body = json!({ "route": "r1", "path_prefix": "/static/" });
    let (status, v, _) = call(&f, Method::POST, "/admin/v1/cache/purge", Some(body)).await;
    assert_eq!((status, v["purged"].as_u64()), (StatusCode::OK, Some(7)));
    let seen = cache.purges.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        (seen[0].route.as_deref(), seen[0].path_prefix.as_deref(), seen[0].all),
        (Some("r1"), Some("/static/"), false)
    );

    // Nothing selected, or a typo: refused, and the cache is never asked.
    for bad in [json!({}), json!({ "all": false }), json!({ "alll": true })] {
        let (status, _, text) = call(&f, Method::POST, "/admin/v1/cache/purge", Some(bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    }
    assert_eq!(cache.purges.lock().unwrap().len(), 1);
    // JSON is required, like every admin write.
    let (status, ..) =
        request(&f, LOCAL, Method::POST, "/admin/v1/cache/purge", None, &[("host", "127.0.0.1:9901")]).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn cache_endpoints_are_404_without_a_cache_and_guarded_like_the_rest() {
    let f = fixture(None);
    assert_eq!(call(&f, Method::GET, "/admin/v1/cache", None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        call(&f, Method::POST, "/admin/v1/cache/purge", Some(json!({ "all": true }))).await.0,
        StatusCode::NOT_FOUND
    );
    // Purging is a write: the usual loopback / token / CSRF rules apply.
    let (f, cache) = cache_fixture();
    let (status, ..) = request(
        &f,
        "10.0.0.1:5000",
        Method::POST,
        "/admin/v1/cache/purge",
        Some(json!({ "all": true })),
        &[("host", "127.0.0.1:9901")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, ..) = request(
        &f,
        LOCAL,
        Method::POST,
        "/admin/v1/cache/purge",
        Some(json!({ "all": true })),
        &[("host", "127.0.0.1:9901"), ("origin", "https://evil.test")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "browser-originated purge refused");
    assert!(cache.purges.lock().unwrap().is_empty());
}

#[tokio::test]
async fn logo_endpoints_serve_transparent_and_dark_svgs() {
    let f = fixture(None);
    for path in ["/favicon.svg", "/admin/v1/logo.svg"] {
        let (status, _, text) = call(&f, Method::GET, path, None).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(text.starts_with("<svg ") && !text.contains("fill=\"#0B0F19\""), "{path}: {text}");
    }
    let (status, _, text) = call(&f, Method::GET, "/admin/v1/logo-dark.svg", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(text.starts_with("<svg ") && text.contains("fill=\"#0B0F19\""));
}
