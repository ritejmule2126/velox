//! The response cache through the full app: admin purge API and every protocol.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::BodyExt;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use support::*;
use velox_cli::App;
use velox_core::Config;

fn counting(hits: Arc<AtomicUsize>) -> Handler {
    handler(move |req| {
        let n = hits.fetch_add(1, Ordering::SeqCst) + 1;
        async move {
            let mut r = text(format!("n={n} path={}\n", req.uri()).repeat(200));
            r.headers_mut().insert("cache-control", "max-age=300".parse().unwrap());
            r.headers_mut().insert("content-type", "text/plain".parse().unwrap());
            r
        }
    })
}

async fn plain_app(backend: std::net::SocketAddr, extra: &str) -> App {
    let toml = format!(
        "[server]\nhttp_addr = \"127.0.0.1:0\"\ndrain_timeout = \"1s\"\n[admin]\naddr = \"127.0.0.1:0\"\n{extra}\n\
         [[upstream]]\nname = \"app\"\nbackends = [{{ addr = \"{backend}\" }}]\n\
         [[route]]\nname = \"site\"\nupstream = \"app\"\ncache = {{}}\n"
    );
    App::start(Config::from_toml_str(&toml).unwrap(), None).await.unwrap()
}

fn header(head: &str, name: &str) -> String {
    head.lines()
        .find_map(|l| l.to_ascii_lowercase().strip_prefix(&format!("{name}:")).map(|v| v.trim().to_owned()))
        .unwrap_or_default()
}

#[tokio::test]
async fn the_admin_api_reports_and_purges_the_cache() {
    let hits = Arc::new(AtomicUsize::new(0));
    let backend = Mock::start(counting(Arc::clone(&hits))).await;
    let app = plain_app(backend.addr, "").await;
    let (http, adm) = (app.running.http_addr.unwrap(), app.admin_addr.unwrap());
    let state = |path: &'static str| async move { header(&plain(http, path, "").await.1, "x-velox-cache") };

    for p in ["/static/a.js", "/static/b.js", "/api/users?page=1"] {
        assert_eq!(state(p).await, "miss", "{p}");
        assert_eq!(state(p).await, "hit", "{p}");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 3);
    let (status, stats) = admin(adm, "GET", "/admin/v1/cache", None).await;
    assert_eq!(status, 200);
    assert_eq!(
        (stats["entries"].as_u64(), stats["hits"].as_u64(), stats["misses"].as_u64()),
        (Some(3), Some(3), Some(3))
    );
    assert!(stats["bytes"].as_u64().unwrap() > 0);

    // An empty request must never mean "purge everything".
    for body in [json!({}), json!({ "all": false })] {
        let (status, v) = admin(adm, "POST", "/admin/v1/cache/purge", Some(body)).await;
        assert_eq!(status, 400, "{v}");
    }
    assert_eq!(admin(adm, "GET", "/admin/v1/cache", None).await.1["entries"], 3);
    // Unknown selector fields are typos, not wildcards.
    assert_eq!(admin(adm, "POST", "/admin/v1/cache/purge", Some(json!({ "pth": "/x" }))).await.0, 400);

    // Precise purges.
    let (status, v) = admin(adm, "POST", "/admin/v1/cache/purge", Some(json!({ "path_prefix": "/static/" }))).await;
    assert_eq!((status, v["purged"].as_u64()), (200, Some(2)));
    assert_eq!(state("/static/a.js").await, "miss", "purged");
    assert_eq!(state("/api/users?page=1").await, "hit", "untouched");
    let (_, v) =
        admin(adm, "POST", "/admin/v1/cache/purge", Some(json!({ "route": "site", "path": "/api/users?page=1" })))
            .await;
    assert_eq!(v["purged"], 1);
    let (_, v) = admin(adm, "POST", "/admin/v1/cache/purge", Some(json!({ "route": "nope" }))).await;
    assert_eq!(v["purged"], 0);
    let (_, v) = admin(adm, "POST", "/admin/v1/cache/purge", Some(json!({ "host": "example.test" }))).await;
    assert_eq!(v["purged"], 1, "the host the tests send is example.test");
    // Everything.
    state("/x").await;
    state("/y").await;
    let (_, v) = admin(adm, "POST", "/admin/v1/cache/purge", Some(json!({ "all": true }))).await;
    assert_eq!(v["purged"], 2);
    let stats = admin(adm, "GET", "/admin/v1/cache", None).await.1;
    assert_eq!((stats["entries"].as_u64(), stats["bytes"].as_u64()), (Some(0), Some(0)));
    let m = app.metrics.render().unwrap();
    assert!(m.contains("velox_cache_purged_total 6"), "{m}");
    assert!(m.contains("velox_cache_entries 0") && m.contains("velox_cache_bytes 0"), "{m}");
    assert!(app.shutdown().await);
}

#[tokio::test]
async fn cached_responses_are_served_identically_over_http2_and_http3() {
    let hits = Arc::new(AtomicUsize::new(0));
    let backend = Mock::start(counting(Arc::clone(&hits))).await;
    let dir = tempfile::tempdir().unwrap();
    let (cert, key, der) = write_cert(dir.path());
    let toml = format!(
        "[server]\nhttps_addr = \"127.0.0.1:0\"\nh3 = true\ndrain_timeout = \"2s\"\n[admin]\naddr = \"127.0.0.1:0\"\n\
         [compression]\nenabled = true\n\
         [[tls.certs]]\ncert_file = \"{}\"\nkey_file = \"{}\"\n\
         [[upstream]]\nname = \"app\"\nbackends = [{{ addr = \"{}\" }}]\n[[route]]\nupstream = \"app\"\ncache = {{}}\n",
        cert.display(),
        key.display(),
        backend.addr
    );
    let app = App::start(Config::from_toml_str(&toml).unwrap(), None).await.unwrap();
    let (tcp, udp) = (app.running.https_addr.unwrap(), app.running.h3_addr.unwrap());

    // Fill over HTTP/1.1, then hit over HTTP/2 and HTTP/3 (and again over h1).
    let first = https1(tcp, &der, Method::GET, "/doc", Bytes::new()).await;
    assert_eq!(first.headers["x-velox-cache"], "miss");
    let h2 = https2(tcp, &der, Method::GET, "/doc", Bytes::new()).await;
    assert_eq!((h2.status, h2.headers["x-velox-cache"].to_str().unwrap()), (StatusCode::OK, "hit"));
    assert_eq!(h2.body, first.body);
    let h3 = http3(udp, &der, Method::GET, "/doc", Bytes::new()).await;
    assert_eq!((h3.status, h3.headers["x-velox-cache"].to_str().unwrap()), (StatusCode::OK, "hit"));
    assert_eq!(h3.body, first.body);
    assert_eq!(hits.load(Ordering::SeqCst), 1, "one backend request served all three protocols");
    assert!(h2.headers.contains_key("age"));

    // A compressing HTTP/2 client gets the cached object compressed, once per request.
    let mut conn = h2_connection(tcp, &der).await;
    let req = http::Request::builder()
        .uri("https://localhost/doc")
        .header("accept-encoding", "gzip")
        .body(http_body_util::Full::new(Bytes::new()))
        .unwrap();
    let resp = conn.send_request(req).await.unwrap();
    assert_eq!(resp.headers()["x-velox-cache"], "hit");
    assert_eq!(resp.headers()["content-encoding"], "gzip");
    let compressed = resp.into_body().collect().await.unwrap().to_bytes();
    let mut plain_out = Vec::new();
    std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&compressed[..]), &mut plain_out).unwrap();
    assert_eq!(plain_out, first.body.to_vec());
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // A conditional request whose validator cannot match (no `Last-Modified` was
    // stored) gets the full response, not a bogus 304.
    let req = http::Request::builder()
        .uri("https://localhost/doc")
        .header("if-modified-since", "Fri, 01 Jan 2100 00:00:00 GMT")
        .body(http_body_util::Full::new(Bytes::new()))
        .unwrap();
    assert_eq!(conn.send_request(req).await.unwrap().status(), StatusCode::OK);
    assert!(app.shutdown().await);
}

#[tokio::test]
async fn http_and_https_responses_are_cached_separately() {
    // The backend sees `X-Forwarded-Proto` per listener and may answer differently
    // (absolute URLs, redirects), so the two must never share an entry.
    let backend = Mock::start(handler(|req| async move {
        let proto = req.headers().get("x-forwarded-proto").map_or("?", |v| v.to_str().unwrap()).to_owned();
        let mut r = text(format!("seen over {proto}"));
        r.headers_mut().insert("cache-control", "max-age=300".parse().unwrap());
        r
    }))
    .await;
    let dir = tempfile::tempdir().unwrap();
    let (cert, key, der) = write_cert(dir.path());
    let toml = format!(
        "[server]\nhttp_addr = \"127.0.0.1:0\"\nhttps_addr = \"127.0.0.1:0\"\nh3 = false\ndrain_timeout = \"2s\"\n\
         [admin]\naddr = \"127.0.0.1:0\"\n[[tls.certs]]\ncert_file = \"{}\"\nkey_file = \"{}\"\n\
         [[upstream]]\nname = \"app\"\nbackends = [{{ addr = \"{}\" }}]\n[[route]]\nupstream = \"app\"\ncache = {{}}\n",
        cert.display(),
        key.display(),
        backend.addr
    );
    let app = App::start(Config::from_toml_str(&toml).unwrap(), None).await.unwrap();
    let (http, https) = (app.running.http_addr.unwrap(), app.running.https_addr.unwrap());
    let over_http = || async move { plain(http, "/same", "").await };
    let over_tls = || async { https1(https, &der, Method::GET, "/same", Bytes::new()).await };

    let (_, head, body) = over_http().await;
    assert_eq!((header(&head, "x-velox-cache").as_str(), body.as_str()), ("miss", "seen over http"));
    let r = over_tls().await;
    assert_eq!(r.headers["x-velox-cache"], "miss", "the https request must not be served the http copy");
    assert_eq!(r.text(), "seen over https");
    // Each is then served from its own entry.
    let (_, head, body) = over_http().await;
    assert_eq!((header(&head, "x-velox-cache").as_str(), body.as_str()), ("hit", "seen over http"));
    let r = over_tls().await;
    assert_eq!((r.headers["x-velox-cache"].to_str().unwrap(), r.text().as_str()), ("hit", "seen over https"));
    assert_eq!(backend.hits(), 2);
    assert!(app.shutdown().await);
}
