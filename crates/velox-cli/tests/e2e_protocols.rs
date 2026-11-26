//! HTTP/1.1, HTTP/2 and HTTP/3 through the full Velox stack, with real TLS.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use bytes::Bytes;
use http::{Method, StatusCode, Version};
use http_body_util::BodyExt;
use std::sync::Arc;
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use velox_cli::App;
use velox_core::Config;

fn describe_request() -> Handler {
    handler(|req| async move {
        let (parts, body) = req.into_parts();
        let body = body.collect().await.unwrap().to_bytes();
        let mut out = format!("{} {} body={}\n", parts.method, parts.uri, body.len());
        for (k, v) in &parts.headers {
            out.push_str(&format!("{k}: {}\n", v.to_str().unwrap_or("?")));
        }
        text(out)
    })
}

async fn start_tls_app(
    extra: &str,
    upstream: &Mock,
) -> (App, rustls::pki_types::CertificateDer<'static>, tempfile::TempDir) {
    start_tls_app_with("", extra, upstream.addr).await
}

async fn start_tls_app_with(
    upstream_extra: &str,
    extra: &str,
    backend: std::net::SocketAddr,
) -> (App, rustls::pki_types::CertificateDer<'static>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key, der) = write_cert(dir.path());
    let toml = format!(
        "[server]\nhttps_addr = \"127.0.0.1:0\"\nh3 = true\ndrain_timeout = \"2s\"\n\
         [admin]\naddr = \"127.0.0.1:0\"\n\
         [[tls.certs]]\ncert_file = \"{}\"\nkey_file = \"{}\"\n\
         [[upstream]]\nname = \"app\"\n{upstream_extra}\nbackends = [{{ addr = \"{backend}\" }}]\n\
         [[route]]\nupstream = \"app\"\n{extra}",
        cert.display(),
        key.display(),
    );
    let app = App::start(Config::from_toml_str(&toml).unwrap(), None).await.unwrap();
    (app, der, dir)
}

#[tokio::test]
async fn http11_http2_and_http3_all_serve_the_same_site() {
    let backend = Mock::start(describe_request()).await;
    let (app, der, _dir) = start_tls_app("", &backend).await;
    let tcp = app.running.https_addr.unwrap();
    let udp = app.running.h3_addr.expect("HTTP/3 endpoint must be running");

    let r1 = https1(tcp, &der, Method::GET, "/hello?x=1", Bytes::new()).await;
    let r2 = https2(tcp, &der, Method::GET, "/hello?x=1", Bytes::new()).await;
    let r3 = http3(udp, &der, Method::GET, "/hello?x=1", Bytes::new()).await;

    assert_eq!(r1.version, Version::HTTP_11);
    assert_eq!(r2.version, Version::HTTP_2);
    assert_eq!(r3.version, Version::HTTP_3);
    for (name, r) in [("h1", &r1), ("h2", &r2), ("h3", &r3)] {
        assert_eq!(r.status, StatusCode::OK, "{name}");
        let t = r.text().to_ascii_lowercase();
        assert!(t.starts_with("get /hello?x=1 body=0"), "{name}: {t}");
        assert!(t.contains("x-forwarded-proto: https"), "{name}: {t}");
        assert!(t.contains("x-forwarded-for: 127.0.0.1"), "{name}: {t}");
        assert!(t.contains("x-request-id: "), "{name}: {t}");
        assert!(t.contains("forwarded: for=127.0.0.1;proto=https"), "{name}: {t}");
        assert!(!t.contains("\nconnection:"), "hop-by-hop must not leak upstream ({name}): {t}");
        assert!(r.headers.contains_key("x-request-id"), "{name}");
        assert_eq!(r.headers["strict-transport-security"], "max-age=31536000", "{name}");
        assert_eq!(r.headers["x-content-type-options"], "nosniff", "{name}");
    }
    // Smuggling-adjacent: absolute-form targets are refused outright.
    assert_eq!(https1_absolute_form(tcp, &der).await, StatusCode::BAD_REQUEST);

    // Alt-Svc advertises the *actual* QUIC port on TCP responses only.
    let alt = format!("h3=\":{}\"; ma=86400", udp.port());
    assert_eq!(r1.headers["alt-svc"], alt.as_str());
    assert_eq!(r2.headers["alt-svc"], alt.as_str());
    assert!(!r3.headers.contains_key("alt-svc"));

    // Bodies in every protocol.
    let payload = Bytes::from(vec![b'x'; 100_000]);
    for (name, r) in [
        ("h1", https1(tcp, &der, Method::POST, "/up", payload.clone()).await),
        ("h2", https2(tcp, &der, Method::POST, "/up", payload.clone()).await),
        ("h3", http3(udp, &der, Method::POST, "/up", payload.clone()).await),
    ] {
        assert_eq!(r.status, StatusCode::OK, "{name}");
        assert!(r.text().starts_with("POST /up body=100000"), "{name}: {}", &r.text()[..60.min(r.text().len())]);
    }

    // The protocol breakdown is visible in Prometheus.
    let m = app.metrics.render().unwrap();
    for proto in ["h1", "h2", "h3"] {
        assert!(
            m.lines()
                .any(|l| l.starts_with(&format!("velox_http_requests_total{{protocol=\"{proto}\",status=\"200\"}}"))),
            "missing {proto} counter:\n{m}"
        );
    }
    assert!(m.contains("velox_h3_enabled 1"));
    assert!(m.contains("velox_http_request_duration_seconds_bucket"));
    assert!(app.shutdown().await);
}

#[tokio::test]
async fn http2_multiplexes_many_concurrent_streams_on_one_connection() {
    let backend = Mock::start(handler(|req| async move {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        text(req.uri().path().to_owned())
    }))
    .await;
    let (app, der, _dir) = start_tls_app("", &backend).await;
    let send = h2_connection(app.running.https_addr.unwrap(), &der).await;
    let t0 = std::time::Instant::now();
    let mut tasks = Vec::new();
    for i in 0..50 {
        let mut s = send.clone();
        tasks.push(tokio::spawn(async move {
            let resp = s.send_request(build(Method::GET, &format!("/s{i}"), Bytes::new())).await.unwrap();
            let status = resp.status();
            (i, status, resp.into_body().collect().await.unwrap().to_bytes())
        }));
    }
    for t in tasks {
        let (i, status, body) = t.await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, format!("/s{i}"));
    }
    assert!(t0.elapsed() < std::time::Duration::from_secs(3), "streams must run concurrently, took {:?}", t0.elapsed());
    assert!(app.shutdown().await);
}

#[tokio::test]
async fn limits_and_routing_errors_apply_on_every_protocol() {
    let backend = Mock::start(describe_request()).await;
    let (app, der, _dir) = start_tls_app(
        "[limits]\nmax_request_body_bytes = 1000\n[rate_limit]\nrequests_per_second = 0.5\nburst = 1000\n",
        &backend,
    )
    .await;
    let tcp = app.running.https_addr.unwrap();
    let udp = app.running.h3_addr.unwrap();
    let big = Bytes::from(vec![0u8; 2000]);
    assert_eq!(https1(tcp, &der, Method::POST, "/", big.clone()).await.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(https2(tcp, &der, Method::POST, "/", big.clone()).await.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(http3(udp, &der, Method::POST, "/", big).await.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(backend.hits(), 0, "oversized bodies are refused before reaching the backend");
    assert_eq!(https2(tcp, &der, Method::POST, "/", Bytes::from(vec![1u8; 900])).await.status, StatusCode::OK);
    assert!(app.shutdown().await);
}

#[tokio::test]
async fn rate_limiting_returns_429_over_http2_and_http3() {
    let backend = Mock::start(describe_request()).await;
    let (app, der, _dir) = start_tls_app("[rate_limit]\nrequests_per_second = 0.1\nburst = 2\n", &backend).await;
    let tcp = app.running.https_addr.unwrap();
    let udp = app.running.h3_addr.unwrap();
    // Burst of 2 is shared per client IP across protocols.
    assert_eq!(https2(tcp, &der, Method::GET, "/", Bytes::new()).await.status, StatusCode::OK);
    assert_eq!(http3(udp, &der, Method::GET, "/", Bytes::new()).await.status, StatusCode::OK);
    let limited = https2(tcp, &der, Method::GET, "/", Bytes::new()).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.headers.contains_key("retry-after"));
    assert_eq!(http3(udp, &der, Method::GET, "/", Bytes::new()).await.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(app.metrics.render().unwrap().contains("velox_rate_limited_total{route=\"route-0\"} 2"));
    assert!(app.shutdown().await);
}

#[tokio::test]
async fn tls_handshake_failures_are_counted_and_do_not_hurt_the_listener() {
    let backend = Mock::start(describe_request()).await;
    let (app, der, _dir) = start_tls_app("", &backend).await;
    let tcp = app.running.https_addr.unwrap();
    // Plaintext HTTP spoken to the TLS port.
    let mut s = tokio::net::TcpStream::connect(tcp).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), s.read_to_end(&mut buf)).await;
    eventually(5, "handshake error metric", || async {
        app.metrics.render().unwrap().contains("velox_tls_handshake_errors_total{reason=")
    })
    .await;
    // A stalled handshake times out instead of pinning a connection slot.
    assert_eq!(https2(tcp, &der, Method::GET, "/", Bytes::new()).await.status, StatusCode::OK);
    assert!(app.shutdown().await);
}

#[tokio::test]
async fn tls_certificates_hot_reload_without_dropping_the_listener() {
    let backend = Mock::start(describe_request()).await;
    let dir = tempfile::tempdir().unwrap();
    let (cert, key, der1) = write_cert(dir.path());
    let cfg_path = dir.path().join("velox.toml");
    let toml = format!(
        "[server]\nhttps_addr = \"127.0.0.1:0\"\nh3 = false\n[admin]\naddr = \"127.0.0.1:0\"\n\
         [[tls.certs]]\ncert_file = \"{}\"\nkey_file = \"{}\"\n\
         [[upstream]]\nname=\"app\"\nbackends=[{{addr=\"{}\"}}]\n[[route]]\nupstream=\"app\"\n",
        cert.display(),
        key.display(),
        backend.addr
    );
    std::fs::write(&cfg_path, &toml).unwrap();
    let app = App::start(Config::load(&cfg_path).unwrap(), Some(cfg_path.clone())).await.unwrap();
    let tcp = app.running.https_addr.unwrap();
    assert_eq!(https2(tcp, &der1, Method::GET, "/", Bytes::new()).await.status, StatusCode::OK);

    // Rotate the certificate on disk, then reload.
    let (_, _, der2) = write_cert(dir.path());
    assert_ne!(der1.as_ref(), der2.as_ref());
    let reloader = Arc::clone(&app.reloader);
    tokio::task::spawn_blocking(move || reloader.reload()).await.unwrap().unwrap();
    assert_eq!(https2(tcp, &der2, Method::GET, "/", Bytes::new()).await.status, StatusCode::OK, "new cert is served");
    // The old certificate no longer validates.
    let tcp_stream = tokio::net::TcpStream::connect(tcp).await.unwrap();
    let c = tokio_rustls::TlsConnector::from(client_tls(&der1, &[b"h2"]));
    assert!(c.connect(rustls::pki_types::ServerName::try_from("localhost").unwrap(), tcp_stream).await.is_err());
    assert!(app.shutdown().await);
}

// ---------------- HTTP/3 request-body regressions ----------------

#[tokio::test]
async fn h3_trailers_only_request_forwards_its_trailers() {
    // Regression: when the first `recv_data()` is `None` (no data frames at
    // all) the trailers that follow were never polled, so they were dropped.
    let (backend, hits) = h2c_trailer_backend().await;
    let (app, der, _dir) = start_tls_app_with("protocol = \"h2c\"", "", backend).await;
    let mut client = h3_client(app.running.h3_addr.unwrap(), &der).await;
    let req = http::Request::builder().method("POST").uri("https://localhost/t").body(()).unwrap();
    let mut stream = client.send.send_request(req).await.unwrap();
    let mut trailers = http::HeaderMap::new();
    trailers.insert("x-checksum", "abc123".parse().unwrap());
    stream.send_trailers(trailers).await.unwrap();
    stream.finish().await.unwrap();
    let (status, body) = h3_read_response(&mut stream).await;
    let body = String::from_utf8_lossy(&body).into_owned();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("body=0"), "{body}");
    assert!(body.contains("trailer x-checksum=abc123"), "trailers must reach the backend: {body}");
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    client.close().await;
    assert!(app.shutdown().await);
}

#[tokio::test]
async fn h3_data_then_trailers_are_both_forwarded() {
    let (backend, _) = h2c_trailer_backend().await;
    let (app, der, _dir) = start_tls_app_with("protocol = \"h2c\"", "", backend).await;
    let mut client = h3_client(app.running.h3_addr.unwrap(), &der).await;
    let req = http::Request::builder().method("POST").uri("https://localhost/t").body(()).unwrap();
    let mut stream = client.send.send_request(req).await.unwrap();
    stream.send_data(Bytes::from_static(b"hello")).await.unwrap();
    let mut trailers = http::HeaderMap::new();
    trailers.insert("x-end", "done".parse().unwrap());
    stream.send_trailers(trailers).await.unwrap();
    stream.finish().await.unwrap();
    let (status, body) = h3_read_response(&mut stream).await;
    let body = String::from_utf8_lossy(&body).into_owned();
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("body=5") && body.contains("trailer x-end=done"), "{body}");
    client.close().await;
    assert!(app.shutdown().await);
}

#[tokio::test]
async fn h3_content_length_must_match_the_bytes_actually_sent() {
    let backend = Mock::start(describe_request()).await;
    let (app, der, _dir) = start_tls_app("", &backend).await;
    let addr = app.running.h3_addr.unwrap();

    for (declared, sent, label) in [(3usize, 10usize, "more bytes than declared"), (10, 4, "stream closed early")] {
        let mut client = h3_client(addr, &der).await;
        let req = http::Request::builder()
            .method("POST")
            .uri("https://localhost/len")
            .header("content-length", declared.to_string())
            .body(())
            .unwrap();
        let mut stream = client.send.send_request(req).await.unwrap();
        stream.send_data(Bytes::from(vec![b'x'; sent])).await.unwrap();
        stream.finish().await.unwrap();
        let (status, _) = h3_read_response(&mut stream).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label}: must fail cleanly, not silently truncate");
        client.close().await;
    }
    assert_eq!(backend.hits(), 0, "a mismatched body must never be executed upstream");
    // The honest request still works.
    assert_eq!(http3(addr, &der, Method::POST, "/ok", Bytes::from_static(b"12345")).await.status, StatusCode::OK);
    assert_eq!(backend.hits(), 1);
    assert!(app.shutdown().await);
}

#[tokio::test]
async fn h3_stalled_request_body_gets_a_408_instead_of_a_silent_drop() {
    // Regression: the first body frame was awaited before the handler ran, and
    // a stall ended the stream with no HTTP response at all.
    let backend = Mock::start(describe_request()).await;
    let (app, der, _dir) = start_tls_app("[timeouts]\nrequest_body_idle = \"300ms\"\n", &backend).await;
    let mut client = h3_client(app.running.h3_addr.unwrap(), &der).await;
    let req = http::Request::builder()
        .method("POST")
        .uri("https://localhost/slow-upload")
        .header("content-length", "10")
        .body(())
        .unwrap();
    let mut stream = client.send.send_request(req).await.unwrap();
    // …and never send a single body byte.
    let t0 = std::time::Instant::now();
    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), stream.recv_response())
        .await
        .expect("the server must answer, not leave the stream hanging")
        .unwrap();
    assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
    assert!(t0.elapsed() < std::time::Duration::from_secs(3), "answered promptly: {:?}", t0.elapsed());
    assert_eq!(backend.hits(), 0);
    client.close().await;
    assert!(app.shutdown().await);
}

#[tokio::test]
async fn h3_requests_are_routed_while_the_body_is_still_arriving() {
    // The handler must not wait for the first body frame: an unroutable
    // request is refused immediately even though its body never starts.
    let backend = Mock::start(describe_request()).await;
    let toml = "[limits]\nmax_request_body_bytes = 5\n";
    let (app, der, _dir) = start_tls_app(toml, &backend).await;
    let mut client = h3_client(app.running.h3_addr.unwrap(), &der).await;
    let req = http::Request::builder()
        .method("POST")
        .uri("https://localhost/x")
        .header("content-length", "50")
        .body(())
        .unwrap();
    let mut stream = client.send.send_request(req).await.unwrap();
    let resp = tokio::time::timeout(std::time::Duration::from_secs(2), stream.recv_response())
        .await
        .expect("413 is decided from the headers alone")
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    client.close().await;
    assert!(app.shutdown().await);
}
