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

// ---------------- HTTP/3 body fast paths ----------------

#[tokio::test]
async fn h3_content_length_zero_spawns_no_body_pump() {
    let backend = Mock::start(describe_request()).await;
    // A long idle timeout: a lingering pump would outlive the whole test.
    let (app, der, _dir) = start_tls_app("[timeouts]\nrequest_body_idle = \"60s\"\n", &backend).await;
    let mut client = h3_client(app.running.h3_addr.unwrap(), &der).await;
    // Make sure the connection-level tasks exist before taking the baseline.
    let tasks = app.proxy.shutdown().tasks.clone();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let baseline = tasks.len();

    for round in 0..3 {
        let req = http::Request::builder()
            .method("POST")
            .uri("https://localhost/zero")
            .header("content-length", "0")
            .body(())
            .unwrap();
        let mut stream = client.send.send_request(req).await.unwrap();
        // Deliberately do NOT finish the stream: the server must neither wait for
        // a FIN nor park a task on it.
        let (status, body) = h3_read_response(&mut stream).await;
        let body = String::from_utf8_lossy(&body).into_owned();
        assert_eq!(status, StatusCode::OK, "round {round}: {body}");
        assert!(body.contains("POST /zero body=0"), "{body}");
        assert!(body.contains("content-length: 0"), "an empty body is framed explicitly: {body}");
        eventually(3, "request task to finish", || {
            let tasks = tasks.clone();
            async move { tasks.len() == baseline }
        })
        .await;
    }
    assert_eq!(backend.hits(), 3);
    client.close().await;
    assert!(app.shutdown().await);
}

#[tokio::test]
async fn h3_bodyless_get_and_streaming_uploads_are_not_delayed_or_mangled() {
    let backend = Mock::start(describe_request()).await;
    let (app, der, _dir) = start_tls_app("", &backend).await;
    let addr = app.running.h3_addr.unwrap();

    // GET / HEAD / DELETE without Content-Length: forwarded with no body framing at all.
    for m in [Method::GET, Method::DELETE, Method::OPTIONS] {
        let r = http3(addr, &der, m.clone(), "/probe", Bytes::new()).await;
        assert_eq!(r.status, StatusCode::OK, "{m}");
        let body = String::from_utf8_lossy(&r.body).into_owned();
        assert!(body.contains("body=0") && !body.contains("transfer-encoding"), "{m}: {body}");
    }

    // A POST with no Content-Length streams: a slow second chunk (longer than
    // any grace period) still arrives intact, in order, and the request is
    // forwarded chunked.
    let mut client = h3_client(addr, &der).await;
    let req = http::Request::builder().method("POST").uri("https://localhost/stream").body(()).unwrap();
    let mut stream = client.send.send_request(req).await.unwrap();
    stream.send_data(Bytes::from_static(b"first-")).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    stream.send_data(Bytes::from_static(b"second")).await.unwrap();
    stream.finish().await.unwrap();
    let (status, body) = h3_read_response(&mut stream).await;
    let body = String::from_utf8_lossy(&body).into_owned();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("POST /stream body=12"), "{body}");
    assert!(body.contains("transfer-encoding: chunked"), "{body}");
    client.close().await;

    // A POST that really has no body at all (FIN with the headers) still works.
    let r = http3(addr, &der, Method::POST, "/empty", Bytes::new()).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&r.body).contains("POST /empty body=0"));
    assert!(app.shutdown().await);
}

// ---------------- PROXY protocol in front of TLS ----------------

#[tokio::test]
async fn proxy_protocol_header_precedes_the_tls_handshake() {
    use velox_proxy::proxy_protocol::{encode_v1, encode_v2};
    let backend = Mock::start(describe_request()).await;
    let dir = tempfile::tempdir().unwrap();
    let (cert, key, der) = write_cert(dir.path());
    let toml = format!(
        "[server]\nhttps_addr = \"127.0.0.1:0\"\nh3 = false\ndrain_timeout = \"2s\"\n\
         proxy_protocol = true\nproxy_protocol_trusted = [\"127.0.0.0/8\"]\n[admin]\naddr = \"127.0.0.1:0\"\n\
         [[tls.certs]]\ncert_file = \"{}\"\nkey_file = \"{}\"\n\
         [[upstream]]\nname = \"app\"\nbackends = [{{ addr = \"{}\" }}]\n[[route]]\nupstream = \"app\"\n",
        cert.display(),
        key.display(),
        backend.addr
    );
    let app = App::start(Config::from_toml_str(&toml).unwrap(), None).await.unwrap();
    let addr = app.running.https_addr.unwrap();

    let request = |header: Vec<u8>, alpn: &'static [u8]| {
        let der = der.clone();
        async move {
            let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            tcp.write_all(&header).await.unwrap();
            let connector = tokio_rustls::TlsConnector::from(client_tls(&der, &[alpn]));
            let mut tls = connector
                .connect(rustls::pki_types::ServerName::try_from("localhost").unwrap(), tcp)
                .await
                .map_err(|e| e.to_string())?;
            tls.write_all(b"GET /tls HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.unwrap();
            let mut out = String::new();
            let _ = tls.read_to_string(&mut out).await;
            Ok::<_, String>(out)
        }
    };
    let (client, server) = ("203.0.113.77:40000".parse().unwrap(), "10.0.0.1:443".parse().unwrap());
    for (label, header) in [("v2", encode_v2(client, server, &[])), ("v1", encode_v1(client, server))] {
        let out = request(header, b"http/1.1").await.unwrap();
        assert!(out.starts_with("HTTP/1.1 200"), "{label}: {out}");
        assert!(out.contains("x-real-ip: 203.0.113.77"), "{label}: the real client reaches the backend: {out}");
        assert!(out.contains("x-forwarded-proto: https"), "{label}: {out}");
    }
    // Without the header, the TLS ClientHello is not a PROXY header: refused before any handshake.
    assert!(request(Vec::new(), b"http/1.1").await.is_err(), "unframed TLS must be refused");
    assert!(app.metrics.render().unwrap().contains("velox_proxy_protocol_errors_total{reason=\"invalid\"}"));
    assert!(app.shutdown().await);
}

// ---------------- response compression on every protocol ----------------

fn json_doc() -> Vec<u8> {
    "{\"id\": 42, \"name\": \"velox\", \"tags\": [\"edge\", \"proxy\"]}\n".repeat(400).into_bytes()
}

fn decode_body(encoding: &str, data: &[u8]) -> Vec<u8> {
    use std::io::Read;
    let mut out = Vec::new();
    match encoding {
        "gzip" => flate2::read::GzDecoder::new(data).read_to_end(&mut out).unwrap(),
        "br" => brotli::Decompressor::new(data, 4096).read_to_end(&mut out).unwrap(),
        "zstd" => zstd::stream::read::Decoder::new(data).unwrap().read_to_end(&mut out).unwrap(),
        other => panic!("unexpected encoding {other}"),
    };
    out
}

#[tokio::test]
async fn compression_works_identically_over_http1_http2_and_http3() {
    let doc = json_doc();
    let served = doc.clone();
    let backend = Mock::start(handler(move |_| {
        let served = served.clone();
        async move {
            let mut r = text(String::from_utf8(served).unwrap());
            r.headers_mut().insert("content-type", "application/json".parse().unwrap());
            r
        }
    }))
    .await;
    let dir = tempfile::tempdir().unwrap();
    let (cert, key, der) = write_cert(dir.path());
    let toml = format!(
        "[server]\nhttps_addr = \"127.0.0.1:0\"\nh3 = true\ndrain_timeout = \"2s\"\n[admin]\naddr = \"127.0.0.1:0\"\n\
         [compression]\nenabled = true\n\
         [[tls.certs]]\ncert_file = \"{}\"\nkey_file = \"{}\"\n\
         [[upstream]]\nname = \"app\"\nbackends = [{{ addr = \"{}\" }}]\n[[route]]\nupstream = \"app\"\n",
        cert.display(),
        key.display(),
        backend.addr
    );
    let app = App::start(Config::from_toml_str(&toml).unwrap(), None).await.unwrap();
    let (tcp_addr, h3_addr) = (app.running.https_addr.unwrap(), app.running.h3_addr.unwrap());

    // HTTP/2
    let mut h2 = h2_connection(tcp_addr, &der).await;
    for (accept, expect) in [("zstd, br, gzip", "zstd"), ("br, gzip", "br"), ("gzip", "gzip")] {
        let req = http::Request::builder()
            .uri("https://localhost/data.json")
            .header("accept-encoding", accept)
            .body(http_body_util::Full::new(Bytes::new()))
            .unwrap();
        let resp = h2.send_request(req).await.unwrap();
        assert_eq!(resp.version(), Version::HTTP_2);
        assert_eq!(resp.headers()["content-encoding"], expect);
        assert_eq!(resp.headers()["vary"], "Accept-Encoding");
        assert!(!resp.headers().contains_key("content-length"));
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(decode_body(expect, &body), doc, "h2 {expect}");
    }

    // HTTP/3
    let mut client = h3_client(h3_addr, &der).await;
    for (accept, expect) in [("br", "br"), ("zstd", "zstd")] {
        let req = http::Request::builder()
            .uri("https://localhost/data.json")
            .header("accept-encoding", accept)
            .body(())
            .unwrap();
        let mut stream = client.send.send_request(req).await.unwrap();
        stream.finish().await.unwrap();
        let resp = stream.recv_response().await.unwrap();
        assert_eq!(resp.headers()["content-encoding"], expect);
        let mut body = bytes::BytesMut::new();
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            use bytes::Buf;
            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
        assert_eq!(decode_body(expect, &body), doc, "h3 {expect}");
    }
    client.close().await;

    // HTTP/1.1 over TLS, with and without a usable Accept-Encoding.
    let r = https1(tcp_addr, &der, Method::GET, "/data.json", Bytes::new()).await;
    assert!(!r.headers.contains_key("content-encoding"), "no Accept-Encoding ⇒ identity");
    assert_eq!(r.headers["vary"], "Accept-Encoding");
    assert_eq!(r.body, doc);

    let metrics = app.metrics.render().unwrap();
    for enc in ["zstd", "br", "gzip"] {
        assert!(
            metrics.contains(&format!("velox_compression_responses_total{{encoding=\"{enc}\"}}")),
            "{enc}: {metrics}"
        );
    }
    assert!(app.shutdown().await);
}
