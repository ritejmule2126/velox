//! HTTPS / mTLS to backends, through the full Velox stack.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::Duration;
use support::*;
use velox_cli::App;
use velox_core::Config;

fn describe() -> Handler {
    handler(|req| async move { text(format!("hello from tls backend {}", req.uri())) })
}

async fn start_app(upstream: &str, extra: &str) -> App {
    let toml = format!(
        "[server]\nhttp_addr = \"127.0.0.1:0\"\ndrain_timeout = \"1s\"\n[admin]\naddr = \"127.0.0.1:0\"\n{extra}\n\
         [[upstream]]\nname = \"app\"\nretries = 0\n{upstream}\n[[route]]\nupstream = \"app\"\n"
    );
    App::start(Config::from_toml_str(&toml).unwrap(), None).await.unwrap()
}

fn pem(p: &Path) -> String {
    p.display().to_string()
}

#[tokio::test]
async fn https_backend_is_verified_against_a_custom_ca_and_sni_is_sent() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key, _) = write_named_cert(dir.path(), "srv", &["localhost", "backend.internal", "127.0.0.1"]);
    let b =
        tls_backend(describe(), &cert, &key, TlsBackendOpts { alpn: vec![b"http/1.1"], ..Default::default() }).await;

    // Verified by IP SAN, no SNI (IP literals carry none).
    let up = format!(
        "backends = [{{ addr = \"https://127.0.0.1:{}\" }}]\ntls = {{ ca_file = \"{}\" }}",
        b.addr.port(),
        pem(&cert)
    );
    let app = start_app(&up, "").await;
    let (status, head, body) = plain(app.running.http_addr.unwrap(), "/hi?x=1", "").await;
    assert_eq!(status, 200, "{head}\n{body}");
    assert!(body.contains("hello from tls backend /hi?x=1"), "{body}");
    assert!(head.to_ascii_lowercase().contains("x-alpn: http/1.1"), "{head}");
    assert_eq!(b.snis.lock().unwrap().last().unwrap(), &None);
    assert!(app.shutdown().await);

    // `server_name` sets SNI and the name the certificate is checked against.
    let up = format!(
        "backends = [{{ addr = \"https://127.0.0.1:{}\" }}]\ntls = {{ ca_file = \"{}\", server_name = \"backend.internal\" }}",
        b.addr.port(),
        pem(&cert)
    );
    let app = start_app(&up, "").await;
    let (status, _, _) = plain(app.running.http_addr.unwrap(), "/", "").await;
    assert_eq!(status, 200);
    assert_eq!(b.snis.lock().unwrap().last().unwrap().as_deref(), Some("backend.internal"));
    assert!(app.shutdown().await);

    // A name the certificate does not cover is refused.
    let up = format!(
        "backends = [{{ addr = \"https://127.0.0.1:{}\" }}]\ntls = {{ ca_file = \"{}\", server_name = \"other.example\" }}",
        b.addr.port(),
        pem(&cert)
    );
    let app = start_app(&up, "").await;
    let hits_before = b.hits.load(Ordering::SeqCst);
    let (status, _, _) = plain(app.running.http_addr.unwrap(), "/", "").await;
    assert_eq!(status, 502, "name mismatch must fail closed");
    assert_eq!(b.hits.load(Ordering::SeqCst), hits_before, "no request reached the backend");
    assert!(app.shutdown().await);
}

#[tokio::test]
async fn untrusted_backend_certificates_fail_closed_unless_verification_is_explicitly_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key, _) = write_named_cert(dir.path(), "srv", &["localhost", "127.0.0.1"]);
    let b = tls_backend(describe(), &cert, &key, TlsBackendOpts::default()).await;

    // Default trust store (public roots): a self-signed backend is rejected.
    let up = format!("backends = [{{ addr = \"https://127.0.0.1:{}\" }}]", b.addr.port());
    let app = start_app(&up, "").await;
    for _ in 0..3 {
        let (status, _, body) = plain(app.running.http_addr.unwrap(), "/", "").await;
        assert_eq!(status, 502, "{body}");
        assert!(!body.contains("127.0.0.1"), "errors never leak backend details: {body}");
    }
    assert_eq!(b.hits.load(Ordering::SeqCst), 0);
    let metrics = app.metrics.render().unwrap();
    assert!(metrics.contains("velox_upstream_tls_errors_total{reason="), "{metrics}");
    assert!(app.shutdown().await);

    // Explicit opt-out works (and only then).
    let up = format!(
        "backends = [{{ addr = \"https://127.0.0.1:{}\" }}]\ntls = {{ insecure_skip_verify = true }}",
        b.addr.port()
    );
    let app = start_app(&up, "").await;
    let (status, _, body) = plain(app.running.http_addr.unwrap(), "/", "").await;
    assert_eq!(status, 200, "{body}");
    assert!(app.shutdown().await);
}

#[tokio::test]
async fn mtls_client_certificate_is_presented_and_rotation_applies_without_a_reload() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key, _) = write_named_cert(dir.path(), "srv", &["localhost", "127.0.0.1"]);
    let (c1, k1, der1) = write_named_cert(dir.path(), "client1", &["client-one.test"]);
    let (c2, k2, der2) = write_named_cert(dir.path(), "client2", &["client-two.test", "extra.test"]);
    // The backend trusts both identities; it demands one.
    let b = tls_backend(
        describe(),
        &cert,
        &key,
        TlsBackendOpts { client_roots: vec![der1.clone(), der2.clone()], ..Default::default() },
    )
    .await;
    let addr = format!("https://127.0.0.1:{}", b.addr.port());

    // Without a client certificate the backend refuses the connection.
    let no_cert = format!("backends = [{{ addr = \"{addr}\" }}]\ntls = {{ ca_file = \"{}\" }}", pem(&cert));
    let app = start_app(&no_cert, "").await;
    let (status, _, _) = plain(app.running.http_addr.unwrap(), "/", "").await;
    assert_eq!(status, 502, "mTLS backend must reject an anonymous client");
    assert_eq!(b.hits.load(Ordering::SeqCst), 0);
    assert!(app.shutdown().await);

    // With one, requests succeed and the backend sees exactly that identity.
    let live_cert = dir.path().join("live.crt");
    let live_key = dir.path().join("live.key");
    std::fs::copy(&c1, &live_cert).unwrap();
    std::fs::copy(&k1, &live_key).unwrap();
    let with_cert = format!(
        "backends = [{{ addr = \"{addr}\" }}]\ntls = {{ ca_file = \"{}\", client_cert_file = \"{}\", client_key_file = \"{}\", reload_interval = \"100ms\" }}\n\
         pool = {{ idle_timeout = \"1s\", max_idle_per_backend = 0 }}",
        pem(&cert),
        pem(&live_cert),
        pem(&live_key)
    );
    let app = start_app(&with_cert, "").await;
    let http = app.running.http_addr.unwrap();
    let (status, _, body) = plain(http, "/", "").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(b.client_certs.lock().unwrap().last().unwrap().as_deref(), Some(der1.as_ref()));

    // Rotate the files in place — no config reload, no restart.
    std::fs::copy(&c2, &live_cert).unwrap();
    std::fs::copy(&k2, &live_key).unwrap();
    eventually(10, "rotated client certificate to be used", || {
        let (b_certs, der2) = (std::sync::Arc::clone(&b.client_certs), der2.clone());
        async move {
            let (status, _, _) = plain(http, "/", "").await;
            status == 200 && b_certs.lock().unwrap().last().unwrap().as_deref() == Some(der2.as_ref())
        }
    })
    .await;

    // A broken rotation (half-written file) keeps the last good identity serving.
    std::fs::write(&live_cert, "-----BEGIN CERTIFICATE-----\ngarbage").unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    for _ in 0..3 {
        let (status, _, body) = plain(http, "/", "").await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(b.client_certs.lock().unwrap().last().unwrap().as_deref(), Some(der2.as_ref()));
    }
    assert!(app.shutdown().await);
}

#[tokio::test]
async fn https_backends_speak_http2_via_alpn_and_mix_with_cleartext_backends() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key, _) = write_named_cert(dir.path(), "srv", &["localhost", "127.0.0.1"]);
    let tls =
        tls_backend(describe(), &cert, &key, TlsBackendOpts { alpn: vec![b"h2", b"http/1.1"], ..Default::default() })
            .await;

    // protocol = "h2": ALPN selects HTTP/2 and requests multiplex over it.
    let up = format!(
        "protocol = \"h2\"\nbackends = [{{ addr = \"https://127.0.0.1:{}\" }}]\ntls = {{ ca_file = \"{}\" }}",
        tls.addr.port(),
        pem(&cert)
    );
    let app = start_app(&up, "").await;
    let http = app.running.http_addr.unwrap();
    let (status, head, _) = plain(http, "/", "").await;
    assert_eq!(status, 200);
    assert!(head.to_ascii_lowercase().contains("x-alpn: h2"), "{head}");
    assert!(app.shutdown().await);

    // protocol = "http1" over the same server negotiates http/1.1 even though it offers h2.
    let up = format!(
        "backends = [{{ addr = \"https://127.0.0.1:{}\" }}]\ntls = {{ ca_file = \"{}\" }}",
        tls.addr.port(),
        pem(&cert)
    );
    let app = start_app(&up, "").await;
    let (_, head, _) = plain(app.running.http_addr.unwrap(), "/", "").await;
    assert!(head.to_ascii_lowercase().contains("x-alpn: http/1.1"), "{head}");
    assert!(app.shutdown().await);

    // One pool, one TLS and one cleartext backend: round-robin reaches both.
    let plain_backend = Mock::start(describe()).await;
    let up = format!(
        "backends = [{{ addr = \"https://127.0.0.1:{}\" }}, {{ addr = \"{}\" }}]\ntls = {{ ca_file = \"{}\" }}",
        tls.addr.port(),
        plain_backend.addr,
        pem(&cert)
    );
    let before = tls.hits.load(Ordering::SeqCst);
    let app = start_app(&up, "").await;
    for _ in 0..6 {
        let (status, _, _) = plain(app.running.http_addr.unwrap(), "/", "").await;
        assert_eq!(status, 200);
    }
    assert_eq!(tls.hits.load(Ordering::SeqCst) - before, 3);
    assert_eq!(plain_backend.hits(), 3);
    assert!(app.shutdown().await);
}

#[tokio::test]
async fn https_backend_health_checks_complete_the_tls_handshake() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key, _) = write_named_cert(dir.path(), "srv", &["localhost", "127.0.0.1"]);
    let healthy = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let h = std::sync::Arc::clone(&healthy);
    let b = tls_backend(
        handler(move |req| {
            let h = std::sync::Arc::clone(&h);
            async move {
                if req.uri().path() == "/health" && !h.load(Ordering::SeqCst) {
                    let mut r = text("down");
                    *r.status_mut() = http::StatusCode::SERVICE_UNAVAILABLE;
                    return r;
                }
                text("ok")
            }
        }),
        &cert,
        &key,
        TlsBackendOpts::default(),
    )
    .await;
    let up = format!(
        "backends = [{{ addr = \"https://127.0.0.1:{}\" }}]\ntls = {{ ca_file = \"{}\" }}\n\
         health = {{ kind = \"http\", path = \"/health\", interval = \"100ms\", timeout = \"1s\", jitter = 0.0, healthy_threshold = 1, unhealthy_threshold = 1 }}",
        b.addr.port(),
        pem(&cert)
    );
    let app = start_app(&up, "").await;
    let admin_addr = app.admin_addr.unwrap();
    let state = |want: bool| async move {
        let (_, v) = support::admin(admin_addr, "GET", "/admin/v1/upstreams/app", None).await;
        v["backends"][0]["healthy"] == serde_json::json!(want)
    };
    eventually(5, "backend healthy over TLS", || state(true)).await;
    healthy.store(false, Ordering::SeqCst);
    eventually(5, "backend marked unhealthy by the TLS probe", || state(false)).await;
    healthy.store(true, Ordering::SeqCst);
    eventually(5, "backend recovers", || state(true)).await;
    assert!(app.shutdown().await);
}
