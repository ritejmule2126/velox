//! Inbound client-certificate authentication (mutual TLS), through the full app.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, SerialNumber};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use support::*;
use velox_cli::App;
use velox_core::Config;

/// A throwaway certificate authority.
struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

impl Ca {
    fn new(name: &str) -> Self {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec![]).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.distinguished_name.push(DnType::CommonName, name);
        let cert = p.self_signed(&key).unwrap();
        Self { cert, key }
    }

    fn pem(&self) -> String {
        self.cert.pem()
    }

    /// A client certificate for `cn` signed by this CA.
    fn client(&self, cn: &str, serial: u8) -> Client {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec![]).unwrap();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.distinguished_name.push(DnType::OrganizationName, "Acme");
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        p.serial_number = Some(SerialNumber::from(vec![0x0A, serial]));
        let cert = p.signed_by(&key, &self.cert, &self.key).unwrap();
        Client { chain: vec![cert.der().clone()], key: PrivatePkcs8KeyDer::from(key.serialize_der()) }
    }
}

struct Client {
    chain: Vec<CertificateDer<'static>>,
    key: PrivatePkcs8KeyDer<'static>,
}

impl Clone for Client {
    fn clone(&self) -> Self {
        Self { chain: self.chain.clone(), key: self.key.clone_key() }
    }
}

fn tls_config(
    server_der: &CertificateDer<'static>,
    alpn: &[&[u8]],
    client: Option<&Client>,
) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(server_der.clone()).unwrap();
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots);
    let mut cfg = match client {
        Some(c) => builder.with_client_auth_cert(c.chain.clone(), PrivateKeyDer::Pkcs8(c.key.clone_key())).unwrap(),
        None => builder.with_no_client_auth(),
    };
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Arc::new(cfg)
}

/// One request over TLS (`h2` or `http/1.1`); `Err` if the connection or request failed.
async fn get(
    addr: SocketAddr,
    server_der: &CertificateDer<'static>,
    client: Option<&Client>,
    h2: bool,
    headers: &[(&str, &str)],
) -> Result<(u16, String), String> {
    let alpn: &[&[u8]] = if h2 { &[b"h2"] } else { &[b"http/1.1"] };
    let tcp = tokio::net::TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let tls = tokio_rustls::TlsConnector::from(tls_config(server_der, alpn, client))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .map_err(|e| e.to_string())?;
    let mut req =
        http::Request::builder().uri(if h2 { "https://localhost/who" } else { "/who" }).header("host", "localhost");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let req = req.body(Empty::<Bytes>::new()).unwrap();
    let run = async {
        let resp = if h2 {
            let (mut send, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .map_err(|e| e.to_string())?;
            tokio::spawn(conn);
            send.send_request(req).await.map_err(|e| e.to_string())?
        } else {
            let (mut send, conn) =
                hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.map_err(|e| e.to_string())?;
            tokio::spawn(conn);
            send.send_request(req).await.map_err(|e| e.to_string())?
        };
        let status = resp.status().as_u16();
        let body = resp.into_body().collect().await.map_err(|e| e.to_string())?.to_bytes();
        Ok::<_, String>((status, String::from_utf8_lossy(&body).to_ascii_lowercase()))
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), run).await.map_err(|_| "timed out".to_owned())?
}

fn echo() -> Handler {
    handler(|req| async move {
        let mut out = String::new();
        for (k, v) in req.headers() {
            if k.as_str().starts_with("x-client-cert") {
                out.push_str(&format!("{k}: {}\n", v.to_str().unwrap_or("?")));
            }
        }
        text(if out.is_empty() { "no identity".to_owned() } else { out })
    })
}

struct Rig {
    app: App,
    server_der: CertificateDer<'static>,
    config_path: PathBuf,
    dir: tempfile::TempDir,
    backend: Mock,
}

impl Rig {
    fn tcp(&self) -> SocketAddr {
        self.app.running.https_addr.unwrap()
    }
    fn udp(&self) -> SocketAddr {
        self.app.running.h3_addr.unwrap()
    }
}

fn config_text(cert: &Path, key: &Path, backend: SocketAddr, tls_extra: &str, security: &str, route: &str) -> String {
    format!(
        "[server]\nhttps_addr = \"127.0.0.1:0\"\nh3 = true\ndrain_timeout = \"1s\"\n[admin]\naddr = \"127.0.0.1:0\"\n\
         [tls]\n{tls_extra}\n[[tls.certs]]\ncert_file = \"{}\"\nkey_file = \"{}\"\n\
         [security]\n{security}\n\
         [[upstream]]\nname = \"app\"\nbackends = [{{ addr = \"{backend}\" }}]\n\
         [[route]]\nupstream = \"app\"\n{route}\n",
        cert.display(),
        key.display()
    )
}

async fn rig(tls_extra: &str, security: &str, route: &str, ca: &Ca) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key, server_der) = write_cert(dir.path());
    std::fs::write(dir.path().join("client-ca.pem"), ca.pem()).unwrap();
    let backend = Mock::start(echo()).await;
    let ca_path = dir.path().join("client-ca.pem");
    let tls_extra = tls_extra.replace("{CA}", &ca_path.display().to_string());
    let text = config_text(&cert, &key, backend.addr, &tls_extra, security, route);
    let config_path = dir.path().join("velox.toml");
    std::fs::write(&config_path, &text).unwrap();
    let app = App::start(Config::load(&config_path).unwrap(), Some(config_path.clone())).await.unwrap();
    Rig { app, server_der, config_path, dir, backend }
}

const REQUIRED: &str = "client_ca_file = \"{CA}\"";
const OPTIONAL: &str = "client_ca_file = \"{CA}\"\nclient_auth_required = false";

#[tokio::test]
async fn a_valid_client_certificate_is_verified_and_its_identity_reaches_the_backend() {
    let ca = Ca::new("Corp CA");
    let r = rig(REQUIRED, "", "", &ca).await;
    let alice = ca.client("alice", 0x2A);
    for h2 in [false, true] {
        let (status, body) = get(r.tcp(), &r.server_der, Some(&alice), h2, &[]).await.unwrap();
        assert_eq!(status, 200, "h2={h2}: {body}");
        assert!(
            body.contains("x-client-cert-subject:") && body.contains("cn=alice") && body.contains("o=acme"),
            "h2={h2}: {body}"
        );
        assert!(body.contains("x-client-cert-serial: 0a2a"), "h2={h2}: {body}");
    }
    assert!(r.app.shutdown().await);
}

#[tokio::test]
async fn clients_without_a_trusted_certificate_are_refused_during_the_handshake() {
    let ca = Ca::new("Corp CA");
    let r = rig(REQUIRED, "", "", &ca).await;
    let rogue_ca = Ca::new("Rogue CA");
    let mallory = rogue_ca.client("mallory", 1);
    for h2 in [false, true] {
        assert!(get(r.tcp(), &r.server_der, None, h2, &[]).await.is_err(), "h2={h2}: no certificate");
        assert!(
            get(r.tcp(), &r.server_der, Some(&mallory), h2, &[]).await.is_err(),
            "h2={h2}: certificate from another CA"
        );
    }
    assert_eq!(r.backend.hits(), 0, "nothing reached the backend");
    let m = r.app.metrics.render().unwrap();
    assert!(m.contains("velox_tls_handshake_errors_total{reason="), "{m}");
    // And a good client is unaffected afterwards.
    let alice = ca.client("alice", 2);
    assert_eq!(get(r.tcp(), &r.server_der, Some(&alice), false, &[]).await.unwrap().0, 200);
    assert!(r.app.shutdown().await);
}

#[tokio::test]
async fn optional_client_auth_admits_anonymous_clients_but_never_a_bad_certificate() {
    let ca = Ca::new("Corp CA");
    let r = rig(OPTIONAL, "", "", &ca).await;
    let (status, body) = get(r.tcp(), &r.server_der, None, false, &[]).await.unwrap();
    assert_eq!((status, body.as_str()), (200, "no identity"), "anonymous passes with no identity attached");
    let (_, body) = get(r.tcp(), &r.server_der, Some(&ca.client("bob", 3)), true, &[]).await.unwrap();
    assert!(body.contains("cn=bob"), "{body}");
    let rogue = Ca::new("Rogue").client("mallory", 4);
    assert!(
        get(r.tcp(), &r.server_der, Some(&rogue), false, &[]).await.is_err(),
        "present-but-untrusted is still refused"
    );
    assert!(r.app.shutdown().await);
}

#[tokio::test]
async fn identity_headers_cannot_be_forged_by_clients_but_are_kept_from_trusted_proxies() {
    let ca = Ca::new("Corp CA");
    let forged = [("x-client-cert-subject", "CN=admin"), ("x-client-cert-serial", "FFFF")];
    // Anonymous client (optional mode) trying to claim an identity: stripped.
    let r = rig(OPTIONAL, "", "", &ca).await;
    let (_, body) = get(r.tcp(), &r.server_der, None, false, &forged).await.unwrap();
    assert_eq!(body, "no identity", "forged identity from an untrusted client: {body}");
    // A real certificate wins over whatever the client claims.
    let (_, body) = get(r.tcp(), &r.server_der, Some(&ca.client("alice", 5)), true, &forged).await.unwrap();
    assert!(body.contains("cn=alice") && !body.contains("admin") && !body.contains("ffff"), "{body}");
    assert!(r.app.shutdown().await);

    // A trusted proxy (here: the test client's own address) that terminated mTLS itself
    // may pass the identity it verified; with no certificate of our own, it is preserved.
    let r = rig(OPTIONAL, "trusted_proxies = [\"127.0.0.0/8\"]", "", &ca).await;
    let (_, body) = get(r.tcp(), &r.server_der, None, false, &forged).await.unwrap();
    assert!(body.contains("cn=admin") && body.contains("ffff"), "forwarded by a trusted proxy: {body}");
    // …but a certificate Velox verified itself always overrides it.
    let (_, body) = get(r.tcp(), &r.server_der, Some(&ca.client("carol", 6)), false, &forged).await.unwrap();
    assert!(body.contains("cn=carol") && !body.contains("admin"), "{body}");
    assert!(r.app.shutdown().await);
}

#[tokio::test]
async fn http3_verifies_client_certificates_too() {
    let ca = Ca::new("Corp CA");
    let r = rig(REQUIRED, "", "", &ca).await;
    let alice = ca.client("alice", 7);
    let h3 = |client: Option<Client>| {
        let (addr, der) = (r.udp(), r.server_der.clone());
        async move {
            let quic =
                quinn::crypto::rustls::QuicClientConfig::try_from(tls_config(&der, &[b"h3"], client.as_ref())).unwrap();
            let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
            let conn =
                tokio::time::timeout(std::time::Duration::from_secs(5), endpoint.connect(addr, "localhost").unwrap())
                    .await
                    .map_err(|_| "timed out".to_owned())?
                    .map_err(|e| e.to_string())?;
            let (mut driver, mut send) =
                h3::client::new(h3_quinn::Connection::new(conn.clone())).await.map_err(|e| e.to_string())?;
            tokio::spawn(async move {
                let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
            });
            let req = http::Request::builder().uri("https://localhost/who").body(()).unwrap();
            let mut stream = send.send_request(req).await.map_err(|e| e.to_string())?;
            stream.finish().await.map_err(|e| e.to_string())?;
            let resp = tokio::time::timeout(std::time::Duration::from_secs(5), stream.recv_response())
                .await
                .map_err(|_| "timed out".to_owned())?
                .map_err(|e| e.to_string())?;
            let mut body = Vec::new();
            while let Some(mut chunk) = stream.recv_data().await.map_err(|e| e.to_string())? {
                body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
            }
            Ok::<_, String>((resp.status().as_u16(), String::from_utf8_lossy(&body).to_ascii_lowercase()))
        }
    };
    let (status, body) = h3(Some(alice)).await.unwrap();
    assert_eq!(status, 200);
    assert!(body.contains("cn=alice") && body.contains("x-client-cert-serial: 0a07"), "{body}");
    assert!(h3(None).await.is_err(), "QUIC handshake without a certificate must fail");
    assert!(h3(Some(Ca::new("Rogue").client("mallory", 8))).await.is_err(), "…and so must one from an untrusted CA");
    assert!(r.app.shutdown().await);
}

#[tokio::test]
async fn the_client_ca_bundle_hot_reloads_and_a_bad_bundle_changes_nothing() {
    let (ca1, ca2) = (Ca::new("CA one"), Ca::new("CA two"));
    let r = rig(REQUIRED, "", "", &ca1).await;
    let (from1, from2) = (ca1.client("one", 1), ca2.client("two", 2));
    let ca_file = r.dir.path().join("client-ca.pem");
    let works = |c: &Client| {
        let (addr, der, c) = (r.tcp(), r.server_der.clone(), c.clone());
        async move { get(addr, &der, Some(&c), false, &[]).await.map(|(s, _)| s) }
    };
    assert_eq!(works(&from1).await, Ok(200));
    assert!(works(&from2).await.is_err());

    // Publish a bundle trusting both CAs and reload (what SIGHUP does).
    std::fs::write(&ca_file, format!("{}{}", ca1.pem(), ca2.pem())).unwrap();
    r.app.reloader.reload().unwrap();
    assert_eq!(works(&from1).await, Ok(200), "still trusted");
    assert_eq!(works(&from2).await, Ok(200), "newly trusted without a restart");

    // Rotate CA one out.
    std::fs::write(&ca_file, ca2.pem()).unwrap();
    r.app.reloader.reload().unwrap();
    assert!(works(&from1).await.is_err(), "the retired CA's clients are refused");
    assert_eq!(works(&from2).await, Ok(200));

    // A broken bundle: the reload fails, and the previous bundle keeps working.
    std::fs::write(&ca_file, "this is not PEM").unwrap();
    assert!(r.app.reloader.reload().is_err());
    assert_eq!(works(&from2).await, Ok(200), "last good bundle kept");
    assert!(works(&from1).await.is_err());

    // Remove the setting entirely: client authentication switches off.
    let text = std::fs::read_to_string(&r.config_path)
        .unwrap()
        .replace(&format!("client_ca_file = \"{}\"\n", ca_file.display()), "");
    std::fs::write(&r.config_path, text).unwrap();
    r.app.reloader.reload().unwrap();
    let (status, body) = get(r.tcp(), &r.server_der, None, false, &[]).await.unwrap();
    assert_eq!((status, body.as_str()), (200, "no identity"), "mTLS is off: anonymous clients are served");
    assert!(r.app.shutdown().await);
}

#[tokio::test]
async fn requests_with_a_verified_identity_never_use_the_shared_cache() {
    let ca = Ca::new("Corp CA");
    let r = rig(OPTIONAL, "", "cache = { default_ttl = \"60s\" }", &ca).await;
    let alice = ca.client("alice", 9);
    // Anonymous requests are cacheable…
    for _ in 0..2 {
        get(r.tcp(), &r.server_der, None, false, &[]).await.unwrap();
    }
    assert_eq!(r.backend.hits(), 1, "the anonymous response was cached");
    // …but an authenticated one always goes to the backend, so identity-dependent
    // responses are never stored or shared.
    for _ in 0..2 {
        let (_, body) = get(r.tcp(), &r.server_der, Some(&alice), false, &[]).await.unwrap();
        assert!(body.contains("cn=alice"));
    }
    assert_eq!(r.backend.hits(), 3);
    assert!(r.app.shutdown().await);
}
