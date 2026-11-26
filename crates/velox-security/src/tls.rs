//! TLS configuration on `rustls`: SNI-based certificate selection with
//! lock-free hot reload, self-signed development certificates, and the
//! `ServerConfig` builders for TCP (h2/http1.1) and QUIC (h3).

use arc_swap::ArcSwap;
use rustls::crypto::ring as ring_provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use velox_core::config::TlsConfig;

/// TLS setup failures.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// A certificate or key file could not be read.
    #[error("cannot read {path}: {source}")]
    Io {
        /// File that failed.
        path: String,
        /// Underlying error.
        source: std::io::Error,
    },
    /// PEM content could not be decoded.
    #[error("invalid PEM in {path}: {reason}")]
    Pem {
        /// File that failed.
        path: String,
        /// Decoder message.
        reason: String,
    },
    /// The private key type is not supported or does not match.
    #[error("unusable private key in {path}: {reason}")]
    Key {
        /// File that failed.
        path: String,
        /// Reason.
        reason: String,
    },
    /// Certificate generation failed.
    #[error("certificate generation failed: {0}")]
    Generate(String),
    /// `rustls` rejected the configuration.
    #[error("rustls configuration error: {0}")]
    Rustls(#[from] rustls::Error),
}

/// Load a certificate chain + private key from PEM files.
pub fn load_certified_key(cert_file: &Path, key_file: &Path) -> Result<Arc<CertifiedKey>, TlsError> {
    let read = |p: &Path| std::fs::read(p).map_err(|source| TlsError::Io { path: p.display().to_string(), source });
    let cert_pem = read(cert_file)?;
    let key_pem = read(key_file)?;
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<_, _>>()
        .map_err(|e| TlsError::Pem { path: cert_file.display().to_string(), reason: e.to_string() })?;
    if chain.is_empty() {
        return Err(TlsError::Pem { path: cert_file.display().to_string(), reason: "no certificates found".into() });
    }
    let key = PrivateKeyDer::from_pem_slice(&key_pem)
        .map_err(|e| TlsError::Pem { path: key_file.display().to_string(), reason: e.to_string() })?;
    certified_key(chain, &key, &key_file.display().to_string())
}

/// Build a [`CertifiedKey`] from DER parts.
pub fn certified_key(
    chain: Vec<CertificateDer<'static>>,
    key: &PrivateKeyDer<'_>,
    origin: &str,
) -> Result<Arc<CertifiedKey>, TlsError> {
    let signing = ring_provider::sign::any_supported_type(key)
        .map_err(|e| TlsError::Key { path: origin.to_owned(), reason: e.to_string() })?;
    let ck = CertifiedKey::new(chain, signing);
    ck.keys_match().map_err(|e| TlsError::Key { path: origin.to_owned(), reason: e.to_string() })?;
    Ok(Arc::new(ck))
}

/// Generate an in-memory self-signed certificate for `names` (development).
pub fn self_signed(names: &[String]) -> Result<Arc<CertifiedKey>, TlsError> {
    let mut sans: Vec<String> = names.iter().filter(|n| !n.starts_with("*.") || n.len() > 2).cloned().collect();
    for default in ["localhost", "127.0.0.1", "::1"] {
        if !sans.iter().any(|s| s == default) {
            sans.push(default.to_owned());
        }
    }
    let generated = rcgen::generate_simple_self_signed(sans).map_err(|e| TlsError::Generate(e.to_string()))?;
    let der = PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der());
    certified_key(vec![generated.cert.der().clone()], &PrivateKeyDer::Pkcs8(der), "self-signed")
}

#[derive(Debug, Default)]
struct CertTable {
    exact: HashMap<String, Arc<CertifiedKey>>,
    wildcard: Vec<(String, Arc<CertifiedKey>)>,
    default: Option<Arc<CertifiedKey>>,
}

impl CertTable {
    fn lookup(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        if let Some(name) = sni {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            if let Some(c) = self.exact.get(&name) {
                return Some(Arc::clone(c));
            }
            if let Some((_, rest)) = name.split_once('.') {
                if let Some((_, c)) = self.wildcard.iter().find(|(suffix, _)| suffix == rest) {
                    return Some(Arc::clone(c));
                }
            }
        }
        self.default.clone()
    }
}

/// Selects a certificate by SNI. Tables are swapped atomically, so reloads
/// never interrupt handshakes in progress.
#[derive(Debug)]
pub struct SniResolver {
    table: ArcSwap<CertTable>,
    /// Inbound client-certificate policy (`tls.client_ca_file`), reloaded with the certificates.
    client_auth: Arc<crate::client_cert::ClientAuth>,
    /// Certificates obtained dynamically (ACME), consulted first.
    dynamic: ArcSwap<HashMap<String, Arc<CertifiedKey>>>,
}

impl SniResolver {
    /// Build a resolver from the `[tls]` section.
    pub fn from_config(cfg: &TlsConfig) -> Result<Arc<Self>, TlsError> {
        let r = Arc::new(Self {
            client_auth: crate::client_cert::ClientAuth::from_config(cfg)?,
            table: ArcSwap::from_pointee(CertTable::default()),
            dynamic: ArcSwap::from_pointee(HashMap::new()),
        });
        r.reload(cfg)?;
        Ok(r)
    }

    /// The inbound client-certificate policy shared by every listener.
    pub fn client_auth(&self) -> &Arc<crate::client_cert::ClientAuth> {
        &self.client_auth
    }

    /// Re-read certificate files and the client CA bundle. On error nothing
    /// changes: the previous certificates and client policy stay active.
    pub fn reload(&self, cfg: &TlsConfig) -> Result<(), TlsError> {
        // Build every new piece first, then install them; a failure leaves all as it was.
        let client_auth = crate::client_cert::ClientAuth::prepare(cfg)?;
        let mut table = CertTable::default();
        for c in &cfg.certs {
            let ck = load_certified_key(&c.cert_file, &c.key_file)?;
            if c.server_names.is_empty() {
                table.default = Some(Arc::clone(&ck));
            }
            for n in &c.server_names {
                let n = n.to_ascii_lowercase();
                match n.strip_prefix("*.") {
                    Some(suffix) => table.wildcard.push((suffix.to_owned(), Arc::clone(&ck))),
                    None => {
                        table.exact.insert(n, Arc::clone(&ck));
                    }
                }
            }
            if table.default.is_none() {
                table.default = Some(Arc::clone(&ck));
            }
        }
        if table.default.is_none() && cfg.self_signed_fallback {
            let names: Vec<String> = cfg.certs.iter().flat_map(|c| c.server_names.clone()).collect();
            table.default = Some(self_signed(&names)?);
        }
        self.client_auth.install(client_auth);
        self.table.store(Arc::new(table));
        Ok(())
    }

    /// Install (or replace) a dynamically issued certificate for `domain`.
    pub fn set_dynamic(&self, domain: &str, key: Arc<CertifiedKey>) {
        let mut next = (**self.dynamic.load()).clone();
        next.insert(domain.to_ascii_lowercase(), key);
        self.dynamic.store(Arc::new(next));
    }

    /// Whether any certificate (static, dynamic or fallback) is available.
    pub fn has_certificates(&self) -> bool {
        let t = self.table.load();
        t.default.is_some() || !t.exact.is_empty() || !self.dynamic.load().is_empty()
    }

    /// Resolve by SNI name (also used by tests).
    pub fn resolve_name(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        if let Some(name) = sni {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            if let Some(c) = self.dynamic.load().get(&name) {
                return Some(Arc::clone(c));
            }
        }
        self.table.load().lookup(sni)
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.resolve_name(client_hello.server_name())
    }
}

fn base_builder(
    versions: &[&'static rustls::SupportedProtocolVersion],
    client_auth: Arc<crate::client_cert::ClientAuth>,
) -> Result<rustls::ConfigBuilder<rustls::ServerConfig, rustls::server::WantsServerCert>, TlsError> {
    Ok(rustls::ServerConfig::builder_with_provider(Arc::new(ring_provider::default_provider()))
        .with_protocol_versions(versions)?
        .with_client_cert_verifier(client_auth))
}

/// `ServerConfig` for the TCP listener: TLS 1.2/1.3, ALPN `h2` + `http/1.1`.
pub fn tcp_server_config(resolver: Arc<SniResolver>) -> Result<Arc<rustls::ServerConfig>, TlsError> {
    let mut cfg = base_builder(rustls::ALL_VERSIONS, Arc::clone(resolver.client_auth()))?.with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// `ServerConfig` for QUIC: TLS 1.3 only, ALPN `h3`.
pub fn quic_server_config(resolver: Arc<SniResolver>) -> Result<Arc<rustls::ServerConfig>, TlsError> {
    let mut cfg =
        base_builder(&[&rustls::version::TLS13], Arc::clone(resolver.client_auth()))?.with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![b"h3".to_vec()];
    Ok(Arc::new(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use velox_core::config::CertConfig;

    fn write_pair(dir: &Path, name: &str, sans: &[&str]) -> CertConfigPaths {
        let g = rcgen::generate_simple_self_signed(sans.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>()).unwrap();
        let cert = dir.join(format!("{name}.crt"));
        let key = dir.join(format!("{name}.key"));
        std::fs::write(&cert, g.cert.pem()).unwrap();
        std::fs::write(&key, g.key_pair.serialize_pem()).unwrap();
        CertConfigPaths { cert, key }
    }

    struct CertConfigPaths {
        cert: std::path::PathBuf,
        key: std::path::PathBuf,
    }

    fn cfg_entry(p: &CertConfigPaths, names: &[&str]) -> CertConfig {
        CertConfig {
            server_names: names.iter().map(|s| (*s).to_owned()).collect(),
            cert_file: p.cert.clone(),
            key_file: p.key.clone(),
        }
    }

    #[test]
    fn sni_selection_exact_wildcard_default() {
        let dir = tempfile::tempdir().unwrap();
        let a = write_pair(dir.path(), "a", &["a.example.com"]);
        let w = write_pair(dir.path(), "w", &["*.wild.example.com"]);
        let d = write_pair(dir.path(), "d", &["default.example.com"]);
        let cfg = TlsConfig {
            certs: vec![cfg_entry(&a, &["a.example.com"]), cfg_entry(&w, &["*.wild.example.com"]), cfg_entry(&d, &[])],
            ..TlsConfig::default()
        };
        let r = SniResolver::from_config(&cfg).unwrap();
        let ka = load_certified_key(&a.cert, &a.key).unwrap();
        let kw = load_certified_key(&w.cert, &w.key).unwrap();
        let kd = load_certified_key(&d.cert, &d.key).unwrap();
        assert_eq!(r.resolve_name(Some("A.Example.com.")).unwrap().cert, ka.cert);
        assert_eq!(r.resolve_name(Some("x.wild.example.com")).unwrap().cert, kw.cert);
        assert_eq!(r.resolve_name(Some("nomatch.org")).unwrap().cert, kd.cert);
        assert_eq!(r.resolve_name(None).unwrap().cert, kd.cert);
    }

    #[test]
    fn reload_swaps_atomically_and_keeps_old_on_error() {
        let dir = tempfile::tempdir().unwrap();
        let a = write_pair(dir.path(), "a", &["a.test"]);
        let cfg = TlsConfig { certs: vec![cfg_entry(&a, &[])], ..TlsConfig::default() };
        let r = SniResolver::from_config(&cfg).unwrap();
        let before = r.resolve_name(None).unwrap();

        let bad = TlsConfig {
            certs: vec![CertConfig {
                server_names: vec![],
                cert_file: dir.path().join("missing.crt"),
                key_file: dir.path().join("missing.key"),
            }],
            ..TlsConfig::default()
        };
        assert!(r.reload(&bad).is_err());
        assert_eq!(r.resolve_name(None).unwrap().cert, before.cert, "old table retained");

        let b = write_pair(dir.path(), "b", &["b.test"]);
        r.reload(&TlsConfig { certs: vec![cfg_entry(&b, &[])], ..TlsConfig::default() }).unwrap();
        assert_ne!(r.resolve_name(None).unwrap().cert, before.cert);
    }

    #[test]
    fn self_signed_fallback_and_dynamic_override() {
        let cfg = TlsConfig { self_signed_fallback: true, ..TlsConfig::default() };
        let r = SniResolver::from_config(&cfg).unwrap();
        assert!(r.has_certificates());
        let fallback = r.resolve_name(Some("anything")).unwrap();
        let dynamic = self_signed(&["acme.test".to_owned()]).unwrap();
        r.set_dynamic("ACME.test", Arc::clone(&dynamic));
        assert_eq!(r.resolve_name(Some("acme.test")).unwrap().cert, dynamic.cert);
        assert_eq!(r.resolve_name(Some("other.test")).unwrap().cert, fallback.cert);
    }

    #[test]
    fn rejects_garbage_pem_and_mismatched_keys() {
        let dir = tempfile::tempdir().unwrap();
        let a = write_pair(dir.path(), "a", &["a.test"]);
        let b = write_pair(dir.path(), "b", &["b.test"]);
        std::fs::write(dir.path().join("junk.crt"), "not pem").unwrap();
        assert!(load_certified_key(&dir.path().join("junk.crt"), &a.key).is_err());
        assert!(load_certified_key(&a.cert, &b.key).is_err(), "cert/key mismatch must fail");
    }

    #[test]
    fn server_configs_advertise_expected_alpn() {
        let r = SniResolver::from_config(&TlsConfig { self_signed_fallback: true, ..TlsConfig::default() }).unwrap();
        let tcp = tcp_server_config(Arc::clone(&r)).unwrap();
        assert_eq!(tcp.alpn_protocols, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        let quic = quic_server_config(r).unwrap();
        assert_eq!(quic.alpn_protocols, vec![b"h3".to_vec()]);
    }
}

/// When a PEM certificate chain's *leaf* stops being valid (`notAfter`), as seconds
/// since the Unix epoch. Used by `velox doctor` to warn before certificates lapse.
pub fn leaf_not_after(path: &Path) -> Result<i64, TlsError> {
    let display = path.display().to_string();
    let pem = std::fs::read(path).map_err(|source| TlsError::Io { path: display.clone(), source })?;
    let leaf = CertificateDer::pem_slice_iter(&pem)
        .next()
        .ok_or_else(|| TlsError::Pem { path: display.clone(), reason: "no certificates found".into() })?
        .map_err(|e| TlsError::Pem { path: display.clone(), reason: e.to_string() })?;
    let (_, cert) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|e| TlsError::Pem { path: display, reason: format!("not a valid X.509 certificate: {e}") })?;
    Ok(cert.validity().not_after.timestamp())
}

/// Like [`leaf_not_after`] for every certificate in a bundle; returns the soonest
/// `notAfter` (a CA bundle is only as good as its first expiry).
pub fn bundle_earliest_not_after(path: &Path) -> Result<i64, TlsError> {
    let display = path.display().to_string();
    let pem = std::fs::read(path).map_err(|source| TlsError::Io { path: display.clone(), source })?;
    let mut earliest: Option<i64> = None;
    for cert in CertificateDer::pem_slice_iter(&pem) {
        let cert = cert.map_err(|e| TlsError::Pem { path: display.clone(), reason: e.to_string() })?;
        let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref()).map_err(|e| TlsError::Pem {
            path: display.clone(),
            reason: format!("not a valid X.509 certificate: {e}"),
        })?;
        let t = parsed.validity().not_after.timestamp();
        earliest = Some(earliest.map_or(t, |e| e.min(t)));
    }
    earliest.ok_or(TlsError::Pem { path: display, reason: "no certificates found".into() })
}

#[cfg(test)]
mod expiry_tests {
    use super::*;

    #[test]
    fn expiry_is_read_from_the_leaf_and_the_earliest_of_a_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let make = |days: i64| {
            let mut p = rcgen::CertificateParams::new(vec!["x.test".into()]).unwrap();
            let now = time::OffsetDateTime::now_utc();
            p.not_before = now - time::Duration::days(1);
            p.not_after = now + time::Duration::days(days);
            p.self_signed(&rcgen::KeyPair::generate().unwrap()).unwrap().pem()
        };
        let (soon, late) = (dir.path().join("soon.pem"), dir.path().join("bundle.pem"));
        std::fs::write(&soon, make(10)).unwrap();
        std::fs::write(&late, format!("{}{}", make(400), make(30))).unwrap();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let days = |t: i64| (t - now) / 86_400;
        assert!((9..=10).contains(&days(leaf_not_after(&soon).unwrap())));
        assert!((399..=400).contains(&days(leaf_not_after(&late).unwrap())), "the first certificate is the leaf");
        assert!((29..=30).contains(&days(bundle_earliest_not_after(&late).unwrap())), "the soonest in a bundle");
        std::fs::write(dir.path().join("junk.pem"), "nope").unwrap();
        assert!(leaf_not_after(&dir.path().join("junk.pem")).is_err());
        assert!(bundle_earliest_not_after(&dir.path().join("missing.pem")).is_err());
    }
}
