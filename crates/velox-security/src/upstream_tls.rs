//! Client-side TLS for `https://` backends.
//!
//! [`UpstreamTlsRegistry`] turns an `[upstream.tls]` table into a shared
//! `rustls::ClientConfig`:
//!
//! * trust anchors are the bundled Mozilla roots, or *only* `ca_file` when one
//!   is given (private PKI);
//! * an optional client certificate enables mTLS;
//! * ALPN follows the upstream protocol (`h2` or `http/1.1`);
//! * `insecure_skip_verify` swaps in a verifier that accepts any certificate
//!   (opt-in, loudly named, off by default);
//! * on-disk files are re-stat'ed on every lookup, so rotating a short-lived
//!   workload certificate in place takes effect without a reload. A rotation
//!   that produces unreadable files keeps the previous, working configuration.

use crate::tls::TlsError;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring as ring_provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;
use velox_core::config::UpstreamTlsConfig;

type FileStamp = Vec<Option<(SystemTime, u64)>>;

fn stamp(cfg: &UpstreamTlsConfig) -> FileStamp {
    [&cfg.ca_file, &cfg.client_cert_file, &cfg.client_key_file]
        .into_iter()
        .flatten()
        .map(|p| std::fs::metadata(p).ok().and_then(|m| Some((m.modified().ok()?, m.len()))))
        .collect()
}

fn read_pem(path: &Path) -> Result<Vec<u8>, TlsError> {
    std::fs::read(path).map_err(|source| TlsError::Io { path: path.display().to_string(), source })
}

fn load_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let pem = read_pem(path)?;
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<_, _>>()
        .map_err(|e| TlsError::Pem { path: path.display().to_string(), reason: e.to_string() })?;
    if chain.is_empty() {
        return Err(TlsError::Pem { path: path.display().to_string(), reason: "no certificates found".into() });
    }
    Ok(chain)
}

/// Accepts every server certificate. Only reachable through
/// `insecure_skip_verify = true`.
#[derive(Debug)]
struct NoVerification(Vec<SignatureScheme>);

impl ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.clone()
    }
}

/// Build a `ClientConfig` for `cfg` (`h2` selects the ALPN offer).
pub fn build_client_config(cfg: &UpstreamTlsConfig, h2: bool) -> Result<ClientConfig, TlsError> {
    let provider = Arc::new(ring_provider::default_provider());
    let builder =
        ClientConfig::builder_with_provider(Arc::clone(&provider)).with_protocol_versions(rustls::ALL_VERSIONS)?;
    let builder = if cfg.insecure_skip_verify {
        let schemes = provider.signature_verification_algorithms.supported_schemes();
        builder.dangerous().with_custom_certificate_verifier(Arc::new(NoVerification(schemes)))
    } else {
        let mut roots = RootCertStore::empty();
        match &cfg.ca_file {
            Some(path) => {
                for cert in load_chain(path)? {
                    roots.add(cert).map_err(|e| TlsError::Pem {
                        path: path.display().to_string(),
                        reason: format!("unusable CA certificate: {e}"),
                    })?;
                }
            }
            None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        }
        builder.with_root_certificates(roots)
    };
    let mut config = match (&cfg.client_cert_file, &cfg.client_key_file) {
        (Some(cert), Some(key)) => {
            let chain = load_chain(cert)?;
            let key_pem = read_pem(key)?;
            let key = PrivateKeyDer::from_pem_slice(&key_pem)
                .map_err(|e| TlsError::Pem { path: key.display().to_string(), reason: e.to_string() })?;
            builder.with_client_auth_cert(chain, key)?
        }
        _ => builder.with_no_client_auth(),
    };
    config.alpn_protocols = if h2 { vec![b"h2".to_vec()] } else { vec![b"http/1.1".to_vec()] };
    Ok(config)
}

/// The SNI / verification name for a backend: `tls.server_name` if set, else
/// the backend's own host (an IP literal is verified against IP SANs).
pub fn server_name(cfg: Option<&UpstreamTlsConfig>, host: &str) -> Result<ServerName<'static>, TlsError> {
    let name = cfg.and_then(|c| c.server_name.as_deref()).unwrap_or(host);
    let name = name.trim_start_matches('[').trim_end_matches(']');
    ServerName::try_from(name.to_owned())
        .map_err(|e| TlsError::Key { path: "server_name".into(), reason: format!("`{name}`: {e}") })
}

struct Slot {
    stamp: FileStamp,
    config: Arc<ClientConfig>,
}

/// Shared, rotation-aware cache of client TLS configurations.
///
/// Equal `(config, ALPN)` pairs share one `ClientConfig` (and therefore one TLS
/// session cache). Callers receive the *same* `Arc` until something on disk
/// changes, so `Arc::ptr_eq` is a cheap "did it change?" test.
#[derive(Default)]
pub struct UpstreamTlsRegistry {
    slots: Mutex<HashMap<(UpstreamTlsConfig, bool), Slot>>,
}

impl std::fmt::Debug for UpstreamTlsRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamTlsRegistry").finish_non_exhaustive()
    }
}

impl UpstreamTlsRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// The client configuration for `cfg` (`None` = defaults: public roots, no
    /// client certificate). Re-checks the files' timestamps and rebuilds if
    /// they changed; if the rebuild fails the previous configuration is kept.
    pub fn client_config(&self, cfg: Option<&UpstreamTlsConfig>, h2: bool) -> Result<Arc<ClientConfig>, TlsError> {
        let cfg = cfg.cloned().unwrap_or_default();
        let key = (cfg, h2);
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        let now_stamp = stamp(&key.0);
        if let Some(slot) = slots.get_mut(&key) {
            if slot.stamp == now_stamp {
                return Ok(Arc::clone(&slot.config));
            }
            return match build_client_config(&key.0, h2) {
                Ok(c) => {
                    tracing::info!("upstream TLS material changed on disk; reloaded");
                    slot.config = Arc::new(c);
                    slot.stamp = now_stamp;
                    Ok(Arc::clone(&slot.config))
                }
                Err(e) => {
                    // Mid-rotation (half-written file, key/cert mismatch): keep
                    // serving with what works and look again next time.
                    tracing::warn!(error = %e, "upstream TLS reload failed; keeping the previous configuration");
                    Ok(Arc::clone(&slot.config))
                }
            };
        }
        let config = Arc::new(build_client_config(&key.0, h2)?);
        slots.insert(key, Slot { stamp: now_stamp, config: Arc::clone(&config) });
        Ok(config)
    }

    /// Forget configurations no upstream uses any more.
    pub fn retain<'a>(&self, live: impl Iterator<Item = (&'a UpstreamTlsConfig, bool)>) {
        let live: std::collections::HashSet<(UpstreamTlsConfig, bool)> = live.map(|(c, h2)| (c.clone(), h2)).collect();
        self.slots.lock().unwrap_or_else(PoisonError::into_inner).retain(|k, _| live.contains(k));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_pair(dir: &Path, name: &str, sans: &[&str]) -> (std::path::PathBuf, std::path::PathBuf) {
        let g = rcgen::generate_simple_self_signed(sans.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>()).unwrap();
        let (cert, key) = (dir.join(format!("{name}.crt")), dir.join(format!("{name}.key")));
        std::fs::write(&cert, g.cert.pem()).unwrap();
        std::fs::write(&key, g.key_pair.serialize_pem()).unwrap();
        (cert, key)
    }

    #[test]
    fn defaults_use_public_roots_and_alpn_follows_the_protocol() {
        let reg = UpstreamTlsRegistry::new();
        let h1 = reg.client_config(None, false).unwrap();
        assert_eq!(h1.alpn_protocols, vec![b"http/1.1".to_vec()]);
        let h2 = reg.client_config(None, true).unwrap();
        assert_eq!(h2.alpn_protocols, vec![b"h2".to_vec()]);
        assert!(Arc::ptr_eq(&h1, &reg.client_config(None, false).unwrap()), "equal configs share one ClientConfig");
        assert!(Arc::ptr_eq(&h1, &reg.client_config(Some(&UpstreamTlsConfig::default()), false).unwrap()));
    }

    #[test]
    fn custom_ca_and_mtls_material_load_and_bad_files_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, _) = write_pair(dir.path(), "ca", &["ca.test"]);
        let (client, client_key) = write_pair(dir.path(), "client", &["client.test"]);
        let reg = UpstreamTlsRegistry::new();
        let cfg = UpstreamTlsConfig {
            ca_file: Some(ca.clone()),
            client_cert_file: Some(client.clone()),
            client_key_file: Some(client_key.clone()),
            ..Default::default()
        };
        assert!(reg.client_config(Some(&cfg), true).is_ok());
        // Missing / garbage / mismatched files fail fast instead of silently
        // downgrading to "no client certificate" or "trust everything".
        let missing = UpstreamTlsConfig { ca_file: Some(dir.path().join("nope.pem")), ..Default::default() };
        assert!(matches!(reg.client_config(Some(&missing), false), Err(TlsError::Io { .. })));
        std::fs::write(dir.path().join("junk.pem"), "not pem").unwrap();
        let junk = UpstreamTlsConfig { ca_file: Some(dir.path().join("junk.pem")), ..Default::default() };
        assert!(matches!(reg.client_config(Some(&junk), false), Err(TlsError::Pem { .. })));
        let (other, _) = write_pair(dir.path(), "other", &["other.test"]);
        let mismatch = UpstreamTlsConfig {
            client_cert_file: Some(other),
            client_key_file: Some(client_key),
            ..Default::default()
        };
        assert!(reg.client_config(Some(&mismatch), false).is_err(), "cert/key mismatch must fail");
    }

    #[test]
    fn rotated_files_rebuild_and_broken_rotations_keep_the_old_config() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, _) = write_pair(dir.path(), "ca", &["ca.test"]);
        let cfg = UpstreamTlsConfig { ca_file: Some(ca.clone()), ..Default::default() };
        let reg = UpstreamTlsRegistry::new();
        let first = reg.client_config(Some(&cfg), false).unwrap();
        assert!(Arc::ptr_eq(&first, &reg.client_config(Some(&cfg), false).unwrap()), "unchanged → same Arc");

        // Rotate: new content (and a different length, so the stamp differs even
        // on filesystems with coarse mtimes).
        let (new_ca, _) = write_pair(dir.path(), "new", &["rotated.example.test", "second.example.test"]);
        std::fs::copy(&new_ca, &ca).unwrap();
        let second = reg.client_config(Some(&cfg), false).unwrap();
        assert!(!Arc::ptr_eq(&first, &second), "rotation must produce a fresh ClientConfig");

        // A half-written rotation must not take traffic down.
        std::fs::write(&ca, "-----BEGIN CERTIFICATE-----\ngarbage").unwrap();
        let third = reg.client_config(Some(&cfg), false).unwrap();
        assert!(Arc::ptr_eq(&second, &third), "kept the last good configuration");
    }

    #[test]
    fn insecure_mode_is_explicit_and_server_name_rules() {
        let reg = UpstreamTlsRegistry::new();
        let insecure = UpstreamTlsConfig { insecure_skip_verify: true, ..Default::default() };
        assert!(reg.client_config(Some(&insecure), false).is_ok());
        assert!(!UpstreamTlsConfig::default().insecure_skip_verify);
        // SNI: override wins; IPs and bracketed IPv6 are accepted.
        let named = UpstreamTlsConfig { server_name: Some("svc.internal".into()), ..Default::default() };
        assert_eq!(server_name(Some(&named), "10.0.0.1").unwrap(), ServerName::try_from("svc.internal").unwrap());
        assert!(matches!(server_name(None, "10.0.0.1").unwrap(), ServerName::IpAddress(_)));
        assert!(matches!(server_name(None, "[::1]").unwrap(), ServerName::IpAddress(_)));
        assert!(matches!(server_name(None, "app.example.com").unwrap(), ServerName::DnsName(_)));
        assert!(server_name(None, "").is_err());
    }

    #[test]
    fn retain_drops_unused_configs() {
        let reg = UpstreamTlsRegistry::new();
        let a = UpstreamTlsConfig { server_name: Some("a.test".into()), ..Default::default() };
        let first = reg.client_config(Some(&a), false).unwrap();
        reg.retain(std::iter::empty());
        assert!(!Arc::ptr_eq(&first, &reg.client_config(Some(&a), false).unwrap()));
    }
}
