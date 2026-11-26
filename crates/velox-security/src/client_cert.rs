//! Inbound mutual TLS: a hot-reloadable client-certificate verifier and the
//! identity (`Subject`, serial) extracted from a verified certificate.
//!
//! The verifier is a thin wrapper around rustls' `WebPkiClientVerifier` held in
//! an [`ArcSwap`], so replacing the trusted CA bundle on reload is one atomic
//! pointer swap: handshakes already in progress finish against the old bundle,
//! new ones see the new one, and the `ServerConfig` (with its session cache) is
//! never rebuilt. It advertises no CA "hint" list (nothing in the TLS
//! `CertificateRequest` names acceptable issuers), as most proxies by default.

use crate::tls::TlsError;
use arc_swap::ArcSwap;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::ring as ring_provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::WebPkiClientVerifier;
use rustls::{DigitallySignedStruct, DistinguishedName, RootCertStore, SignatureScheme};
use std::path::Path;
use std::sync::Arc;
use velox_core::config::TlsConfig;

type Inner = Option<Arc<dyn ClientCertVerifier>>;

/// The listener-wide client-certificate policy; see the [module docs](self).
pub struct ClientAuth {
    current: ArcSwap<Inner>,
}

impl std::fmt::Debug for ClientAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientAuth").field("enabled", &self.current.load().is_some()).finish()
    }
}

/// A client-authentication policy that has been loaded but not yet installed.
pub struct PreparedClientAuth(Inner);

/// Build the verifier `cfg` asks for (`None` = client authentication off).
fn build(cfg: &TlsConfig) -> Result<Inner, TlsError> {
    let Some(path) = &cfg.client_ca_file else { return Ok(None) };
    let display = path.display().to_string();
    let pem = std::fs::read(path).map_err(|source| TlsError::Io { path: display.clone(), source })?;
    let mut roots = RootCertStore::empty();
    let mut count = 0;
    for cert in CertificateDer::pem_slice_iter(&pem) {
        let cert = cert.map_err(|e| TlsError::Pem { path: display.clone(), reason: e.to_string() })?;
        roots
            .add(cert)
            .map_err(|e| TlsError::Pem { path: display.clone(), reason: format!("unusable CA certificate: {e}") })?;
        count += 1;
    }
    if count == 0 {
        return Err(TlsError::Pem { path: display, reason: "no certificates found".into() });
    }
    let builder =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::new(ring_provider::default_provider()));
    let builder = if cfg.client_auth_required.unwrap_or(true) { builder } else { builder.allow_unauthenticated() };
    let verifier = builder.build().map_err(|e| TlsError::Pem { path: display, reason: e.to_string() })?;
    Ok(Some(verifier))
}

impl ClientAuth {
    /// Build from the `[tls]` section.
    pub fn from_config(cfg: &TlsConfig) -> Result<Arc<Self>, TlsError> {
        Ok(Arc::new(Self { current: ArcSwap::from_pointee(build(cfg)?) }))
    }

    /// Load what `cfg` asks for without installing it (the fallible half of a reload).
    pub fn prepare(cfg: &TlsConfig) -> Result<PreparedClientAuth, TlsError> {
        build(cfg).map(PreparedClientAuth)
    }

    /// Install a prepared policy. Cannot fail, so a caller can prepare several
    /// things and only then install them all.
    pub fn install(&self, prepared: PreparedClientAuth) {
        self.current.store(Arc::new(prepared.0));
    }

    /// Replace the policy. On error the previous one stays in force.
    pub fn reload(&self, cfg: &TlsConfig) -> Result<(), TlsError> {
        self.install(Self::prepare(cfg)?);
        Ok(())
    }

    /// Is client authentication currently on?
    pub fn enabled(&self) -> bool {
        self.current.load().is_some()
    }

    /// Verify the CA bundle `cfg` names (used by `velox validate` / `doctor`).
    pub fn check(path: &Path) -> Result<(), TlsError> {
        build(&TlsConfig { client_ca_file: Some(path.to_owned()), ..TlsConfig::default() }).map(|_| ())
    }
}

impl ClientCertVerifier for ClientAuth {
    fn offer_client_auth(&self) -> bool {
        self.current.load().is_some()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.current.load().as_ref().as_ref().is_some_and(|v| v.client_auth_mandatory())
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        match self.current.load().as_ref() {
            Some(v) => v.verify_client_cert(end_entity, intermediates, now),
            None => Err(rustls::Error::General("client certificates are not accepted here".into())),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        match self.current.load().as_ref() {
            Some(v) => v.verify_tls12_signature(message, cert, dss),
            None => Err(rustls::Error::General("client certificates are not accepted here".into())),
        }
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        match self.current.load().as_ref() {
            Some(v) => v.verify_tls13_signature(message, cert, dss),
            None => Err(rustls::Error::General("client certificates are not accepted here".into())),
        }
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        match self.current.load().as_ref() {
            Some(v) => v.supported_verify_schemes(),
            None => ring_provider::default_provider().signature_verification_algorithms.supported_schemes(),
        }
    }
}

/// Who the verified client is, as the backend will be told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCert {
    /// The certificate subject (`CN=…, O=…`), made safe for a header value.
    pub subject: String,
    /// The serial number in uppercase hex.
    pub serial: String,
}

/// Longest identity string forwarded (anything beyond is cut).
const MAX_FIELD: usize = 1024;

/// Make `s` safe for an HTTP header value: printable ASCII passes, everything
/// else (control characters, non-ASCII, `%`) is percent-encoded byte by byte, so
/// a hostile subject cannot inject a newline or a second header.
pub fn header_safe(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if out.len() >= MAX_FIELD {
            break;
        }
        if (0x20..0x7f).contains(&b) && b != b'%' {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

impl ClientCert {
    /// Extract the identity from a DER certificate (the one the handshake verified).
    pub fn from_der(der: &[u8]) -> Option<Self> {
        let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
        let serial = cert.tbs_certificate.raw_serial().iter().fold(String::new(), |mut acc, b| {
            acc.push_str(&format!("{b:02X}"));
            acc
        });
        Some(Self { subject: header_safe(&cert.subject().to_string()), serial })
    }

    /// The identity of the leaf certificate in a verified peer chain.
    pub fn from_chain(chain: Option<&[CertificateDer<'_>]>) -> Option<Self> {
        Self::from_der(chain?.first()?.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_strings_cannot_inject_headers() {
        assert_eq!(header_safe("CN=alice, O=Acme"), "CN=alice, O=Acme");
        assert_eq!(header_safe("CN=a\r\nX-Admin: 1"), "CN=a%0D%0AX-Admin: 1");
        assert_eq!(header_safe("CN=100%"), "CN=100%25", "the escape character itself is escaped");
        assert_eq!(header_safe("CN=Jos\u{e9}"), "CN=Jos%C3%A9");
        assert_eq!(header_safe("a\0b"), "a%00b");
        assert!(header_safe(&"x".repeat(5000)).len() <= MAX_FIELD + 3);
        // Whatever comes out is always a legal header value.
        for hostile in ["\r\n", "\u{0}\u{7f}", "\u{202e}rtl", "\t", "\u{1F600}"] {
            assert!(http::HeaderValue::from_str(&header_safe(hostile)).is_ok(), "{hostile:?}");
        }
    }

    #[test]
    fn subject_and_serial_come_from_the_certificate() {
        let mut params = rcgen::CertificateParams::new(vec!["client.test".into()]).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, "alice");
        params.distinguished_name.push(rcgen::DnType::OrganizationName, "Acme Corp");
        params.serial_number = Some(rcgen::SerialNumber::from(vec![0x01, 0xAB, 0xCD]));
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let id = ClientCert::from_der(cert.der()).unwrap();
        assert!(id.subject.contains("CN=alice") && id.subject.contains("O=Acme Corp"), "{}", id.subject);
        assert_eq!(id.serial, "01ABCD");
        assert_eq!(ClientCert::from_chain(Some(&[cert.der().clone()])), Some(id));
        assert_eq!(ClientCert::from_chain(Some(&[])), None);
        assert_eq!(ClientCert::from_chain(None), None);
        assert_eq!(ClientCert::from_der(b"not a certificate"), None);
    }

    #[test]
    fn the_policy_follows_the_config_and_survives_a_bad_reload() {
        let dir = tempfile::tempdir().unwrap();
        let ca = |name: &str| {
            let mut p = rcgen::CertificateParams::new(vec![]).unwrap();
            p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let cert = p.self_signed(&rcgen::KeyPair::generate().unwrap()).unwrap();
            let path = dir.path().join(name);
            std::fs::write(&path, cert.pem()).unwrap();
            path
        };
        let off = TlsConfig::default();
        let auth = ClientAuth::from_config(&off).unwrap();
        assert!(!auth.enabled() && !auth.offer_client_auth() && !auth.client_auth_mandatory());
        assert!(auth.verify_client_cert(&CertificateDer::from(vec![1]), &[], UnixTime::now()).is_err());

        let required = TlsConfig { client_ca_file: Some(ca("a.pem")), ..TlsConfig::default() };
        auth.reload(&required).unwrap();
        assert!(auth.enabled() && auth.offer_client_auth() && auth.client_auth_mandatory());
        let optional = TlsConfig { client_auth_required: Some(false), ..required.clone() };
        auth.reload(&optional).unwrap();
        assert!(auth.offer_client_auth() && !auth.client_auth_mandatory(), "optional: offered, not required");
        assert!(auth.root_hint_subjects().is_empty());

        // Unusable bundles are errors and leave the policy as it was.
        std::fs::write(dir.path().join("junk.pem"), "not pem").unwrap();
        for bad in [dir.path().join("junk.pem"), dir.path().join("missing.pem")] {
            assert!(auth.reload(&TlsConfig { client_ca_file: Some(bad), ..TlsConfig::default() }).is_err());
            assert!(auth.offer_client_auth() && !auth.client_auth_mandatory(), "still the optional policy");
        }
        // Dropping the setting turns client authentication off again.
        auth.reload(&off).unwrap();
        assert!(!auth.enabled());
        assert!(ClientAuth::check(&dir.path().join("a.pem")).is_ok());
        assert!(ClientAuth::check(&dir.path().join("junk.pem")).is_err());
    }
}
