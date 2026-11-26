//! Edge verification of JSON Web Tokens (RFC 7519 / 7515) for `[route.jwt]`.
//!
//! The verifier is deliberately small and strict:
//!
//! * **Allow-listed algorithms.** Only the configured `HS256` / `RS256` /
//!   `ES256` are accepted; `none` and everything else is refused. Names are
//!   case-sensitive, as RFC 7518 specifies.
//! * **No algorithm confusion.** A key has a *type* (HMAC secret, RSA public
//!   key, P-256 public key) and is only ever tried for the algorithm that
//!   matches it, so an attacker cannot make Velox treat an RSA public key as an
//!   HMAC secret.
//! * **Bounded input.** Tokens over 8 KiB are refused before any parsing; a
//!   header carrying `crit` (a critical extension we do not implement) is
//!   refused as RFC 7515 §4.1.11 requires.
//! * **Strict claims.** `exp` is required by default and must be a number;
//!   `nbf`, `iss` and `aud` are enforced when present/configured, with a
//!   bounded `leeway`.
//! * **Constant-time signature checks** (via `ring`).
//! * **Rotation without risk.** Key files are re-stat'ed every
//!   `reload_interval`; a rotation that produces unreadable or empty key
//!   material keeps the last good keys instead of locking everyone out.
//!
//! Key material comes from an environment variable or file (HS256), a PEM of
//! SPKI `PUBLIC KEY` blocks (RS256 / ES256), or a JWKS document (RSA and P-256,
//! selected by `kid`; symmetric `oct` JWKs are not accepted).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use http::{HeaderMap, HeaderName};
use ring::{hmac, signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::SubjectPublicKeyInfoDer;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use velox_core::config::{JwtAlgorithm, JwtConfig};

/// Largest token we will look at.
pub const MAX_TOKEN_BYTES: usize = 8 * 1024;
/// Most candidate keys tried for one token.
const MAX_CANDIDATES: usize = 16;
/// Shortest acceptable HS256 secret (the hash's output size, RFC 7518 §3.2).
pub const MIN_SECRET_BYTES: usize = 32;

/// Why a token was refused (never sent to the client; for logs and metrics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtError {
    /// No token where one is required.
    Missing,
    /// Not a well-formed JWT (structure, encoding, JSON, claim types, size).
    Malformed,
    /// `alg` is not one of the route's accepted algorithms.
    Algorithm,
    /// No key matches the token's `kid` / algorithm.
    UnknownKey,
    /// The signature does not verify.
    Signature,
    /// `exp` has passed.
    Expired,
    /// `nbf` is in the future.
    NotYetValid,
    /// `iss` does not match.
    Issuer,
    /// `aud` does not match.
    Audience,
    /// The route's keys could not be loaded (server-side problem).
    Unavailable,
}

impl JwtError {
    /// A low-cardinality label for metrics and logs.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Malformed => "malformed",
            Self::Algorithm => "algorithm",
            Self::UnknownKey => "unknown_key",
            Self::Signature => "signature",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::Issuer => "issuer",
            Self::Audience => "audience",
            Self::Unavailable => "unavailable",
        }
    }
}

/// The verified claims of a token.
pub type Claims = Map<String, Value>;

// ------------------------------------------------------------------ DER bits

/// Read one DER element: `(tag, content, rest)`.
fn der(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = buf.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first & 0x80 == 0 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n].iter().fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        (len, &rest[n..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![u8::try_from(len).unwrap_or(0)]
    } else {
        let bytes: Vec<u8> = len.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
        let mut out = vec![0x80 | u8::try_from(bytes.len()).unwrap_or(0)];
        out.extend(bytes);
        out
    }
}

/// A DER INTEGER from unsigned big-endian bytes.
fn der_uint(be: &[u8]) -> Vec<u8> {
    let trimmed: &[u8] = {
        let first = be.iter().position(|b| *b != 0).unwrap_or(be.len().saturating_sub(1));
        &be[first..]
    };
    let mut body = Vec::with_capacity(trimmed.len() + 1);
    // Zero is a single 0x00 octet, never an empty INTEGER; a set high bit needs a sign byte.
    if trimmed.first().is_none_or(|b| b & 0x80 != 0) {
        body.push(0);
    }
    body.extend_from_slice(trimmed);
    let mut out = vec![0x02];
    out.extend(der_len(body.len()));
    out.extend(body);
    out
}

/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`.
fn rsa_public_key(n: &[u8], e: &[u8]) -> Vec<u8> {
    let mut body = der_uint(n);
    body.extend(der_uint(e));
    let mut out = vec![0x30];
    out.extend(der_len(body.len()));
    out.extend(body);
    out
}

const OID_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
const OID_EC: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

// --------------------------------------------------------------------- keys

#[derive(Clone)]
enum KeyKind {
    Hmac(hmac::Key),
    /// PKCS#1 `RSAPublicKey` DER.
    Rsa(Vec<u8>),
    /// Uncompressed P-256 point (`04 || x || y`).
    Ec(Vec<u8>),
}

impl KeyKind {
    fn algorithm(&self) -> JwtAlgorithm {
        match self {
            Self::Hmac(_) => JwtAlgorithm::HS256,
            Self::Rsa(_) => JwtAlgorithm::RS256,
            Self::Ec(_) => JwtAlgorithm::ES256,
        }
    }
}

#[derive(Clone)]
struct Key {
    kid: Option<String>,
    /// A JWK may pin its algorithm.
    pinned: Option<JwtAlgorithm>,
    kind: KeyKind,
}

/// The keys of one route.
#[derive(Clone, Default)]
pub struct KeySet {
    keys: Vec<Key>,
}

impl std::fmt::Debug for KeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.debug_struct("KeySet").field("keys", &self.keys.len()).finish()
    }
}

/// Why key material could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// I/O failure.
    #[error("cannot read {path}: {source}")]
    Io {
        /// File.
        path: String,
        /// Cause.
        source: std::io::Error,
    },
    /// The content is not usable key material.
    #[error("{what}: {reason}")]
    Invalid {
        /// Which input.
        what: String,
        /// Why.
        reason: String,
    },
}

fn invalid(what: &str, reason: impl Into<String>) -> KeyError {
    KeyError::Invalid { what: what.to_owned(), reason: reason.into() }
}

fn read(path: &Path) -> Result<Vec<u8>, KeyError> {
    std::fs::read(path).map_err(|source| KeyError::Io { path: path.display().to_string(), source })
}

fn hmac_key(what: &str, secret: &[u8]) -> Result<Key, KeyError> {
    if secret.len() < MIN_SECRET_BYTES {
        return Err(invalid(what, format!("HS256 secrets must be at least {MIN_SECRET_BYTES} bytes")));
    }
    Ok(Key { kid: None, pinned: None, kind: KeyKind::Hmac(hmac::Key::new(hmac::HMAC_SHA256, secret)) })
}

/// Parse an SPKI `SubjectPublicKeyInfo` into a key.
fn spki_key(what: &str, spki: &[u8]) -> Result<KeyKind, KeyError> {
    let bad = |why: &str| invalid(what, why);
    let (tag, seq, _) = der(spki).ok_or_else(|| bad("not valid DER"))?;
    if tag != 0x30 {
        return Err(bad("not a SubjectPublicKeyInfo"));
    }
    let (tag, alg, rest) = der(seq).ok_or_else(|| bad("malformed algorithm identifier"))?;
    let (tag2, bits, _) = der(rest).ok_or_else(|| bad("missing public key"))?;
    if tag != 0x30 || tag2 != 0x03 {
        return Err(bad("not a SubjectPublicKeyInfo"));
    }
    let (&unused, key) = bits.split_first().ok_or_else(|| bad("empty public key"))?;
    if unused != 0 {
        return Err(bad("unexpected padding in the public key"));
    }
    let (oid_tag, oid, params) = der(alg).ok_or_else(|| bad("malformed algorithm OID"))?;
    if oid_tag != 0x06 {
        return Err(bad("malformed algorithm OID"));
    }
    if oid == OID_RSA {
        // The key must itself be a SEQUENCE of two INTEGERs.
        let (t, body, _) = der(key).ok_or_else(|| bad("malformed RSA key"))?;
        let ok =
            t == 0x30 && der(body).is_some_and(|(t1, _, r)| t1 == 0x02 && der(r).is_some_and(|(t2, _, _)| t2 == 0x02));
        if !ok {
            return Err(bad("malformed RSA key"));
        }
        Ok(KeyKind::Rsa(key.to_vec()))
    } else if oid == OID_EC {
        let (ct, curve, _) = der(params).ok_or_else(|| bad("missing EC curve"))?;
        if ct != 0x06 || curve != OID_P256 {
            return Err(bad("only P-256 EC keys are supported (ES256)"));
        }
        if key.len() != 65 || key[0] != 0x04 {
            return Err(bad("EC public key must be an uncompressed P-256 point"));
        }
        Ok(KeyKind::Ec(key.to_vec()))
    } else {
        Err(bad("unsupported public key type (RSA and P-256 are supported)"))
    }
}

fn pem_keys(path: &Path) -> Result<Vec<Key>, KeyError> {
    let what = path.display().to_string();
    let data = read(path)?;
    let mut keys = Vec::new();
    for block in SubjectPublicKeyInfoDer::pem_slice_iter(&data) {
        let spki = block.map_err(|e| invalid(&what, format!("invalid PEM: {e}")))?;
        keys.push(Key { kid: None, pinned: None, kind: spki_key(&what, spki.as_ref())? });
    }
    if keys.is_empty() {
        return Err(invalid(&what, "no `PUBLIC KEY` PEM blocks found"));
    }
    Ok(keys)
}

fn b64(v: &Value, field: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(v.get(field)?.as_str()?).ok()
}

fn jwks_keys(path: &Path) -> Result<Vec<Key>, KeyError> {
    let what = path.display().to_string();
    let doc: Value = serde_json::from_slice(&read(path)?).map_err(|e| invalid(&what, format!("invalid JSON: {e}")))?;
    let entries = doc.get("keys").and_then(Value::as_array).ok_or_else(|| invalid(&what, "no `keys` array"))?;
    let mut keys = Vec::new();
    for (i, jwk) in entries.iter().enumerate() {
        let ctx = format!("{what}: key #{i}");
        // Keys meant for encryption are not signature keys.
        if jwk.get("use").and_then(Value::as_str).is_some_and(|u| u != "sig") {
            continue;
        }
        let pinned = match jwk.get("alg").and_then(Value::as_str) {
            None => None,
            Some("RS256") => Some(JwtAlgorithm::RS256),
            Some("ES256") => Some(JwtAlgorithm::ES256),
            Some(_) => continue, // some other algorithm: not ours to use
        };
        let kind = match jwk.get("kty").and_then(Value::as_str) {
            Some("RSA") => {
                let (Some(n), Some(e)) = (b64(jwk, "n"), b64(jwk, "e")) else {
                    return Err(invalid(&ctx, "RSA key needs base64url `n` and `e`"));
                };
                KeyKind::Rsa(rsa_public_key(&n, &e))
            }
            Some("EC") => {
                if jwk.get("crv").and_then(Value::as_str) != Some("P-256") {
                    return Err(invalid(&ctx, "only the P-256 curve is supported"));
                }
                let (Some(x), Some(y)) = (b64(jwk, "x"), b64(jwk, "y")) else {
                    return Err(invalid(&ctx, "EC key needs base64url `x` and `y`"));
                };
                if x.len() != 32 || y.len() != 32 {
                    return Err(invalid(&ctx, "P-256 coordinates must be 32 bytes"));
                }
                let mut point = vec![0x04];
                point.extend(x);
                point.extend(y);
                KeyKind::Ec(point)
            }
            Some("oct") => {
                return Err(invalid(&ctx, "symmetric (`oct`) keys are not accepted in a JWKS; use secret_file"))
            }
            _ => continue, // OKP etc.: unsupported, skip
        };
        keys.push(Key { kid: jwk.get("kid").and_then(Value::as_str).map(str::to_owned), pinned, kind });
    }
    if keys.is_empty() {
        return Err(invalid(&what, "no usable RSA / P-256 signature keys"));
    }
    Ok(keys)
}

impl KeySet {
    /// Load every key `cfg` names. Fails (rather than loading "whatever works")
    /// if any configured source is unusable.
    pub fn load(cfg: &JwtConfig) -> Result<Self, KeyError> {
        let mut keys = Vec::new();
        if let Some(var) = &cfg.secret_env {
            let value = std::env::var(var).map_err(|_| invalid(var, "environment variable is not set"))?;
            keys.push(hmac_key(var, value.as_bytes())?);
        }
        if let Some(path) = &cfg.secret_file {
            let mut bytes = read(path)?;
            if bytes.ends_with(b"\n") {
                bytes.pop();
                if bytes.ends_with(b"\r") {
                    bytes.pop();
                }
            }
            keys.push(hmac_key(&path.display().to_string(), &bytes)?);
        }
        if let Some(path) = &cfg.public_key_file {
            keys.extend(pem_keys(path)?);
        }
        if let Some(path) = &cfg.jwks_file {
            keys.extend(jwks_keys(path)?);
        }
        if keys.is_empty() {
            return Err(invalid("jwt", "no key material configured"));
        }
        Ok(Self { keys })
    }

    /// A key set holding one HS256 secret (at least [`MIN_SECRET_BYTES`] long).
    pub fn hmac(secret: &[u8]) -> Result<Self, KeyError> {
        Ok(Self { keys: vec![hmac_key("secret", secret)?] })
    }

    /// Number of keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// `true` when there are no keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

// ------------------------------------------------------------- verification

fn header_token<'a>(cfg: &JwtConfig, headers: &'a HeaderMap) -> Result<Option<&'a str>, JwtError> {
    let name = HeaderName::from_bytes(cfg.header.as_bytes()).map_err(|_| JwtError::Unavailable)?;
    let mut values = headers.get_all(&name).iter();
    let Some(first) = values.next() else { return Ok(None) };
    if values.next().is_some() {
        return Err(JwtError::Malformed); // two tokens are ambiguous
    }
    let value = first.to_str().map_err(|_| JwtError::Malformed)?.trim();
    if cfg.scheme.is_empty() {
        return Ok(Some(value));
    }
    let (scheme, rest) = value.split_once(' ').ok_or(JwtError::Malformed)?;
    if !scheme.eq_ignore_ascii_case(&cfg.scheme) {
        return Err(JwtError::Malformed);
    }
    Ok(Some(rest.trim()))
}

fn numeric_date(v: &Value) -> Option<f64> {
    v.as_f64().filter(|n| n.is_finite() && *n >= 0.0)
}

fn check_signature(key: &Key, alg: JwtAlgorithm, signing_input: &[u8], sig: &[u8]) -> bool {
    match (&key.kind, alg) {
        (KeyKind::Hmac(k), JwtAlgorithm::HS256) => hmac::verify(k, signing_input, sig).is_ok(),
        (KeyKind::Rsa(der), JwtAlgorithm::RS256) => {
            signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, der)
                .verify(signing_input, sig)
                .is_ok()
        }
        (KeyKind::Ec(point), JwtAlgorithm::ES256) => {
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                .verify(signing_input, sig)
                .is_ok()
        }
        _ => false, // a key is never used for an algorithm of another type
    }
}

/// Verify `token` against `keys` under `cfg`'s policy at time `now`.
pub fn verify_token(cfg: &JwtConfig, keys: &KeySet, token: &str, now: SystemTime) -> Result<Claims, JwtError> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(JwtError::Malformed);
    }
    let mut parts = token.split('.');
    let (Some(h64), Some(p64), Some(s64), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(JwtError::Malformed);
    };
    if h64.is_empty() || p64.is_empty() || s64.is_empty() {
        return Err(JwtError::Malformed);
    }
    let decode = |s: &str| URL_SAFE_NO_PAD.decode(s).map_err(|_| JwtError::Malformed);
    let header: Value = serde_json::from_slice(&decode(h64)?).map_err(|_| JwtError::Malformed)?;
    let header = header.as_object().ok_or(JwtError::Malformed)?;
    if header.contains_key("crit") {
        return Err(JwtError::Malformed); // a critical extension we do not understand
    }
    let alg = match header.get("alg").and_then(Value::as_str) {
        Some(name) => cfg.algorithms.iter().copied().find(|a| a.name() == name).ok_or(JwtError::Algorithm)?,
        None => return Err(JwtError::Malformed),
    };
    let kid = match header.get("kid") {
        None => None,
        Some(Value::String(k)) => Some(k.as_str()),
        Some(_) => return Err(JwtError::Malformed),
    };
    let signature_bytes = decode(s64)?;
    // A token naming a `kid` we hold selects those keys; otherwise only keys
    // without a `kid` (a bare PEM / secret) are candidates.
    let named: Vec<&Key> = keys.keys.iter().filter(|k| kid.is_some() && k.kid.as_deref() == kid).collect();
    let pool: Vec<&Key> = if named.is_empty() { keys.keys.iter().filter(|k| k.kid.is_none()).collect() } else { named };
    let candidates: Vec<&Key> = pool
        .into_iter()
        .filter(|k| k.kind.algorithm() == alg && k.pinned.is_none_or(|p| p == alg))
        .take(MAX_CANDIDATES)
        .collect();
    if candidates.is_empty() {
        return Err(JwtError::UnknownKey);
    }
    let signing_input = &token.as_bytes()[..h64.len() + 1 + p64.len()];
    if !candidates.iter().any(|k| check_signature(k, alg, signing_input, &signature_bytes)) {
        return Err(JwtError::Signature);
    }

    // The signature is good: now the claims.
    let claims: Value = serde_json::from_slice(&decode(p64)?).map_err(|_| JwtError::Malformed)?;
    let Value::Object(claims) = claims else { return Err(JwtError::Malformed) };
    let now_s = now.duration_since(UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64());
    let leeway = cfg.leeway.as_secs_f64();
    match claims.get("exp") {
        Some(v) => {
            let exp = numeric_date(v).ok_or(JwtError::Malformed)?;
            if now_s > exp + leeway {
                return Err(JwtError::Expired);
            }
        }
        None if cfg.require_exp => return Err(JwtError::Malformed),
        None => {}
    }
    if let Some(v) = claims.get("nbf") {
        if now_s + leeway < numeric_date(v).ok_or(JwtError::Malformed)? {
            return Err(JwtError::NotYetValid);
        }
    }
    if let Some(want) = &cfg.issuer {
        match claims.get("iss") {
            Some(Value::String(iss)) if iss == want => {}
            _ => return Err(JwtError::Issuer),
        }
    }
    if !cfg.audience.is_empty() {
        let ok = match claims.get("aud") {
            Some(Value::String(a)) => cfg.audience.contains(a),
            Some(Value::Array(list)) => {
                list.iter().any(|a| a.as_str().is_some_and(|a| cfg.audience.iter().any(|w| w == a)))
            }
            _ => false,
        };
        if !ok {
            return Err(JwtError::Audience);
        }
    }
    Ok(claims)
}

/// The text of a claim as a header value: strings, numbers, booleans, and
/// arrays of those (joined with `,`). Anything unprintable or over-long is
/// dropped rather than forwarded.
pub fn claim_header_text(v: &Value) -> Option<String> {
    fn scalar(v: &Value) -> Option<String> {
        match v {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => None, // no nesting: arrays hold scalars only
        }
    }
    let text = match v {
        Value::Array(items) => items.iter().map(scalar).collect::<Option<Vec<_>>>()?.join(","),
        other => scalar(other)?,
    };
    (text.len() <= 256 && text.bytes().all(|b| (0x20..0x7f).contains(&b))).then_some(text)
}

// ----------------------------------------------------------------- registry

type FileStamp = Vec<Option<(SystemTime, u64)>>;

fn stamp(cfg: &JwtConfig) -> FileStamp {
    [&cfg.secret_file, &cfg.public_key_file, &cfg.jwks_file]
        .into_iter()
        .flatten()
        .map(|p| std::fs::metadata(p).ok().and_then(|m| Some((m.modified().ok()?, m.len()))))
        .collect()
}

struct Slot {
    keys: Arc<KeySet>,
    stamp: FileStamp,
    next_check: Instant,
}

/// Loads and caches each route's keys, re-checking their files for rotation.
#[derive(Default)]
pub struct JwtRegistry {
    slots: Mutex<HashMap<JwtConfig, Slot>>,
}

impl std::fmt::Debug for JwtRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtRegistry").finish_non_exhaustive()
    }
}

impl JwtRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// The current keys for `cfg`. Rotated files are picked up within
    /// `reload_interval`; if the new material is unusable the previous keys stay.
    pub fn keys(&self, cfg: &JwtConfig) -> Result<Arc<KeySet>, KeyError> {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        if let Some(slot) = slots.get_mut(cfg) {
            if now < slot.next_check {
                return Ok(Arc::clone(&slot.keys));
            }
            slot.next_check = now + cfg.reload_interval;
            let current = stamp(cfg);
            if current != slot.stamp {
                match KeySet::load(cfg) {
                    Ok(keys) => {
                        tracing::info!(keys = keys.len(), "JWT key material changed on disk; reloaded");
                        slot.keys = Arc::new(keys);
                        slot.stamp = current;
                    }
                    Err(e) => tracing::warn!(error = %e, "JWT key reload failed; keeping the previous keys"),
                }
            }
            return Ok(Arc::clone(&slot.keys));
        }
        let keys = Arc::new(KeySet::load(cfg)?);
        slots.insert(
            cfg.clone(),
            Slot { keys: Arc::clone(&keys), stamp: stamp(cfg), next_check: now + cfg.reload_interval },
        );
        Ok(keys)
    }

    /// Check a request's token. `Ok(None)` means "no token and none was required".
    pub fn verify(&self, cfg: &JwtConfig, headers: &HeaderMap, now: SystemTime) -> Result<Option<Claims>, JwtError> {
        let Some(token) = header_token(cfg, headers)? else {
            return if cfg.required { Err(JwtError::Missing) } else { Ok(None) };
        };
        if token.is_empty() {
            return Err(JwtError::Malformed);
        }
        let keys = self.keys(cfg).map_err(|e| {
            tracing::error!(error = %e, "JWT keys unavailable");
            JwtError::Unavailable
        })?;
        verify_token(cfg, &keys, token, now).map(Some)
    }

    /// Forget keys of routes that no longer exist.
    pub fn retain<'a>(&self, live: impl Iterator<Item = &'a JwtConfig>) {
        let live: std::collections::HashSet<&JwtConfig> = live.collect();
        self.slots.lock().unwrap_or_else(PoisonError::into_inner).retain(|k, _| live.contains(k));
    }
}

/// Load every route's keys now, so a bad key file fails `validate` / startup /
/// reload instead of the first request.
pub fn check_config(cfg: &velox_core::Config) -> Result<(), String> {
    let mut problems = Vec::new();
    for (i, route) in cfg.routes.iter().enumerate() {
        if let Some(j) = &route.jwt {
            if let Err(e) = KeySet::load(j) {
                problems.push(format!("route `{}`: jwt: {e}", cfg.route_id(i)));
            }
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, RsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING, RSA_PKCS1_SHA256};
    use serde_json::json;
    use std::time::Duration;

    const RSA_PRIVATE_PEM: &str = include_str!("../tests/fixtures/test-only-rsa-private.pem");
    const RSA_PUBLIC_PEM: &str = include_str!("../tests/fixtures/test-only-rsa-public.pem");
    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef-secret";

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    fn enc(v: &Value) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
    }

    /// Sign `claims` with the given algorithm.
    struct Signer {
        rsa: RsaKeyPair,
        ec: EcdsaKeyPair,
        ec_public: Vec<u8>,
    }

    fn signer() -> Signer {
        let pkcs8 = rustls::pki_types::PrivatePkcs8KeyDer::from_pem_slice(RSA_PRIVATE_PEM.as_bytes()).unwrap();
        let rsa = RsaKeyPair::from_pkcs8(pkcs8.secret_pkcs8_der()).unwrap();
        let rng = SystemRandom::new();
        let ec_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let ec = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, ec_pkcs8.as_ref(), &rng).unwrap();
        let ec_public = ec.public_key().as_ref().to_vec();
        Signer { rsa, ec, ec_public }
    }

    impl Signer {
        fn token(&self, alg: &str, kid: Option<&str>, claims: &Value) -> String {
            let mut header = json!({ "alg": alg, "typ": "JWT" });
            if let Some(k) = kid {
                header["kid"] = json!(k);
            }
            let input = format!("{}.{}", enc(&header), enc(claims));
            let sig = match alg {
                "HS256" => hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, SECRET), input.as_bytes()).as_ref().to_vec(),
                "RS256" => {
                    let mut sig = vec![0u8; self.rsa.public().modulus_len()];
                    self.rsa.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), input.as_bytes(), &mut sig).unwrap();
                    sig
                }
                "ES256" => self.ec.sign(&SystemRandom::new(), input.as_bytes()).unwrap().as_ref().to_vec(),
                _ => Vec::new(), // `none` and friends: an empty signature segment is built by callers
            };
            format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
        }
    }

    fn claims(extra: Value) -> Value {
        let mut c = json!({ "sub": "alice", "exp": now() + 600 });
        c.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        c
    }

    fn keyset(s: &Signer) -> KeySet {
        let mut keys = vec![hmac_key("t", SECRET).unwrap()];
        let spki = SubjectPublicKeyInfoDer::from_pem_slice(RSA_PUBLIC_PEM.as_bytes()).unwrap();
        keys.push(Key { kid: None, pinned: None, kind: spki_key("rsa", spki.as_ref()).unwrap() });
        keys.push(Key { kid: None, pinned: None, kind: KeyKind::Ec(s.ec_public.clone()) });
        KeySet { keys }
    }

    fn cfg(algs: &[JwtAlgorithm]) -> JwtConfig {
        JwtConfig { algorithms: algs.to_vec(), ..JwtConfig::default() }
    }

    const ALL: [JwtAlgorithm; 3] = [JwtAlgorithm::HS256, JwtAlgorithm::RS256, JwtAlgorithm::ES256];

    fn check(c: &JwtConfig, k: &KeySet, token: &str) -> Result<Claims, JwtError> {
        verify_token(c, k, token, SystemTime::now())
    }

    #[test]
    fn all_three_algorithms_verify_and_return_the_claims() {
        let s = signer();
        let (c, k) = (cfg(&ALL), keyset(&s));
        for alg in ["HS256", "RS256", "ES256"] {
            let claims = check(&c, &k, &s.token(alg, None, &claims(json!({ "role": "admin" }))))
                .unwrap_or_else(|e| panic!("{alg}: {e:?}"));
            assert_eq!(claims["sub"], "alice", "{alg}");
            assert_eq!(claims["role"], "admin", "{alg}");
        }
    }

    #[test]
    fn only_listed_algorithms_are_accepted_and_none_never_is() {
        let s = signer();
        let k = keyset(&s);
        let rs_only = cfg(&[JwtAlgorithm::RS256]);
        assert_eq!(check(&rs_only, &k, &s.token("HS256", None, &claims(json!({})))), Err(JwtError::Algorithm));
        assert_eq!(check(&rs_only, &k, &s.token("ES256", None, &claims(json!({})))), Err(JwtError::Algorithm));
        assert!(check(&rs_only, &k, &s.token("RS256", None, &claims(json!({})))).is_ok());
        // `alg: none`, in every spelling, with and without a signature.
        for alg in ["none", "None", "NONE", "nOnE", "hs256", "Rs256", "RS384", "PS256", "EdDSA", ""] {
            let header = enc(&json!({ "alg": alg }));
            for sig in ["", "AAAA"] {
                let t = format!("{header}.{}.{sig}", enc(&claims(json!({}))));
                assert!(check(&cfg(&ALL), &k, &t).is_err(), "alg {alg:?} sig {sig:?} must be refused");
            }
        }
    }

    #[test]
    fn a_key_is_never_used_for_an_algorithm_of_another_type() {
        // The classic confusion attack: sign HS256 using the RSA *public key* as the secret.
        let s = signer();
        let attacker_secret = RSA_PUBLIC_PEM.as_bytes();
        let input = format!("{}.{}", enc(&json!({ "alg": "HS256" })), enc(&claims(json!({ "sub": "mallory" }))));
        let sig = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, attacker_secret), input.as_bytes());
        let forged = format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()));
        // A route that only holds RSA/EC public keys and (wrongly) lists HS256 must still refuse it.
        let public_only =
            KeySet { keys: keyset(&s).keys.into_iter().filter(|k| !matches!(k.kind, KeyKind::Hmac(_))).collect() };
        assert_eq!(check(&cfg(&ALL), &public_only, &forged), Err(JwtError::UnknownKey));
        // And with the real secret present, the attacker's signature simply does not verify.
        assert_eq!(check(&cfg(&ALL), &keyset(&s), &forged), Err(JwtError::Signature));
        // An RS256 token cannot be verified by an HMAC key either.
        let hmac_only = KeySet { keys: vec![hmac_key("t", SECRET).unwrap()] };
        assert_eq!(
            check(&cfg(&ALL), &hmac_only, &s.token("RS256", None, &claims(json!({})))),
            Err(JwtError::UnknownKey)
        );
    }

    #[test]
    fn tampering_and_wrong_keys_fail_the_signature() {
        let s = signer();
        let (c, k) = (cfg(&ALL), keyset(&s));
        let good = s.token("RS256", None, &claims(json!({})));
        let mut parts: Vec<&str> = good.split('.').collect();
        // Swap in different claims under the original signature.
        let evil = enc(&claims(json!({ "sub": "admin" })));
        parts[1] = &evil;
        assert_eq!(check(&c, &k, &parts.join(".")), Err(JwtError::Signature));
        // Flip a bit of the signature.
        let mut sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        sig[0] ^= 1;
        let flipped = format!("{}.{}.{}", parts[0], good.split('.').nth(1).unwrap(), URL_SAFE_NO_PAD.encode(sig));
        assert_eq!(check(&c, &k, &flipped), Err(JwtError::Signature));
        // A token signed by some other key.
        let other = signer();
        assert_eq!(
            check(&cfg(&[JwtAlgorithm::ES256]), &k, &other.token("ES256", None, &claims(json!({})))),
            Err(JwtError::Signature)
        );
    }

    #[test]
    fn time_claims_are_enforced_with_a_bounded_leeway() {
        let s = signer();
        let k = keyset(&s);
        let c = JwtConfig { leeway: Duration::from_secs(10), ..cfg(&ALL) };
        let t = |extra: Value| {
            let mut claims = json!({ "sub": "a" });
            claims.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            s.token("ES256", None, &claims)
        };
        // exp
        assert!(check(&c, &k, &t(json!({ "exp": now() + 60 }))).is_ok());
        assert_eq!(check(&c, &k, &t(json!({ "exp": now() - 60 }))), Err(JwtError::Expired));
        assert!(check(&c, &k, &t(json!({ "exp": now() - 5 }))).is_ok(), "inside the leeway");
        assert!(check(&c, &k, &t(json!({ "exp": (now() + 60) as f64 + 0.5 }))).is_ok(), "fractional NumericDate");
        // nbf
        assert_eq!(check(&c, &k, &t(json!({ "exp": now() + 600, "nbf": now() + 120 }))), Err(JwtError::NotYetValid));
        assert!(check(&c, &k, &t(json!({ "exp": now() + 600, "nbf": now() + 5 }))).is_ok(), "inside the leeway");
        assert!(check(&c, &k, &t(json!({ "exp": now() + 600, "nbf": now() - 60 }))).is_ok());
        // Wrong types are malformed, never silently ignored.
        for bad in [
            json!({ "exp": "tomorrow" }),
            json!({ "exp": -1 }),
            json!({ "exp": null }),
            json!({ "exp": now() + 60, "nbf": "x" }),
        ] {
            assert_eq!(check(&c, &k, &t(bad.clone())), Err(JwtError::Malformed), "{bad}");
        }
        // exp is mandatory unless the route says otherwise.
        let no_exp = s.token("ES256", None, &json!({ "sub": "a" }));
        assert_eq!(check(&c, &k, &no_exp), Err(JwtError::Malformed));
        assert!(check(&JwtConfig { require_exp: false, ..c.clone() }, &k, &no_exp).is_ok());
    }

    #[test]
    fn issuer_and_audience_are_matched_exactly() {
        let s = signer();
        let k = keyset(&s);
        let c = JwtConfig {
            issuer: Some("https://issuer.test".into()),
            audience: vec!["api".into(), "admin".into()],
            ..cfg(&ALL)
        };
        let ok = |extra: Value| check(&c, &k, &s.token("ES256", None, &claims(extra)));
        assert!(ok(json!({ "iss": "https://issuer.test", "aud": "api" })).is_ok());
        assert!(ok(json!({ "iss": "https://issuer.test", "aud": ["web", "admin"] })).is_ok(), "any listed audience");
        assert_eq!(ok(json!({ "aud": "api" })), Err(JwtError::Issuer), "missing iss");
        assert_eq!(
            ok(json!({ "iss": "https://issuer.test/", "aud": "api" })),
            Err(JwtError::Issuer),
            "not a prefix match"
        );
        assert_eq!(
            ok(json!({ "iss": ["https://issuer.test"], "aud": "api" })),
            Err(JwtError::Issuer),
            "iss must be a string"
        );
        assert_eq!(ok(json!({ "iss": "https://issuer.test" })), Err(JwtError::Audience), "missing aud");
        assert_eq!(ok(json!({ "iss": "https://issuer.test", "aud": "other" })), Err(JwtError::Audience));
        assert_eq!(ok(json!({ "iss": "https://issuer.test", "aud": ["a", 7] })), Err(JwtError::Audience));
        assert_eq!(ok(json!({ "iss": "https://issuer.test", "aud": [] })), Err(JwtError::Audience));
        // Unconfigured: not checked.
        assert!(check(&cfg(&ALL), &k, &s.token("ES256", None, &claims(json!({ "iss": "x", "aud": "y" })))).is_ok());
    }

    #[test]
    fn malformed_tokens_are_refused_without_panicking() {
        let s = signer();
        let (c, k) = (cfg(&ALL), keyset(&s));
        let good = s.token("ES256", None, &claims(json!({})));
        let mut cases: Vec<String> = vec![
            String::new(),
            "x".into(),
            "a.b".into(),
            "a.b.c.d".into(),
            "..".into(),
            "a..c".into(),
            format!("{good}."),
            format!(".{good}"),
            good.replace('.', "=."), // padding is not base64url-no-pad
            good.replace('A', "+"),  // standard-alphabet characters
            "!!!.!!!.!!!".into(),
            format!("{}.{}.sig", enc(&json!([1, 2])), enc(&json!({}))), // header not an object
            format!("{}.{}.sig", enc(&json!({ "alg": 5 })), enc(&json!({}))),
            format!("{}.{}.sig", enc(&json!({ "alg": "ES256", "kid": 5 })), enc(&json!({}))),
            format!("{}.{}.sig", enc(&json!({ "alg": "ES256", "crit": ["exp"] })), enc(&claims(json!({})))),
            format!("{}.{}.AAAA", enc(&json!({ "alg": "ES256" })), URL_SAFE_NO_PAD.encode("not json")),
            "a".repeat(MAX_TOKEN_BYTES + 1),
        ];
        // Tokens built from the good one by truncation at every position.
        for cut in 0..good.len() {
            cases.push(good[..cut].to_owned());
        }
        for t in &cases {
            assert!(check(&c, &k, t).is_err(), "{:?} must be refused", &t[..t.len().min(40)]);
        }
        assert!(check(&c, &k, &good).is_ok());
    }

    #[test]
    fn kid_selects_keys_from_a_jwks_and_rotation_keeps_old_keys_working() {
        let s = signer();
        let other = signer();
        let keys = |entries: Vec<(&str, &Signer)>| KeySet {
            keys: entries
                .into_iter()
                .map(|(kid, sg)| Key { kid: Some(kid.into()), pinned: None, kind: KeyKind::Ec(sg.ec_public.clone()) })
                .collect(),
        };
        let set = keys(vec![("2024-a", &s), ("2025-b", &other)]);
        let c = cfg(&[JwtAlgorithm::ES256]);
        assert!(check(&c, &set, &s.token("ES256", Some("2024-a"), &claims(json!({})))).is_ok());
        assert!(check(&c, &set, &other.token("ES256", Some("2025-b"), &claims(json!({})))).is_ok());
        // A token claiming one key's kid but signed by the other is refused.
        assert_eq!(
            check(&c, &set, &other.token("ES256", Some("2024-a"), &claims(json!({})))),
            Err(JwtError::Signature)
        );
        // An unknown kid does not fall back to "try everything".
        assert_eq!(check(&c, &set, &s.token("ES256", Some("nope"), &claims(json!({})))), Err(JwtError::UnknownKey));
        // No kid with only kid-tagged keys: nothing to try.
        assert_eq!(check(&c, &set, &s.token("ES256", None, &claims(json!({})))), Err(JwtError::UnknownKey));
    }

    #[test]
    fn der_and_pem_key_parsing() {
        // The RSA SPKI from openssl parses, and a re-encoded n/e round-trips to the same key.
        let spki = SubjectPublicKeyInfoDer::from_pem_slice(RSA_PUBLIC_PEM.as_bytes()).unwrap();
        let KeyKind::Rsa(pkcs1) = spki_key("rsa", spki.as_ref()).unwrap() else { panic!("expected RSA") };
        let (_, body, _) = der(&pkcs1).unwrap();
        let (_, n, rest) = der(body).unwrap();
        let (_, e, _) = der(rest).unwrap();
        assert_eq!(rsa_public_key(n, e), pkcs1, "DER writer matches openssl's encoding");
        // Garbage and wrong key types are errors, not panics.
        for bad in [&b""[..], b"\x30", b"\x30\x00", b"\x30\x03\x01\x01\x00", &[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]] {
            assert!(spki_key("x", bad).is_err());
        }
        // der_uint minimal encoding: leading zeros stripped, sign byte added.
        assert_eq!(der_uint(&[0, 0, 0x7f]), [0x02, 0x01, 0x7f]);
        assert_eq!(der_uint(&[0x80]), [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(der_uint(&[]), [0x02, 0x01, 0x00]);
        assert_eq!(der_len(0x7f), [0x7f]);
        assert_eq!(der_len(0x80), [0x81, 0x80]);
        assert_eq!(der_len(0x1234), [0x82, 0x12, 0x34]);
    }

    #[test]
    fn claim_text_for_forwarding_is_conservative() {
        assert_eq!(claim_header_text(&json!("alice")).as_deref(), Some("alice"));
        assert_eq!(claim_header_text(&json!(42)).as_deref(), Some("42"));
        assert_eq!(claim_header_text(&json!(true)).as_deref(), Some("true"));
        assert_eq!(claim_header_text(&json!(["a", "b", 3])).as_deref(), Some("a,b,3"));
        for refused in [
            json!(null),
            json!({ "a": 1 }),
            json!([[1]]),
            json!("line\nbreak"),
            json!("caf\u{e9}"),
            json!("x".repeat(300)),
            json!(["ok", { "no": 1 }]),
        ] {
            assert_eq!(claim_header_text(&refused), None, "{refused}");
        }
    }

    // ---- key files ----

    fn rsa_components() -> (Vec<u8>, Vec<u8>) {
        let spki = SubjectPublicKeyInfoDer::from_pem_slice(RSA_PUBLIC_PEM.as_bytes()).unwrap();
        let KeyKind::Rsa(pkcs1) = spki_key("rsa", spki.as_ref()).unwrap() else { panic!() };
        let (_, body, _) = der(&pkcs1).unwrap();
        let (_, n, rest) = der(body).unwrap();
        let (_, e, _) = der(rest).unwrap();
        (n.to_vec(), e.to_vec())
    }

    fn jwks_doc(s: &Signer, extra: Vec<Value>) -> String {
        let (n, e) = rsa_components();
        let mut keys = vec![
            json!({ "kty": "RSA", "kid": "rsa-1", "use": "sig", "alg": "RS256", "n": URL_SAFE_NO_PAD.encode(&n), "e": URL_SAFE_NO_PAD.encode(&e) }),
            json!({ "kty": "EC", "kid": "ec-1", "crv": "P-256",
                    "x": URL_SAFE_NO_PAD.encode(&s.ec_public[1..33]), "y": URL_SAFE_NO_PAD.encode(&s.ec_public[33..]) }),
            json!({ "kty": "RSA", "kid": "enc-only", "use": "enc", "n": "AQAB", "e": "AQAB" }),
            json!({ "kty": "OKP", "kid": "ed", "crv": "Ed25519", "x": "AAAA" }),
        ];
        keys.extend(extra);
        json!({ "keys": keys }).to_string()
    }

    #[test]
    fn keys_load_from_jwks_pem_and_secret_files() {
        let dir = tempfile::tempdir().unwrap();
        let s = signer();
        let write = |name: &str, data: &[u8]| {
            let p = dir.path().join(name);
            std::fs::write(&p, data).unwrap();
            p
        };
        let jwks = write("jwks.json", jwks_doc(&s, vec![]).as_bytes());
        let c = JwtConfig { jwks_file: Some(jwks), ..cfg(&[JwtAlgorithm::RS256, JwtAlgorithm::ES256]) };
        let keys = KeySet::load(&c).unwrap();
        assert_eq!(keys.len(), 2, "RSA + EC kept; the encryption key and the OKP key are skipped");
        assert!(check(&c, &keys, &s.token("RS256", Some("rsa-1"), &claims(json!({})))).is_ok(), "RS256 via JWKS n/e");
        assert!(check(&c, &keys, &s.token("ES256", Some("ec-1"), &claims(json!({})))).is_ok(), "ES256 via JWKS x/y");
        // A jwk pinned to RS256 is not used for ES256, and kid mixes are refused.
        assert_eq!(check(&c, &keys, &s.token("ES256", Some("rsa-1"), &claims(json!({})))), Err(JwtError::UnknownKey));
        assert_eq!(
            check(&c, &keys, &s.token("RS256", Some("enc-only"), &claims(json!({})))),
            Err(JwtError::UnknownKey)
        );

        // PEM with the RSA key; a secret file (one trailing newline ignored).
        let pem = write("pub.pem", RSA_PUBLIC_PEM.as_bytes());
        let mut secret = SECRET.to_vec();
        secret.push(b'\n');
        let sec = write("secret", &secret);
        let c = JwtConfig { public_key_file: Some(pem), secret_file: Some(sec), ..cfg(&ALL) };
        let keys = KeySet::load(&c).unwrap();
        assert!(check(&c, &keys, &s.token("RS256", None, &claims(json!({})))).is_ok());
        assert!(
            check(&c, &keys, &s.token("HS256", None, &claims(json!({})))).is_ok(),
            "the newline is not part of the secret"
        );

        // The secret may also come from the environment.
        std::env::set_var("VELOX_TEST_JWT_SECRET", String::from_utf8(SECRET.to_vec()).unwrap());
        let c = JwtConfig { secret_env: Some("VELOX_TEST_JWT_SECRET".into()), ..cfg(&[JwtAlgorithm::HS256]) };
        assert!(check(&c, &KeySet::load(&c).unwrap(), &s.token("HS256", None, &claims(json!({})))).is_ok());
    }

    #[test]
    fn unusable_key_material_is_refused_loudly() {
        let dir = tempfile::tempdir().unwrap();
        let s = signer();
        let write = |name: &str, data: &str| {
            let p = dir.path().join(name);
            std::fs::write(&p, data).unwrap();
            p
        };
        let load = |c: &JwtConfig| KeySet::load(c).map(|_| ()).unwrap_err().to_string();
        let base = cfg(&ALL);
        assert!(load(&JwtConfig { secret_file: Some(write("short", "tooshort")), ..base.clone() })
            .contains("at least 32 bytes"));
        assert!(
            load(&JwtConfig { secret_env: Some("VELOX_DEFINITELY_UNSET".into()), ..base.clone() }).contains("not set")
        );
        assert!(load(&JwtConfig { public_key_file: Some(write("junk.pem", "nope")), ..base.clone() })
            .contains("PUBLIC KEY"));
        assert!(load(&JwtConfig { public_key_file: Some(dir.path().join("missing.pem")), ..base.clone() })
            .contains("missing.pem"));
        // A private key (or certificate) is not a public key.
        let private = write("priv.pem", RSA_PRIVATE_PEM);
        assert!(load(&JwtConfig { public_key_file: Some(private), ..base.clone() }).contains("PUBLIC KEY"));
        // Bad JWKS: not JSON, no keys, symmetric key, unsupported curve, short coordinates.
        for (name, doc, want) in [
            ("notjson", "{{".to_owned(), "invalid JSON"),
            ("nokeys", "{}".to_owned(), "no `keys`"),
            ("empty", "{\"keys\": []}".to_owned(), "no usable"),
            ("oct", json!({ "keys": [{ "kty": "oct", "k": "c2VjcmV0" }] }).to_string(), "symmetric"),
            ("p384", json!({ "keys": [{ "kty": "EC", "crv": "P-384", "x": "AA", "y": "AA" }] }).to_string(), "P-256"),
            (
                "short",
                json!({ "keys": [{ "kty": "EC", "crv": "P-256", "x": "AA", "y": "AA" }] }).to_string(),
                "32 bytes",
            ),
            ("rsa-missing", json!({ "keys": [{ "kty": "RSA", "n": "AQAB" }] }).to_string(), "`n` and `e`"),
        ] {
            let p = write(name, &doc);
            let err = load(&JwtConfig { jwks_file: Some(p), ..base.clone() });
            assert!(err.contains(want), "{name}: {err}");
        }
        let _ = s;
        // Nothing configured at all.
        assert!(load(&base).contains("no key material"));
    }

    #[test]
    fn the_registry_picks_up_rotation_and_keeps_the_last_good_keys_when_it_breaks() {
        let dir = tempfile::tempdir().unwrap();
        let (old, new) = (signer(), signer());
        let path = dir.path().join("jwks.json");
        let write_keys = |sg: &Signer, kid: &str| {
            let doc = json!({ "keys": [{ "kty": "EC", "kid": kid, "crv": "P-256",
                "x": URL_SAFE_NO_PAD.encode(&sg.ec_public[1..33]), "y": URL_SAFE_NO_PAD.encode(&sg.ec_public[33..]) }] });
            std::fs::write(&path, doc.to_string()).unwrap();
        };
        write_keys(&old, "k1");
        let c = JwtConfig {
            jwks_file: Some(path.clone()),
            reload_interval: Duration::from_millis(60),
            ..cfg(&[JwtAlgorithm::ES256])
        };
        let reg = JwtRegistry::new();
        let mut headers = HeaderMap::new();
        let present = |h: &mut HeaderMap, t: &str| {
            h.insert("authorization", format!("Bearer {t}").parse().unwrap());
        };
        present(&mut headers, &old.token("ES256", Some("k1"), &claims(json!({}))));
        assert!(reg.verify(&c, &headers, SystemTime::now()).unwrap().is_some());

        // Rotate: k2 replaces k1 (and the file length changes so the stamp differs).
        std::thread::sleep(Duration::from_millis(100));
        write_keys(&new, "key-two-with-a-longer-id");
        present(&mut headers, &new.token("ES256", Some("key-two-with-a-longer-id"), &claims(json!({}))));
        assert!(
            reg.verify(&c, &headers, SystemTime::now()).unwrap().is_some(),
            "the new key is used after the next check"
        );
        present(&mut headers, &old.token("ES256", Some("k1"), &claims(json!({}))));
        assert_eq!(reg.verify(&c, &headers, SystemTime::now()), Err(JwtError::UnknownKey), "the retired key is gone");

        // A broken rotation (half-written file) must not lock everyone out.
        std::thread::sleep(Duration::from_millis(100));
        std::fs::write(&path, "{ \"keys\": [").unwrap();
        std::thread::sleep(Duration::from_millis(100));
        present(&mut headers, &new.token("ES256", Some("key-two-with-a-longer-id"), &claims(json!({}))));
        assert!(reg.verify(&c, &headers, SystemTime::now()).unwrap().is_some(), "last good keys kept");
    }

    #[test]
    fn the_registry_applies_the_presence_rules_and_header_syntax() {
        let dir = tempfile::tempdir().unwrap();
        let s = signer();
        let pem = dir.path().join("k.pem");
        std::fs::write(&pem, RSA_PUBLIC_PEM).unwrap();
        let c = JwtConfig { public_key_file: Some(pem), ..cfg(&[JwtAlgorithm::RS256]) };
        let reg = JwtRegistry::new();
        let tok = s.token("RS256", None, &claims(json!({})));
        let with = |name: &'static str, value: &str| {
            let mut h = HeaderMap::new();
            h.insert(name, value.parse().unwrap());
            h
        };
        let go = |h: &HeaderMap| reg.verify(&c, h, SystemTime::now());
        assert!(go(&with("authorization", &format!("Bearer {tok}"))).unwrap().is_some());
        assert!(
            go(&with("authorization", &format!("bearer {tok}"))).unwrap().is_some(),
            "the scheme is case-insensitive"
        );
        assert_eq!(go(&HeaderMap::new()), Err(JwtError::Missing));
        for bad in [
            format!("Basic {tok}"),
            tok.clone(),
            "Bearer".to_owned(),
            "Bearer ".to_owned(),
            format!("Bearer {tok} extra"),
        ] {
            assert!(go(&with("authorization", &bad)).is_err(), "{bad:?}");
        }
        // Two Authorization headers are ambiguous.
        let mut two = HeaderMap::new();
        two.append("authorization", format!("Bearer {tok}").parse().unwrap());
        two.append("authorization", format!("Bearer {tok}").parse().unwrap());
        assert_eq!(go(&two), Err(JwtError::Malformed));
        // Optional tokens: absent is fine, present-but-bad is not.
        let optional = JwtConfig { required: false, ..c.clone() };
        assert_eq!(reg.verify(&optional, &HeaderMap::new(), SystemTime::now()), Ok(None));
        assert!(reg.verify(&optional, &with("authorization", "Bearer garbage"), SystemTime::now()).is_err());
        // A custom header with a bare token.
        let custom = JwtConfig { header: "x-api-token".into(), scheme: String::new(), ..c.clone() };
        assert!(reg.verify(&custom, &with("x-api-token", &tok), SystemTime::now()).unwrap().is_some());
        assert_eq!(
            reg.verify(&custom, &with("authorization", &format!("Bearer {tok}")), SystemTime::now()),
            Err(JwtError::Missing)
        );
        // Keys that cannot be loaded fail closed.
        let broken = JwtConfig { public_key_file: Some(dir.path().join("gone.pem")), ..c };
        assert_eq!(
            reg.verify(&broken, &with("authorization", &format!("Bearer {tok}")), SystemTime::now()),
            Err(JwtError::Unavailable)
        );
    }

    /// The invariants of the `jwt_token` fuzz target, replayed over generated
    /// garbage so `cargo test` catches a violation: re-signed random JSON-ish
    /// header/payload pairs never panic, and anything accepted has the claims the
    /// route demands.
    #[test]
    fn fuzz_invariants_hold_for_resigned_garbage() {
        let cfg = JwtConfig {
            algorithms: vec![JwtAlgorithm::HS256],
            issuer: Some("https://issuer.test".into()),
            audience: vec!["api".into()],
            ..JwtConfig::default()
        };
        let keys = KeySet::hmac(SECRET).unwrap();
        let key = hmac::Key::new(hmac::HMAC_SHA256, SECRET);
        let fragments = [
            r#"{"alg":"HS256"}"#,
            r#"{"alg":"HS256","kid":"x"}"#,
            r#"{"alg":"none"}"#,
            r#"{"alg":"HS256","crit":["b64"]}"#,
            "{",
            "[]",
            "null",
            "",
            r#"{"exp":9999999999,"iss":"https://issuer.test","aud":"api"}"#,
            r#"{"exp":9999999999,"iss":"https://issuer.test","aud":["x","api"]}"#,
            r#"{"exp":1,"iss":"https://issuer.test","aud":"api"}"#,
            r#"{"exp":"soon"}"#,
            r#"{"exp":9999999999,"nbf":9999999998}"#,
            r#"{"exp":9999999999,"iss":"other","aud":"api"}"#,
            r#"{"exp":9999999999,"iss":"https://issuer.test"}"#,
            "\u{0}\u{ff}",
        ];
        let mut x: u64 = 0x5DEECE66D;
        let mut next = move |n: usize| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x % n as u64) as usize
        };
        let (mut accepted, mut refused) = (0, 0);
        for _ in 0..20_000 {
            let (h, p) = (fragments[next(fragments.len())], fragments[next(fragments.len())]);
            let input = format!("{}.{}", URL_SAFE_NO_PAD.encode(h), URL_SAFE_NO_PAD.encode(p));
            let sig = hmac::sign(&key, input.as_bytes());
            let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()));
            match verify_token(&cfg, &keys, &token, SystemTime::now()) {
                Ok(claims) => {
                    accepted += 1;
                    assert_eq!(claims.get("iss").and_then(Value::as_str), Some("https://issuer.test"), "{p}");
                    assert!(claims.contains_key("exp") && claims.contains_key("aud"), "{p}");
                    assert!(!h.contains("none") && !h.contains("crit"), "{h}");
                }
                Err(_) => refused += 1,
            }
            // Arbitrary mutations of a valid token are never accepted (the signature breaks).
            let mut bytes = token.into_bytes();
            let i = next(bytes.len());
            bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
            if let Ok(mutated) = String::from_utf8(bytes) {
                if mutated != format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref())) {
                    assert!(
                        verify_token(&cfg, &keys, &mutated, SystemTime::now()).is_err(),
                        "a mutated token was accepted: {mutated}"
                    );
                }
            }
        }
        assert!(accepted > 100 && refused > 100, "both outcomes must be exercised ({accepted}/{refused})");
    }
}
