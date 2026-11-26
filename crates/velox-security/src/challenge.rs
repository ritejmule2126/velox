//! Storage for pending ACME HTTP-01 challenge responses.
//!
//! This type is always compiled so the proxy can serve
//! `/.well-known/acme-challenge/<token>` regardless of the `acme` feature.

use dashmap::DashMap;

/// URL prefix under which HTTP-01 challenges are answered.
pub const CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

/// Maps challenge tokens to their key authorizations.
#[derive(Debug, Default)]
pub struct ChallengeStore {
    tokens: DashMap<String, String>,
}

impl ChallengeStore {
    /// Register the response for `token`.
    pub fn insert(&self, token: String, key_authorization: String) {
        self.tokens.insert(token, key_authorization);
    }

    /// Remove a finished challenge.
    pub fn remove(&self, token: &str) {
        self.tokens.remove(token);
    }

    /// The response body for a request `path`, if it is a known challenge.
    pub fn respond(&self, path: &str) -> Option<String> {
        let token = path.strip_prefix(CHALLENGE_PREFIX)?;
        if token.is_empty()
            || token.len() > 256
            || !token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
        self.tokens.get(token).map(|v| v.clone())
    }

    /// Number of pending challenges.
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// `true` when nothing is pending.
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serves_only_known_well_formed_tokens() {
        let s = ChallengeStore::default();
        s.insert("abc-DEF_1".into(), "abc-DEF_1.thumb".into());
        assert_eq!(s.respond("/.well-known/acme-challenge/abc-DEF_1").as_deref(), Some("abc-DEF_1.thumb"));
        assert!(s.respond("/.well-known/acme-challenge/other").is_none());
        assert!(s.respond("/.well-known/acme-challenge/../etc").is_none());
        assert!(s.respond("/.well-known/acme-challenge/").is_none());
        assert!(s.respond("/other").is_none());
        s.remove("abc-DEF_1");
        assert!(s.is_empty());
    }
}
