//! The management surface of the response cache, kept in `velox-core` so the
//! admin API can purge entries without depending on the proxy crate.

use serde::{Deserialize, Serialize};

/// Which cached entries to drop. At least one selector is required; several
/// narrow the match (they are ANDed).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurgeRequest {
    /// Drop everything.
    #[serde(default)]
    pub all: bool,
    /// Only entries of this route (its name or `route-<n>` id).
    #[serde(default)]
    pub route: Option<String>,
    /// Only entries for this host (case-insensitive, no port).
    #[serde(default)]
    pub host: Option<String>,
    /// Only the entry for exactly this path and query (`/a/b?x=1`).
    #[serde(default)]
    pub path: Option<String>,
    /// Only entries whose path starts with this prefix (query excluded).
    #[serde(default)]
    pub path_prefix: Option<String>,
}

impl PurgeRequest {
    /// Does this request select anything at all? (An empty request is refused
    /// rather than silently meaning "everything".)
    pub fn is_selective(&self) -> bool {
        self.all || self.route.is_some() || self.host.is_some() || self.path.is_some() || self.path_prefix.is_some()
    }
}

/// A point-in-time view of the cache.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CacheStats {
    /// Cached objects (a `Vary`-ing URL counts once per variant).
    pub entries: usize,
    /// Bytes held (bodies, headers and keys).
    pub bytes: usize,
    /// The configured ceiling.
    pub max_bytes: u64,
    /// Lookups served from the cache since start.
    pub hits: u64,
    /// Eligible lookups that went to the backend.
    pub misses: u64,
    /// Entries removed to make room.
    pub evictions: u64,
}

/// What the admin API needs from the cache.
pub trait CacheAdmin: Send + Sync + 'static {
    /// Remove matching entries; returns how many were dropped.
    fn purge(&self, request: &PurgeRequest) -> usize;
    /// Current occupancy and counters.
    fn stats(&self) -> CacheStats;
}
