//! Opt-in in-memory response cache for `GET`/`HEAD`.
//!
//! Three layers, each testable on its own:
//!
//! 1. **Policy** ([`classify_request`], [`evaluate_response`], [`serve_hit`]) —
//!    the shared-cache subset of RFC 9111 that Velox implements, as pure
//!    functions over headers.
//! 2. **Store** ([`Cache`]) — a sharded, byte-bounded LRU. A URL maps to a set of
//!    `Vary` variants. Each shard has its own lock, held only for map operations
//!    (never across I/O or while copying bodies, which are reference-counted
//!    [`Bytes`]).
//! 3. **Fill** ([`FillTicket`], [`CacheFill`]) — on a miss the response streams to
//!    the client unchanged while a bounded copy is collected; the entry is
//!    inserted only if the body ended cleanly, matched its declared length and
//!    stayed under `max_entry_bytes`.
//!
//! What is cached, strictly:
//!
//! * Only `GET` is stored; `HEAD` is answered from a stored `GET`. Requests with
//!   `Authorization`, `Range`/`If-Range`, a body, or `Upgrade` never touch the
//!   cache, nor does a request `Cache-Control: no-store`; `no-cache`,
//!   `max-age=0` and `Pragma: no-cache` skip the lookup but may refresh the entry.
//! * Responses are stored only with an explicit lifetime — `s-maxage`, then
//!   `max-age`, then `Expires` (relative to `Date`) — or the route's configured
//!   `default_ttl`. Velox does not guess ("heuristic") freshness.
//! * Never stored: `no-store`, `private`, `no-cache`, `Set-Cookie`, `Vary: *`,
//!   `Pragma: no-cache`, partial content, and statuses outside the cacheable set
//!   (200, 203, 204, 300, 301, 308, 404, 405, 410, 414, 501). Responses with
//!   trailers are not stored either.
//! * Matching honours `Vary` by comparing the stored request header values.
//!   `If-None-Match` (weak comparison, `*`) and `If-Modified-Since` produce `304`
//!   from a stored `200`.
//! * A successful unsafe request (`POST`/`PUT`/`PATCH`/`DELETE`) to a URL
//!   invalidates that URL (RFC 9111 §4.4).
//!
//! Not implemented, by design: serving stale content, background revalidation,
//! and request coalescing (concurrent misses each go to the backend).

use crate::body::ProxyBody;
use crate::error::BoxError;
use bytes::{Bytes, BytesMut};
use http::header::{
    HeaderName, HeaderValue, AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_LOCATION, CONTENT_RANGE, COOKIE,
    DATE, ETAG, EXPIRES, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE, LAST_MODIFIED, PRAGMA, RANGE, SET_COOKIE,
    TRANSFER_ENCODING, UPGRADE, VARY,
};
use http::{HeaderMap, Method, StatusCode};
use http_body::{Body, Frame, SizeHint};
use pin_project_lite::pin_project;
use std::collections::{BTreeMap, HashMap};
use std::hash::{BuildHasher, RandomState};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime};
use velox_core::cache_admin::{CacheAdmin, CacheStats, PurgeRequest};
use velox_core::config::RouteCacheConfig;
use velox_telemetry::Metrics;

/// Response header describing how the cache treated the request.
pub const X_CACHE: HeaderName = HeaderName::from_static("x-velox-cache");
/// `Age`.
const AGE: HeaderName = HeaderName::from_static("age");

/// Most `Vary` variants kept per URL.
const MAX_VARIANTS: usize = 8;
/// Longest cache key accepted (longer URLs are simply not cached).
const MAX_KEY_BYTES: usize = 4096;
/// Fixed per-entry overhead added to the size estimate.
const ENTRY_OVERHEAD: usize = 256;

// ------------------------------------------------------------------ policy

/// Parsed `Cache-Control` directives (all header lines together).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CacheControl {
    /// `no-store`.
    pub no_store: bool,
    /// `no-cache` (with or without field names).
    pub no_cache: bool,
    /// `private` (with or without field names).
    pub private: bool,
    /// `public`.
    pub public: bool,
    /// `max-age`; an invalid value counts as `0` (stale), per RFC 9111 §4.2.1.
    pub max_age: Option<u64>,
    /// `s-maxage`, same rule.
    pub s_maxage: Option<u64>,
}

fn delta_seconds(v: &str) -> u64 {
    let v = v.trim().trim_matches('"');
    if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) {
        v.parse().unwrap_or(u64::MAX) // absurdly large: effectively forever (clamped later)
    } else {
        0
    }
}

impl CacheControl {
    /// Parse every `Cache-Control` line.
    pub fn parse(headers: &HeaderMap) -> Self {
        let mut cc = Self::default();
        for line in headers.get_all(CACHE_CONTROL) {
            let Ok(line) = line.to_str() else {
                cc.no_store = true; // unreadable: be conservative
                continue;
            };
            for directive in line.split(',') {
                let (name, value) = directive.split_once('=').map_or((directive, None), |(n, v)| (n, Some(v)));
                let name = name.trim();
                if name.eq_ignore_ascii_case("no-store") {
                    cc.no_store = true;
                } else if name.eq_ignore_ascii_case("no-cache") {
                    cc.no_cache = true;
                } else if name.eq_ignore_ascii_case("private") {
                    cc.private = true;
                } else if name.eq_ignore_ascii_case("public") {
                    cc.public = true;
                } else if name.eq_ignore_ascii_case("max-age") {
                    // The first occurrence wins when a directive is repeated.
                    cc.max_age.get_or_insert_with(|| value.map_or(0, delta_seconds));
                } else if name.eq_ignore_ascii_case("s-maxage") {
                    cc.s_maxage.get_or_insert_with(|| value.map_or(0, delta_seconds));
                }
            }
        }
        cc
    }
}

/// How a request interacts with the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestMode {
    /// Serve a fresh hit; otherwise fetch and store.
    Normal,
    /// The client wants a fresh answer: skip the lookup, but store the result.
    Refresh,
    /// Never touch the cache (the reason is a metric label).
    Bypass(&'static str),
}

/// Decide how `method`/`headers` may use the cache. `has_body` is true for
/// requests that carry a body; `allow_cookies` is the route's opt-in to caching
/// requests that carry a `Cookie`.
pub fn classify_request(method: &Method, headers: &HeaderMap, has_body: bool, allow_cookies: bool) -> RequestMode {
    if !matches!(*method, Method::GET | Method::HEAD) {
        return RequestMode::Bypass("method");
    }
    if has_body {
        return RequestMode::Bypass("body");
    }
    if headers.contains_key(AUTHORIZATION) {
        return RequestMode::Bypass("authorization");
    }
    if !allow_cookies && headers.contains_key(COOKIE) {
        return RequestMode::Bypass("cookie");
    }
    if headers.contains_key(RANGE) || headers.contains_key(IF_RANGE) {
        return RequestMode::Bypass("range");
    }
    if headers.contains_key(UPGRADE) {
        return RequestMode::Bypass("upgrade");
    }
    let cc = CacheControl::parse(headers);
    if cc.no_store {
        return RequestMode::Bypass("no-store");
    }
    let pragma_no_cache = headers
        .get_all(PRAGMA)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("no-cache")));
    if cc.no_cache || cc.max_age == Some(0) || pragma_no_cache {
        return RequestMode::Refresh;
    }
    RequestMode::Normal
}

/// A response the cache may keep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Storable {
    /// How much longer it stays fresh (already net of any `Age`).
    pub lifetime: Duration,
    /// The `Age` the backend (or an upstream cache) reported.
    pub upstream_age: u64,
    /// Request headers the response varies on (sorted, unique).
    pub vary: Vec<HeaderName>,
}

const CACHEABLE_STATUS: [u16; 11] = [200, 203, 204, 300, 301, 308, 404, 405, 410, 414, 501];

fn http_date(headers: &HeaderMap, name: &HeaderName) -> Option<SystemTime> {
    httpdate::parse_http_date(headers.get(name)?.to_str().ok()?).ok()
}

/// May this response be stored, and for how long?
///
/// `Err` carries a short reason (a metric label).
pub fn evaluate_response(
    status: StatusCode,
    headers: &HeaderMap,
    route: &RouteCacheConfig,
    now: SystemTime,
) -> Result<Storable, &'static str> {
    if !CACHEABLE_STATUS.contains(&status.as_u16()) {
        return Err("status");
    }
    if headers.contains_key(CONTENT_RANGE) {
        return Err("range");
    }
    let cc = CacheControl::parse(headers);
    if cc.no_store {
        return Err("no-store");
    }
    if cc.private {
        return Err("private");
    }
    if cc.no_cache {
        return Err("no-cache");
    }
    if headers.contains_key(SET_COOKIE) {
        return Err("set-cookie");
    }
    let pragma = headers
        .get_all(PRAGMA)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("no-cache")));
    if pragma && cc.max_age.is_none() && cc.s_maxage.is_none() {
        return Err("no-cache");
    }

    let mut vary = Vec::new();
    for line in headers.get_all(VARY) {
        let line = line.to_str().map_err(|_| "vary")?;
        for name in line.split(',').map(str::trim).filter(|n| !n.is_empty()) {
            if name == "*" {
                return Err("vary-star");
            }
            vary.push(HeaderName::from_bytes(name.as_bytes()).map_err(|_| "vary")?);
        }
    }
    vary.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    vary.dedup();
    if vary.len() > 8 {
        return Err("vary");
    }

    // Freshness lifetime: s-maxage, max-age, Expires - Date, then the route default.
    let explicit = if let Some(s) = cc.s_maxage {
        Some(Duration::from_secs(s))
    } else if let Some(m) = cc.max_age {
        Some(Duration::from_secs(m))
    } else if headers.contains_key(EXPIRES) {
        let date = http_date(headers, &DATE).unwrap_or(now);
        // An unparseable `Expires` means "already expired" (RFC 9111 §5.3).
        Some(http_date(headers, &EXPIRES).and_then(|e| e.duration_since(date).ok()).unwrap_or_default())
    } else {
        None
    };
    let mut lifetime = match (explicit, route.default_ttl) {
        (Some(l), _) => l,
        (None, Some(d)) => d,
        (None, None) => return Err("no-freshness"),
    };
    if let Some(max) = route.max_ttl {
        lifetime = lifetime.min(max);
    }
    let upstream_age = headers.get(AGE).and_then(|v| v.to_str().ok()).map_or(0, delta_seconds);
    let lifetime = lifetime.saturating_sub(Duration::from_secs(upstream_age));
    if lifetime.is_zero() {
        return Err("expired");
    }
    Ok(Storable { lifetime, upstream_age, vary })
}

/// The request's value(s) of header `name`, joined (for `Vary` comparison).
fn request_value(headers: &HeaderMap, name: &HeaderName) -> Option<Bytes> {
    let mut lines = headers.get_all(name).iter();
    let first = lines.next()?;
    let Some(second) = lines.next() else { return Some(Bytes::copy_from_slice(first.as_bytes().trim_ascii())) };
    let mut joined = Vec::from(first.as_bytes().trim_ascii());
    for v in std::iter::once(second).chain(lines) {
        joined.extend_from_slice(b", ");
        joined.extend_from_slice(v.as_bytes().trim_ascii());
    }
    Some(Bytes::from(joined))
}

fn vary_snapshot(names: &[HeaderName], request: &HeaderMap) -> Vec<(HeaderName, Option<Bytes>)> {
    names.iter().map(|n| (n.clone(), request_value(request, n))).collect()
}

// ------------------------------------------------------------------- entries

/// One stored response.
#[derive(Debug)]
pub struct Entry {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
    vary: Vec<(HeaderName, Option<Bytes>)>,
    stored_at: Instant,
    fresh_until: Instant,
    base_age: u64,
    size: usize,
    etag: Option<HeaderValue>,
    last_modified: Option<SystemTime>,
}

impl Entry {
    /// Seconds old, as `Age` would report it.
    pub fn age(&self, now: Instant) -> u64 {
        self.base_age.saturating_add(now.saturating_duration_since(self.stored_at).as_secs())
    }

    fn is_fresh(&self, now: Instant) -> bool {
        now < self.fresh_until
    }

    fn matches(&self, request: &HeaderMap) -> bool {
        self.vary.iter().all(|(name, stored)| request_value(request, name) == *stored)
    }

    /// Body size in bytes.
    pub fn body_len(&self) -> usize {
        self.body.len()
    }
}

fn estimate_size(key: &str, headers: &HeaderMap, body: &Bytes) -> usize {
    key.len()
        + body.len()
        + headers.iter().map(|(k, v)| k.as_str().len() + v.len() + 32).sum::<usize>()
        + ENTRY_OVERHEAD
}

/// What to remember about a URL independent of its variants (for purging).
#[derive(Debug)]
pub struct KeyMeta {
    route: Arc<str>,
    host: String,
    /// Whether the client connection was TLS: Velox tells the backend
    /// (`X-Forwarded-Proto`), and its answer may differ, so the two never share an entry.
    secure: bool,
    /// `path?query` as keyed.
    target: String,
}

impl KeyMeta {
    /// Describe a cache key. `host` has no port; it is lowercased here.
    pub fn new(route: &Arc<str>, host: &str, secure: bool, target: &str) -> Self {
        Self { route: Arc::clone(route), host: host.to_ascii_lowercase(), secure, target: target.to_owned() }
    }

    /// The map key for this URL, or `None` if it is too long to cache.
    pub fn key(&self) -> Option<Arc<str>> {
        let key = format!("{}\0{}\0{}\0{}", self.route, self.host, u8::from(self.secure), self.target);
        (key.len() <= MAX_KEY_BYTES).then(|| Arc::from(key))
    }

    fn matches(&self, p: &PurgeRequest) -> bool {
        if p.all {
            return true;
        }
        let path = self.target.split('?').next().unwrap_or("");
        p.route.as_deref().is_none_or(|r| *self.route == *r)
            && p.host.as_deref().is_none_or(|h| self.host.eq_ignore_ascii_case(h))
            && p.path.as_deref().is_none_or(|t| self.target == t)
            && p.path_prefix.as_deref().is_none_or(|pre| path.starts_with(pre))
    }
}

// --------------------------------------------------------------------- store

struct Slot {
    variants: Vec<Arc<Entry>>,
    meta: Arc<KeyMeta>,
    tick: u64,
    bytes: usize,
}

#[derive(Default)]
struct Shard {
    map: HashMap<Arc<str>, Slot>,
    /// LRU order: smallest tick = least recently used.
    lru: BTreeMap<u64, Arc<str>>,
    tick: u64,
    bytes: usize,
    entries: usize,
}

impl Shard {
    fn touch(&mut self, key: &Arc<str>) {
        self.tick += 1;
        if let Some(slot) = self.map.get_mut(key) {
            self.lru.remove(&slot.tick);
            slot.tick = self.tick;
            self.lru.insert(self.tick, Arc::clone(key));
        }
    }

    fn remove_slot(&mut self, key: &str) -> Option<Slot> {
        let slot = self.map.remove(key)?;
        self.lru.remove(&slot.tick);
        self.bytes -= slot.bytes;
        self.entries -= slot.variants.len();
        Some(slot)
    }

    /// Add `entry` to `key`'s slot, replacing the variant with the same `Vary`
    /// values and bounding the variant count (oldest dropped first).
    fn insert_variant(&mut self, key: &Arc<str>, meta: &Arc<KeyMeta>, entry: &Arc<Entry>) {
        let slot = self.map.entry(Arc::clone(key)).or_insert_with(|| Slot {
            variants: Vec::new(),
            meta: Arc::clone(meta),
            tick: 0,
            bytes: 0,
        });
        let (mut freed_bytes, mut freed_entries) = (0usize, 0usize);
        slot.variants.retain(|v| {
            let same = v.vary == entry.vary;
            if same {
                freed_bytes += v.size;
                freed_entries += 1;
            }
            !same
        });
        while slot.variants.len() >= MAX_VARIANTS {
            let oldest = slot.variants.iter().enumerate().min_by_key(|(_, v)| v.stored_at).map_or(0, |(i, _)| i);
            let gone = slot.variants.remove(oldest);
            freed_bytes += gone.size;
            freed_entries += 1;
        }
        slot.variants.push(Arc::clone(entry));
        slot.bytes = slot.bytes - freed_bytes + entry.size;
        self.bytes = self.bytes - freed_bytes + entry.size;
        self.entries = self.entries - freed_entries + 1;
    }

    /// Drop the oldest variant of `key` other than `keep`; `false` if none.
    fn evict_other_variant(&mut self, key: &Arc<str>, keep: &Arc<Entry>) -> bool {
        let Some(slot) = self.map.get_mut(key) else { return false };
        let Some(idx) = slot
            .variants
            .iter()
            .enumerate()
            .filter(|(_, v)| !Arc::ptr_eq(v, keep))
            .min_by_key(|(_, v)| v.stored_at)
            .map(|(i, _)| i)
        else {
            return false;
        };
        let gone = slot.variants.remove(idx);
        slot.bytes -= gone.size;
        self.bytes -= gone.size;
        self.entries -= 1;
        true
    }

    /// Drop expired variants of `key`; remove the slot if none remain.
    fn prune(&mut self, key: &Arc<str>, now: Instant) {
        let Some(slot) = self.map.get_mut(key) else { return };
        let before = slot.variants.len();
        let freed: usize = slot.variants.iter().filter(|v| !v.is_fresh(now)).map(|v| v.size).sum();
        slot.variants.retain(|v| v.is_fresh(now));
        slot.bytes -= freed;
        self.bytes -= freed;
        self.entries -= before - slot.variants.len();
        if slot.variants.is_empty() {
            self.remove_slot(key);
        }
    }
}

/// The sharded LRU.
pub struct Cache {
    shards: Vec<Mutex<Shard>>,
    hasher: RandomState,
    entries: AtomicUsize,
    bytes: AtomicUsize,
    max_bytes: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
}

impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cache").field("shards", &self.shards.len()).field("stats", &self.stats()).finish()
    }
}

/// What an insertion did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inserted {
    /// Whether the entry is now in the cache.
    pub stored: bool,
    /// Entries evicted to make room.
    pub evicted: usize,
}

impl Cache {
    /// An empty cache with `shards` independent LRUs.
    pub fn new(shards: usize) -> Self {
        Self {
            shards: (0..shards.max(1)).map(|_| Mutex::new(Shard::default())).collect(),
            hasher: RandomState::new(),
            entries: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
            max_bytes: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    fn shard(&self, key: &str) -> &Mutex<Shard> {
        let idx = (self.hasher.hash_one(key) % self.shards.len() as u64) as usize;
        &self.shards[idx]
    }

    fn lock(shard: &Mutex<Shard>) -> std::sync::MutexGuard<'_, Shard> {
        shard.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Re-derive the global gauges from one shard's change.
    fn account(&self, before: (usize, usize), after: (usize, usize)) {
        let adjust = |counter: &AtomicUsize, before: usize, after: usize| {
            if after >= before {
                counter.fetch_add(after - before, Ordering::Relaxed);
            } else {
                counter.fetch_sub(before - after, Ordering::Relaxed);
            }
        };
        adjust(&self.entries, before.0, after.0);
        adjust(&self.bytes, before.1, after.1);
    }

    /// A fresh entry for `key` whose `Vary` request headers match `request`.
    /// Counts a hit or a miss.
    pub fn get(&self, key: &Arc<str>, request: &HeaderMap, now: Instant) -> Option<Arc<Entry>> {
        let mut shard = Self::lock(self.shard(key));
        let before = (shard.entries, shard.bytes);
        shard.prune(key, now);
        let found = shard.map.get(key).and_then(|slot| slot.variants.iter().find(|v| v.matches(request)).cloned());
        if found.is_some() {
            shard.touch(key);
        }
        let after = (shard.entries, shard.bytes);
        drop(shard);
        self.account(before, after);
        if found.is_some() {
            self.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
        }
        found
    }

    /// Count a lookup that was skipped but still goes to the backend.
    pub fn count_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Store `entry` under `key`, evicting least-recently-used URLs from the
    /// same shard until the shard fits its share of `max_bytes`.
    pub fn insert(&self, key: &Arc<str>, meta: &Arc<KeyMeta>, entry: Entry, max_bytes: u64) -> Inserted {
        self.max_bytes.store(max_bytes, Ordering::Relaxed);
        let budget = usize::try_from(max_bytes / self.shards.len() as u64).unwrap_or(usize::MAX);
        if entry.size > budget {
            return Inserted { stored: false, evicted: 0 };
        }
        let now = Instant::now();
        let mut shard = Self::lock(self.shard(key));
        let before = (shard.entries, shard.bytes);
        shard.prune(key, now);
        let entry = Arc::new(entry);
        shard.insert_variant(key, meta, &entry);
        shard.touch(key);
        // Evict whole least-recently-used URLs from the cold end until the shard
        // fits. The URL just stored is never one of them…
        let mut evicted = 0;
        while shard.bytes > budget {
            let Some(victim) = shard.lru.values().next().cloned() else { break };
            if *victim == **key {
                break;
            }
            if let Some(slot) = shard.remove_slot(&victim) {
                evicted += slot.variants.len();
            }
        }
        // …but its own older variants may still have to go.
        while shard.bytes > budget && shard.evict_other_variant(key, &entry) {
            evicted += 1;
        }
        let after = (shard.entries, shard.bytes);
        drop(shard);
        self.account(before, after);
        self.evictions.fetch_add(evicted as u64, Ordering::Relaxed);
        Inserted { stored: true, evicted }
    }

    /// Remove every variant of `key` (an unsafe request succeeded).
    pub fn invalidate(&self, key: &str) -> usize {
        let mut shard = Self::lock(self.shard(key));
        let before = (shard.entries, shard.bytes);
        let removed = shard.remove_slot(key).map_or(0, |s| s.variants.len());
        let after = (shard.entries, shard.bytes);
        drop(shard);
        self.account(before, after);
        removed
    }

    /// Remove everything `request` selects.
    pub fn purge_matching(&self, request: &PurgeRequest) -> usize {
        let mut removed = 0;
        for shard in &self.shards {
            let mut shard = Self::lock(shard);
            let before = (shard.entries, shard.bytes);
            let doomed: Vec<Arc<str>> =
                shard.map.iter().filter(|(_, s)| s.meta.matches(request)).map(|(k, _)| Arc::clone(k)).collect();
            for key in doomed {
                removed += shard.remove_slot(&key).map_or(0, |s| s.variants.len());
            }
            let after = (shard.entries, shard.bytes);
            drop(shard);
            self.account(before, after);
        }
        removed
    }

    /// Current occupancy and counters.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            entries: self.entries.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            max_bytes: self.max_bytes.load(Ordering::Relaxed),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
        }
    }
}

impl CacheAdmin for Cache {
    fn purge(&self, request: &PurgeRequest) -> usize {
        self.purge_matching(request)
    }

    fn stats(&self) -> CacheStats {
        Cache::stats(self)
    }
}

// ------------------------------------------------------------------- serving

/// A response built from a cache hit.
#[derive(Debug)]
pub struct HitResponse {
    /// `200` (or the stored status), or `304` for a satisfied conditional.
    pub status: StatusCode,
    /// Response headers, including `Age`.
    pub headers: HeaderMap,
    /// The body (empty for `304`).
    pub body: Bytes,
}

fn weak_etag_eq(a: &[u8], b: &[u8]) -> bool {
    let strip = |e: &[u8]| e.strip_prefix(b"W/").map_or_else(|| e.to_vec(), <[u8]>::to_vec);
    strip(a.trim_ascii()) == strip(b.trim_ascii())
}

fn if_none_match_hits(inm: &HeaderMap, etag: Option<&HeaderValue>) -> Option<bool> {
    let lines: Vec<&HeaderValue> = inm.get_all(IF_NONE_MATCH).iter().collect();
    if lines.is_empty() {
        return None;
    }
    Some(lines.iter().any(|l| {
        l.as_bytes().split(|&b| b == b',').any(|tag| {
            let tag = tag.trim_ascii();
            // `*` matches any current representation, validator or not.
            tag == b"*" || etag.is_some_and(|e| weak_etag_eq(tag, e.as_bytes()))
        })
    }))
}

/// Build the response for a hit, evaluating `If-None-Match` /
/// `If-Modified-Since` against the stored validators.
pub fn serve_hit(entry: &Entry, request: &HeaderMap, now: Instant) -> HitResponse {
    let age = HeaderValue::from(entry.age(now));
    let not_modified = entry.status == StatusCode::OK
        && match if_none_match_hits(request, entry.etag.as_ref()) {
            Some(matched) => matched,
            None => request
                .get(IF_MODIFIED_SINCE)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| httpdate::parse_http_date(v).ok())
                .zip(entry.last_modified)
                .is_some_and(|(since, modified)| modified <= since),
        };
    if not_modified {
        // RFC 9110 §15.4.5: the validators and caching metadata, no content headers.
        let mut headers = HeaderMap::new();
        for name in [ETAG, CACHE_CONTROL, EXPIRES, CONTENT_LOCATION, VARY, LAST_MODIFIED, DATE] {
            for v in entry.headers.get_all(&name) {
                headers.append(name.clone(), v.clone());
            }
        }
        headers.insert(AGE, age);
        return HitResponse { status: StatusCode::NOT_MODIFIED, headers, body: Bytes::new() };
    }
    let mut headers = entry.headers.clone();
    headers.insert(AGE, age);
    HitResponse { status: entry.status, headers, body: entry.body.clone() }
}

// ---------------------------------------------------------------------- fill

/// Everything needed to turn a miss into an entry once its body is complete.
pub struct FillTicket {
    /// The shared cache.
    pub cache: Arc<Cache>,
    /// Metrics sink.
    pub metrics: Arc<Metrics>,
    /// The map key.
    pub key: Arc<str>,
    /// The URL's identity (for purging).
    pub meta: Arc<KeyMeta>,
    /// The route's cache settings.
    pub route: RouteCacheConfig,
    /// The client's request headers (the values `Vary` is compared on).
    pub request_headers: HeaderMap,
    /// `[cache].max_bytes`.
    pub max_bytes: u64,
    /// `[cache].max_entry_bytes`.
    pub max_entry_bytes: u64,
}

impl std::fmt::Debug for FillTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FillTicket").field("key", &self.key).finish_non_exhaustive()
    }
}

/// The outcome of offering a response to the cache.
#[derive(Debug, PartialEq, Eq)]
pub enum Offer {
    /// The response will be stored when its body completes (or already was).
    Filling,
    /// Not storable, for this reason.
    Pass(&'static str),
}

struct Pending {
    cache: Arc<Cache>,
    metrics: Arc<Metrics>,
    key: Arc<str>,
    meta: Arc<KeyMeta>,
    status: StatusCode,
    headers: HeaderMap,
    storable: Storable,
    vary: Vec<(HeaderName, Option<Bytes>)>,
    max_bytes: u64,
}

impl Pending {
    fn store(self, body: Bytes) {
        let now = Instant::now();
        let mut headers = self.headers;
        headers.remove(TRANSFER_ENCODING);
        headers.insert(CONTENT_LENGTH, HeaderValue::from(body.len()));
        let size = estimate_size(&self.key, &headers, &body);
        let entry = Entry {
            status: self.status,
            etag: headers.get(ETAG).cloned(),
            last_modified: http_date(&headers, &LAST_MODIFIED),
            headers,
            body,
            vary: self.vary,
            stored_at: now,
            fresh_until: now + self.storable.lifetime,
            base_age: self.storable.upstream_age,
            size,
        };
        let done = self.cache.insert(&self.key, &self.meta, entry, self.max_bytes);
        if done.stored {
            self.metrics.cache_stored();
        }
        if done.evicted > 0 {
            self.metrics.cache_evicted(done.evicted as u64);
        }
        let s = self.cache.stats();
        self.metrics.cache_size(s.entries, s.bytes);
    }
}

impl FillTicket {
    /// Offer a response. On [`Offer::Filling`] the returned body must be sent to
    /// the client in place of `body`: it forwards every frame untouched and
    /// stores the response when (and only if) the body completes cleanly.
    pub fn offer(self, status: StatusCode, headers: &HeaderMap, body: ProxyBody) -> (Offer, ProxyBody) {
        let storable = match evaluate_response(status, headers, &self.route, SystemTime::now()) {
            Ok(s) => s,
            Err(why) => return (Offer::Pass(why), body),
        };
        let declared =
            headers.get(CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<u64>().ok());
        if declared.is_some_and(|n| n > self.max_entry_bytes) {
            return (Offer::Pass("too-large"), body);
        }
        let mut stored_headers = headers.clone();
        for name in [AGE, X_CACHE, SET_COOKIE] {
            stored_headers.remove(name);
        }
        let pending = Pending {
            vary: vary_snapshot(&storable.vary, &self.request_headers),
            cache: self.cache,
            metrics: self.metrics,
            key: self.key,
            meta: self.meta,
            status,
            headers: stored_headers,
            storable,
            max_bytes: self.max_bytes,
        };
        // A body that is already complete (204, `Content-Length: 0`) is never
        // polled by the server, so it is stored right here.
        if body.is_end_stream() {
            pending.store(Bytes::new());
            return (Offer::Filling, body);
        }
        let limit = usize::try_from(self.max_entry_bytes).unwrap_or(usize::MAX);
        (Offer::Filling, ProxyBody::boxed(CacheFill::new(body, limit, declared, pending)))
    }
}

pin_project! {
    /// Forwards a response body while collecting a bounded copy for the cache.
    pub struct CacheFill {
        #[pin] inner: ProxyBody,
        buf: BytesMut,
        limit: usize,
        declared: Option<u64>,
        // Set once the copy can no longer be a faithful, storable one.
        abandoned: bool,
        pending: Option<Pending>,
    }
}

impl CacheFill {
    fn new(inner: ProxyBody, limit: usize, declared: Option<u64>, pending: Pending) -> Self {
        Self { inner, buf: BytesMut::new(), limit, declared, abandoned: false, pending: Some(pending) }
    }
}

impl Body for CacheFill {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let mut this = self.project();
        let polled = this.inner.as_mut().poll_frame(cx);
        // Is the representation complete after this poll? Servers do not always
        // ask for the final `None`: HTTP/1 stops after `Content-Length` bytes and
        // HTTP/2 as soon as `is_end_stream()` is true, so completion is decided
        // by the length / end-of-stream signals, not only by seeing `None`.
        let finished = match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    if !*this.abandoned {
                        if this.buf.len() + data.len() > *this.limit {
                            *this.abandoned = true;
                            *this.buf = BytesMut::new(); // give the memory back immediately
                        } else {
                            this.buf.extend_from_slice(data);
                        }
                    }
                } else {
                    *this.abandoned = true; // trailers: not a representation we store
                }
                let by_length = this.declared.is_some_and(|d| d == this.buf.len() as u64);
                by_length || this.inner.is_end_stream()
            }
            Poll::Ready(Some(Err(_))) => {
                *this.abandoned = true;
                *this.pending = None;
                false
            }
            Poll::Ready(None) => true,
            Poll::Pending => false,
        };
        if finished {
            if let Some(pending) = this.pending.take() {
                let complete = !*this.abandoned && this.declared.is_none_or(|d| d == this.buf.len() as u64);
                if complete {
                    pending.store(std::mem::take(this.buf).freeze());
                }
            }
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

// ----------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    fn hv(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).unwrap()
    }

    fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(HeaderName::from_bytes(k.as_bytes()).unwrap(), hv(v));
        }
        h
    }

    fn route() -> RouteCacheConfig {
        RouteCacheConfig::default()
    }

    fn eval(pairs: &[(&str, &str)]) -> Result<Storable, &'static str> {
        evaluate_response(StatusCode::OK, &hm(pairs), &route(), SystemTime::now())
    }

    // ---- request classification ----

    #[test]
    fn requests_that_must_never_touch_the_cache() {
        let get = Method::GET;
        assert_eq!(classify_request(&get, &hm(&[]), false, false), RequestMode::Normal);
        assert_eq!(classify_request(&Method::HEAD, &hm(&[]), false, false), RequestMode::Normal);
        for (m, h, body, why) in [
            (Method::POST, vec![], false, "method"),
            (Method::PUT, vec![], false, "method"),
            (Method::GET, vec![], true, "body"),
            (Method::GET, vec![("authorization", "Bearer x")], false, "authorization"),
            (Method::GET, vec![("cookie", "sid=abc")], false, "cookie"),
            (Method::GET, vec![("range", "bytes=0-9")], false, "range"),
            (Method::GET, vec![("if-range", "\"x\"")], false, "range"),
            (Method::GET, vec![("upgrade", "websocket")], false, "upgrade"),
            (Method::GET, vec![("cache-control", "no-store")], false, "no-store"),
            (Method::GET, vec![("cache-control", "max-age=60, No-Store")], false, "no-store"),
        ] {
            assert_eq!(classify_request(&m, &hm(&h), body, false), RequestMode::Bypass(why), "{why}");
        }
    }

    #[test]
    fn cookies_bypass_the_cache_unless_the_route_opts_in() {
        let with_cookie = hm(&[("cookie", "sid=abc")]);
        assert_eq!(classify_request(&Method::GET, &with_cookie, false, false), RequestMode::Bypass("cookie"));
        assert_eq!(classify_request(&Method::GET, &with_cookie, false, true), RequestMode::Normal);
        // The opt-in does not weaken any other rule.
        let both = hm(&[("cookie", "a=b"), ("authorization", "x")]);
        assert_eq!(classify_request(&Method::GET, &both, false, true), RequestMode::Bypass("authorization"));
    }

    #[test]
    fn http_and_https_never_share_an_entry() {
        let route: Arc<str> = Arc::from("r");
        let (plain, secure) = (KeyMeta::new(&route, "h", false, "/p"), KeyMeta::new(&route, "H", true, "/p"));
        assert_ne!(plain.key(), secure.key());
        assert_eq!(secure.key(), KeyMeta::new(&route, "h", true, "/p").key(), "host case does not matter");
    }

    #[test]
    fn requests_that_demand_freshness_skip_the_lookup_but_may_refresh() {
        for h in [
            vec![("cache-control", "no-cache")],
            vec![("cache-control", "max-age=0")],
            vec![("pragma", "no-cache")],
            vec![("cache-control", "max-age=0, must-revalidate")],
        ] {
            assert_eq!(classify_request(&Method::GET, &hm(&h), false, false), RequestMode::Refresh, "{h:?}");
        }
        assert_eq!(
            classify_request(&Method::GET, &hm(&[("cache-control", "max-age=60")]), false, false),
            RequestMode::Normal
        );
    }

    // ---- response evaluation ----

    #[test]
    fn freshness_comes_from_s_maxage_then_max_age_then_expires_then_the_route_default() {
        assert_eq!(eval(&[("cache-control", "max-age=60")]).unwrap().lifetime, Duration::from_secs(60));
        assert_eq!(eval(&[("cache-control", "max-age=60, s-maxage=300")]).unwrap().lifetime, Duration::from_secs(300));
        assert_eq!(eval(&[("cache-control", "public, MAX-AGE=\"90\"")]).unwrap().lifetime, Duration::from_secs(90));
        // Expires is relative to Date, not to our clock.
        let r =
            eval(&[("date", "Wed, 21 Oct 2015 07:28:00 GMT"), ("expires", "Wed, 21 Oct 2015 07:30:00 GMT")]).unwrap();
        assert_eq!(r.lifetime, Duration::from_secs(120));
        // max-age beats Expires.
        let r = eval(&[("cache-control", "max-age=10"), ("expires", "Wed, 21 Oct 2099 07:28:00 GMT")]).unwrap();
        assert_eq!(r.lifetime, Duration::from_secs(10));
        // No explicit freshness: Velox does not guess.
        assert_eq!(eval(&[("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")]).unwrap_err(), "no-freshness");
        let with_default = RouteCacheConfig { default_ttl: Some(Duration::from_secs(45)), ..route() };
        let r = evaluate_response(StatusCode::OK, &hm(&[]), &with_default, SystemTime::now()).unwrap();
        assert_eq!(r.lifetime, Duration::from_secs(45));
        // An explicit lifetime still wins over the default; max_ttl clamps both.
        let clamped = RouteCacheConfig { max_ttl: Some(Duration::from_secs(5)), ..with_default };
        let r =
            evaluate_response(StatusCode::OK, &hm(&[("cache-control", "max-age=600")]), &clamped, SystemTime::now())
                .unwrap();
        assert_eq!(r.lifetime, Duration::from_secs(5));
    }

    #[test]
    fn invalid_or_zero_lifetimes_are_never_stored() {
        for h in [
            vec![("cache-control", "max-age=0")],
            vec![("cache-control", "max-age=banana")], // invalid ⇒ stale
            vec![("cache-control", "max-age=-5")],
            vec![("cache-control", "max-age")],
            vec![("expires", "not a date")],
            vec![("expires", "0")],
            vec![("date", "Wed, 21 Oct 2015 07:28:00 GMT"), ("expires", "Wed, 21 Oct 2015 07:20:00 GMT")], // in the past
        ] {
            assert!(eval(&h).is_err(), "{h:?}");
        }
        // The upstream's Age is subtracted.
        assert_eq!(eval(&[("cache-control", "max-age=100"), ("age", "30")]).unwrap().lifetime, Duration::from_secs(70));
        assert_eq!(eval(&[("cache-control", "max-age=100"), ("age", "30")]).unwrap().upstream_age, 30);
        assert_eq!(eval(&[("cache-control", "max-age=100"), ("age", "100")]).unwrap_err(), "expired");
    }

    #[test]
    fn responses_the_cache_must_not_keep() {
        for (h, why) in [
            (vec![("cache-control", "no-store, max-age=60")], "no-store"),
            (vec![("cache-control", "private, max-age=60")], "private"),
            (vec![("cache-control", "private=\"set-cookie\", max-age=60")], "private"),
            (vec![("cache-control", "no-cache, max-age=60")], "no-cache"),
            (vec![("cache-control", "max-age=60"), ("set-cookie", "a=b")], "set-cookie"),
            (vec![("cache-control", "max-age=60"), ("vary", "*")], "vary-star"),
            (vec![("cache-control", "max-age=60"), ("vary", "accept, *")], "vary-star"),
            (vec![("cache-control", "max-age=60"), ("vary", "bad header")], "vary"),
            (vec![("pragma", "no-cache"), ("expires", "Wed, 21 Oct 2099 07:28:00 GMT")], "no-cache"),
            (vec![("cache-control", "max-age=60"), ("content-range", "bytes 0-1/9")], "range"),
        ] {
            assert_eq!(eval(&h).unwrap_err(), why, "{h:?}");
        }
        // Status handling.
        for code in [201u16, 202, 206, 302, 303, 304, 307, 400, 401, 403, 429, 500, 502, 503] {
            let r = evaluate_response(
                StatusCode::from_u16(code).unwrap(),
                &hm(&[("cache-control", "max-age=60")]),
                &route(),
                SystemTime::now(),
            );
            assert_eq!(r.unwrap_err(), "status", "{code}");
        }
        for code in [200u16, 203, 204, 300, 301, 308, 404, 405, 410, 414, 501] {
            let r = evaluate_response(
                StatusCode::from_u16(code).unwrap(),
                &hm(&[("cache-control", "max-age=60")]),
                &route(),
                SystemTime::now(),
            );
            assert!(r.is_ok(), "{code}");
        }
    }

    #[test]
    fn vary_names_are_normalised() {
        let s =
            eval(&[("cache-control", "max-age=60"), ("vary", "Accept-Language, accept"), ("vary", "ACCEPT")]).unwrap();
        assert_eq!(s.vary.iter().map(HeaderName::as_str).collect::<Vec<_>>(), ["accept", "accept-language"]);
        assert!(eval(&[("cache-control", "max-age=60")]).unwrap().vary.is_empty());
    }

    // ---- the store ----

    fn meta(route: &str, host: &str, target: &str) -> (Arc<str>, Arc<KeyMeta>) {
        let m = Arc::new(KeyMeta::new(&Arc::from(route), host, true, target));
        (m.key().unwrap(), m)
    }

    fn entry(body: &str, lifetime: Duration, vary: Vec<(HeaderName, Option<Bytes>)>) -> Entry {
        let now = Instant::now();
        let body = Bytes::from(body.to_owned());
        let headers = hm(&[("content-type", "text/plain"), ("etag", "\"v1\"")]);
        Entry {
            status: StatusCode::OK,
            size: estimate_size("k", &headers, &body),
            etag: headers.get(ETAG).cloned(),
            last_modified: None,
            headers,
            body,
            vary,
            stored_at: now,
            fresh_until: now + lifetime,
            base_age: 0,
        }
    }

    const BIG: u64 = 1 << 30;

    #[test]
    fn hit_miss_expiry_and_accounting() {
        let c = Cache::new(4);
        let (key, m) = meta("r", "example.com", "/a?x=1");
        let req = hm(&[]);
        assert!(c.get(&key, &req, Instant::now()).is_none());
        let e = entry("hello", Duration::from_millis(80), vec![]);
        let size = e.size;
        assert_eq!(c.insert(&key, &m, e, BIG), Inserted { stored: true, evicted: 0 });
        let s = c.stats();
        assert_eq!((s.entries, s.bytes, s.hits, s.misses), (1, size, 0, 1));
        let hit = c.get(&key, &req, Instant::now()).unwrap();
        assert_eq!(hit.body, "hello");
        assert_eq!(c.stats().hits, 1);
        // Expiry removes the entry and its bytes.
        std::thread::sleep(Duration::from_millis(120));
        assert!(c.get(&key, &req, Instant::now()).is_none());
        let s = c.stats();
        assert_eq!((s.entries, s.bytes), (0, 0), "expired entries are reclaimed, not just hidden");
    }

    #[test]
    fn lru_evicts_the_coldest_url_in_a_shard_and_keeps_the_hot_one() {
        let c = Cache::new(1);
        let body = "x".repeat(1000);
        let probe = entry(&body, Duration::from_secs(60), vec![]);
        let budget = (probe.size * 3 + probe.size / 2) as u64; // room for three
        let key = |i: usize| meta("r", "h", &format!("/{i}"));
        for i in 0..3 {
            let (k, m) = key(i);
            c.insert(&k, &m, entry(&body, Duration::from_secs(60), vec![]), budget);
        }
        // Touch /0 so /1 becomes the coldest.
        let (k0, _m0) = key(0);
        assert!(c.get(&k0, &hm(&[]), Instant::now()).is_some());
        let (k3, m3) = key(3);
        let done = c.insert(&k3, &m3, entry(&body, Duration::from_secs(60), vec![]), budget);
        assert_eq!(done, Inserted { stored: true, evicted: 1 });
        let alive = |i: usize| c.get(&key(i).0, &hm(&[]), Instant::now()).is_some();
        assert!(alive(0) && alive(2) && alive(3), "recently used entries survive");
        assert!(!alive(1), "the least recently used one was evicted");
        let s = c.stats();
        assert!(s.bytes as u64 <= budget, "{} <= {budget}", s.bytes);
        assert_eq!((s.entries, s.evictions), (3, 1));
    }

    #[test]
    fn an_entry_larger_than_a_shard_is_refused_not_thrashed() {
        let c = Cache::new(4);
        let (k, m) = meta("r", "h", "/big");
        let e = entry(&"x".repeat(10_000), Duration::from_secs(60), vec![]);
        let done = c.insert(&k, &m, e, 4 * 5_000); // 5 000 per shard
        assert_eq!(done, Inserted { stored: false, evicted: 0 });
        assert_eq!(c.stats().entries, 0);
    }

    #[test]
    fn variants_are_keyed_on_the_stored_vary_values() {
        let c = Cache::new(2);
        let (k, m) = meta("r", "h", "/v");
        let lang = HeaderName::from_static("accept-language");
        let variant = |v: &str, body: &str| {
            let e = entry(body, Duration::from_secs(60), vec![(lang.clone(), Some(Bytes::from(v.to_owned())))]);
            c.insert(&k, &m, e, BIG);
        };
        variant("en", "english");
        variant("fr", "français");
        let get = |h: &[(&str, &str)]| c.get(&k, &hm(h), Instant::now()).map(|e| e.body.clone());
        assert_eq!(get(&[("accept-language", "en")]).unwrap(), "english");
        assert_eq!(get(&[("accept-language", "fr")]).unwrap(), "français");
        assert!(get(&[("accept-language", "de")]).is_none());
        assert!(get(&[]).is_none(), "a missing header is its own variant");
        assert_eq!(c.stats().entries, 2);
        // Re-storing the same variant replaces it instead of piling up.
        variant("en", "english v2");
        assert_eq!(c.stats().entries, 2);
        assert_eq!(get(&[("accept-language", "en")]).unwrap(), "english v2");
        // Variants are bounded.
        for i in 0..20 {
            variant(&format!("x{i}"), "v");
        }
        assert!(c.stats().entries <= MAX_VARIANTS);
    }

    #[test]
    fn invalidate_and_purge_select_precisely() {
        let c = Cache::new(4);
        let put = |route: &str, host: &str, target: &str| {
            let (k, m) = meta(route, host, target);
            c.insert(&k, &m, entry("b", Duration::from_secs(60), vec![]), BIG);
            k
        };
        let a = put("api", "example.com", "/v1/users");
        put("api", "example.com", "/v1/users?page=2");
        put("api", "other.com", "/v1/users");
        put("web", "example.com", "/index.html");
        put("web", "example.com", "/static/app.js");
        assert_eq!(c.stats().entries, 5);

        assert_eq!(c.invalidate(&a), 1);
        assert_eq!(c.invalidate(&a), 0);
        let purge = |p: PurgeRequest| c.purge_matching(&p);
        assert_eq!(purge(PurgeRequest { path_prefix: Some("/static/".into()), ..Default::default() }), 1);
        assert_eq!(purge(PurgeRequest { host: Some("OTHER.com".into()), ..Default::default() }), 1);
        assert_eq!(
            purge(PurgeRequest {
                route: Some("api".into()),
                path: Some("/v1/users?page=2".into()),
                ..Default::default()
            }),
            1
        );
        assert_eq!(purge(PurgeRequest { route: Some("nope".into()), ..Default::default() }), 0);
        assert_eq!(c.stats().entries, 1);
        assert_eq!(purge(PurgeRequest { all: true, ..Default::default() }), 1);
        let s = c.stats();
        assert_eq!((s.entries, s.bytes), (0, 0), "byte accounting returns to zero");
        assert!(!PurgeRequest::default().is_selective());
    }

    #[test]
    fn concurrent_use_keeps_the_accounting_exact() {
        let c = Arc::new(Cache::new(8));
        let handles: Vec<_> = (0..8)
            .map(|t| {
                let c = Arc::clone(&c);
                std::thread::spawn(move || {
                    for i in 0..400usize {
                        let (k, m) = meta("r", "h", &format!("/{}", (i * 7 + t) % 50));
                        match i % 4 {
                            0 | 1 => {
                                c.insert(&k, &m, entry("body body body", Duration::from_secs(60), vec![]), 20_000);
                            }
                            2 => {
                                let _ = c.get(&k, &hm(&[]), Instant::now());
                            }
                            _ => {
                                c.invalidate(&k);
                            }
                        }
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let s = c.stats();
        assert!(s.bytes <= 20_000 + 8 * 400, "bounded: {}", s.bytes);
        // Whatever is left must sum to the gauges exactly.
        let (mut entries, mut bytes) = (0, 0);
        for shard in &c.shards {
            let sh = Cache::lock(shard);
            entries += sh.map.values().map(|s| s.variants.len()).sum::<usize>();
            bytes += sh.map.values().map(|s| s.bytes).sum::<usize>();
            assert_eq!(sh.bytes, sh.map.values().map(|s| s.bytes).sum::<usize>());
            assert_eq!(sh.lru.len(), sh.map.len(), "LRU index matches the map");
        }
        assert_eq!((s.entries, s.bytes), (entries, bytes));
        c.purge_matching(&PurgeRequest { all: true, ..Default::default() });
        assert_eq!((c.stats().entries, c.stats().bytes), (0, 0));
    }

    // ---- serving ----

    fn stored(headers: &[(&str, &str)]) -> Entry {
        let mut e = entry("payload", Duration::from_secs(60), vec![]);
        for (k, v) in headers {
            e.headers.insert(HeaderName::from_bytes(k.as_bytes()).unwrap(), hv(v));
        }
        e.etag = e.headers.get(ETAG).cloned();
        e.last_modified = http_date(&e.headers, &LAST_MODIFIED);
        e
    }

    #[test]
    fn hits_carry_age_and_conditionals_become_304() {
        let mut e = stored(&[("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT"), ("cache-control", "max-age=60")]);
        e.base_age = 10;
        let now = e.stored_at + Duration::from_secs(5);
        let full = serve_hit(&e, &hm(&[]), now);
        assert_eq!(
            (full.status, full.body.as_ref(), full.headers[AGE].to_str().unwrap()),
            (StatusCode::OK, &b"payload"[..], "15")
        );
        // If-None-Match: exact, weak, list, star.
        for inm in ["\"v1\"", "W/\"v1\"", "\"other\", \"v1\"", "*", " \"v1\" "] {
            let r = serve_hit(&e, &hm(&[("if-none-match", inm)]), now);
            assert_eq!(r.status, StatusCode::NOT_MODIFIED, "{inm}");
            assert!(r.body.is_empty());
            assert_eq!(r.headers[ETAG], "\"v1\"");
            assert_eq!(r.headers[CACHE_CONTROL], "max-age=60");
            assert!(!r.headers.contains_key(CONTENT_LENGTH) && !r.headers.contains_key("content-type"));
            assert_eq!(r.headers[AGE], "15");
        }
        assert_eq!(serve_hit(&e, &hm(&[("if-none-match", "\"nope\"")]), now).status, StatusCode::OK);
        // If-None-Match wins over If-Modified-Since when both are present.
        let both = hm(&[("if-none-match", "\"nope\""), ("if-modified-since", "Wed, 21 Oct 2099 07:28:00 GMT")]);
        assert_eq!(serve_hit(&e, &both, now).status, StatusCode::OK);
        // If-Modified-Since alone.
        let ims = |d: &str| serve_hit(&e, &hm(&[("if-modified-since", d)]), now).status;
        assert_eq!(ims("Wed, 21 Oct 2015 07:28:00 GMT"), StatusCode::NOT_MODIFIED);
        assert_eq!(ims("Fri, 21 Oct 2016 07:28:00 GMT"), StatusCode::NOT_MODIFIED);
        assert_eq!(ims("Tue, 21 Oct 2014 07:28:00 GMT"), StatusCode::OK);
        assert_eq!(ims("garbage"), StatusCode::OK);
        // No validators stored: conditionals cannot match.
        let mut bare = entry("x", Duration::from_secs(60), vec![]);
        bare.headers.remove(ETAG);
        bare.etag = None;
        assert_eq!(
            serve_hit(&bare, &hm(&[("if-none-match", "*")]), now).status,
            StatusCode::NOT_MODIFIED,
            "`*` matches any current representation"
        );
        assert_eq!(serve_hit(&bare, &hm(&[("if-none-match", "\"x\"")]), now).status, StatusCode::OK);
    }

    // ---- the fill ----

    fn ticket(
        cache: &Arc<Cache>,
        route: RouteCacheConfig,
        request: HeaderMap,
        max_entry: u64,
    ) -> (FillTicket, Arc<str>) {
        let (key, m) = meta("r", "h", "/fill");
        (
            FillTicket {
                cache: Arc::clone(cache),
                metrics: Arc::new(Metrics::new().unwrap()),
                key: Arc::clone(&key),
                meta: m,
                route,
                request_headers: request,
                max_bytes: BIG,
                max_entry_bytes: max_entry,
            },
            key,
        )
    }

    fn body_of(frames: Vec<Result<Frame<Bytes>, BoxError>>) -> ProxyBody {
        ProxyBody::boxed(http_body_util::StreamBody::new(futures_util::stream::iter(frames)))
    }

    fn data(s: &str) -> Result<Frame<Bytes>, BoxError> {
        Ok(Frame::data(Bytes::from(s.to_owned())))
    }

    async fn drain(mut b: ProxyBody) -> usize {
        let mut n = 0;
        while let Some(f) = b.frame().await {
            if let Ok(d) = f.map(Frame::into_data) {
                n += d.map_or(0, |d| d.len());
            }
        }
        n
    }

    #[tokio::test]
    async fn a_miss_streams_unchanged_and_is_stored_when_the_body_completes() {
        let cache = Arc::new(Cache::new(2));
        let (t, key) = ticket(&cache, route(), hm(&[("accept-language", "en")]), 1024);
        let resp = hm(&[
            ("cache-control", "max-age=60"),
            ("vary", "accept-language"),
            ("content-type", "text/plain"),
            ("age", "0"),
            ("transfer-encoding", "chunked"),
        ]);
        let (offer, body) = t.offer(StatusCode::OK, &resp, body_of(vec![data("hel"), data("lo")]));
        assert_eq!(offer, Offer::Filling);
        assert!(
            cache.get(&key, &hm(&[("accept-language", "en")]), Instant::now()).is_none(),
            "nothing is stored before the body ends"
        );
        assert_eq!(drain(body).await, 5, "the client sees the full body");
        let e = cache.get(&key, &hm(&[("accept-language", "en")]), Instant::now()).expect("stored");
        assert_eq!(e.body, "hello");
        assert_eq!(e.headers[CONTENT_LENGTH], "5");
        assert!(!e.headers.contains_key(TRANSFER_ENCODING) && !e.headers.contains_key(AGE));
        assert!(
            cache.get(&key, &hm(&[("accept-language", "fr")]), Instant::now()).is_none(),
            "keyed on the Vary value seen at fill time"
        );
    }

    #[tokio::test]
    async fn incomplete_oversized_or_mismatched_bodies_are_never_stored() {
        let resp = |extra: &[(&str, &str)]| {
            let mut h = vec![("cache-control", "max-age=60")];
            h.extend_from_slice(extra);
            hm(&h)
        };
        // Too large mid-stream: the client still gets everything.
        let cache = Arc::new(Cache::new(1));
        let (t, key) = ticket(&cache, route(), hm(&[]), 8);
        let (_, body) = t.offer(StatusCode::OK, &resp(&[]), body_of(vec![data("12345"), data("67890")]));
        assert_eq!(drain(body).await, 10);
        assert!(cache.get(&key, &hm(&[]), Instant::now()).is_none());
        // Declared too large: not even attempted.
        let (t, _) = ticket(&cache, route(), hm(&[]), 8);
        let (offer, _) = t.offer(StatusCode::OK, &resp(&[("content-length", "999")]), body_of(vec![data("x")]));
        assert_eq!(offer, Offer::Pass("too-large"));
        // Declared length does not match what arrived.
        let (t, key) = ticket(&cache, route(), hm(&[]), 1024);
        let (_, body) = t.offer(StatusCode::OK, &resp(&[("content-length", "10")]), body_of(vec![data("short")]));
        drain(body).await;
        assert!(cache.get(&key, &hm(&[]), Instant::now()).is_none(), "truncated body");
        // Upstream error mid-body.
        let (t, key) = ticket(&cache, route(), hm(&[]), 1024);
        let (_, body) = t.offer(StatusCode::OK, &resp(&[]), body_of(vec![data("partial"), Err("boom".into())]));
        drain(body).await;
        assert!(cache.get(&key, &hm(&[]), Instant::now()).is_none());
        // Trailers.
        let (t, key) = ticket(&cache, route(), hm(&[]), 1024);
        let (_, body) =
            t.offer(StatusCode::OK, &resp(&[]), body_of(vec![data("x"), Ok(Frame::trailers(hm(&[("x-t", "1")])))]));
        drain(body).await;
        assert!(cache.get(&key, &hm(&[]), Instant::now()).is_none());
        // Dropped before the end (client went away).
        let (t, key) = ticket(&cache, route(), hm(&[]), 1024);
        let (_, mut body) = t.offer(StatusCode::OK, &resp(&[]), body_of(vec![data("abc"), data("def")]));
        let _ = body.frame().await;
        drop(body);
        assert!(cache.get(&key, &hm(&[]), Instant::now()).is_none());
        assert_eq!(cache.stats().entries, 0);
    }

    #[tokio::test]
    async fn already_complete_bodies_are_stored_immediately_and_unstorable_ones_are_passed() {
        let cache = Arc::new(Cache::new(1));
        let (t, key) = ticket(&cache, route(), hm(&[]), 1024);
        let (offer, _) = t.offer(StatusCode::NO_CONTENT, &hm(&[("cache-control", "max-age=60")]), ProxyBody::Empty);
        assert_eq!(offer, Offer::Filling);
        let e = cache.get(&key, &hm(&[]), Instant::now()).expect("a 204 is stored without anyone polling its body");
        assert_eq!((e.status, e.body_len()), (StatusCode::NO_CONTENT, 0));
        let (t, _) = ticket(&cache, route(), hm(&[]), 1024);
        let (offer, body) =
            t.offer(StatusCode::OK, &hm(&[("cache-control", "private")]), body_of(vec![data("secret")]));
        assert_eq!(offer, Offer::Pass("private"));
        assert_eq!(drain(body).await, 6, "a passed response is untouched");
    }

    /// A body like hyper's own: it knows its length, and the consumer (an HTTP/1
    /// server with `Content-Length`, an HTTP/2 stream) stops after the last data
    /// frame because `is_end_stream()` says so — it never polls for the final `None`.
    struct NoTail {
        frames: Vec<Bytes>,
        total: u64,
        sent: u64,
    }

    impl Body for NoTail {
        type Data = Bytes;
        type Error = BoxError;
        fn poll_frame(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
            if self.frames.is_empty() {
                panic!("polled past the end: a real server would not have");
            }
            let f = self.frames.remove(0);
            self.sent += f.len() as u64;
            Poll::Ready(Some(Ok(Frame::data(f))))
        }
        fn is_end_stream(&self) -> bool {
            self.sent == self.total
        }
        fn size_hint(&self) -> SizeHint {
            SizeHint::with_exact(self.total)
        }
    }

    #[tokio::test]
    async fn a_consumer_that_never_polls_for_the_final_none_still_completes_the_fill() {
        for declared in [Some("8"), None] {
            let cache = Arc::new(Cache::new(1));
            let (t, key) = ticket(&cache, route(), hm(&[]), 1024);
            let mut resp = vec![("cache-control", "max-age=60")];
            resp.extend(declared.map(|d| ("content-length", d)));
            let inner =
                ProxyBody::boxed(NoTail { frames: vec![Bytes::from("abcd"), Bytes::from("efgh")], total: 8, sent: 0 });
            let (offer, mut body) = t.offer(StatusCode::OK, &hm(&resp), inner);
            assert_eq!(offer, Offer::Filling);
            // Exactly what hyper does: take frames until the body says it is done.
            while !body.is_end_stream() {
                body.frame().await.unwrap().unwrap();
            }
            let e = cache.get(&key, &hm(&[]), Instant::now()).expect("stored without a trailing poll");
            assert_eq!(e.body, "abcdefgh", "declared = {declared:?}");
        }
    }

    /// The invariants the `cache_policy` fuzz target asserts, replayed over
    /// randomly assembled header lines so `cargo test` catches a violation.
    #[test]
    fn policy_invariants_hold_under_random_headers() {
        const FRAGMENTS: [&str; 24] = [
            "no-store",
            "private",
            "private=\"set-cookie\"",
            "no-cache",
            "public",
            "max-age=60",
            "max-age=0",
            "max-age=-1",
            "max-age=99999999999999999999999",
            "s-maxage=30",
            "s-maxage=abc",
            "must-revalidate",
            "*",
            "accept-encoding",
            "accept, origin",
            "bad header",
            "Wed, 21 Oct 2015 07:28:00 GMT",
            "Wed, 21 Oct 2099 07:28:00 GMT",
            "garbage",
            "0",
            "30",
            "",
            ",",
            "=",
        ];
        const NAMES: [&str; 6] = ["cache-control", "vary", "expires", "age", "pragma", "date"];
        let mut x: u64 = 0x1234_5678_9ABC_DEF1;
        let mut next = move |n: usize| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x % n as u64) as usize
        };
        let cap = Duration::from_secs(3600);
        let route =
            RouteCacheConfig { default_ttl: Some(Duration::from_secs(30)), max_ttl: Some(cap), ..Default::default() };
        let (mut accepted, mut rejected) = (0, 0);
        for _ in 0..60_000 {
            let mut h = HeaderMap::new();
            for _ in 0..next(6) {
                let mut value = FRAGMENTS[next(FRAGMENTS.len())].to_owned();
                if next(2) == 0 {
                    value = format!("{value}, {}", FRAGMENTS[next(FRAGMENTS.len())]);
                }
                if let Ok(v) = HeaderValue::from_str(&value) {
                    h.append(HeaderName::from_static(NAMES[next(NAMES.len())]), v);
                }
            }
            for status in [StatusCode::OK, StatusCode::NOT_FOUND, StatusCode::PARTIAL_CONTENT, StatusCode::BAD_GATEWAY]
            {
                match evaluate_response(status, &h, &route, SystemTime::now()) {
                    Ok(s) => {
                        accepted += 1;
                        let cc = CacheControl::parse(&h);
                        assert!(!cc.no_store && !cc.private && !cc.no_cache, "{h:?}");
                        assert!(!s.lifetime.is_zero() && s.lifetime <= cap, "{:?} for {h:?}", s.lifetime);
                        assert!(s.vary.len() <= 8 && !h.contains_key(SET_COOKIE));
                        assert!(CACHEABLE_STATUS.contains(&status.as_u16()));
                    }
                    Err(_) => rejected += 1,
                }
            }
        }
        assert!(
            accepted > 1_000 && rejected > 1_000,
            "the generator should exercise both outcomes ({accepted}/{rejected})"
        );
    }
}
