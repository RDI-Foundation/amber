use std::sync::Arc;

use amber_manifest::{Manifest, ManifestDigest};
use dashmap::DashMap;
use url::Url;

/// A cache scope partitions URL-based cache entries.
///
/// This is critical once resolution can vary by environment (e.g. the same URL scheme
/// can resolve differently under different environments).
///
/// Notes:
/// - Digest-based cache entries are *global* and shared across scopes.
/// - URL-based cache entries are *scoped*.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct CacheScope(u64);

impl CacheScope {
    /// The default/global scope (used by legacy callers).
    pub const DEFAULT: CacheScope = CacheScope(0);

    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub const fn id(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cacheability {
    /// For sources where references are mutable.
    ByDigestOnly,
    /// The reference is immutable and can be used as a cache key.
    ByUrlAndDigest,
}

#[derive(Clone, Debug, Default)]
pub struct Cache {
    inner: Arc<CacheInner>,
}

#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub resolved_url: Url,
    pub manifest: Arc<Manifest>,
}

#[derive(Debug, Default)]
struct CacheInner {
    by_url: DashMap<(CacheScope, Url), CacheEntry>,
    by_digest: DashMap<ManifestDigest, CacheEntry>,
}

impl Cache {
    /// Store a manifest (owned) under `url` and its sha256 digest.
    /// Uses `url` as the resolved URL.
    pub fn put(&self, url: Url, manifest: Manifest) {
        self.put_arc_scoped(CacheScope::DEFAULT, url.clone(), url, Arc::new(manifest));
    }

    /// Store a manifest (shared) under `url` and its sha256 digest.
    ///
    /// This is useful when you want to alias multiple URLs to the same manifest content
    /// without producing multiple Arcs.
    pub fn put_arc(&self, url: Url, resolved_url: Url, manifest: Arc<Manifest>) {
        self.put_arc_scoped(CacheScope::DEFAULT, url, resolved_url, manifest);
    }

    /// Store a manifest (shared) under `url` and its sha256 digest, in a specific cache scope.
    ///
    /// - URL-based entries are scoped.
    /// - Digest-based entries are global.
    pub fn put_arc_scoped(
        &self,
        scope: CacheScope,
        url: Url,
        resolved_url: Url,
        manifest: Arc<Manifest>,
    ) {
        let digest = manifest.digest();
        let entry = CacheEntry {
            resolved_url,
            manifest: Arc::clone(&manifest),
        };

        self.inner.by_url.insert((scope, url), entry.clone());
        self.inner.by_digest.insert(digest, entry);
    }

    pub fn get_by_url(&self, url: &Url) -> Option<CacheEntry> {
        self.get_by_url_scoped(CacheScope::DEFAULT, url)
    }

    pub fn get_by_url_scoped(&self, scope: CacheScope, url: &Url) -> Option<CacheEntry> {
        // DashMap doesn't support borrowed lookup for tuple keys; clone is fine here.
        let key = (scope, url.clone());
        self.inner.by_url.get(&key).map(|r| r.value().clone())
    }

    pub fn get_by_digest(&self, digest: &ManifestDigest) -> Option<CacheEntry> {
        self.inner.by_digest.get(digest).map(|r| r.value().clone())
    }
}
