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

/// A resolved manifest result, as seen through a scoped URL alias.
#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub resolved_url: Url,
    pub manifest: Arc<Manifest>,
}

#[derive(Clone, Debug)]
struct UrlEntry {
    resolved_url: Url,
    digest: ManifestDigest,
}

#[derive(Debug, Default)]
struct CacheInner {
    /// Scoped URL aliases (ephemeral / environment-sensitive).
    by_url: DashMap<(CacheScope, Url), UrlEntry>,
    /// Global content store by digest (the thing that becomes persistent later).
    by_digest: DashMap<ManifestDigest, Arc<Manifest>>,
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

        // Content store (global, de-duped by digest).
        let _ = self
            .inner
            .by_digest
            .entry(digest)
            .or_insert_with(|| Arc::clone(&manifest));

        // Alias store (scoped, records per-reference resolved_url provenance).
        self.inner.by_url.insert(
            (scope, url),
            UrlEntry {
                resolved_url,
                digest,
            },
        );
    }

    pub fn get_by_url(&self, url: &Url) -> Option<CacheEntry> {
        self.get_by_url_scoped(CacheScope::DEFAULT, url)
    }

    pub fn get_by_url_scoped(&self, scope: CacheScope, url: &Url) -> Option<CacheEntry> {
        // DashMap doesn't support borrowed lookup for tuple keys; clone is fine here.
        let key = (scope, url.clone());
        let alias = self.inner.by_url.get(&key)?.value().clone();
        let manifest = self.inner.by_digest.get(&alias.digest)?.value().clone();
        Some(CacheEntry {
            resolved_url: alias.resolved_url,
            manifest,
        })
    }

    pub fn get_by_digest(&self, digest: &ManifestDigest) -> Option<Arc<Manifest>> {
        self.inner.by_digest.get(digest).map(|r| r.value().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_store_preserves_resolved_url_per_url() {
        let cache = Cache::default();
        let manifest: Manifest = r#"{ manifest_version: "1.0.0" }"#.parse().unwrap();
        let digest = manifest.digest();
        let manifest = Arc::new(manifest);

        let url_b = Url::parse("count://b").unwrap();
        let url_a = Url::parse("count://a").unwrap();

        cache.put_arc_scoped(
            CacheScope::DEFAULT,
            url_b.clone(),
            url_b.clone(),
            Arc::clone(&manifest),
        );
        cache.put_arc_scoped(
            CacheScope::DEFAULT,
            url_a.clone(),
            url_a.clone(),
            Arc::clone(&manifest),
        );

        // Content store is keyed only by digest.
        assert!(cache.get_by_digest(&digest).is_some());

        // Aliases preserve per-URL resolved_url provenance.
        let a = cache.get_by_url(&url_a).expect("url_a entry");
        assert_eq!(a.resolved_url, url_a);
        assert_eq!(a.manifest.digest(), digest);

        let b = cache.get_by_url(&url_b).expect("url_b entry");
        assert_eq!(b.resolved_url, url_b);
        assert_eq!(b.manifest.digest(), digest);
    }
}
