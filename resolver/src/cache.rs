use std::sync::Arc;

use amber_manifest::{DigestAlg, Manifest, ManifestDigest};
use dashmap::DashMap;
use url::Url;

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
    by_url: DashMap<Url, CacheEntry>,
    by_digest: DashMap<ManifestDigest, CacheEntry>,
}

impl Cache {
    /// Store a manifest (owned) under `url` and all supported digests.
    /// Uses `url` as the resolved URL.
    pub fn put(&self, url: Url, manifest: Manifest) {
        self.put_arc(url.clone(), url, Arc::new(manifest));
    }

    /// Store a manifest (shared) under `url` and all supported digests.
    ///
    /// This is useful when you want to alias multiple URLs to the same manifest content
    /// without producing multiple Arcs / duplicating digest entries unnecessarily.
    pub fn put_arc(&self, url: Url, resolved_url: Url, manifest: Arc<Manifest>) {
        let digest = manifest.digest(DigestAlg::default());
        let entry = CacheEntry {
            resolved_url,
            manifest: Arc::clone(&manifest),
        };

        self.inner.by_url.insert(url, entry.clone());
        self.inner.by_digest.insert(digest, entry);
    }

    pub fn get_by_url(&self, url: &Url) -> Option<CacheEntry> {
        self.inner.by_url.get(url).map(|r| r.value().clone())
    }

    pub fn get_by_digest(&self, digest: &ManifestDigest) -> Option<CacheEntry> {
        self.inner.by_digest.get(digest).map(|r| r.value().clone())
    }
}
