use std::sync::Arc;

use dashmap::DashMap;
use url::Url;

use crate::manifest::{DigestAlg, Manifest, ManifestDigest};

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

#[derive(Debug, Default)]
struct CacheInner {
    by_url: DashMap<Url, Arc<Manifest>>,
    by_digest: DashMap<ManifestDigest, Arc<Manifest>>,
}

impl Cache {
    /// Store a manifest (owned) under `url` and all supported digests.
    pub fn put(&self, url: Url, manifest: Manifest) {
        self.put_arc(url, Arc::new(manifest));
    }

    /// Store a manifest (shared) under `url` and all supported digests.
    ///
    /// This is useful when you want to alias multiple URLs to the same manifest content
    /// without producing multiple Arcs / duplicating digest entries unnecessarily.
    pub fn put_arc(&self, url: Url, manifest: Arc<Manifest>) {
        let digest = manifest.digest(DigestAlg::default());

        self.inner.by_url.insert(url, Arc::clone(&manifest));
        self.inner.by_digest.insert(digest, Arc::clone(&manifest));
    }

    pub fn get_by_url(&self, url: &Url) -> Option<Arc<Manifest>> {
        self.inner.by_url.get(url).map(|r| Arc::clone(r.value()))
    }

    pub fn get_by_digest(&self, digest: &ManifestDigest) -> Option<Arc<Manifest>> {
        self.inner
            .by_digest
            .get(digest)
            .map(|r| Arc::clone(r.value()))
    }
}
