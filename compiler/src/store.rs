use std::sync::Arc;

use amber_manifest::{Manifest, ManifestDigest};
use dashmap::DashMap;

/// Global manifest content store keyed by digest.
///
/// This is intentionally *not* a URL cache. URLs are mutable; digests are identity.
///
/// Notes:
/// - Cheap to clone (Arc).
/// - Thread-safe (DashMap) for concurrent resolution.
#[derive(Clone, Debug, Default)]
pub struct DigestStore {
    inner: Arc<StoreInner>,
}

#[derive(Debug, Default)]
struct StoreInner {
    by_digest: DashMap<ManifestDigest, Arc<Manifest>>,
}

impl DigestStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, digest: &ManifestDigest) -> Option<Arc<Manifest>> {
        self.inner.by_digest.get(digest).map(|r| r.value().clone())
    }

    /// Insert a manifest under a known digest.
    ///
    /// If the digest already exists, this returns the existing manifest and drops the provided Arc.
    pub fn put(&self, digest: ManifestDigest, manifest: Arc<Manifest>) -> Arc<Manifest> {
        self.inner
            .by_digest
            .entry(digest)
            .or_insert_with(|| Arc::clone(&manifest))
            .clone()
    }
}
