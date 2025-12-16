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
    by_url: DashMap<Url, Arc<Manifest>>,
    by_digest: DashMap<ManifestDigest, Arc<Manifest>>,
}

impl Cache {
    pub fn put(&self, url: Url, manifest: Manifest) {
        let digests = DigestAlg::all().map(|alg| manifest.digest(alg));

        let m = Arc::new(manifest);

        self.by_url.insert(url, Arc::clone(&m));
        for d in digests {
            self.by_digest.insert(d, Arc::clone(&m));
        }
    }

    pub fn get_by_url(&self, url: &Url) -> Option<Arc<Manifest>> {
        self.by_url.get(url).map(|r| Arc::clone(r.value()))
    }

    pub fn get_by_digest(&self, digest: &ManifestDigest) -> Option<Arc<Manifest>> {
        self.by_digest.get(digest).map(|r| Arc::clone(r.value()))
    }
}
