use std::sync::Arc;

use amber_manifest::{Manifest, ManifestDigest, ManifestSpans};
use dashmap::DashMap;
use miette::NamedSource;
use url::Url;

pub(crate) fn display_url(url: &Url) -> String {
    if url.scheme() == "file"
        && let Ok(path) = url.to_file_path()
        && let Some(path) = path.to_str()
    {
        return path.to_string();
    }
    url.to_string()
}

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

#[derive(Clone, Debug)]
pub struct StoredSource {
    pub digest: ManifestDigest,
    pub source: Arc<str>,
    pub spans: Arc<ManifestSpans>,
}

#[derive(Debug, Default)]
struct StoreInner {
    by_digest: DashMap<ManifestDigest, Arc<Manifest>>,
    by_url: DashMap<Url, StoredSource>,
}

impl DigestStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, digest: &ManifestDigest) -> Option<Arc<Manifest>> {
        self.inner.by_digest.get(digest).map(|r| r.value().clone())
    }

    pub fn get_source(&self, url: &Url) -> Option<StoredSource> {
        self.inner.by_url.get(url).map(|r| r.value().clone())
    }

    pub(crate) fn diagnostic_source(
        &self,
        url: &Url,
    ) -> Option<(NamedSource<Arc<str>>, Arc<ManifestSpans>)> {
        let StoredSource {
            source,
            spans,
            digest: _,
        } = self.get_source(url)?;
        let name = display_url(url);
        let src = NamedSource::new(name, source).with_language("json5");
        Some((src, spans))
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

    pub fn put_source(&self, url: Url, source: StoredSource) {
        self.inner.by_url.insert(url, source);
    }
}
