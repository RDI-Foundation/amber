pub mod cache;
pub mod file;
pub mod http;
pub mod remote;

use amber_manifest::{Manifest, ManifestDigest};
pub use cache::{Cache, CacheEntry, CacheScope, Cacheability};
pub use file::FileResolver;
pub use http::{ContentTypePolicy, HttpResolver, HttpResolverOptions};
pub use remote::{Backend, RemoteResolver};
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unsupported URL scheme `{scheme}`")]
    UnsupportedScheme { scheme: String },
    #[error("response body from `{url}` exceeds max size {max_bytes} bytes (got {size} bytes)")]
    ResponseTooLarge {
        url: Url,
        size: u64,
        max_bytes: usize,
    },
    #[error("missing content type for `{url}`")]
    MissingContentType { url: Url },
    #[error("unsupported content type `{content_type}` for `{url}`")]
    UnsupportedContentType { url: Url, content_type: String },
    #[error("mismatched digest for `{0}`")]
    MismatchedDigest(Url),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("manifest parse error: {0}")]
    Manifest(#[from] amber_manifest::Error),
}

#[derive(Clone, Debug, Default)]
pub struct Resolver {
    pub file: file::FileResolver,
    pub http: http::HttpResolver,
    remotes: remote::RemoteDispatch,
}

impl Resolver {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn with_remote(&self, resolver: remote::RemoteResolver) -> Self {
        Self {
            file: self.file,
            http: self.http.clone(),
            remotes: self.remotes.with_remote(resolver),
        }
    }

    pub fn with_remotes<I>(&self, resolvers: I) -> Self
    where
        I: IntoIterator<Item = remote::RemoteResolver>,
    {
        Self {
            file: self.file,
            http: self.http.clone(),
            remotes: self.remotes.with_remotes(resolvers),
        }
    }

    pub async fn resolve(
        &self,
        url: &Url,
        digest: Option<ManifestDigest>,
    ) -> Result<Resolution, Error> {
        let res = self.resolve_url(url).await?;
        match digest {
            Some(expected) => {
                let Resolution {
                    url,
                    manifest,
                    cacheability,
                } = res;
                let actual = manifest.digest();
                if actual != expected {
                    return Err(Error::MismatchedDigest(url));
                }
                Ok(Resolution {
                    url,
                    manifest,
                    cacheability,
                })
            }
            None => Ok(res),
        }
    }

    async fn resolve_url(&self, url: &Url) -> Result<Resolution, Error> {
        if let Some(resolver) = self.remotes.get(url.scheme()) {
            return resolver.resolve_url(url).await;
        }

        match url.scheme() {
            "file" => self.file.resolve_url(url).await,
            "http" | "https" => self.http.resolve_url(url).await,
            scheme => Err(Error::UnsupportedScheme {
                scheme: scheme.to_string(),
            }),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Resolution {
    /// The URL where the content was actually found.
    pub url: Url,
    pub manifest: Manifest,
    pub cacheability: crate::cache::Cacheability,
}

#[cfg(test)]
mod tests {
    use amber_manifest::{Manifest, ManifestDigest};
    use url::Url;

    use super::{Error, Resolver};

    pub(super) async fn assert_digest_mismatch_errors(
        resolver: &Resolver,
        url: &Url,
        expected_url: &Url,
        manifest: &Manifest,
    ) {
        let digest = manifest.digest();
        let mut bytes = digest.into_bytes();
        bytes[0] ^= 0xff;
        let mismatched = ManifestDigest::new(bytes);

        let err = resolver.resolve(url, Some(mismatched)).await.unwrap_err();
        let Error::MismatchedDigest(err_url) = err else {
            panic!("expected MismatchedDigest error");
        };
        assert_eq!(err_url, *expected_url);
    }
}
