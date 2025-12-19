#[cfg(feature = "file-resolver")]
pub mod file;
#[cfg(feature = "http-resolver")]
pub mod http;
#[cfg(feature = "remote-resolver")]
pub mod remote;

use url::Url;

use crate::manifest::{self, Manifest, ManifestDigest};

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
    #[cfg(feature = "http-resolver")]
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("manifest parse error: {0}")]
    Manifest(#[from] manifest::Error),
}

#[derive(Clone, Debug, Default)]
pub struct Resolver {
    #[cfg(feature = "file-resolver")]
    pub file: file::FileResolver,
    #[cfg(feature = "http-resolver")]
    pub http: http::HttpResolver,
    #[cfg(feature = "remote-resolver")]
    remotes: remote::RemoteDispatch,
}

impl Resolver {
    pub fn new() -> Self {
        Default::default()
    }

    #[cfg(feature = "remote-resolver")]
    pub fn with_remote(&self, resolver: remote::RemoteResolver) -> Self {
        Self {
            #[cfg(feature = "file-resolver")]
            file: self.file,
            #[cfg(feature = "http-resolver")]
            http: self.http.clone(),
            remotes: self.remotes.with_remote(resolver),
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
                let actual = manifest.digest(expected.alg());
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
        #[cfg(feature = "remote-resolver")]
        if let Some(resolver) = self.remotes.get(url.scheme()) {
            return resolver.resolve_url(url).await;
        }

        match url.scheme() {
            #[cfg(feature = "file-resolver")]
            "file" => self.file.resolve_url(url).await,
            #[cfg(feature = "http-resolver")]
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
    use url::Url;

    use super::{Error, Resolver};
    use crate::manifest::{DigestAlg, Manifest, ManifestDigest};

    pub(super) async fn assert_digest_mismatch_errors(
        resolver: &Resolver,
        url: &Url,
        manifest: &Manifest,
    ) {
        let digest = manifest.digest(DigestAlg::default());
        let mismatched = match digest {
            ManifestDigest::Sha256(mut bytes) => {
                bytes[0] ^= 0xff;
                ManifestDigest::Sha256(bytes)
            }
        };

        let err = resolver.resolve(url, Some(mismatched)).await.unwrap_err();
        let Error::MismatchedDigest(err_url) = err else {
            panic!("expected MismatchedDigest error");
        };
        assert_eq!(err_url, *url);
    }
}
