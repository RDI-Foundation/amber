#[cfg(feature = "file-resolver")]
pub mod file;
#[cfg(feature = "http-resolver")]
pub mod http;

use url::Url;

use crate::manifest::{self, Manifest, ManifestDigest};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unsupported URL scheme `{scheme}`")]
    UnsupportedScheme { scheme: String },
    #[error("mismatched digest")]
    MismatchedDigest,
    #[cfg(feature = "http-resolver")]
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("manifest parse error: {0}")]
    Manifest(#[from] manifest::Error),
}

pub trait Resolver: Send + Sync {
    /// The URL schemes that this resolver can resolve.
    fn schemes() -> &'static [&'static str];

    fn resolve(
        &self,
        url: &Url,
        digest: Option<ManifestDigest>,
    ) -> impl Future<Output = Result<Resolution, Error>> + Send {
        async {
            if !Self::schemes().contains(&url.scheme()) {
                return Err(Error::UnsupportedScheme {
                    scheme: url.scheme().to_string(),
                });
            }
            let res = self.resolve_url(url).await?;
            if let Some(digest) = digest
                && res.manifest.digest(digest.alg()) != digest
            {
                return Err(Error::MismatchedDigest);
            }
            Ok(res)
        }
    }

    fn resolve_url(&self, url: &Url) -> impl Future<Output = Result<Resolution, Error>> + Send;
}

#[derive(Clone, Debug)]
pub struct Resolution {
    /// The URL where the content was actually found.
    pub url: Url,
    pub manifest: Manifest,
}

#[cfg(test)]
mod tests {
    use super::{Error, Resolver};
    use crate::manifest::{DigestAlg, Manifest, ManifestDigest};

    pub(super) async fn assert_digest_mismatch_errors<R: Resolver>(
        resolver: &R,
        url: &url::Url,
        manifest: &Manifest,
    ) {
        let digest = manifest.digest(DigestAlg::Sha384);
        let mismatched = match digest {
            ManifestDigest::Sha384(mut bytes) => {
                bytes[0] ^= 0xff;
                ManifestDigest::Sha384(bytes)
            }
            _ => unreachable!("digest(DigestAlg::Sha384) must return ManifestDigest::Sha384"),
        };

        let err = resolver.resolve(url, Some(mismatched)).await.unwrap_err();
        assert!(matches!(err, Error::MismatchedDigest));
    }
}
