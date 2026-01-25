use std::{
    fmt,
    io::{self, Write},
    str::FromStr,
    sync::Arc,
};

use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use serde_with::{DeserializeFromStr, SerializeDisplay};
use sha2::Digest as _;
use url::{ParseError, Url};

use crate::error::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, DeserializeFromStr, SerializeDisplay)]
#[non_exhaustive]
pub struct ManifestDigest([u8; 32]);

impl ManifestDigest {
    pub const ALG: &'static str = "sha256";

    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    pub(crate) fn digest(manifest: &crate::manifest::RawManifest) -> Self {
        struct HashWriter<'a>(&'a mut sha2::Sha256);

        impl Write for HashWriter<'_> {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.update(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let mut hasher = sha2::Sha256::new();
        serde_json::to_writer(HashWriter(&mut hasher), manifest)
            .expect("hashing manifest JSON cannot fail");
        Self(hasher.finalize().into())
    }
}

impl AsRef<[u8]> for ManifestDigest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl FromStr for ManifestDigest {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let Some((alg, hash_b64)) = input.split_once(':') else {
            return Err(Error::InvalidManifestDigest(input.to_string()));
        };

        if alg != Self::ALG {
            return Err(Error::InvalidManifestDigest(input.to_string()));
        }

        let hash = base64::engine::general_purpose::STANDARD
            .decode(hash_b64)
            .map_err(|_| Error::InvalidManifestDigest(input.to_string()))?;

        let Ok(bytes) = hash.as_slice().try_into() else {
            return Err(Error::InvalidManifestDigest(input.to_string()));
        };

        Ok(Self(bytes))
    }
}

impl fmt::Display for ManifestDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(Self::ALG)?;
        f.write_str(":")?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(self);
        f.write_str(&encoded)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub struct ManifestRef {
    pub url: ManifestUrl,
    #[serde(default)]
    pub digest: Option<ManifestDigest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, DeserializeFromStr, SerializeDisplay)]
#[non_exhaustive]
pub enum ManifestUrl {
    Absolute(Url),
    Relative(Arc<str>),
}

impl ManifestUrl {
    fn parse(input: &str) -> Result<Self, Error> {
        if input.is_empty() {
            return Err(Error::InvalidManifestRef(input.to_string()));
        }

        match Url::parse(input) {
            Ok(url) => Ok(Self::Absolute(url)),
            Err(ParseError::RelativeUrlWithoutBase) => Ok(Self::Relative(Arc::from(input))),
            Err(_) => Err(Error::InvalidManifestRef(input.to_string())),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            ManifestUrl::Absolute(url) => url.as_str(),
            ManifestUrl::Relative(value) => value,
        }
    }

    pub fn as_url(&self) -> Option<&Url> {
        match self {
            ManifestUrl::Absolute(url) => Some(url),
            ManifestUrl::Relative(_) => None,
        }
    }

    pub fn is_relative(&self) -> bool {
        matches!(self, ManifestUrl::Relative(_))
    }

    pub fn resolve(&self, base: &Url) -> Result<Url, ParseError> {
        match self {
            ManifestUrl::Absolute(url) => Ok(url.clone()),
            ManifestUrl::Relative(rel) => base.join(rel),
        }
    }
}

impl fmt::Display for ManifestUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ManifestUrl {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

impl FromStr for ManifestRef {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            url: ManifestUrl::parse(input)?,
            digest: None,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestRefObject {
    url: ManifestUrl,
    #[serde(default)]
    digest: Option<ManifestDigest>,
}

impl<'de> Deserialize<'de> for ManifestRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::String(url) => Ok(Self {
                url: ManifestUrl::parse(&url).map_err(serde::de::Error::custom)?,
                digest: None,
            }),
            Value::Object(map) => {
                let obj = serde_json::from_value::<ManifestRefObject>(Value::Object(map))
                    .map_err(serde::de::Error::custom)?;
                Ok(Self {
                    url: obj.url,
                    digest: obj.digest,
                })
            }
            _ => Err(serde::de::Error::custom(
                "manifest ref must be a URL string or an object",
            )),
        }
    }
}

impl ManifestRef {
    pub fn new(url: Url, digest: Option<ManifestDigest>) -> Self {
        Self {
            url: ManifestUrl::Absolute(url),
            digest,
        }
    }

    pub fn from_url(url: Url) -> Self {
        Self {
            url: ManifestUrl::Absolute(url),
            digest: None,
        }
    }

    pub fn resolve_against(&self, base: &Url) -> Result<Self, ParseError> {
        let url = self.url.resolve(base)?;
        Ok(Self {
            url: ManifestUrl::Absolute(url),
            digest: self.digest,
        })
    }
}
