#[cfg(test)]
mod tests;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{self, Write},
    str::FromStr,
};

use base64::Engine;
use semver::Version;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use serde_with::{DeserializeFromStr, MapPreventDuplicates, SerializeDisplay, serde_as};
use sha2::Digest as _;
use url::Url;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("json5 parse error: {0}")]
    Json5(#[from] json5::Error),
    #[error("json5 deserialize error: {0}")]
    Json5Path(#[from] serde_path_to_error::Error<json5::Error>),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid manifest reference `{0}`")]
    InvalidManifestRef(String),
    #[error("invalid manifest digest `{0}`")]
    InvalidManifestDigest(String),
    #[error("invalid interpolation `{0}`")]
    InvalidInterpolation(String),
    #[error("invalid binding `{input}`: {message}")]
    InvalidBinding { input: String, message: String },
    #[error("unclosed quote in args string")]
    UnclosedQuote,
    #[error("export `{name}` not provided or slotted")]
    UnknownExport { name: String },
    #[error("unknown endpoint `{name}` referenced")]
    UnknownEndpoint { name: String },
    #[error("invalid config schema: {0}")]
    InvalidConfigSchema(String),
}

macro_rules! count {
    ($ident:ident) => { 1 };
    ($head:ident, $($rest:ident),+) => { 1 + count!($($rest),+) }
}

macro_rules! first {
    ($head:expr $(, $($rest:expr),+)?) => {
        $head
    };
}

macro_rules! digest {
    ($( ($name:ident, $size:literal, $tag:literal) ),+ $(,)? ) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, DeserializeFromStr, SerializeDisplay)]
        #[non_exhaustive]
        pub enum DigestAlg {
            $($name),+
        }

        impl DigestAlg {
            pub fn all() -> [Self; count!($($name),+)] {
                [$(Self::$name),+]
            }
        }

        impl Default for DigestAlg {
            fn default() -> Self {
                first!(Self::$($name),+)
            }
        }

        impl fmt::Display for DigestAlg {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", match self {
                    $( Self::$name => $tag ),+
                })
            }
        }

        impl FromStr for DigestAlg {
            type Err = Error;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                match input {
                    $($tag => Ok(Self::$name)),+,
                    alg => Err(Error::InvalidManifestDigest(format!("unknown digest alg: {alg}")))
                }
            }
        }

        #[derive(Clone, Debug, PartialEq, Eq, Hash, DeserializeFromStr, SerializeDisplay)]
        #[non_exhaustive]
        pub enum ManifestDigest {
            $( $name([u8; $size]) ),+
        }

        impl ManifestDigest {
            pub fn digest(manifest: &RawManifest, alg: DigestAlg) -> Self {
                match alg {
                    $(DigestAlg::$name => {
                        struct HashWriter<'a>(&'a mut sha2::$name);

                        impl Write for HashWriter<'_> {
                            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                                self.0.update(buf);
                                Ok(buf.len())
                            }

                            fn flush(&mut self) -> io::Result<()> {
                                Ok(())
                            }
                        }

                        let mut hasher = sha2::$name::new();
                        serde_json::to_writer(HashWriter(&mut hasher), manifest).unwrap();
                        Self::$name(hasher.finalize().into())
                    }),+
                }
            }

            pub fn alg(&self) -> DigestAlg {
                match self {
                    $( Self::$name(_) => DigestAlg::$name ),+
                }
            }
        }

        impl TryFrom<(DigestAlg, &[u8])> for ManifestDigest {
            type Error = Error;

            fn try_from((alg, hash): (DigestAlg, &[u8])) -> Result<Self, Self::Error> {
                match alg {
                    $(
                    DigestAlg::$name => {
                        let Ok(bytes) = hash.try_into() else {
                            return Err(Error::InvalidManifestDigest(
                                    format!("expected {} bytes but got {}", $size, hash.len())));
                        };
                        Ok(Self::$name(bytes))
                    }
                    )+,
                }
            }
        }

        impl AsRef<[u8]> for ManifestDigest {
            fn as_ref(&self) -> &[u8] {
                match self {
                    $( Self::$name(bytes) => &*bytes ),+
                }
            }
        }
    }
}

digest!(
    (Sha256, 32, "sha256"),
    // This is how to add others:
    // (Sha384, 48, "sha384"),
    // (Sha512, 64, "sha512"),
);

impl FromStr for ManifestDigest {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let trimmed = input.trim();
        let Some((alg, hash_b64)) = trimmed.split_once(':') else {
            return Err(Error::InvalidManifestDigest(trimmed.to_string()));
        };

        let alg = alg.trim().parse()?;
        let hash = base64::engine::general_purpose::STANDARD
            .decode(hash_b64.trim())
            .map_err(|_| Error::InvalidManifestDigest(trimmed.to_string()))?;

        (alg, hash.as_slice()).try_into()
    }
}

impl fmt::Display for ManifestDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.alg())?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(self);
        f.write_str(&encoded)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub struct ManifestRef {
    pub url: Url,
    #[serde(default)]
    pub digest: Option<ManifestDigest>,
}

impl<'de> Deserialize<'de> for ManifestRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::String(url) => {
                let trimmed = url.trim();
                let url = Url::parse(trimmed).map_err(|_| {
                    serde::de::Error::custom(Error::InvalidManifestRef(trimmed.to_string()))
                })?;
                Ok(Self { url, digest: None })
            }
            Value::Object(mut map) => {
                let url = match map.remove("url") {
                    Some(Value::String(url)) => url,
                    Some(_) => {
                        return Err(serde::de::Error::custom(
                            "manifest ref `url` must be a string",
                        ));
                    }
                    None => return Err(serde::de::Error::custom("manifest ref missing `url`")),
                };

                let trimmed = url.trim();
                let url = Url::parse(trimmed).map_err(|_| {
                    serde::de::Error::custom(Error::InvalidManifestRef(trimmed.to_string()))
                })?;

                let digest = match map.remove("digest") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(digest)) => Some(
                        digest
                            .parse::<ManifestDigest>()
                            .map_err(serde::de::Error::custom)?,
                    ),
                    Some(_) => {
                        return Err(serde::de::Error::custom(
                            "manifest ref `digest` must be a string",
                        ));
                    }
                };

                Ok(Self { url, digest })
            }
            _ => Err(serde::de::Error::custom(
                "manifest ref must be a URL string or an object",
            )),
        }
    }
}

impl FromStr for ManifestRef {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let trimmed = input.trim();
        let url =
            Url::parse(trimmed).map_err(|_| Error::InvalidManifestRef(trimmed.to_string()))?;
        Ok(Self { url, digest: None })
    }
}

#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    DeserializeFromStr,
    SerializeDisplay,
)]
#[non_exhaustive]
pub struct InterpolatedString {
    pub parts: Vec<InterpolatedPart>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum InterpolatedPart {
    Literal(String),
    Interpolation {
        source: InterpolationSource,
        query: String,
    },
}

impl FromStr for InterpolatedPart {
    type Err = Error;

    fn from_str(inner: &str) -> Result<Self, Error> {
        let trimmed = inner.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidInterpolation(trimmed.to_string()));
        }

        let mut segments = trimmed.split('.').map(str::trim);
        let prefix = segments
            .next()
            .ok_or_else(|| Error::InvalidInterpolation(trimmed.to_string()))?;

        let source = match prefix {
            "config" => InterpolationSource::Config,
            "slots" => InterpolationSource::Slots,
            _ => return Err(Error::InvalidInterpolation(trimmed.to_string())),
        };

        let rest: Vec<&str> = segments.filter(|s| !s.is_empty()).collect();
        let query = rest.join(".");

        Ok(InterpolatedPart::Interpolation { source, query })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum InterpolationSource {
    Config,
    Slots,
}

impl fmt::Display for InterpolationSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            InterpolationSource::Config => "config",
            InterpolationSource::Slots => "slots",
        };
        f.write_str(s)
    }
}

impl FromStr for InterpolatedString {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut parts = Vec::new();
        let mut rest = input;

        while let Some(start) = rest.find("${") {
            let before = &rest[..start];
            if !before.is_empty() {
                parts.push(InterpolatedPart::Literal(before.to_string()));
            }

            let after_start = &rest[start + 2..];
            let end = after_start
                .find('}')
                .ok_or_else(|| Error::InvalidInterpolation(input.to_string()))?;
            let inner = &after_start[..end];
            parts.push(inner.parse()?);
            rest = &after_start[end + 1..];
        }

        if !rest.is_empty() {
            parts.push(InterpolatedPart::Literal(rest.to_string()));
        }

        Ok(Self { parts })
    }
}

impl fmt::Display for InterpolatedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for part in &self.parts {
            match part {
                InterpolatedPart::Literal(s) => f.write_str(s)?,
                InterpolatedPart::Interpolation { source, query } => {
                    f.write_str("${")?;
                    write!(f, "{source}")?;
                    if !query.is_empty() {
                        f.write_str(".")?;
                        f.write_str(query)?;
                    }
                    f.write_str("}")?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ProgramArgs(pub Vec<InterpolatedString>);

impl<'de> Deserialize<'de> for ProgramArgs {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum ProgramArgsForm {
            String(String),
            List(Vec<InterpolatedString>),
        }

        match ProgramArgsForm::deserialize(deserializer)? {
            ProgramArgsForm::String(s) => {
                let tokens = shlex::split(&s)
                    .ok_or_else(|| serde::de::Error::custom(Error::UnclosedQuote))?;
                let mut args = Vec::new();
                for token in tokens {
                    args.push(
                        token
                            .parse::<InterpolatedString>()
                            .map_err(serde::de::Error::custom)?,
                    );
                }
                Ok(ProgramArgs(args))
            }
            ProgramArgsForm::List(list) => Ok(ProgramArgs(list)),
        }
    }
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Program {
    pub image: String,
    #[serde(default)]
    pub args: ProgramArgs,
    #[serde_as(as = "MapPreventDuplicates<_, _>")]
    #[serde(default)]
    pub env: BTreeMap<String, InterpolatedString>,
    #[serde(default)]
    pub network: Option<Network>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Network {
    #[serde(default)]
    pub endpoints: BTreeSet<Endpoint>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Endpoint {
    pub name: String,
    // TODO: this should be an enum tagged by `NetworkProtocol` and carrying appropriate data for the protocol
    pub port: u16,
    #[serde(default = "default_protocol")]
    pub protocol: NetworkProtocol,
    #[serde(default = "default_path")]
    pub path: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum NetworkProtocol {
    Http,
    Https,
    Tcp,
    Udp,
}

impl fmt::Display for NetworkProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            NetworkProtocol::Http => "http",
            NetworkProtocol::Https => "https",
            NetworkProtocol::Tcp => "tcp",
            NetworkProtocol::Udp => "udp",
        };
        f.write_str(s)
    }
}

fn default_protocol() -> NetworkProtocol {
    NetworkProtocol::Http
}

fn default_path() -> String {
    "/".to_string()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum CapabilityKind {
    Mcp,
    Llm,
    Http,
    A2a,
}

impl fmt::Display for CapabilityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            CapabilityKind::Mcp => "mcp",
            CapabilityKind::Llm => "llm",
            CapabilityKind::Http => "http",
            CapabilityKind::A2a => "a2a",
        };
        f.write_str(s)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CapabilityDecl {
    pub kind: CapabilityKind,
    #[serde(default)]
    pub profile: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SlotDecl {
    #[serde(flatten)]
    pub decl: CapabilityDecl,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ProvideDecl {
    #[serde(flatten)]
    pub decl: CapabilityDecl,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub capability: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum ComponentDecl {
    Reference(ManifestRef),
    Object(ComponentRef),
}

impl<'de> Deserialize<'de> for ComponentDecl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::String(url) => Ok(ComponentDecl::Reference(
                url.parse::<ManifestRef>()
                    .map_err(serde::de::Error::custom)?,
            )),
            Value::Object(map) => {
                if map.contains_key("manifest") {
                    let inner = serde_json::from_value(Value::Object(map))
                        .map_err(serde::de::Error::custom)?;
                    Ok(ComponentDecl::Object(inner))
                } else {
                    let inner = serde_json::from_value(Value::Object(map))
                        .map_err(serde::de::Error::custom)?;
                    Ok(ComponentDecl::Reference(inner))
                }
            }
            _ => Err(serde::de::Error::custom(
                "component decl must be a URL string or an object",
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ComponentRef {
    pub manifest: ManifestRef,
    #[serde(default)]
    pub config: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ConfigSchema(pub Value);

impl<'de> Deserialize<'de> for ConfigSchema {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        jsonschema::validator_for(&value)
            .map_err(|e| serde::de::Error::custom(Error::InvalidConfigSchema(e.to_string())))?;
        Ok(ConfigSchema(value))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[non_exhaustive]
pub struct Binding {
    pub to: String,
    pub slot: String,
    pub from: String,
    pub capability: String,
    #[serde(default)]
    pub weak: bool,
}

impl<'de> Deserialize<'de> for Binding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct ExplicitBindingForm {
            to: String,
            slot: String,
            from: String,
            capability: String,
            #[serde(default)]
            weak: bool,
        }

        #[derive(Deserialize)]
        struct DotBindingForm {
            to: String,
            from: String,
            #[serde(default)]
            weak: bool,
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum BindingForm {
            Explicit(ExplicitBindingForm),
            Dot(DotBindingForm),
        }

        match BindingForm::deserialize(deserializer)? {
            BindingForm::Explicit(explicit) => Ok(Binding {
                to: parse_binding_component_ref(&explicit.to).map_err(serde::de::Error::custom)?,
                slot: explicit.slot,
                from: parse_binding_component_ref(&explicit.from)
                    .map_err(serde::de::Error::custom)?,
                capability: explicit.capability,
                weak: explicit.weak,
            }),
            BindingForm::Dot(dot) => {
                let (to, slot) = split_binding_side(&dot.to).map_err(serde::de::Error::custom)?;
                let (from, capability) =
                    split_binding_side(&dot.from).map_err(serde::de::Error::custom)?;
                Ok(Binding {
                    to,
                    slot,
                    from,
                    capability,
                    weak: dot.weak,
                })
            }
        }
    }
}

fn parse_binding_component_ref(input: &str) -> Result<String, Error> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidBinding {
            input: input.to_string(),
            message: "component ref cannot be empty".to_string(),
        });
    }

    match trimmed {
        "self" => Ok(trimmed.to_string()),
        _ => match trimmed.strip_prefix('#') {
            Some(name) => {
                let name = name.trim();
                if name.is_empty() {
                    return Err(Error::InvalidBinding {
                        input: trimmed.to_string(),
                        message: "expected `#<child>`".to_string(),
                    });
                }
                Ok(format!("#{name}"))
            }
            None => Err(Error::InvalidBinding {
                input: trimmed.to_string(),
                message: "expected `self` or `#<child>`".to_string(),
            }),
        },
    }
}

fn split_binding_side(input: &str) -> Result<(String, String), Error> {
    let trimmed = input.trim();
    let Some((left, right)) = trimmed.split_once('.') else {
        return Err(Error::InvalidBinding {
            input: trimmed.to_string(),
            message: "expected `<component-ref>.<name>`".to_string(),
        });
    };

    let left = left.trim();
    let right = right.trim();

    if left.is_empty() || right.is_empty() {
        return Err(Error::InvalidBinding {
            input: trimmed.to_string(),
            message: "expected `<component-ref>.<name>`".to_string(),
        });
    }

    let component = parse_binding_component_ref(left)?;
    Ok((component, right.to_string()))
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RawManifest {
    pub manifest_version: Version,
    #[serde(default)]
    pub program: Option<Program>,
    #[serde_as(as = "MapPreventDuplicates<_, _>")]
    #[serde(default)]
    pub components: BTreeMap<String, ComponentDecl>,
    #[serde(default)]
    pub config_schema: Option<ConfigSchema>,
    #[serde_as(as = "MapPreventDuplicates<_, _>")]
    #[serde(default)]
    pub slots: BTreeMap<String, SlotDecl>,
    #[serde_as(as = "MapPreventDuplicates<_, _>")]
    #[serde(default)]
    pub provides: BTreeMap<String, ProvideDecl>,
    #[serde(default)]
    pub bindings: BTreeSet<Binding>,
    #[serde(default)]
    pub exports: BTreeSet<String>,
}

impl RawManifest {
    pub fn digest(&self, alg: DigestAlg) -> ManifestDigest {
        ManifestDigest::digest(self, alg)
    }

    pub fn validate(self) -> Result<Manifest, Error> {
        let mut available: BTreeSet<&String> = self.provides.keys().collect();
        available.extend(self.slots.keys());

        for name in &self.exports {
            if !available.contains(name) {
                return Err(Error::UnknownExport { name: name.clone() });
            }
        }

        let mut defined_endpoints = BTreeSet::new();
        if let Some(program) = &self.program
            && let Some(network) = &program.network
        {
            for endpoint in &network.endpoints {
                defined_endpoints.insert(endpoint.name.as_str());
            }
        }

        for provide in self.provides.values() {
            if let Some(endpoint) = provide.endpoint.as_deref()
                && !defined_endpoints.contains(endpoint)
            {
                return Err(Error::UnknownEndpoint {
                    name: endpoint.to_string(),
                });
            }
        }

        Ok(Manifest { raw: self })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "RawManifest", try_from = "RawManifest")]
pub struct Manifest {
    raw: RawManifest,
}

impl Manifest {
    pub fn empty() -> Self {
        Self::from_str("{manifest_version:\"0.0.0\"}").unwrap()
    }
}

impl TryFrom<RawManifest> for Manifest {
    type Error = Error;

    fn try_from(raw: RawManifest) -> Result<Self, Self::Error> {
        raw.validate()
    }
}

impl From<Manifest> for RawManifest {
    fn from(manifest: Manifest) -> Self {
        manifest.raw
    }
}

impl FromStr for Manifest {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut deserializer = json5::Deserializer::from_str(input)?;
        Ok(serde_path_to_error::deserialize(&mut deserializer)?)
    }
}

impl std::ops::Deref for Manifest {
    type Target = RawManifest;

    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}
