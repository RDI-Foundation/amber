#[cfg(test)]
mod tests;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr,
};

use base64::Engine;
use semver::Version;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use serde_with::{DeserializeFromStr, MapPreventDuplicates, SerializeDisplay, serde_as};
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlg {
    Sha384,
}

impl fmt::Display for HashAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            HashAlg::Sha384 => "sha384",
        };
        f.write_str(s)
    }
}

#[derive(Clone, Debug, DeserializeFromStr, Eq, Hash, PartialEq, SerializeDisplay)]
pub struct ManifestDigest {
    pub alg: HashAlg,
    pub hash: [u8; 48],
}

impl FromStr for ManifestDigest {
    type Err = ValidationError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let trimmed = input.trim();
        let Some((alg, hash_b64)) = trimmed.split_once(':') else {
            return Err(ValidationError::InvalidManifestDigest(trimmed.to_string()));
        };

        let alg = match alg.trim() {
            "sha384" => HashAlg::Sha384,
            _ => return Err(ValidationError::InvalidManifestDigest(trimmed.to_string())),
        };

        let hash_b64 = hash_b64.trim();
        let hash = base64::engine::general_purpose::STANDARD
            .decode(hash_b64)
            .map_err(|_| ValidationError::InvalidManifestDigest(trimmed.to_string()))?;

        let Ok(hash) = hash.try_into() else {
            return Err(ValidationError::InvalidManifestDigest(trimmed.to_string()));
        };

        Ok(Self { alg, hash })
    }
}

impl fmt::Display for ManifestDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.alg)?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(self.hash);
        f.write_str(&encoded)
    }
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
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
                    serde::de::Error::custom(ValidationError::InvalidManifestRef(
                        trimmed.to_string(),
                    ))
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
                    serde::de::Error::custom(ValidationError::InvalidManifestRef(
                        trimmed.to_string(),
                    ))
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
    type Err = ValidationError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let trimmed = input.trim();
        let url = Url::parse(trimmed)
            .map_err(|_| ValidationError::InvalidManifestRef(trimmed.to_string()))?;
        Ok(Self { url, digest: None })
    }
}

#[derive(
    Clone,
    Debug,
    Default,
    DeserializeFromStr,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    SerializeDisplay,
)]
pub struct InterpolatedString {
    pub parts: Vec<InterpolatedPart>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum InterpolatedPart {
    Literal(String),
    Interpolation {
        source: InterpolationSource,
        query: String,
    },
}

impl FromStr for InterpolatedPart {
    type Err = ValidationError;

    fn from_str(inner: &str) -> Result<Self, ValidationError> {
        let trimmed = inner.trim();
        if trimmed.is_empty() {
            return Err(ValidationError::InvalidInterpolation(trimmed.to_string()));
        }

        let mut segments = trimmed.split('.').map(str::trim);
        let prefix = segments
            .next()
            .ok_or_else(|| ValidationError::InvalidInterpolation(trimmed.to_string()))?;

        let source = match prefix {
            "config" => InterpolationSource::Config,
            "slots" => InterpolationSource::Slots,
            _ => return Err(ValidationError::InvalidInterpolation(trimmed.to_string())),
        };

        let rest: Vec<&str> = segments.filter(|s| !s.is_empty()).collect();
        let query = rest.join(".");

        Ok(InterpolatedPart::Interpolation { source, query })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
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
    type Err = ValidationError;

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
                .ok_or_else(|| ValidationError::InvalidInterpolation(input.to_string()))?;
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

#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ProgramArgs(pub Vec<InterpolatedString>);

impl<'de> Deserialize<'de> for ProgramArgs {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Sugar {
            String(String),
            List(Vec<InterpolatedString>),
        }

        match Sugar::deserialize(deserializer)? {
            Sugar::String(s) => {
                let tokens = shlex::split(&s)
                    .ok_or_else(|| serde::de::Error::custom(ValidationError::UnclosedQuote))?;
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
            Sugar::List(list) => Ok(ProgramArgs(list)),
        }
    }
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Network {
    #[serde(default)]
    pub endpoints: BTreeSet<Endpoint>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Endpoint {
    pub name: String,
    // TODO: this should be an enum tagged by `NetworkProtocol` and carrying appropriate data for the protocol
    pub port: u16,
    #[serde(default = "default_protocol")]
    pub protocol: NetworkProtocol,
    #[serde(default = "default_path")]
    pub path: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
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

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct CapabilityDecl {
    pub kind: CapabilityKind,
    #[serde(default)]
    pub profile: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SlotDecl {
    #[serde(flatten)]
    pub decl: CapabilityDecl,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(untagged)]
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

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ComponentRef {
    pub manifest: ManifestRef,
    #[serde(default)]
    pub config: Option<Value>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ConfigSchema(pub Value);

impl<'de> Deserialize<'de> for ConfigSchema {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        jsonschema::validator_for(&value).map_err(|e| {
            serde::de::Error::custom(ValidationError::InvalidConfigSchema(e.to_string()))
        })?;
        Ok(ConfigSchema(value))
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Binding {
    pub target_component: String,
    pub target_slot: String,
    pub source_component: String,
    pub source_capability: String,
}

impl<'de> Deserialize<'de> for Binding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Canonical {
            target_component: String,
            target_slot: String,
            source_component: String,
            #[serde(default)]
            source_capability: Option<String>,
        }

        #[derive(Deserialize)]
        struct Dot {
            target: String,
            source: String,
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Sugar {
            Canonical(Canonical),
            Dot(Dot),
        }

        let sugar = Sugar::deserialize(deserializer)?;
        let binding = match sugar {
            Sugar::Canonical(c) => {
                let Some(source_capability) = c.source_capability else {
                    return Err(serde::de::Error::custom(
                        "binding missing `source_capability`",
                    ));
                };

                Binding {
                    target_component: c.target_component,
                    target_slot: c.target_slot,
                    source_component: c.source_component,
                    source_capability,
                }
            }
            Sugar::Dot(d) => {
                let (target_component, target_slot) =
                    split_binding_side(&d.target).map_err(serde::de::Error::custom)?;
                let (source_component, source_capability) =
                    split_binding_side(&d.source).map_err(serde::de::Error::custom)?;
                Binding {
                    target_component,
                    target_slot,
                    source_component,
                    source_capability,
                }
            }
        };

        Ok(binding)
    }
}

fn split_binding_side(input: &str) -> Result<(String, String), ValidationError> {
    let trimmed = input.trim();
    let Some((left, right)) = trimmed.split_once('.') else {
        return Err(ValidationError::InvalidBinding {
            input: trimmed.to_string(),
            message: "expected `component.name`".to_string(),
        });
    };

    let left = left.trim();
    let right = right.trim();

    if left.is_empty() || right.is_empty() {
        return Err(ValidationError::InvalidBinding {
            input: trimmed.to_string(),
            message: "expected `component.name`".to_string(),
        });
    }

    Ok((left.to_string(), right.to_string()))
}

#[serde_as]
#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RawManifest {
    manifest_version: Version,
    #[serde(default)]
    program: Option<Program>,
    #[serde_as(as = "MapPreventDuplicates<_, _>")]
    #[serde(default)]
    components: BTreeMap<String, ComponentDecl>,
    #[serde(default)]
    config_schema: Option<ConfigSchema>,
    #[serde_as(as = "MapPreventDuplicates<_, _>")]
    #[serde(default)]
    slots: BTreeMap<String, SlotDecl>,
    #[serde_as(as = "MapPreventDuplicates<_, _>")]
    #[serde(default)]
    provides: BTreeMap<String, ProvideDecl>,
    #[serde(default)]
    bindings: BTreeSet<Binding>,
    #[serde(default)]
    exports: BTreeSet<String>,
}

impl RawManifest {
    pub fn validate(self) -> Result<Manifest, ValidationError> {
        let mut available: BTreeSet<&String> = self.provides.keys().collect();
        available.extend(self.slots.keys());

        for name in &self.exports {
            if !available.contains(name) {
                return Err(ValidationError::UnknownExport { name: name.clone() });
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
                return Err(ValidationError::UnknownEndpoint {
                    name: endpoint.to_string(),
                });
            }
        }

        Ok(Manifest(self))
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Manifest(pub RawManifest);

impl<'de> Deserialize<'de> for Manifest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        RawManifest::deserialize(deserializer)?
            .validate()
            .map_err(serde::de::Error::custom)
    }
}

impl FromStr for Manifest {
    type Err = ValidationError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut deserializer = json5::Deserializer::from_str(input)?;
        let raw: RawManifest = serde_path_to_error::deserialize(&mut deserializer)?;
        raw.validate()
    }
}

impl std::ops::Deref for Manifest {
    type Target = RawManifest;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
