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
    #[error("invalid component ref `{input}`: {message}")]
    InvalidComponentRef { input: String, message: String },
    #[error("invalid binding `{input}`: {message}")]
    InvalidBinding { input: String, message: String },
    #[error("invalid {kind} name `{name}`: dots are reserved")]
    InvalidName { kind: &'static str, name: String },
    #[error("unclosed quote in args string")]
    UnclosedQuote,
    #[error("export `{name}` not provided or slotted")]
    UnknownExport { name: String },
    #[error("capability `{name}` cannot be declared as both slot and provide")]
    AmbiguousCapabilityName { name: String },
    #[error("binding target `{to}.{slot}` is bound more than once")]
    DuplicateBindingTarget { to: String, slot: String },
    #[error("binding references unknown child `#{child}`")]
    UnknownBindingChild { child: String },
    #[error("binding target `self.{slot}` references unknown slot")]
    UnknownBindingSlot { slot: String },
    #[error("binding source `self.{capability}` references unknown provide")]
    UnknownBindingProvide { capability: String },
    #[error("slot `{name}` must be bound or exported")]
    UnusedSlot { name: String },
    #[error("provide `{name}` must be bound or exported")]
    UnusedProvide { name: String },
    #[error("duplicate endpoint name `{name}`")]
    DuplicateEndpointName { name: String },
    #[error("unknown endpoint `{name}` referenced")]
    UnknownEndpoint { name: String },
    #[error("invalid config schema: {0}")]
    InvalidConfigSchema(String),
    #[error(
        "unsupported manifest version `{version}` (supported major version: {supported_major})"
    )]
    UnsupportedManifestVersion {
        version: Version,
        supported_major: u64,
    },
}

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

    pub fn digest(manifest: &RawManifest) -> Self {
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
            Value::String(url) => Ok(Self {
                url: Url::parse(&url).map_err(|_| {
                    serde::de::Error::custom(Error::InvalidManifestRef(url.clone()))
                })?,
                digest: None,
            }),
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

                let url = Url::parse(&url).map_err(|_| {
                    serde::de::Error::custom(Error::InvalidManifestRef(url.clone()))
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

                if !map.is_empty() {
                    let mut keys = map.keys().cloned().collect::<Vec<_>>();
                    keys.sort();
                    let suffix = if keys.len() == 1 { "" } else { "s" };
                    return Err(serde::de::Error::custom(format!(
                        "manifest ref contains unknown field{suffix}: {}",
                        keys.join(", ")
                    )));
                }

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
        Ok(Self {
            url: Url::parse(input).map_err(|_| Error::InvalidManifestRef(input.to_string()))?,
            digest: None,
        })
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
        if inner.is_empty() {
            return Err(Error::InvalidInterpolation(inner.to_string()));
        }

        let mut segments = inner.split('.');
        let prefix = segments
            .next()
            .ok_or_else(|| Error::InvalidInterpolation(inner.to_string()))?;

        let source = match prefix {
            "config" => InterpolationSource::Config,
            "slots" => InterpolationSource::Slots,
            _ => return Err(Error::InvalidInterpolation(inner.to_string())),
        };

        let query = segments
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(".");

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
        let mut current_literal = String::new();
        let mut chars = input.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '$' && chars.peek() == Some(&'{') {
                chars.next(); // consume '{'
                if !current_literal.is_empty() {
                    parts.push(InterpolatedPart::Literal(std::mem::take(
                        &mut current_literal,
                    )));
                }

                let mut inner = String::new();
                let mut closed = false;
                for ic in chars.by_ref() {
                    if ic == '}' {
                        closed = true;
                        break;
                    }
                    inner.push(ic);
                }

                if !closed {
                    return Err(Error::InvalidInterpolation(input.to_string()));
                }
                parts.push(inner.parse()?);
            } else {
                current_literal.push(c);
            }
        }

        if !current_literal.is_empty() {
            parts.push(InterpolatedPart::Literal(current_literal));
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
    #[serde(default, deserialize_with = "deserialize_endpoints")]
    pub endpoints: BTreeSet<Endpoint>,
}

fn deserialize_endpoints<'de, D>(deserializer: D) -> Result<BTreeSet<Endpoint>, D::Error>
where
    D: Deserializer<'de>,
{
    let endpoints = Vec::<Endpoint>::deserialize(deserializer)?;
    let mut names = BTreeSet::new();
    for endpoint in &endpoints {
        if !names.insert(endpoint.name.as_str()) {
            return Err(serde::de::Error::custom(Error::DuplicateEndpointName {
                name: endpoint.name.clone(),
            }));
        }
    }
    Ok(endpoints.into_iter().collect())
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

#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, DeserializeFromStr, SerializeDisplay,
)]
#[non_exhaustive]
pub enum LocalComponentRef {
    Self_,
    Child(String),
}

impl LocalComponentRef {
    pub fn is_self(&self) -> bool {
        matches!(self, Self::Self_)
    }
}

impl fmt::Display for LocalComponentRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Self_ => f.write_str("self"),
            Self::Child(name) => {
                f.write_str("#")?;
                f.write_str(name)
            }
        }
    }
}

impl FromStr for LocalComponentRef {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_component_ref(input).map_err(|err| Error::InvalidComponentRef {
            input: err.input,
            message: err.message,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ProvideDecl {
    #[serde(flatten)]
    pub decl: CapabilityDecl,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub from: Option<LocalComponentRef>,
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

impl ManifestRef {
    pub fn new(url: Url, digest: Option<ManifestDigest>) -> Self {
        Self { url, digest }
    }

    pub fn from_url(url: Url) -> Self {
        Self { url, digest: None }
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
    pub to: LocalComponentRef,
    pub slot: String,
    pub from: LocalComponentRef,
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
            BindingForm::Explicit(explicit) => {
                ensure_binding_name_no_dot(&explicit.slot, explicit.slot.as_str())
                    .map_err(serde::de::Error::custom)?;
                ensure_binding_name_no_dot(&explicit.capability, explicit.capability.as_str())
                    .map_err(serde::de::Error::custom)?;
                Ok(Binding {
                    to: parse_binding_component_ref(&explicit.to)
                        .map_err(serde::de::Error::custom)?,
                    slot: explicit.slot,
                    from: parse_binding_component_ref(&explicit.from)
                        .map_err(serde::de::Error::custom)?,
                    capability: explicit.capability,
                    weak: explicit.weak,
                })
            }
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

#[derive(Debug)]
struct ComponentRefParseError {
    input: String,
    message: String,
}

fn parse_component_ref(input: &str) -> Result<LocalComponentRef, ComponentRefParseError> {
    if input.is_empty() {
        return Err(ComponentRefParseError {
            input: input.to_string(),
            message: "component ref cannot be empty".to_string(),
        });
    }

    match input {
        "self" => Ok(LocalComponentRef::Self_),
        _ => match input.strip_prefix('#') {
            Some("") => Err(ComponentRefParseError {
                input: input.to_string(),
                message: "expected `#<child>`".to_string(),
            }),
            Some(name) if name.contains('.') => Err(ComponentRefParseError {
                input: input.to_string(),
                message: "child name cannot contain `.`".to_string(),
            }),
            Some(name) => Ok(LocalComponentRef::Child(name.to_string())),
            None => Err(ComponentRefParseError {
                input: input.to_string(),
                message: "expected `self` or `#<child>`".to_string(),
            }),
        },
    }
}

fn parse_binding_component_ref(input: &str) -> Result<LocalComponentRef, Error> {
    parse_component_ref(input).map_err(|err| Error::InvalidBinding {
        input: err.input,
        message: err.message,
    })
}

fn ensure_name_no_dot(name: &str, kind: &'static str) -> Result<(), Error> {
    if name.contains('.') {
        return Err(Error::InvalidName {
            kind,
            name: name.to_string(),
        });
    }
    Ok(())
}

fn ensure_binding_name_no_dot(name: &str, input: &str) -> Result<(), Error> {
    if name.contains('.') {
        return Err(Error::InvalidBinding {
            input: input.to_string(),
            message: "binding names cannot contain `.`".to_string(),
        });
    }
    Ok(())
}

fn split_binding_side(input: &str) -> Result<(LocalComponentRef, String), Error> {
    let Some((left, right)) = input.split_once('.') else {
        return Err(Error::InvalidBinding {
            input: input.to_string(),
            message: "expected `<component-ref>.<name>`".to_string(),
        });
    };

    if left.is_empty() || right.is_empty() {
        return Err(Error::InvalidBinding {
            input: input.to_string(),
            message: "expected `<component-ref>.<name>`".to_string(),
        });
    }

    let component = parse_binding_component_ref(left)?;
    ensure_binding_name_no_dot(right, input)?;
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

const SUPPORTED_MANIFEST_MAJOR: u64 = 1;

impl RawManifest {
    pub fn digest(&self) -> ManifestDigest {
        ManifestDigest::digest(self)
    }

    fn validate_version(&self) -> Result<(), Error> {
        if self.manifest_version.major != SUPPORTED_MANIFEST_MAJOR {
            return Err(Error::UnsupportedManifestVersion {
                version: self.manifest_version.clone(),
                supported_major: SUPPORTED_MANIFEST_MAJOR,
            });
        }
        Ok(())
    }

    pub fn validate(self) -> Result<Manifest, Error> {
        self.validate_version()?;
        for name in self.components.keys() {
            ensure_name_no_dot(name, "child")?;
        }
        for name in self.slots.keys() {
            ensure_name_no_dot(name, "slot")?;
        }
        for name in self.provides.keys() {
            ensure_name_no_dot(name, "provide")?;
        }
        for name in &self.exports {
            ensure_name_no_dot(name, "export")?;
        }
        for provide in self.provides.values() {
            if let Some(capability) = &provide.capability {
                ensure_name_no_dot(capability, "capability")?;
            }
        }
        if let Some(name) = self
            .slots
            .keys()
            .find(|name| self.provides.contains_key(*name))
        {
            return Err(Error::AmbiguousCapabilityName { name: name.clone() });
        }

        let mut bound_targets = BTreeSet::new();
        let mut self_bound_slots = BTreeSet::new();
        let mut self_bound_capabilities = BTreeSet::new();

        for binding in &self.bindings {
            let target = (&binding.to, binding.slot.as_str());
            if !bound_targets.insert(target) {
                return Err(Error::DuplicateBindingTarget {
                    to: binding.to.to_string(),
                    slot: binding.slot.clone(),
                });
            }

            match &binding.to {
                LocalComponentRef::Self_ => {
                    if !self.slots.contains_key(&binding.slot) {
                        return Err(Error::UnknownBindingSlot {
                            slot: binding.slot.clone(),
                        });
                    }
                    self_bound_slots.insert(binding.slot.as_str());
                }
                LocalComponentRef::Child(name) => {
                    if !self.components.contains_key(name) {
                        return Err(Error::UnknownBindingChild {
                            child: name.clone(),
                        });
                    }
                }
            }

            match &binding.from {
                LocalComponentRef::Self_ => {
                    if !self.provides.contains_key(&binding.capability) {
                        return Err(Error::UnknownBindingProvide {
                            capability: binding.capability.clone(),
                        });
                    }
                    self_bound_capabilities.insert(binding.capability.as_str());
                }
                LocalComponentRef::Child(name) => {
                    if !self.components.contains_key(name) {
                        return Err(Error::UnknownBindingChild {
                            child: name.clone(),
                        });
                    }
                }
            }
        }

        let mut available: BTreeSet<&String> = self.provides.keys().collect();
        available.extend(self.slots.keys());

        for name in &self.exports {
            if !available.contains(name) {
                return Err(Error::UnknownExport { name: name.clone() });
            }
        }

        for name in self.slots.keys() {
            if !self.exports.contains(name) && !self_bound_slots.contains(name.as_str()) {
                return Err(Error::UnusedSlot { name: name.clone() });
            }
        }

        for name in self.provides.keys() {
            if !self.exports.contains(name) && !self_bound_capabilities.contains(name.as_str()) {
                return Err(Error::UnusedProvide { name: name.clone() });
            }
        }

        let mut defined_endpoints = BTreeSet::new();
        if let Some(program) = &self.program
            && let Some(network) = &program.network
        {
            for endpoint in &network.endpoints {
                if !defined_endpoints.insert(endpoint.name.as_str()) {
                    return Err(Error::DuplicateEndpointName {
                        name: endpoint.name.clone(),
                    });
                }
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
        Self::from_str("{manifest_version:\"1.0.0\"}").unwrap()
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
