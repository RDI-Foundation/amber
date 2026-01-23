#![allow(unused_assignments)]

mod config_schema_profile;
mod document;
pub mod framework;
pub mod lint;
mod spans;
#[cfg(test)]
mod tests;

use std::{
    borrow::Borrow,
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    hash::{Hash, Hasher},
    io::{self, Write},
    str::FromStr,
    sync::{Arc, OnceLock},
};

use amber_json5::DiagnosticError;
use base64::Engine;
pub use document::{ManifestDocError, ParsedManifest};
pub use framework::{
    FrameworkBindingShape, FrameworkCapabilitySpec, framework_capabilities, framework_capability,
};
use miette::Diagnostic;
use semver::{Version, VersionReq};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use serde_with::{
    DefaultOnNull, DeserializeFromStr, MapPreventDuplicates, SerializeDisplay, serde_as,
};
use sha2::Digest as _;
pub use spans::{
    BindingSpans, BindingTargetKey, CapabilityDeclSpans, ComponentDeclSpans, EndpointSpans,
    EnvironmentSpans, ExportSpans, ManifestSpans, ProgramSpans, ProvideDeclSpans,
    span_for_json_pointer,
};
use thiserror::Error;
use url::{ParseError, Url};

#[allow(unused_assignments)]
#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum Error {
    #[error("{0}")]
    #[diagnostic(code(manifest::json5_error))]
    Json5(DiagnosticError),

    #[error("{0}")]
    #[diagnostic(code(manifest::deserialize_error))]
    Json5Path(DiagnosticError),

    #[error("io error: {0}")]
    #[diagnostic(code(manifest::io_error))]
    Io(#[from] std::io::Error),

    #[error("invalid manifest reference `{0}`")]
    #[diagnostic(code(manifest::invalid_reference))]
    InvalidManifestRef(String),

    #[error("invalid manifest digest `{0}`")]
    #[diagnostic(code(manifest::invalid_digest))]
    InvalidManifestDigest(String),

    #[error("invalid interpolation `{0}`")]
    #[diagnostic(code(manifest::invalid_interpolation))]
    InvalidInterpolation(String),

    #[error("invalid component ref `{input}`: {message}")]
    #[diagnostic(code(manifest::invalid_component_ref))]
    InvalidComponentRef { input: String, message: String },

    #[error("invalid binding `{input}`: {message}")]
    #[diagnostic(code(manifest::invalid_binding))]
    InvalidBinding { input: String, message: String },

    #[error("binding mixes dot form with `slot`/`capability`")]
    #[diagnostic(
        code(manifest::mixed_binding_form),
        help("Use either dot form or explicit `slot`/`capability` fields.")
    )]
    MixedBindingForm { to: String, from: String },

    #[error("invalid export target `{input}`: {message}")]
    #[diagnostic(code(manifest::invalid_export_target))]
    InvalidExportTarget { input: String, message: String },

    #[error("invalid {kind} name `{name}`: dots are reserved")]
    #[diagnostic(code(manifest::invalid_name))]
    InvalidName { kind: &'static str, name: String },

    #[error("unclosed quote in args string")]
    #[diagnostic(code(manifest::unclosed_quote))]
    UnclosedQuote,

    #[error(
        "program.entrypoint must be non-empty (implicit image entrypoints are unsupported; set \
         `program.entrypoint`/`program.args` to an explicit command)"
    )]
    #[diagnostic(code(manifest::empty_entrypoint))]
    EmptyEntrypoint,

    #[error("export `{export}` references unknown capability `{target}`")]
    #[diagnostic(code(manifest::unknown_export_target))]
    UnknownExportTarget { export: String, target: String },

    #[error("export `{export}` references unknown child `#{child}`")]
    #[diagnostic(code(manifest::unknown_export_child))]
    UnknownExportChild { export: String, child: String },

    #[error("capability `{name}` cannot be declared as both slot and provide")]
    #[diagnostic(code(manifest::ambiguous_capability_name))]
    AmbiguousCapabilityName { name: String },

    #[error("binding target `{to}.{slot}` is bound more than once")]
    #[diagnostic(code(manifest::duplicate_binding_target))]
    DuplicateBindingTarget { to: String, slot: String },

    #[error("binding name `{name}` is used more than once")]
    #[diagnostic(code(manifest::duplicate_binding_name))]
    DuplicateBindingName { name: String },

    #[error("binding references unknown child `#{child}`")]
    #[diagnostic(code(manifest::unknown_binding_child))]
    UnknownBindingChild { child: String },

    #[error("binding target `self.{slot}` references unknown slot")]
    #[diagnostic(code(manifest::unknown_binding_slot))]
    UnknownBindingSlot { slot: String },

    #[error("binding source `self.{capability}` references unknown provide")]
    #[diagnostic(code(manifest::unknown_binding_provide))]
    UnknownBindingProvide { capability: String },

    #[error("unknown framework capability `{capability}`")]
    #[diagnostic(code(manifest::unknown_framework_capability), help("{help}"))]
    UnknownFrameworkCapability { capability: String, help: String },

    #[error("duplicate endpoint name `{name}`")]
    #[diagnostic(code(manifest::duplicate_endpoint_name))]
    DuplicateEndpointName { name: String },

    #[error("unknown endpoint `{name}` referenced")]
    #[diagnostic(code(manifest::unknown_endpoint))]
    UnknownEndpoint { name: String },

    #[error("provide `{name}` must declare an endpoint")]
    #[diagnostic(code(manifest::missing_provide_endpoint))]
    MissingProvideEndpoint { name: String },

    #[error("invalid config definition: {0}")]
    #[diagnostic(code(manifest::invalid_config_schema))]
    InvalidConfigSchema(String),

    #[error("unsupported manifest version `{version}` (supported: {supported_req})")]
    #[diagnostic(code(manifest::unsupported_version))]
    UnsupportedManifestVersion {
        version: Version,
        supported_req: &'static str,
    },

    // --- Environments (resolution environments) ---
    #[error("environment `{name}` extends unknown environment `{extends}`")]
    #[diagnostic(code(manifest::unknown_environment_extends))]
    UnknownEnvironmentExtends { name: String, extends: String },

    #[error("environment `{name}` has a cycle in `extends`")]
    #[diagnostic(code(manifest::environment_cycle))]
    EnvironmentCycle { name: String },

    #[error("component `#{child}` references unknown environment `{environment}`")]
    #[diagnostic(code(manifest::unknown_component_environment))]
    UnknownComponentEnvironment { child: String, environment: String },
}

macro_rules! name_type {
    ($name:ident, $kind:expr) => {
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Arc<str>);

        impl $name {
            pub fn new(name: String) -> Result<Self, Error> {
                ensure_name_no_dot(&name, $kind)?;
                Ok(Self(Arc::from(name)))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = Error;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = Error;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                ensure_name_no_dot(value, $kind)?;
                Ok(Self(Arc::from(value)))
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0.to_string()
            }
        }

        impl From<&$name> for String {
            fn from(value: &$name) -> Self {
                value.0.to_string()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl Borrow<str> for $name {
            fn borrow(&self) -> &str {
                &self.0
            }
        }
    };
}

name_type!(ChildName, "child");
name_type!(SlotName, "slot");
name_type!(ProvideName, "provide");
name_type!(ExportName, "export");
name_type!(BindingName, "binding");
name_type!(FrameworkCapabilityName, "framework capability");

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

    fn digest(manifest: &RawManifest) -> Self {
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

impl InterpolatedString {
    /// Visit slot names referenced by `${slots...}` interpolations.
    ///
    /// The visited slot name is the first query segment (e.g. `${slots.llm.url}` visits `llm`).
    /// Returns `true` if the interpolation references all slots (e.g. `${slots}`).
    pub fn visit_slot_uses(&self, mut visit: impl FnMut(&str)) -> bool {
        for part in &self.parts {
            let InterpolatedPart::Interpolation { source, query } = part else {
                continue;
            };
            if *source != InterpolationSource::Slots {
                continue;
            }
            if query.is_empty() {
                return true;
            }
            let slot = query
                .split_once('.')
                .map_or(query.as_str(), |(first, _)| first);
            if slot.is_empty() {
                return false;
            }
            visit(slot);
        }
        false
    }
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

        let (prefix, query) = inner
            .split_once('.')
            .map_or((inner, ""), |(prefix, query)| (prefix, query));

        let source = match prefix {
            "config" => InterpolationSource::Config,
            "slots" => InterpolationSource::Slots,
            "bindings" => InterpolationSource::Bindings,
            _ => return Err(Error::InvalidInterpolation(inner.to_string())),
        };

        Ok(InterpolatedPart::Interpolation {
            source,
            query: query.to_string(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum InterpolationSource {
    Config,
    Slots,
    Bindings,
}

impl fmt::Display for InterpolationSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            InterpolationSource::Config => "config",
            InterpolationSource::Slots => "slots",
            InterpolationSource::Bindings => "bindings",
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
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Program {
    pub image: String,
    #[serde(default, alias = "entrypoint")]
    pub args: ProgramArgs,
    #[serde_as(as = "MapPreventDuplicates<_, _>")]
    #[serde(default)]
    pub env: BTreeMap<String, InterpolatedString>,
    #[serde(default)]
    pub network: Option<Network>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Endpoint {
    pub name: String,
    // TODO: this should be an enum tagged by `NetworkProtocol` and carrying appropriate data for the protocol
    pub port: u16,
    #[serde(default = "default_protocol")]
    pub protocol: NetworkProtocol,
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
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CapabilityDecl {
    pub kind: CapabilityKind,
    #[serde(default)]
    pub profile: Option<String>,
}

impl fmt::Display for CapabilityDecl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        if let Some(profile) = &self.profile {
            write!(f, " (profile \"{profile}\")")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, DeserializeFromStr, SerializeDisplay,
)]
#[non_exhaustive]
pub enum BindingSourceRef {
    Component(LocalComponentRef),
    Framework,
}

impl fmt::Display for BindingSourceRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Component(component) => component.fmt(f),
            Self::Framework => f.write_str("framework"),
        }
    }
}

impl FromStr for BindingSourceRef {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_binding_source_ref(input)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, DeserializeFromStr, SerializeDisplay)]
#[non_exhaustive]
pub struct RawExportTarget {
    pub component: LocalComponentRef,
    pub name: String,
}

impl RawExportTarget {
    pub fn is_self(&self) -> bool {
        self.component.is_self()
    }
}

impl fmt::Display for RawExportTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.component {
            LocalComponentRef::Self_ => {
                f.write_str("self.")?;
                f.write_str(&self.name)
            }
            LocalComponentRef::Child(child) => {
                f.write_str("#")?;
                f.write_str(child)?;
                f.write_str(".")?;
                f.write_str(&self.name)
            }
        }
    }
}

impl FromStr for RawExportTarget {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.is_empty() {
            return Err(Error::InvalidExportTarget {
                input: input.to_string(),
                message: "export target cannot be empty".to_string(),
            });
        }
        if input == "framework" || input.starts_with("framework.") {
            return Err(Error::InvalidExportTarget {
                input: input.to_string(),
                message: "framework is only valid as a binding source".to_string(),
            });
        }

        match input.split_once('.') {
            None => {
                ensure_name_no_dot(input, "export target")?;
                Ok(Self {
                    component: LocalComponentRef::Self_,
                    name: input.to_string(),
                })
            }
            Some((left, right)) => {
                if left.is_empty() || right.is_empty() {
                    return Err(Error::InvalidExportTarget {
                        input: input.to_string(),
                        message: "expected `<component-ref>.<name>`".to_string(),
                    });
                }
                let component =
                    parse_component_ref(left).map_err(|err| Error::InvalidExportTarget {
                        input: input.to_string(),
                        message: err.message,
                    })?;
                ensure_name_no_dot(right, "export target")?;
                Ok(Self {
                    component,
                    name: right.to_string(),
                })
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ProvideDecl {
    #[serde(flatten)]
    pub decl: CapabilityDecl,
    #[serde(default)]
    pub endpoint: Option<String>,
}

/// A named resolution environment, used to resolve child manifests.
///
/// The compiler interprets the resolver names here via an external registry (provided by the host).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct EnvironmentDecl {
    /// Optional base environment to extend (within the same manifest).
    #[serde(default)]
    pub extends: Option<String>,
    /// Names of resolvers to add (interpreted by the host/compiler).
    #[serde(default)]
    pub resolvers: Vec<String>,
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

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ComponentRef {
    pub manifest: ManifestRef,
    #[serde(default)]
    #[serde_as(deserialize_as = "DefaultOnNull")]
    pub config: Option<Value>,
    /// Optional resolution environment name (defined in the *parent* manifest's `environments`).
    #[serde(default)]
    pub environment: Option<String>,
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
        config_schema_profile::validate(&value)
            .map_err(|e| serde::de::Error::custom(Error::InvalidConfigSchema(e)))?;
        Ok(ConfigSchema(value))
    }
}

#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
/// A binding wires a target slot to a source provide.
pub struct RawBinding {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub to: LocalComponentRef,
    pub slot: String,
    pub from: BindingSourceRef,
    pub capability: String,
    /// If true, this binding does not participate in dependency ordering or cycle detection.
    #[serde(default)]
    pub weak: bool,
    #[serde(skip)]
    mixed_form: bool,
    #[serde(skip)]
    raw_to: Option<String>,
    #[serde(skip)]
    raw_from: Option<String>,
}

impl PartialEq for RawBinding {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.to == other.to
            && self.slot == other.slot
            && self.from == other.from
            && self.capability == other.capability
            && self.weak == other.weak
    }
}

impl Eq for RawBinding {}

impl PartialOrd for RawBinding {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RawBinding {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            &self.name,
            &self.to,
            &self.slot,
            &self.from,
            &self.capability,
            &self.weak,
        )
            .cmp(&(
                &other.name,
                &other.to,
                &other.slot,
                &other.from,
                &other.capability,
                &other.weak,
            ))
    }
}

impl Hash for RawBinding {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.to.hash(state);
        self.slot.hash(state);
        self.from.hash(state);
        self.capability.hash(state);
        self.weak.hash(state);
    }
}

impl<'de> Deserialize<'de> for RawBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct BindingInput {
            #[serde(default)]
            name: Option<String>,
            #[serde(default)]
            to: Option<String>,
            #[serde(default)]
            slot: Option<String>,
            #[serde(default)]
            from: Option<String>,
            #[serde(default)]
            capability: Option<String>,
            #[serde(default)]
            weak: bool,
        }

        let BindingInput {
            name,
            to,
            slot,
            from,
            capability,
            weak,
        } = BindingInput::deserialize(deserializer)?;

        let to =
            to.ok_or_else(|| serde::de::Error::custom("binding is missing required field `to`"))?;
        let from = from
            .ok_or_else(|| serde::de::Error::custom("binding is missing required field `from`"))?;

        match (slot, capability) {
            (Some(slot), Some(capability)) => {
                if to.contains('.') || from.contains('.') {
                    return Ok(RawBinding {
                        name,
                        to: LocalComponentRef::Self_,
                        slot,
                        from: BindingSourceRef::Component(LocalComponentRef::Self_),
                        capability,
                        weak,
                        mixed_form: true,
                        raw_to: Some(to),
                        raw_from: Some(from),
                    });
                }
                ensure_binding_name_no_dot(&slot, slot.as_str())
                    .map_err(serde::de::Error::custom)?;
                ensure_binding_name_no_dot(&capability, capability.as_str())
                    .map_err(serde::de::Error::custom)?;
                Ok(RawBinding {
                    name,
                    to: parse_binding_target_ref(&to).map_err(serde::de::Error::custom)?,
                    slot,
                    from: parse_binding_source_ref(&from).map_err(serde::de::Error::custom)?,
                    capability,
                    weak,
                    mixed_form: false,
                    raw_to: None,
                    raw_from: None,
                })
            }
            (None, None) => {
                let (to, slot) = split_binding_target(&to).map_err(serde::de::Error::custom)?;
                let (from, capability) =
                    split_binding_source(&from).map_err(serde::de::Error::custom)?;
                Ok(RawBinding {
                    name,
                    to,
                    slot,
                    from,
                    capability,
                    weak,
                    mixed_form: false,
                    raw_to: None,
                    raw_from: None,
                })
            }
            (Some(_), None) => Err(serde::de::Error::custom(
                "binding has `slot` but is missing `capability` (either add `capability`, or use \
                 dot form `to: \"<component-ref>.<slot>\", from: \"<component-ref>.<provide>\"`)",
            )),
            (None, Some(_)) => Err(serde::de::Error::custom(
                "binding has `capability` but is missing `slot` (either add `slot`, or use dot \
                 form `to: \"<component-ref>.<slot>\", from: \"<component-ref>.<provide>\"`)",
            )),
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

fn binding_target_key_for_component_ref(
    component: &LocalComponentRef,
    slot: &str,
) -> BindingTargetKey {
    match component {
        LocalComponentRef::Self_ => BindingTargetKey::SelfSlot(slot.into()),
        LocalComponentRef::Child(child) => BindingTargetKey::ChildSlot {
            child: child.as_str().into(),
            slot: slot.into(),
        },
    }
}

pub(crate) fn binding_target_key_for_binding(
    to: &str,
    slot: Option<&str>,
) -> Option<BindingTargetKey> {
    if let Some(slot) = slot
        && let Ok(component) = parse_binding_target_ref(to)
    {
        return Some(binding_target_key_for_component_ref(&component, slot));
    }

    let (component, slot) = split_binding_target(to).ok()?;
    Some(binding_target_key_for_component_ref(&component, &slot))
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

fn is_framework_ref(input: &str) -> bool {
    input == "framework"
}

fn parse_binding_target_ref(input: &str) -> Result<LocalComponentRef, Error> {
    if is_framework_ref(input) {
        return Err(Error::InvalidBinding {
            input: input.to_string(),
            message: "framework cannot be a binding target".to_string(),
        });
    }
    parse_component_ref(input).map_err(|err| Error::InvalidBinding {
        input: err.input,
        message: err.message,
    })
}

fn parse_binding_source_ref(input: &str) -> Result<BindingSourceRef, Error> {
    if is_framework_ref(input) {
        return Ok(BindingSourceRef::Framework);
    }
    let component = parse_component_ref(input).map_err(|err| Error::InvalidBinding {
        input: err.input,
        message: err.message,
    })?;
    Ok(BindingSourceRef::Component(component))
}

fn split_binding_target(input: &str) -> Result<(LocalComponentRef, String), Error> {
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

    let component = parse_binding_target_ref(left)?;
    ensure_binding_name_no_dot(right, input)?;
    Ok((component, right.to_string()))
}

fn split_binding_source(input: &str) -> Result<(BindingSourceRef, String), Error> {
    let Some((left, right)) = input.split_once('.') else {
        return Err(Error::InvalidBinding {
            input: input.to_string(),
            message: "expected `<source-ref>.<name>`".to_string(),
        });
    };

    if left.is_empty() || right.is_empty() {
        return Err(Error::InvalidBinding {
            input: input.to_string(),
            message: "expected `<source-ref>.<name>`".to_string(),
        });
    }

    let source = parse_binding_source_ref(left)?;
    ensure_binding_name_no_dot(right, input)?;
    Ok((source, right.to_string()))
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ExportTarget {
    SelfProvide(ProvideName),
    ChildExport {
        child: ChildName,
        export: ExportName,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum BindingTarget {
    SelfSlot(SlotName),
    ChildSlot { child: ChildName, slot: SlotName },
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum BindingSource {
    SelfProvide(ProvideName),
    ChildExport {
        child: ChildName,
        export: ExportName,
    },
    Framework(FrameworkCapabilityName),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Binding {
    pub name: Option<BindingName>,
    pub from: BindingSource,
    pub weak: bool,
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RawManifest {
    pub manifest_version: Version,
    #[serde(default)]
    pub program: Option<Program>,
    #[serde_as(as = "MapPreventDuplicates<_, _>")]
    #[serde(default)]
    pub components: BTreeMap<String, ComponentDecl>,

    /// Optional named resolution environments for resolving child manifests.
    #[serde_as(as = "MapPreventDuplicates<_, _>")]
    #[serde(default)]
    pub environments: BTreeMap<String, EnvironmentDecl>,

    #[serde(default)]
    pub config_schema: Option<ConfigSchema>,
    #[serde_as(as = "MapPreventDuplicates<_, _>")]
    #[serde(default)]
    pub slots: BTreeMap<String, SlotDecl>,
    #[serde_as(as = "MapPreventDuplicates<_, _>")]
    #[serde(default)]
    pub provides: BTreeMap<String, ProvideDecl>,
    #[serde(default)]
    pub bindings: BTreeSet<RawBinding>,
    #[serde_as(as = "MapPreventDuplicates<_, _>")]
    #[serde(default)]
    pub exports: BTreeMap<String, RawExportTarget>,
}

const SUPPORTED_MANIFEST_VERSION_REQ: &str = "^0.1.0";

fn supported_manifest_version_req() -> &'static VersionReq {
    static REQ: OnceLock<VersionReq> = OnceLock::new();
    REQ.get_or_init(|| {
        VersionReq::parse(SUPPORTED_MANIFEST_VERSION_REQ)
            .expect("supported manifest version requirement must be valid")
    })
}

struct ValidateCtx<'a> {
    components: &'a BTreeMap<ChildName, ComponentDecl>,
    slots: &'a BTreeMap<SlotName, SlotDecl>,
    provides: &'a BTreeMap<ProvideName, ProvideDecl>,
}

fn validate_environment_names(
    environments: &BTreeMap<String, EnvironmentDecl>,
) -> Result<(), Error> {
    for name in environments.keys() {
        ensure_name_no_dot(name, "environment")?;
    }
    Ok(())
}

fn convert_components(
    components: BTreeMap<String, ComponentDecl>,
) -> Result<BTreeMap<ChildName, ComponentDecl>, Error> {
    components
        .into_iter()
        .map(|(name, decl)| Ok((ChildName::try_from(name)?, decl)))
        .collect::<Result<BTreeMap<_, _>, Error>>()
}

fn convert_slots(slots: BTreeMap<String, SlotDecl>) -> Result<BTreeMap<SlotName, SlotDecl>, Error> {
    slots
        .into_iter()
        .map(|(name, decl)| Ok((SlotName::try_from(name)?, decl)))
        .collect::<Result<BTreeMap<_, _>, Error>>()
}

fn convert_provides(
    provides: BTreeMap<String, ProvideDecl>,
) -> Result<BTreeMap<ProvideName, ProvideDecl>, Error> {
    provides
        .into_iter()
        .map(|(name, decl)| Ok((ProvideName::try_from(name)?, decl)))
        .collect::<Result<BTreeMap<_, _>, Error>>()
}

fn validate_environment_extends(
    environments: &BTreeMap<String, EnvironmentDecl>,
) -> Result<(), Error> {
    for (env_name, env) in environments {
        if let Some(ext) = env.extends.as_deref()
            && !environments.contains_key(ext)
        {
            return Err(Error::UnknownEnvironmentExtends {
                name: env_name.clone(),
                extends: ext.to_string(),
            });
        }
    }
    Ok(())
}

fn validate_environment_cycles(
    environments: &BTreeMap<String, EnvironmentDecl>,
) -> Result<(), Error> {
    let mut state: HashMap<String, u8> = HashMap::new(); // 0/none=unvisited, 1=visiting, 2=done
    fn dfs(
        name: &str,
        envs: &BTreeMap<String, EnvironmentDecl>,
        state: &mut HashMap<String, u8>,
    ) -> Result<(), Error> {
        match state.get(name).copied() {
            Some(1) => {
                return Err(Error::EnvironmentCycle {
                    name: name.to_string(),
                });
            }
            Some(2) => return Ok(()),
            _ => {}
        }

        state.insert(name.to_string(), 1);
        if let Some(ext) = envs.get(name).and_then(|e| e.extends.as_deref()) {
            dfs(ext, envs, state)?;
        }
        state.insert(name.to_string(), 2);
        Ok(())
    }

    for name in environments.keys() {
        dfs(name, environments, &mut state)?;
    }
    Ok(())
}

fn validate_component_environments(
    components: &BTreeMap<ChildName, ComponentDecl>,
    environments: &BTreeMap<String, EnvironmentDecl>,
) -> Result<(), Error> {
    for (child_name, decl) in components {
        if let ComponentDecl::Object(obj) = decl
            && let Some(env) = obj.environment.as_deref()
            && !environments.contains_key(env)
        {
            return Err(Error::UnknownComponentEnvironment {
                child: child_name.to_string(),
                environment: env.to_string(),
            });
        }
    }
    Ok(())
}

fn validate_no_ambiguous_capability(
    slots: &BTreeMap<SlotName, SlotDecl>,
    provides: &BTreeMap<ProvideName, ProvideDecl>,
) -> Result<(), Error> {
    if let Some(name) = slots
        .keys()
        .find(|name| provides.contains_key(name.as_str()))
    {
        return Err(Error::AmbiguousCapabilityName {
            name: name.to_string(),
        });
    }
    Ok(())
}

fn resolve_binding_target(
    ctx: &ValidateCtx<'_>,
    to: LocalComponentRef,
    slot: String,
) -> Result<BindingTarget, Error> {
    match to {
        LocalComponentRef::Self_ => {
            let (slot_name, _) = ctx
                .slots
                .get_key_value(slot.as_str())
                .ok_or_else(|| Error::UnknownBindingSlot { slot })?;
            Ok(BindingTarget::SelfSlot(slot_name.clone()))
        }
        LocalComponentRef::Child(child) => {
            let (child_name, _) = ctx
                .components
                .get_key_value(child.as_str())
                .ok_or_else(|| Error::UnknownBindingChild { child })?;
            let slot_name = SlotName::try_from(slot)?;
            Ok(BindingTarget::ChildSlot {
                child: child_name.clone(),
                slot: slot_name,
            })
        }
    }
}

fn framework_capability_help() -> String {
    let caps = framework_capabilities();
    if caps.is_empty() {
        return "framework exposes no capabilities yet".to_string();
    }
    let names = caps
        .iter()
        .take(20)
        .map(|cap| cap.name.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!("Known framework capabilities: {names}")
}

fn resolve_binding_source(
    ctx: &ValidateCtx<'_>,
    from: BindingSourceRef,
    capability: String,
) -> Result<BindingSource, Error> {
    match from {
        BindingSourceRef::Component(LocalComponentRef::Self_) => {
            let (provide_name, _) = ctx
                .provides
                .get_key_value(capability.as_str())
                .ok_or_else(|| Error::UnknownBindingProvide { capability })?;
            Ok(BindingSource::SelfProvide(provide_name.clone()))
        }
        BindingSourceRef::Component(LocalComponentRef::Child(child)) => {
            let (child_name, _) = ctx
                .components
                .get_key_value(child.as_str())
                .ok_or_else(|| Error::UnknownBindingChild { child })?;
            let export = ExportName::try_from(capability)?;
            Ok(BindingSource::ChildExport {
                child: child_name.clone(),
                export,
            })
        }
        BindingSourceRef::Framework => {
            let Some(spec) = framework_capability(capability.as_str()) else {
                return Err(Error::UnknownFrameworkCapability {
                    capability,
                    help: framework_capability_help(),
                });
            };
            Ok(BindingSource::Framework(spec.name.clone()))
        }
    }
}

fn build_bindings(
    bindings: BTreeSet<RawBinding>,
    ctx: &ValidateCtx<'_>,
) -> Result<BTreeMap<BindingTarget, Binding>, Error> {
    let mut bindings_out = BTreeMap::new();
    let mut binding_names = BTreeSet::new();

    for binding in bindings {
        let RawBinding {
            name,
            to,
            slot,
            from,
            capability,
            weak,
            mixed_form,
            raw_to,
            raw_from,
        } = binding;

        if mixed_form {
            return Err(Error::MixedBindingForm {
                to: raw_to.unwrap_or_else(|| to.to_string()),
                from: raw_from.unwrap_or_else(|| from.to_string()),
            });
        }

        let name = match name {
            Some(name) => {
                let name = BindingName::try_from(name)?;
                if !binding_names.insert(name.clone()) {
                    return Err(Error::DuplicateBindingName {
                        name: name.to_string(),
                    });
                }
                Some(name)
            }
            None => None,
        };

        let target = resolve_binding_target(ctx, to, slot)?;
        let source = resolve_binding_source(ctx, from, capability)?;

        if bindings_out.contains_key(&target) {
            let to = match &target {
                BindingTarget::SelfSlot(_) => "self".to_string(),
                BindingTarget::ChildSlot { child, .. } => format!("#{child}"),
            };
            let slot = match &target {
                BindingTarget::SelfSlot(name) => name.to_string(),
                BindingTarget::ChildSlot { slot, .. } => slot.to_string(),
            };
            return Err(Error::DuplicateBindingTarget { to, slot });
        }

        bindings_out.insert(
            target,
            Binding {
                name,
                from: source,
                weak,
            },
        );
    }

    Ok(bindings_out)
}

fn resolve_export_target(
    ctx: &ValidateCtx<'_>,
    export_name: &ExportName,
    target: RawExportTarget,
) -> Result<ExportTarget, Error> {
    match target.component {
        LocalComponentRef::Self_ => {
            if let Some((provide_name, _)) = ctx.provides.get_key_value(target.name.as_str()) {
                Ok(ExportTarget::SelfProvide(provide_name.clone()))
            } else {
                Err(Error::UnknownExportTarget {
                    export: export_name.to_string(),
                    target: target.name,
                })
            }
        }
        LocalComponentRef::Child(child) => {
            let (child_name, _) =
                ctx.components
                    .get_key_value(child.as_str())
                    .ok_or_else(|| Error::UnknownExportChild {
                        export: export_name.to_string(),
                        child,
                    })?;
            let export = ExportName::try_from(target.name)?;
            Ok(ExportTarget::ChildExport {
                child: child_name.clone(),
                export,
            })
        }
    }
}

fn build_exports(
    exports: BTreeMap<String, RawExportTarget>,
    ctx: &ValidateCtx<'_>,
) -> Result<BTreeMap<ExportName, ExportTarget>, Error> {
    let mut exports_out = BTreeMap::new();

    for (export, target) in exports {
        let export_name = ExportName::try_from(export)?;
        let target = resolve_export_target(ctx, &export_name, target)?;
        exports_out.insert(export_name, target);
    }

    Ok(exports_out)
}

fn validate_endpoints(
    program: Option<&Program>,
    provides: &BTreeMap<ProvideName, ProvideDecl>,
) -> Result<(), Error> {
    let mut defined_endpoints = BTreeSet::new();
    if let Some(program) = program
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

    for (provide_name, provide) in provides {
        let Some(endpoint) = provide.endpoint.as_deref() else {
            return Err(Error::MissingProvideEndpoint {
                name: provide_name.to_string(),
            });
        };

        if !defined_endpoints.contains(endpoint) {
            return Err(Error::UnknownEndpoint {
                name: endpoint.to_string(),
            });
        }
    }

    Ok(())
}

impl RawManifest {
    fn digest(&self) -> ManifestDigest {
        ManifestDigest::digest(self)
    }

    fn validate_version(&self) -> Result<(), Error> {
        let req = supported_manifest_version_req();
        if !req.matches(&self.manifest_version) {
            return Err(Error::UnsupportedManifestVersion {
                version: self.manifest_version.clone(),
                supported_req: SUPPORTED_MANIFEST_VERSION_REQ,
            });
        }
        Ok(())
    }

    pub fn validate(self) -> Result<Manifest, Error> {
        self.validate_version()?;
        let digest = self.digest();

        let RawManifest {
            manifest_version,
            program,
            components,
            environments,
            config_schema,
            slots,
            provides,
            bindings,
            exports,
        } = self;

        validate_environment_names(&environments)?;

        let components = convert_components(components)?;
        let slots = convert_slots(slots)?;
        let provides = convert_provides(provides)?;

        validate_environment_extends(&environments)?;
        validate_environment_cycles(&environments)?;
        validate_component_environments(&components, &environments)?;
        validate_no_ambiguous_capability(&slots, &provides)?;

        let ctx = ValidateCtx {
            components: &components,
            slots: &slots,
            provides: &provides,
        };

        let bindings_out = build_bindings(bindings, &ctx)?;
        let exports_out = build_exports(exports, &ctx)?;
        validate_endpoints(program.as_ref(), &provides)?;

        if let Some(program) = program.as_ref()
            && program.args.0.is_empty()
        {
            return Err(Error::EmptyEntrypoint);
        }

        Ok(Manifest {
            manifest_version,
            program,
            components,
            environments,
            config_schema,
            slots,
            provides,
            bindings: bindings_out,
            exports: exports_out,
            digest,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "RawManifest", try_from = "RawManifest")]
pub struct Manifest {
    manifest_version: Version,
    program: Option<Program>,
    components: BTreeMap<ChildName, ComponentDecl>,
    environments: BTreeMap<String, EnvironmentDecl>,
    config_schema: Option<ConfigSchema>,
    slots: BTreeMap<SlotName, SlotDecl>,
    provides: BTreeMap<ProvideName, ProvideDecl>,
    bindings: BTreeMap<BindingTarget, Binding>,
    exports: BTreeMap<ExportName, ExportTarget>,
    digest: ManifestDigest,
}

impl Manifest {
    pub fn manifest_version(&self) -> &Version {
        &self.manifest_version
    }

    pub fn program(&self) -> Option<&Program> {
        self.program.as_ref()
    }

    pub fn components(&self) -> &BTreeMap<ChildName, ComponentDecl> {
        &self.components
    }

    pub fn environments(&self) -> &BTreeMap<String, EnvironmentDecl> {
        &self.environments
    }

    pub fn config_schema(&self) -> Option<&ConfigSchema> {
        self.config_schema.as_ref()
    }

    pub fn slots(&self) -> &BTreeMap<SlotName, SlotDecl> {
        &self.slots
    }

    pub fn provides(&self) -> &BTreeMap<ProvideName, ProvideDecl> {
        &self.provides
    }

    pub fn bindings(&self) -> &BTreeMap<BindingTarget, Binding> {
        &self.bindings
    }

    pub fn exports(&self) -> &BTreeMap<ExportName, ExportTarget> {
        &self.exports
    }

    pub fn empty() -> Self {
        RawManifest {
            manifest_version: Version::new(0, 1, 0),
            program: None,
            components: BTreeMap::new(),
            environments: BTreeMap::new(),
            config_schema: None,
            slots: BTreeMap::new(),
            provides: BTreeMap::new(),
            bindings: BTreeSet::new(),
            exports: BTreeMap::new(),
        }
        .validate()
        .expect("empty manifest is valid")
    }

    pub fn digest(&self) -> ManifestDigest {
        self.digest
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
        RawManifest::from(&manifest)
    }
}

impl From<&Manifest> for RawManifest {
    fn from(manifest: &Manifest) -> Self {
        let components = manifest
            .components
            .iter()
            .map(|(name, decl)| (name.to_string(), decl.clone()))
            .collect();

        let slots = manifest
            .slots
            .iter()
            .map(|(name, decl)| (name.to_string(), decl.clone()))
            .collect();

        let provides = manifest
            .provides
            .iter()
            .map(|(name, decl)| (name.to_string(), decl.clone()))
            .collect();

        let bindings = manifest
            .bindings
            .iter()
            .map(|(target, binding)| {
                let (to, slot) = match target {
                    BindingTarget::SelfSlot(name) => (LocalComponentRef::Self_, name.to_string()),
                    BindingTarget::ChildSlot { child, slot } => (
                        LocalComponentRef::Child(child.to_string()),
                        slot.to_string(),
                    ),
                };

                let (from, capability) = match &binding.from {
                    BindingSource::SelfProvide(name) => (
                        BindingSourceRef::Component(LocalComponentRef::Self_),
                        name.to_string(),
                    ),
                    BindingSource::ChildExport { child, export } => (
                        BindingSourceRef::Component(LocalComponentRef::Child(child.to_string())),
                        export.to_string(),
                    ),
                    BindingSource::Framework(name) => {
                        (BindingSourceRef::Framework, name.to_string())
                    }
                };

                RawBinding {
                    name: binding.name.as_ref().map(ToString::to_string),
                    to,
                    slot,
                    from,
                    capability,
                    weak: binding.weak,
                    mixed_form: false,
                    raw_to: None,
                    raw_from: None,
                }
            })
            .collect();

        let exports = manifest
            .exports
            .iter()
            .map(|(name, target)| {
                let target = match target {
                    ExportTarget::SelfProvide(provide) => RawExportTarget {
                        component: LocalComponentRef::Self_,
                        name: provide.to_string(),
                    },
                    ExportTarget::ChildExport { child, export } => RawExportTarget {
                        component: LocalComponentRef::Child(child.to_string()),
                        name: export.to_string(),
                    },
                };

                (name.to_string(), target)
            })
            .collect();

        RawManifest {
            manifest_version: manifest.manifest_version.clone(),
            program: manifest.program.clone(),
            components,
            environments: manifest.environments.clone(),
            config_schema: manifest.config_schema.clone(),
            slots,
            provides,
            bindings,
            exports,
        }
    }
}

impl FromStr for Manifest {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let raw: RawManifest = amber_json5::parse(input).map_err(|e| match e.kind() {
            amber_json5::DiagnosticKind::Parse => Error::Json5(e),
            amber_json5::DiagnosticKind::Deserialize => Error::Json5Path(e),
        })?;
        raw.validate()
    }
}
