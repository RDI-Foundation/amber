use std::{
    cmp::Ordering,
    collections::BTreeMap,
    fmt,
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
    str::FromStr,
    sync::LazyLock,
};

use bon::bon;
use jsonptr::PointerBuf;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use serde_with::{
    DefaultOnNull, DeserializeFromStr, MapPreventDuplicates, SerializeDisplay, rust::double_option,
    serde_as,
};

use crate::{
    config_schema_profile,
    error::Error,
    interpolation::{
        InlineStringSpec, InterpolatedString, InterpolationSource, ProgramEntrypoint,
        ProgramEnvValue, RawProgramEntrypoint, RawProgramEnvValue,
    },
    names::{
        ChildName, ExportName, FrameworkCapabilityName, ProvideName, ResourceName, SlotName,
        ensure_name_no_dot,
    },
    refs::ManifestRef,
    spans::BindingTargetKey,
};
mod program;
pub use self::program::*;

#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    bon::Builder,
)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Network {
    #[serde(default)]
    #[builder(default)]
    pub endpoints: Vec<Endpoint>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, bon::Builder)]
#[builder(on(String, into))]
#[non_exhaustive]
pub struct Endpoint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<crate::WhenPath>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub each: Option<crate::EachPath>,
    pub name: InterpolatedString,
    pub port: EndpointPort,
    #[serde(default = "default_protocol_template")]
    #[builder(default = default_protocol_template())]
    pub protocol: InterpolatedString,
}

impl Endpoint {
    pub fn is_variadic(&self) -> bool {
        self.when.is_some() || self.each.is_some()
    }

    pub fn literal_name(&self) -> Option<&str> {
        self.name.as_literal()
    }

    pub fn literal_port(&self) -> Option<u16> {
        self.port.as_literal()
    }

    pub fn literal_protocol(&self) -> Option<NetworkProtocol> {
        self.protocol.as_literal()?.parse().ok()
    }

    pub fn visit_slot_uses(&self, mut visit: impl FnMut(&str)) -> bool {
        if let Some(when) = &self.when
            && when.visit_slot_uses(&mut visit)
        {
            return true;
        }
        if let Some(each) = &self.each {
            each.visit_slot_uses(&mut visit);
        }
        if self.name.visit_slot_uses(&mut visit) || self.protocol.visit_slot_uses(&mut visit) {
            return true;
        }
        self.port.visit_slot_uses(visit)
    }

    pub fn visit_config_uses(&self, mut visit: impl FnMut(&str)) {
        if let Some(when) = &self.when {
            when.visit_config_uses(&mut visit);
        }
        if let Some(each) = &self.each {
            each.visit_config_uses(&mut visit);
        }
        self.name.visit_config_uses(&mut visit);
        self.protocol.visit_config_uses(&mut visit);
        self.port.visit_config_uses(visit);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum NetworkProtocol {
    Http,
    Https,
    Tcp,
}

impl fmt::Display for NetworkProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            NetworkProtocol::Http => "http",
            NetworkProtocol::Https => "https",
            NetworkProtocol::Tcp => "tcp",
        };
        f.write_str(s)
    }
}

impl FromStr for NetworkProtocol {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "http" => Ok(Self::Http),
            "https" => Ok(Self::Https),
            "tcp" => Ok(Self::Tcp),
            other => Err(format!("unknown network protocol `{other}`")),
        }
    }
}

fn default_protocol() -> NetworkProtocol {
    NetworkProtocol::Http
}

fn default_protocol_template() -> InterpolatedString {
    InterpolatedString::from_literal(default_protocol().to_string())
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum EndpointPort {
    Literal(u16),
    Interpolated(InterpolatedString),
}

impl EndpointPort {
    pub fn as_literal(&self) -> Option<u16> {
        match self {
            Self::Literal(value) => Some(*value),
            Self::Interpolated(_) => None,
        }
    }

    pub fn visit_slot_uses(&self, visit: impl FnMut(&str)) -> bool {
        match self {
            Self::Literal(_) => false,
            Self::Interpolated(value) => value.visit_slot_uses(visit),
        }
    }

    pub fn visit_config_uses(&self, visit: impl FnMut(&str)) {
        if let Self::Interpolated(value) = self {
            value.visit_config_uses(visit);
        }
    }
}

impl fmt::Display for EndpointPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Literal(value) => write!(f, "{value}"),
            Self::Interpolated(value) => f.write_str(
                value
                    .as_literal()
                    .expect("interpolated endpoint port is not concrete here"),
            ),
        }
    }
}

impl Serialize for EndpointPort {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Literal(value) => serializer.serialize_u16(*value),
            Self::Interpolated(value) => value.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for EndpointPort {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum PortValue {
            Literal(u16),
            Interpolated(String),
        }

        match PortValue::deserialize(deserializer)? {
            PortValue::Literal(value) => Ok(Self::Literal(value)),
            PortValue::Interpolated(value) => value
                .parse::<InterpolatedString>()
                .map(Self::Interpolated)
                .map_err(serde::de::Error::custom),
        }
    }
}

impl<'de> Deserialize<'de> for Endpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct EndpointFields {
            #[serde(default)]
            when: Option<crate::WhenPath>,
            #[serde(default)]
            each: Option<crate::EachPath>,
            name: InterpolatedString,
            port: EndpointPort,
            #[serde(default = "default_protocol_template")]
            protocol: InterpolatedString,
        }

        let endpoint = EndpointFields::deserialize(deserializer)?;
        Ok(Self {
            when: endpoint.when,
            each: endpoint.each,
            name: endpoint.name,
            port: endpoint.port,
            protocol: endpoint.protocol,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum CapabilityKind {
    Mcp,
    Llm,
    Http,
    Component,
    Docker,
    A2a,
    Storage,
    Kvm,
}

impl fmt::Display for CapabilityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            CapabilityKind::Mcp => "mcp",
            CapabilityKind::Llm => "llm",
            CapabilityKind::Http => "http",
            CapabilityKind::Component => "component",
            CapabilityKind::Docker => "docker",
            CapabilityKind::A2a => "a2a",
            CapabilityKind::Storage => "storage",
            CapabilityKind::Kvm => "kvm",
        };
        f.write_str(s)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CapabilityTransport {
    Http,
    NonNetwork,
}

impl CapabilityKind {
    pub const fn transport(self) -> CapabilityTransport {
        match self {
            Self::Mcp | Self::Llm | Self::Http | Self::Component | Self::A2a => {
                CapabilityTransport::Http
            }
            Self::Docker | Self::Storage | Self::Kvm => CapabilityTransport::NonNetwork,
        }
    }
}

#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, bon::Builder,
)]
#[builder(on(String, into))]
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

#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, bon::Builder,
)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct SlotDecl {
    #[serde(flatten)]
    pub decl: CapabilityDecl,
    #[serde(default)]
    #[builder(default)]
    pub optional: bool,
    #[serde(default)]
    #[builder(default)]
    pub multiple: bool,
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
    Serialize,
    Deserialize,
    bon::Builder,
)]
#[builder(on(String, into))]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct StorageResourceParams {
    #[serde(default)]
    pub size: Option<InterpolatedString>,
    #[serde(default)]
    pub retention: Option<InterpolatedString>,
    #[serde(default)]
    pub sharing: Option<InterpolatedString>,
}

#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, bon::Builder,
)]
#[builder(on(String, into))]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ResourceDecl {
    pub kind: CapabilityKind,
    #[serde(default)]
    pub params: StorageResourceParams,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RuntimeBackend {
    Direct,
    Vm,
    Compose,
    Kubernetes,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub struct RealmSelector(String);

impl RealmSelector {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RealmSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for RealmSelector {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RealmSelector {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

impl FromStr for RealmSelector {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        fn parse_leaf(selector: &str, prefix: &str, kind: &'static str) -> Result<(), Error> {
            let Some(name) = selector.strip_prefix(prefix) else {
                return Err(Error::InvalidRealmSelector {
                    selector: selector.to_string(),
                    message: format!("expected prefix `{prefix}`"),
                });
            };
            if name.is_empty() {
                return Err(Error::InvalidRealmSelector {
                    selector: selector.to_string(),
                    message: "selector name must not be empty".to_string(),
                });
            }
            ensure_name_no_dot(name, kind)
        }

        if input.starts_with("slots.") {
            parse_leaf(input, "slots.", "slot")?;
            return Ok(Self(input.to_string()));
        }
        if input.starts_with("provides.") {
            parse_leaf(input, "provides.", "provide")?;
            return Ok(Self(input.to_string()));
        }
        if input.starts_with("resources.") {
            parse_leaf(input, "resources.", "resource")?;
            return Ok(Self(input.to_string()));
        }
        if input.starts_with("external.") {
            parse_leaf(input, "external.", "external binding")?;
            return Ok(Self(input.to_string()));
        }
        if let Some(rest) = input.strip_prefix("children.") {
            let Some((child, suffix)) = rest.split_once(".exports.") else {
                return Err(Error::InvalidRealmSelector {
                    selector: input.to_string(),
                    message: "expected `children.<child>.exports.<export>`".to_string(),
                });
            };
            ensure_name_no_dot(child, "child")?;
            ensure_name_no_dot(suffix, "export")?;
            return Ok(Self(input.to_string()));
        }

        Err(Error::InvalidRealmSelector {
            selector: input.to_string(),
            message: "expected `slots.<name>`, `provides.<name>`, `resources.<name>`, \
                      `external.<name>`, or `children.<child>.exports.<export>`"
                .to_string(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum ChildTemplateManifestDecl {
    One(ManifestRef),
    Many(Vec<ManifestRef>),
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, bon::Builder)]
#[builder(on(String, into))]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ChildTemplateLimitsDecl {
    #[serde(default)]
    pub max_live_children: Option<u32>,
    #[serde(default)]
    pub name_pattern: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, bon::Builder)]
#[builder(on(String, into))]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ChildTemplateDecl {
    #[serde(default)]
    pub manifest: Option<ChildTemplateManifestDecl>,
    #[serde(default)]
    pub config: BTreeMap<String, Value>,
    #[serde(default)]
    pub bindings: BTreeMap<String, RealmSelector>,
    #[serde(default)]
    pub visible_exports: Vec<String>,
    #[serde(default)]
    pub limits: Option<ChildTemplateLimitsDecl>,
    #[serde(default)]
    pub possible_backends: Vec<RuntimeBackend>,
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
    Slots,
    Provides,
    Framework,
    Resources,
}

impl fmt::Display for BindingSourceRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Component(component) => component.fmt(f),
            Self::Slots => f.write_str("slots"),
            Self::Provides => f.write_str("provides"),
            Self::Framework => f.write_str("framework"),
            Self::Resources => f.write_str("resources"),
        }
    }
}

impl FromStr for BindingSourceRef {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_binding_source_ref(input)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum LocalCapabilityRefKind {
    Slot,
    Provide,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, DeserializeFromStr, SerializeDisplay)]
#[non_exhaustive]
pub struct RawExportTarget {
    pub component: LocalComponentRef,
    pub name: String,
    pub(crate) local_kind: Option<LocalCapabilityRefKind>,
}

impl RawExportTarget {
    pub fn is_self(&self) -> bool {
        self.component.is_self()
    }
}

impl fmt::Display for RawExportTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.component, self.local_kind) {
            (LocalComponentRef::Self_, Some(LocalCapabilityRefKind::Slot)) => {
                f.write_str("slots.")?;
                f.write_str(&self.name)
            }
            (LocalComponentRef::Self_, Some(LocalCapabilityRefKind::Provide)) => {
                f.write_str("provides.")?;
                f.write_str(&self.name)
            }
            (LocalComponentRef::Self_, None) => {
                f.write_str("self.")?;
                f.write_str(&self.name)
            }
            (LocalComponentRef::Child(child), _) => {
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
                    local_kind: None,
                })
            }
            Some((left, right)) => {
                if left.is_empty() || right.is_empty() {
                    return Err(Error::InvalidExportTarget {
                        input: input.to_string(),
                        message: "expected `<component-ref>.<name>`".to_string(),
                    });
                }
                let (component, local_kind) = match left {
                    "slots" => (LocalComponentRef::Self_, Some(LocalCapabilityRefKind::Slot)),
                    "provides" => (
                        LocalComponentRef::Self_,
                        Some(LocalCapabilityRefKind::Provide),
                    ),
                    _ => (
                        parse_component_ref(left).map_err(|err| Error::InvalidExportTarget {
                            input: input.to_string(),
                            message: err.message,
                        })?,
                        None,
                    ),
                };
                ensure_name_no_dot(right, "export target")?;
                Ok(Self {
                    component,
                    name: right.to_string(),
                    local_kind,
                })
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, DeserializeFromStr, SerializeDisplay)]
#[non_exhaustive]
pub struct PolicyRef {
    pub alias: String,
    pub export: String,
}

impl fmt::Display for PolicyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("#")?;
        f.write_str(&self.alias)?;
        f.write_str(".")?;
        f.write_str(&self.export)
    }
}

impl FromStr for PolicyRef {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_policy_ref(input)
    }
}

#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, bon::Builder,
)]
#[builder(on(String, into))]
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
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, bon::Builder)]
#[builder(on(String, into))]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct EnvironmentDecl {
    /// Optional base environment to extend (within the same manifest).
    #[serde(default)]
    pub extends: Option<String>,
    /// Names of resolvers to add (interpreted by the host/compiler).
    #[serde(default)]
    #[builder(default)]
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

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, bon::Builder)]
#[builder(on(String, into))]
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
#[non_exhaustive]
pub struct ConfigSchema(pub Value);

impl ConfigSchema {
    pub(crate) fn validate_value(value: &Value) -> Result<(), Error> {
        jsonschema::validator_for(value).map_err(|e| Error::InvalidConfigSchema(e.to_string()))?;
        config_schema_profile::validate(value).map_err(Error::InvalidConfigSchema)?;
        Ok(())
    }

    pub fn new(value: Value) -> Result<Self, Error> {
        Self::validate_value(&value)?;
        Ok(Self(value))
    }
}

impl TryFrom<Value> for ConfigSchema {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for ConfigSchema {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        ConfigSchema::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
/// A binding wires a target slot to a source capability.
pub struct RawBinding {
    pub to: LocalComponentRef,
    pub slot: String,
    pub from: BindingSourceRef,
    pub capability: String,
    /// If true, this binding does not participate in dependency ordering or cycle detection.
    #[serde(default)]
    pub weak: bool,
    #[serde(skip)]
    pub(crate) mixed_form: bool,
    #[serde(skip)]
    pub(crate) raw_to: Option<String>,
    #[serde(skip)]
    pub(crate) raw_from: Option<String>,
}

impl PartialEq for RawBinding {
    fn eq(&self, other: &Self) -> bool {
        self.to == other.to
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
            &self.to,
            &self.slot,
            &self.from,
            &self.capability,
            &self.weak,
        )
            .cmp(&(
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
                ensure_binding_ref_name_no_dot(&slot, slot.as_str())
                    .map_err(serde::de::Error::custom)?;
                ensure_binding_ref_name_no_dot(&capability, capability.as_str())
                    .map_err(serde::de::Error::custom)?;
                Ok(RawBinding {
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
                 dot form `to: \"<component-ref>.<slot>\", from: \"<source-ref>.<capability>\"`)",
            )),
            (None, Some(_)) => Err(serde::de::Error::custom(
                "binding has `capability` but is missing `slot` (either add `slot`, or use dot \
                 form `to: \"<component-ref>.<slot>\", from: \"<source-ref>.<capability>\"`)",
            )),
        }
    }
}

#[bon]
impl RawBinding {
    #[builder(on(String, into))]
    pub fn new(
        to: String,
        slot: String,
        from: String,
        capability: String,
        #[builder(default)] weak: bool,
    ) -> Result<Self, Error> {
        ensure_binding_ref_name_no_dot(&slot, slot.as_str())?;
        ensure_binding_ref_name_no_dot(&capability, capability.as_str())?;

        Ok(Self {
            to: parse_binding_target_ref(&to)?,
            slot,
            from: parse_binding_source_ref(&from)?,
            capability,
            weak,
            mixed_form: false,
            raw_to: None,
            raw_from: None,
        })
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

fn ensure_binding_ref_name_no_dot(name: &str, input: &str) -> Result<(), Error> {
    if name.contains('.') {
        return Err(Error::InvalidBinding {
            input: input.to_string(),
            message: "names cannot contain `.`".to_string(),
        });
    }
    Ok(())
}

fn is_framework_ref(input: &str) -> bool {
    input == "framework"
}

fn is_slots_ref(input: &str) -> bool {
    input == "slots"
}

fn is_provides_ref(input: &str) -> bool {
    input == "provides"
}

fn is_resources_ref(input: &str) -> bool {
    input == "resources"
}

fn parse_binding_target_ref(input: &str) -> Result<LocalComponentRef, Error> {
    if is_framework_ref(input)
        || is_resources_ref(input)
        || is_slots_ref(input)
        || is_provides_ref(input)
    {
        return Err(Error::InvalidBinding {
            input: input.to_string(),
            message: format!("{input} cannot be a binding target"),
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
    if is_resources_ref(input) {
        return Ok(BindingSourceRef::Resources);
    }
    if is_slots_ref(input) {
        return Ok(BindingSourceRef::Slots);
    }
    if is_provides_ref(input) {
        return Ok(BindingSourceRef::Provides);
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
    ensure_binding_ref_name_no_dot(right, input)?;
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
    ensure_binding_ref_name_no_dot(right, input)?;
    Ok((source, right.to_string()))
}

fn parse_policy_ref(input: &str) -> Result<PolicyRef, Error> {
    let Some(rest) = input.strip_prefix('#') else {
        return Err(Error::InvalidPolicyRef {
            input: input.to_string(),
            message: "expected `#<use>.<export>`".to_string(),
        });
    };
    let Some((alias, export)) = rest.split_once('.') else {
        return Err(Error::InvalidPolicyRef {
            input: input.to_string(),
            message: "expected `#<use>.<export>`".to_string(),
        });
    };
    if alias.is_empty() || export.is_empty() || export.contains('.') {
        return Err(Error::InvalidPolicyRef {
            input: input.to_string(),
            message: "expected `#<use>.<export>`".to_string(),
        });
    }

    crate::names::ensure_name_no_dot(alias, "use")?;
    crate::names::ensure_name_no_dot(export, "export")?;

    Ok(PolicyRef {
        alias: alias.to_string(),
        export: export.to_string(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ExportTarget {
    SelfProvide(ProvideName),
    SelfSlot(SlotName),
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
    SelfSlot(SlotName),
    Resource(ResourceName),
    ChildExport {
        child: ChildName,
        export: ExportName,
    },
    Framework(FrameworkCapabilityName),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Binding {
    pub from: BindingSource,
    pub weak: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ManifestBinding {
    pub target: BindingTarget,
    pub binding: Binding,
}
