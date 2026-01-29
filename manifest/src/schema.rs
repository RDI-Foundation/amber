use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fmt,
    hash::{Hash, Hasher},
    str::FromStr,
};

use bon::bon;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use serde_with::{
    DefaultOnNull, DeserializeFromStr, MapPreventDuplicates, SerializeDisplay, serde_as,
};

use crate::{
    config_schema_profile,
    error::Error,
    interpolation::{InterpolatedString, ProgramArgs},
    names::{
        BindingName, ChildName, ExportName, FrameworkCapabilityName, ProvideName, SlotName,
        ensure_name_no_dot,
    },
    refs::ManifestRef,
    spans::BindingTargetKey,
};

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, bon::Builder,
)]
#[builder(on(String, into))]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Program {
    pub image: String,
    #[serde(default, alias = "entrypoint")]
    #[builder(default)]
    pub args: ProgramArgs,
    #[serde_as(as = "MapPreventDuplicates<_, _>")]
    #[serde(default)]
    #[builder(default)]
    pub env: BTreeMap<String, InterpolatedString>,
    #[serde(default)]
    pub network: Option<Network>,
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
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Network {
    #[serde(default, deserialize_with = "deserialize_endpoints")]
    #[builder(default)]
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

#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, bon::Builder,
)]
#[builder(on(String, into))]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Endpoint {
    pub name: String,
    // TODO: this should be an enum tagged by `NetworkProtocol` and carrying appropriate data for the protocol
    pub port: u16,
    #[serde(default = "default_protocol")]
    #[builder(default = default_protocol())]
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

#[derive(Clone, Debug, PartialEq, Eq, Hash, DeserializeFromStr, SerializeDisplay, bon::Builder)]
#[builder(on(String, into))]
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
    pub(crate) mixed_form: bool,
    #[serde(skip)]
    pub(crate) raw_to: Option<String>,
    #[serde(skip)]
    pub(crate) raw_from: Option<String>,
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

#[bon]
impl RawBinding {
    #[builder(on(String, into))]
    pub fn new(
        name: Option<String>,
        to: String,
        slot: String,
        from: String,
        capability: String,
        #[builder(default)] weak: bool,
    ) -> Result<Self, Error> {
        ensure_binding_name_no_dot(&slot, slot.as_str())?;
        ensure_binding_name_no_dot(&capability, capability.as_str())?;

        Ok(Self {
            name,
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
