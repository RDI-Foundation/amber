use std::{
    collections::{BTreeMap, BTreeSet},
    sync::LazyLock,
};

use amber_manifest::{
    FrameworkCapabilityName, InterpolatedString, NetworkProtocol, ProgramEntrypoint,
    ProgramEnvValue, SlotTarget, VmCloudInit, VmEgress, VmScalarU32, parse_slot_query,
};
use amber_template::{TemplatePart, TemplateString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

static EMPTY_PROGRAM_ENTRYPOINT: LazyLock<ProgramEntrypoint> =
    LazyLock::new(ProgramEntrypoint::default);
static EMPTY_PROGRAM_ENV: LazyLock<BTreeMap<String, ProgramEnvValue>> =
    LazyLock::new(BTreeMap::new);

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Program {
    Image(ProgramImage),
    Path(ProgramPath),
    Vm(ProgramVm),
}

impl Program {
    pub fn image_ref(&self) -> Option<&str> {
        match self {
            Self::Image(program) => Some(program.image.as_str()),
            Self::Path(_) | Self::Vm(_) => None,
        }
    }

    pub fn path_ref(&self) -> Option<&str> {
        match self {
            Self::Image(_) | Self::Vm(_) => None,
            Self::Path(program) => Some(program.path.as_str()),
        }
    }

    pub fn command(&self) -> &ProgramEntrypoint {
        match self {
            Self::Image(program) => &program.entrypoint,
            Self::Path(program) => &program.args,
            Self::Vm(_) => &EMPTY_PROGRAM_ENTRYPOINT,
        }
    }

    pub fn env(&self) -> &BTreeMap<String, ProgramEnvValue> {
        match self {
            Self::Image(program) => &program.common.env,
            Self::Path(program) => &program.common.env,
            Self::Vm(_) => &EMPTY_PROGRAM_ENV,
        }
    }

    pub fn network(&self) -> Option<&ProgramNetwork> {
        match self {
            Self::Image(program) => program.common.network.as_ref(),
            Self::Path(program) => program.common.network.as_ref(),
            Self::Vm(program) => program.network.as_ref(),
        }
    }

    pub fn mounts(&self) -> &[ProgramMount] {
        match self {
            Self::Image(program) => &program.common.mounts,
            Self::Path(program) => &program.common.mounts,
            Self::Vm(program) => &program.mounts,
        }
    }

    pub fn visit_slot_uses(&self, mut visit: impl FnMut(&str)) -> bool {
        match self {
            Self::Image(program) => {
                if let Ok(parsed) = program.image.parse::<InterpolatedString>()
                    && parsed.visit_slot_uses(&mut visit)
                {
                    return true;
                }
            }
            Self::Path(program) => {
                if let Ok(parsed) = program.path.parse::<InterpolatedString>()
                    && parsed.visit_slot_uses(&mut visit)
                {
                    return true;
                }
            }
            Self::Vm(program) => {
                if let Ok(parsed) = program.image.parse::<InterpolatedString>()
                    && parsed.visit_slot_uses(&mut visit)
                {
                    return true;
                }
                for scalar in [&program.cpus, &program.memory_mib] {
                    let VmScalarU32::Interpolated(raw) = scalar else {
                        continue;
                    };
                    if let Ok(parsed) = raw.parse::<InterpolatedString>()
                        && parsed.visit_slot_uses(&mut visit)
                    {
                        return true;
                    }
                }
                if let Some(raw) = program.cloud_init.user_data.as_deref()
                    && let Ok(parsed) = raw.parse::<InterpolatedString>()
                    && parsed.visit_slot_uses(&mut visit)
                {
                    return true;
                }
                if let Some(raw) = program.cloud_init.vendor_data.as_deref()
                    && let Ok(parsed) = raw.parse::<InterpolatedString>()
                    && parsed.visit_slot_uses(&mut visit)
                {
                    return true;
                }
            }
        }

        if self.command().visit_slot_uses(&mut visit) {
            return true;
        }

        for value in self.env().values() {
            if value.visit_slot_uses(&mut visit) {
                return true;
            }
        }

        for mount in self.mounts() {
            if mount.visit_slot_uses(&mut visit) {
                return true;
            }
        }

        false
    }
}

impl Serialize for Program {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct ProgramFields<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            image: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            path: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            vm: Option<&'a ProgramVm>,
            #[serde(skip_serializing_if = "Option::is_none")]
            entrypoint: Option<&'a ProgramEntrypoint>,
            #[serde(skip_serializing_if = "Option::is_none")]
            args: Option<&'a ProgramEntrypoint>,
            #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
            env: &'a BTreeMap<String, ProgramEnvValue>,
            #[serde(skip_serializing_if = "Option::is_none")]
            network: Option<&'a ProgramNetwork>,
            #[serde(default, skip_serializing_if = "<[_]>::is_empty")]
            mounts: &'a [ProgramMount],
        }

        let fields = match self {
            Self::Image(program) => ProgramFields {
                image: Some(program.image.as_str()),
                path: None,
                vm: None,
                entrypoint: Some(&program.entrypoint),
                args: None,
                env: &program.common.env,
                network: program.common.network.as_ref(),
                mounts: &program.common.mounts,
            },
            Self::Path(program) => ProgramFields {
                image: None,
                path: Some(program.path.as_str()),
                vm: None,
                entrypoint: None,
                args: Some(&program.args),
                env: &program.common.env,
                network: program.common.network.as_ref(),
                mounts: &program.common.mounts,
            },
            Self::Vm(program) => ProgramFields {
                image: None,
                path: None,
                vm: Some(program),
                entrypoint: None,
                args: None,
                env: &EMPTY_PROGRAM_ENV,
                network: None,
                mounts: &[],
            },
        };

        fields.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Program {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ProgramFields {
            #[serde(default)]
            image: Option<ProgramImageField>,
            #[serde(default)]
            path: Option<ProgramPathField>,
            #[serde(default)]
            vm: Option<ProgramVm>,
            #[serde(default)]
            entrypoint: Option<ProgramEntrypoint>,
            #[serde(default)]
            args: Option<ProgramEntrypoint>,
            #[serde(default)]
            env: BTreeMap<String, ProgramEnvValue>,
            #[serde(default)]
            network: Option<ProgramNetwork>,
            #[serde(default)]
            mounts: Vec<ProgramMount>,
        }

        let fields = ProgramFields::deserialize(deserializer)?;
        match (fields.image, fields.path, fields.vm) {
            (Some(image), None, None) => {
                if fields.args.is_some() {
                    return Err(serde::de::Error::custom(
                        "program.args is only supported with program.path",
                    ));
                }
                Ok(Self::Image(ProgramImage {
                    image: image.0,
                    entrypoint: fields.entrypoint.unwrap_or_default(),
                    common: ProgramCommon {
                        env: fields.env,
                        network: fields.network,
                        mounts: fields.mounts,
                    },
                }))
            }
            (None, Some(path), None) => {
                if fields.entrypoint.is_some() {
                    return Err(serde::de::Error::custom(
                        "program.entrypoint is only supported with program.image",
                    ));
                }
                Ok(Self::Path(ProgramPath {
                    path: path.0,
                    args: fields.args.unwrap_or_default(),
                    common: ProgramCommon {
                        env: fields.env,
                        network: fields.network,
                        mounts: fields.mounts,
                    },
                }))
            }
            (None, None, Some(vm)) => {
                if fields.entrypoint.is_some() {
                    return Err(serde::de::Error::custom(
                        "program.entrypoint is only supported with program.image",
                    ));
                }
                if fields.args.is_some() {
                    return Err(serde::de::Error::custom(
                        "program.args is only supported with program.path",
                    ));
                }
                if !fields.env.is_empty() {
                    return Err(serde::de::Error::custom(
                        "program.env is not supported with program.vm",
                    ));
                }
                if fields.network.is_some() {
                    return Err(serde::de::Error::custom(
                        "program.network must be nested under program.vm",
                    ));
                }
                if !fields.mounts.is_empty() {
                    return Err(serde::de::Error::custom(
                        "program.mounts must be nested under program.vm",
                    ));
                }
                Ok(Self::Vm(vm))
            }
            (Some(_), Some(_), None) => Err(serde::de::Error::custom(
                "program must declare exactly one of `image`, `path`, or `vm`",
            )),
            (Some(_), None, Some(_)) | (None, Some(_), Some(_)) | (Some(_), Some(_), Some(_)) => {
                Err(serde::de::Error::custom(
                    "program must declare exactly one of `image`, `path`, or `vm`",
                ))
            }
            (None, None, None) => Err(serde::de::Error::custom(
                "program must declare either `image`, `path`, or `vm`",
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
struct ProgramImageField(#[serde(deserialize_with = "deserialize_program_string")] String);

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
struct ProgramPathField(#[serde(deserialize_with = "deserialize_program_string")] String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramImage {
    #[serde(deserialize_with = "deserialize_program_string")]
    pub image: String,
    #[serde(default)]
    pub entrypoint: ProgramEntrypoint,
    #[serde(flatten)]
    pub common: ProgramCommon,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramPath {
    #[serde(deserialize_with = "deserialize_program_string")]
    pub path: String,
    #[serde(default)]
    pub args: ProgramEntrypoint,
    #[serde(flatten)]
    pub common: ProgramCommon,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramVm {
    #[serde(deserialize_with = "deserialize_program_string")]
    pub image: String,
    pub cpus: VmScalarU32,
    pub memory_mib: VmScalarU32,
    #[serde(default)]
    pub network: Option<ProgramNetwork>,
    #[serde(default)]
    pub mounts: Vec<ProgramMount>,
    #[serde(default)]
    pub cloud_init: VmCloudInit,
    #[serde(default)]
    pub egress: VmEgress,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramCommon {
    #[serde(default)]
    pub env: BTreeMap<String, ProgramEnvValue>,
    #[serde(default)]
    pub network: Option<ProgramNetwork>,
    #[serde(default)]
    pub mounts: Vec<ProgramMount>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ProgramNetwork {
    pub endpoints: Vec<Endpoint>,
}

impl<'de> Deserialize<'de> for ProgramNetwork {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ProgramNetworkFields {
            #[serde(default)]
            endpoints: Vec<Endpoint>,
        }

        let fields = ProgramNetworkFields::deserialize(deserializer)?;
        let mut names = BTreeSet::new();
        for endpoint in &fields.endpoints {
            if endpoint.name.is_empty() {
                return Err(serde::de::Error::custom(
                    "program endpoint names must not be empty",
                ));
            }
            if !names.insert(endpoint.name.as_str()) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate endpoint name `{}`",
                    endpoint.name
                )));
            }
        }

        Ok(Self {
            endpoints: fields.endpoints,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub name: String,
    pub port: u16,
    #[serde(default = "default_network_protocol")]
    pub protocol: NetworkProtocol,
}

fn default_network_protocol() -> NetworkProtocol {
    NetworkProtocol::Http
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProgramMount {
    File(FileMount),
    Slot {
        path: String,
        slot: String,
    },
    Resource {
        path: String,
        resource: String,
    },
    Framework {
        path: String,
        capability: FrameworkCapabilityName,
    },
}

impl Serialize for ProgramMount {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        #[serde(tag = "kind", rename_all = "snake_case")]
        enum ProgramMountFields<'a> {
            File(&'a FileMount),
            Slot {
                path: &'a str,
                slot: &'a str,
            },
            Resource {
                path: &'a str,
                resource: &'a str,
            },
            Framework {
                path: &'a str,
                capability: &'a FrameworkCapabilityName,
            },
        }

        let fields = match self {
            Self::File(mount) => ProgramMountFields::File(mount),
            Self::Slot { path, slot } => ProgramMountFields::Slot { path, slot },
            Self::Resource { path, resource } => ProgramMountFields::Resource { path, resource },
            Self::Framework { path, capability } => {
                ProgramMountFields::Framework { path, capability }
            }
        };

        fields.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ProgramMount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case")]
        enum ProgramMountFields {
            File(FileMount),
            Slot {
                path: String,
                slot: String,
            },
            Resource {
                path: String,
                resource: String,
            },
            Framework {
                path: String,
                capability: FrameworkCapabilityName,
            },
        }

        match ProgramMountFields::deserialize(deserializer)? {
            ProgramMountFields::File(mount) => Ok(Self::File(mount)),
            ProgramMountFields::Slot { path, slot } => {
                validate_concrete_mount_path(&path).map_err(serde::de::Error::custom)?;
                Ok(Self::Slot { path, slot })
            }
            ProgramMountFields::Resource { path, resource } => {
                validate_concrete_mount_path(&path).map_err(serde::de::Error::custom)?;
                Ok(Self::Resource { path, resource })
            }
            ProgramMountFields::Framework { path, capability } => {
                validate_concrete_mount_path(&path).map_err(serde::de::Error::custom)?;
                Ok(Self::Framework { path, capability })
            }
        }
    }
}

impl ProgramMount {
    pub fn visit_slot_uses(&self, mut visit: impl FnMut(&str)) -> bool {
        match self {
            Self::File(mount) => mount.visit_slot_uses(&mut visit),
            Self::Slot { slot, .. } => {
                visit(slot);
                false
            }
            Self::Resource { .. } | Self::Framework { .. } => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileMount {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<ProgramCondition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub each: Option<ProgramEach>,
    pub path: TemplateString,
    pub source: FileMountSource,
}

impl FileMount {
    pub fn visit_slot_uses(&self, visit: &mut impl FnMut(&str)) -> bool {
        if let Some(when) = &self.when
            && when.visit_slot_uses(&mut *visit)
        {
            return true;
        }
        if let Some(each) = &self.each {
            each.visit_slot_uses(&mut *visit);
        }
        if visit_template_string_slot_uses(&self.path, &mut *visit) {
            return true;
        }
        self.source.visit_slot_uses(visit)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FileMountSource {
    Config { path: TemplateString },
    Secret { path: TemplateString },
}

impl FileMountSource {
    fn visit_slot_uses(&self, visit: &mut impl FnMut(&str)) -> bool {
        match self {
            Self::Config { path } | Self::Secret { path } => {
                visit_template_string_slot_uses(path, visit)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProgramCondition {
    Config { path: String },
    Slot { query: String },
}

impl ProgramCondition {
    fn visit_slot_uses(&self, visit: &mut impl FnMut(&str)) -> bool {
        match self {
            Self::Config { .. } => false,
            Self::Slot { query } => visit_slot_query_uses(query, visit),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProgramEach {
    Config { path: String },
    Slot { slot: String },
}

impl ProgramEach {
    fn visit_slot_uses(&self, visit: &mut impl FnMut(&str)) {
        if let Self::Slot { slot } = self {
            visit(slot);
        }
    }
}

fn visit_template_string_slot_uses(value: &TemplateString, visit: &mut impl FnMut(&str)) -> bool {
    for part in value {
        match part {
            TemplatePart::Slot { slot, .. } => {
                if visit_slot_query_uses(slot, visit) {
                    return true;
                }
            }
            TemplatePart::Item { slot, .. } => visit(slot),
            TemplatePart::Lit { .. }
            | TemplatePart::Config { .. }
            | TemplatePart::CurrentItem { .. } => {}
        }
    }
    false
}

fn visit_slot_query_uses(query: &str, visit: &mut impl FnMut(&str)) -> bool {
    match parse_slot_query(query) {
        Ok(parsed) => match parsed.target {
            SlotTarget::All => true,
            SlotTarget::Slot(slot) => {
                visit(slot);
                false
            }
        },
        Err(_) => query.is_empty(),
    }
}

fn deserialize_program_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_program_string(value).map_err(serde::de::Error::custom)
}

fn validate_program_string(value: String) -> Result<String, String> {
    value
        .parse::<InterpolatedString>()
        .map_err(|err| err.to_string())?;
    Ok(value)
}

fn validate_concrete_mount_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/') {
        return Err("mount path must be absolute".to_string());
    }
    if path.split('/').any(|segment| segment == "..") {
        return Err("mount path must not contain `..`".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{FrameworkCapabilityName, Program, ProgramMount};

    #[test]
    fn program_deserialize_rejects_image_with_args() {
        let err = serde_json::from_value::<Program>(json!({
            "image": "app",
            "args": ["--bad"],
        }))
        .expect_err("image programs must reject args");

        assert!(
            err.to_string()
                .contains("program.args is only supported with program.path")
        );
    }

    #[test]
    fn program_deserialize_rejects_duplicate_endpoint_names() {
        let err = serde_json::from_value::<Program>(json!({
            "image": "app",
            "entrypoint": ["app"],
            "network": {
                "endpoints": [
                    { "name": "api", "port": 8080 },
                    { "name": "api", "port": 9090 }
                ]
            }
        }))
        .expect_err("duplicate lowered endpoints must be rejected");

        assert!(err.to_string().contains("duplicate endpoint name `api`"));
    }

    #[test]
    fn program_deserialize_rejects_invalid_non_file_mount_path() {
        let err = serde_json::from_value::<Program>(json!({
            "image": "app",
            "entrypoint": ["app"],
            "mounts": [
                { "kind": "resource", "path": "../data", "resource": "state" }
            ]
        }))
        .expect_err("invalid concrete mount paths must be rejected");

        assert!(err.to_string().contains("mount path must be absolute"));
    }

    #[test]
    fn program_mount_serializes_with_kind_tag() {
        let value = serde_json::to_value(ProgramMount::Framework {
            path: "/var/run/docker.sock".to_string(),
            capability: FrameworkCapabilityName::try_from("docker").expect("capability"),
        })
        .expect("program mount should serialize");

        assert_eq!(
            value,
            json!({
                "kind": "framework",
                "path": "/var/run/docker.sock",
                "capability": "docker"
            })
        );
    }
}
