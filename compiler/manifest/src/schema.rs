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

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Program {
    Image(ProgramImage),
    Path(ProgramPath),
    Vm(ProgramVmField),
}

static EMPTY_PROGRAM_ENTRYPOINT: LazyLock<ProgramEntrypoint> =
    LazyLock::new(ProgramEntrypoint::default);
static EMPTY_PROGRAM_ENV: LazyLock<BTreeMap<String, ProgramEnvValue>> =
    LazyLock::new(BTreeMap::new);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgramCommandKind {
    Entrypoint,
    Args,
}

impl ProgramCommandKind {
    fn label(self) -> &'static str {
        match self {
            Self::Entrypoint => "program.entrypoint",
            Self::Args => "program.args",
        }
    }

    fn json_pointer(self) -> &'static str {
        match self {
            Self::Entrypoint => "/program/entrypoint",
            Self::Args => "/program/args",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgramConfigUseSite<'a> {
    Image,
    Path,
    VmImage,
    VmCpus,
    VmMemoryMib,
    VmCloudInitUserData,
    VmCloudInitVendorData,
    CommandWhen {
        kind: ProgramCommandKind,
        index: usize,
    },
    CommandEach {
        kind: ProgramCommandKind,
        index: usize,
    },
    CommandValue {
        kind: ProgramCommandKind,
        index: usize,
    },
    EnvWhen {
        name: &'a str,
    },
    EnvEach {
        name: &'a str,
    },
    EnvValue {
        name: &'a str,
        wrapped: bool,
    },
    EndpointWhen {
        index: usize,
    },
    EndpointEach {
        index: usize,
    },
    EndpointName {
        index: usize,
    },
    EndpointPort {
        index: usize,
    },
    EndpointProtocol {
        index: usize,
    },
    MountWhen {
        index: usize,
    },
    MountEach {
        index: usize,
    },
    MountName {
        index: usize,
    },
    MountPath {
        index: usize,
    },
    MountSource {
        index: usize,
    },
}

impl fmt::Display for ProgramConfigUseSite<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Image => f.write_str("program.image"),
            Self::Path => f.write_str("program.path"),
            Self::VmImage => f.write_str("program.vm.image"),
            Self::VmCpus => f.write_str("program.vm.cpus"),
            Self::VmMemoryMib => f.write_str("program.vm.memory_mib"),
            Self::VmCloudInitUserData => f.write_str("program.vm.cloud_init.user_data"),
            Self::VmCloudInitVendorData => f.write_str("program.vm.cloud_init.vendor_data"),
            Self::CommandWhen { kind, index } => write!(f, "{}[{index}].when", kind.label()),
            Self::CommandEach { kind, index } => write!(f, "{}[{index}].each", kind.label()),
            Self::CommandValue { kind, index } => write!(f, "{}[{index}]", kind.label()),
            Self::EnvWhen { name } => write!(f, "program.env.{name}.when"),
            Self::EnvEach { name } => write!(f, "program.env.{name}.each"),
            Self::EnvValue {
                name,
                wrapped: true,
            } => write!(f, "program.env.{name}.value"),
            Self::EnvValue {
                name,
                wrapped: false,
            } => write!(f, "program.env.{name}"),
            Self::EndpointWhen { index } => write!(f, "program.network.endpoints[{index}].when"),
            Self::EndpointEach { index } => write!(f, "program.network.endpoints[{index}].each"),
            Self::EndpointName { index } => write!(f, "program.network.endpoints[{index}].name"),
            Self::EndpointPort { index } => write!(f, "program.network.endpoints[{index}].port"),
            Self::EndpointProtocol { index } => {
                write!(f, "program.network.endpoints[{index}].protocol")
            }
            Self::MountWhen { index } => write!(f, "program.mounts[{index}].when"),
            Self::MountEach { index } => write!(f, "program.mounts[{index}].each"),
            Self::MountName { index } => write!(f, "program.mounts[{index}].name"),
            Self::MountPath { index } => write!(f, "program.mounts[{index}].path"),
            Self::MountSource { index } => write!(f, "program.mounts[{index}].from"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProgramFieldLocation {
    Common,
    Vm,
}

impl ProgramFieldLocation {
    fn mounts_pointer(self) -> &'static str {
        match self {
            Self::Common => "/program/mounts",
            Self::Vm => "/program/vm/mounts",
        }
    }

    fn endpoints_pointer(self) -> &'static str {
        match self {
            Self::Common => "/program/network/endpoints",
            Self::Vm => "/program/vm/network/endpoints",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProgramVersionGatedSyntax<'a> {
    ConditionalCommandItem {
        kind: ProgramCommandKind,
        index: usize,
    },
    VariadicCommandItem {
        kind: ProgramCommandKind,
        index: usize,
    },
    ConditionalEnvValue {
        name: &'a str,
    },
    VariadicEnvValue {
        name: &'a str,
    },
    ConditionalMount {
        location: ProgramFieldLocation,
        index: usize,
    },
    VariadicMount {
        location: ProgramFieldLocation,
        index: usize,
    },
    ConditionalEndpoint {
        location: ProgramFieldLocation,
        index: usize,
    },
    VariadicEndpoint {
        location: ProgramFieldLocation,
        index: usize,
    },
}

impl ProgramVersionGatedSyntax<'_> {
    pub(crate) fn required_version(self) -> &'static str {
        match self {
            Self::ConditionalCommandItem { .. }
            | Self::ConditionalEnvValue { .. }
            | Self::ConditionalMount { .. }
            | Self::ConditionalEndpoint { .. } => "0.2.0",
            Self::VariadicCommandItem { .. }
            | Self::VariadicEnvValue { .. }
            | Self::VariadicMount { .. }
            | Self::VariadicEndpoint { .. } => "0.3.0",
        }
    }

    pub(crate) fn feature(self) -> &'static str {
        match self {
            Self::ConditionalCommandItem { .. } => "conditional argument items",
            Self::VariadicCommandItem { .. } => "variadic argument expansion",
            Self::ConditionalEnvValue { .. } => "conditional environment values",
            Self::VariadicEnvValue { .. } => "variadic environment expansion",
            Self::ConditionalMount { .. } => "conditional mounts",
            Self::VariadicMount { .. } => "variadic mounts",
            Self::ConditionalEndpoint { .. } => "conditional endpoints",
            Self::VariadicEndpoint { .. } => "variadic endpoints",
        }
    }

    pub(crate) fn pointer(self) -> String {
        match self {
            Self::ConditionalCommandItem { kind, index }
            | Self::VariadicCommandItem { kind, index } => {
                format!("{}/{index}", kind.json_pointer())
            }
            Self::ConditionalEnvValue { name } | Self::VariadicEnvValue { name } => {
                format!("/program/env/{name}")
            }
            Self::ConditionalMount { location, index }
            | Self::VariadicMount { location, index } => {
                format!("{}/{index}", location.mounts_pointer())
            }
            Self::ConditionalEndpoint { location, index }
            | Self::VariadicEndpoint { location, index } => {
                format!("{}/{index}", location.endpoints_pointer())
            }
        }
    }
}

impl<'de> Deserialize<'de> for Program {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[serde_as]
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ProgramFields {
            #[serde(default)]
            image: Option<ProgramImageField>,
            #[serde(default)]
            path: Option<ProgramPathField>,
            #[serde(default)]
            vm: Option<VmProgram>,
            #[serde(default)]
            #[serde(deserialize_with = "double_option::deserialize")]
            entrypoint: Option<Option<ProgramEntrypoint>>,
            #[serde(default)]
            #[serde(deserialize_with = "double_option::deserialize")]
            args: Option<Option<ProgramEntrypoint>>,
            #[serde_as(as = "MapPreventDuplicates<_, _>")]
            #[serde(default)]
            env: BTreeMap<String, ProgramEnvValue>,
            #[serde(default)]
            network: Option<Network>,
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
                    entrypoint: fields.entrypoint.flatten().unwrap_or_default(),
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
                    args: fields.args.flatten().unwrap_or_default(),
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
                        "program.env is not supported with program.vm; configure guest startup \
                         with program.vm.cloud_init.user_data or vendor_data",
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
                Ok(Self::Vm(ProgramVmField(vm)))
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

impl Serialize for Program {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct VmProgramEnvelope<'a> {
            vm: &'a VmProgram,
        }

        match self {
            Self::Image(program) => program.serialize(serializer),
            Self::Path(program) => program.serialize(serializer),
            Self::Vm(program) => VmProgramEnvelope { vm: &program.0 }.serialize(serializer),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(transparent)]
struct ProgramImageField(#[serde(deserialize_with = "deserialize_program_image")] String);

#[derive(Clone, Debug, Deserialize)]
#[serde(transparent)]
struct ProgramPathField(#[serde(deserialize_with = "deserialize_program_path")] String);

impl Program {
    pub fn image(image: ProgramImage) -> Self {
        Self::Image(image)
    }

    pub fn path(path: ProgramPath) -> Self {
        Self::Path(path)
    }

    pub fn vm(vm: VmProgram) -> Self {
        Self::Vm(ProgramVmField(vm))
    }

    pub fn image_ref(&self) -> Option<&str> {
        match self {
            Self::Image(program) => Some(program.image.as_str()),
            Self::Path(_) | Self::Vm(_) => None,
        }
    }

    pub fn path_ref(&self) -> Option<&str> {
        match self {
            Self::Image(_) => None,
            Self::Path(program) => Some(program.path.as_str()),
            Self::Vm(_) => None,
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

    pub fn network(&self) -> Option<ProgramNetworkRef<'_>> {
        match self {
            Self::Image(program) => program
                .common
                .network
                .as_ref()
                .map(ProgramNetworkRef::Common),
            Self::Path(program) => program
                .common
                .network
                .as_ref()
                .map(ProgramNetworkRef::Common),
            Self::Vm(program) => program.0.network.as_ref().map(ProgramNetworkRef::Vm),
        }
    }

    pub fn mounts(&self) -> &[ProgramMount] {
        match self {
            Self::Image(program) => &program.common.mounts,
            Self::Path(program) => &program.common.mounts,
            Self::Vm(program) => &program.0.mounts,
        }
    }

    pub(crate) fn first_conditional_syntax(&self) -> Option<ProgramVersionGatedSyntax<'_>> {
        self.first_command_or_env_syntax(true).or_else(|| {
            let location = match self {
                Self::Vm(_) => ProgramFieldLocation::Vm,
                Self::Image(_) | Self::Path(_) => ProgramFieldLocation::Common,
            };
            self.mounts()
                .iter()
                .enumerate()
                .find_map(|(index, mount)| {
                    mount
                        .when
                        .as_ref()
                        .map(|_| ProgramVersionGatedSyntax::ConditionalMount { location, index })
                })
                .or_else(|| {
                    self.network().and_then(|network| {
                        network
                            .endpoints()
                            .iter()
                            .enumerate()
                            .find_map(|(index, endpoint)| {
                                endpoint.when.as_ref().map(|_| {
                                    ProgramVersionGatedSyntax::ConditionalEndpoint {
                                        location,
                                        index,
                                    }
                                })
                            })
                    })
                })
        })
    }

    pub(crate) fn first_variadic_syntax(&self) -> Option<ProgramVersionGatedSyntax<'_>> {
        self.first_command_or_env_syntax(false).or_else(|| {
            let location = match self {
                Self::Vm(_) => ProgramFieldLocation::Vm,
                Self::Image(_) | Self::Path(_) => ProgramFieldLocation::Common,
            };
            self.mounts()
                .iter()
                .enumerate()
                .find_map(|(index, mount)| {
                    mount
                        .each
                        .as_ref()
                        .map(|_| ProgramVersionGatedSyntax::VariadicMount { location, index })
                })
                .or_else(|| {
                    self.network().and_then(|network| {
                        network
                            .endpoints()
                            .iter()
                            .enumerate()
                            .find_map(|(index, endpoint)| {
                                endpoint.each.as_ref().map(|_| {
                                    ProgramVersionGatedSyntax::VariadicEndpoint { location, index }
                                })
                            })
                    })
                })
        })
    }

    fn first_command_or_env_syntax<'a>(
        &'a self,
        conditional: bool,
    ) -> Option<ProgramVersionGatedSyntax<'a>> {
        let (kind, command, env) = match self {
            Self::Image(program) => (
                Some(ProgramCommandKind::Entrypoint),
                Some(&program.entrypoint),
                Some(&program.common.env),
            ),
            Self::Path(program) => (
                Some(ProgramCommandKind::Args),
                Some(&program.args),
                Some(&program.common.env),
            ),
            Self::Vm(_) => (None, None, None),
        };

        if let (Some(kind), Some(command)) = (kind, command)
            && let Some(index) = command.0.iter().position(|item| {
                if conditional {
                    item.when().is_some()
                } else {
                    item.each().is_some()
                }
            })
        {
            return Some(if conditional {
                ProgramVersionGatedSyntax::ConditionalCommandItem { kind, index }
            } else {
                ProgramVersionGatedSyntax::VariadicCommandItem { kind, index }
            });
        }

        env.and_then(|env| {
            env.iter().find_map(|(name, value)| {
                if conditional {
                    value
                        .when()
                        .map(|_| ProgramVersionGatedSyntax::ConditionalEnvValue { name })
                } else {
                    value
                        .each()
                        .map(|_| ProgramVersionGatedSyntax::VariadicEnvValue { name })
                }
            })
        })
    }

    /// Visit config paths referenced anywhere in the program.
    pub fn visit_config_uses(&self, mut visit: impl FnMut(ProgramConfigUseSite<'_>, &str)) {
        fn visit_raw_string_config_uses(
            raw: &str,
            location: ProgramConfigUseSite<'_>,
            visit: &mut impl FnMut(ProgramConfigUseSite<'_>, &str),
        ) {
            let Ok(parsed) = raw.parse::<InterpolatedString>() else {
                return;
            };
            parsed.visit_config_uses(|query| visit(location, query));
        }

        fn visit_vm_scalar_config_uses(
            scalar: &VmScalarU32,
            location: ProgramConfigUseSite<'_>,
            visit: &mut impl FnMut(ProgramConfigUseSite<'_>, &str),
        ) {
            let VmScalarU32::Interpolated(raw) = scalar else {
                return;
            };
            visit_raw_string_config_uses(raw, location, visit);
        }

        fn visit_command_config_uses(
            kind: ProgramCommandKind,
            command: &ProgramEntrypoint,
            visit: &mut impl FnMut(ProgramConfigUseSite<'_>, &str),
        ) {
            for (index, item) in command.0.iter().enumerate() {
                if let Some(when) = item.when()
                    && when.source() == InterpolationSource::Config
                {
                    visit(
                        ProgramConfigUseSite::CommandWhen { kind, index },
                        when.query(),
                    );
                }
                if let Some(each) = item.each()
                    && let Some(path) = each.config_path()
                {
                    visit(ProgramConfigUseSite::CommandEach { kind, index }, path);
                }
                item.visit_values(|value| {
                    value.visit_config_uses(|query| {
                        visit(ProgramConfigUseSite::CommandValue { kind, index }, query)
                    });
                });
            }
        }

        fn visit_env_config_uses(
            env: &BTreeMap<String, ProgramEnvValue>,
            visit: &mut impl FnMut(ProgramConfigUseSite<'_>, &str),
        ) {
            for (name, value) in env {
                if let Some(when) = value.when()
                    && when.source() == InterpolationSource::Config
                {
                    visit(ProgramConfigUseSite::EnvWhen { name }, when.query());
                }
                if let Some(path) = value.each().and_then(|each| each.config_path()) {
                    visit(ProgramConfigUseSite::EnvEach { name }, path);
                }
                let wrapped = value.when().is_some() || value.each().is_some();
                value.value().visit_config_uses(|query| {
                    visit(ProgramConfigUseSite::EnvValue { name, wrapped }, query)
                });
            }
        }

        fn visit_network_config_uses(
            network: ProgramNetworkRef<'_>,
            visit: &mut impl FnMut(ProgramConfigUseSite<'_>, &str),
        ) {
            for (index, endpoint) in network.endpoints().iter().enumerate() {
                if let Some(when) = &endpoint.when
                    && when.source() == InterpolationSource::Config
                {
                    visit(ProgramConfigUseSite::EndpointWhen { index }, when.query());
                }
                if let Some(path) = endpoint
                    .each
                    .as_ref()
                    .and_then(crate::EachPath::config_path)
                {
                    visit(ProgramConfigUseSite::EndpointEach { index }, path);
                }
                endpoint.name.visit_config_uses(|query| {
                    visit(ProgramConfigUseSite::EndpointName { index }, query)
                });
                if let EndpointPort::Interpolated(port) = &endpoint.port {
                    port.visit_config_uses(|query| {
                        visit(ProgramConfigUseSite::EndpointPort { index }, query)
                    });
                }
                endpoint.protocol.visit_config_uses(|query| {
                    visit(ProgramConfigUseSite::EndpointProtocol { index }, query)
                });
            }
        }

        fn visit_mount_config_uses(
            mounts: &[ProgramMount],
            visit: &mut impl FnMut(ProgramConfigUseSite<'_>, &str),
        ) {
            for (index, mount) in mounts.iter().enumerate() {
                if let Some(when) = &mount.when
                    && when.source() == InterpolationSource::Config
                {
                    visit(ProgramConfigUseSite::MountWhen { index }, when.query());
                }
                if let Some(path) = mount.each.as_ref().and_then(crate::EachPath::config_path) {
                    visit(ProgramConfigUseSite::MountEach { index }, path);
                }
                if let Some(name) = &mount.name {
                    name.visit_config_uses(|query| {
                        visit(ProgramConfigUseSite::MountName { index }, query)
                    });
                }
                mount.path.visit_config_uses(|query| {
                    visit(ProgramConfigUseSite::MountPath { index }, query)
                });
                if let Some(source) = mount.literal_source() {
                    match source {
                        MountSource::Config(path) => {
                            visit(ProgramConfigUseSite::MountSource { index }, &path);
                        }
                        MountSource::Resource(_)
                        | MountSource::Slot(_)
                        | MountSource::Framework(_) => {}
                    }
                }
                mount.source.visit_config_uses(|query| {
                    visit(ProgramConfigUseSite::MountSource { index }, query)
                });
            }
        }

        match self {
            Self::Image(program) => {
                visit_raw_string_config_uses(
                    &program.image,
                    ProgramConfigUseSite::Image,
                    &mut visit,
                );
                visit_command_config_uses(
                    ProgramCommandKind::Entrypoint,
                    &program.entrypoint,
                    &mut visit,
                );
                visit_env_config_uses(&program.common.env, &mut visit);
            }
            Self::Path(program) => {
                visit_raw_string_config_uses(&program.path, ProgramConfigUseSite::Path, &mut visit);
                visit_command_config_uses(ProgramCommandKind::Args, &program.args, &mut visit);
                visit_env_config_uses(&program.common.env, &mut visit);
            }
            Self::Vm(program) => {
                visit_raw_string_config_uses(
                    &program.0.image,
                    ProgramConfigUseSite::VmImage,
                    &mut visit,
                );
                visit_vm_scalar_config_uses(
                    &program.0.cpus,
                    ProgramConfigUseSite::VmCpus,
                    &mut visit,
                );
                visit_vm_scalar_config_uses(
                    &program.0.memory_mib,
                    ProgramConfigUseSite::VmMemoryMib,
                    &mut visit,
                );
                if let Some(raw) = program.0.cloud_init.user_data.as_deref() {
                    visit_raw_string_config_uses(
                        raw,
                        ProgramConfigUseSite::VmCloudInitUserData,
                        &mut visit,
                    );
                }
                if let Some(raw) = program.0.cloud_init.vendor_data.as_deref() {
                    visit_raw_string_config_uses(
                        raw,
                        ProgramConfigUseSite::VmCloudInitVendorData,
                        &mut visit,
                    );
                }
            }
        }

        if let Some(network) = self.network() {
            visit_network_config_uses(network, &mut visit);
        }
        visit_mount_config_uses(self.mounts(), &mut visit);
    }

    /// Visit slot names referenced anywhere in the program. Returns `true` if the program
    /// references all slots.
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
                if let Ok(parsed) = program.0.image.parse::<InterpolatedString>()
                    && parsed.visit_slot_uses(&mut visit)
                {
                    return true;
                }
                for scalar in [&program.0.cpus, &program.0.memory_mib] {
                    let VmScalarU32::Interpolated(raw) = scalar else {
                        continue;
                    };
                    if let Ok(parsed) = raw.parse::<InterpolatedString>()
                        && parsed.visit_slot_uses(&mut visit)
                    {
                        return true;
                    }
                }
                for value in [
                    program.0.cloud_init.user_data.as_deref(),
                    program.0.cloud_init.vendor_data.as_deref(),
                ]
                .into_iter()
                .flatten()
                {
                    if let Ok(parsed) = value.parse::<InterpolatedString>()
                        && parsed.visit_slot_uses(&mut visit)
                    {
                        return true;
                    }
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

        if let Some(network) = self.network() {
            for endpoint in network.endpoints() {
                if endpoint.visit_slot_uses(&mut visit) {
                    return true;
                }
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

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum RawProgram {
    Image(RawProgramImage),
    Path(RawProgramPath),
    Vm(RawProgramVmField),
}

impl<'de> Deserialize<'de> for RawProgram {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[serde_as]
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ProgramFields {
            #[serde(default)]
            image: Option<InlineStringSpec>,
            #[serde(default)]
            path: Option<InlineStringSpec>,
            #[serde(default)]
            vm: Option<RawVmProgram>,
            #[serde(default)]
            #[serde(deserialize_with = "double_option::deserialize")]
            entrypoint: Option<Option<RawProgramEntrypoint>>,
            #[serde(default)]
            #[serde(deserialize_with = "double_option::deserialize")]
            args: Option<Option<RawProgramEntrypoint>>,
            #[serde_as(as = "MapPreventDuplicates<_, _>")]
            #[serde(default)]
            env: BTreeMap<String, RawProgramEnvValue>,
            #[serde(default)]
            network: Option<Network>,
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
                Ok(Self::Image(RawProgramImage {
                    image,
                    entrypoint: fields.entrypoint.flatten().unwrap_or_default(),
                    common: RawProgramCommon {
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
                Ok(Self::Path(RawProgramPath {
                    path,
                    args: fields.args.flatten().unwrap_or_default(),
                    common: RawProgramCommon {
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
                        "program.env is not supported with program.vm; configure guest startup \
                         with program.vm.cloud_init.user_data or vendor_data",
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
                Ok(Self::Vm(RawProgramVmField(vm)))
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

impl Serialize for RawProgram {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct VmProgramEnvelope<'a> {
            vm: &'a RawVmProgram,
        }

        match self {
            Self::Image(program) => program.serialize(serializer),
            Self::Path(program) => program.serialize(serializer),
            Self::Vm(program) => VmProgramEnvelope { vm: &program.0 }.serialize(serializer),
        }
    }
}

impl RawProgram {
    pub fn resolve(self, origin: Option<&Path>) -> Result<(Program, bool), Error> {
        let mut resolver = FileReferenceResolver::new(origin);
        let program = match self {
            Self::Image(program) => Program::Image(program.resolve(&mut resolver)?),
            Self::Path(program) => Program::Path(program.resolve(&mut resolver)?),
            Self::Vm(program) => Program::Vm(ProgramVmField(program.0.resolve(&mut resolver)?)),
        };
        Ok((program, resolver.used_refs))
    }
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, bon::Builder,
)]
#[builder(on(String, into))]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RawProgramImage {
    pub image: InlineStringSpec,
    #[serde(default)]
    #[builder(default)]
    pub entrypoint: RawProgramEntrypoint,
    #[serde(flatten)]
    pub common: RawProgramCommon,
}

impl RawProgramImage {
    fn resolve(self, resolver: &mut FileReferenceResolver<'_>) -> Result<ProgramImage, Error> {
        Ok(ProgramImage {
            image: resolver.resolve_program_string(
                self.image,
                "/program/image",
                validate_program_image,
            )?,
            entrypoint: self
                .entrypoint
                .resolve("/program/entrypoint", &mut |value, pointer| {
                    resolver.resolve_inline_string(value, pointer)
                })?,
            common: self.common.resolve("/program", resolver)?,
        })
    }
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, bon::Builder,
)]
#[builder(on(String, into))]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RawProgramPath {
    pub path: InlineStringSpec,
    #[serde(default)]
    #[builder(default)]
    pub args: RawProgramEntrypoint,
    #[serde(flatten)]
    pub common: RawProgramCommon,
}

impl RawProgramPath {
    fn resolve(self, resolver: &mut FileReferenceResolver<'_>) -> Result<ProgramPath, Error> {
        Ok(ProgramPath {
            path: resolver.resolve_program_string(
                self.path,
                "/program/path",
                validate_program_path,
            )?,
            args: self.args.resolve("/program/args", &mut |value, pointer| {
                resolver.resolve_inline_string(value, pointer)
            })?,
            common: self.common.resolve("/program", resolver)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct RawProgramVmField(pub RawVmProgram);

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, bon::Builder,
)]
#[builder(on(String, into))]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RawVmProgram {
    pub image: InlineStringSpec,
    pub cpus: VmScalarU32,
    pub memory_mib: VmScalarU32,
    #[serde(default)]
    pub network: Option<VmNetwork>,
    #[serde(default)]
    #[builder(default)]
    pub mounts: Vec<ProgramMount>,
    #[serde(default)]
    pub cloud_init: RawVmCloudInit,
}

impl<'de> Deserialize<'de> for RawProgramVmField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        RawVmProgram::deserialize(deserializer).map(Self)
    }
}

impl RawVmProgram {
    fn resolve(self, resolver: &mut FileReferenceResolver<'_>) -> Result<VmProgram, Error> {
        Ok(VmProgram {
            image: resolver.resolve_program_string(
                self.image,
                "/program/vm/image",
                validate_program_image,
            )?,
            cpus: self.cpus,
            memory_mib: self.memory_mib,
            network: self.network,
            mounts: self.mounts,
            cloud_init: self.cloud_init.resolve(resolver)?,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RawVmCloudInit {
    #[serde(default)]
    pub user_data: Option<InlineStringSpec>,
    #[serde(default)]
    pub vendor_data: Option<InlineStringSpec>,
}

impl RawVmCloudInit {
    fn resolve(self, resolver: &mut FileReferenceResolver<'_>) -> Result<VmCloudInit, Error> {
        Ok(VmCloudInit {
            user_data: self
                .user_data
                .map(|value| {
                    resolver.resolve_inline_string(value, "/program/vm/cloud_init/user_data")
                })
                .transpose()?,
            vendor_data: self
                .vendor_data
                .map(|value| {
                    resolver.resolve_inline_string(value, "/program/vm/cloud_init/vendor_data")
                })
                .transpose()?,
        })
    }
}

#[serde_as]
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
pub struct RawProgramCommon {
    #[serde_as(as = "MapPreventDuplicates<_, _>")]
    #[serde(default)]
    #[builder(default)]
    pub env: BTreeMap<String, RawProgramEnvValue>,
    #[serde(default)]
    pub network: Option<Network>,
    #[serde(default)]
    #[builder(default)]
    pub mounts: Vec<ProgramMount>,
}

impl RawProgramCommon {
    fn resolve(
        self,
        pointer: &str,
        resolver: &mut FileReferenceResolver<'_>,
    ) -> Result<ProgramCommon, Error> {
        let env = self
            .env
            .into_iter()
            .map(|(key, value)| {
                let pointer = pointer_with_segment(&pointer_with_segment(pointer, "env"), &key);
                value
                    .resolve(&pointer, &mut |value, pointer| {
                        resolver.resolve_inline_string(value, pointer)
                    })
                    .map(|value| (key, value))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        Ok(ProgramCommon {
            env,
            network: self.network,
            mounts: self.mounts,
        })
    }
}

impl From<Program> for RawProgram {
    fn from(value: Program) -> Self {
        match value {
            Program::Image(program) => Self::Image(program.into()),
            Program::Path(program) => Self::Path(program.into()),
            Program::Vm(program) => Self::Vm(program.into()),
        }
    }
}

impl From<&Program> for RawProgram {
    fn from(value: &Program) -> Self {
        value.clone().into()
    }
}

impl From<ProgramImage> for RawProgramImage {
    fn from(value: ProgramImage) -> Self {
        Self {
            image: value.image.into(),
            entrypoint: value.entrypoint.into(),
            common: value.common.into(),
        }
    }
}

impl From<ProgramPath> for RawProgramPath {
    fn from(value: ProgramPath) -> Self {
        Self {
            path: value.path.into(),
            args: value.args.into(),
            common: value.common.into(),
        }
    }
}

impl From<ProgramVmField> for RawProgramVmField {
    fn from(value: ProgramVmField) -> Self {
        Self(value.0.into())
    }
}

impl From<VmProgram> for RawVmProgram {
    fn from(value: VmProgram) -> Self {
        Self {
            image: value.image.into(),
            cpus: value.cpus,
            memory_mib: value.memory_mib,
            network: value.network,
            mounts: value.mounts,
            cloud_init: value.cloud_init.into(),
        }
    }
}

impl From<VmCloudInit> for RawVmCloudInit {
    fn from(value: VmCloudInit) -> Self {
        Self {
            user_data: value.user_data.map(InlineStringSpec::Inline),
            vendor_data: value.vendor_data.map(InlineStringSpec::Inline),
        }
    }
}

impl From<ProgramCommon> for RawProgramCommon {
    fn from(value: ProgramCommon) -> Self {
        Self {
            env: value
                .env
                .into_iter()
                .map(|(key, value)| (key, value.into()))
                .collect(),
            network: value.network,
            mounts: value.mounts,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ProgramNetworkRef<'a> {
    Common(&'a Network),
    Vm(&'a VmNetwork),
}

impl<'a> ProgramNetworkRef<'a> {
    pub fn endpoints(self) -> &'a [Endpoint] {
        match self {
            Self::Common(network) => network.endpoints.as_slice(),
            Self::Vm(network) => network.endpoints.as_slice(),
        }
    }
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, bon::Builder,
)]
#[builder(on(String, into))]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ProgramImage {
    #[serde(deserialize_with = "deserialize_program_image")]
    pub image: String,
    #[serde(default)]
    #[builder(default)]
    pub entrypoint: ProgramEntrypoint,
    #[serde(flatten)]
    pub common: ProgramCommon,
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, bon::Builder,
)]
#[builder(on(String, into))]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ProgramPath {
    #[serde(deserialize_with = "deserialize_program_path")]
    pub path: String,
    #[serde(default)]
    #[builder(default)]
    pub args: ProgramEntrypoint,
    #[serde(flatten)]
    pub common: ProgramCommon,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProgramVmField(pub VmProgram);

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, bon::Builder,
)]
#[builder(on(String, into))]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct VmProgram {
    #[serde(deserialize_with = "deserialize_program_image")]
    pub image: String,
    pub cpus: VmScalarU32,
    pub memory_mib: VmScalarU32,
    #[serde(default)]
    pub network: Option<VmNetwork>,
    #[serde(default)]
    #[builder(default)]
    pub mounts: Vec<ProgramMount>,
    #[serde(default)]
    pub cloud_init: VmCloudInit,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct VmCloudInit {
    #[serde(default)]
    pub user_data: Option<String>,
    #[serde(default)]
    pub vendor_data: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum VmScalarU32 {
    Literal(u32),
    Interpolated(String),
}

impl<'de> Deserialize<'de> for VmScalarU32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Scalar {
            Literal(u32),
            Interpolated(String),
        }

        match Scalar::deserialize(deserializer)? {
            Scalar::Literal(value) => Ok(Self::Literal(value)),
            Scalar::Interpolated(value) => {
                value
                    .parse::<InterpolatedString>()
                    .map_err(serde::de::Error::custom)?;
                Ok(Self::Interpolated(value))
            }
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct VmNetwork {
    #[serde(default)]
    pub endpoints: Vec<Endpoint>,
    #[serde(default)]
    pub egress: VmEgress,
}

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VmEgress {
    #[default]
    None,
    Optional,
}

#[serde_as]
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
pub struct ProgramCommon {
    #[serde_as(as = "MapPreventDuplicates<_, _>")]
    #[serde(default)]
    #[builder(default)]
    pub env: BTreeMap<String, ProgramEnvValue>,
    #[serde(default)]
    pub network: Option<Network>,
    #[serde(default)]
    #[builder(default)]
    pub mounts: Vec<ProgramMount>,
}

#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, bon::Builder,
)]
#[builder(on(String, into))]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ProgramMount {
    #[serde(default)]
    pub when: Option<crate::WhenPath>,
    #[serde(default)]
    pub each: Option<crate::EachPath>,
    #[serde(default)]
    pub name: Option<InterpolatedString>,
    pub path: InterpolatedString,
    #[serde(rename = "from")]
    pub source: InterpolatedString,
}

impl ProgramMount {
    pub fn is_variadic(&self) -> bool {
        self.when.is_some() || self.each.is_some()
    }

    pub fn literal_name(&self) -> Option<&str> {
        self.name.as_ref().and_then(InterpolatedString::as_literal)
    }

    pub fn literal_path(&self) -> Option<&str> {
        self.path.as_literal()
    }

    pub fn literal_source(&self) -> Option<MountSource> {
        self.source.as_literal()?.parse().ok()
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
        if let Some(name) = &self.name
            && name.visit_slot_uses(&mut visit)
        {
            return true;
        }
        if self.path.visit_slot_uses(&mut visit) || self.source.visit_slot_uses(&mut visit) {
            return true;
        }
        if let Some(MountSource::Slot(slot)) = self.literal_source() {
            visit(&slot);
        }
        false
    }

    pub fn visit_config_uses(&self, mut visit: impl FnMut(&str)) {
        if let Some(when) = &self.when {
            when.visit_config_uses(&mut visit);
        }
        if let Some(each) = &self.each {
            each.visit_config_uses(&mut visit);
        }
        if let Some(name) = &self.name {
            name.visit_config_uses(&mut visit);
        }
        self.path.visit_config_uses(&mut visit);
        self.source.visit_config_uses(&mut visit);
        if let Some(source) = self.literal_source() {
            match source {
                MountSource::Config(path) => visit(&path),
                MountSource::Resource(_) | MountSource::Slot(_) | MountSource::Framework(_) => {}
            }
        }
    }
}

#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, DeserializeFromStr, SerializeDisplay,
)]
#[non_exhaustive]
pub enum MountSource {
    Config(String),
    Resource(String),
    Slot(String),
    Framework(FrameworkCapabilityName),
}

impl fmt::Display for MountSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MountSource::Config(path) => write_prefixed(f, "config", path),
            MountSource::Resource(name) => write_prefixed(f, "resources", name),
            MountSource::Slot(name) => write_prefixed(f, "slots", name),
            MountSource::Framework(name) => write!(f, "framework.{name}"),
        }
    }
}

impl FromStr for MountSource {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        fn ensure_path(input: &str, path: &str) -> Result<String, Error> {
            if path.is_empty() {
                return Err(Error::InvalidMountSource {
                    mount: input.to_string(),
                    message: "expected a path segment".to_string(),
                });
            }
            if path.split('.').any(|seg| seg.is_empty()) {
                return Err(Error::InvalidMountSource {
                    mount: input.to_string(),
                    message: "path contains an empty segment".to_string(),
                });
            }
            Ok(path.to_string())
        }

        if input == "config" {
            return Ok(MountSource::Config(String::new()));
        }
        if let Some(path) = input.strip_prefix("config.") {
            return Ok(MountSource::Config(ensure_path(input, path)?));
        }
        if let Some(name) = input.strip_prefix("resources.") {
            let name = ensure_path(input, name)?;
            return Ok(MountSource::Resource(name));
        }
        if let Some(name) = input.strip_prefix("slots.") {
            let name = ensure_path(input, name)?;
            return Ok(MountSource::Slot(name));
        }
        if let Some(name) = input.strip_prefix("framework.") {
            let name = ensure_path(input, name)?;
            let cap = FrameworkCapabilityName::try_from(name.as_str()).map_err(|_| {
                Error::InvalidMountSource {
                    mount: input.to_string(),
                    message: "framework capability name contains an invalid character".to_string(),
                }
            })?;
            return Ok(MountSource::Framework(cap));
        }
        if input == "framework" {
            return Err(Error::InvalidMountSource {
                mount: input.to_string(),
                message: "framework mounts require a capability name (framework.<capability>)"
                    .to_string(),
            });
        }

        Err(Error::InvalidMountSource {
            mount: input.to_string(),
            message: "unknown mount source".to_string(),
        })
    }
}

struct FileReferenceResolver<'a> {
    origin: Option<&'a Path>,
    used_refs: bool,
}

impl<'a> FileReferenceResolver<'a> {
    fn new(origin: Option<&'a Path>) -> Self {
        Self {
            origin,
            used_refs: false,
        }
    }

    fn resolve_inline_string(
        &mut self,
        value: InlineStringSpec,
        pointer: &str,
    ) -> Result<String, Error> {
        match value {
            InlineStringSpec::Inline(value) => Ok(value),
            InlineStringSpec::File(file_ref) => {
                self.used_refs = true;
                let path = self.resolve_path(file_ref.file.as_str(), pointer)?;
                std::fs::read_to_string(&path).map_err(|err| Error::ProgramFileReference {
                    pointer: pointer.to_string(),
                    path: display_file_reference_path(file_ref.file.as_str(), &path),
                    message: err.to_string(),
                })
            }
        }
    }

    fn resolve_program_string(
        &mut self,
        value: InlineStringSpec,
        pointer: &str,
        validate: impl FnOnce(String) -> Result<String, Error>,
    ) -> Result<String, Error> {
        match value {
            InlineStringSpec::Inline(value) => Ok(value),
            InlineStringSpec::File(file_ref) => {
                self.used_refs = true;
                let path = self.resolve_path(file_ref.file.as_str(), pointer)?;
                let value =
                    std::fs::read_to_string(&path).map_err(|err| Error::ProgramFileReference {
                        pointer: pointer.to_string(),
                        path: display_file_reference_path(file_ref.file.as_str(), &path),
                        message: err.to_string(),
                    })?;
                validate(value)
            }
        }
    }

    fn resolve_path(&self, raw: &str, pointer: &str) -> Result<PathBuf, Error> {
        if raw.is_empty() {
            return Err(Error::ProgramFileReference {
                pointer: pointer.to_string(),
                path: raw.to_string(),
                message: "path must not be empty".to_string(),
            });
        }

        let path = Path::new(raw);
        if path.is_absolute() {
            return Ok(path.to_path_buf());
        }

        let Some(origin) = self.origin else {
            return Err(Error::ProgramFileReference {
                pointer: pointer.to_string(),
                path: raw.to_string(),
                message: "relative file references require a file-backed manifest".to_string(),
            });
        };

        Ok(origin.join(path))
    }
}

fn write_prefixed(f: &mut fmt::Formatter<'_>, prefix: &str, path: &str) -> fmt::Result {
    if path.is_empty() {
        f.write_str(prefix)
    } else {
        write!(f, "{prefix}.{path}")
    }
}

fn validate_program_image(image: String) -> Result<String, Error> {
    image.parse::<InterpolatedString>()?;
    Ok(image)
}

fn validate_program_path(path: String) -> Result<String, Error> {
    path.parse::<InterpolatedString>()?;
    Ok(path)
}

fn deserialize_program_image<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let image = String::deserialize(deserializer)?;
    validate_program_image(image).map_err(serde::de::Error::custom)
}

fn deserialize_program_path<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let path = String::deserialize(deserializer)?;
    validate_program_path(path).map_err(serde::de::Error::custom)
}

fn parse_pointer(pointer: &str) -> PointerBuf {
    if pointer.is_empty() {
        PointerBuf::new()
    } else {
        PointerBuf::parse(pointer.to_string()).expect("pointer must be valid")
    }
}

fn pointer_with_segment(pointer: &str, segment: &str) -> String {
    let mut pointer = parse_pointer(pointer);
    pointer.push_back(segment);
    pointer.to_string()
}

fn display_file_reference_path(raw: &str, resolved: &Path) -> String {
    if Path::new(raw).is_absolute() {
        resolved.display().to_string()
    } else {
        raw.to_string()
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
    Docker,
    A2a,
    Storage,
}

impl fmt::Display for CapabilityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            CapabilityKind::Mcp => "mcp",
            CapabilityKind::Llm => "llm",
            CapabilityKind::Http => "http",
            CapabilityKind::Docker => "docker",
            CapabilityKind::A2a => "a2a",
            CapabilityKind::Storage => "storage",
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
            Self::Mcp | Self::Llm | Self::Http | Self::A2a => CapabilityTransport::Http,
            Self::Docker | Self::Storage => CapabilityTransport::NonNetwork,
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
    Resources,
}

impl fmt::Display for BindingSourceRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Component(component) => component.fmt(f),
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

fn is_resources_ref(input: &str) -> bool {
    input == "resources"
}

fn parse_binding_target_ref(input: &str) -> Result<LocalComponentRef, Error> {
    if is_framework_ref(input) || is_resources_ref(input) {
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
