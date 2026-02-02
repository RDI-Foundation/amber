use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    str::FromStr,
    sync::OnceLock,
};

use bon::bon;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::{MapPreventDuplicates, serde_as};

use crate::{
    error::Error,
    framework::{framework_capabilities, framework_capability},
    names::{BindingName, ChildName, ExportName, ProvideName, SlotName, ensure_name_no_dot},
    refs::{ManifestDigest, ManifestRef, ManifestUrl},
    schema::{
        Binding, BindingSource, BindingSourceRef, BindingTarget, ComponentDecl, ConfigSchema,
        EnvironmentDecl, ExportTarget, LocalComponentRef, Program, ProvideDecl, RawBinding,
        RawExportTarget, SlotDecl,
    },
};

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
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

fn validate_manifest_ref(reference: &ManifestRef) -> Result<(), Error> {
    // Re-parse the string form to enforce the same invariants serde enforces for manifests loaded
    // from JSON/JSON5, even when the user mutates the public fields programmatically.
    let _ = reference.url.as_str().parse::<ManifestUrl>()?;
    Ok(())
}

fn validate_component_manifest_refs(
    components: &BTreeMap<String, ComponentDecl>,
) -> Result<(), Error> {
    for decl in components.values() {
        match decl {
            ComponentDecl::Reference(reference) => validate_manifest_ref(reference)?,
            ComponentDecl::Object(obj) => validate_manifest_ref(&obj.manifest)?,
        }
    }
    Ok(())
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
        LocalComponentRef::Self_ => Err(Error::BindingTargetSelfSlot { slot }),
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
            if let Some((slot_name, _)) = ctx.slots.get_key_value(capability.as_str()) {
                return Ok(BindingSource::SelfSlot(slot_name.clone()));
            }
            if let Some((provide_name, _)) = ctx.provides.get_key_value(capability.as_str()) {
                return Ok(BindingSource::SelfProvide(provide_name.clone()));
            }
            Err(Error::UnknownBindingSource { capability })
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
                return Ok(ExportTarget::SelfProvide(provide_name.clone()));
            }
            if let Some((slot_name, _)) = ctx.slots.get_key_value(target.name.as_str()) {
                return Ok(ExportTarget::SelfSlot(slot_name.clone()));
            }
            Err(Error::UnknownExportTarget {
                export: export_name.to_string(),
                target: target.name,
            })
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
            metadata,
        } = self;

        if let Some(schema) = config_schema.as_ref() {
            ConfigSchema::validate_value(&schema.0)?;
        }
        validate_component_manifest_refs(&components)?;
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
            metadata,
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
    metadata: Option<Value>,
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
            metadata: None,
        }
        .validate()
        .expect("empty manifest is valid")
    }

    pub fn metadata(&self) -> Option<&Value> {
        self.metadata.as_ref()
    }

    pub fn digest(&self) -> ManifestDigest {
        self.digest
    }
}

#[bon]
impl Manifest {
    #[builder]
    pub fn new(
        #[builder(default = Version::new(0, 1, 0))] manifest_version: Version,
        program: Option<Program>,
        #[builder(default)] components: BTreeMap<String, ComponentDecl>,
        #[builder(default)] environments: BTreeMap<String, EnvironmentDecl>,
        config_schema: Option<Value>,
        #[builder(default)] slots: BTreeMap<String, SlotDecl>,
        #[builder(default)] provides: BTreeMap<String, ProvideDecl>,
        #[builder(default)] bindings: BTreeSet<RawBinding>,
        #[builder(default)] exports: BTreeMap<String, RawExportTarget>,
        metadata: Option<Value>,
    ) -> Result<Self, Error> {
        let config_schema = config_schema.map(ConfigSchema::try_from).transpose()?;

        RawManifest {
            manifest_version,
            program,
            components,
            environments,
            config_schema,
            slots,
            provides,
            bindings,
            exports,
            metadata,
        }
        .validate()
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
                    BindingSource::SelfSlot(name) => (
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
                    ExportTarget::SelfSlot(slot) => RawExportTarget {
                        component: LocalComponentRef::Self_,
                        name: slot.to_string(),
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
            metadata: manifest.metadata.clone(),
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

#[cfg(test)]
mod tests;
