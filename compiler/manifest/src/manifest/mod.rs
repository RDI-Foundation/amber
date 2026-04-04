use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    path::Path,
    str::FromStr,
    sync::OnceLock,
};

use amber_config as rc;
use bon::bon;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::{MapPreventDuplicates, serde_as};

use crate::{
    error::Error,
    framework::{framework_capabilities, framework_capability},
    names::{
        ChildName, ExportName, ProvideName, ResourceName, SlotName, TemplateName,
        ensure_name_no_dot,
    },
    refs::{ManifestDigest, ManifestRef, ManifestUrl},
    schema::{
        Binding, BindingSource, BindingSourceRef, BindingTarget, CapabilityKind,
        ChildTemplateAllowedManifests, ChildTemplateDecl, ComponentDecl, ConfigSchema,
        EnvironmentDecl, ExportTarget, LocalCapabilityRefKind, LocalComponentRef, ManifestBinding,
        MountSource, Program, ProvideDecl, RawBinding, RawExportTarget, RawProgram, ResourceDecl,
        SlotDecl, VmScalarU32,
    },
};

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RawManifest {
    pub manifest_version: Version,
    #[serde(default)]
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub experimental_features: BTreeSet<ExperimentalFeature>,
    #[serde(default)]
    pub program: Option<RawProgram>,
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
    #[serde_as(as = "MapPreventDuplicates<_, _>")]
    #[serde(default)]
    pub resources: BTreeMap<String, ResourceDecl>,
    #[serde_as(as = "MapPreventDuplicates<_, _>")]
    #[serde(default)]
    pub child_templates: BTreeMap<String, ChildTemplateDecl>,
    #[serde(default)]
    pub bindings: Vec<RawBinding>,
    #[serde_as(as = "MapPreventDuplicates<_, _>")]
    #[serde(default)]
    pub exports: BTreeMap<String, RawExportTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExperimentalFeature {
    Docker,
    Kvm,
}

impl fmt::Display for ExperimentalFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExperimentalFeature::Docker => f.write_str("docker"),
            ExperimentalFeature::Kvm => f.write_str("kvm"),
        }
    }
}

const SUPPORTED_MANIFEST_VERSION_REQ: &str = ">=0.1.0, <1.0.0";

fn supported_manifest_version_req() -> &'static VersionReq {
    static REQ: OnceLock<VersionReq> = OnceLock::new();
    REQ.get_or_init(|| {
        VersionReq::parse(SUPPORTED_MANIFEST_VERSION_REQ)
            .expect("supported manifest version requirement must be valid")
    })
}

struct UnsupportedProgramSyntax {
    feature: &'static str,
    pointer: String,
}

fn validate_program_syntax_manifest_version(
    manifest_version: &Version,
    program: Option<&Program>,
) -> Result<(), Error> {
    let Some(program) = program else {
        return Ok(());
    };

    let Some((required_version, unsupported)) =
        find_unsupported_program_syntax(program, manifest_version)
    else {
        return Ok(());
    };

    Err(Error::UnsupportedProgramSyntaxForManifestVersion {
        manifest_version: Box::new(manifest_version.clone()),
        required_version,
        feature: unsupported.feature,
        pointer: unsupported.pointer,
    })
}

fn find_unsupported_program_syntax(
    program: &Program,
    manifest_version: &Version,
) -> Option<(&'static str, UnsupportedProgramSyntax)> {
    if manifest_version < &Version::new(0, 2, 0)
        && let Some(syntax) = program.first_conditional_syntax()
    {
        return Some((
            syntax.required_version(),
            UnsupportedProgramSyntax {
                feature: syntax.feature(),
                pointer: syntax.pointer(),
            },
        ));
    }

    if manifest_version < &Version::new(0, 3, 0)
        && let Some(syntax) = program.first_variadic_syntax()
    {
        return Some((
            syntax.required_version(),
            UnsupportedProgramSyntax {
                feature: syntax.feature(),
                pointer: syntax.pointer(),
            },
        ));
    }

    None
}

struct ValidateCtx<'a> {
    components: &'a BTreeMap<ChildName, ComponentDecl>,
    slots: &'a BTreeMap<SlotName, SlotDecl>,
    provides: &'a BTreeMap<ProvideName, ProvideDecl>,
    resources: &'a BTreeMap<ResourceName, ResourceDecl>,
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

fn convert_resources(
    resources: BTreeMap<String, ResourceDecl>,
) -> Result<BTreeMap<ResourceName, ResourceDecl>, Error> {
    resources
        .into_iter()
        .map(|(name, decl)| Ok((ResourceName::try_from(name)?, decl)))
        .collect::<Result<BTreeMap<_, _>, Error>>()
}

fn convert_child_templates(
    child_templates: BTreeMap<String, ChildTemplateDecl>,
) -> Result<BTreeMap<TemplateName, ChildTemplateDecl>, Error> {
    child_templates
        .into_iter()
        .map(|(name, decl)| Ok((TemplateName::try_from(name)?, decl)))
        .collect::<Result<BTreeMap<_, _>, Error>>()
}

fn validate_resource_decls(resources: &BTreeMap<ResourceName, ResourceDecl>) -> Result<(), Error> {
    for (name, resource) in resources {
        if resource.kind != CapabilityKind::Storage {
            return Err(Error::UnsupportedResourceKind {
                name: name.to_string(),
                kind: resource.kind,
            });
        }
    }

    Ok(())
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

fn validate_child_templates(
    child_templates: &BTreeMap<TemplateName, ChildTemplateDecl>,
    slots: &BTreeMap<SlotName, SlotDecl>,
    _bindings: &[RawBinding],
) -> Result<(), Error> {
    let declares_component_slot = slots
        .values()
        .any(|slot| slot.decl.kind == CapabilityKind::Component);
    if !child_templates.is_empty() && !declares_component_slot {
        return Err(Error::ChildTemplatesRequireComponentSlot);
    }

    for (template_name, template) in child_templates {
        match (&template.manifest, &template.allowed_manifests) {
            (Some(_), None) | (None, Some(_)) => {}
            (Some(_), Some(_)) => {
                return Err(Error::InvalidChildTemplate {
                    template: template_name.to_string(),
                    message: "exactly one of `manifest` or `allowed_manifests` must be present"
                        .to_string(),
                });
            }
            (None, None) => {
                return Err(Error::InvalidChildTemplate {
                    template: template_name.to_string(),
                    message: "one of `manifest` or `allowed_manifests` is required".to_string(),
                });
            }
        }

        if let Some(reference) = &template.manifest {
            validate_manifest_ref(reference)?;
        }

        if let Some(allowed) = &template.allowed_manifests {
            match allowed {
                ChildTemplateAllowedManifests::Refs(refs) => {
                    if refs.is_empty() {
                        return Err(Error::InvalidChildTemplate {
                            template: template_name.to_string(),
                            message: "`allowed_manifests` must not be empty".to_string(),
                        });
                    }
                    for reference in refs {
                        validate_manifest_ref(reference)?;
                    }
                }
                ChildTemplateAllowedManifests::Selector(selector) => {
                    if selector.root.trim().is_empty() {
                        return Err(Error::InvalidChildTemplate {
                            template: template_name.to_string(),
                            message: "`allowed_manifests.root` must not be empty".to_string(),
                        });
                    }
                }
            }
        }

        for slot_name in template.bindings.keys() {
            ensure_name_no_dot(slot_name, "slot")?;
        }

        for export_name in &template.visible_exports {
            ensure_name_no_dot(export_name, "export")?;
        }
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

fn require_framework_capability_feature(
    capability: &str,
    required_feature: Option<ExperimentalFeature>,
    enabled_features: &BTreeSet<ExperimentalFeature>,
) -> Result<(), Error> {
    let Some(feature) = required_feature else {
        return Ok(());
    };
    if enabled_features.contains(&feature) {
        return Ok(());
    }
    Err(Error::FrameworkCapabilityRequiresFeature {
        capability: capability.to_string(),
        feature: feature.to_string(),
    })
}

fn resolve_binding_source(
    ctx: &ValidateCtx<'_>,
    from: BindingSourceRef,
    capability: String,
    enabled_features: &BTreeSet<ExperimentalFeature>,
) -> Result<BindingSource, Error> {
    match from {
        BindingSourceRef::Slots => {
            let (slot_name, _) = ctx
                .slots
                .get_key_value(capability.as_str())
                .ok_or_else(|| Error::UnknownBindingSource {
                    reference: format!("slots.{capability}"),
                    expected: "slot",
                })?;
            Ok(BindingSource::SelfSlot(slot_name.clone()))
        }
        BindingSourceRef::Provides => {
            let (provide_name, _) =
                ctx.provides
                    .get_key_value(capability.as_str())
                    .ok_or_else(|| Error::UnknownBindingSource {
                        reference: format!("provides.{capability}"),
                        expected: "provide",
                    })?;
            Ok(BindingSource::SelfProvide(provide_name.clone()))
        }
        BindingSourceRef::Component(LocalComponentRef::Self_) => {
            if let Some((slot_name, _)) = ctx.slots.get_key_value(capability.as_str()) {
                return Ok(BindingSource::SelfSlot(slot_name.clone()));
            }
            if let Some((provide_name, _)) = ctx.provides.get_key_value(capability.as_str()) {
                return Ok(BindingSource::SelfProvide(provide_name.clone()));
            }
            Err(Error::UnknownBindingSource {
                reference: format!("self.{capability}"),
                expected: "slot or provide",
            })
        }
        BindingSourceRef::Resources => {
            let (resource_name, _) = ctx
                .resources
                .get_key_value(capability.as_str())
                .ok_or_else(|| Error::UnknownBindingResource {
                    resource: capability.clone(),
                })?;
            Ok(BindingSource::Resource(resource_name.clone()))
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
            require_framework_capability_feature(
                capability.as_str(),
                spec.required_experimental_feature,
                enabled_features,
            )?;
            Ok(BindingSource::Framework(spec.name.clone()))
        }
    }
}

fn build_bindings(
    bindings: Vec<RawBinding>,
    ctx: &ValidateCtx<'_>,
    enabled_features: &BTreeSet<ExperimentalFeature>,
) -> Result<Vec<ManifestBinding>, Error> {
    let mut bindings_out = Vec::with_capacity(bindings.len());

    for binding in bindings {
        let RawBinding {
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

        let target = resolve_binding_target(ctx, to, slot)?;
        let source = resolve_binding_source(ctx, from, capability, enabled_features)?;

        bindings_out.push(ManifestBinding {
            target,
            binding: Binding { from: source, weak },
        });
    }

    Ok(bindings_out)
}

fn resolve_export_target(
    ctx: &ValidateCtx<'_>,
    export_name: &ExportName,
    target: RawExportTarget,
) -> Result<ExportTarget, Error> {
    match target.component {
        LocalComponentRef::Self_ if target.local_kind == Some(LocalCapabilityRefKind::Provide) => {
            let (provide_name, _) = ctx
                .provides
                .get_key_value(target.name.as_str())
                .ok_or_else(|| Error::UnknownExportTarget {
                    export: export_name.to_string(),
                    target: target.name.clone(),
                    expected: "provide",
                })?;
            Ok(ExportTarget::SelfProvide(provide_name.clone()))
        }
        LocalComponentRef::Self_ if target.local_kind == Some(LocalCapabilityRefKind::Slot) => {
            let (slot_name, _) =
                ctx.slots
                    .get_key_value(target.name.as_str())
                    .ok_or_else(|| Error::UnknownExportTarget {
                        export: export_name.to_string(),
                        target: target.name.clone(),
                        expected: "slot",
                    })?;
            Ok(ExportTarget::SelfSlot(slot_name.clone()))
        }
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
                expected: "capability",
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
    let mut unconditional_literal_endpoints = BTreeSet::new();
    let mut possible_literal_endpoints = BTreeSet::new();
    let mut has_opaque_endpoint_name = false;
    if let Some(program) = program
        && let Some(network) = program.network()
    {
        for endpoint in network.endpoints() {
            let Some(name) = endpoint.name.as_literal() else {
                has_opaque_endpoint_name = true;
                continue;
            };

            possible_literal_endpoints.insert(name);

            if endpoint.when.is_none()
                && endpoint.each.is_none()
                && !unconditional_literal_endpoints.insert(name)
            {
                return Err(Error::DuplicateEndpointName {
                    name: name.to_string(),
                });
            }
        }
    }

    for (provide_name, provide) in provides {
        if provide.decl.kind == CapabilityKind::Storage {
            return Err(Error::UnsupportedProvideKind {
                name: provide_name.to_string(),
                kind: provide.decl.kind,
            });
        }

        let Some(endpoint) = provide.endpoint.as_deref() else {
            return Err(Error::MissingProvideEndpoint {
                name: provide_name.to_string(),
            });
        };

        if !possible_literal_endpoints.contains(endpoint) && !has_opaque_endpoint_name {
            return Err(Error::UnknownEndpoint {
                name: endpoint.to_string(),
            });
        }
    }

    Ok(())
}

fn validate_mount_literal_path(path: &str) -> Result<(), Error> {
    if !path.starts_with('/') {
        return Err(Error::InvalidMountPath {
            path: path.to_string(),
            message: "mount path must be absolute".to_string(),
        });
    }
    if path.split('/').any(|seg| seg == "..") {
        return Err(Error::InvalidMountPath {
            path: path.to_string(),
            message: "mount path must not contain `..`".to_string(),
        });
    }
    Ok(())
}

fn validate_program_file_mount_source(
    display_path: &str,
    literal_path: Option<&str>,
    config_schema: Option<&ConfigSchema>,
) -> Result<(), Error> {
    let Some(schema) = config_schema else {
        return Err(Error::InvalidMountConfigPath {
            path: display_path.to_string(),
            message: "component has no config_schema".to_string(),
        });
    };

    let Some(path) = literal_path else {
        return Ok(());
    };

    validate_mount_path(&schema.0, path).map_err(|message| Error::InvalidMountConfigPath {
        path: path.to_string(),
        message,
    })?;

    Ok(())
}

fn validate_mounts(
    program: Option<&Program>,
    config_schema: Option<&ConfigSchema>,
    resources: &BTreeMap<ResourceName, ResourceDecl>,
    slots: &BTreeMap<SlotName, SlotDecl>,
    enabled_features: &BTreeSet<ExperimentalFeature>,
) -> Result<(), Error> {
    let Some(program) = program else {
        return Ok(());
    };

    let mut names = BTreeSet::new();
    let mut paths = BTreeSet::new();

    for mount in program.mounts() {
        let is_variadic = mount.is_variadic();

        if let Some(name) = mount.literal_name() {
            ensure_name_no_dot(name, "mount")?;
            if !is_variadic && !names.insert(name) {
                return Err(Error::DuplicateMountName {
                    name: name.to_string(),
                });
            }
        }

        if let Some(path) = mount.literal_path() {
            validate_mount_literal_path(path)?;
            if !is_variadic && !paths.insert(path) {
                return Err(Error::DuplicateMountPath {
                    path: path.to_string(),
                });
            }
        }

        if let Some(source) = mount.source.as_literal() {
            match source.parse::<MountSource>()? {
                MountSource::Config(path) => {
                    validate_program_file_mount_source(&path, Some(&path), config_schema)?;
                }
                MountSource::Resource(resource) => {
                    if !resources.contains_key(resource.as_str()) {
                        return Err(Error::UnknownMountResource { resource });
                    }
                }
                MountSource::Framework(name) => {
                    let capability = name.as_str();
                    let Some(spec) = framework_capability(capability) else {
                        return Err(Error::UnknownFrameworkCapability {
                            capability: capability.to_string(),
                            help: framework_capability_help(),
                        });
                    };
                    if spec.decl.kind == CapabilityKind::Component {
                        return Err(Error::UnsupportedMountSource {
                            mount: format!("framework.{capability}"),
                        });
                    }
                    require_framework_capability_feature(
                        capability,
                        spec.required_experimental_feature,
                        enabled_features,
                    )?;
                }
                MountSource::Slot(slot) => {
                    let Some(slot_decl) = slots.get(slot.as_str()) else {
                        return Err(Error::UnknownMountSlot { slot: slot.clone() });
                    };
                    if slot_decl.decl.kind != CapabilityKind::Storage {
                        return Err(Error::MountSlotRequiresStorage {
                            slot: slot.clone(),
                            kind: slot_decl.decl.kind,
                        });
                    }
                }
            }
        }
    }

    Ok(())
}

fn validate_mount_path(schema: &Value, path: &str) -> Result<(), String> {
    match rc::schema_lookup(schema, path) {
        Ok(rc::SchemaLookup::Found) | Ok(rc::SchemaLookup::Unknown) => Ok(()),
        Err(err) => Err(err.to_string()),
    }
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
        self.validate_with_origin(None)
            .map(|(manifest, _)| manifest)
    }

    pub fn validate_with_origin(self, origin: Option<&Path>) -> Result<(Manifest, bool), Error> {
        self.validate_version()?;

        let RawManifest {
            manifest_version,
            experimental_features,
            program,
            components,
            environments,
            config_schema,
            slots,
            provides,
            resources,
            child_templates,
            bindings,
            exports,
            metadata,
        } = self;

        let (program, used_file_refs) = program
            .map(|program| program.resolve(origin))
            .transpose()?
            .map_or((None, false), |(program, used)| (Some(program), used));

        validate_program_syntax_manifest_version(&manifest_version, program.as_ref())?;

        if let Some(schema) = config_schema.as_ref() {
            ConfigSchema::validate_value(&schema.0)?;
        }
        validate_component_manifest_refs(&components)?;
        validate_environment_names(&environments)?;

        let components = convert_components(components)?;
        let slots = convert_slots(slots)?;
        let provides = convert_provides(provides)?;
        let resources = convert_resources(resources)?;
        let child_templates = convert_child_templates(child_templates)?;

        validate_environment_extends(&environments)?;
        validate_environment_cycles(&environments)?;
        validate_component_environments(&components, &environments)?;
        validate_no_ambiguous_capability(&slots, &provides)?;
        validate_resource_decls(&resources)?;
        validate_child_templates(&child_templates, &slots, &bindings)?;

        let ctx = ValidateCtx {
            components: &components,
            slots: &slots,
            provides: &provides,
            resources: &resources,
        };

        let bindings_out = build_bindings(bindings, &ctx, &experimental_features)?;
        let exports_out = build_exports(exports, &ctx)?;
        validate_endpoints(program.as_ref(), &provides)?;
        validate_mounts(
            program.as_ref(),
            config_schema.as_ref(),
            &resources,
            &slots,
            &experimental_features,
        )?;

        if let Some(program) = program.as_ref() {
            match program {
                Program::Image(program) if program.entrypoint.is_empty() => {
                    return Err(Error::EmptyEntrypoint);
                }
                Program::Path(program) if program.path.trim().is_empty() => {
                    return Err(Error::EmptyProgramPath);
                }
                Program::Vm(program) if program.0.image.trim().is_empty() => {
                    return Err(Error::EmptyVmImage);
                }
                Program::Vm(program) if matches!(program.0.cpus, VmScalarU32::Literal(0)) => {
                    return Err(Error::InvalidVmCpus);
                }
                Program::Vm(program) if matches!(program.0.memory_mib, VmScalarU32::Literal(0)) => {
                    return Err(Error::InvalidVmMemoryMib);
                }
                _ => {}
            }
        }

        let mut manifest = Manifest {
            manifest_version,
            experimental_features,
            program,
            components,
            environments,
            config_schema,
            slots,
            provides,
            resources,
            child_templates,
            bindings: bindings_out,
            exports: exports_out,
            metadata,
            digest: ManifestDigest::new([0; 32]),
        };
        manifest.digest = RawManifest::from(&manifest).digest();
        Ok((manifest, used_file_refs))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "RawManifest", try_from = "RawManifest")]
pub struct Manifest {
    manifest_version: Version,
    experimental_features: BTreeSet<ExperimentalFeature>,
    program: Option<Program>,
    components: BTreeMap<ChildName, ComponentDecl>,
    environments: BTreeMap<String, EnvironmentDecl>,
    config_schema: Option<ConfigSchema>,
    slots: BTreeMap<SlotName, SlotDecl>,
    provides: BTreeMap<ProvideName, ProvideDecl>,
    resources: BTreeMap<ResourceName, ResourceDecl>,
    child_templates: BTreeMap<TemplateName, ChildTemplateDecl>,
    bindings: Vec<ManifestBinding>,
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

    pub fn experimental_features(&self) -> &BTreeSet<ExperimentalFeature> {
        &self.experimental_features
    }

    pub fn uses_experimental_feature(&self, feature: ExperimentalFeature) -> bool {
        self.experimental_features.contains(&feature)
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

    pub fn resources(&self) -> &BTreeMap<ResourceName, ResourceDecl> {
        &self.resources
    }

    pub fn child_templates(&self) -> &BTreeMap<TemplateName, ChildTemplateDecl> {
        &self.child_templates
    }

    pub fn bindings(&self) -> &[ManifestBinding] {
        &self.bindings
    }

    pub fn exports(&self) -> &BTreeMap<ExportName, ExportTarget> {
        &self.exports
    }

    pub fn empty() -> Self {
        RawManifest {
            manifest_version: Version::new(0, 2, 0),
            experimental_features: BTreeSet::new(),
            program: None,
            components: BTreeMap::new(),
            environments: BTreeMap::new(),
            config_schema: None,
            slots: BTreeMap::new(),
            provides: BTreeMap::new(),
            resources: BTreeMap::new(),
            child_templates: BTreeMap::new(),
            bindings: Vec::new(),
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
        #[builder(default = Version::new(0, 2, 0))] manifest_version: Version,
        #[builder(default)] experimental_features: BTreeSet<ExperimentalFeature>,
        program: Option<Program>,
        #[builder(default)] components: BTreeMap<String, ComponentDecl>,
        #[builder(default)] environments: BTreeMap<String, EnvironmentDecl>,
        config_schema: Option<Value>,
        #[builder(default)] slots: BTreeMap<String, SlotDecl>,
        #[builder(default)] provides: BTreeMap<String, ProvideDecl>,
        #[builder(default)] resources: BTreeMap<String, ResourceDecl>,
        #[builder(default)] child_templates: BTreeMap<String, ChildTemplateDecl>,
        #[builder(default)] bindings: Vec<RawBinding>,
        #[builder(default)] exports: BTreeMap<String, RawExportTarget>,
        metadata: Option<Value>,
    ) -> Result<Self, Error> {
        let config_schema = config_schema.map(ConfigSchema::try_from).transpose()?;

        RawManifest {
            manifest_version,
            experimental_features,
            program: program.map(RawProgram::from),
            components,
            environments,
            config_schema,
            slots,
            provides,
            resources,
            child_templates,
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

        let resources = manifest
            .resources
            .iter()
            .map(|(name, decl)| (name.to_string(), decl.clone()))
            .collect();

        let child_templates = manifest
            .child_templates
            .iter()
            .map(|(name, decl)| (name.to_string(), decl.clone()))
            .collect();

        let bindings = manifest
            .bindings
            .iter()
            .map(|manifest_binding| {
                let (to, slot) = match &manifest_binding.target {
                    BindingTarget::SelfSlot(name) => (LocalComponentRef::Self_, name.to_string()),
                    BindingTarget::ChildSlot { child, slot } => (
                        LocalComponentRef::Child(child.to_string()),
                        slot.to_string(),
                    ),
                };

                let (from, capability) = match &manifest_binding.binding.from {
                    BindingSource::SelfProvide(name) => {
                        (BindingSourceRef::Provides, name.to_string())
                    }
                    BindingSource::SelfSlot(name) => (BindingSourceRef::Slots, name.to_string()),
                    BindingSource::Resource(name) => {
                        (BindingSourceRef::Resources, name.to_string())
                    }
                    BindingSource::ChildExport { child, export } => (
                        BindingSourceRef::Component(LocalComponentRef::Child(child.to_string())),
                        export.to_string(),
                    ),
                    BindingSource::Framework(name) => {
                        (BindingSourceRef::Framework, name.to_string())
                    }
                };

                RawBinding {
                    to,
                    slot,
                    from,
                    capability,
                    weak: manifest_binding.binding.weak,
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
                        local_kind: Some(LocalCapabilityRefKind::Provide),
                    },
                    ExportTarget::SelfSlot(slot) => RawExportTarget {
                        component: LocalComponentRef::Self_,
                        name: slot.to_string(),
                        local_kind: Some(LocalCapabilityRefKind::Slot),
                    },
                    ExportTarget::ChildExport { child, export } => RawExportTarget {
                        component: LocalComponentRef::Child(child.to_string()),
                        name: export.to_string(),
                        local_kind: None,
                    },
                };

                (name.to_string(), target)
            })
            .collect();

        RawManifest {
            manifest_version: manifest.manifest_version.clone(),
            experimental_features: manifest.experimental_features.clone(),
            program: manifest.program.as_ref().map(RawProgram::from),
            components,
            environments: manifest.environments.clone(),
            config_schema: manifest.config_schema.clone(),
            slots,
            provides,
            resources,
            child_templates,
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
