// Shared backend config planning: resolve program templates/mounts and compute per-component scope.
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::Path,
};

use amber_config as rc;
use amber_manifest::{
    InterpolatedPart, InterpolationSource, MountSource, ProgramArgItem, VmScalarU32,
    framework_capability,
};
use amber_scenario::{ComponentId, Scenario};
use amber_template::{
    ConditionalProgramArgTemplate, ConditionalProgramEnvTemplate, MountSpec, MountTemplateSpec,
    ProgramArgTemplate, ProgramEnvTemplate, ProgramTemplateSpec, RepeatedProgramArgTemplate,
    RepeatedProgramEnvTemplate, RepeatedTemplateSource, TemplatePart, TemplateSpec, TemplateString,
};
use base64::Engine as _;
use serde::Serialize;
use serde_json::Value;

use crate::{
    config_resolution::{
        QueryResolution, parse_query_segments, resolve_config_query_node,
        validate_config_query_syntax,
    },
    config_scope::{RuntimeConfigView, build_runtime_config_view},
    config_templates,
    slot_query::{
        SlotObject, SlotTarget, SlotValue, parse_slot_query, resolve_slot_query,
        slot_query_is_present,
    },
    targets::common::{TargetError as MeshError, component_label},
};

#[derive(Clone, Debug)]
pub(crate) struct ConfigPlan {
    pub(crate) root_leaves: Vec<rc::SchemaLeaf>,
    pub(crate) program_plans: HashMap<ComponentId, ProgramPlan>,
    pub(crate) mount_specs: HashMap<ComponentId, Vec<MountSpec>>,
    pub(crate) needs_helper: bool,
    pub(crate) needs_runtime_config: bool,
    pub(crate) runtime_views: HashMap<ComponentId, RuntimeConfigView>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExpandedEndpoint {
    pub(crate) name: String,
    pub(crate) port: u16,
    pub(crate) protocol: amber_manifest::NetworkProtocol,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct EndpointPlan {
    by_component: HashMap<ComponentId, Vec<ExpandedEndpoint>>,
}

impl EndpointPlan {
    pub(crate) fn component_endpoints(&self, id: ComponentId) -> &[ExpandedEndpoint] {
        self.by_component.get(&id).map(Vec::as_slice).unwrap_or(&[])
    }

    pub(crate) fn lookup(&self, id: ComponentId, endpoint_name: &str) -> Option<&ExpandedEndpoint> {
        self.component_endpoints(id)
            .iter()
            .find(|endpoint| endpoint.name == endpoint_name)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProgramImagePart {
    Literal(String),
    RootConfigPath(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProgramImagePlan {
    Static(String),
    RuntimeTemplate(Vec<ProgramImagePart>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProgramImageOrigin {
    ProgramImage,
    ComponentConfigPath(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProgramSupport {
    Image { backend_label: &'static str },
    Path { backend_label: &'static str },
    Vm { backend_label: &'static str },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeAddressResolution {
    Static,
    Deferred,
}

impl ProgramImagePlan {
    pub(crate) fn collect_runtime_root_paths(&self, out: &mut BTreeSet<String>) {
        let Self::RuntimeTemplate(parts) = self else {
            return;
        };
        for part in parts {
            if let ProgramImagePart::RootConfigPath(path) = part {
                out.insert(path.clone());
            }
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum ProgramPlan {
    Resolved {
        source: ProgramSourcePlan,
        entrypoint: Vec<String>,
        env: BTreeMap<String, String>,
    },
    Helper {
        source: ProgramSourcePlan,
        template_spec: TemplateSpec,
        needs_runtime_config: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum VmScalarResolutionU32 {
    Static(u32),
    RuntimeConfig(String),
}

impl ProgramPlan {
    pub(crate) fn image(&self) -> Option<&ProgramImagePlan> {
        match self {
            Self::Resolved {
                source: ProgramSourcePlan::Image { image, .. },
                ..
            }
            | Self::Helper {
                source: ProgramSourcePlan::Image { image, .. },
                ..
            } => Some(image),
            Self::Resolved { .. } | Self::Helper { .. } => None,
        }
    }

    pub(crate) fn image_origin(&self) -> Option<&ProgramImageOrigin> {
        match self {
            Self::Resolved {
                source: ProgramSourcePlan::Image { image_origin, .. },
                ..
            }
            | Self::Helper {
                source: ProgramSourcePlan::Image { image_origin, .. },
                ..
            } => Some(image_origin),
            Self::Resolved { .. } | Self::Helper { .. } => None,
        }
    }

    pub(crate) fn is_helper(&self) -> bool {
        matches!(self, Self::Helper { .. })
    }

    pub(crate) fn needs_runtime_config(&self) -> bool {
        match self {
            Self::Resolved { .. } => false,
            Self::Helper {
                needs_runtime_config,
                ..
            } => *needs_runtime_config,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfigPresence {
    Present,
    Absent,
    Runtime,
}

#[derive(Clone, Debug)]
pub(crate) enum ProgramSourcePlan {
    Image {
        image: ProgramImagePlan,
        image_origin: ProgramImageOrigin,
    },
    Path,
}

#[derive(Clone, Debug)]
pub(crate) struct RuntimeConfigPayload<'a> {
    pub(crate) root_schema_b64: String,
    pub(crate) component_cfg_template_b64: String,
    pub(crate) component_schema_b64: String,
    pub(crate) allowed_root_leaf_paths: &'a BTreeSet<String>,
}

#[derive(Clone, Debug)]
pub(crate) enum ComponentExecutionPlan<'a> {
    Resolved {
        entrypoint: &'a [String],
        env: &'a BTreeMap<String, String>,
    },
    HelperRunner {
        entrypoint_b64: Option<String>,
        env_b64: Option<String>,
        template_spec_b64: Option<String>,
        runtime_config: Option<RuntimeConfigPayload<'a>>,
        mount_spec_b64: Option<String>,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct ComponentRuntimePlan<'a> {
    pub(crate) needs_helper: bool,
    pub(crate) execution: ComponentExecutionPlan<'a>,
}

fn compose_component_config_templates(
    scenario: &Scenario,
) -> Result<HashMap<ComponentId, rc::RootConfigTemplate>, MeshError> {
    let composed =
        config_templates::compose_root_config_templates(scenario.root, &scenario.components);
    if let Some(err) = composed.errors.first() {
        return Err(MeshError::new(format!(
            "failed to compose component config templates: {}",
            err.message
        )));
    }
    Ok(composed.templates)
}

pub(crate) fn build_config_plan(
    scenario: &Scenario,
    program_components: &[ComponentId],
    program_support: ProgramSupport,
    runtime_address_resolution: RuntimeAddressResolution,
    slot_values_by_component: &HashMap<ComponentId, BTreeMap<String, SlotValue>>,
) -> Result<ConfigPlan, MeshError> {
    let resolved_templates = compose_component_config_templates(scenario)?;

    let mut used_config_paths_by_component: HashMap<ComponentId, BTreeSet<String>> =
        HashMap::with_capacity(program_components.len());
    for id in program_components {
        let component = scenario.component(*id);
        let Some(program) = component.program.as_ref() else {
            continue;
        };
        let template_opt = resolved_templates
            .get(id)
            .and_then(|template| template.node());
        let slots = slot_values_by_component.get(id).ok_or_else(|| {
            MeshError::new(format!(
                "internal error: missing slot values for {}",
                component_label(scenario, *id)
            ))
        })?;
        let used_paths = program_used_config_paths(program, template_opt, slots)?;
        if !used_paths.is_empty() {
            used_config_paths_by_component.insert(*id, used_paths);
        }
    }

    let root_schema = scenario
        .component(scenario.root)
        .config_schema
        .as_ref()
        .cloned();

    let root_leaves = if let Some(schema) = &root_schema {
        rc::collect_leaf_paths(schema).map_err(|e| {
            MeshError::new(format!(
                "failed to enumerate root config definition leaf paths: {e}"
            ))
        })?
    } else {
        Vec::new()
    };
    let root_leaf_paths: BTreeSet<&str> =
        root_leaves.iter().map(|leaf| leaf.path.as_str()).collect();

    let mut program_plans = HashMap::new();
    let mut vm_cloud_init_paths_by_component = HashMap::new();
    let mut needs_helper = false;
    let mut needs_runtime_config = false;

    for id in program_components {
        let c = scenario.component(*id);
        let program = c.program.as_ref().expect("program component has program");

        let slots = slot_values_by_component.get(id).ok_or_else(|| {
            MeshError::new(format!(
                "internal error: missing slot values for {}",
                component_label(scenario, *id)
            ))
        })?;
        let component_template = resolved_templates.get(id).ok_or_else(|| {
            MeshError::new(format!(
                "no config template for component {}",
                component_label(scenario, *id)
            ))
        })?;
        let template_opt = component_template.node();

        let component_schema = scenario.component(*id).config_schema.as_ref().cloned();

        let plan = build_program_plan(
            scenario,
            *id,
            program,
            program_support,
            runtime_address_resolution,
            slots,
            template_opt,
            component_schema.as_ref(),
        )?;
        if matches!(plan, ProgramPlan::Helper { .. }) {
            needs_helper = true;
        }
        if plan.needs_runtime_config() {
            needs_runtime_config = true;
        }
        if let Some(image) = plan.image() {
            let mut runtime_paths = BTreeSet::new();
            image.collect_runtime_root_paths(&mut runtime_paths);
            if !runtime_paths.is_empty() {
                needs_runtime_config = true;
            }
            for path in runtime_paths {
                if !root_leaf_paths.contains(path.as_str()) {
                    return Err(MeshError::new(format!(
                        "program.image in {} requires runtime config path config.{path}, but \
                         runtime image interpolation only supports paths that resolve to one \
                         concrete root config value",
                        component_label(scenario, *id)
                    )));
                }
            }
        }
        let mut vm_scalar_paths = BTreeSet::new();
        collect_vm_scalar_runtime_paths(
            program,
            &component_label(scenario, *id),
            template_opt,
            &mut vm_scalar_paths,
        )?;
        if !vm_scalar_paths.is_empty() {
            needs_runtime_config = true;
        }
        let mut vm_cloud_init_paths = BTreeSet::new();
        collect_vm_cloud_init_runtime_paths(
            scenario,
            *id,
            program,
            slots,
            template_opt,
            &mut vm_cloud_init_paths,
        )?;
        if !vm_cloud_init_paths.is_empty() {
            needs_runtime_config = true;
        }
        vm_cloud_init_paths_by_component.insert(*id, vm_cloud_init_paths);
        program_plans.insert(*id, plan);
    }

    let mount_specs = build_mount_specs(
        scenario,
        program_components,
        &resolved_templates,
        slot_values_by_component,
    )?;
    let mounts_need_runtime = mount_specs
        .values()
        .any(|specs| mount_specs_need_config(specs));
    needs_runtime_config = needs_runtime_config || mounts_need_runtime;
    if !mount_specs.is_empty() {
        needs_helper = true;
    }

    if needs_runtime_config && root_schema.is_none() {
        return Err(MeshError::new(
            "root component must declare `config_schema` when runtime config interpolation is \
             required",
        ));
    }

    let mut runtime_views = HashMap::new();
    if needs_runtime_config {
        let root_schema = root_schema
            .as_ref()
            .expect("root schema required for runtime config");
        for id in program_components {
            let program_plan = program_plans
                .get(id)
                .expect("program plan should exist for program component");
            let mount_specs = mount_specs.get(id);
            let vm_cloud_init_paths = vm_cloud_init_paths_by_component
                .get(id)
                .expect("vm cloud-init path set should exist for program component");
            let needs_config_payload = program_plan.needs_runtime_config()
                || mount_specs.is_some_and(|specs| mount_specs_need_config(specs))
                || !vm_cloud_init_paths.is_empty();
            if !needs_config_payload {
                continue;
            }

            let component_schema = scenario
                .component(*id)
                .config_schema
                .as_ref()
                .expect("component config schema required");
            let component_template = resolved_templates
                .get(id)
                .expect("component template should exist");
            let used_paths = used_component_paths(
                program_plan,
                mount_specs.map(|specs| specs.as_slice()),
                Some(vm_cloud_init_paths),
            );

            let view = build_runtime_config_view(
                &component_label(scenario, *id),
                root_schema,
                &root_leaves,
                component_template,
                component_schema,
                &used_paths,
            )
            .map_err(|e| MeshError::new(e.to_string()))?;
            runtime_views.insert(*id, view);
        }
    }

    Ok(ConfigPlan {
        root_leaves,
        program_plans,
        mount_specs,
        needs_helper,
        needs_runtime_config,
        runtime_views,
    })
}

// Security: only expose runtime config needed by program templates and mounts.
fn used_component_paths(
    program_plan: &ProgramPlan,
    mount_specs: Option<&[MountSpec]>,
    extra_paths: Option<&BTreeSet<String>>,
) -> BTreeSet<String> {
    let mut used = BTreeSet::new();

    if let ProgramPlan::Helper { template_spec, .. } = program_plan {
        collect_used_paths_from_template_spec(template_spec, &mut used);
    }

    if let Some(specs) = mount_specs {
        for spec in specs {
            if let MountSpec::Template(spec) = spec {
                if let Some(when) = &spec.when {
                    used.insert(when.clone());
                }
                if let Some(RepeatedTemplateSource::Config { path }) = &spec.each {
                    used.insert(path.clone());
                }
                collect_used_paths_from_template_string(&spec.path, &mut used);
                collect_mount_source_used_paths(&spec.source, &mut used);
            }
        }
    }

    if let Some(paths) = extra_paths {
        used.extend(paths.iter().cloned());
    }

    used
}

fn collect_mount_source_used_paths(source: &TemplateString, out: &mut BTreeSet<String>) {
    collect_used_paths_from_template_string(source, out);
    match render_template_string_static(source) {
        Ok(rendered) => {
            if let Ok(MountSource::Config(path) | MountSource::Secret(path)) =
                rendered.parse::<MountSource>()
            {
                out.insert(path);
            }
        }
        Err(_) => {
            // Dynamic mount sources can select arbitrary config keys at runtime, so the runtime
            // config view must conservatively include the full component config.
            out.insert(String::new());
        }
    }
}

fn collect_vm_cloud_init_runtime_paths(
    scenario: &Scenario,
    id: ComponentId,
    program: &amber_manifest::Program,
    slots: &BTreeMap<String, SlotValue>,
    template_opt: Option<&rc::ConfigNode>,
    out: &mut BTreeSet<String>,
) -> Result<(), MeshError> {
    let amber_manifest::Program::Vm(program) = program else {
        return Ok(());
    };
    for (field_name, raw) in [
        (
            "program.vm.cloud_init.user_data",
            program.0.cloud_init.user_data.as_deref(),
        ),
        (
            "program.vm.cloud_init.vendor_data",
            program.0.cloud_init.vendor_data.as_deref(),
        ),
    ] {
        let Some(raw) = raw else {
            continue;
        };
        let Some(ts) = build_vm_cloud_init_template_string(
            scenario,
            id,
            field_name,
            Some(raw),
            RuntimeAddressResolution::Deferred,
            slots,
            template_opt,
        )?
        else {
            continue;
        };
        for part in ts {
            if let TemplatePart::Config { config } = part {
                out.insert(config);
            }
        }
    }
    Ok(())
}

fn collect_vm_scalar_runtime_paths(
    program: &amber_manifest::Program,
    component: &str,
    template_opt: Option<&rc::ConfigNode>,
    out: &mut BTreeSet<String>,
) -> Result<(), MeshError> {
    let amber_manifest::Program::Vm(program) = program else {
        return Ok(());
    };
    for (field_name, scalar) in [
        ("program.vm.cpus", &program.0.cpus),
        ("program.vm.memory_mib", &program.0.memory_mib),
    ] {
        if let VmScalarResolutionU32::RuntimeConfig(path) =
            resolve_vm_scalar_u32(template_opt, scalar, component, field_name)?
        {
            out.insert(path);
        }
    }
    Ok(())
}

pub(crate) fn build_vm_cloud_init_template_string(
    scenario: &Scenario,
    id: ComponentId,
    field_name: &str,
    raw: Option<&str>,
    runtime_address_resolution: RuntimeAddressResolution,
    slots: &BTreeMap<String, SlotValue>,
    template_opt: Option<&rc::ConfigNode>,
) -> Result<Option<TemplateString>, MeshError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let parsed = raw
        .parse::<amber_manifest::InterpolatedString>()
        .map_err(|err| {
            MeshError::new(format!(
                "failed to parse {field_name} interpolation in {}: {err}",
                component_label(scenario, id)
            ))
        })?;
    let mut needs_helper = false;
    let mut needs_runtime_config = false;
    resolve_program_template_string(
        scenario,
        id,
        field_name,
        &parsed,
        runtime_address_resolution,
        slots,
        template_opt,
        ItemResolution::NotAllowed,
        &mut needs_helper,
        &mut needs_runtime_config,
        false,
    )
    .map(Some)
}

pub(crate) fn resolve_vm_scalar_u32(
    template_opt: Option<&rc::ConfigNode>,
    scalar: &VmScalarU32,
    component: &str,
    field_name: &str,
) -> Result<VmScalarResolutionU32, MeshError> {
    match scalar {
        VmScalarU32::Literal(value) => {
            if *value == 0 {
                return Err(MeshError::new(format!(
                    "{field_name} in component {component} must be greater than zero"
                )));
            }
            Ok(VmScalarResolutionU32::Static(*value))
        }
        VmScalarU32::Interpolated(raw) => {
            let parsed = raw
                .parse::<amber_manifest::InterpolatedString>()
                .map_err(|err| {
                    MeshError::new(format!(
                        "failed to parse {field_name} interpolation in component {component}: \
                         {err}"
                    ))
                })?;
            let [InterpolatedPart::Interpolation { source, query }] = parsed.parts.as_slice()
            else {
                return Err(MeshError::new(format!(
                    "component {component} uses {field_name} with mixed interpolation, but VM \
                     resource fields must be either a literal number or a single `${{config...}}` \
                     reference"
                )));
            };
            if *source != InterpolationSource::Config {
                return Err(MeshError::new(format!(
                    "component {component} uses non-config interpolation in {field_name}; only \
                     `${{config...}}` is supported there"
                )));
            }
            resolve_vm_scalar_query(template_opt, query, field_name)
        }
        _ => Err(MeshError::new(format!(
            "component {component} uses an unsupported scalar form in {field_name}"
        ))),
    }
}

fn resolve_vm_scalar_query(
    template_opt: Option<&rc::ConfigNode>,
    query: &str,
    field_name: &str,
) -> Result<VmScalarResolutionU32, MeshError> {
    let render_error = || {
        MeshError::new(format!(
            "{field_name} must resolve to an unsigned integer config leaf or a single runtime \
             root config reference"
        ))
    };

    if query.is_empty() {
        return Err(MeshError::new(format!(
            "{field_name} cannot reference the entire runtime config object; reference an integer \
             leaf like `${{config.resources.cpus}}`"
        )));
    }

    let Some(template) = template_opt else {
        validate_config_query_syntax(query).map_err(MeshError::new)?;
        return Ok(VmScalarResolutionU32::RuntimeConfig(query.to_string()));
    };

    match resolve_config_query_node(template, query).map_err(MeshError::new)? {
        QueryResolution::RuntimePath(path) => Ok(VmScalarResolutionU32::RuntimeConfig(path)),
        QueryResolution::Node(node) if !node.contains_runtime() => {
            let value = node
                .evaluate_static()
                .map_err(|err| MeshError::new(err.to_string()))?;
            let Some(value) = value.as_u64() else {
                return Err(render_error());
            };
            if value == 0 || value > u32::MAX as u64 {
                return Err(MeshError::new(format!(
                    "{field_name} must be an unsigned integer greater than zero"
                )));
            }
            Ok(VmScalarResolutionU32::Static(value as u32))
        }
        QueryResolution::Node(rc::ConfigNode::ConfigRef(path)) => {
            if path.is_empty() {
                return Err(MeshError::new(format!(
                    "{field_name} cannot reference the entire runtime config object; reference an \
                     integer leaf like `${{config.resources.cpus}}`"
                )));
            }
            Ok(VmScalarResolutionU32::RuntimeConfig(path.clone()))
        }
        QueryResolution::Node(_) => Err(render_error()),
    }
}

fn encode_json_b64(value: &(impl Serialize + ?Sized)) -> Result<String, serde_json::Error> {
    let bytes = serde_json::to_vec(value)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

pub(crate) fn mount_specs_need_config(specs: &[MountSpec]) -> bool {
    specs
        .iter()
        .any(|spec| matches!(spec, MountSpec::Template(_)))
}

pub(crate) fn build_component_runtime_plan<'a>(
    component_label: &str,
    program_plan: &'a ProgramPlan,
    mount_specs: Option<&'a [MountSpec]>,
    runtime_view: Option<&'a RuntimeConfigView>,
    extra_helper_requirement: bool,
    extra_runtime_config_requirement: bool,
) -> Result<ComponentRuntimePlan<'a>, MeshError> {
    let needs_config_payload = program_plan.needs_runtime_config()
        || mount_specs.is_some_and(mount_specs_need_config)
        || extra_runtime_config_requirement;
    let needs_helper =
        program_plan.is_helper() || mount_specs.is_some() || extra_helper_requirement;

    let mount_spec_b64 = mount_specs
        .map(|specs| {
            encode_json_b64(specs).map_err(|e| MeshError::new(format!("{component_label}: {e}")))
        })
        .transpose()?;

    let encode_component_payload = |component_template: &rc::RootConfigTemplate,
                                    component_schema: &Value|
     -> Result<(String, String), MeshError> {
        let component_cfg_template_b64 = encode_json_b64(&component_template.to_json_ir())
            .map_err(|e| {
                MeshError::new(format!(
                    "failed to serialize component config template for {component_label}: {e}"
                ))
            })?;
        let component_schema_b64 =
            encode_json_b64(&rc::canonical_json(component_schema)).map_err(|e| {
                MeshError::new(format!(
                    "failed to serialize component config definition for {component_label}: {e}"
                ))
            })?;
        Ok((component_schema_b64, component_cfg_template_b64))
    };

    let build_runtime_payload = |component_schema_b64: String,
                                 component_cfg_template_b64: String|
     -> Result<RuntimeConfigPayload<'a>, MeshError> {
        let view = runtime_view.expect("runtime config view should be computed");
        let root_schema_b64 = encode_json_b64(&rc::canonical_json(&view.pruned_root_schema))
            .map_err(|e| {
                MeshError::new(format!(
                    "failed to serialize root config definition for {component_label}: {e}"
                ))
            })?;

        Ok(RuntimeConfigPayload {
            root_schema_b64,
            component_cfg_template_b64,
            component_schema_b64,
            allowed_root_leaf_paths: &view.allowed_root_leaf_paths,
        })
    };

    let execution = match program_plan {
        ProgramPlan::Resolved {
            entrypoint, env, ..
        } if !needs_helper => ComponentExecutionPlan::Resolved { entrypoint, env },
        ProgramPlan::Resolved {
            entrypoint, env, ..
        } => {
            let entrypoint_b64 =
                Some(encode_json_b64(entrypoint).map_err(|e| MeshError::new(e.to_string()))?);
            let env_b64 = Some(encode_json_b64(env).map_err(|e| MeshError::new(e.to_string()))?);
            let runtime_config = if needs_config_payload {
                let view = runtime_view.expect("runtime config view should be computed");
                let (component_schema_b64, component_cfg_template_b64) =
                    encode_component_payload(&view.component_template, &view.component_schema)?;
                Some(build_runtime_payload(
                    component_schema_b64,
                    component_cfg_template_b64,
                )?)
            } else {
                None
            };

            ComponentExecutionPlan::HelperRunner {
                entrypoint_b64,
                env_b64,
                template_spec_b64: None,
                runtime_config,
                mount_spec_b64,
            }
        }
        ProgramPlan::Helper {
            template_spec,
            needs_runtime_config,
            ..
        } => {
            let template_spec_b64 = encode_json_b64(template_spec).map_err(|e| {
                MeshError::new(format!(
                    "failed to serialize template spec for {component_label}: {e}"
                ))
            })?;
            let runtime_config = if *needs_runtime_config {
                let view = runtime_view.expect("runtime config view should be computed");
                let (component_schema_b64, component_cfg_template_b64) =
                    encode_component_payload(&view.component_template, &view.component_schema)?;
                Some(build_runtime_payload(
                    component_schema_b64,
                    component_cfg_template_b64,
                )?)
            } else {
                None
            };

            ComponentExecutionPlan::HelperRunner {
                entrypoint_b64: None,
                env_b64: None,
                template_spec_b64: Some(template_spec_b64),
                runtime_config,
                mount_spec_b64,
            }
        }
    };

    Ok(ComponentRuntimePlan {
        needs_helper,
        execution,
    })
}

fn collect_used_paths_from_template_spec(spec: &TemplateSpec, out: &mut BTreeSet<String>) {
    for arg in &spec.program.entrypoint {
        match arg {
            ProgramArgTemplate::Arg(ts) => collect_used_paths_from_template_string(ts, out),
            ProgramArgTemplate::Conditional(group) => {
                out.insert(group.when.clone());
                for ts in &group.argv {
                    collect_used_paths_from_template_string(ts, out);
                }
            }
            ProgramArgTemplate::Repeated(repeated) => {
                if let Some(when) = &repeated.when {
                    out.insert(when.clone());
                }
                let RepeatedTemplateSource::Config { path } = &repeated.each;
                out.insert(path.clone());
                if let Some(arg) = &repeated.arg {
                    collect_used_paths_from_template_string(arg, out);
                }
                for ts in &repeated.argv {
                    collect_used_paths_from_template_string(ts, out);
                }
            }
        }
    }
    for value in spec.program.env.values() {
        match value {
            ProgramEnvTemplate::Value(ts) => collect_used_paths_from_template_string(ts, out),
            ProgramEnvTemplate::Conditional(group) => {
                out.insert(group.when.clone());
                collect_used_paths_from_template_string(&group.value, out);
            }
            ProgramEnvTemplate::Repeated(repeated) => {
                if let Some(when) = &repeated.when {
                    out.insert(when.clone());
                }
                let RepeatedTemplateSource::Config { path } = &repeated.each;
                out.insert(path.clone());
                collect_used_paths_from_template_string(&repeated.value, out);
            }
        }
    }
}

fn collect_used_paths_from_template_string(ts: &TemplateString, out: &mut BTreeSet<String>) {
    for part in ts {
        if let TemplatePart::Config { config } = part {
            out.insert(config.clone());
        }
    }
}

fn interpolated_string_uses_config(value: &amber_manifest::InterpolatedString) -> bool {
    value.parts.iter().any(|part| {
        matches!(
            part,
            InterpolatedPart::Interpolation {
                source: InterpolationSource::Config,
                ..
            }
        )
    })
}

fn mount_uses_config(mount: &amber_manifest::ProgramMount) -> bool {
    mount
        .when
        .as_ref()
        .is_some_and(|when| when.source() == InterpolationSource::Config)
        || mount
            .each
            .as_ref()
            .is_some_and(|each| each.source() == InterpolationSource::Config)
        || mount
            .literal_source()
            .is_some_and(|source| matches!(source, MountSource::Config(_) | MountSource::Secret(_)))
        || interpolated_string_uses_config(&mount.path)
        || interpolated_string_uses_config(&mount.source)
}

fn build_mount_specs(
    scenario: &Scenario,
    program_components: &[ComponentId],
    resolved_templates: &HashMap<ComponentId, rc::RootConfigTemplate>,
    slot_values_by_component: &HashMap<ComponentId, BTreeMap<String, SlotValue>>,
) -> Result<HashMap<ComponentId, Vec<MountSpec>>, MeshError> {
    let mut out = HashMap::new();

    for id in program_components {
        let component = scenario.component(*id);
        let program = component
            .program
            .as_ref()
            .expect("program component has program");
        if program.mounts().is_empty() {
            continue;
        }

        let slots = slot_values_by_component.get(id).ok_or_else(|| {
            MeshError::new(format!(
                "internal error: missing slot values for {}",
                component_label(scenario, *id)
            ))
        })?;
        let needs_component_config = program.mounts().iter().any(mount_uses_config);

        if needs_component_config && component.config_schema.is_none() {
            return Err(MeshError::new(format!(
                "component {} requires config_schema when using program.mounts",
                component_label(scenario, *id)
            )));
        }

        let template_opt = if needs_component_config {
            let template = resolved_templates.get(id).ok_or_else(|| {
                MeshError::new(format!(
                    "no config template for component {}",
                    component_label(scenario, *id)
                ))
            })?;
            template.node()
        } else {
            None
        };

        let mut specs = Vec::new();
        for (mount_idx, mount) in program.mounts().iter().enumerate() {
            let when = resolve_program_when(mount.when.as_ref(), template_opt, slots)?;
            if matches!(when, ResolvedWhen::Absent) {
                continue;
            }
            let runtime_when = match &when {
                ResolvedWhen::Runtime(query) => Some(query.clone()),
                ResolvedWhen::Present | ResolvedWhen::Absent => None,
            };
            let location = format!("program.mounts[{mount_idx}]");

            let emit_spec = |item_resolution,
                             runtime_each: Option<RepeatedTemplateSource>,
                             specs: &mut Vec<MountSpec>|
             -> Result<(), MeshError> {
                let mut needs_helper_for_mount = false;
                let mut needs_runtime_config_for_mount = false;
                let path_ts = resolve_program_template_string(
                    scenario,
                    *id,
                    &format!("{location}.path"),
                    &mount.path,
                    RuntimeAddressResolution::Static,
                    slots,
                    template_opt,
                    item_resolution,
                    &mut needs_helper_for_mount,
                    &mut needs_runtime_config_for_mount,
                    true,
                )?;
                let source_ts = resolve_program_template_string(
                    scenario,
                    *id,
                    &format!("{location}.from"),
                    &mount.source,
                    RuntimeAddressResolution::Static,
                    slots,
                    template_opt,
                    item_resolution,
                    &mut needs_helper_for_mount,
                    &mut needs_runtime_config_for_mount,
                    true,
                )?;

                if runtime_when.is_some()
                    || runtime_each.is_some()
                    || needs_helper_for_mount
                    || needs_runtime_config_for_mount
                {
                    specs.push(MountSpec::Template(MountTemplateSpec {
                        when: runtime_when.clone(),
                        each: runtime_each,
                        path: path_ts,
                        source: source_ts,
                    }));
                    return Ok(());
                }

                let path = render_template_string_static(&path_ts)?;
                let source_raw = render_template_string_static(&source_ts)?;
                let source = source_raw.parse::<MountSource>().map_err(|err| {
                    MeshError::new(format!(
                        "invalid mount source `{source_raw}` in {} {location}: {err}",
                        component_label(scenario, *id)
                    ))
                })?;
                match source {
                    MountSource::Config(path_query) | MountSource::Secret(path_query) => {
                        match resolve_config_query_for_mount(template_opt, &path_query)? {
                            MountResolution::Static(value) => {
                                let content = rc::stringify_for_mount(&value)
                                    .map_err(|err| MeshError::new(err.to_string()))?;
                                specs.push(MountSpec::Literal { path, content });
                            }
                            MountResolution::Runtime => {
                                specs.push(MountSpec::Template(MountTemplateSpec {
                                    when: runtime_when.clone(),
                                    each: runtime_each,
                                    path: path_ts,
                                    source: source_ts,
                                }));
                            }
                        }
                    }
                    MountSource::Resource(_) | MountSource::Slot(_) => {
                        // Storage mounts are planned separately from helper-written file mounts.
                    }
                    MountSource::Framework(name) => {
                        if framework_capability(name.as_str()).is_none() {
                            return Err(MeshError::new(format!(
                                "unknown framework mount source framework.{} in {}",
                                name,
                                component_label(scenario, *id)
                            )));
                        }
                        // Handled by target-specific runtime wiring.
                    }
                    _ => {
                        return Err(MeshError::new(format!(
                            "unsupported mount source `{source_raw}` in {}",
                            component_label(scenario, *id)
                        )));
                    }
                }
                Ok(())
            };

            match mount.each.as_ref() {
                None => emit_spec(ItemResolution::NotAllowed, None, &mut specs)?,
                Some(each) => match each.source() {
                    InterpolationSource::Slots => {
                        let slot_name = each
                            .slot()
                            .expect("slot-based each path should expose a slot name");
                        let items = repeated_slot_items_for_component(
                            scenario, *id, slot_name, slots, &location,
                        )?;
                        for item in items {
                            emit_spec(ItemResolution::StaticSlot(item), None, &mut specs)?;
                        }
                    }
                    InterpolationSource::Config => {
                        match resolve_config_each_values(template_opt, each.query(), &location)? {
                            ConfigEachResolution::Static(items) => {
                                for item in &items {
                                    emit_spec(
                                        ItemResolution::StaticConfig(item),
                                        None,
                                        &mut specs,
                                    )?;
                                }
                            }
                            ConfigEachResolution::Runtime => {
                                emit_spec(
                                    ItemResolution::RuntimeCurrentItem,
                                    Some(RepeatedTemplateSource::Config {
                                        path: each.query().to_string(),
                                    }),
                                    &mut specs,
                                )?;
                            }
                        }
                    }
                    InterpolationSource::Item => unreachable!("each paths never use item"),
                    _ => unreachable!("unsupported interpolation source for each"),
                },
            }
        }

        if !specs.is_empty() {
            out.insert(*id, specs);
        }
    }

    Ok(out)
}

fn endpoint_uses_config(endpoint: &amber_manifest::Endpoint) -> bool {
    endpoint
        .when
        .as_ref()
        .is_some_and(|when| when.source() == InterpolationSource::Config)
        || endpoint
            .each
            .as_ref()
            .is_some_and(|each| each.source() == InterpolationSource::Config)
        || interpolated_string_uses_config(&endpoint.name)
        || interpolated_string_uses_config(&endpoint.protocol)
        || matches!(
            &endpoint.port,
            amber_manifest::EndpointPort::Interpolated(value)
                if interpolated_string_uses_config(value)
        )
}

fn resolve_endpoint_template_string(
    component: &str,
    location: &str,
    value: &amber_manifest::InterpolatedString,
    template_opt: Option<&rc::ConfigNode>,
    item: Option<&Value>,
) -> Result<String, MeshError> {
    let mut rendered = String::new();
    for part in &value.parts {
        match part {
            InterpolatedPart::Literal(lit) => rendered.push_str(lit),
            InterpolatedPart::Interpolation { source, query } => match source {
                InterpolationSource::Config => {
                    match resolve_config_query_for_program(template_opt, query)? {
                        ConfigResolution::Static(value) => rendered.push_str(&value),
                        ConfigResolution::Runtime => {
                            return Err(MeshError::new(format!(
                                "{component} {location} depends on runtime config, but endpoints \
                                 must resolve entirely at compile time"
                            )));
                        }
                    }
                }
                InterpolationSource::Item => {
                    let item = item.ok_or_else(|| {
                        MeshError::new(format!(
                            "`item` interpolation is only valid inside repeated endpoint `each` \
                             expansions in {component} {location}"
                        ))
                    })?;
                    rendered.push_str(&resolve_item_interpolation_from_value(
                        item, query, component, location,
                    )?);
                }
                InterpolationSource::Slots => {
                    let label = if query.is_empty() {
                        "slots".to_string()
                    } else {
                        format!("slots.{query}")
                    };
                    return Err(MeshError::new(format!(
                        "{component} {location} references `{label}`, but endpoints cannot depend \
                         on slots because mesh planning and port allocation happen before slot \
                         values exist"
                    )));
                }
                _ => {
                    return Err(MeshError::new(format!(
                        "unsupported interpolation source {source} in {component} {location}",
                    )));
                }
            },
            _ => {
                return Err(MeshError::new(format!(
                    "unsupported interpolation in {component} {location}",
                )));
            }
        }
    }
    Ok(rendered)
}

pub(crate) fn build_endpoint_plan(scenario: &Scenario) -> Result<EndpointPlan, MeshError> {
    let resolved_templates = compose_component_config_templates(scenario)?;
    let mut by_component = HashMap::new();

    for (id, component) in scenario.components_iter() {
        let Some(program) = component.program.as_ref() else {
            continue;
        };
        let Some(network) = program.network() else {
            continue;
        };
        if network.endpoints().is_empty() {
            continue;
        }

        let needs_component_config = network.endpoints().iter().any(endpoint_uses_config);
        if needs_component_config && component.config_schema.is_none() {
            return Err(MeshError::new(format!(
                "component {} requires config_schema when using variadic or interpolated \
                 program.network.endpoints",
                component_label(scenario, id)
            )));
        }
        let template_opt = if needs_component_config {
            let template = resolved_templates.get(&id).ok_or_else(|| {
                MeshError::new(format!(
                    "no config template for component {}",
                    component_label(scenario, id)
                ))
            })?;
            template.node()
        } else {
            None
        };

        let component_name = component_label(scenario, id);
        let mut endpoints = Vec::new();
        let mut seen_names = BTreeSet::new();

        for (endpoint_idx, endpoint) in network.endpoints().iter().enumerate() {
            let when = match endpoint.when.as_ref() {
                Some(when) => match when.source() {
                    InterpolationSource::Config => {
                        resolve_program_when(Some(when), template_opt, &BTreeMap::new())?
                    }
                    InterpolationSource::Slots => {
                        return Err(MeshError::new(format!(
                            "{} program.network.endpoints[{endpoint_idx}] uses `when: \
                             \"{when}\"`, but endpoints cannot depend on slots because mesh \
                             planning and port allocation happen before slot values exist",
                            component_name
                        )));
                    }
                    _ => {
                        return Err(MeshError::new(format!(
                            "{} program.network.endpoints[{endpoint_idx}] uses unsupported `when` \
                             source `{when}`",
                            component_name
                        )));
                    }
                },
                None => ResolvedWhen::Present,
            };
            if matches!(when, ResolvedWhen::Absent) {
                continue;
            }
            if let ResolvedWhen::Runtime(query) = &when {
                return Err(MeshError::new(format!(
                    "{} program.network.endpoints[{endpoint_idx}] depends on runtime config \
                     `{query}`, but endpoints must resolve entirely at compile time",
                    component_name
                )));
            }

            let location = format!("program.network.endpoints[{endpoint_idx}]");
            let emit_endpoint = |item: Option<&Value>,
                                 endpoints: &mut Vec<ExpandedEndpoint>,
                                 seen_names: &mut BTreeSet<String>|
             -> Result<(), MeshError> {
                let name = resolve_endpoint_template_string(
                    &component_name,
                    &format!("{location}.name"),
                    &endpoint.name,
                    template_opt,
                    item,
                )?;
                if name.is_empty() {
                    return Err(MeshError::new(format!(
                        "{} {location}.name resolves to an empty string",
                        component_name
                    )));
                }
                let port = match &endpoint.port {
                    amber_manifest::EndpointPort::Literal(value) => *value,
                    amber_manifest::EndpointPort::Interpolated(value) => {
                        resolve_endpoint_template_string(
                            &component_name,
                            &format!("{location}.port"),
                            value,
                            template_opt,
                            item,
                        )?
                        .parse::<u16>()
                        .map_err(|err| {
                            MeshError::new(format!(
                                "{} {location}.port must resolve to a valid u16: {err}",
                                component_name
                            ))
                        })?
                    }
                    _ => {
                        return Err(MeshError::new(format!(
                            "{} {location}.port uses an unsupported endpoint port form",
                            component_name
                        )));
                    }
                };
                let protocol = resolve_endpoint_template_string(
                    &component_name,
                    &format!("{location}.protocol"),
                    &endpoint.protocol,
                    template_opt,
                    item,
                )?
                .parse::<amber_manifest::NetworkProtocol>()
                .map_err(MeshError::new)?;

                if !seen_names.insert(name.clone()) {
                    return Err(MeshError::new(format!(
                        "component {} defines duplicate endpoint name `{name}` after endpoint \
                         expansion",
                        component_label(scenario, id)
                    )));
                }

                endpoints.push(ExpandedEndpoint {
                    name,
                    port,
                    protocol,
                });
                Ok(())
            };

            match endpoint.each.as_ref() {
                None => emit_endpoint(None, &mut endpoints, &mut seen_names)?,
                Some(each) => match each.source() {
                    InterpolationSource::Config => {
                        match resolve_config_each_values(template_opt, each.query(), &location)? {
                            ConfigEachResolution::Static(items) => {
                                for item in &items {
                                    emit_endpoint(Some(item), &mut endpoints, &mut seen_names)?;
                                }
                            }
                            ConfigEachResolution::Runtime => {
                                return Err(MeshError::new(format!(
                                    "{} {location} depends on runtime config, but endpoints must \
                                     resolve entirely at compile time",
                                    component_name
                                )));
                            }
                        }
                    }
                    InterpolationSource::Slots => {
                        return Err(MeshError::new(format!(
                            "{} {location} uses `each: \"{}\"`, but endpoints cannot depend on \
                             slots because mesh planning and port allocation happen before slot \
                             values exist",
                            component_name, each
                        )));
                    }
                    InterpolationSource::Item => unreachable!("each paths never use item"),
                    _ => unreachable!("unsupported interpolation source for each"),
                },
            }
        }

        if !endpoints.is_empty() {
            by_component.insert(id, endpoints);
        }
    }

    Ok(EndpointPlan { by_component })
}

fn program_used_config_paths(
    program: &amber_manifest::Program,
    template_opt: Option<&rc::ConfigNode>,
    slots: &BTreeMap<String, SlotValue>,
) -> Result<BTreeSet<String>, MeshError> {
    let mut used = BTreeSet::new();

    match program {
        amber_manifest::Program::Image(program) => {
            if let Ok(parsed) = program.image.parse::<amber_manifest::InterpolatedString>() {
                collect_program_config_paths(&parsed.parts, &mut used);
            }
        }
        amber_manifest::Program::Path(program) => {
            if let Ok(parsed) = program.path.parse::<amber_manifest::InterpolatedString>() {
                collect_program_config_paths(&parsed.parts, &mut used);
            }
        }
        amber_manifest::Program::Vm(program) => {
            if let Ok(parsed) = program
                .0
                .image
                .parse::<amber_manifest::InterpolatedString>()
            {
                collect_program_config_paths(&parsed.parts, &mut used);
            }
            for scalar in [&program.0.cpus, &program.0.memory_mib] {
                let amber_manifest::VmScalarU32::Interpolated(raw) = scalar else {
                    continue;
                };
                if let Ok(parsed) = raw.parse::<amber_manifest::InterpolatedString>() {
                    collect_program_config_paths(&parsed.parts, &mut used);
                }
            }
            for value in [
                program.0.cloud_init.user_data.as_deref(),
                program.0.cloud_init.vendor_data.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                if let Ok(parsed) = value.parse::<amber_manifest::InterpolatedString>() {
                    collect_program_config_paths(&parsed.parts, &mut used);
                }
            }
        }
        _ => {}
    }
    for arg in &program.command().0 {
        let condition = match arg.when() {
            Some(when) => {
                let presence = resolve_condition_presence_for_program(
                    when.source(),
                    when.query(),
                    template_opt,
                    slots,
                )?;
                if when.source() == InterpolationSource::Config
                    && !matches!(presence, ConfigPresence::Absent)
                {
                    used.insert(when.query().to_string());
                }
                presence
            }
            None => ConfigPresence::Present,
        };
        if matches!(condition, ConfigPresence::Absent) {
            continue;
        }
        if let Some(each) = arg.each()
            && each.source() == InterpolationSource::Config
        {
            used.insert(each.query().to_string());
        }
        if static_each_is_empty(arg.each(), template_opt, slots, "program command")? == Some(true) {
            continue;
        }
        arg.visit_values(|value| collect_program_config_paths(&value.parts, &mut used));
    }
    for value in program.env().values() {
        let condition = match value.when() {
            Some(when) => {
                let presence = resolve_condition_presence_for_program(
                    when.source(),
                    when.query(),
                    template_opt,
                    slots,
                )?;
                if when.source() == InterpolationSource::Config
                    && !matches!(presence, ConfigPresence::Absent)
                {
                    used.insert(when.query().to_string());
                }
                presence
            }
            None => ConfigPresence::Present,
        };
        if matches!(condition, ConfigPresence::Absent) {
            continue;
        }
        if let Some(each) = value.each()
            && each.source() == InterpolationSource::Config
        {
            used.insert(each.query().to_string());
        }
        if static_each_is_empty(value.each(), template_opt, slots, "program env")? == Some(true) {
            continue;
        }
        collect_program_config_paths(&value.value().parts, &mut used);
    }
    for mount in program.mounts() {
        let condition = match &mount.when {
            Some(when) => {
                let presence = resolve_condition_presence_for_program(
                    when.source(),
                    when.query(),
                    template_opt,
                    slots,
                )?;
                if when.source() == InterpolationSource::Config
                    && !matches!(presence, ConfigPresence::Absent)
                {
                    used.insert(when.query().to_string());
                }
                presence
            }
            None => ConfigPresence::Present,
        };
        if matches!(condition, ConfigPresence::Absent) {
            continue;
        }
        if let Some(each) = &mount.each
            && each.source() == InterpolationSource::Config
        {
            used.insert(each.query().to_string());
        }
        if static_each_is_empty(mount.each.as_ref(), template_opt, slots, "program mounts")?
            == Some(true)
        {
            continue;
        }
        collect_program_config_paths(&mount.path.parts, &mut used);
        collect_program_config_paths(&mount.source.parts, &mut used);
        if let Some(source) = mount.literal_source()
            && let MountSource::Config(path) | MountSource::Secret(path) = source
        {
            used.insert(path);
        }
    }

    Ok(used)
}

fn collect_program_config_paths(parts: &[InterpolatedPart], out: &mut BTreeSet<String>) {
    for part in parts {
        let InterpolatedPart::Interpolation { source, query } = part else {
            continue;
        };
        if *source == InterpolationSource::Config {
            out.insert(query.clone());
        }
    }
}

fn static_each_is_empty(
    each: Option<&amber_manifest::EachPath>,
    template_opt: Option<&rc::ConfigNode>,
    slots: &BTreeMap<String, SlotValue>,
    location: &str,
) -> Result<Option<bool>, MeshError> {
    let Some(each) = each else {
        return Ok(Some(false));
    };

    match each.source() {
        InterpolationSource::Config => {
            match resolve_config_each_values(template_opt, each.query(), location)? {
                ConfigEachResolution::Static(items) => Ok(Some(items.is_empty())),
                ConfigEachResolution::Runtime => Ok(None),
            }
        }
        InterpolationSource::Slots => Ok(Some(
            repeated_slot_items(
                slots,
                each.slot()
                    .expect("slot-based each path should expose a slot"),
            )
            .is_empty(),
        )),
        InterpolationSource::Item => unreachable!("each paths never use item"),
        _ => unreachable!("unsupported interpolation source for each"),
    }
}

fn resolve_condition_presence_for_program(
    source: InterpolationSource,
    query: &str,
    template_opt: Option<&rc::ConfigNode>,
    slots: &BTreeMap<String, SlotValue>,
) -> Result<ConfigPresence, MeshError> {
    match source {
        InterpolationSource::Config => {
            let Some(template) = template_opt else {
                return Ok(ConfigPresence::Runtime);
            };
            match resolve_optional_config_query_node(template, query)? {
                None => Ok(ConfigPresence::Absent),
                Some(QueryResolution::RuntimePath(_)) => Ok(ConfigPresence::Runtime),
                Some(QueryResolution::Node(node)) => {
                    if node.contains_runtime() {
                        Ok(ConfigPresence::Runtime)
                    } else {
                        let value = node
                            .evaluate_static()
                            .map_err(|err| MeshError::new(err.to_string()))?;
                        if value.is_null() {
                            Ok(ConfigPresence::Absent)
                        } else {
                            Ok(ConfigPresence::Present)
                        }
                    }
                }
            }
        }
        InterpolationSource::Slots => Ok(
            if slot_query_is_present(slots, query).map_err(MeshError::new)? {
                ConfigPresence::Present
            } else {
                ConfigPresence::Absent
            },
        ),
        _ => Err(MeshError::new(format!(
            "unsupported conditional interpolation source for `{source}.{query}`"
        ))),
    }
}

fn resolve_optional_config_query_node<'a>(
    template: &'a rc::ConfigNode,
    query: &str,
) -> Result<Option<QueryResolution<'a>>, MeshError> {
    if query.is_empty() {
        return Ok(Some(QueryResolution::Node(template)));
    }

    let segments = parse_query_segments(query)?;
    let mut current = template;
    for (idx, seg) in segments.iter().enumerate() {
        match current {
            rc::ConfigNode::Object(map) => {
                let Some(next) = map.get(*seg) else {
                    return Ok(None);
                };
                current = next;
            }
            rc::ConfigNode::ConfigRef(path) => {
                let suffix = segments[idx..].join(".");
                let full = if path.is_empty() {
                    suffix
                } else {
                    format!("{path}.{suffix}")
                };
                return Ok(Some(QueryResolution::RuntimePath(full)));
            }
            _ => return Ok(None),
        }
    }
    Ok(Some(QueryResolution::Node(current)))
}

#[derive(Debug)]
enum ConfigResolution {
    Static(String),
    Runtime,
}

#[derive(Debug)]
enum ImageConfigResolution {
    Static(String),
    RuntimeTemplate(Vec<ProgramImagePart>),
}

#[derive(Debug)]
enum MountResolution {
    Static(Value),
    Runtime,
}

#[derive(Debug)]
enum ConfigEachResolution {
    Static(Vec<Value>),
    Runtime,
}

fn resolve_config_query_for_program(
    template: Option<&rc::ConfigNode>,
    query: &str,
) -> Result<ConfigResolution, MeshError> {
    let Some(template) = template else {
        return Ok(ConfigResolution::Runtime);
    };

    let cur = match resolve_config_query_node(template, query).map_err(MeshError::new)? {
        QueryResolution::Node(cur) => cur,
        QueryResolution::RuntimePath(_) => return Ok(ConfigResolution::Runtime),
    };

    if !cur.contains_runtime() {
        let v = cur
            .evaluate_static()
            .map_err(|e| MeshError::new(e.to_string()))?;
        Ok(ConfigResolution::Static(
            rc::stringify_for_interpolation(&v).map_err(|e| MeshError::new(e.to_string()))?,
        ))
    } else {
        Ok(ConfigResolution::Runtime)
    }
}

fn resolve_program_image_runtime_node(
    node: &rc::ConfigNode,
) -> Result<ImageConfigResolution, MeshError> {
    match node {
        rc::ConfigNode::ConfigRef(path) => {
            if path.is_empty() {
                return Err(MeshError::new(
                    "program.image cannot reference the entire runtime config object; reference a \
                     string leaf like ${config.image}",
                ));
            }
            Ok(ImageConfigResolution::RuntimeTemplate(vec![
                ProgramImagePart::RootConfigPath(path.clone()),
            ]))
        }
        rc::ConfigNode::StringTemplate(parts) => {
            let mut out: Vec<ProgramImagePart> = Vec::with_capacity(parts.len());
            for part in parts {
                match part {
                    TemplatePart::Lit { lit } => {
                        if !lit.is_empty() {
                            out.push(ProgramImagePart::Literal(lit.clone()));
                        }
                    }
                    TemplatePart::Config { config } => {
                        if config.is_empty() {
                            return Err(MeshError::new(
                                "program.image cannot reference the entire runtime config object; \
                                 reference a string leaf like ${config.image}",
                            ));
                        }
                        out.push(ProgramImagePart::RootConfigPath(config.clone()));
                    }
                    TemplatePart::Slot { slot, .. } => {
                        return Err(MeshError::new(format!(
                            "failed to resolve runtime image template: unresolved slots.{slot} \
                             interpolation"
                        )));
                    }
                    TemplatePart::Item { item, .. } => {
                        return Err(MeshError::new(format!(
                            "failed to resolve runtime image template: unresolved item.{item} \
                             interpolation"
                        )));
                    }
                    TemplatePart::CurrentItem { item } => {
                        return Err(MeshError::new(format!(
                            "failed to resolve runtime image template: unresolved item.{item} \
                             interpolation"
                        )));
                    }
                }
            }
            if out.is_empty() {
                return Err(MeshError::new(
                    "internal error: produced empty runtime template for program.image",
                ));
            }
            Ok(ImageConfigResolution::RuntimeTemplate(out))
        }
        _ => Err(MeshError::new(
            "program.image cannot interpolate a runtime-derived non-string config value; use a \
             string config leaf containing the full image reference",
        )),
    }
}

fn resolve_config_query_for_program_image(
    template: Option<&rc::ConfigNode>,
    query: &str,
) -> Result<ImageConfigResolution, MeshError> {
    let Some(template) = template else {
        if query.is_empty() {
            return Err(MeshError::new(
                "program.image cannot reference the entire runtime config object; reference a \
                 string leaf like ${config.image}",
            ));
        }
        validate_config_query_syntax(query).map_err(MeshError::new)?;
        return Ok(ImageConfigResolution::RuntimeTemplate(vec![
            ProgramImagePart::RootConfigPath(query.to_string()),
        ]));
    };

    match resolve_config_query_node(template, query).map_err(MeshError::new)? {
        QueryResolution::RuntimePath(path) => Ok(ImageConfigResolution::RuntimeTemplate(vec![
            ProgramImagePart::RootConfigPath(path),
        ])),
        QueryResolution::Node(cur) => {
            if !cur.contains_runtime() {
                let v = cur
                    .evaluate_static()
                    .map_err(|e| MeshError::new(e.to_string()))?;
                Ok(ImageConfigResolution::Static(
                    rc::stringify_for_interpolation(&v)
                        .map_err(|e| MeshError::new(e.to_string()))?,
                ))
            } else {
                resolve_program_image_runtime_node(cur)
            }
        }
    }
}

fn resolve_config_query_for_mount(
    template: Option<&rc::ConfigNode>,
    query: &str,
) -> Result<MountResolution, MeshError> {
    let Some(template) = template else {
        return Ok(MountResolution::Runtime);
    };

    let cur = match resolve_config_query_node(template, query).map_err(MeshError::new)? {
        QueryResolution::Node(cur) => cur,
        QueryResolution::RuntimePath(_) => return Ok(MountResolution::Runtime),
    };

    if cur.contains_runtime() {
        Ok(MountResolution::Runtime)
    } else {
        cur.evaluate_static()
            .map(MountResolution::Static)
            .map_err(|e| MeshError::new(e.to_string()))
    }
}

fn resolve_config_each_values(
    template: Option<&rc::ConfigNode>,
    query: &str,
    location: &str,
) -> Result<ConfigEachResolution, MeshError> {
    let Some(template) = template else {
        validate_config_query_syntax(query).map_err(MeshError::new)?;
        return Ok(ConfigEachResolution::Runtime);
    };

    let Some(resolution) = resolve_optional_config_query_node(template, query)? else {
        return Ok(ConfigEachResolution::Static(Vec::new()));
    };

    match resolution {
        QueryResolution::RuntimePath(_) => Ok(ConfigEachResolution::Runtime),
        QueryResolution::Node(node) => {
            if node.contains_runtime() {
                return Ok(ConfigEachResolution::Runtime);
            }

            let value = node
                .evaluate_static()
                .map_err(|err| MeshError::new(err.to_string()))?;
            match value {
                Value::Null => Ok(ConfigEachResolution::Static(Vec::new())),
                Value::Array(values) => Ok(ConfigEachResolution::Static(values)),
                other => Err(MeshError::new(format!(
                    "{location} uses `each: \"config.{query}\"`, but config.{query} resolves to \
                     {} instead of an array",
                    value_kind(&other)
                ))),
            }
        }
    }
}

fn render_template_string_static(ts: &TemplateString) -> Result<String, MeshError> {
    if rc::template_string_is_runtime(ts) {
        return Err(MeshError::new(
            "internal error: attempted to render a runtime template string statically",
        ));
    }
    let mut out = String::new();
    for part in ts {
        match part {
            TemplatePart::Lit { lit } => out.push_str(lit),
            TemplatePart::Config { .. } => unreachable!(),
            TemplatePart::Slot { .. } => unreachable!(),
            TemplatePart::Item { .. } => unreachable!(),
            TemplatePart::CurrentItem { .. } => unreachable!(),
        }
    }
    Ok(out)
}

fn validate_explicit_program_path(component: &str, path: &str) -> Result<(), MeshError> {
    let has_separator = path.contains('/') || path.contains('\\');
    if Path::new(path).is_absolute() || has_separator {
        return Ok(());
    }

    Err(MeshError::new(format!(
        "component {component} uses program.path `{path}` without a path separator; direct \
         execution does not search PATH, so use an absolute path or a manifest-relative path like \
         `./bin/server`"
    )))
}

fn push_image_literal(parts: &mut Vec<ProgramImagePart>, lit: impl Into<String>) {
    let lit = lit.into();
    if lit.is_empty() {
        return;
    }
    match parts.last_mut() {
        Some(ProgramImagePart::Literal(existing)) => existing.push_str(&lit),
        _ => parts.push(ProgramImagePart::Literal(lit)),
    }
}

fn extend_image_parts(parts: &mut Vec<ProgramImagePart>, extra: Vec<ProgramImagePart>) {
    for part in extra {
        match part {
            ProgramImagePart::Literal(lit) => push_image_literal(parts, lit),
            ProgramImagePart::RootConfigPath(path) => {
                parts.push(ProgramImagePart::RootConfigPath(path))
            }
        }
    }
}

#[derive(Clone, Copy)]
enum ItemResolution<'a> {
    NotAllowed,
    RuntimeSlotTemplate {
        scope: u64,
        slot: &'a str,
        index: usize,
        item: &'a SlotObject,
    },
    RuntimeCurrentItem,
    StaticSlot(&'a SlotObject),
    StaticConfig(&'a Value),
}

fn repeated_slot_items<'a>(slots: &'a BTreeMap<String, SlotValue>, slot: &str) -> &'a [SlotObject] {
    match slots.get(slot) {
        Some(SlotValue::One(value)) => std::slice::from_ref(value),
        Some(SlotValue::Many(values)) => values.as_slice(),
        None => &[],
    }
}

fn repeated_slot_items_for_component<'a>(
    scenario: &'a Scenario,
    id: ComponentId,
    slot: &str,
    slots: &'a BTreeMap<String, SlotValue>,
    location: &str,
) -> Result<&'a [SlotObject], MeshError> {
    let component = component_label(scenario, id);
    let slot_decl = scenario.component(id).slots.get(slot).ok_or_else(|| {
        MeshError::new(format!("unknown slot `{slot}` in {component} {location}"))
    })?;
    if !slot_decl.multiple {
        return Err(MeshError::new(format!(
            "slot `{slot}` in {component} {location} is not declared with `multiple: true`"
        )));
    }
    Ok(repeated_slot_items(slots, slot))
}

fn query_value_opt<'a>(root: &'a Value, query: &str) -> Option<&'a Value> {
    if query.is_empty() {
        return Some(root);
    }
    let mut current = root;
    for segment in query.split('.') {
        match current {
            Value::Object(map) => current = map.get(segment)?,
            _ => return None,
        }
    }
    Some(current)
}

fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn resolve_item_interpolation_from_value(
    item: &Value,
    query: &str,
    component: &str,
    location: &str,
) -> Result<String, MeshError> {
    let value = query_value_opt(item, query).ok_or_else(|| {
        let label = if query.is_empty() {
            "item".to_string()
        } else {
            format!("item.{query}")
        };
        MeshError::new(format!(
            "failed to resolve {label} in {component} {location}"
        ))
    })?;
    rc::stringify_for_interpolation(value).map_err(|err| {
        MeshError::new(format!(
            "failed to stringify repeated slot item in {component} {location}: {err}"
        ))
    })
}

fn resolve_slot_item_interpolation(
    item: &SlotObject,
    query: &str,
    component: &str,
    location: &str,
) -> Result<String, MeshError> {
    let value = serde_json::to_value(item).map_err(|err| {
        MeshError::new(format!(
            "failed to serialize repeated slot item in {component} {location}: {err}"
        ))
    })?;
    resolve_item_interpolation_from_value(&value, query, component, location)
}

fn join_template_strings(values: Vec<TemplateString>, separator: &str) -> TemplateString {
    let mut out = Vec::new();
    for (idx, mut value) in values.into_iter().enumerate() {
        if idx > 0 && !separator.is_empty() {
            out.push(TemplatePart::lit(separator));
        }
        out.append(&mut value);
    }
    out
}

fn resolve_slot_interpolation(
    scenario: &Scenario,
    id: ComponentId,
    location: &str,
    source: &InterpolationSource,
    query: &str,
    slots: &BTreeMap<String, SlotValue>,
) -> Result<Option<String>, MeshError> {
    let component = component_label(scenario, id);
    match source {
        InterpolationSource::Slots => {
            let parsed = parse_slot_query(query).map_err(|err| {
                let label = if query.is_empty() {
                    "slots".to_string()
                } else {
                    format!("slots.{query}")
                };
                MeshError::new(format!(
                    "failed to resolve slot query in {component}: invalid slots interpolation \
                     `{label}`: {err}"
                ))
            })?;

            match parsed.target {
                SlotTarget::All => {
                    if scenario
                        .component(id)
                        .slots
                        .values()
                        .any(|slot| slot.multiple)
                    {
                        return Err(MeshError::new(format!(
                            "failed to resolve slot query in {component}: `${{slots}}` is not \
                             valid when the component declares any `multiple: true` slots"
                        )));
                    }
                }
                SlotTarget::Slot(slot_name) => {
                    if scenario
                        .component(id)
                        .slots
                        .get(slot_name)
                        .is_some_and(|slot| slot.multiple)
                    {
                        return Err(MeshError::new(format!(
                            "failed to resolve slot query in {component}: slot `{slot_name}` is \
                             declared with `multiple: true`; use `each: \"slots.{slot_name}\"` \
                             and `${{item...}}`"
                        )));
                    }
                }
            }

            resolve_slot_query(slots, query).map(Some).map_err(|e| {
                MeshError::new(format!("failed to resolve slot query in {component}: {e}"))
            })
        }
        InterpolationSource::Config => Ok(None),
        InterpolationSource::Item => Err(MeshError::new(format!(
            "`item` interpolation is only valid inside repeated `each` expansions in {component} \
             {location}",
        ))),
        other => Err(MeshError::new(format!(
            "unsupported interpolation source {other} in {component} {location}",
        ))),
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_program_template_string(
    scenario: &Scenario,
    id: ComponentId,
    location: &str,
    value: &amber_manifest::InterpolatedString,
    runtime_address_resolution: RuntimeAddressResolution,
    slots: &BTreeMap<String, SlotValue>,
    template_opt: Option<&rc::ConfigNode>,
    item_resolution: ItemResolution<'_>,
    needs_helper_for_program_templates: &mut bool,
    needs_runtime_config_for_program_templates: &mut bool,
    require_non_empty: bool,
) -> Result<TemplateString, MeshError> {
    let component = component_label(scenario, id);
    let mut ts: TemplateString = Vec::new();
    for part in &value.parts {
        match part {
            InterpolatedPart::Literal(lit) => ts.push(TemplatePart::lit(lit)),
            InterpolatedPart::Interpolation { source, query } => {
                if *source == InterpolationSource::Item {
                    match item_resolution {
                        ItemResolution::NotAllowed => {
                            return Err(MeshError::new(format!(
                                "`item` interpolation is only valid inside repeated `each` \
                                 expansions in {component} {location}",
                            )));
                        }
                        ItemResolution::RuntimeSlotTemplate {
                            scope,
                            slot,
                            index,
                            item,
                        } => {
                            resolve_slot_item_interpolation(item, query, &component, location)?;
                            ts.push(TemplatePart::item(scope, slot, index, query.clone()));
                            *needs_helper_for_program_templates = true;
                        }
                        ItemResolution::RuntimeCurrentItem => {
                            ts.push(TemplatePart::current_item(query.clone()));
                            *needs_helper_for_program_templates = true;
                        }
                        ItemResolution::StaticSlot(item) => {
                            ts.push(TemplatePart::lit(resolve_slot_item_interpolation(
                                item, query, &component, location,
                            )?));
                        }
                        ItemResolution::StaticConfig(item) => {
                            ts.push(TemplatePart::lit(resolve_item_interpolation_from_value(
                                item, query, &component, location,
                            )?));
                        }
                    }
                    continue;
                }
                match source {
                    InterpolationSource::Slots
                        if matches!(
                            runtime_address_resolution,
                            RuntimeAddressResolution::Deferred
                        ) =>
                    {
                        ts.push(TemplatePart::slot(id.0 as u64, query.clone()));
                        *needs_helper_for_program_templates = true;
                        continue;
                    }
                    _ => {}
                }
                if let Some(value) =
                    resolve_slot_interpolation(scenario, id, location, source, query, slots)?
                {
                    ts.push(TemplatePart::lit(value));
                    continue;
                }
                match resolve_config_query_for_program(template_opt, query)? {
                    ConfigResolution::Static(value) => ts.push(TemplatePart::lit(value)),
                    ConfigResolution::Runtime => {
                        ts.push(TemplatePart::config(query.clone()));
                        *needs_helper_for_program_templates = true;
                        *needs_runtime_config_for_program_templates = true;
                    }
                }
            }
            _ => {
                return Err(MeshError::new(format!(
                    "unsupported interpolation part in {component} {location}",
                )));
            }
        }
    }
    if require_non_empty && ts.is_empty() {
        return Err(MeshError::new(format!(
            "internal error: produced empty template for {component} {location}",
        )));
    }
    Ok(ts)
}

#[derive(Clone, Debug)]
enum ResolvedWhen {
    Present,
    Absent,
    Runtime(String),
}

fn resolve_program_when(
    when: Option<&amber_manifest::WhenPath>,
    template_opt: Option<&rc::ConfigNode>,
    slots: &BTreeMap<String, SlotValue>,
) -> Result<ResolvedWhen, MeshError> {
    let Some(when) = when else {
        return Ok(ResolvedWhen::Present);
    };

    match resolve_condition_presence_for_program(when.source(), when.query(), template_opt, slots)?
    {
        ConfigPresence::Present => Ok(ResolvedWhen::Present),
        ConfigPresence::Absent => Ok(ResolvedWhen::Absent),
        ConfigPresence::Runtime => {
            if when.source() != InterpolationSource::Config {
                return Err(MeshError::new(format!(
                    "internal error: runtime program `when` must be config-based, got `{when}`"
                )));
            }
            Ok(ResolvedWhen::Runtime(when.query().to_string()))
        }
    }
}

fn emit_program_arg_templates(
    out: &mut Vec<ProgramArgTemplate>,
    argv: Vec<TemplateString>,
    runtime_when: Option<String>,
    needs_helper_for_program_templates: &mut bool,
    needs_runtime_config_for_program_templates: &mut bool,
) {
    if argv.is_empty() {
        return;
    }

    if let Some(when) = runtime_when {
        *needs_helper_for_program_templates = true;
        *needs_runtime_config_for_program_templates = true;
        out.push(ProgramArgTemplate::Conditional(
            ConditionalProgramArgTemplate { when, argv },
        ));
        return;
    }

    out.extend(argv.into_iter().map(ProgramArgTemplate::Arg));
}

#[allow(clippy::too_many_arguments)]
fn append_program_command_item_templates(
    scenario: &Scenario,
    id: ComponentId,
    location_prefix: &str,
    idx: usize,
    item: &ProgramArgItem,
    runtime_address_resolution: RuntimeAddressResolution,
    slots: &BTreeMap<String, SlotValue>,
    template_opt: Option<&rc::ConfigNode>,
    needs_helper_for_program_templates: &mut bool,
    needs_runtime_config_for_program_templates: &mut bool,
    out: &mut Vec<ProgramArgTemplate>,
) -> Result<(), MeshError> {
    let when = resolve_program_when(item.when(), template_opt, slots)?;
    if matches!(when, ResolvedWhen::Absent) {
        return Ok(());
    }

    let runtime_when = match &when {
        ResolvedWhen::Runtime(query) => Some(query.clone()),
        ResolvedWhen::Present | ResolvedWhen::Absent => None,
    };

    let location = format!("{location_prefix}[{idx}]");
    let render_arg = |location: &str,
                      value: &amber_manifest::InterpolatedString,
                      item_resolution,
                      needs_helper_for_program_templates: &mut bool,
                      needs_runtime_config_for_program_templates: &mut bool|
     -> Result<TemplateString, MeshError> {
        resolve_program_template_string(
            scenario,
            id,
            location,
            value,
            runtime_address_resolution,
            slots,
            template_opt,
            item_resolution,
            needs_helper_for_program_templates,
            needs_runtime_config_for_program_templates,
            true,
        )
    };

    match item.each() {
        None => {
            let mut argv = Vec::new();
            match &item.value {
                amber_manifest::ProgramArgValue::Arg(arg) => {
                    argv.push(render_arg(
                        &location,
                        arg,
                        ItemResolution::NotAllowed,
                        needs_helper_for_program_templates,
                        needs_runtime_config_for_program_templates,
                    )?);
                }
                amber_manifest::ProgramArgValue::Argv(args) => {
                    for (group_idx, arg) in args.iter().enumerate() {
                        argv.push(render_arg(
                            &format!("{location}.argv[{group_idx}]"),
                            arg,
                            ItemResolution::NotAllowed,
                            needs_helper_for_program_templates,
                            needs_runtime_config_for_program_templates,
                        )?);
                    }
                }
            }
            emit_program_arg_templates(
                out,
                argv,
                runtime_when,
                needs_helper_for_program_templates,
                needs_runtime_config_for_program_templates,
            );
            Ok(())
        }
        Some(each) => match each.source() {
            InterpolationSource::Slots => {
                let scope = id.0 as u64;
                let slot_name = each
                    .slot()
                    .expect("slot-based each path should expose a slot name");
                let items =
                    repeated_slot_items_for_component(scenario, id, slot_name, slots, &location)?;
                if items.is_empty() {
                    return Ok(());
                }

                let item_resolution = |item_idx, item| {
                    if matches!(
                        runtime_address_resolution,
                        RuntimeAddressResolution::Deferred
                    ) {
                        ItemResolution::RuntimeSlotTemplate {
                            scope,
                            slot: slot_name,
                            index: item_idx,
                            item,
                        }
                    } else {
                        ItemResolution::StaticSlot(item)
                    }
                };

                let mut argv = Vec::new();
                match &item.value {
                    amber_manifest::ProgramArgValue::Arg(arg) => {
                        let arg_location = format!("{location}.arg");
                        if let Some(join) = item.join() {
                            let mut rendered = Vec::with_capacity(items.len());
                            for (item_idx, repeated_item) in items.iter().enumerate() {
                                rendered.push(render_arg(
                                    &arg_location,
                                    arg,
                                    item_resolution(item_idx, repeated_item),
                                    needs_helper_for_program_templates,
                                    needs_runtime_config_for_program_templates,
                                )?);
                            }
                            argv.push(join_template_strings(rendered, join));
                        } else {
                            for (item_idx, repeated_item) in items.iter().enumerate() {
                                argv.push(render_arg(
                                    &arg_location,
                                    arg,
                                    item_resolution(item_idx, repeated_item),
                                    needs_helper_for_program_templates,
                                    needs_runtime_config_for_program_templates,
                                )?);
                            }
                        }
                    }
                    amber_manifest::ProgramArgValue::Argv(args) => {
                        for (item_idx, repeated_item) in items.iter().enumerate() {
                            for (group_idx, arg) in args.iter().enumerate() {
                                argv.push(render_arg(
                                    &format!("{location}.argv[{group_idx}]"),
                                    arg,
                                    item_resolution(item_idx, repeated_item),
                                    needs_helper_for_program_templates,
                                    needs_runtime_config_for_program_templates,
                                )?);
                            }
                        }
                    }
                }

                emit_program_arg_templates(
                    out,
                    argv,
                    runtime_when,
                    needs_helper_for_program_templates,
                    needs_runtime_config_for_program_templates,
                );
                Ok(())
            }
            InterpolationSource::Config => {
                match resolve_config_each_values(template_opt, each.query(), &location)? {
                    ConfigEachResolution::Static(items) => {
                        if items.is_empty() {
                            return Ok(());
                        }

                        let mut argv = Vec::new();
                        match &item.value {
                            amber_manifest::ProgramArgValue::Arg(arg) => {
                                let arg_location = format!("{location}.arg");
                                if let Some(join) = item.join() {
                                    let mut rendered = Vec::with_capacity(items.len());
                                    for repeated_item in &items {
                                        rendered.push(render_arg(
                                            &arg_location,
                                            arg,
                                            ItemResolution::StaticConfig(repeated_item),
                                            needs_helper_for_program_templates,
                                            needs_runtime_config_for_program_templates,
                                        )?);
                                    }
                                    argv.push(join_template_strings(rendered, join));
                                } else {
                                    for repeated_item in &items {
                                        argv.push(render_arg(
                                            &arg_location,
                                            arg,
                                            ItemResolution::StaticConfig(repeated_item),
                                            needs_helper_for_program_templates,
                                            needs_runtime_config_for_program_templates,
                                        )?);
                                    }
                                }
                            }
                            amber_manifest::ProgramArgValue::Argv(args) => {
                                for repeated_item in &items {
                                    for (group_idx, arg) in args.iter().enumerate() {
                                        argv.push(render_arg(
                                            &format!("{location}.argv[{group_idx}]"),
                                            arg,
                                            ItemResolution::StaticConfig(repeated_item),
                                            needs_helper_for_program_templates,
                                            needs_runtime_config_for_program_templates,
                                        )?);
                                    }
                                }
                            }
                        }

                        emit_program_arg_templates(
                            out,
                            argv,
                            runtime_when,
                            needs_helper_for_program_templates,
                            needs_runtime_config_for_program_templates,
                        );
                        Ok(())
                    }
                    ConfigEachResolution::Runtime => {
                        *needs_helper_for_program_templates = true;
                        *needs_runtime_config_for_program_templates = true;

                        let repeated = match &item.value {
                            amber_manifest::ProgramArgValue::Arg(arg) => {
                                RepeatedProgramArgTemplate {
                                    when: runtime_when,
                                    each: RepeatedTemplateSource::Config {
                                        path: each.query().to_string(),
                                    },
                                    arg: Some(render_arg(
                                        &format!("{location}.arg"),
                                        arg,
                                        ItemResolution::RuntimeCurrentItem,
                                        needs_helper_for_program_templates,
                                        needs_runtime_config_for_program_templates,
                                    )?),
                                    argv: Vec::new(),
                                    join: item.join().map(ToString::to_string),
                                }
                            }
                            amber_manifest::ProgramArgValue::Argv(args) => {
                                let mut argv = Vec::with_capacity(args.0.len());
                                for (group_idx, arg) in args.iter().enumerate() {
                                    argv.push(render_arg(
                                        &format!("{location}.argv[{group_idx}]"),
                                        arg,
                                        ItemResolution::RuntimeCurrentItem,
                                        needs_helper_for_program_templates,
                                        needs_runtime_config_for_program_templates,
                                    )?);
                                }
                                RepeatedProgramArgTemplate {
                                    when: runtime_when,
                                    each: RepeatedTemplateSource::Config {
                                        path: each.query().to_string(),
                                    },
                                    arg: None,
                                    argv,
                                    join: None,
                                }
                            }
                        };

                        out.push(ProgramArgTemplate::Repeated(repeated));
                        Ok(())
                    }
                }
            }
            InterpolationSource::Item => {
                unreachable!("each paths never use item as a source")
            }
            _ => unreachable!("unsupported interpolation source for each"),
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn build_program_plan(
    scenario: &Scenario,
    id: ComponentId,
    program: &amber_manifest::Program,
    program_support: ProgramSupport,
    runtime_address_resolution: RuntimeAddressResolution,
    slots: &BTreeMap<String, SlotValue>,
    template_opt: Option<&rc::ConfigNode>,
    component_schema: Option<&Value>,
) -> Result<ProgramPlan, MeshError> {
    let component = component_label(scenario, id);
    let mut entrypoint_ts: Vec<ProgramArgTemplate> = Vec::new();
    let mut needs_helper_for_program_templates = false;
    let mut needs_runtime_config_for_program_templates = false;
    let (source, program_env) = match program {
        amber_manifest::Program::Image(program) => {
            match program_support {
                ProgramSupport::Path { backend_label } => {
                    return Err(MeshError::new(format!(
                        "component {} uses `program.image`, but {backend_label} only supports \
                         `program.path`",
                        component_label(scenario, id)
                    )));
                }
                ProgramSupport::Vm { backend_label } => {
                    return Err(MeshError::new(format!(
                        "component {} uses `program.image`, but {backend_label} only supports \
                         `program.vm`",
                        component_label(scenario, id)
                    )));
                }
                ProgramSupport::Image { .. } => {}
            }
            let mut image_parts: Vec<ProgramImagePart> = Vec::new();
            let image = program
                .image
                .parse::<amber_manifest::InterpolatedString>()
                .map_err(|err| {
                    MeshError::new(format!(
                        "failed to parse program.image interpolation in {component}: {err}",
                    ))
                })?;
            // If program.image is exactly one `${config...}` interpolation, image diagnostics should
            // point at the corresponding component config path; otherwise they should point at
            // program.image itself.
            let image_origin = match image.parts.as_slice() {
                [
                    InterpolatedPart::Interpolation {
                        source: InterpolationSource::Config,
                        query,
                    },
                ] => ProgramImageOrigin::ComponentConfigPath(query.clone()),
                _ => ProgramImageOrigin::ProgramImage,
            };
            for part in &image.parts {
                match part {
                    InterpolatedPart::Literal(lit) => {
                        push_image_literal(&mut image_parts, lit.clone())
                    }
                    InterpolatedPart::Interpolation { source, query } => {
                        if let Some(value) = resolve_slot_interpolation(
                            scenario,
                            id,
                            "program.image",
                            source,
                            query,
                            slots,
                        )? {
                            push_image_literal(&mut image_parts, value);
                            continue;
                        }
                        match resolve_config_query_for_program_image(template_opt, query)? {
                            ImageConfigResolution::Static(value) => {
                                push_image_literal(&mut image_parts, value);
                            }
                            ImageConfigResolution::RuntimeTemplate(parts) => {
                                extend_image_parts(&mut image_parts, parts);
                            }
                        }
                    }
                    _ => {
                        return Err(MeshError::new(format!(
                            "unsupported interpolation part in {component} program.image",
                        )));
                    }
                }
            }
            if image_parts.is_empty() {
                return Err(MeshError::new(format!(
                    "internal error: produced empty image template for {component} program.image",
                )));
            }
            let image = if image_parts
                .iter()
                .any(|part| matches!(part, ProgramImagePart::RootConfigPath(_)))
            {
                ProgramImagePlan::RuntimeTemplate(image_parts)
            } else {
                let mut rendered = String::new();
                for part in image_parts {
                    let ProgramImagePart::Literal(lit) = part else {
                        unreachable!("runtime root config path was handled above");
                    };
                    rendered.push_str(&lit);
                }
                ProgramImagePlan::Static(rendered)
            };

            for (idx, item) in program.entrypoint.0.iter().enumerate() {
                append_program_command_item_templates(
                    scenario,
                    id,
                    "program.entrypoint",
                    idx,
                    item,
                    runtime_address_resolution,
                    slots,
                    template_opt,
                    &mut needs_helper_for_program_templates,
                    &mut needs_runtime_config_for_program_templates,
                    &mut entrypoint_ts,
                )?;
            }

            (
                ProgramSourcePlan::Image {
                    image,
                    image_origin,
                },
                &program.common.env,
            )
        }
        amber_manifest::Program::Path(program) => {
            match program_support {
                ProgramSupport::Image { backend_label } => {
                    return Err(MeshError::new(format!(
                        "component {} uses `program.path`, but {backend_label} only supports \
                         `program.image`; use `amber compile --direct`",
                        component_label(scenario, id)
                    )));
                }
                ProgramSupport::Vm { backend_label } => {
                    return Err(MeshError::new(format!(
                        "component {} uses `program.path`, but {backend_label} only supports \
                         `program.vm`",
                        component_label(scenario, id)
                    )));
                }
                ProgramSupport::Path { .. } => {}
            }
            let path = program
                .path
                .parse::<amber_manifest::InterpolatedString>()
                .map_err(|err| {
                    MeshError::new(format!(
                        "failed to parse program.path interpolation in {component}: {err}",
                    ))
                })?;
            let path_ts = resolve_program_template_string(
                scenario,
                id,
                "program.path",
                &path,
                runtime_address_resolution,
                slots,
                template_opt,
                ItemResolution::NotAllowed,
                &mut needs_helper_for_program_templates,
                &mut needs_runtime_config_for_program_templates,
                true,
            )?;
            if rc::template_string_is_runtime(&path_ts) {
                return Err(MeshError::new(format!(
                    "component {component} uses runtime interpolation in program.path, but direct \
                     execution requires an explicit executable path"
                )));
            }
            validate_explicit_program_path(&component, &render_template_string_static(&path_ts)?)?;
            entrypoint_ts.push(ProgramArgTemplate::Arg(path_ts));

            for (idx, item) in program.args.0.iter().enumerate() {
                append_program_command_item_templates(
                    scenario,
                    id,
                    "program.args",
                    idx,
                    item,
                    runtime_address_resolution,
                    slots,
                    template_opt,
                    &mut needs_helper_for_program_templates,
                    &mut needs_runtime_config_for_program_templates,
                    &mut entrypoint_ts,
                )?;
            }

            (ProgramSourcePlan::Path, &program.common.env)
        }
        amber_manifest::Program::Vm(program) => {
            let ProgramSupport::Vm { .. } = program_support else {
                return Err(MeshError::new(format!(
                    "component {} uses `program.vm`, but this backend does not support VM programs",
                    component_label(scenario, id)
                )));
            };
            let mut image_parts: Vec<ProgramImagePart> = Vec::new();
            let image = program
                .0
                .image
                .parse::<amber_manifest::InterpolatedString>()
                .map_err(|err| {
                    MeshError::new(format!(
                        "failed to parse program.vm.image interpolation in {component}: {err}",
                    ))
                })?;
            let image_origin = match image.parts.as_slice() {
                [
                    InterpolatedPart::Interpolation {
                        source: InterpolationSource::Config,
                        query,
                    },
                ] => ProgramImageOrigin::ComponentConfigPath(query.clone()),
                _ => ProgramImageOrigin::ProgramImage,
            };
            for part in &image.parts {
                match part {
                    InterpolatedPart::Literal(lit) => {
                        push_image_literal(&mut image_parts, lit.clone())
                    }
                    InterpolatedPart::Interpolation { source, query } => {
                        if let Some(value) = resolve_slot_interpolation(
                            scenario,
                            id,
                            "program.vm.image",
                            source,
                            query,
                            slots,
                        )? {
                            push_image_literal(&mut image_parts, value);
                            continue;
                        }
                        match resolve_config_query_for_program_image(template_opt, query)? {
                            ImageConfigResolution::Static(value) => {
                                push_image_literal(&mut image_parts, value);
                            }
                            ImageConfigResolution::RuntimeTemplate(parts) => {
                                extend_image_parts(&mut image_parts, parts);
                            }
                        }
                    }
                    _ => {
                        return Err(MeshError::new(format!(
                            "unsupported interpolation part in {component} program.vm.image",
                        )));
                    }
                }
            }
            if image_parts.is_empty() {
                return Err(MeshError::new(format!(
                    "internal error: produced empty image template for {component} \
                     program.vm.image",
                )));
            }
            let image = if image_parts
                .iter()
                .any(|part| matches!(part, ProgramImagePart::RootConfigPath(_)))
            {
                ProgramImagePlan::RuntimeTemplate(image_parts)
            } else {
                let mut rendered = String::new();
                for part in image_parts {
                    let ProgramImagePart::Literal(lit) = part else {
                        unreachable!("runtime root config path was handled above");
                    };
                    rendered.push_str(&lit);
                }
                ProgramImagePlan::Static(rendered)
            };

            return Ok(ProgramPlan::Resolved {
                source: ProgramSourcePlan::Image {
                    image,
                    image_origin,
                },
                entrypoint: Vec::new(),
                env: BTreeMap::new(),
            });
        }
        _ => {
            return Err(MeshError::new(format!(
                "component {} uses an unsupported program variant",
                component_label(scenario, id)
            )));
        }
    };

    let mut env_ts: BTreeMap<String, ProgramEnvTemplate> = BTreeMap::new();
    for (k, v) in program_env {
        let when = resolve_program_when(v.when(), template_opt, slots)?;
        if matches!(when, ResolvedWhen::Absent) {
            continue;
        }
        let runtime_when = match &when {
            ResolvedWhen::Runtime(query) => Some(query.clone()),
            ResolvedWhen::Present | ResolvedWhen::Absent => None,
        };
        let location = format!("program.env.{k}.value");

        match v.each() {
            None => {
                let ts = resolve_program_template_string(
                    scenario,
                    id,
                    &location,
                    v.value(),
                    runtime_address_resolution,
                    slots,
                    template_opt,
                    ItemResolution::NotAllowed,
                    &mut needs_helper_for_program_templates,
                    &mut needs_runtime_config_for_program_templates,
                    false,
                )?;
                if let Some(when) = runtime_when {
                    needs_helper_for_program_templates = true;
                    needs_runtime_config_for_program_templates = true;
                    env_ts.insert(
                        k.clone(),
                        ProgramEnvTemplate::Conditional(ConditionalProgramEnvTemplate {
                            when,
                            value: ts,
                        }),
                    );
                } else {
                    env_ts.insert(k.clone(), ProgramEnvTemplate::Value(ts));
                }
            }
            Some(each) => match each.source() {
                InterpolationSource::Slots => {
                    let scope = id.0 as u64;
                    let slot_name = each
                        .slot()
                        .expect("slot-based each path should expose a slot name");
                    let items = repeated_slot_items_for_component(
                        scenario,
                        id,
                        slot_name,
                        slots,
                        &format!("program.env.{k}"),
                    )?;
                    if items.is_empty() {
                        continue;
                    }

                    let mut rendered = Vec::with_capacity(items.len());
                    for (item_idx, item) in items.iter().enumerate() {
                        let item_resolution = if matches!(
                            runtime_address_resolution,
                            RuntimeAddressResolution::Deferred
                        ) {
                            ItemResolution::RuntimeSlotTemplate {
                                scope,
                                slot: slot_name,
                                index: item_idx,
                                item,
                            }
                        } else {
                            ItemResolution::StaticSlot(item)
                        };
                        rendered.push(resolve_program_template_string(
                            scenario,
                            id,
                            &location,
                            v.value(),
                            runtime_address_resolution,
                            slots,
                            template_opt,
                            item_resolution,
                            &mut needs_helper_for_program_templates,
                            &mut needs_runtime_config_for_program_templates,
                            false,
                        )?);
                    }
                    let value = join_template_strings(
                        rendered,
                        v.join().expect("program env each requires join"),
                    );
                    if let Some(when) = runtime_when {
                        needs_helper_for_program_templates = true;
                        needs_runtime_config_for_program_templates = true;
                        env_ts.insert(
                            k.clone(),
                            ProgramEnvTemplate::Conditional(ConditionalProgramEnvTemplate {
                                when,
                                value,
                            }),
                        );
                    } else {
                        env_ts.insert(k.clone(), ProgramEnvTemplate::Value(value));
                    }
                }
                InterpolationSource::Config => {
                    match resolve_config_each_values(template_opt, each.query(), &location)? {
                        ConfigEachResolution::Static(items) => {
                            if items.is_empty() {
                                continue;
                            }

                            let mut rendered = Vec::with_capacity(items.len());
                            for item in &items {
                                rendered.push(resolve_program_template_string(
                                    scenario,
                                    id,
                                    &location,
                                    v.value(),
                                    runtime_address_resolution,
                                    slots,
                                    template_opt,
                                    ItemResolution::StaticConfig(item),
                                    &mut needs_helper_for_program_templates,
                                    &mut needs_runtime_config_for_program_templates,
                                    false,
                                )?);
                            }
                            let value = join_template_strings(
                                rendered,
                                v.join().expect("program env each requires join"),
                            );
                            if let Some(when) = runtime_when {
                                needs_helper_for_program_templates = true;
                                needs_runtime_config_for_program_templates = true;
                                env_ts.insert(
                                    k.clone(),
                                    ProgramEnvTemplate::Conditional(
                                        ConditionalProgramEnvTemplate { when, value },
                                    ),
                                );
                            } else {
                                env_ts.insert(k.clone(), ProgramEnvTemplate::Value(value));
                            }
                        }
                        ConfigEachResolution::Runtime => {
                            needs_helper_for_program_templates = true;
                            needs_runtime_config_for_program_templates = true;
                            env_ts.insert(
                                k.clone(),
                                ProgramEnvTemplate::Repeated(RepeatedProgramEnvTemplate {
                                    when: runtime_when,
                                    each: RepeatedTemplateSource::Config {
                                        path: each.query().to_string(),
                                    },
                                    value: resolve_program_template_string(
                                        scenario,
                                        id,
                                        &location,
                                        v.value(),
                                        runtime_address_resolution,
                                        slots,
                                        template_opt,
                                        ItemResolution::RuntimeCurrentItem,
                                        &mut needs_helper_for_program_templates,
                                        &mut needs_runtime_config_for_program_templates,
                                        false,
                                    )?,
                                    join: v
                                        .join()
                                        .expect("program env each requires join")
                                        .to_string(),
                                }),
                            );
                        }
                    }
                }
                InterpolationSource::Item => unreachable!("each paths never use item"),
                _ => unreachable!("unsupported interpolation source for each"),
            },
        }
    }

    if needs_helper_for_program_templates {
        if needs_runtime_config_for_program_templates {
            component_schema.ok_or_else(|| {
                MeshError::new(format!(
                    "component {} requires config_schema when using runtime config interpolation",
                    component
                ))
            })?;
        }

        let spec = TemplateSpec {
            program: ProgramTemplateSpec {
                entrypoint: entrypoint_ts,
                env: env_ts,
            },
        };

        Ok(ProgramPlan::Helper {
            source,
            template_spec: spec,
            needs_runtime_config: needs_runtime_config_for_program_templates,
        })
    } else {
        let rendered_entrypoint = entrypoint_ts
            .into_iter()
            .map(|arg| match arg {
                ProgramArgTemplate::Arg(ts) => render_template_string_static(&ts),
                ProgramArgTemplate::Conditional(_) => Err(MeshError::new(
                    "internal error: conditional arg item reached resolved program plan",
                )),
                ProgramArgTemplate::Repeated(_) => Err(MeshError::new(
                    "internal error: repeated arg template reached resolved program plan",
                )),
            })
            .collect::<Result<Vec<_>, _>>()?;
        if rendered_entrypoint.is_empty() {
            return Err(MeshError::new(format!(
                "component {component} resolves to an empty program entrypoint"
            )));
        }
        let rendered_env = env_ts
            .into_iter()
            .map(|(k, value)| match value {
                ProgramEnvTemplate::Value(ts) => {
                    render_template_string_static(&ts).map(|rendered| (k, rendered))
                }
                ProgramEnvTemplate::Conditional(_) => Err(MeshError::new(
                    "internal error: conditional env value reached resolved program plan",
                )),
                ProgramEnvTemplate::Repeated(_) => Err(MeshError::new(
                    "internal error: repeated env value reached resolved program plan",
                )),
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        Ok(ProgramPlan::Resolved {
            source,
            entrypoint: rendered_entrypoint,
            env: rendered_env,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use amber_manifest::{Manifest, ManifestDigest};
    use amber_scenario::{BindingEdge, Component, Moniker, Scenario};

    use super::*;

    fn test_scenario() -> Scenario {
        let manifest: Manifest = r#"
            {
              manifest_version: "0.3.0",
              slots: {
                api: { kind: "http", optional: true },
                upstream: { kind: "http", optional: true, multiple: true },
              },
            }
        "#
        .parse()
        .expect("manifest");

        Scenario {
            root: ComponentId(0),
            components: vec![Some(Component {
                id: ComponentId(0),
                parent: None,
                moniker: Moniker::from(Arc::<str>::from("/")),
                digest: ManifestDigest::new([0; 32]),
                config: None,
                config_schema: None,
                program: None,
                slots: manifest
                    .slots()
                    .iter()
                    .map(|(name, decl)| (name.to_string(), decl.clone()))
                    .collect(),
                provides: BTreeMap::new(),
                resources: BTreeMap::new(),
                metadata: None,
                children: Vec::new(),
            })],
            bindings: Vec::<BindingEdge>::new(),
            exports: Vec::new(),
        }
    }

    fn test_slot_values() -> BTreeMap<String, SlotValue> {
        BTreeMap::from([
            (
                "api".to_string(),
                SlotValue::One(SlotObject {
                    url: "http://127.0.0.1:31001".to_string(),
                }),
            ),
            (
                "upstream".to_string(),
                SlotValue::Many(vec![SlotObject {
                    url: "http://127.0.0.1:32001".to_string(),
                }]),
            ),
        ])
    }

    fn component_with_config_and_program(
        id: usize,
        parent: Option<usize>,
        moniker: &str,
        config_schema: Option<serde_json::Value>,
        config: Option<serde_json::Value>,
        program: Option<serde_json::Value>,
    ) -> Component {
        Component {
            id: ComponentId(id),
            parent: parent.map(ComponentId),
            moniker: Moniker::from(Arc::<str>::from(moniker)),
            digest: ManifestDigest::new([id as u8; 32]),
            config,
            config_schema,
            program: program.map(|program| serde_json::from_value(program).expect("program")),
            slots: BTreeMap::new(),
            provides: BTreeMap::new(),
            resources: BTreeMap::new(),
            metadata: None,
            children: Vec::new(),
        }
    }

    #[test]
    fn resolve_slot_interpolation_rejects_whole_slots_when_component_declares_repeated_slots() {
        let err = resolve_slot_interpolation(
            &test_scenario(),
            ComponentId(0),
            "program.args[0]",
            &InterpolationSource::Slots,
            "",
            &test_slot_values(),
        )
        .expect_err("whole-slots interpolation should fail");

        let message = err.to_string();
        assert!(message.contains("`${slots}`"), "{message}");
        assert!(message.contains("multiple: true"), "{message}");
    }

    #[test]
    fn resolve_slot_interpolation_rejects_singular_query_for_repeated_slot() {
        let err = resolve_slot_interpolation(
            &test_scenario(),
            ComponentId(0),
            "program.args[0]",
            &InterpolationSource::Slots,
            "upstream.url",
            &test_slot_values(),
        )
        .expect_err("singular repeated-slot interpolation should fail");

        let message = err.to_string();
        assert!(message.contains("slot `upstream`"), "{message}");
        assert!(message.contains("multiple: true"), "{message}");
        assert!(message.contains("slots.upstream"), "{message}");
    }

    #[test]
    fn build_endpoint_plan_expands_variadic_config_endpoints() {
        let root = component_with_config_and_program(0, None, "/", None, None, None);
        let child = component_with_config_and_program(
            1,
            Some(0),
            "/api",
            Some(serde_json::json!({
                "type": "object",
                "properties": {
                    "ports": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": { "type": "string" },
                                "port": { "type": "integer" },
                                "protocol": { "type": "string" }
                            },
                            "required": ["name", "port", "protocol"]
                        }
                    }
                },
                "required": ["ports"]
            })),
            Some(serde_json::json!({
                "ports": [
                    { "name": "http", "port": 8080, "protocol": "http" },
                    { "name": "admin", "port": 9000, "protocol": "tcp" }
                ]
            })),
            Some(serde_json::json!({
                "image": "service",
                "entrypoint": ["service"],
                "network": {
                    "endpoints": [
                        {
                            "when": "config.missing_optional",
                            "name": "debug",
                            "port": 7000
                        },
                        {
                            "each": "config.ports",
                            "name": "${item.name}",
                            "port": "${item.port}",
                            "protocol": "${item.protocol}"
                        }
                    ]
                }
            })),
        );

        let mut root = root;
        root.children.push(ComponentId(1));
        let scenario = Scenario {
            root: ComponentId(0),
            components: vec![Some(root), Some(child)],
            bindings: Vec::<BindingEdge>::new(),
            exports: Vec::new(),
        };

        let endpoint_plan = build_endpoint_plan(&scenario).expect("endpoint plan");

        assert_eq!(
            endpoint_plan.component_endpoints(ComponentId(1)),
            &[
                ExpandedEndpoint {
                    name: "http".to_string(),
                    port: 8080,
                    protocol: amber_manifest::NetworkProtocol::Http,
                },
                ExpandedEndpoint {
                    name: "admin".to_string(),
                    port: 9000,
                    protocol: amber_manifest::NetworkProtocol::Tcp,
                },
            ]
        );
    }
}
