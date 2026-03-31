// Shared backend config planning: resolve program templates/mounts and compute per-component scope.
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::Path,
};

use amber_config as rc;
use amber_manifest::{
    InterpolatedPart, InterpolationSource, MountSource, ProgramArgItem, VmScalarU32,
};
use amber_scenario::{
    ComponentId, FileMount, FileMountSource, Program, ProgramCondition, ProgramEach, ProgramMount,
    Scenario,
};
use amber_template::{
    ConditionalProgramArgTemplate, ConditionalProgramEnvTemplate, MountSpec, MountTemplateSpec,
    ProgramArgTemplate, ProgramEnvTemplate, ProgramTemplateSpec, RepeatedProgramArgTemplate,
    RepeatedProgramEnvTemplate, RepeatedTemplateSource, TemplatePart, TemplateSpec, TemplateString,
};
use base64::Engine as _;
use serde::Serialize;
use serde_json::Value;

use crate::{
    config::{
        analysis::{ComponentConfigAnalysis, RuntimeValueSource, ScenarioConfigAnalysis},
        query::{ConfigEachResolution, ConfigPresence},
        scope::RuntimeConfigView,
    },
    slots::{
        SlotObject, SlotTarget, SlotValue, parse_slot_query, resolve_slot_query,
        slot_query_is_present,
    },
    targets::common::{TargetError as MeshError, component_label},
};
mod mounts;
mod templates;

use self::templates::{
    ItemResolution, ResolvedWhen, append_program_command_item_templates, join_template_strings,
    repeated_slot_items_for_component, resolve_item_interpolation_from_value,
    resolve_program_template_string, resolve_program_when, resolve_slot_item_interpolation,
};
pub(crate) use self::{mounts::build_mount_specs, templates::resolve_slot_interpolation};

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

pub(crate) fn build_config_plan(
    scenario: &Scenario,
    config_analysis: &ScenarioConfigAnalysis,
    program_components: &[ComponentId],
    program_support: ProgramSupport,
    runtime_address_resolution: RuntimeAddressResolution,
    slot_values_by_component: &HashMap<ComponentId, BTreeMap<String, SlotValue>>,
) -> Result<ConfigPlan, MeshError> {
    if let Some(err) = config_analysis.template_errors().first() {
        return Err(MeshError::new(format!(
            "failed to compose component config templates: {}",
            err.message
        )));
    }

    let root_leaves = config_analysis.root_leaves().to_vec();
    let root_leaf_paths: BTreeSet<&str> =
        root_leaves.iter().map(|leaf| leaf.path.as_str()).collect();

    let mut program_plans = HashMap::new();
    let mut vm_runtime_paths_by_component = HashMap::new();
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
        let component_config = config_analysis.component(*id).ok_or_else(|| {
            MeshError::new(format!(
                "no config analysis for component {}",
                component_label(scenario, *id)
            ))
        })?;

        let plan = build_program_plan(
            scenario,
            *id,
            program,
            program_support,
            runtime_address_resolution,
            slots,
            component_config,
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
            component_config,
            &mut vm_scalar_paths,
        )?;
        if !vm_scalar_paths.is_empty() {
            needs_runtime_config = true;
        }
        let mut vm_image_paths = BTreeSet::new();
        collect_vm_image_runtime_paths(
            scenario,
            *id,
            program,
            slots,
            component_config,
            &mut vm_image_paths,
        )?;
        if !vm_image_paths.is_empty() {
            needs_runtime_config = true;
        }
        let mut vm_cloud_init_paths = BTreeSet::new();
        collect_vm_cloud_init_runtime_paths(
            scenario,
            *id,
            program,
            slots,
            component_config,
            &mut vm_cloud_init_paths,
        )?;
        if !vm_cloud_init_paths.is_empty() {
            needs_runtime_config = true;
        }
        let mut vm_runtime_paths = vm_scalar_paths;
        vm_runtime_paths.extend(vm_image_paths);
        vm_runtime_paths.extend(vm_cloud_init_paths);
        vm_runtime_paths_by_component.insert(*id, vm_runtime_paths);
        program_plans.insert(*id, plan);
    }

    let mount_specs = build_mount_specs(
        scenario,
        config_analysis,
        program_components,
        runtime_address_resolution,
        slot_values_by_component,
    )?;
    let mounts_need_runtime = mount_specs
        .values()
        .any(|specs| mount_specs_need_config(specs));
    needs_runtime_config = needs_runtime_config || mounts_need_runtime;
    if !mount_specs.is_empty() {
        needs_helper = true;
    }

    if needs_runtime_config && config_analysis.root_schema().is_none() {
        return Err(MeshError::new(
            "root component must declare `config_schema` when runtime config interpolation is \
             required",
        ));
    }

    let mut runtime_views = HashMap::new();
    if needs_runtime_config {
        for id in program_components {
            let program_plan = program_plans
                .get(id)
                .expect("program plan should exist for program component");
            let mount_specs = mount_specs.get(id);
            let vm_runtime_paths = vm_runtime_paths_by_component
                .get(id)
                .expect("vm runtime path set should exist for program component");
            let needs_config_payload = program_plan.needs_runtime_config()
                || mount_specs.is_some_and(|specs| mount_specs_need_config(specs))
                || !vm_runtime_paths.is_empty();
            if !needs_config_payload {
                continue;
            }

            let component_config = config_analysis
                .component(*id)
                .expect("component config analysis should exist");
            let used_paths = used_component_paths(
                program_plan,
                mount_specs.map(|specs| specs.as_slice()),
                Some(vm_runtime_paths),
            );

            let view = component_config
                .build_runtime_view(&component_label(scenario, *id), &used_paths)
                .map_err(MeshError::new)?;
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
            if let Ok(MountSource::Config(path)) = rendered.parse::<MountSource>() {
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
    program: &Program,
    slots: &BTreeMap<String, SlotValue>,
    component_config: &ComponentConfigAnalysis,
    out: &mut BTreeSet<String>,
) -> Result<(), MeshError> {
    let Program::Vm(program) = program else {
        return Ok(());
    };
    for (field_name, raw) in [
        (
            "program.vm.cloud_init.user_data",
            program.cloud_init.user_data.as_deref(),
        ),
        (
            "program.vm.cloud_init.vendor_data",
            program.cloud_init.vendor_data.as_deref(),
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
            component_config,
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

fn collect_vm_image_runtime_paths(
    scenario: &Scenario,
    id: ComponentId,
    program: &Program,
    slots: &BTreeMap<String, SlotValue>,
    component_config: &ComponentConfigAnalysis,
    out: &mut BTreeSet<String>,
) -> Result<(), MeshError> {
    let Program::Vm(program) = program else {
        return Ok(());
    };
    let image = program
        .image
        .parse::<amber_manifest::InterpolatedString>()
        .map_err(|err| {
            MeshError::new(format!(
                "failed to parse program.vm.image interpolation in {}: {err}",
                component_label(scenario, id)
            ))
        })?;
    for part in &image.parts {
        let InterpolatedPart::Interpolation { source, query } = part else {
            continue;
        };
        if resolve_slot_interpolation(scenario, id, "program.vm.image", source, query, slots)?
            .is_some()
        {
            continue;
        }
        if component_config
            .resolve_static_string_query(query)
            .map_err(MeshError::new)?
            .is_none()
        {
            out.insert(query.clone());
        }
    }
    Ok(())
}

fn collect_vm_scalar_runtime_paths(
    program: &Program,
    component: &str,
    component_config: &ComponentConfigAnalysis,
    out: &mut BTreeSet<String>,
) -> Result<(), MeshError> {
    let Program::Vm(program) = program else {
        return Ok(());
    };
    for (field_name, scalar) in [
        ("program.vm.cpus", &program.cpus),
        ("program.vm.memory_mib", &program.memory_mib),
    ] {
        if let VmScalarResolutionU32::RuntimeConfig(path) =
            resolve_vm_scalar_u32(component_config, scalar, component, field_name)?
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
    component_config: &ComponentConfigAnalysis,
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
        component_config,
        ItemResolution::NotAllowed,
        &mut needs_helper,
        &mut needs_runtime_config,
        false,
    )
    .map(Some)
}

pub(crate) fn resolve_vm_scalar_u32(
    component_config: &ComponentConfigAnalysis,
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
            resolve_vm_scalar_query(component_config, query, field_name)
        }
        _ => Err(MeshError::new(format!(
            "component {component} uses an unsupported scalar form in {field_name}"
        ))),
    }
}

fn resolve_vm_scalar_query(
    component_config: &ComponentConfigAnalysis,
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

    match component_config
        .resolve_static_value(query)
        .map_err(MeshError::new)?
    {
        Some(value) => {
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
        None => Ok(VmScalarResolutionU32::RuntimeConfig(query.to_string())),
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

fn template_string_uses_config(value: &TemplateString) -> bool {
    value
        .iter()
        .any(|part| matches!(part, TemplatePart::Config { .. }))
}

fn file_mount_uses_config(mount: &FileMount) -> bool {
    mount
        .when
        .as_ref()
        .is_some_and(|when| matches!(when, ProgramCondition::Config { .. }))
        || mount
            .each
            .as_ref()
            .is_some_and(|each| matches!(each, ProgramEach::Config { .. }))
        || template_string_uses_config(&mount.path)
        || matches!(&mount.source, FileMountSource::Config { .. })
}

pub(crate) fn build_endpoint_plan(scenario: &Scenario) -> Result<EndpointPlan, MeshError> {
    let mut by_component = HashMap::new();

    for (id, component) in scenario.components_iter() {
        let Some(program) = component.program.as_ref() else {
            continue;
        };
        let Some(network) = program.network() else {
            continue;
        };
        if network.endpoints.is_empty() {
            continue;
        }
        by_component.insert(
            id,
            network
                .endpoints
                .iter()
                .map(|endpoint| ExpandedEndpoint {
                    name: endpoint.name.clone(),
                    port: endpoint.port,
                    protocol: endpoint.protocol,
                })
                .collect(),
        );
    }

    Ok(EndpointPlan { by_component })
}

fn resolve_condition_presence_for_program(
    source: InterpolationSource,
    query: &str,
    component_config: &ComponentConfigAnalysis,
    slots: &BTreeMap<String, SlotValue>,
) -> Result<ConfigPresence, MeshError> {
    match source {
        InterpolationSource::Config => component_config
            .resolve_presence(query)
            .map_err(MeshError::new),
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

fn resolve_config_query_for_program(
    component_config: &ComponentConfigAnalysis,
    query: &str,
) -> Result<ConfigResolution, MeshError> {
    match component_config
        .resolve_static_string_query(query)
        .map_err(MeshError::new)?
    {
        Some(value) => Ok(ConfigResolution::Static(value)),
        None => Ok(ConfigResolution::Runtime),
    }
}

fn resolve_program_image_runtime_node(
    node: &rc::ConfigNode,
    field_name: &str,
) -> Result<ImageConfigResolution, MeshError> {
    match node {
        rc::ConfigNode::ConfigRef(path) => {
            if path.is_empty() {
                return Err(MeshError::new(format!(
                    "{field_name} cannot reference the entire runtime config object; reference a \
                     string leaf like ${{config.image}}"
                )));
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
                            return Err(MeshError::new(format!(
                                "{field_name} cannot reference the entire runtime config object; \
                                 reference a string leaf like ${{config.image}}"
                            )));
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
    component_config: &ComponentConfigAnalysis,
    query: &str,
    field_name: &str,
) -> Result<ImageConfigResolution, MeshError> {
    match component_config
        .resolve_runtime_value_source(query)
        .map_err(MeshError::new)?
    {
        RuntimeValueSource::Static(value) => Ok(ImageConfigResolution::Static(
            rc::stringify_for_interpolation(&value).map_err(|e| MeshError::new(e.to_string()))?,
        )),
        RuntimeValueSource::RuntimeRootPath(path) => {
            if path.is_empty() {
                return Err(MeshError::new(format!(
                    "{field_name} cannot reference the entire runtime config object; reference a \
                     string leaf like ${{config.image}}"
                )));
            }
            Ok(ImageConfigResolution::RuntimeTemplate(vec![
                ProgramImagePart::RootConfigPath(path),
            ]))
        }
        RuntimeValueSource::RuntimeNode(cur) => resolve_program_image_runtime_node(cur, field_name),
    }
}

fn resolve_config_query_for_mount(
    component_config: &ComponentConfigAnalysis,
    query: &str,
) -> Result<MountResolution, MeshError> {
    match component_config
        .resolve_static_value(query)
        .map_err(MeshError::new)?
    {
        Some(value) => Ok(MountResolution::Static(value)),
        None => Ok(MountResolution::Runtime),
    }
}

fn resolve_config_each_values(
    component_config: &ComponentConfigAnalysis,
    query: &str,
    location: &str,
) -> Result<ConfigEachResolution, MeshError> {
    component_config
        .resolve_each_values(query, location)
        .map_err(MeshError::new)
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

fn build_program_plan(
    scenario: &Scenario,
    id: ComponentId,
    program: &Program,
    program_support: ProgramSupport,
    runtime_address_resolution: RuntimeAddressResolution,
    slots: &BTreeMap<String, SlotValue>,
    component_config: &ComponentConfigAnalysis,
) -> Result<ProgramPlan, MeshError> {
    let component = component_label(scenario, id);
    let mut entrypoint_ts: Vec<ProgramArgTemplate> = Vec::new();
    let mut needs_helper_for_program_templates = false;
    let mut needs_runtime_config_for_program_templates = false;
    let (source, program_env) = match program {
        Program::Image(program) => {
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
                        match resolve_config_query_for_program_image(
                            component_config,
                            query,
                            "program.image",
                        )? {
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
                    component_config,
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
        Program::Path(program) => {
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
                component_config,
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
                    component_config,
                    &mut needs_helper_for_program_templates,
                    &mut needs_runtime_config_for_program_templates,
                    &mut entrypoint_ts,
                )?;
            }

            (ProgramSourcePlan::Path, &program.common.env)
        }
        Program::Vm(program) => {
            let ProgramSupport::Vm { .. } = program_support else {
                return Err(MeshError::new(format!(
                    "component {} uses `program.vm`, but this backend does not support VM programs",
                    component_label(scenario, id)
                )));
            };
            let mut image_parts: Vec<ProgramImagePart> = Vec::new();
            let image = program
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
                        match resolve_config_query_for_program_image(
                            component_config,
                            query,
                            "program.vm.image",
                        )? {
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
        let when = resolve_program_when(v.when(), component_config, slots)?;
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
                    component_config,
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
                            component_config,
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
                    match resolve_config_each_values(component_config, each.query(), &location)? {
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
                                    component_config,
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
                                        component_config,
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
            component_config.component_schema().ok_or_else(|| {
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
mod tests;
