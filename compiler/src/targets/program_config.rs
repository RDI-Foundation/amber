// Shared backend config planning: resolve program templates/mounts and compute per-component scope.
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::Path,
};

use amber_config as rc;
use amber_manifest::{
    InterpolatedPart, InterpolationSource, MountSource, ProgramArgItem, framework_capability,
};
use amber_scenario::{ComponentId, Scenario};
use amber_template::{
    ConditionalProgramArgTemplate, ProgramArgTemplate, ProgramTemplateSpec, TemplatePart,
    TemplateSpec, TemplateString,
};
use base64::Engine as _;
use serde::Serialize;
use serde_json::Value;

use crate::{
    binding_query::{BindingObject, parse_binding_query, resolve_binding_query},
    config_scope::{RuntimeConfigView, build_runtime_config_view},
    config_templates,
    slot_query::{SlotObject, resolve_slot_query},
    targets::common::{TargetError as MeshError, component_label},
};

#[derive(Clone, Debug)]
pub(crate) struct ConfigPlan {
    pub(crate) root_leaves: Vec<rc::SchemaLeaf>,
    pub(crate) program_plans: HashMap<ComponentId, ProgramPlan>,
    pub(crate) mount_specs: HashMap<ComponentId, Vec<MountSpec>>,
    pub(crate) binding_values_by_scope: HashMap<u64, BTreeMap<String, BindingObject>>,
    pub(crate) needs_helper: bool,
    pub(crate) needs_runtime_config: bool,
    pub(crate) runtime_views: HashMap<ComponentId, RuntimeConfigView>,
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
    ImageOnly { backend_label: &'static str },
    PathOnly { backend_label: &'static str },
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

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum MountSpec {
    Literal { path: String, content: String },
    Config { path: String, config: String },
}

pub(crate) fn build_config_plan(
    scenario: &Scenario,
    program_components: &[ComponentId],
    program_support: ProgramSupport,
    runtime_address_resolution: RuntimeAddressResolution,
    slot_values_by_component: &HashMap<ComponentId, BTreeMap<String, SlotObject>>,
    binding_values_by_component: &HashMap<ComponentId, BTreeMap<String, BindingObject>>,
) -> Result<ConfigPlan, MeshError> {
    let composed =
        config_templates::compose_root_config_templates(scenario.root, &scenario.components);
    if let Some(err) = composed.errors.first() {
        return Err(MeshError::new(format!(
            "failed to compose component config templates: {}",
            err.message
        )));
    }

    let mut used_config_paths_by_component: HashMap<ComponentId, BTreeSet<String>> =
        HashMap::with_capacity(program_components.len());
    for id in program_components {
        let component = scenario.component(*id);
        let Some(program) = component.program.as_ref() else {
            continue;
        };
        let template_opt = composed
            .templates
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

    let required_bindings_by_scope =
        collect_required_bindings_by_scope(&used_config_paths_by_component, &composed.templates)?;
    let binding_urls_by_scope = binding_urls_by_scope(
        scenario,
        slot_values_by_component,
        &required_bindings_by_scope,
    )?;
    let resolved_templates = if matches!(
        runtime_address_resolution,
        RuntimeAddressResolution::Deferred
    ) {
        composed.templates
    } else {
        resolve_binding_templates(
            composed.templates,
            &binding_urls_by_scope,
            &used_config_paths_by_component,
            scenario,
        )?
    };

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
        let bindings = binding_values_by_component.get(id).ok_or_else(|| {
            MeshError::new(format!(
                "internal error: missing binding values for {}",
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
            bindings,
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
        program_plans.insert(*id, plan);
    }

    let mount_specs = build_mount_specs(scenario, program_components, &resolved_templates)?;
    let mounts_need_runtime = mount_specs.values().any(|specs| {
        specs
            .iter()
            .any(|spec| matches!(spec, MountSpec::Config { .. }))
    });
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
            let needs_config_payload = program_plan.needs_runtime_config()
                || mount_specs.is_some_and(|specs| mount_specs_need_config(specs));
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
            let used_paths =
                used_component_paths(program_plan, mount_specs.map(|specs| specs.as_slice()));

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
        binding_values_by_scope: binding_urls_by_scope,
        needs_helper,
        needs_runtime_config,
        runtime_views,
    })
}

// Security: only expose runtime config needed by program templates and mounts.
fn used_component_paths(
    program_plan: &ProgramPlan,
    mount_specs: Option<&[MountSpec]>,
) -> BTreeSet<String> {
    let mut used = BTreeSet::new();

    if let ProgramPlan::Helper { template_spec, .. } = program_plan {
        collect_used_paths_from_template_spec(template_spec, &mut used);
    }

    if let Some(specs) = mount_specs {
        for spec in specs {
            if let MountSpec::Config { config, .. } = spec {
                used.insert(config.clone());
            }
        }
    }

    used
}

fn encode_json_b64(value: &(impl Serialize + ?Sized)) -> Result<String, serde_json::Error> {
    let bytes = serde_json::to_vec(value)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

pub(crate) fn mount_specs_need_config(specs: &[MountSpec]) -> bool {
    specs
        .iter()
        .any(|spec| matches!(spec, MountSpec::Config { .. }))
}

pub(crate) fn build_component_runtime_plan<'a>(
    component_label: &str,
    program_plan: &'a ProgramPlan,
    mount_specs: Option<&'a [MountSpec]>,
    runtime_view: Option<&'a RuntimeConfigView>,
    extra_helper_requirement: bool,
) -> Result<ComponentRuntimePlan<'a>, MeshError> {
    let needs_config_payload =
        program_plan.needs_runtime_config() || mount_specs.is_some_and(mount_specs_need_config);
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
            ProgramArgTemplate::Group(group) => {
                out.insert(group.when_present.clone());
                for ts in &group.argv {
                    collect_used_paths_from_template_string(ts, out);
                }
            }
        }
    }
    for ts in spec.program.env.values() {
        collect_used_paths_from_template_string(ts, out);
    }
}

fn collect_used_paths_from_template_string(ts: &TemplateString, out: &mut BTreeSet<String>) {
    for part in ts {
        if let TemplatePart::Config { config } = part {
            out.insert(config.clone());
        }
    }
}

fn build_mount_specs(
    scenario: &Scenario,
    program_components: &[ComponentId],
    resolved_templates: &HashMap<ComponentId, rc::RootConfigTemplate>,
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

        let has_config_or_secret_mount = program.mounts().iter().any(|mount| {
            matches!(
                mount.source,
                MountSource::Config(_) | MountSource::Secret(_)
            )
        });

        if has_config_or_secret_mount && component.config_schema.is_none() {
            return Err(MeshError::new(format!(
                "component {} requires config_schema when using program.mounts",
                component_label(scenario, *id)
            )));
        }

        let template_opt = if has_config_or_secret_mount {
            let template = resolved_templates.get(id).ok_or_else(|| {
                MeshError::new(format!(
                    "no config template for component {}",
                    component_label(scenario, *id)
                ))
            })?;
            Some(template.node())
        } else {
            None
        };

        let mut specs = Vec::new();
        for mount in program.mounts() {
            let query = match &mount.source {
                MountSource::Config(path) | MountSource::Secret(path) => path,
                MountSource::Framework(name) => {
                    if framework_capability(name.as_str()).is_none() {
                        return Err(MeshError::new(format!(
                            "unknown framework mount source framework.{} in {}",
                            name,
                            component_label(scenario, *id)
                        )));
                    }
                    // Handled by target-specific runtime wiring. Config mount specs only cover
                    // config/secret file materialization.
                    continue;
                }
                other => {
                    return Err(MeshError::new(format!(
                        "reserved mount source {other} in {}",
                        component_label(scenario, *id)
                    )));
                }
            };

            let template_opt = template_opt.expect("config/secret mounts require template");
            match resolve_config_query_for_mount(template_opt, query)? {
                MountResolution::Static(value) => {
                    let content = rc::stringify_for_mount(&value)
                        .map_err(|e| MeshError::new(e.to_string()))?;
                    specs.push(MountSpec::Literal {
                        path: mount.path.clone(),
                        content,
                    });
                }
                MountResolution::Runtime => {
                    specs.push(MountSpec::Config {
                        path: mount.path.clone(),
                        config: query.clone(),
                    });
                }
            }
        }

        if !specs.is_empty() {
            out.insert(*id, specs);
        }
    }

    Ok(out)
}

fn binding_urls_by_scope(
    scenario: &Scenario,
    slot_values_by_component: &HashMap<ComponentId, BTreeMap<String, SlotObject>>,
    required_bindings_by_scope: &HashMap<u64, BTreeSet<String>>,
) -> Result<HashMap<u64, BTreeMap<String, BindingObject>>, MeshError> {
    let mut out: HashMap<u64, BTreeMap<String, BindingObject>> = HashMap::new();

    for (&scope, required_names) in required_bindings_by_scope {
        let realm = ComponentId(scope as usize);
        let Some(component) = scenario.components.get(realm.0).and_then(|c| c.as_ref()) else {
            return Err(MeshError::new(format!(
                "internal error: missing bindings scope component id {scope}"
            )));
        };
        let mut by_name = BTreeMap::new();

        for name in required_names {
            let slot_ref = component.binding_decls.get(name).ok_or_else(|| {
                MeshError::new(format!(
                    "internal error: missing binding declaration `{name}` in {}",
                    component.moniker.as_str()
                ))
            })?;
            let slot_values = slot_values_by_component
                .get(&slot_ref.component)
                .ok_or_else(|| {
                    MeshError::new(format!(
                        "internal error: missing slot values for {}",
                        component_label(scenario, slot_ref.component)
                    ))
                })?;
            let slot = slot_values.get(slot_ref.name.as_str()).ok_or_else(|| {
                MeshError::new(format!(
                    "internal error: missing slot url for {}.{}",
                    component_label(scenario, slot_ref.component),
                    slot_ref.name
                ))
            })?;

            by_name.insert(
                name.clone(),
                BindingObject {
                    url: slot.url.clone(),
                },
            );
        }

        out.insert(scope, by_name);
    }

    Ok(out)
}

fn collect_required_bindings_by_scope(
    used_paths_by_component: &HashMap<ComponentId, BTreeSet<String>>,
    templates: &HashMap<ComponentId, rc::RootConfigTemplate>,
) -> Result<HashMap<u64, BTreeSet<String>>, MeshError> {
    let mut out: HashMap<u64, BTreeSet<String>> = HashMap::new();
    for (id, used_paths) in used_paths_by_component {
        let Some(template) = templates.get(id) else {
            continue;
        };
        let Some(node) = template.node() else {
            continue;
        };
        collect_required_bindings_in_paths(node, used_paths, &mut out)?;
    }
    Ok(out)
}

fn program_used_config_paths(
    program: &amber_manifest::Program,
    template_opt: Option<&rc::ConfigNode>,
    slots: &BTreeMap<String, SlotObject>,
) -> Result<BTreeSet<String>, MeshError> {
    let mut used = BTreeSet::new();

    if let Some(executable) = program.path_ref().or_else(|| program.image_ref())
        && let Ok(parsed) = executable.parse::<amber_manifest::InterpolatedString>()
    {
        collect_program_config_paths(&parsed.parts, &mut used);
    }
    for arg in &program.command().0 {
        match arg {
            ProgramArgItem::Arg(arg) => collect_program_config_paths(&arg.parts, &mut used),
            ProgramArgItem::Group(group) => {
                match resolve_condition_presence_for_program(
                    group.when_present.source(),
                    group.when_present.query(),
                    template_opt,
                    slots,
                )? {
                    ConfigPresence::Present => {
                        if group.when_present.source() == InterpolationSource::Config {
                            used.insert(group.when_present.query().to_string());
                        }
                        for arg in &group.argv.0 {
                            collect_program_config_paths(&arg.parts, &mut used);
                        }
                    }
                    ConfigPresence::Absent => {}
                    ConfigPresence::Runtime => {
                        used.insert(group.when_present.query().to_string());
                        for arg in &group.argv.0 {
                            collect_program_config_paths(&arg.parts, &mut used);
                        }
                    }
                }
            }
        }
    }
    for value in program.env().values() {
        collect_program_config_paths(&value.parts, &mut used);
    }
    for mount in program.mounts() {
        match &mount.source {
            MountSource::Config(path) | MountSource::Secret(path) => {
                used.insert(path.clone());
            }
            _ => {}
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

fn resolve_condition_presence_for_program(
    source: InterpolationSource,
    query: &str,
    template_opt: Option<&rc::ConfigNode>,
    slots: &BTreeMap<String, SlotObject>,
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
        InterpolationSource::Slots => Ok(if slot_query_is_present(slots, query)? {
            ConfigPresence::Present
        } else {
            ConfigPresence::Absent
        }),
        InterpolationSource::Bindings => Err(MeshError::new(format!(
            "unsupported conditional interpolation source bindings.{query}"
        ))),
        _ => Err(MeshError::new(format!(
            "unsupported conditional interpolation source for `{source}.{query}`"
        ))),
    }
}

fn slot_query_is_present(
    slots: &BTreeMap<String, SlotObject>,
    query: &str,
) -> Result<bool, MeshError> {
    let parsed = crate::slot_query::parse_slot_query(query).map_err(|err| {
        MeshError::new(format!(
            "invalid slots interpolation 'slots.{query}': {err}"
        ))
    })?;
    Ok(match parsed.target {
        crate::slot_query::SlotTarget::All => !slots.is_empty(),
        crate::slot_query::SlotTarget::Slot(slot) => slots.contains_key(slot),
    })
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

fn collect_required_bindings_in_paths(
    node: &rc::ConfigNode,
    used_paths: &BTreeSet<String>,
    out: &mut HashMap<u64, BTreeSet<String>>,
) -> Result<(), MeshError> {
    for path in used_paths {
        let Some(target) = config_node_for_path(node, path) else {
            continue;
        };
        collect_required_bindings_in_node(target, out)?;
    }
    Ok(())
}

fn config_node_for_path<'a>(node: &'a rc::ConfigNode, path: &str) -> Option<&'a rc::ConfigNode> {
    if path.is_empty() {
        return Some(node);
    }

    let mut current = node;
    for segment in path.split('.') {
        if segment.is_empty() {
            return None;
        }
        match current {
            rc::ConfigNode::Object(map) => {
                current = map.get(segment)?;
            }
            rc::ConfigNode::ConfigRef(_) => return None,
            _ => return None,
        }
    }

    Some(current)
}

fn collect_required_bindings_in_node(
    node: &rc::ConfigNode,
    out: &mut HashMap<u64, BTreeSet<String>>,
) -> Result<(), MeshError> {
    match node {
        rc::ConfigNode::StringTemplate(parts) => {
            for part in parts {
                let TemplatePart::Binding { binding, scope } = part else {
                    continue;
                };
                let parsed = parse_binding_query(binding).map_err(|err| {
                    let label = if binding.is_empty() {
                        "bindings".to_string()
                    } else {
                        format!("bindings.{binding}")
                    };
                    MeshError::new(format!(
                        "internal error: invalid binding query `{label}` in composed config \
                         template: {err}"
                    ))
                })?;
                out.entry(*scope)
                    .or_default()
                    .insert(parsed.name.to_string());
            }
        }
        rc::ConfigNode::Array(values) => {
            for value in values {
                collect_required_bindings_in_node(value, out)?;
            }
        }
        rc::ConfigNode::Object(map) => {
            for value in map.values() {
                collect_required_bindings_in_node(value, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn resolve_binding_templates(
    templates: HashMap<ComponentId, rc::RootConfigTemplate>,
    bindings_by_scope: &HashMap<u64, BTreeMap<String, BindingObject>>,
    used_paths_by_component: &HashMap<ComponentId, BTreeSet<String>>,
    scenario: &Scenario,
) -> Result<HashMap<ComponentId, rc::RootConfigTemplate>, MeshError> {
    let mut out = HashMap::with_capacity(templates.len());
    for (id, template) in templates {
        let resolved = match template {
            rc::RootConfigTemplate::Root => rc::RootConfigTemplate::Root,
            rc::RootConfigTemplate::Node(node) => {
                let resolved = if let Some(used_paths) = used_paths_by_component.get(&id) {
                    resolve_binding_parts_in_paths(node, used_paths, bindings_by_scope).map_err(
                        |err| {
                            MeshError::new(format!(
                                "failed to resolve binding interpolation in config for {}: {err}",
                                component_label(scenario, id)
                            ))
                        },
                    )?
                } else {
                    node
                };
                rc::RootConfigTemplate::Node(resolved)
            }
        };
        out.insert(id, resolved);
    }
    Ok(out)
}

fn resolve_binding_parts_in_paths(
    node: rc::ConfigNode,
    used_paths: &BTreeSet<String>,
    bindings_by_scope: &HashMap<u64, BTreeMap<String, BindingObject>>,
) -> Result<rc::ConfigNode, MeshError> {
    if used_paths.contains("") {
        return resolve_binding_parts_in_config(&node, bindings_by_scope);
    }
    resolve_binding_parts_in_paths_at(node, "", used_paths, bindings_by_scope)
}

fn resolve_binding_parts_in_paths_at(
    node: rc::ConfigNode,
    path: &str,
    used_paths: &BTreeSet<String>,
    bindings_by_scope: &HashMap<u64, BTreeMap<String, BindingObject>>,
) -> Result<rc::ConfigNode, MeshError> {
    if used_paths.contains(path) {
        return resolve_binding_parts_in_config(&node, bindings_by_scope);
    }
    if !has_used_descendant(path, used_paths) {
        return Ok(node);
    }

    let map = match node {
        rc::ConfigNode::Object(map) => map,
        other => return Ok(other),
    };

    let mut out = BTreeMap::new();
    for (key, value) in map {
        let child_path = if path.is_empty() {
            key.clone()
        } else {
            format!("{path}.{key}")
        };
        if used_paths.contains(&child_path) || has_used_descendant(&child_path, used_paths) {
            out.insert(
                key,
                resolve_binding_parts_in_paths_at(
                    value,
                    &child_path,
                    used_paths,
                    bindings_by_scope,
                )?,
            );
        } else {
            out.insert(key, value);
        }
    }
    Ok(rc::ConfigNode::Object(out))
}

fn has_used_descendant(path: &str, used_paths: &BTreeSet<String>) -> bool {
    if path.is_empty() {
        return !used_paths.is_empty();
    }
    let prefix = format!("{path}.");
    used_paths
        .iter()
        .any(|used_path| used_path.starts_with(&prefix))
}

fn resolve_binding_parts_in_config(
    node: &rc::ConfigNode,
    bindings_by_scope: &HashMap<u64, BTreeMap<String, BindingObject>>,
) -> Result<rc::ConfigNode, MeshError> {
    match node {
        rc::ConfigNode::StringTemplate(parts) => {
            let mut out = Vec::with_capacity(parts.len());
            for part in parts {
                match part {
                    TemplatePart::Lit { lit } => out.push(TemplatePart::lit(lit)),
                    TemplatePart::Config { config } => out.push(TemplatePart::config(config)),
                    TemplatePart::Slot { slot, .. } => {
                        return Err(MeshError::new(format!(
                            "internal error: unexpected runtime slot interpolation slots.{slot} \
                             in config template"
                        )));
                    }
                    TemplatePart::Binding { binding, scope } => {
                        let bindings = bindings_by_scope.get(scope).ok_or_else(|| {
                            MeshError::new(format!("bindings scope {scope} is missing"))
                        })?;
                        let url = resolve_binding_query(bindings, binding)?;
                        out.push(TemplatePart::lit(url));
                    }
                }
            }
            Ok(rc::ConfigNode::StringTemplate(out).simplify())
        }
        rc::ConfigNode::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(resolve_binding_parts_in_config(item, bindings_by_scope)?);
            }
            Ok(rc::ConfigNode::Array(out))
        }
        rc::ConfigNode::Object(map) => {
            let mut out = BTreeMap::new();
            for (k, v) in map {
                out.insert(
                    k.clone(),
                    resolve_binding_parts_in_config(v, bindings_by_scope)?,
                );
            }
            Ok(rc::ConfigNode::Object(out))
        }
        other => Ok(other.clone()),
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

enum QueryResolution<'a> {
    Node(&'a rc::ConfigNode),
    RuntimePath(String),
}

fn parse_query_segments(query: &str) -> Result<Vec<&str>, MeshError> {
    query
        .split('.')
        .map(|seg| {
            if seg.is_empty() {
                Err(MeshError::new(format!(
                    "invalid config path {query:?}: empty segment"
                )))
            } else {
                Ok(seg)
            }
        })
        .collect()
}

fn resolve_config_query_node<'a>(
    template: &'a rc::ConfigNode,
    query: &str,
) -> Result<QueryResolution<'a>, MeshError> {
    if query.is_empty() {
        return Ok(QueryResolution::Node(template));
    }

    let segments = parse_query_segments(query)?;
    let mut current = template;
    for (idx, seg) in segments.iter().enumerate() {
        match current {
            rc::ConfigNode::Object(map) => {
                let Some(next) = map.get(*seg) else {
                    return Err(MeshError::new(format!(
                        "config.{query} not found (missing key {seg:?})"
                    )));
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
                return Ok(QueryResolution::RuntimePath(full));
            }
            _ => {
                return Err(MeshError::new(format!(
                    "config.{query} not found (encountered non-object before segment {seg:?})"
                )));
            }
        }
    }
    Ok(QueryResolution::Node(current))
}

fn resolve_config_query_for_program(
    template: Option<&rc::ConfigNode>,
    query: &str,
) -> Result<ConfigResolution, MeshError> {
    let Some(template) = template else {
        return Ok(ConfigResolution::Runtime);
    };

    let cur = match resolve_config_query_node(template, query)? {
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
                    TemplatePart::Binding { binding, .. } => {
                        return Err(MeshError::new(format!(
                            "failed to resolve runtime image template: unresolved \
                             bindings.{binding} interpolation"
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
        parse_query_segments(query)?;
        return Ok(ImageConfigResolution::RuntimeTemplate(vec![
            ProgramImagePart::RootConfigPath(query.to_string()),
        ]));
    };

    match resolve_config_query_node(template, query)? {
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

    let cur = match resolve_config_query_node(template, query)? {
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
            TemplatePart::Binding { .. } => unreachable!(),
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

fn resolve_slot_or_binding_interpolation(
    scenario: &Scenario,
    id: ComponentId,
    location: &str,
    source: &InterpolationSource,
    query: &str,
    slots: &BTreeMap<String, SlotObject>,
    bindings: &BTreeMap<String, BindingObject>,
) -> Result<Option<String>, MeshError> {
    let component = component_label(scenario, id);
    match source {
        InterpolationSource::Slots => resolve_slot_query(slots, query).map(Some).map_err(|e| {
            MeshError::new(format!("failed to resolve slot query in {component}: {e}"))
        }),
        InterpolationSource::Bindings => {
            resolve_binding_query(bindings, query)
                .map(Some)
                .map_err(|e| {
                    MeshError::new(format!(
                        "failed to resolve binding query in {component}: {e}"
                    ))
                })
        }
        InterpolationSource::Config => Ok(None),
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
    slots: &BTreeMap<String, SlotObject>,
    bindings: &BTreeMap<String, BindingObject>,
    template_opt: Option<&rc::ConfigNode>,
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
                    InterpolationSource::Bindings
                        if matches!(
                            runtime_address_resolution,
                            RuntimeAddressResolution::Deferred
                        ) =>
                    {
                        ts.push(TemplatePart::binding(id.0 as u64, query.clone()));
                        *needs_helper_for_program_templates = true;
                        continue;
                    }
                    _ => {}
                }
                if let Some(value) = resolve_slot_or_binding_interpolation(
                    scenario, id, location, source, query, slots, bindings,
                )? {
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

#[allow(clippy::too_many_arguments)]
fn append_program_command_item_templates(
    scenario: &Scenario,
    id: ComponentId,
    location_prefix: &str,
    idx: usize,
    item: &ProgramArgItem,
    runtime_address_resolution: RuntimeAddressResolution,
    slots: &BTreeMap<String, SlotObject>,
    bindings: &BTreeMap<String, BindingObject>,
    template_opt: Option<&rc::ConfigNode>,
    needs_helper_for_program_templates: &mut bool,
    needs_runtime_config_for_program_templates: &mut bool,
    out: &mut Vec<ProgramArgTemplate>,
) -> Result<(), MeshError> {
    match item {
        ProgramArgItem::Arg(arg) => {
            let location = format!("{location_prefix}[{idx}]");
            let ts = resolve_program_template_string(
                scenario,
                id,
                &location,
                arg,
                runtime_address_resolution,
                slots,
                bindings,
                template_opt,
                needs_helper_for_program_templates,
                needs_runtime_config_for_program_templates,
                true,
            )?;
            out.push(ProgramArgTemplate::Arg(ts));
        }
        ProgramArgItem::Group(group) => match resolve_condition_presence_for_program(
            group.when_present.source(),
            group.when_present.query(),
            template_opt,
            slots,
        )? {
            ConfigPresence::Absent => {}
            ConfigPresence::Present => {
                for (group_idx, arg) in group.argv.0.iter().enumerate() {
                    let location = format!("{location_prefix}[{idx}].argv[{group_idx}]");
                    let ts = resolve_program_template_string(
                        scenario,
                        id,
                        &location,
                        arg,
                        runtime_address_resolution,
                        slots,
                        bindings,
                        template_opt,
                        needs_helper_for_program_templates,
                        needs_runtime_config_for_program_templates,
                        true,
                    )?;
                    out.push(ProgramArgTemplate::Arg(ts));
                }
            }
            ConfigPresence::Runtime => {
                if group.when_present.source() != InterpolationSource::Config {
                    return Err(MeshError::new(format!(
                        "internal error: runtime conditional program arg group requires \
                         config-based `when_present`, got `{}`",
                        group.when_present
                    )));
                }
                let mut argv = Vec::with_capacity(group.argv.0.len());
                for (group_idx, arg) in group.argv.0.iter().enumerate() {
                    let location = format!("{location_prefix}[{idx}].argv[{group_idx}]");
                    let ts = resolve_program_template_string(
                        scenario,
                        id,
                        &location,
                        arg,
                        runtime_address_resolution,
                        slots,
                        bindings,
                        template_opt,
                        needs_helper_for_program_templates,
                        needs_runtime_config_for_program_templates,
                        true,
                    )?;
                    argv.push(ts);
                }
                *needs_helper_for_program_templates = true;
                *needs_runtime_config_for_program_templates = true;
                out.push(ProgramArgTemplate::Group(ConditionalProgramArgTemplate {
                    when_present: group.when_present.query().to_string(),
                    argv,
                }));
            }
        },
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_program_plan(
    scenario: &Scenario,
    id: ComponentId,
    program: &amber_manifest::Program,
    program_support: ProgramSupport,
    runtime_address_resolution: RuntimeAddressResolution,
    slots: &BTreeMap<String, SlotObject>,
    bindings: &BTreeMap<String, BindingObject>,
    template_opt: Option<&rc::ConfigNode>,
    component_schema: Option<&Value>,
) -> Result<ProgramPlan, MeshError> {
    let component = component_label(scenario, id);
    let mut entrypoint_ts: Vec<ProgramArgTemplate> = Vec::new();
    let mut needs_helper_for_program_templates = false;
    let mut needs_runtime_config_for_program_templates = false;
    let (source, program_env) = match program {
        amber_manifest::Program::Image(program) => {
            if let ProgramSupport::PathOnly { backend_label } = program_support {
                return Err(MeshError::new(format!(
                    "component {} uses `program.image`, but {backend_label} only supports \
                     `program.path`",
                    component_label(scenario, id)
                )));
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
                        if let Some(value) = resolve_slot_or_binding_interpolation(
                            scenario,
                            id,
                            "program.image",
                            source,
                            query,
                            slots,
                            bindings,
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
                    bindings,
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
            if let ProgramSupport::ImageOnly { backend_label } = program_support {
                return Err(MeshError::new(format!(
                    "component {} uses `program.path`, but {backend_label} only supports \
                     `program.image`; use `amber compile --direct`",
                    component_label(scenario, id)
                )));
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
                bindings,
                template_opt,
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
                    bindings,
                    template_opt,
                    &mut needs_helper_for_program_templates,
                    &mut needs_runtime_config_for_program_templates,
                    &mut entrypoint_ts,
                )?;
            }

            (ProgramSourcePlan::Path, &program.common.env)
        }
        _ => {
            return Err(MeshError::new(format!(
                "component {} uses an unsupported program variant",
                component_label(scenario, id)
            )));
        }
    };

    let mut env_ts: BTreeMap<String, TemplateString> = BTreeMap::new();
    for (k, v) in program_env {
        let location = format!("program.env.{k}");
        let ts = resolve_program_template_string(
            scenario,
            id,
            &location,
            v,
            runtime_address_resolution,
            slots,
            bindings,
            template_opt,
            &mut needs_helper_for_program_templates,
            &mut needs_runtime_config_for_program_templates,
            false,
        )?;
        env_ts.insert(k.clone(), ts);
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
                ProgramArgTemplate::Group(_) => Err(MeshError::new(
                    "internal error: conditional arg group reached resolved program plan",
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
            .map(|(k, ts)| render_template_string_static(&ts).map(|rendered| (k, rendered)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        Ok(ProgramPlan::Resolved {
            source,
            entrypoint: rendered_entrypoint,
            env: rendered_env,
        })
    }
}
