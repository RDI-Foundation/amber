// Mesh config planning: resolve program templates/mounts and compute per-component scope.
use std::collections::{BTreeMap, BTreeSet, HashMap};

use amber_config as rc;
use amber_manifest::{InterpolatedPart, InterpolationSource, MountSource, framework_capability};
use amber_scenario::{ComponentId, Scenario};
use amber_template::{ProgramTemplateSpec, TemplatePart, TemplateSpec, TemplateString};
use base64::Engine as _;
use serde::Serialize;
use serde_json::Value;

use crate::{
    binding_query::{BindingObject, parse_binding_query, resolve_binding_query},
    config_scope::{RuntimeConfigView, build_runtime_config_view},
    config_templates,
    slot_query::{SlotObject, resolve_slot_query},
    targets::mesh::plan::{MeshError, component_label},
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
    Direct {
        image: ProgramImagePlan,
        image_origin: ProgramImageOrigin,
        entrypoint: Vec<String>,
        env: BTreeMap<String, String>,
    },
    Helper {
        image: ProgramImagePlan,
        image_origin: ProgramImageOrigin,
        template_spec: TemplateSpec,
    },
}

impl ProgramPlan {
    pub(crate) fn image(&self) -> &ProgramImagePlan {
        match self {
            Self::Direct { image, .. } => image,
            Self::Helper { image, .. } => image,
        }
    }

    pub(crate) fn image_origin(&self) -> &ProgramImageOrigin {
        match self {
            Self::Direct { image_origin, .. } => image_origin,
            Self::Helper { image_origin, .. } => image_origin,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct HelperPayload {
    pub(crate) template_spec_b64: String,
    pub(crate) component_cfg_template_b64: String,
    pub(crate) component_schema_b64: String,
}

#[derive(Clone, Debug)]
pub(crate) struct ComponentConfigPayload {
    pub(crate) component_cfg_template_b64: String,
    pub(crate) component_schema_b64: String,
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
        let component = scenario.component(*id).expect("component should exist");
        let Some(program) = component.program.as_ref() else {
            continue;
        };
        let used_paths = program_used_config_paths(program);
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
    let resolved_templates = resolve_binding_templates(
        composed.templates,
        &binding_urls_by_scope,
        &used_config_paths_by_component,
        scenario,
    )?;

    let root_schema = scenario
        .component(scenario.root)
        .expect("root component should exist")
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
        let c = scenario.component(*id).expect("component should exist");
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

        let component_schema = scenario
            .component(*id)
            .expect("component should exist")
            .config_schema
            .as_ref()
            .cloned();

        let plan = build_program_plan(
            scenario,
            *id,
            program,
            slots,
            bindings,
            template_opt,
            component_schema.as_ref(),
        )?;
        if matches!(plan, ProgramPlan::Helper { .. }) {
            needs_helper = true;
            needs_runtime_config = true;
        }
        let mut runtime_paths = BTreeSet::new();
        plan.image().collect_runtime_root_paths(&mut runtime_paths);
        if !runtime_paths.is_empty() {
            needs_runtime_config = true;
        }
        for path in runtime_paths {
            if !root_leaf_paths.contains(path.as_str()) {
                return Err(MeshError::new(format!(
                    "program.image in {} requires runtime config path config.{path}, but runtime \
                     image interpolation only supports paths that resolve to one concrete root \
                     config value",
                    component_label(scenario, *id)
                )));
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
            let needs_config_payload = matches!(program_plan, ProgramPlan::Helper { .. })
                || mount_specs.is_some_and(|specs| mount_specs_need_config(specs));
            if !needs_config_payload {
                continue;
            }

            let component_schema = scenario
                .component(*id)
                .expect("component should exist")
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
        needs_helper,
        needs_runtime_config,
        runtime_views,
    })
}

pub(crate) fn encode_helper_payload(
    component_label: &str,
    template_spec: &TemplateSpec,
    component_template: &rc::RootConfigTemplate,
    component_schema: &Value,
) -> Result<HelperPayload, MeshError> {
    let b64 = base64::engine::general_purpose::STANDARD;

    let spec_json = serde_json::to_vec(template_spec).map_err(|e| {
        MeshError::new(format!(
            "failed to serialize template spec for {component_label}: {e}"
        ))
    })?;
    let spec_b64 = b64.encode(spec_json);

    let component_payload =
        encode_component_payload(component_label, component_template, component_schema)?;

    Ok(HelperPayload {
        template_spec_b64: spec_b64,
        component_cfg_template_b64: component_payload.component_cfg_template_b64,
        component_schema_b64: component_payload.component_schema_b64,
    })
}

pub(crate) fn encode_component_payload(
    component_label: &str,
    component_template: &rc::RootConfigTemplate,
    component_schema: &Value,
) -> Result<ComponentConfigPayload, MeshError> {
    let b64 = base64::engine::general_purpose::STANDARD;

    let template_json = serde_json::to_vec(&component_template.to_json_ir()).map_err(|e| {
        MeshError::new(format!(
            "failed to serialize component config template for {component_label}: {e}"
        ))
    })?;
    let template_b64 = b64.encode(template_json);

    let schema_json = serde_json::to_vec(&rc::canonical_json(component_schema)).map_err(|e| {
        MeshError::new(format!(
            "failed to serialize component config definition for {component_label}: {e}"
        ))
    })?;
    let schema_b64 = b64.encode(schema_json);

    Ok(ComponentConfigPayload {
        component_cfg_template_b64: template_b64,
        component_schema_b64: schema_b64,
    })
}

pub(crate) fn encode_schema_b64(label: &str, schema: &Value) -> Result<String, MeshError> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let schema_json = serde_json::to_vec(&rc::canonical_json(schema))
        .map_err(|e| MeshError::new(format!("failed to serialize {label}: {e}")))?;
    Ok(b64.encode(schema_json))
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

pub(crate) fn encode_mount_spec_b64(label: &str, specs: &[MountSpec]) -> Result<String, MeshError> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let spec_json =
        serde_json::to_vec(specs).map_err(|e| MeshError::new(format!("{label}: {e}")))?;
    Ok(b64.encode(spec_json))
}

pub(crate) fn encode_direct_entrypoint_b64(entrypoint: &[String]) -> Result<String, MeshError> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let payload = serde_json::to_vec(entrypoint).map_err(|e| MeshError::new(format!("{e}")))?;
    Ok(b64.encode(payload))
}

pub(crate) fn encode_direct_env_b64(env: &BTreeMap<String, String>) -> Result<String, MeshError> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let payload = serde_json::to_vec(env).map_err(|e| MeshError::new(format!("{e}")))?;
    Ok(b64.encode(payload))
}

pub(crate) fn mount_specs_need_config(specs: &[MountSpec]) -> bool {
    specs
        .iter()
        .any(|spec| matches!(spec, MountSpec::Config { .. }))
}

fn collect_used_paths_from_template_spec(spec: &TemplateSpec, out: &mut BTreeSet<String>) {
    for ts in &spec.program.entrypoint {
        collect_used_paths_from_template_string(ts, out);
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
        let component = scenario.component(*id).expect("component should exist");
        let program = component
            .program
            .as_ref()
            .expect("program component has program");
        if program.mounts.is_empty() {
            continue;
        }

        let has_config_or_secret_mount = program.mounts.iter().any(|mount| {
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
        for mount in &program.mounts {
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

fn program_used_config_paths(program: &amber_manifest::Program) -> BTreeSet<String> {
    let mut used = BTreeSet::new();

    if let Ok(image) = program.image.parse::<amber_manifest::InterpolatedString>() {
        collect_program_config_paths(&image.parts, &mut used);
    }
    for arg in &program.entrypoint.0 {
        collect_program_config_paths(&arg.parts, &mut used);
    }
    for value in program.env.values() {
        collect_program_config_paths(&value.parts, &mut used);
    }
    for mount in &program.mounts {
        match &mount.source {
            MountSource::Config(path) | MountSource::Secret(path) => {
                used.insert(path.clone());
            }
            _ => {}
        }
    }

    used
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

fn resolve_config_query_for_program(
    template: Option<&rc::ConfigNode>,
    query: &str,
) -> Result<ConfigResolution, MeshError> {
    let Some(template) = template else {
        return Ok(ConfigResolution::Runtime);
    };

    let cur = if query.is_empty() {
        template
    } else {
        let mut current = template;
        for seg in query.split('.') {
            if seg.is_empty() {
                return Err(MeshError::new(format!(
                    "invalid config path {query:?}: empty segment"
                )));
            }
            match current {
                rc::ConfigNode::Object(map) => {
                    let Some(next) = map.get(seg) else {
                        return Err(MeshError::new(format!(
                            "config.{query} not found (missing key {seg:?})"
                        )));
                    };
                    current = next;
                }
                rc::ConfigNode::ConfigRef(_) => return Ok(ConfigResolution::Runtime),
                _ => {
                    return Err(MeshError::new(format!(
                        "config.{query} not found (encountered non-object before segment {seg:?})"
                    )));
                }
            }
        }
        current
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
        for seg in query.split('.') {
            if seg.is_empty() {
                return Err(MeshError::new(format!(
                    "invalid config path {query:?}: empty segment"
                )));
            }
        }
        return Ok(ImageConfigResolution::RuntimeTemplate(vec![
            ProgramImagePart::RootConfigPath(query.to_string()),
        ]));
    };

    if query.is_empty() {
        return if !template.contains_runtime() {
            let v = template
                .evaluate_static()
                .map_err(|e| MeshError::new(e.to_string()))?;
            Ok(ImageConfigResolution::Static(
                rc::stringify_for_interpolation(&v).map_err(|e| MeshError::new(e.to_string()))?,
            ))
        } else {
            resolve_program_image_runtime_node(template)
        };
    }

    let segments = query.split('.').collect::<Vec<_>>();
    for seg in &segments {
        if seg.is_empty() {
            return Err(MeshError::new(format!(
                "invalid config path {query:?}: empty segment"
            )));
        }
    }

    let mut cur = template;
    for (idx, seg) in segments.iter().enumerate() {
        match cur {
            rc::ConfigNode::Object(map) => {
                let Some(next) = map.get(*seg) else {
                    return Err(MeshError::new(format!(
                        "config.{query} not found (missing key {seg:?})"
                    )));
                };
                cur = next;
            }
            rc::ConfigNode::ConfigRef(path) => {
                let suffix = segments[idx..].join(".");
                let full = if path.is_empty() {
                    suffix
                } else {
                    format!("{path}.{suffix}")
                };
                return Ok(ImageConfigResolution::RuntimeTemplate(vec![
                    ProgramImagePart::RootConfigPath(full),
                ]));
            }
            _ => {
                return Err(MeshError::new(format!(
                    "config.{query} not found (encountered non-object before segment {seg:?})"
                )));
            }
        }
    }

    if !cur.contains_runtime() {
        let v = cur
            .evaluate_static()
            .map_err(|e| MeshError::new(e.to_string()))?;
        Ok(ImageConfigResolution::Static(
            rc::stringify_for_interpolation(&v).map_err(|e| MeshError::new(e.to_string()))?,
        ))
    } else {
        resolve_program_image_runtime_node(cur)
    }
}

fn resolve_config_query_for_mount(
    template: Option<&rc::ConfigNode>,
    query: &str,
) -> Result<MountResolution, MeshError> {
    let Some(template) = template else {
        return Ok(MountResolution::Runtime);
    };

    if query.is_empty() {
        return if !template.contains_runtime() {
            let v = template
                .evaluate_static()
                .map_err(|e| MeshError::new(e.to_string()))?;
            Ok(MountResolution::Static(v))
        } else {
            Ok(MountResolution::Runtime)
        };
    }

    let mut cur = template;
    for seg in query.split('.') {
        if seg.is_empty() {
            return Err(MeshError::new(format!(
                "invalid config path {query:?}: empty segment"
            )));
        }
        match cur {
            rc::ConfigNode::Object(map) => {
                let Some(next) = map.get(seg) else {
                    return Err(MeshError::new(format!(
                        "config.{query} not found (missing key {seg:?})"
                    )));
                };
                cur = next;
            }
            rc::ConfigNode::ConfigRef(_) => return Ok(MountResolution::Runtime),
            _ => {
                return Err(MeshError::new(format!(
                    "config.{query} not found (encountered non-object before segment {seg:?})"
                )));
            }
        }
    }

    if !cur.contains_runtime() {
        let v = cur
            .evaluate_static()
            .map_err(|e| MeshError::new(e.to_string()))?;
        Ok(MountResolution::Static(v))
    } else {
        Ok(MountResolution::Runtime)
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
            TemplatePart::Binding { .. } => unreachable!(),
        }
    }
    Ok(out)
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

#[allow(clippy::too_many_arguments)]
fn resolve_program_template_string(
    scenario: &Scenario,
    id: ComponentId,
    location: &str,
    value: &amber_manifest::InterpolatedString,
    slots: &BTreeMap<String, SlotObject>,
    bindings: &BTreeMap<String, BindingObject>,
    template_opt: Option<&rc::ConfigNode>,
    needs_helper_for_program_templates: &mut bool,
    require_non_empty: bool,
) -> Result<TemplateString, MeshError> {
    let mut ts: TemplateString = Vec::new();
    for part in &value.parts {
        match part {
            InterpolatedPart::Literal(lit) => ts.push(TemplatePart::lit(lit)),
            InterpolatedPart::Interpolation { source, query } => match source {
                InterpolationSource::Slots => {
                    let value = resolve_slot_query(slots, query).map_err(|e| {
                        MeshError::new(format!(
                            "failed to resolve slot query in {}: {e}",
                            component_label(scenario, id)
                        ))
                    })?;
                    ts.push(TemplatePart::lit(value));
                }
                InterpolationSource::Bindings => {
                    let value = resolve_binding_query(bindings, query).map_err(|e| {
                        MeshError::new(format!(
                            "failed to resolve binding query in {}: {e}",
                            component_label(scenario, id)
                        ))
                    })?;
                    ts.push(TemplatePart::lit(value));
                }
                InterpolationSource::Config => {
                    match resolve_config_query_for_program(template_opt, query)? {
                        ConfigResolution::Static(value) => ts.push(TemplatePart::lit(value)),
                        ConfigResolution::Runtime => {
                            ts.push(TemplatePart::config(query.clone()));
                            *needs_helper_for_program_templates = true;
                        }
                    }
                }
                other => {
                    return Err(MeshError::new(format!(
                        "unsupported interpolation source {other} in {} {location}",
                        component_label(scenario, id)
                    )));
                }
            },
            _ => {
                return Err(MeshError::new(format!(
                    "unsupported interpolation part in {} {location}",
                    component_label(scenario, id)
                )));
            }
        }
    }
    if require_non_empty && ts.is_empty() {
        return Err(MeshError::new(format!(
            "internal error: produced empty template for {} {location}",
            component_label(scenario, id)
        )));
    }
    Ok(ts)
}

#[allow(clippy::too_many_arguments)]
fn build_program_plan(
    scenario: &Scenario,
    id: ComponentId,
    program: &amber_manifest::Program,
    slots: &BTreeMap<String, SlotObject>,
    bindings: &BTreeMap<String, BindingObject>,
    template_opt: Option<&rc::ConfigNode>,
    component_schema: Option<&Value>,
) -> Result<ProgramPlan, MeshError> {
    let mut entrypoint_ts: Vec<TemplateString> = Vec::new();
    // Helper mode is required only for runtime config interpolation in
    // program.entrypoint/program.env (not for program.image runtime interpolation).
    let mut needs_helper_for_program_templates = false;
    let mut image_parts: Vec<ProgramImagePart> = Vec::new();
    let image = program
        .image
        .parse::<amber_manifest::InterpolatedString>()
        .map_err(|err| {
            MeshError::new(format!(
                "failed to parse program.image interpolation in {}: {err}",
                component_label(scenario, id)
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
            InterpolatedPart::Literal(lit) => push_image_literal(&mut image_parts, lit.clone()),
            InterpolatedPart::Interpolation { source, query } => match source {
                InterpolationSource::Slots => {
                    let value = resolve_slot_query(slots, query).map_err(|e| {
                        MeshError::new(format!(
                            "failed to resolve slot query in {}: {e}",
                            component_label(scenario, id)
                        ))
                    })?;
                    push_image_literal(&mut image_parts, value);
                }
                InterpolationSource::Bindings => {
                    let value = resolve_binding_query(bindings, query).map_err(|e| {
                        MeshError::new(format!(
                            "failed to resolve binding query in {}: {e}",
                            component_label(scenario, id)
                        ))
                    })?;
                    push_image_literal(&mut image_parts, value);
                }
                InterpolationSource::Config => {
                    match resolve_config_query_for_program_image(template_opt, query)? {
                        ImageConfigResolution::Static(value) => {
                            push_image_literal(&mut image_parts, value);
                        }
                        ImageConfigResolution::RuntimeTemplate(parts) => {
                            extend_image_parts(&mut image_parts, parts);
                        }
                    }
                }
                other => {
                    return Err(MeshError::new(format!(
                        "unsupported interpolation source {other} in {} program.image",
                        component_label(scenario, id)
                    )));
                }
            },
            _ => {
                return Err(MeshError::new(format!(
                    "unsupported interpolation part in {} program.image",
                    component_label(scenario, id)
                )));
            }
        }
    }
    if image_parts.is_empty() {
        return Err(MeshError::new(format!(
            "internal error: produced empty image template for {} program.image",
            component_label(scenario, id)
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

    for (idx, arg) in program.entrypoint.0.iter().enumerate() {
        let location = format!("program.entrypoint[{idx}]");
        let ts = resolve_program_template_string(
            scenario,
            id,
            &location,
            arg,
            slots,
            bindings,
            template_opt,
            &mut needs_helper_for_program_templates,
            true,
        )?;
        entrypoint_ts.push(ts);
    }

    let mut env_ts: BTreeMap<String, TemplateString> = BTreeMap::new();
    for (k, v) in &program.env {
        let location = format!("program.env.{k}");
        let ts = resolve_program_template_string(
            scenario,
            id,
            &location,
            v,
            slots,
            bindings,
            template_opt,
            &mut needs_helper_for_program_templates,
            false,
        )?;
        env_ts.insert(k.clone(), ts);
    }

    if needs_helper_for_program_templates {
        component_schema.ok_or_else(|| {
            MeshError::new(format!(
                "component {} requires config_schema when using runtime config interpolation",
                component_label(scenario, id)
            ))
        })?;

        let spec = TemplateSpec {
            program: ProgramTemplateSpec {
                entrypoint: entrypoint_ts,
                env: env_ts,
            },
        };

        Ok(ProgramPlan::Helper {
            image,
            image_origin,
            template_spec: spec,
        })
    } else {
        let mut rendered_entrypoint: Vec<String> = Vec::new();
        for ts in entrypoint_ts {
            rendered_entrypoint.push(render_template_string_static(&ts)?);
        }

        let mut rendered_env: BTreeMap<String, String> = BTreeMap::new();
        for (k, ts) in env_ts {
            rendered_env.insert(k, render_template_string_static(&ts)?);
        }

        Ok(ProgramPlan::Direct {
            image,
            image_origin,
            entrypoint: rendered_entrypoint,
            env: rendered_env,
        })
    }
}
