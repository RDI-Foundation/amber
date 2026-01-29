use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use amber_config as rc;
use amber_manifest::{BindingTarget, InterpolatedPart, InterpolationSource, Manifest};
use amber_scenario::{ComponentId, Scenario};
use amber_template::{ProgramTemplateSpec, TemplatePart, TemplateSpec, TemplateString};
use base64::Engine as _;
use serde_json::Value;

use super::{MeshError, component_label};
use crate::{
    binding_query::{BindingObject, resolve_binding_query},
    config_templates,
    slot_query::{SlotObject, resolve_slot_query},
};

#[derive(Clone, Debug)]
pub(crate) struct ConfigPlan {
    pub(crate) root_schema: Option<Value>,
    pub(crate) root_leaves: Vec<rc::SchemaLeaf>,
    pub(crate) program_plans: HashMap<ComponentId, ProgramPlan>,
    pub(crate) uses_helper: bool,
}

#[derive(Clone, Debug)]
pub(crate) enum ProgramPlan {
    Direct {
        entrypoint: Vec<String>,
        env: BTreeMap<String, String>,
    },
    Helper {
        template_spec: TemplateSpec,
        component_template: rc::RootConfigTemplate,
        component_schema: Value,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct HelperPayload {
    pub(crate) template_spec_b64: String,
    pub(crate) component_cfg_template_b64: String,
    pub(crate) component_schema_b64: String,
}

pub(crate) fn build_config_plan(
    scenario: &Scenario,
    manifests: &[Option<Arc<Manifest>>],
    program_components: &[ComponentId],
    slot_values_by_component: &HashMap<ComponentId, BTreeMap<String, SlotObject>>,
    binding_values_by_component: &HashMap<ComponentId, BTreeMap<String, BindingObject>>,
) -> Result<ConfigPlan, MeshError> {
    let composed = config_templates::compose_root_config_templates(
        scenario.root,
        &scenario.components,
        manifests,
    );
    if let Some(err) = composed.errors.first() {
        return Err(MeshError::new(format!(
            "failed to compose component config templates: {}",
            err.message
        )));
    }

    let binding_urls_by_scope =
        binding_urls_by_scope(scenario, manifests, slot_values_by_component)?;
    let resolved_templates =
        resolve_binding_templates(composed.templates, &binding_urls_by_scope, scenario)?;

    let root_schema = manifests[scenario.root.0]
        .as_ref()
        .and_then(|m| m.config_schema())
        .map(|s| s.0.clone());

    let root_leaves = if let Some(schema) = &root_schema {
        rc::collect_leaf_paths(schema).map_err(|e| {
            MeshError::new(format!(
                "failed to enumerate root config definition leaf paths: {e}"
            ))
        })?
    } else {
        Vec::new()
    };

    let mut program_plans = HashMap::new();
    let mut uses_helper = false;

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

        let component_schema = manifests[id.0]
            .as_ref()
            .and_then(|m| m.config_schema())
            .map(|s| s.0.clone());

        let plan = build_program_plan(
            scenario,
            *id,
            program,
            slots,
            bindings,
            template_opt,
            component_schema.as_ref(),
            component_template,
        )?;
        if matches!(plan, ProgramPlan::Helper { .. }) {
            uses_helper = true;
        }
        program_plans.insert(*id, plan);
    }

    if uses_helper && root_schema.is_none() {
        return Err(MeshError::new(
            "root component must declare `config_schema` when runtime config interpolation is \
             required",
        ));
    }

    Ok(ConfigPlan {
        root_schema,
        root_leaves,
        program_plans,
        uses_helper,
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

    Ok(HelperPayload {
        template_spec_b64: spec_b64,
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

fn binding_urls_by_scope(
    scenario: &Scenario,
    manifests: &[Option<Arc<Manifest>>],
    slot_values_by_component: &HashMap<ComponentId, BTreeMap<String, SlotObject>>,
) -> Result<HashMap<u64, BTreeMap<String, BindingObject>>, MeshError> {
    let mut out: HashMap<u64, BTreeMap<String, BindingObject>> = HashMap::new();

    for (idx, manifest) in manifests.iter().enumerate() {
        let Some(manifest) = manifest else {
            continue;
        };
        let realm = ComponentId(idx);
        let mut by_name = BTreeMap::new();

        for (target, binding) in manifest.bindings() {
            let Some(name) = binding.name.as_ref() else {
                continue;
            };

            let (target_component, slot_name) = match target {
                BindingTarget::SelfSlot(slot) => (realm, slot.as_str()),
                BindingTarget::ChildSlot { child, slot } => {
                    let child_id = child_component_id_for_name(scenario, realm, child.as_str())?;
                    (child_id, slot.as_str())
                }
                _ => {
                    return Err(MeshError::new(format!(
                        "unsupported binding target {:?} in {}",
                        target,
                        component_label(scenario, realm)
                    )));
                }
            };

            let slot_values = slot_values_by_component
                .get(&target_component)
                .ok_or_else(|| {
                    MeshError::new(format!(
                        "internal error: missing slot values for {}",
                        component_label(scenario, target_component)
                    ))
                })?;
            let slot = slot_values.get(slot_name).ok_or_else(|| {
                MeshError::new(format!(
                    "internal error: missing slot url for {}.{}",
                    component_label(scenario, target_component),
                    slot_name
                ))
            })?;

            by_name.insert(
                name.to_string(),
                BindingObject {
                    url: slot.url.clone(),
                },
            );
        }

        out.insert(realm.0 as u64, by_name);
    }

    Ok(out)
}

fn resolve_binding_templates(
    templates: HashMap<ComponentId, rc::RootConfigTemplate>,
    bindings_by_scope: &HashMap<u64, BTreeMap<String, BindingObject>>,
    scenario: &Scenario,
) -> Result<HashMap<ComponentId, rc::RootConfigTemplate>, MeshError> {
    let mut out = HashMap::with_capacity(templates.len());
    for (id, template) in templates {
        let resolved = match template {
            rc::RootConfigTemplate::Root => rc::RootConfigTemplate::Root,
            rc::RootConfigTemplate::Node(node) => {
                let resolved =
                    resolve_binding_parts_in_config(&node, bindings_by_scope).map_err(|err| {
                        MeshError::new(format!(
                            "failed to resolve binding interpolation in config for {}: {err}",
                            component_label(scenario, id)
                        ))
                    })?;
                rc::RootConfigTemplate::Node(resolved)
            }
        };
        out.insert(id, resolved);
    }
    Ok(out)
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

fn child_component_id_for_name(
    scenario: &Scenario,
    parent: ComponentId,
    child_name: &str,
) -> Result<ComponentId, MeshError> {
    let parent_component = scenario.component(parent);
    for child_id in &parent_component.children {
        let child = scenario.component(*child_id);
        if child.moniker.local_name() == Some(child_name) {
            return Ok(*child_id);
        }
    }
    Err(MeshError::new(format!(
        "internal error: missing child {child_name:?} for {}",
        component_label(scenario, parent)
    )))
}

#[derive(Debug)]
enum ConfigResolution {
    Static(String),
    Runtime,
}

fn resolve_config_query_for_program(
    template: Option<&rc::ConfigNode>,
    query: &str,
) -> Result<ConfigResolution, MeshError> {
    let Some(template) = template else {
        return Ok(ConfigResolution::Runtime);
    };

    if query.is_empty() {
        return if !template.contains_runtime() {
            let v = template
                .evaluate_static()
                .map_err(|e| MeshError::new(e.to_string()))?;
            Ok(ConfigResolution::Static(
                rc::stringify_for_interpolation(&v).map_err(|e| MeshError::new(e.to_string()))?,
            ))
        } else {
            Ok(ConfigResolution::Runtime)
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
            rc::ConfigNode::ConfigRef(_) => return Ok(ConfigResolution::Runtime),
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
        Ok(ConfigResolution::Static(
            rc::stringify_for_interpolation(&v).map_err(|e| MeshError::new(e.to_string()))?,
        ))
    } else {
        Ok(ConfigResolution::Runtime)
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

#[allow(clippy::too_many_arguments)]
fn build_program_plan(
    scenario: &Scenario,
    id: ComponentId,
    program: &amber_manifest::Program,
    slots: &BTreeMap<String, SlotObject>,
    bindings: &BTreeMap<String, BindingObject>,
    template_opt: Option<&rc::ConfigNode>,
    component_schema: Option<&Value>,
    component_template: &rc::RootConfigTemplate,
) -> Result<ProgramPlan, MeshError> {
    let mut entrypoint_ts: Vec<TemplateString> = Vec::new();
    let mut needs_helper = false;

    for (idx, arg) in program.args.0.iter().enumerate() {
        let mut ts: TemplateString = Vec::new();
        for part in &arg.parts {
            match part {
                InterpolatedPart::Literal(lit) => ts.push(TemplatePart::lit(lit)),
                InterpolatedPart::Interpolation { source, query } => match source {
                    InterpolationSource::Slots => {
                        let v = resolve_slot_query(slots, query).map_err(|e| {
                            MeshError::new(format!(
                                "failed to resolve slot query in {}: {e}",
                                component_label(scenario, id)
                            ))
                        })?;
                        ts.push(TemplatePart::lit(v));
                    }
                    InterpolationSource::Bindings => {
                        let v = resolve_binding_query(bindings, query).map_err(|e| {
                            MeshError::new(format!(
                                "failed to resolve binding query in {}: {e}",
                                component_label(scenario, id)
                            ))
                        })?;
                        ts.push(TemplatePart::lit(v));
                    }
                    InterpolationSource::Config => {
                        match resolve_config_query_for_program(template_opt, query)? {
                            ConfigResolution::Static(v) => ts.push(TemplatePart::lit(v)),
                            ConfigResolution::Runtime => {
                                ts.push(TemplatePart::config(query.clone()));
                                needs_helper = true;
                            }
                        }
                    }
                    other => {
                        return Err(MeshError::new(format!(
                            "unsupported interpolation source {other} in {} \
                             program.entrypoint[{idx}]",
                            component_label(scenario, id)
                        )));
                    }
                },
                _ => {
                    return Err(MeshError::new(format!(
                        "unsupported interpolation part in {} program.entrypoint[{idx}]",
                        component_label(scenario, id)
                    )));
                }
            }
        }
        if ts.is_empty() {
            return Err(MeshError::new(format!(
                "internal error: produced empty template for {} program.entrypoint[{idx}]",
                component_label(scenario, id)
            )));
        }
        entrypoint_ts.push(ts);
    }

    let mut env_ts: BTreeMap<String, TemplateString> = BTreeMap::new();
    for (k, v) in &program.env {
        let mut ts: TemplateString = Vec::new();
        for part in &v.parts {
            match part {
                InterpolatedPart::Literal(lit) => ts.push(TemplatePart::lit(lit)),
                InterpolatedPart::Interpolation { source, query } => match source {
                    InterpolationSource::Slots => {
                        let vv = resolve_slot_query(slots, query).map_err(|e| {
                            MeshError::new(format!(
                                "failed to resolve slot query in {}: {e}",
                                component_label(scenario, id)
                            ))
                        })?;
                        ts.push(TemplatePart::lit(vv));
                    }
                    InterpolationSource::Bindings => {
                        let vv = resolve_binding_query(bindings, query).map_err(|e| {
                            MeshError::new(format!(
                                "failed to resolve binding query in {}: {e}",
                                component_label(scenario, id)
                            ))
                        })?;
                        ts.push(TemplatePart::lit(vv));
                    }
                    InterpolationSource::Config => {
                        match resolve_config_query_for_program(template_opt, query)? {
                            ConfigResolution::Static(vv) => ts.push(TemplatePart::lit(vv)),
                            ConfigResolution::Runtime => {
                                ts.push(TemplatePart::config(query.clone()));
                                needs_helper = true;
                            }
                        }
                    }
                    other => {
                        return Err(MeshError::new(format!(
                            "unsupported interpolation source {other} in {} program.env.{k}",
                            component_label(scenario, id)
                        )));
                    }
                },
                _ => {
                    return Err(MeshError::new(format!(
                        "unsupported interpolation part in {} program.env.{k}",
                        component_label(scenario, id)
                    )));
                }
            }
        }
        env_ts.insert(k.clone(), ts);
    }

    if needs_helper {
        let schema = component_schema.ok_or_else(|| {
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
            template_spec: spec,
            component_template: component_template.clone(),
            component_schema: schema.clone(),
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
            entrypoint: rendered_entrypoint,
            env: rendered_env,
        })
    }
}
