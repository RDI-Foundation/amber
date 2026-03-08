use std::collections::{BTreeSet, HashMap, HashSet};

use amber_config::ConfigNode;
use amber_manifest::{
    InterpolatedPart, InterpolatedString, InterpolationSource, MountSource, SlotTarget,
    parse_slot_query,
};
use amber_scenario::{ComponentId, Scenario};
use amber_template::TemplatePart;
use serde_json::Value;

use crate::{binding_query::parse_binding_query, config_templates};

#[derive(Clone, Debug, Default)]
pub(crate) struct BindingUsage {
    by_scope: HashMap<ComponentId, BTreeSet<String>>,
    by_component: HashMap<ComponentId, HashSet<BindingUse>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum BindingUseSource {
    Program,
    Config,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct BindingUse {
    pub(crate) source: BindingUseSource,
    pub(crate) scope: ComponentId,
    pub(crate) name: String,
}

impl BindingUsage {
    fn record(
        &mut self,
        component: ComponentId,
        source: BindingUseSource,
        scope: ComponentId,
        name: &str,
    ) {
        self.by_scope
            .entry(scope)
            .or_default()
            .insert(name.to_string());
        self.by_component
            .entry(component)
            .or_default()
            .insert(BindingUse {
                source,
                scope,
                name: name.to_string(),
            });
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&ComponentId, &BTreeSet<String>)> {
        self.by_scope.iter()
    }

    pub(crate) fn for_component(
        &self,
        component: ComponentId,
    ) -> impl Iterator<Item = &BindingUse> {
        self.by_component
            .get(&component)
            .into_iter()
            .flat_map(|uses| uses.iter())
    }

    pub(crate) fn for_component_with_source(
        &self,
        component: ComponentId,
        source: BindingUseSource,
    ) -> impl Iterator<Item = &BindingUse> {
        self.for_component(component)
            .filter(move |binding_use| binding_use.source == source)
    }
}

pub(crate) fn collect_binding_usage(scenario: &Scenario) -> BindingUsage {
    let mut usage = BindingUsage::default();
    let templates =
        config_templates::compose_root_config_templates(scenario.root, &scenario.components)
            .templates;

    for (id, component) in scenario.components_iter() {
        if let Some(program) = component.program.as_ref() {
            let executable = program.path_ref().or_else(|| program.image_ref());
            if let Some(executable) = executable
                && let Ok(parsed) = executable.parse::<InterpolatedString>()
            {
                record_binding_parts(&parsed.parts, id, BindingUseSource::Program, id, &mut usage);
            }
            for item in &program.command().0 {
                item.visit_values(|value| {
                    record_binding_parts(
                        &value.parts,
                        id,
                        BindingUseSource::Program,
                        id,
                        &mut usage,
                    );
                });
            }
            for value in program.env().values() {
                value.visit_values(|value| {
                    record_binding_parts(
                        &value.parts,
                        id,
                        BindingUseSource::Program,
                        id,
                        &mut usage,
                    );
                });
            }

            let used_paths = collect_program_used_config_paths(
                program,
                templates.get(&id).and_then(|template| template.node()),
                scenario,
                id,
            );
            if !used_paths.is_empty()
                && let Some(template) = templates.get(&id).and_then(|template| template.node())
            {
                record_binding_uses_in_runtime_config_paths(
                    template,
                    &used_paths,
                    id,
                    BindingUseSource::Config,
                    &mut usage,
                );
            }
        }
    }

    usage
}

fn record_binding_parts(
    parts: &[InterpolatedPart],
    component: ComponentId,
    usage_source: BindingUseSource,
    scope: ComponentId,
    usage: &mut BindingUsage,
) {
    for part in parts {
        let InterpolatedPart::Interpolation { source, query } = part else {
            continue;
        };
        if *source != InterpolationSource::Bindings {
            continue;
        }
        if let Ok(parsed) = parse_binding_query(query) {
            usage.record(component, usage_source, scope, parsed.name);
        }
    }
}

fn collect_program_used_config_paths(
    program: &amber_manifest::Program,
    template_opt: Option<&ConfigNode>,
    scenario: &Scenario,
    component_id: ComponentId,
) -> BTreeSet<String> {
    let mut used = BTreeSet::new();

    let executable = program.path_ref().or_else(|| program.image_ref());
    if let Some(executable) = executable
        && let Ok(parsed) = executable.parse::<InterpolatedString>()
    {
        record_program_config_parts(&parsed.parts, &mut used);
    }
    for item in &program.command().0 {
        let Some(when) = item.when() else {
            item.visit_values(|value| record_program_config_parts(&value.parts, &mut used));
            continue;
        };
        if conditional_path_may_be_present(
            template_opt,
            scenario,
            component_id,
            when.source(),
            when.query(),
        ) {
            if when.source() == InterpolationSource::Config {
                used.insert(when.query().to_string());
            }
            item.visit_values(|value| record_program_config_parts(&value.parts, &mut used));
        }
    }
    for value in program.env().values() {
        if let Some(when) = value.when() {
            if conditional_path_may_be_present(
                template_opt,
                scenario,
                component_id,
                when.source(),
                when.query(),
            ) {
                if when.source() == InterpolationSource::Config {
                    used.insert(when.query().to_string());
                }
                value.visit_values(|value| record_program_config_parts(&value.parts, &mut used));
            }
            continue;
        }
        value.visit_values(|value| record_program_config_parts(&value.parts, &mut used));
    }
    for mount in program.mounts() {
        match &mount.source {
            MountSource::Config(path) | MountSource::Secret(path) => {
                used.insert(path.clone());
            }
            MountSource::Resource(_)
            | MountSource::Slot(_)
            | MountSource::Binding(_)
            | MountSource::Framework(_) => {}
            _ => {}
        }
    }

    used
}

fn conditional_path_may_be_present(
    template_opt: Option<&ConfigNode>,
    scenario: &Scenario,
    component_id: ComponentId,
    source: InterpolationSource,
    query: &str,
) -> bool {
    match source {
        InterpolationSource::Config => {
            let Some(template) = template_opt else {
                return true;
            };
            match resolve_optional_config_node_path(template, query) {
                None => false,
                Some(ConfigNode::Null) => false,
                Some(node) => {
                    node.contains_runtime() || !matches!(node.static_subset(), Some(Value::Null))
                }
            }
        }
        InterpolationSource::Slots => slot_query_may_be_present(scenario, component_id, query),
        InterpolationSource::Bindings => true,
        _ => true,
    }
}

fn slot_query_may_be_present(scenario: &Scenario, component_id: ComponentId, query: &str) -> bool {
    let Ok(parsed) = parse_slot_query(query) else {
        return false;
    };
    let SlotTarget::Slot(slot_name) = parsed.target else {
        return false;
    };
    scenario.bindings.iter().any(|binding| {
        binding.to.component == component_id && binding.to.name.as_str() == slot_name
    })
}

fn resolve_optional_config_node_path<'a>(
    template: &'a ConfigNode,
    path: &str,
) -> Option<&'a ConfigNode> {
    if path.is_empty() {
        return Some(template);
    }

    let mut current = template;
    for segment in path.split('.') {
        if segment.is_empty() {
            return None;
        }
        match current {
            ConfigNode::Object(map) => current = map.get(segment)?,
            ConfigNode::ConfigRef(_) => return Some(current),
            _ => return None,
        }
    }
    Some(current)
}

fn record_program_config_parts(parts: &[InterpolatedPart], used: &mut BTreeSet<String>) {
    for part in parts {
        let InterpolatedPart::Interpolation { source, query } = part else {
            continue;
        };
        if *source == InterpolationSource::Config {
            used.insert(query.clone());
        }
    }
}

fn record_binding_uses_in_runtime_config_paths(
    template: &ConfigNode,
    used_paths: &BTreeSet<String>,
    component: ComponentId,
    usage_source: BindingUseSource,
    usage: &mut BindingUsage,
) {
    for path in used_paths {
        let Some(node) = config_node_for_path(template, path) else {
            continue;
        };
        record_binding_uses_in_config_node(node, component, usage_source, usage);
    }
}

fn config_node_for_path<'a>(template: &'a ConfigNode, path: &str) -> Option<&'a ConfigNode> {
    if path.is_empty() {
        return Some(template);
    }

    let mut current = template;
    for segment in path.split('.') {
        if segment.is_empty() {
            return None;
        }
        match current {
            ConfigNode::Object(map) => {
                current = map.get(segment)?;
            }
            ConfigNode::ConfigRef(_) => return None,
            _ => return None,
        }
    }
    Some(current)
}

fn record_binding_uses_in_config_node(
    value: &ConfigNode,
    component: ComponentId,
    usage_source: BindingUseSource,
    usage: &mut BindingUsage,
) {
    match value {
        ConfigNode::StringTemplate(parts) => {
            for part in parts {
                let TemplatePart::Binding { binding, scope } = part else {
                    continue;
                };
                if let Ok(parsed) = parse_binding_query(binding) {
                    usage.record(
                        component,
                        usage_source,
                        ComponentId(*scope as usize),
                        parsed.name,
                    );
                }
            }
        }
        ConfigNode::Array(values) => {
            for value in values {
                record_binding_uses_in_config_node(value, component, usage_source, usage);
            }
        }
        ConfigNode::Object(map) => {
            for value in map.values() {
                record_binding_uses_in_config_node(value, component, usage_source, usage);
            }
        }
        _ => {}
    }
}
