use std::collections::HashMap;

use amber_config as rc;
use amber_manifest::{
    FrameworkCapabilityName, InterpolatedPart, InterpolatedString, InterpolationSource,
    MountSource, WhenPath,
};
use amber_scenario::{ComponentId, Scenario};
use serde_json::Value;

use crate::{
    config_resolution::{QueryResolution, parse_query_segments, resolve_config_query_node},
    config_templates,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum StaticMountKind {
    Slot(String),
    Resource(String),
    Framework(FrameworkCapabilityName),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StaticMount {
    pub(crate) mount_index: usize,
    pub(crate) path: String,
    pub(crate) kind: StaticMountKind,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct StaticMountPlan {
    by_component: HashMap<ComponentId, Vec<StaticMount>>,
}

impl StaticMountPlan {
    pub(crate) fn component_mounts(&self, id: ComponentId) -> &[StaticMount] {
        self.by_component.get(&id).map(Vec::as_slice).unwrap_or(&[])
    }
}

#[derive(Clone, Debug)]
pub(crate) struct MountSemanticsError {
    pub(crate) component: ComponentId,
    pub(crate) mount_index: usize,
    pub(crate) message: String,
}

#[derive(Clone, Debug)]
enum StringResolution {
    Static(String),
    DynamicConfig,
    DynamicSlots,
}

#[derive(Clone, Debug)]
enum WhenResolution {
    Present,
    Absent,
    DynamicConfig,
    DynamicSlots,
}

#[derive(Clone, Debug)]
enum EachResolution {
    None,
    Static(Vec<Value>),
    DynamicConfig,
    DynamicSlots,
}

pub(crate) fn analyze_mount_semantics(
    scenario: &Scenario,
) -> (StaticMountPlan, Vec<MountSemanticsError>) {
    let resolved_templates = compose_component_config_templates(scenario);
    let mut plan = StaticMountPlan::default();
    let mut errors = Vec::new();

    for (id, component) in scenario.components_iter() {
        let Some(program) = component.program.as_ref() else {
            continue;
        };
        if program.mounts().is_empty() {
            continue;
        }
        let template_opt = resolved_templates
            .get(&id)
            .and_then(|template| template.node());

        for (mount_idx, mount) in program.mounts().iter().enumerate() {
            let when = match resolve_when(mount.when.as_ref(), template_opt) {
                Ok(when) => when,
                Err(message) => {
                    errors.push(MountSemanticsError {
                        component: id,
                        mount_index: mount_idx,
                        message,
                    });
                    continue;
                }
            };
            if matches!(when, WhenResolution::Absent) {
                continue;
            }

            let each = match resolve_each(mount.each.as_ref(), template_opt) {
                Ok(each) => each,
                Err(message) => {
                    errors.push(MountSemanticsError {
                        component: id,
                        mount_index: mount_idx,
                        message,
                    });
                    continue;
                }
            };
            if matches!(each, EachResolution::Static(ref items) if items.is_empty()) {
                continue;
            }

            match &each {
                EachResolution::None => analyze_mount_iteration(
                    &mut plan,
                    &mut errors,
                    MountIteration {
                        component: id,
                        mount_index: mount_idx,
                        path: &mount.path,
                        source: &mount.source,
                        when: &when,
                        each_is_dynamic: false,
                        template_opt,
                        item: None,
                    },
                ),
                EachResolution::Static(items) => {
                    for item in items {
                        analyze_mount_iteration(
                            &mut plan,
                            &mut errors,
                            MountIteration {
                                component: id,
                                mount_index: mount_idx,
                                path: &mount.path,
                                source: &mount.source,
                                when: &when,
                                each_is_dynamic: false,
                                template_opt,
                                item: Some(item),
                            },
                        );
                    }
                }
                EachResolution::DynamicConfig => analyze_mount_iteration(
                    &mut plan,
                    &mut errors,
                    MountIteration {
                        component: id,
                        mount_index: mount_idx,
                        path: &mount.path,
                        source: &mount.source,
                        when: &when,
                        each_is_dynamic: true,
                        template_opt,
                        item: None,
                    },
                ),
                EachResolution::DynamicSlots => analyze_mount_iteration(
                    &mut plan,
                    &mut errors,
                    MountIteration {
                        component: id,
                        mount_index: mount_idx,
                        path: &mount.path,
                        source: &mount.source,
                        when: &when,
                        each_is_dynamic: true,
                        template_opt,
                        item: None,
                    },
                ),
            }
        }
    }

    (plan, errors)
}

pub(crate) fn validated_static_mounts(scenario: &Scenario, stage: &str) -> StaticMountPlan {
    let (plan, errors) = analyze_mount_semantics(scenario);
    assert!(
        errors.is_empty(),
        "linker should reject unsupported non-file mount semantics before {stage}: {errors:?}"
    );
    plan
}

pub(crate) fn source_is_guaranteed_file_mount(source: &InterpolatedString) -> bool {
    let Some(prefix) = literal_prefix(source) else {
        return false;
    };
    prefix == "config"
        || prefix.starts_with("config.")
        || prefix == "secret"
        || prefix.starts_with("secret.")
}

fn compose_component_config_templates(
    scenario: &Scenario,
) -> HashMap<ComponentId, rc::RootConfigTemplate> {
    let composed =
        config_templates::compose_root_config_templates(scenario.root, &scenario.components);
    assert!(
        composed.errors.is_empty(),
        "config tree validation should reject invalid component config templates before mount \
         analysis"
    );
    composed.templates
}

struct MountIteration<'a> {
    component: ComponentId,
    mount_index: usize,
    path: &'a InterpolatedString,
    source: &'a InterpolatedString,
    when: &'a WhenResolution,
    each_is_dynamic: bool,
    template_opt: Option<&'a rc::ConfigNode>,
    item: Option<&'a Value>,
}

fn analyze_mount_iteration(
    plan: &mut StaticMountPlan,
    errors: &mut Vec<MountSemanticsError>,
    mount: MountIteration<'_>,
) {
    let MountIteration {
        component,
        mount_index,
        path,
        source,
        when,
        each_is_dynamic,
        template_opt,
        item,
    } = mount;

    let source_resolution = match resolve_interpolated_string(source, template_opt, item) {
        Ok(resolution) => resolution,
        Err(message) => {
            errors.push(MountSemanticsError {
                component,
                mount_index,
                message,
            });
            return;
        }
    };

    match source_resolution {
        StringResolution::Static(raw_source) => {
            let source_kind = match raw_source.parse::<MountSource>() {
                Ok(source_kind) => source_kind,
                Err(err) => {
                    errors.push(MountSemanticsError {
                        component,
                        mount_index,
                        message: format!(
                            "program.mounts[{mount_index}].from resolves to an invalid mount \
                             source: {err}"
                        ),
                    });
                    return;
                }
            };

            let kind = match source_kind {
                MountSource::Config(_) | MountSource::Secret(_) => return,
                MountSource::Slot(slot) => StaticMountKind::Slot(slot),
                MountSource::Resource(resource) => StaticMountKind::Resource(resource),
                MountSource::Framework(capability) => StaticMountKind::Framework(capability),
                _ => unreachable!("mount source parser should only produce known variants"),
            };

            if matches!(
                when,
                WhenResolution::DynamicConfig | WhenResolution::DynamicSlots
            ) {
                errors.push(MountSemanticsError {
                    component,
                    mount_index,
                    message: format!(
                        "program.mounts[{mount_index}] resolves to a non-file mount, but its \
                         `when` condition is not compile-time concrete"
                    ),
                });
                return;
            }
            if each_is_dynamic {
                errors.push(MountSemanticsError {
                    component,
                    mount_index,
                    message: format!(
                        "program.mounts[{mount_index}] resolves to a non-file mount, but its \
                         `each` expansion is not compile-time concrete"
                    ),
                });
                return;
            }

            let path = match resolve_interpolated_string(path, template_opt, item) {
                Ok(StringResolution::Static(path)) => path,
                Ok(StringResolution::DynamicConfig | StringResolution::DynamicSlots) => {
                    errors.push(MountSemanticsError {
                        component,
                        mount_index,
                        message: format!(
                            "program.mounts[{mount_index}] resolves to a non-file mount, but its \
                             `path` is not compile-time concrete"
                        ),
                    });
                    return;
                }
                Err(message) => {
                    errors.push(MountSemanticsError {
                        component,
                        mount_index,
                        message,
                    });
                    return;
                }
            };

            if !path.starts_with('/') {
                errors.push(MountSemanticsError {
                    component,
                    mount_index,
                    message: format!(
                        "program.mounts[{mount_index}].path resolves to `{path}`, but non-file \
                         mount paths must be absolute"
                    ),
                });
                return;
            }
            if path.split('/').any(|segment| segment == "..") {
                errors.push(MountSemanticsError {
                    component,
                    mount_index,
                    message: format!(
                        "program.mounts[{mount_index}].path resolves to `{path}`, but non-file \
                         mount paths must not contain `..`"
                    ),
                });
                return;
            }

            plan.by_component
                .entry(component)
                .or_default()
                .push(StaticMount {
                    mount_index,
                    path,
                    kind,
                });
        }
        StringResolution::DynamicConfig | StringResolution::DynamicSlots => {
            if !source_is_guaranteed_file_mount(source) {
                errors.push(MountSemanticsError {
                    component,
                    mount_index,
                    message: format!(
                        "program.mounts[{mount_index}].from is not compile-time concrete and is \
                         not provably a config/secret file mount"
                    ),
                });
            }
        }
    }
}

fn resolve_interpolated_string(
    value: &InterpolatedString,
    template_opt: Option<&rc::ConfigNode>,
    item: Option<&Value>,
) -> Result<StringResolution, String> {
    let mut rendered = String::new();
    for part in &value.parts {
        match part {
            InterpolatedPart::Literal(lit) => rendered.push_str(lit),
            InterpolatedPart::Interpolation { source, query } => match source {
                InterpolationSource::Config => {
                    let Some(template) = template_opt else {
                        return Ok(StringResolution::DynamicConfig);
                    };
                    match resolve_config_query_node(template, query)
                        .map_err(|err| err.to_string())?
                    {
                        QueryResolution::RuntimePath(_) => {
                            return Ok(StringResolution::DynamicConfig);
                        }
                        QueryResolution::Node(node) => {
                            if node.contains_runtime() {
                                return Ok(StringResolution::DynamicConfig);
                            }
                            let value = node.evaluate_static().map_err(|err| err.to_string())?;
                            rendered.push_str(
                                &rc::stringify_for_interpolation(&value)
                                    .map_err(|err| err.to_string())?,
                            );
                        }
                    }
                }
                InterpolationSource::Item => {
                    let Some(item) = item else {
                        return Err(
                            "`item` interpolation is only valid inside `each` expansions"
                                .to_string(),
                        );
                    };
                    let value = query_value_opt(item, query).ok_or_else(|| {
                        let label = if query.is_empty() {
                            "item".to_string()
                        } else {
                            format!("item.{query}")
                        };
                        format!("{label} not found in the current repeated item")
                    })?;
                    rendered.push_str(
                        &rc::stringify_for_interpolation(value).map_err(|err| err.to_string())?,
                    );
                }
                InterpolationSource::Slots => return Ok(StringResolution::DynamicSlots),
                other => {
                    return Err(format!(
                        "unsupported interpolation source {other} in program.mounts"
                    ));
                }
            },
            _ => return Err("unsupported interpolation syntax in program.mounts".to_string()),
        }
    }

    Ok(StringResolution::Static(rendered))
}

fn resolve_when(
    when: Option<&WhenPath>,
    template_opt: Option<&rc::ConfigNode>,
) -> Result<WhenResolution, String> {
    let Some(when) = when else {
        return Ok(WhenResolution::Present);
    };

    match when.source() {
        InterpolationSource::Config => {
            let Some(template) = template_opt else {
                return Ok(WhenResolution::DynamicConfig);
            };
            let Some(resolution) = resolve_optional_config_query_node(template, when.query())?
            else {
                return Ok(WhenResolution::Absent);
            };
            match resolution {
                QueryResolution::RuntimePath(_) => Ok(WhenResolution::DynamicConfig),
                QueryResolution::Node(node) => {
                    if node.contains_runtime() {
                        return Ok(WhenResolution::DynamicConfig);
                    }
                    let value = node.evaluate_static().map_err(|err| err.to_string())?;
                    if value.is_null() {
                        Ok(WhenResolution::Absent)
                    } else {
                        Ok(WhenResolution::Present)
                    }
                }
            }
        }
        InterpolationSource::Slots => Ok(WhenResolution::DynamicSlots),
        other => Err(format!(
            "unsupported interpolation source {other} in program.mounts[].when"
        )),
    }
}

fn resolve_each(
    each: Option<&amber_manifest::EachPath>,
    template_opt: Option<&rc::ConfigNode>,
) -> Result<EachResolution, String> {
    let Some(each) = each else {
        return Ok(EachResolution::None);
    };

    match each.source() {
        InterpolationSource::Config => {
            let Some(template) = template_opt else {
                return Ok(EachResolution::DynamicConfig);
            };
            let Some(resolution) = resolve_optional_config_query_node(template, each.query())?
            else {
                return Ok(EachResolution::Static(Vec::new()));
            };
            match resolution {
                QueryResolution::RuntimePath(_) => Ok(EachResolution::DynamicConfig),
                QueryResolution::Node(node) => {
                    if node.contains_runtime() {
                        return Ok(EachResolution::DynamicConfig);
                    }
                    let value = node.evaluate_static().map_err(|err| err.to_string())?;
                    match value {
                        Value::Null => Ok(EachResolution::Static(Vec::new())),
                        Value::Array(values) => Ok(EachResolution::Static(values)),
                        other => Err(format!(
                            "program.mounts[].each uses `config.{}`, but config.{} resolves to {} \
                             instead of an array",
                            each.query(),
                            each.query(),
                            value_kind(&other)
                        )),
                    }
                }
            }
        }
        InterpolationSource::Slots => Ok(EachResolution::DynamicSlots),
        other => Err(format!(
            "unsupported interpolation source {other} in program.mounts[].each"
        )),
    }
}

fn resolve_optional_config_query_node<'a>(
    template: &'a rc::ConfigNode,
    query: &str,
) -> Result<Option<QueryResolution<'a>>, String> {
    if query.is_empty() {
        return Ok(Some(QueryResolution::Node(template)));
    }

    let segments = parse_query_segments(query)?;
    let mut current = template;
    for (idx, segment) in segments.iter().enumerate() {
        match current {
            rc::ConfigNode::Object(map) => {
                let Some(next) = map.get(*segment) else {
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

fn literal_prefix(value: &InterpolatedString) -> Option<String> {
    let mut prefix = String::new();
    for part in &value.parts {
        match part {
            InterpolatedPart::Literal(lit) => prefix.push_str(lit),
            _ => return (!prefix.is_empty()).then_some(prefix),
        }
    }
    (!prefix.is_empty()).then_some(prefix)
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

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use amber_manifest::ManifestDigest;
    use amber_scenario::{BindingEdge, Component, Moniker};

    use super::*;

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
    fn analyze_mount_semantics_expands_static_config_storage_mounts() {
        let root = component_with_config_and_program(0, None, "/", None, None, None);
        let child = component_with_config_and_program(
            1,
            Some(0),
            "/worker",
            Some(serde_json::json!({
                "type": "object",
                "properties": {
                    "mounts": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "path": { "type": "string" },
                                "from": { "type": "string" }
                            },
                            "required": ["path", "from"]
                        }
                    }
                },
                "required": ["mounts"]
            })),
            Some(serde_json::json!({
                "mounts": [
                    { "path": "/var/lib/state", "from": "resources.state" },
                    { "path": "/var/cache/app", "from": "slots.cache" }
                ]
            })),
            Some(serde_json::json!({
                "image": "service",
                "entrypoint": ["service"],
                "mounts": [
                    {
                        "each": "config.mounts",
                        "path": "${item.path}",
                        "from": "${item.from}"
                    }
                ]
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

        let (plan, errors) = analyze_mount_semantics(&scenario);

        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(
            plan.component_mounts(ComponentId(1)),
            &[
                StaticMount {
                    mount_index: 0,
                    path: "/var/lib/state".to_string(),
                    kind: StaticMountKind::Resource("state".to_string()),
                },
                StaticMount {
                    mount_index: 0,
                    path: "/var/cache/app".to_string(),
                    kind: StaticMountKind::Slot("cache".to_string()),
                },
            ]
        );
    }

    #[test]
    fn analyze_mount_semantics_rejects_dynamic_non_file_mount_conditions() {
        let root = component_with_config_and_program(0, None, "/", None, None, None);
        let child = component_with_config_and_program(
            1,
            Some(0),
            "/worker",
            None,
            None,
            Some(serde_json::json!({
                "image": "service",
                "entrypoint": ["service"],
                "mounts": [
                    {
                        "when": "slots.enable_state",
                        "path": "/var/lib/state",
                        "from": "resources.state"
                    }
                ]
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

        let (plan, errors) = analyze_mount_semantics(&scenario);

        assert!(plan.component_mounts(ComponentId(1)).is_empty());
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(
            errors[0]
                .message
                .contains("`when` condition is not compile-time concrete"),
            "{errors:?}"
        );
    }
}
