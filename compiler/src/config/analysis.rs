use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};

use amber_config as rc;
use amber_manifest::InterpolatedString;
use amber_scenario::{Component, ComponentId, Scenario};
use serde_json::{Map, Value};

use super::{
    query::{
        ConfigEachResolution, ConfigPresence, QueryResolution, parse_query_segments,
        render_static_config_string, resolve_config_query_node, validate_config_query_syntax,
        value_kind,
    },
    scope::{RuntimeConfigView, build_runtime_config_view},
    templates::{self, TemplateError},
};

#[derive(Clone, Debug)]
pub(crate) struct ScenarioConfigAnalysis {
    root_schema: Option<Arc<Value>>,
    root_leaves: Arc<[rc::SchemaLeaf]>,
    components: HashMap<ComponentId, ComponentConfigAnalysis>,
    template_errors: Vec<TemplateError>,
}

impl ScenarioConfigAnalysis {
    pub(crate) fn from_scenario(scenario: &Scenario) -> Result<Self, String> {
        Self::from_components(scenario.root, &scenario.components)
    }

    pub(crate) fn from_components(
        root: ComponentId,
        components: &[Option<Component>],
    ) -> Result<Self, String> {
        let composed = templates::compose_root_config_templates(root, components);
        let root_schema = components
            .get(root.0)
            .and_then(Option::as_ref)
            .and_then(|component| component.config_schema.clone())
            .map(Arc::new);
        let root_leaves = match root_schema.as_deref() {
            Some(schema) => {
                Arc::<[rc::SchemaLeaf]>::from(rc::collect_leaf_paths(schema).map_err(|err| {
                    format!("failed to enumerate root config definition leaf paths: {err}")
                })?)
            }
            None => Arc::<[rc::SchemaLeaf]>::from(Vec::new()),
        };

        let mut analyzed_components = HashMap::with_capacity(composed.templates.len());
        for (id, template) in composed.templates {
            let component_schema = components
                .get(id.0)
                .and_then(Option::as_ref)
                .and_then(|component| component.config_schema.clone());
            analyzed_components.insert(
                id,
                ComponentConfigAnalysis::new(
                    template,
                    component_schema,
                    root_schema.clone(),
                    root_leaves.clone(),
                )?,
            );
        }

        Ok(Self {
            root_schema,
            root_leaves,
            components: analyzed_components,
            template_errors: composed.errors,
        })
    }

    pub(crate) fn root_schema(&self) -> Option<&Value> {
        self.root_schema.as_deref()
    }

    pub(crate) fn root_leaves(&self) -> &[rc::SchemaLeaf] {
        &self.root_leaves
    }

    pub(crate) fn component(&self, id: ComponentId) -> Option<&ComponentConfigAnalysis> {
        self.components.get(&id)
    }

    pub(crate) fn expect_component(&self, id: ComponentId) -> &ComponentConfigAnalysis {
        self.component(id)
            .expect("config analysis should exist for each component")
    }

    pub(crate) fn template_errors(&self) -> &[TemplateError] {
        &self.template_errors
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ComponentConfigAnalysis {
    template: rc::RootConfigTemplate,
    component_schema: Option<Value>,
    root_schema: Option<Arc<Value>>,
    root_leaves: Arc<[rc::SchemaLeaf]>,
    omission_defaults: Option<Value>,
}

impl ComponentConfigAnalysis {
    fn new(
        template: rc::RootConfigTemplate,
        component_schema: Option<Value>,
        root_schema: Option<Arc<Value>>,
        root_leaves: Arc<[rc::SchemaLeaf]>,
    ) -> Result<Self, String> {
        let omission_defaults = omission_defaults_for_schema(component_schema.as_ref())?;
        Ok(Self {
            template,
            component_schema,
            root_schema,
            root_leaves,
            omission_defaults,
        })
    }

    #[cfg(test)]
    pub(crate) fn standalone(
        template: Option<rc::ConfigNode>,
        component_schema: Option<Value>,
        root_schema: Option<Value>,
    ) -> Result<Self, String> {
        let root_schema = root_schema.map(Arc::new);
        let root_leaves = match root_schema.as_deref() {
            Some(schema) => {
                Arc::<[rc::SchemaLeaf]>::from(rc::collect_leaf_paths(schema).map_err(|err| {
                    format!("failed to enumerate root config definition leaf paths: {err}")
                })?)
            }
            None => Arc::<[rc::SchemaLeaf]>::from(Vec::new()),
        };
        let template = match template {
            Some(template) => rc::RootConfigTemplate::Node(template),
            None if root_schema.is_some() => rc::RootConfigTemplate::Root,
            None => rc::RootConfigTemplate::Node(rc::ConfigNode::empty_object()),
        };
        Self::new(template, component_schema, root_schema, root_leaves)
    }

    pub(crate) fn template(&self) -> &rc::RootConfigTemplate {
        &self.template
    }

    pub(crate) fn template_node(&self) -> Option<&rc::ConfigNode> {
        self.template.node()
    }

    pub(crate) fn component_schema(&self) -> Option<&Value> {
        self.component_schema.as_ref()
    }

    pub(crate) fn root_schema(&self) -> Option<&Value> {
        self.root_schema.as_deref()
    }

    pub(crate) fn root_leaves(&self) -> &[rc::SchemaLeaf] {
        &self.root_leaves
    }

    pub(crate) fn resolve_query<'a>(&'a self, query: &str) -> Result<QueryResolution<'a>, String> {
        match self.template_node() {
            Some(template) => resolve_config_query_node(template, query),
            None => {
                validate_config_query_syntax(query)?;
                Ok(QueryResolution::RuntimePath(query.to_string()))
            }
        }
    }

    pub(crate) fn resolve_presence(&self, query: &str) -> Result<ConfigPresence, String> {
        validate_config_query_syntax(query)?;

        let omission_presence = self.omission_presence(query)?;
        let Some(template) = self.template_node() else {
            return self.root_schema_presence(query);
        };

        match resolve_query_resolution(template, query)? {
            DetailedQueryResolution::Missing => Ok(omission_presence),
            DetailedQueryResolution::Node(node) => {
                if node.contains_runtime() {
                    return Ok(ConfigPresence::Runtime);
                }
                let value = node.evaluate_static().map_err(|err| err.to_string())?;
                if value.is_null() {
                    Ok(ConfigPresence::Absent)
                } else {
                    Ok(ConfigPresence::Present)
                }
            }
            DetailedQueryResolution::RuntimeRef { full_path } => {
                let root_presence = self.root_schema_presence(&full_path)?;
                if matches!(omission_presence, ConfigPresence::Present) {
                    return Ok(match root_presence {
                        ConfigPresence::Present => ConfigPresence::Present,
                        ConfigPresence::Absent
                            if self
                                .runtime_path_ancestors_must_be_non_null_objects(&full_path)? =>
                        {
                            ConfigPresence::Present
                        }
                        ConfigPresence::Runtime
                            if self
                                .runtime_path_ancestors_must_be_non_null_objects(&full_path)?
                                && self
                                    .runtime_path_defined_value_cannot_be_null(&full_path)? =>
                        {
                            ConfigPresence::Present
                        }
                        ConfigPresence::Absent | ConfigPresence::Runtime => ConfigPresence::Runtime,
                    });
                }
                Ok(root_presence)
            }
        }
    }

    pub(crate) fn resolve_each_values(
        &self,
        query: &str,
        location: &str,
    ) -> Result<ConfigEachResolution, String> {
        validate_config_query_syntax(query)?;

        let Some(template) = self.template_node() else {
            return Ok(ConfigEachResolution::Runtime);
        };

        match resolve_query_resolution(template, query)? {
            DetailedQueryResolution::Missing => {
                self.resolve_each_values_from_value(self.omission_value(query)?, query, location)
            }
            DetailedQueryResolution::Node(node) => {
                if node.contains_runtime() {
                    return Ok(ConfigEachResolution::Runtime);
                }
                let value = node.evaluate_static().map_err(|err| err.to_string())?;
                self.resolve_each_values_from_value(Some(&value), query, location)
            }
            DetailedQueryResolution::RuntimeRef { full_path } => {
                if self.root_schema_presence(&full_path)? != ConfigPresence::Absent
                    || !self.runtime_path_ancestors_must_be_non_null_objects(&full_path)?
                {
                    return Ok(ConfigEachResolution::Runtime);
                }
                self.resolve_each_values_from_value(self.omission_value(query)?, query, location)
            }
        }
    }

    pub(crate) fn render_static_string(
        &self,
        value: &InterpolatedString,
    ) -> Result<String, String> {
        render_static_config_string(value, self.template_node())
    }

    pub(crate) fn build_runtime_view(
        &self,
        component_label: &str,
        used_component_paths: &BTreeSet<String>,
    ) -> Result<RuntimeConfigView, String> {
        let root_schema = self.root_schema().ok_or_else(|| {
            "root component must declare `config_schema` when runtime config interpolation is \
             required"
                .to_string()
        })?;
        let component_schema = self.component_schema().ok_or_else(|| {
            format!(
                "component {component_label} requires config_schema when using runtime config \
                 interpolation"
            )
        })?;
        build_runtime_config_view(
            component_label,
            root_schema,
            self.root_leaves(),
            self.template(),
            component_schema,
            used_component_paths,
        )
        .map_err(|err| err.to_string())
    }

    fn omission_presence(&self, query: &str) -> Result<ConfigPresence, String> {
        match self.omission_value(query)? {
            Some(value) if !value.is_null() => Ok(ConfigPresence::Present),
            Some(_) | None => Ok(ConfigPresence::Absent),
        }
    }

    fn omission_value(&self, query: &str) -> Result<Option<&Value>, String> {
        let Some(defaults) = &self.omission_defaults else {
            return Ok(None);
        };
        rc::get_by_path_opt(defaults, query).map_err(|err| err.to_string())
    }

    fn root_schema_presence(&self, query: &str) -> Result<ConfigPresence, String> {
        let Some(root_schema) = self.root_schema() else {
            return Ok(ConfigPresence::Runtime);
        };
        rc::schema_path_presence(root_schema, query)
            .map(|presence| match presence {
                rc::SchemaPresence::Present => ConfigPresence::Present,
                rc::SchemaPresence::Absent => ConfigPresence::Absent,
                rc::SchemaPresence::Runtime => ConfigPresence::Runtime,
            })
            .map_err(|err| err.to_string())
    }

    fn runtime_path_ancestors_must_be_non_null_objects(
        &self,
        full_path: &str,
    ) -> Result<bool, String> {
        let Some(root_schema) = self.root_schema() else {
            return Ok(false);
        };
        match rc::schema_path_ancestors_must_be_non_null_objects(root_schema, full_path) {
            Ok(must_be_objects) => Ok(must_be_objects),
            Err(_) => Ok(false),
        }
    }

    fn runtime_path_defined_value_cannot_be_null(&self, full_path: &str) -> Result<bool, String> {
        let Some(root_schema) = self.root_schema() else {
            return Ok(false);
        };
        match rc::schema_lookup(root_schema, full_path) {
            Ok(rc::SchemaLookup::Found) => {
                match rc::schema_path_accepts_null(root_schema, full_path) {
                    Ok(accepts_null) => Ok(!accepts_null),
                    Err(_) => Ok(false),
                }
            }
            Ok(rc::SchemaLookup::Unknown) | Err(_) => Ok(false),
        }
    }

    fn resolve_each_values_from_value(
        &self,
        value: Option<&Value>,
        query: &str,
        location: &str,
    ) -> Result<ConfigEachResolution, String> {
        match value {
            None | Some(Value::Null) => Ok(ConfigEachResolution::Static(Vec::new())),
            Some(Value::Array(items)) => Ok(ConfigEachResolution::Static(items.clone())),
            Some(other) => Err(format!(
                "{location} uses `each: \"config.{query}\"`, but config.{query} resolves to {} \
                 instead of an array",
                value_kind(other)
            )),
        }
    }
}

fn omission_defaults_for_schema(component_schema: Option<&Value>) -> Result<Option<Value>, String> {
    let Some(component_schema) = component_schema else {
        return Ok(None);
    };
    let mut defaults = Value::Object(Map::new());
    rc::apply_schema_defaults(component_schema, &mut defaults).map_err(|err| err.to_string())?;
    Ok(Some(defaults))
}

enum DetailedQueryResolution<'a> {
    Missing,
    Node(&'a rc::ConfigNode),
    RuntimeRef { full_path: String },
}

fn resolve_query_resolution<'a>(
    template: &'a rc::ConfigNode,
    query: &str,
) -> Result<DetailedQueryResolution<'a>, String> {
    if query.is_empty() {
        return Ok(match template {
            rc::ConfigNode::ConfigRef(path) => DetailedQueryResolution::RuntimeRef {
                full_path: path.clone(),
            },
            _ => DetailedQueryResolution::Node(template),
        });
    }

    let segments = parse_query_segments(query)?;
    let mut current = template;
    for (idx, seg) in segments.iter().enumerate() {
        match current {
            rc::ConfigNode::Object(map) => {
                let Some(next) = map.get(*seg) else {
                    return Ok(DetailedQueryResolution::Missing);
                };
                current = next;
            }
            rc::ConfigNode::ConfigRef(path) => {
                let suffix = segments[idx..].join(".");
                let full_path = if path.is_empty() {
                    suffix
                } else {
                    format!("{path}.{suffix}")
                };
                return Ok(DetailedQueryResolution::RuntimeRef { full_path });
            }
            _ => return Ok(DetailedQueryResolution::Missing),
        }
    }

    Ok(match current {
        rc::ConfigNode::ConfigRef(path) => DetailedQueryResolution::RuntimeRef {
            full_path: path.clone(),
        },
        _ => DetailedQueryResolution::Node(current),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn resolve_presence_uses_component_defaults_for_forwarded_object_children() {
        let component = ComponentConfigAnalysis::standalone(
            Some(rc::ConfigNode::Object(
                [(
                    "settings".to_string(),
                    rc::ConfigNode::ConfigRef("settings".to_string()),
                )]
                .into_iter()
                .collect(),
            )),
            Some(json!({
                "type": "object",
                "properties": {
                    "settings": {
                        "type": "object",
                        "properties": {
                            "mode": { "type": "string", "default": "enabled" }
                        }
                    }
                }
            })),
            Some(json!({
                "type": "object",
                "properties": {
                    "settings": {
                        "type": "object",
                        "properties": {}
                    }
                }
            })),
        )
        .expect("analysis");

        assert_eq!(
            component.resolve_presence("settings.mode").unwrap(),
            ConfigPresence::Present
        );
    }

    #[test]
    fn resolve_presence_keeps_forwarded_object_defaults_runtime_when_root_can_be_null() {
        let component = ComponentConfigAnalysis::standalone(
            Some(rc::ConfigNode::Object(
                [(
                    "settings".to_string(),
                    rc::ConfigNode::ConfigRef("settings".to_string()),
                )]
                .into_iter()
                .collect(),
            )),
            Some(json!({
                "type": "object",
                "properties": {
                    "settings": {
                        "type": ["object", "null"],
                        "properties": {
                            "mode": { "type": "string", "default": "enabled" }
                        }
                    }
                }
            })),
            Some(json!({
                "type": "object",
                "properties": {
                    "settings": {
                        "type": ["object", "null"],
                        "properties": {}
                    }
                }
            })),
        )
        .expect("analysis");

        assert_eq!(
            component.resolve_presence("settings.mode").unwrap(),
            ConfigPresence::Runtime
        );
    }

    #[test]
    fn resolve_presence_keeps_forwarded_object_defaults_runtime_when_leaf_can_be_null() {
        let component = ComponentConfigAnalysis::standalone(
            Some(rc::ConfigNode::Object(
                [(
                    "settings".to_string(),
                    rc::ConfigNode::ConfigRef("settings".to_string()),
                )]
                .into_iter()
                .collect(),
            )),
            Some(json!({
                "type": "object",
                "properties": {
                    "settings": {
                        "type": "object",
                        "properties": {
                            "mode": { "type": "string", "default": "enabled" }
                        }
                    }
                }
            })),
            Some(json!({
                "type": "object",
                "properties": {
                    "settings": {
                        "type": "object",
                        "properties": {
                            "mode": { "type": ["string", "null"] }
                        }
                    }
                }
            })),
        )
        .expect("analysis");

        assert_eq!(
            component.resolve_presence("settings.mode").unwrap(),
            ConfigPresence::Runtime
        );
    }

    #[test]
    fn resolve_presence_keeps_forwarded_object_defaults_runtime_when_root_may_be_non_object() {
        let component = ComponentConfigAnalysis::standalone(
            Some(rc::ConfigNode::Object(
                [(
                    "settings".to_string(),
                    rc::ConfigNode::ConfigRef("settings".to_string()),
                )]
                .into_iter()
                .collect(),
            )),
            Some(json!({
                "type": "object",
                "properties": {
                    "settings": {
                        "type": "object",
                        "properties": {
                            "mode": { "type": "string", "default": "enabled" }
                        }
                    }
                }
            })),
            Some(json!({
                "type": "object",
                "properties": {
                    "settings": {
                        "type": ["object", "string"],
                        "properties": {
                            "mode": { "type": "string" }
                        }
                    }
                }
            })),
        )
        .expect("analysis");

        assert_eq!(
            component.resolve_presence("settings.mode").unwrap(),
            ConfigPresence::Runtime
        );
    }

    #[test]
    fn resolve_presence_uses_component_defaults_for_forwarded_leaf_queries() {
        let component = ComponentConfigAnalysis::standalone(
            Some(rc::ConfigNode::Object(
                [(
                    "child_enabled".to_string(),
                    rc::ConfigNode::ConfigRef("root_enabled".to_string()),
                )]
                .into_iter()
                .collect(),
            )),
            Some(json!({
                "type": "object",
                "properties": {
                    "child_enabled": { "type": "string", "default": "enabled" }
                }
            })),
            Some(json!({
                "type": "object",
                "properties": {
                    "root_enabled": { "type": "string" }
                }
            })),
        )
        .expect("analysis");

        assert_eq!(
            component.resolve_presence("child_enabled").unwrap(),
            ConfigPresence::Present
        );
    }

    #[test]
    fn resolve_each_values_uses_component_default_array_for_omitted_queries() {
        let component = ComponentConfigAnalysis::standalone(
            Some(rc::ConfigNode::empty_object()),
            Some(json!({
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "items": { "type": "string" },
                        "default": ["alpha", "beta"]
                    }
                }
            })),
            None,
        )
        .expect("analysis");

        assert_eq!(
            component
                .resolve_each_values("items", "program.args[0]")
                .unwrap(),
            ConfigEachResolution::Static(vec![json!("alpha"), json!("beta")])
        );
    }

    #[test]
    fn resolve_each_values_rejects_non_array_component_defaults() {
        let component = ComponentConfigAnalysis::standalone(
            Some(rc::ConfigNode::empty_object()),
            Some(json!({
                "type": "object",
                "properties": {
                    "items": {
                        "type": "string",
                        "default": "not-an-array"
                    }
                }
            })),
            None,
        )
        .expect("analysis");

        let err = component
            .resolve_each_values("items", "program.args[0]")
            .expect_err("non-array defaults must fail");
        assert!(err.contains("instead of an array"), "{err}");
        assert!(err.contains("string"), "{err}");
    }

    #[test]
    fn resolve_each_values_uses_component_defaults_for_forwarded_absent_paths() {
        let component = ComponentConfigAnalysis::standalone(
            Some(rc::ConfigNode::Object(
                [(
                    "items".to_string(),
                    rc::ConfigNode::ConfigRef("root_items".to_string()),
                )]
                .into_iter()
                .collect(),
            )),
            Some(json!({
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "items": { "type": "string" },
                        "default": ["alpha", "beta"]
                    }
                }
            })),
            Some(json!({
                "type": "object",
                "properties": {}
            })),
        )
        .expect("analysis");

        assert_eq!(
            component
                .resolve_each_values("items", "program.args[0]")
                .unwrap(),
            ConfigEachResolution::Static(vec![json!("alpha"), json!("beta")])
        );
    }

    #[test]
    fn resolve_each_values_treats_forwarded_absent_paths_without_defaults_as_empty() {
        let component = ComponentConfigAnalysis::standalone(
            Some(rc::ConfigNode::Object(
                [(
                    "items".to_string(),
                    rc::ConfigNode::ConfigRef("root_items".to_string()),
                )]
                .into_iter()
                .collect(),
            )),
            Some(json!({
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "items": { "type": "string" }
                    }
                }
            })),
            Some(json!({
                "type": "object",
                "properties": {}
            })),
        )
        .expect("analysis");

        assert_eq!(
            component
                .resolve_each_values("items", "program.args[0]")
                .unwrap(),
            ConfigEachResolution::Static(Vec::new())
        );
    }

    #[test]
    fn resolve_each_values_keeps_forwarded_defaults_runtime_when_root_can_supply_values() {
        let component = ComponentConfigAnalysis::standalone(
            Some(rc::ConfigNode::Object(
                [(
                    "items".to_string(),
                    rc::ConfigNode::ConfigRef("root_items".to_string()),
                )]
                .into_iter()
                .collect(),
            )),
            Some(json!({
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "items": { "type": "string" },
                        "default": ["alpha", "beta"]
                    }
                }
            })),
            Some(json!({
                "type": "object",
                "properties": {
                    "root_items": {
                        "type": "array",
                        "items": { "type": "string" }
                    }
                }
            })),
        )
        .expect("analysis");

        assert_eq!(
            component
                .resolve_each_values("items", "program.args[0]")
                .unwrap(),
            ConfigEachResolution::Runtime
        );
    }
}
