use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};

use amber_config as rc;
use amber_manifest::{InterpolatedPart, InterpolatedString, InterpolationSource};
use amber_scenario::{Component, ComponentId, Scenario};
use serde_json::{Map, Value};

use super::{
    query::{
        ConfigEachResolution, ConfigPresence, parse_query_segments, validate_config_query_syntax,
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
        let root_omission_config =
            omission_config_for_schema(root_schema.as_deref())?.map(Arc::new);
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
                    root_omission_config.clone(),
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
    root_omission_config: Option<Arc<Value>>,
    root_leaves: Arc<[rc::SchemaLeaf]>,
    omission_defaults: Option<Value>,
}

impl ComponentConfigAnalysis {
    fn new(
        template: rc::RootConfigTemplate,
        component_schema: Option<Value>,
        root_schema: Option<Arc<Value>>,
        root_omission_config: Option<Arc<Value>>,
        root_leaves: Arc<[rc::SchemaLeaf]>,
    ) -> Result<Self, String> {
        let omission_defaults = omission_defaults_for_schema(component_schema.as_ref())?;
        Ok(Self {
            template,
            component_schema,
            root_schema,
            root_omission_config,
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
        let root_omission_config =
            omission_config_for_schema(root_schema.as_deref())?.map(Arc::new);
        let template = match template {
            Some(template) => rc::RootConfigTemplate::Node(template),
            None if root_schema.is_some() => rc::RootConfigTemplate::Root,
            None => rc::RootConfigTemplate::Node(rc::ConfigNode::empty_object()),
        };
        Self::new(
            template,
            component_schema,
            root_schema,
            root_omission_config,
            root_leaves,
        )
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

    pub(crate) fn resolve_presence(&self, query: &str) -> Result<ConfigPresence, String> {
        match self.analyze_query(query)? {
            QuerySemantics::Known(outcomes) => Ok(outcomes.resolve_presence()),
            QuerySemantics::RuntimeUnknown => Ok(ConfigPresence::Runtime),
        }
    }

    pub(crate) fn resolve_static_value(&self, query: &str) -> Result<Option<Value>, String> {
        match self.analyze_query(query)? {
            QuerySemantics::Known(outcomes) => Ok(outcomes.resolve_static_value()),
            QuerySemantics::RuntimeUnknown => Ok(None),
        }
    }

    pub(crate) fn resolve_static_string_query(
        &self,
        query: &str,
    ) -> Result<Option<String>, String> {
        self.resolve_static_value(query)?
            .map(|value| rc::stringify_for_interpolation(&value).map_err(|err| err.to_string()))
            .transpose()
    }

    fn analyze_query(&self, query: &str) -> Result<QuerySemantics, String> {
        validate_config_query_syntax(query)?;

        let Some(template) = self.template_node() else {
            return self.root_query_semantics(query);
        };

        match resolve_query_resolution(template, query)? {
            DetailedQueryResolution::Missing => {
                Ok(QuerySemantics::Known(self.omission_outcomes(query)?))
            }
            DetailedQueryResolution::Node(node) => {
                if node.contains_runtime() {
                    return Ok(QuerySemantics::RuntimeUnknown);
                }
                let value = node.evaluate_static().map_err(|err| err.to_string())?;
                Ok(QuerySemantics::Known(QueryOutcomeSet::from_static_value(
                    value,
                )))
            }
            DetailedQueryResolution::RuntimeRef { root_path, suffix } => Ok(QuerySemantics::Known(
                self.forwarded_runtime_outcomes(query, &root_path, &suffix)?,
            )),
        }
    }

    pub(crate) fn resolve_each_values(
        &self,
        query: &str,
        location: &str,
    ) -> Result<ConfigEachResolution, String> {
        match self.analyze_query(query)? {
            QuerySemantics::Known(outcomes) => outcomes.resolve_each_values(query, location),
            QuerySemantics::RuntimeUnknown => Ok(ConfigEachResolution::Runtime),
        }
    }

    pub(crate) fn render_static_string(
        &self,
        value: &InterpolatedString,
    ) -> Result<String, String> {
        let mut rendered = String::new();
        for part in &value.parts {
            match part {
                InterpolatedPart::Literal(lit) => rendered.push_str(lit),
                InterpolatedPart::Interpolation { source, query } => match source {
                    InterpolationSource::Config => {
                        let Some(value) = self.resolve_static_string_query(query)? else {
                            let path = if query.is_empty() {
                                "config".to_string()
                            } else {
                                format!("config.{query}")
                            };
                            return Err(format!(
                                "{path} depends on runtime root config, which is not available at \
                                 compile time"
                            ));
                        };
                        rendered.push_str(&value);
                    }
                    InterpolationSource::Slots => {
                        return Err(
                            "slot interpolation is not allowed in resource params".to_string()
                        );
                    }
                    other => {
                        return Err(format!(
                            "unsupported interpolation source {other} in resource params"
                        ));
                    }
                },
                _ => return Err("unsupported interpolation syntax in resource params".to_string()),
            }
        }

        Ok(rendered)
    }

    pub(crate) fn resolve_runtime_value_source<'a>(
        &'a self,
        query: &str,
    ) -> Result<RuntimeValueSource<'a>, String> {
        if let Some(value) = self.resolve_static_value(query)? {
            return Ok(RuntimeValueSource::Static(value));
        }

        let Some(template) = self.template_node() else {
            validate_config_query_syntax(query)?;
            return Ok(RuntimeValueSource::RuntimeRootPath(query.to_string()));
        };

        match resolve_query_resolution(template, query)? {
            DetailedQueryResolution::Missing => Err(format!(
                "config.{query} is not defined in this component config"
            )),
            DetailedQueryResolution::Node(node) => {
                if node.contains_runtime() {
                    Ok(RuntimeValueSource::RuntimeNode(node))
                } else {
                    Err(format!(
                        "config.{query} is not defined in this component config"
                    ))
                }
            }
            DetailedQueryResolution::RuntimeRef { root_path, suffix } => Ok(
                RuntimeValueSource::RuntimeRootPath(join_query_path(&root_path, &suffix)),
            ),
        }
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

    fn omission_value(&self, query: &str) -> Result<Option<&Value>, String> {
        let Some(defaults) = &self.omission_defaults else {
            return Ok(None);
        };
        rc::get_by_path_opt(defaults, query).map_err(|err| err.to_string())
    }

    fn omission_outcomes(&self, query: &str) -> Result<QueryOutcomeSet, String> {
        Ok(QueryOutcomeSet::from_omission_value(
            self.omission_value(query)?.cloned(),
        ))
    }

    fn root_query_semantics(&self, query: &str) -> Result<QuerySemantics, String> {
        let Some(_) = self.root_schema() else {
            return Ok(QuerySemantics::RuntimeUnknown);
        };
        Ok(QuerySemantics::Known(
            self.root_resolution_possibilities("", &parse_query_segments(query)?)?
                .into_root_outcomes(),
        ))
    }

    fn forwarded_runtime_outcomes(
        &self,
        query: &str,
        root_path: &str,
        suffix: &str,
    ) -> Result<QueryOutcomeSet, String> {
        let suffix_segments = parse_query_segments(suffix)?;
        let possibilities = self.root_resolution_possibilities(root_path, &suffix_segments)?;
        let mut outcomes = QueryOutcomeSet::default();
        if possibilities.omitted_path {
            outcomes.extend(self.omission_outcomes(query)?);
        }
        if possibilities.blocked {
            outcomes.push_missing();
        }
        if possibilities.null {
            outcomes.push_null();
        }
        if possibilities.non_null {
            outcomes.push_dynamic_non_null();
        }
        Ok(outcomes)
    }

    fn root_resolution_possibilities(
        &self,
        prefix: &str,
        suffix: &[&str],
    ) -> Result<RootPathResolutionPossibilities, String> {
        let exact = self.exact_root_value_possibilities(prefix)?;
        if suffix.is_empty() {
            return Ok(RootPathResolutionPossibilities {
                omitted_path: exact.can_be_missing,
                blocked: false,
                null: exact.can_be_null,
                non_null: exact.can_be_object || exact.can_be_other_non_null,
            });
        }

        let mut out = RootPathResolutionPossibilities::default();
        if exact.can_be_missing {
            out.omitted_path = true;
        }
        if exact.can_be_null || exact.can_be_other_non_null {
            out.blocked = true;
        }
        if exact.can_be_object {
            let next_prefix = if prefix.is_empty() {
                suffix[0].to_string()
            } else {
                format!("{prefix}.{}", suffix[0])
            };
            out.extend(self.root_resolution_possibilities(&next_prefix, &suffix[1..])?);
        }
        Ok(out)
    }

    fn exact_root_value_possibilities(
        &self,
        full_path: &str,
    ) -> Result<ExactRootValuePossibilities, String> {
        let Some(root_schema) = self.root_schema() else {
            return Ok(ExactRootValuePossibilities {
                can_be_missing: true,
                can_be_null: true,
                can_be_object: true,
                can_be_other_non_null: true,
            });
        };

        if full_path.is_empty() {
            return Ok(ExactRootValuePossibilities {
                can_be_missing: false,
                can_be_null: false,
                can_be_object: true,
                can_be_other_non_null: false,
            });
        }

        match rc::schema_lookup(root_schema, full_path) {
            Err(_) => {
                return Ok(ExactRootValuePossibilities {
                    can_be_missing: true,
                    can_be_null: false,
                    can_be_object: false,
                    can_be_other_non_null: false,
                });
            }
            Ok(rc::SchemaLookup::Unknown) => {
                return Ok(ExactRootValuePossibilities {
                    can_be_missing: true,
                    can_be_null: true,
                    can_be_object: true,
                    can_be_other_non_null: true,
                });
            }
            Ok(rc::SchemaLookup::Found) => {}
        }

        let can_be_null =
            rc::schema_path_accepts_null(root_schema, full_path).map_err(|err| err.to_string())?;
        let can_be_object =
            rc::schema_path_may_be_object(root_schema, full_path).map_err(|err| err.to_string())?;
        let can_be_other_non_null = rc::schema_path_may_be_other_non_null(root_schema, full_path)
            .map_err(|err| err.to_string())?;
        let can_be_missing = self.root_omission_value(full_path)?.is_none()
            && !rc::schema_path_is_required(root_schema, full_path)
                .map_err(|err| err.to_string())?;

        Ok(ExactRootValuePossibilities {
            can_be_missing,
            can_be_null,
            can_be_object,
            can_be_other_non_null,
        })
    }

    fn root_omission_value(&self, query: &str) -> Result<Option<&Value>, String> {
        let Some(defaults) = &self.root_omission_config else {
            return Ok(None);
        };
        rc::get_by_path_opt(defaults, query).map_err(|err| err.to_string())
    }
}

pub(crate) enum RuntimeValueSource<'a> {
    Static(Value),
    RuntimeRootPath(String),
    RuntimeNode(&'a rc::ConfigNode),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum QuerySemantics {
    Known(QueryOutcomeSet),
    RuntimeUnknown,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct QueryOutcomeSet {
    can_be_missing: bool,
    can_be_null: bool,
    can_be_dynamic_non_null: bool,
    static_non_null_values: Vec<Value>,
}

impl QueryOutcomeSet {
    fn from_static_value(value: Value) -> Self {
        let mut outcomes = Self::default();
        outcomes.push_static(value);
        outcomes
    }

    fn from_omission_value(value: Option<Value>) -> Self {
        let mut outcomes = Self::default();
        match value {
            Some(value) => outcomes.push_static(value),
            None => outcomes.push_missing(),
        }
        outcomes
    }

    fn push_missing(&mut self) {
        self.can_be_missing = true;
    }

    fn push_null(&mut self) {
        self.can_be_null = true;
    }

    fn push_dynamic_non_null(&mut self) {
        self.can_be_dynamic_non_null = true;
    }

    fn push_static(&mut self, value: Value) {
        if value.is_null() {
            self.push_null();
            return;
        }
        if !self
            .static_non_null_values
            .iter()
            .any(|existing| existing == &value)
        {
            self.static_non_null_values.push(value);
        }
    }

    fn extend(&mut self, other: Self) {
        self.can_be_missing |= other.can_be_missing;
        self.can_be_null |= other.can_be_null;
        self.can_be_dynamic_non_null |= other.can_be_dynamic_non_null;
        for value in other.static_non_null_values {
            self.push_static(value);
        }
    }

    fn resolve_presence(&self) -> ConfigPresence {
        let can_be_truthy = self.can_be_dynamic_non_null || !self.static_non_null_values.is_empty();
        let can_be_falsy = self.can_be_missing || self.can_be_null;
        match (can_be_truthy, can_be_falsy) {
            (true, false) => ConfigPresence::Present,
            (false, true) => ConfigPresence::Absent,
            (true, true) => ConfigPresence::Runtime,
            (false, false) => ConfigPresence::Absent,
        }
    }

    fn resolve_each_values(
        &self,
        query: &str,
        location: &str,
    ) -> Result<ConfigEachResolution, String> {
        if self.can_be_dynamic_non_null {
            return Ok(ConfigEachResolution::Runtime);
        }

        let mut resolved_items: Option<Vec<Value>> =
            (self.can_be_missing || self.can_be_null).then(Vec::new);

        for value in &self.static_non_null_values {
            let items = match value {
                Value::Array(items) => items.clone(),
                other => {
                    return Err(format!(
                        "{location} uses `each: \"config.{query}\"`, but config.{query} resolves \
                         to {} instead of an array",
                        value_kind(other)
                    ));
                }
            };

            match &resolved_items {
                Some(existing) if *existing != items => return Ok(ConfigEachResolution::Runtime),
                Some(_) => {}
                None => resolved_items = Some(items),
            }
        }

        Ok(ConfigEachResolution::Static(
            resolved_items.unwrap_or_default(),
        ))
    }

    fn resolve_static_value(&self) -> Option<Value> {
        if self.can_be_missing || self.can_be_dynamic_non_null {
            return None;
        }

        match (self.can_be_null, self.static_non_null_values.as_slice()) {
            (true, []) => Some(Value::Null),
            (false, [value]) => Some(value.clone()),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ExactRootValuePossibilities {
    can_be_missing: bool,
    can_be_null: bool,
    can_be_object: bool,
    can_be_other_non_null: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RootPathResolutionPossibilities {
    omitted_path: bool,
    blocked: bool,
    null: bool,
    non_null: bool,
}

impl RootPathResolutionPossibilities {
    fn extend(&mut self, other: Self) {
        self.omitted_path |= other.omitted_path;
        self.blocked |= other.blocked;
        self.null |= other.null;
        self.non_null |= other.non_null;
    }

    fn into_root_outcomes(self) -> QueryOutcomeSet {
        let mut outcomes = QueryOutcomeSet::default();
        if self.omitted_path || self.blocked {
            outcomes.push_missing();
        }
        if self.null {
            outcomes.push_null();
        }
        if self.non_null {
            outcomes.push_dynamic_non_null();
        }
        outcomes
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

fn omission_config_for_schema(schema: Option<&Value>) -> Result<Option<Value>, String> {
    let Some(schema) = schema else {
        return Ok(None);
    };
    let mut defaults = Value::Object(Map::new());
    rc::apply_schema_defaults(schema, &mut defaults).map_err(|err| err.to_string())?;
    Ok(Some(defaults))
}

enum DetailedQueryResolution<'a> {
    Missing,
    Node(&'a rc::ConfigNode),
    RuntimeRef { root_path: String, suffix: String },
}

fn join_query_path(prefix: &str, suffix: &str) -> String {
    match (prefix.is_empty(), suffix.is_empty()) {
        (true, true) => String::new(),
        (true, false) => suffix.to_string(),
        (false, true) => prefix.to_string(),
        (false, false) => format!("{prefix}.{suffix}"),
    }
}

fn resolve_query_resolution<'a>(
    template: &'a rc::ConfigNode,
    query: &str,
) -> Result<DetailedQueryResolution<'a>, String> {
    if query.is_empty() {
        return Ok(match template {
            rc::ConfigNode::ConfigRef(path) => DetailedQueryResolution::RuntimeRef {
                root_path: path.clone(),
                suffix: String::new(),
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
                return Ok(DetailedQueryResolution::RuntimeRef {
                    root_path: path.clone(),
                    suffix,
                });
            }
            _ => return Ok(DetailedQueryResolution::Missing),
        }
    }

    Ok(match current {
        rc::ConfigNode::ConfigRef(path) => DetailedQueryResolution::RuntimeRef {
            root_path: path.clone(),
            suffix: String::new(),
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

    #[test]
    fn resolve_presence_tracks_forwarded_leaf_default_matrix() {
        let component_template = Some(rc::ConfigNode::Object(
            [(
                "child_enabled".to_string(),
                rc::ConfigNode::ConfigRef("root_enabled".to_string()),
            )]
            .into_iter()
            .collect(),
        ));
        let component_schema = Some(json!({
            "type": "object",
            "properties": {
                "child_enabled": { "type": "string", "default": "enabled" }
            }
        }));

        let cases = [
            (
                "schema-absent root path uses component default",
                json!({
                    "type": "object",
                    "properties": {}
                }),
                ConfigPresence::Present,
            ),
            (
                "non-null runtime leaf remains compile-time present",
                json!({
                    "type": "object",
                    "properties": {
                        "root_enabled": { "type": "string" }
                    }
                }),
                ConfigPresence::Present,
            ),
            (
                "nullable runtime leaf stays runtime",
                json!({
                    "type": "object",
                    "properties": {
                        "root_enabled": { "type": ["string", "null"] }
                    }
                }),
                ConfigPresence::Runtime,
            ),
            (
                "null-only runtime leaf stays runtime",
                json!({
                    "type": "object",
                    "properties": {
                        "root_enabled": { "type": "null" }
                    }
                }),
                ConfigPresence::Runtime,
            ),
        ];

        for (label, root_schema, expected) in cases {
            let component = ComponentConfigAnalysis::standalone(
                component_template.clone(),
                component_schema.clone(),
                Some(root_schema),
            )
            .unwrap_or_else(|err| panic!("{label}: {err}"));

            assert_eq!(
                component.resolve_presence("child_enabled").unwrap(),
                expected,
                "{label}"
            );
        }
    }

    #[test]
    fn resolve_each_values_tracks_forwarded_array_default_matrix() {
        let component_template = Some(rc::ConfigNode::Object(
            [(
                "items".to_string(),
                rc::ConfigNode::ConfigRef("root_items".to_string()),
            )]
            .into_iter()
            .collect(),
        ));
        let component_schema = Some(json!({
            "type": "object",
            "properties": {
                "items": {
                    "type": ["array", "null"],
                    "items": { "type": "string" },
                    "default": ["alpha", "beta"]
                }
            }
        }));

        let cases = [
            (
                "schema-absent root path folds to component default items",
                json!({
                    "type": "object",
                    "properties": {}
                }),
                ConfigEachResolution::Static(vec![json!("alpha"), json!("beta")]),
            ),
            (
                "non-null runtime array stays runtime",
                json!({
                    "type": "object",
                    "properties": {
                        "root_items": {
                            "type": "array",
                            "items": { "type": "string" }
                        }
                    }
                }),
                ConfigEachResolution::Runtime,
            ),
            (
                "nullable runtime array stays runtime",
                json!({
                    "type": "object",
                    "properties": {
                        "root_items": {
                            "type": ["array", "null"],
                            "items": { "type": "string" }
                        }
                    }
                }),
                ConfigEachResolution::Runtime,
            ),
            (
                "null-only runtime leaf stays runtime because explicit null suppresses defaults",
                json!({
                    "type": "object",
                    "properties": {
                        "root_items": { "type": "null" }
                    }
                }),
                ConfigEachResolution::Runtime,
            ),
        ];

        for (label, root_schema, expected) in cases {
            let component = ComponentConfigAnalysis::standalone(
                component_template.clone(),
                component_schema.clone(),
                Some(root_schema),
            )
            .unwrap_or_else(|err| panic!("{label}: {err}"));

            assert_eq!(
                component
                    .resolve_each_values("items", "program.args[0]")
                    .unwrap(),
                expected,
                "{label}"
            );
        }
    }
}
