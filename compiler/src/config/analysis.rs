use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};

use amber_config as rc;
use amber_manifest::InterpolatedString;
use amber_scenario::{Component, ComponentId, Scenario};
use serde_json::Value;

use super::{
    query::{
        ConfigEachResolution, ConfigPresence, QueryResolution, render_static_config_string,
        resolve_config_each_values, resolve_config_presence_with_root_schema,
        resolve_config_query_node, validate_config_query_syntax,
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
                ComponentConfigAnalysis {
                    template,
                    component_schema,
                    root_schema: root_schema.clone(),
                    root_leaves: root_leaves.clone(),
                },
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
}

impl ComponentConfigAnalysis {
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
        Ok(Self {
            template,
            component_schema,
            root_schema,
            root_leaves,
        })
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
        resolve_config_presence_with_root_schema(self.template_node(), self.root_schema(), query)
    }

    pub(crate) fn resolve_each_values(
        &self,
        query: &str,
        location: &str,
    ) -> Result<ConfigEachResolution, String> {
        resolve_config_each_values(self.template_node(), query, location)
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
}
