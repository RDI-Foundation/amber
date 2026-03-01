use std::collections::HashMap;

use amber_config as rc;
use amber_scenario::{Component, ComponentId};
use serde_json::Value;

use crate::config_template;

#[derive(Clone, Debug)]
pub struct TemplateError {
    pub component: ComponentId,
    pub message: String,
}

#[derive(Debug)]
pub struct ComposedTemplates {
    pub templates: HashMap<ComponentId, rc::RootConfigTemplate>,
    pub errors: Vec<TemplateError>,
}

pub fn compose_root_config_templates(
    root: ComponentId,
    components: &[Option<Component>],
) -> ComposedTemplates {
    let root_schema = components[root.0]
        .as_ref()
        .and_then(|component| component.config_schema.as_ref());

    let root_template = if root_schema.is_some() {
        rc::RootConfigTemplate::Root
    } else {
        rc::RootConfigTemplate::Node(rc::ConfigNode::empty_object())
    };

    let mut templates: HashMap<ComponentId, rc::RootConfigTemplate> = HashMap::new();
    let mut errors = Vec::new();

    #[allow(clippy::too_many_arguments)]
    fn compose_templates_dfs(
        root: ComponentId,
        components: &[Option<Component>],
        id: ComponentId,
        parent_schema: Option<&Value>,
        parent_template: &rc::RootConfigTemplate,
        binding_scope: ComponentId,
        templates: &mut HashMap<ComponentId, rc::RootConfigTemplate>,
        errors: &mut Vec<TemplateError>,
    ) {
        let c = components[id.0].as_ref().expect("component should exist");
        let schema = c.config_schema.as_ref();

        let this_template = if id == root {
            if schema.is_some() {
                rc::RootConfigTemplate::Root
            } else {
                rc::RootConfigTemplate::Node(rc::ConfigNode::empty_object())
            }
        } else if schema.is_none() {
            rc::RootConfigTemplate::Node(rc::ConfigNode::empty_object())
        } else {
            let initial = match config_template::parse_instance_config_template(
                c.config.as_ref(),
                parent_schema,
                binding_scope.0 as u64,
            ) {
                Ok(t) => t,
                Err(err) => {
                    errors.push(TemplateError {
                        component: id,
                        message: err.to_string(),
                    });
                    rc::ConfigNode::empty_object()
                }
            };

            let composed = match rc::compose_config_template(initial, parent_template) {
                Ok(t) => t.simplify(),
                Err(err) => {
                    errors.push(TemplateError {
                        component: id,
                        message: err.to_string(),
                    });
                    rc::ConfigNode::empty_object()
                }
            };

            if !composed.is_object() {
                errors.push(TemplateError {
                    component: id,
                    message: "component config must be an object (non-object config templates are \
                              unsupported)"
                        .to_string(),
                });
                rc::RootConfigTemplate::Node(rc::ConfigNode::empty_object())
            } else {
                rc::RootConfigTemplate::Node(composed)
            }
        };

        templates.insert(id, this_template.clone());

        for &child in &c.children {
            compose_templates_dfs(
                root,
                components,
                child,
                schema,
                &this_template,
                id,
                templates,
                errors,
            );
        }
    }

    compose_templates_dfs(
        root,
        components,
        root,
        root_schema,
        &root_template,
        root,
        &mut templates,
        &mut errors,
    );

    ComposedTemplates { templates, errors }
}
