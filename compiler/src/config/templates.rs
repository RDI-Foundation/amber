use std::collections::HashMap;

use amber_config as rc;
use amber_scenario::{Component, ComponentId};
use serde_json::Value;

use super::template;

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
            let initial =
                match template::parse_instance_config_template(c.config.as_ref(), parent_schema) {
                    Ok(t) => t,
                    Err(err) => {
                        errors.push(TemplateError {
                            component: id,
                            message: err.to_string(),
                        });
                        rc::ConfigNode::empty_object()
                    }
                };

            let mut composed = match rc::compose_config_template(initial, parent_template) {
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
                if let Some(schema) = schema
                    && let Err(err) = rc::apply_schema_defaults_to_node(schema, &mut composed)
                {
                    errors.push(TemplateError {
                        component: id,
                        message: err.to_string(),
                    });
                }
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
        &mut templates,
        &mut errors,
    );

    ComposedTemplates { templates, errors }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use amber_manifest::ManifestDigest;
    use amber_scenario::Moniker;
    use amber_template::RuntimeTemplateContext;
    use serde_json::{Value, json};

    use super::*;

    fn component(
        id: usize,
        parent: Option<usize>,
        moniker: &str,
        config_schema: Option<Value>,
        config: Option<Value>,
        children: Vec<usize>,
    ) -> Component {
        Component {
            id: ComponentId(id),
            parent: parent.map(ComponentId),
            moniker: Moniker::from(Arc::<str>::from(moniker)),
            digest: ManifestDigest::new([id as u8; 32]),
            config,
            config_schema,
            program: None,
            slots: BTreeMap::new(),
            provides: BTreeMap::new(),
            resources: BTreeMap::new(),
            metadata: None,
            child_templates: BTreeMap::new(),
            children: children.into_iter().map(ComponentId).collect(),
        }
    }

    fn resolve_component_config(
        root_schema: &Value,
        component_schema: &Value,
        template: &rc::RootConfigTemplate,
        config_env: &BTreeMap<String, String>,
    ) -> Value {
        rc::resolve_runtime_component_config(
            root_schema,
            component_schema,
            &template.to_template_payload(),
            config_env,
            &RuntimeTemplateContext::default(),
        )
        .expect("resolved component config")
    }

    fn root_schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "exported": {
                    "type": "string",
                    "default": "root-default"
                }
            }
        })
    }

    fn intermediate_schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "forwarded": {
                    "type": "string",
                    "default": "intermediate-default"
                },
                "settings": {
                    "type": "object",
                    "properties": {
                        "explicit": { "type": "string" },
                        "from_root": {
                            "type": "string",
                            "default": "intermediate-object-default"
                        }
                    }
                }
            }
        })
    }

    fn child_schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "final_value": {
                    "type": "string",
                    "default": "child-default"
                },
                "forwarded": { "type": "string" },
                "settings": {
                    "type": "object",
                    "properties": {
                        "explicit": { "type": "string" },
                        "inherited": { "type": "string" },
                        "child_default": {
                            "type": "string",
                            "default": "child-object-default"
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn compose_root_config_templates_apply_defaults_across_layers() {
        let root_schema = root_schema();
        let intermediate_schema = intermediate_schema();
        let child_schema = child_schema();

        let components = vec![
            Some(component(
                0,
                None,
                "/",
                Some(root_schema.clone()),
                None,
                vec![1],
            )),
            Some(component(
                1,
                Some(0),
                "/intermediate",
                Some(intermediate_schema.clone()),
                Some(json!({
                    "forwarded": "${config.exported}",
                    "settings": {
                        "explicit": "intermediate-explicit"
                    }
                })),
                vec![2],
            )),
            Some(component(
                2,
                Some(1),
                "/child",
                Some(child_schema.clone()),
                Some(json!({
                    "forwarded": "${config.forwarded}",
                    "settings": {
                        "explicit": "child-explicit",
                        "inherited": "${config.settings.from_root}"
                    }
                })),
                vec![],
            )),
        ];

        let composed = compose_root_config_templates(ComponentId(0), &components);
        assert!(composed.errors.is_empty(), "{:?}", composed.errors);

        let empty_env = BTreeMap::new();
        let intermediate = resolve_component_config(
            &root_schema,
            &intermediate_schema,
            composed.templates.get(&ComponentId(1)).expect("template"),
            &empty_env,
        );
        assert_eq!(
            intermediate,
            json!({
                "forwarded": "root-default",
                "settings": {
                    "explicit": "intermediate-explicit",
                    "from_root": "intermediate-object-default"
                }
            })
        );

        let child = resolve_component_config(
            &root_schema,
            &child_schema,
            composed.templates.get(&ComponentId(2)).expect("template"),
            &empty_env,
        );
        assert_eq!(
            child,
            json!({
                "final_value": "child-default",
                "forwarded": "root-default",
                "settings": {
                    "explicit": "child-explicit",
                    "inherited": "intermediate-object-default",
                    "child_default": "child-object-default"
                }
            })
        );
    }

    #[test]
    fn compose_root_config_templates_respect_root_env_override() {
        let root_schema = root_schema();
        let intermediate_schema = intermediate_schema();

        let components = vec![
            Some(component(
                0,
                None,
                "/",
                Some(root_schema.clone()),
                None,
                vec![1],
            )),
            Some(component(
                1,
                Some(0),
                "/intermediate",
                Some(intermediate_schema.clone()),
                Some(json!({
                    "forwarded": "${config.exported}"
                })),
                vec![],
            )),
        ];

        let composed = compose_root_config_templates(ComponentId(0), &components);
        assert!(composed.errors.is_empty(), "{:?}", composed.errors);

        let config_env = BTreeMap::from([(
            "AMBER_CONFIG_EXPORTED".to_string(),
            "root-override".to_string(),
        )]);
        let intermediate = resolve_component_config(
            &root_schema,
            &intermediate_schema,
            composed.templates.get(&ComponentId(1)).expect("template"),
            &config_env,
        );
        assert_eq!(
            intermediate,
            json!({
                "forwarded": "root-override",
                "settings": {
                    "from_root": "intermediate-object-default"
                }
            })
        );
    }

    #[test]
    fn compose_root_config_templates_respect_intermediate_and_child_explicit_overrides() {
        let root_schema = root_schema();
        let intermediate_schema = intermediate_schema();
        let child_schema = child_schema();

        let components = vec![
            Some(component(
                0,
                None,
                "/",
                Some(root_schema.clone()),
                None,
                vec![1],
            )),
            Some(component(
                1,
                Some(0),
                "/intermediate",
                Some(intermediate_schema.clone()),
                Some(json!({
                    "forwarded": "intermediate-explicit"
                })),
                vec![2],
            )),
            Some(component(
                2,
                Some(1),
                "/child",
                Some(child_schema.clone()),
                Some(json!({
                    "final_value": "child-explicit",
                    "forwarded": "${config.forwarded}"
                })),
                vec![],
            )),
        ];

        let composed = compose_root_config_templates(ComponentId(0), &components);
        assert!(composed.errors.is_empty(), "{:?}", composed.errors);

        let config_env = BTreeMap::from([(
            "AMBER_CONFIG_EXPORTED".to_string(),
            "root-override".to_string(),
        )]);
        let intermediate = resolve_component_config(
            &root_schema,
            &intermediate_schema,
            composed.templates.get(&ComponentId(1)).expect("template"),
            &config_env,
        );
        assert_eq!(
            intermediate,
            json!({
                "forwarded": "intermediate-explicit",
                "settings": {
                    "from_root": "intermediate-object-default"
                }
            })
        );

        let child = resolve_component_config(
            &root_schema,
            &child_schema,
            composed.templates.get(&ComponentId(2)).expect("template"),
            &config_env,
        );
        assert_eq!(
            child,
            json!({
                "final_value": "child-explicit",
                "forwarded": "intermediate-explicit",
                "settings": {
                    "child_default": "child-object-default"
                }
            })
        );
    }
}
