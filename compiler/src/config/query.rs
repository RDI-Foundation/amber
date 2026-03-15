use amber_config as rc;
use amber_manifest::{InterpolatedPart, InterpolatedString, InterpolationSource};
use serde_json::Value;

pub(crate) enum QueryResolution<'a> {
    Node(&'a rc::ConfigNode),
    RuntimePath(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConfigPresence {
    Present,
    Absent,
    Runtime,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ConfigEachResolution {
    Static(Vec<Value>),
    Runtime,
}

pub(crate) fn validate_config_query_syntax(query: &str) -> Result<(), String> {
    if query.is_empty() {
        return Ok(());
    }

    for seg in query.split('.') {
        if seg.is_empty() {
            return Err(format!("invalid config path {query:?}: empty segment"));
        }
    }

    Ok(())
}

pub(crate) fn parse_query_segments(query: &str) -> Result<Vec<&str>, String> {
    validate_config_query_syntax(query)?;
    if query.is_empty() {
        Ok(Vec::new())
    } else {
        Ok(query.split('.').collect())
    }
}

pub(crate) fn resolve_config_query_node<'a>(
    template: &'a rc::ConfigNode,
    query: &str,
) -> Result<QueryResolution<'a>, String> {
    if query.is_empty() {
        return Ok(QueryResolution::Node(template));
    }

    let segments = parse_query_segments(query)?;

    let mut current = template;
    for (idx, seg) in segments.iter().enumerate() {
        match current {
            rc::ConfigNode::Object(map) => {
                let Some(next) = map.get(*seg) else {
                    return Err(format!("config.{query} not found (missing key {seg:?})"));
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
                return Err(format!(
                    "config.{query} not found (encountered non-object before segment {seg:?})"
                ));
            }
        }
    }

    Ok(QueryResolution::Node(current))
}

#[cfg(test)]
pub(crate) fn resolve_optional_config_query_node<'a>(
    template: &'a rc::ConfigNode,
    query: &str,
) -> Result<Option<QueryResolution<'a>>, String> {
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

#[cfg(test)]
pub(crate) fn resolve_config_presence(
    template: Option<&rc::ConfigNode>,
    query: &str,
) -> Result<ConfigPresence, String> {
    let Some(template) = template else {
        validate_config_query_syntax(query)?;
        return Ok(ConfigPresence::Runtime);
    };

    let Some(resolution) = resolve_optional_config_query_node(template, query)? else {
        return Ok(ConfigPresence::Absent);
    };

    match resolution {
        QueryResolution::RuntimePath(_) => Ok(ConfigPresence::Runtime),
        QueryResolution::Node(node) => {
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
    }
}

#[cfg(test)]
fn resolve_root_schema_presence(
    root_schema: &Value,
    query: &str,
) -> Result<ConfigPresence, String> {
    validate_config_query_syntax(query)?;
    rc::schema_path_presence(root_schema, query)
        .map(|presence| match presence {
            rc::SchemaPresence::Present => ConfigPresence::Present,
            rc::SchemaPresence::Absent => ConfigPresence::Absent,
            rc::SchemaPresence::Runtime => ConfigPresence::Runtime,
        })
        .map_err(|err| err.to_string())
}

#[cfg(test)]
pub(crate) fn resolve_config_presence_with_root_schema(
    template: Option<&rc::ConfigNode>,
    root_schema: Option<&Value>,
    query: &str,
) -> Result<ConfigPresence, String> {
    match template {
        Some(template) => {
            let Some(root_schema) = root_schema else {
                return resolve_config_presence(Some(template), query);
            };

            let Some(resolution) = resolve_optional_config_query_node(template, query)? else {
                return Ok(ConfigPresence::Absent);
            };

            match resolution {
                QueryResolution::RuntimePath(path) => {
                    resolve_root_schema_presence(root_schema, &path)
                }
                QueryResolution::Node(rc::ConfigNode::ConfigRef(path)) => {
                    resolve_root_schema_presence(root_schema, path)
                }
                QueryResolution::Node(node) => {
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
            }
        }
        None => match root_schema {
            Some(root_schema) => resolve_root_schema_presence(root_schema, query),
            None => resolve_config_presence(None, query),
        },
    }
}

pub(crate) fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

pub(crate) fn render_static_config_string(
    value: &InterpolatedString,
    template: Option<&rc::ConfigNode>,
) -> Result<String, String> {
    let mut rendered = String::new();
    for part in &value.parts {
        match part {
            InterpolatedPart::Literal(lit) => rendered.push_str(lit),
            InterpolatedPart::Interpolation { source, query } => match source {
                InterpolationSource::Config => {
                    let Some(template) = template else {
                        return Err("references runtime root config, which is not available at \
                                    compile time"
                            .to_string());
                    };
                    match resolve_config_query_node(template, query)? {
                        QueryResolution::Node(node) => {
                            if node.contains_runtime() {
                                let path = if query.is_empty() {
                                    "config".to_string()
                                } else {
                                    format!("config.{query}")
                                };
                                return Err(format!(
                                    "{path} depends on runtime root config, which is not \
                                     available at compile time"
                                ));
                            }
                            let value = node.evaluate_static().map_err(|err| err.to_string())?;
                            rendered.push_str(
                                &rc::stringify_for_interpolation(&value)
                                    .map_err(|err| err.to_string())?,
                            );
                        }
                        QueryResolution::RuntimePath(path) => {
                            let path = if path.is_empty() {
                                "config".to_string()
                            } else {
                                format!("config.{path}")
                            };
                            return Err(format!(
                                "{path} depends on runtime root config, which is not available at \
                                 compile time"
                            ));
                        }
                    }
                }
                InterpolationSource::Slots => {
                    return Err("slot interpolation is not allowed in resource params".to_string());
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use amber_manifest::InterpolatedString;

    use super::{
        ConfigPresence, parse_query_segments, render_static_config_string, resolve_config_presence,
        resolve_config_presence_with_root_schema, resolve_config_query_node,
        resolve_optional_config_query_node, validate_config_query_syntax,
    };

    #[test]
    fn validate_config_query_syntax_rejects_empty_segments() {
        let err = validate_config_query_syntax("a..b").expect_err("invalid query");
        assert!(err.contains("empty segment"));
    }

    #[test]
    fn resolve_config_query_node_tracks_runtime_suffixes() {
        let node = amber_config::ConfigNode::ConfigRef("storage".to_string());
        let resolved = resolve_config_query_node(&node, "size").expect("query should resolve");
        match resolved {
            super::QueryResolution::RuntimePath(path) => assert_eq!(path, "storage.size"),
            super::QueryResolution::Node(_) => panic!("expected runtime path"),
        }
    }

    #[test]
    fn parse_query_segments_preserves_order() {
        assert_eq!(
            parse_query_segments("storage.size").unwrap(),
            vec!["storage", "size"]
        );
    }

    #[test]
    fn resolve_optional_config_query_node_returns_none_for_missing_path() {
        let node = amber_config::ConfigNode::Object(BTreeMap::from([(
            "storage".to_string(),
            amber_config::ConfigNode::String("10Gi".to_string()),
        )]));
        assert!(
            resolve_optional_config_query_node(&node, "missing")
                .unwrap()
                .is_none(),
            "missing query should return None"
        );
    }

    #[test]
    fn resolve_config_presence_treats_missing_and_null_as_absent() {
        let node = amber_config::ConfigNode::Object(BTreeMap::from([
            ("missing".to_string(), amber_config::ConfigNode::Null),
            (
                "present".to_string(),
                amber_config::ConfigNode::String("x".to_string()),
            ),
        ]));
        assert_eq!(
            resolve_config_presence(Some(&node), "missing").unwrap(),
            ConfigPresence::Absent
        );
        assert_eq!(
            resolve_config_presence(Some(&node), "present").unwrap(),
            ConfigPresence::Present
        );
        assert_eq!(
            resolve_config_presence(Some(&node), "other").unwrap(),
            ConfigPresence::Absent
        );
    }

    #[test]
    fn resolve_config_presence_with_root_schema_uses_defaults_and_requiredness() {
        let root_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "defaulted": {
                    "type": "string",
                    "default": "x"
                },
                "required_string": {
                    "type": "string"
                },
                "optional": {
                    "type": "string"
                },
                "nullable_default": {
                    "type": ["string", "null"],
                    "default": "x"
                },
                "nested": {
                    "type": "object",
                    "properties": {
                        "child": {
                            "type": "string",
                            "default": "y"
                        }
                    }
                }
            },
            "required": ["required_string"]
        });

        assert_eq!(
            resolve_config_presence_with_root_schema(None, Some(&root_schema), "defaulted")
                .unwrap(),
            ConfigPresence::Present
        );
        assert_eq!(
            resolve_config_presence_with_root_schema(None, Some(&root_schema), "required_string")
                .unwrap(),
            ConfigPresence::Present
        );
        assert_eq!(
            resolve_config_presence_with_root_schema(None, Some(&root_schema), "optional").unwrap(),
            ConfigPresence::Runtime
        );
        assert_eq!(
            resolve_config_presence_with_root_schema(None, Some(&root_schema), "nullable_default")
                .unwrap(),
            ConfigPresence::Runtime
        );
        assert_eq!(
            resolve_config_presence_with_root_schema(None, Some(&root_schema), "nested").unwrap(),
            ConfigPresence::Present
        );
    }

    #[test]
    fn resolve_config_presence_with_root_schema_treats_defaulted_objects_as_present() {
        let root_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "settings": {
                    "type": "object",
                    "default": {},
                    "properties": {
                        "profile": { "type": "string" }
                    }
                }
            }
        });

        assert_eq!(
            resolve_config_presence_with_root_schema(None, Some(&root_schema), "settings").unwrap(),
            ConfigPresence::Present
        );
    }

    #[test]
    fn resolve_config_presence_with_root_schema_uses_component_defaults_behind_runtime_refs() {
        let template = amber_config::ConfigNode::Object(BTreeMap::from([(
            "settings".to_string(),
            amber_config::ConfigNode::ConfigRef("settings".to_string()),
        )]));
        let component_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "settings": {
                    "type": "object",
                    "properties": {
                        "mode": {
                            "type": "string",
                            "default": "safe"
                        }
                    }
                }
            }
        });

        assert_eq!(
            resolve_config_presence_with_root_schema(
                Some(&template),
                Some(&component_schema),
                "settings.mode"
            )
            .unwrap(),
            ConfigPresence::Present
        );
    }

    #[test]
    fn resolve_config_presence_with_root_schema_uses_config_ref_leaf_schema_presence() {
        let template = amber_config::ConfigNode::Object(BTreeMap::from([(
            "enabled".to_string(),
            amber_config::ConfigNode::ConfigRef("root_enabled".to_string()),
        )]));
        let root_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "root_enabled": {
                    "type": "boolean",
                    "default": false
                }
            }
        });

        assert_eq!(
            resolve_config_presence_with_root_schema(
                Some(&template),
                Some(&root_schema),
                "enabled"
            )
            .unwrap(),
            ConfigPresence::Present
        );
    }

    #[test]
    fn resolve_config_presence_with_root_schema_uses_resolved_runtime_paths() {
        let template = amber_config::ConfigNode::Object(BTreeMap::from([(
            "settings".to_string(),
            amber_config::ConfigNode::ConfigRef("root_settings".to_string()),
        )]));
        let root_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "root_settings": {
                    "type": "object",
                    "properties": {
                        "mode": {
                            "type": "string",
                            "default": "safe"
                        }
                    }
                }
            }
        });

        assert_eq!(
            resolve_config_presence_with_root_schema(
                Some(&template),
                Some(&root_schema),
                "settings.mode"
            )
            .unwrap(),
            ConfigPresence::Present
        );
    }

    #[test]
    fn render_static_config_string_resolves_static_component_config() {
        let template = amber_config::ConfigNode::Object(BTreeMap::from([(
            "storage_size".to_string(),
            amber_config::ConfigNode::String("10Gi".to_string()),
        )]));
        let value: InterpolatedString = "size=${config.storage_size}".parse().unwrap();
        assert_eq!(
            render_static_config_string(&value, Some(&template)).unwrap(),
            "size=10Gi"
        );
    }

    #[test]
    fn render_static_config_string_rejects_runtime_root_config() {
        let template = amber_config::ConfigNode::Object(BTreeMap::from([(
            "storage_size".to_string(),
            amber_config::ConfigNode::ConfigRef("storage_size".to_string()),
        )]));
        let value: InterpolatedString = "${config.storage_size}".parse().unwrap();
        let err = render_static_config_string(&value, Some(&template)).expect_err("must fail");
        assert!(err.contains("runtime root config"));
    }
}
