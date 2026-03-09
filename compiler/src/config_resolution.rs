use amber_config as rc;
use amber_manifest::{InterpolatedPart, InterpolatedString, InterpolationSource};

pub(crate) enum QueryResolution<'a> {
    Node(&'a rc::ConfigNode),
    RuntimePath(String),
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
                InterpolationSource::Bindings => {
                    return Err(
                        "binding interpolation is not allowed in resource params".to_string()
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use amber_manifest::InterpolatedString;

    use super::{
        parse_query_segments, render_static_config_string, resolve_config_query_node,
        validate_config_query_syntax,
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
