use amber_config::{ConfigError, ConfigNode, SchemaLookup, schema_lookup};
use amber_manifest::{InterpolatedPart, InterpolatedString, InterpolationSource};
use amber_template::{TemplatePart, TemplateString};
use serde_json::Value;

pub fn parse_instance_config_template(
    value: Option<&Value>,
    parent_schema: Option<&Value>,
) -> Result<ConfigNode, ConfigError> {
    parse_instance_config_template_located(value, parent_schema).map_err(|err| err.error)
}

#[derive(Debug)]
pub(crate) struct ConfigTemplateError {
    error: ConfigError,
    pointer: String,
}

impl ConfigTemplateError {
    pub(crate) fn error(&self) -> &ConfigError {
        &self.error
    }

    pub(crate) fn pointer(&self) -> &str {
        &self.pointer
    }
}

pub(crate) fn parse_instance_config_template_located(
    value: Option<&Value>,
    parent_schema: Option<&Value>,
) -> Result<ConfigNode, ConfigTemplateError> {
    let Some(value) = value else {
        return Ok(ConfigNode::empty_object());
    };

    let Value::Object(map) = value else {
        return Err(config_error(
            "",
            ConfigError::validation("component config must be a JSON object".to_string()),
        ));
    };

    let mut out = std::collections::BTreeMap::new();
    for (k, v) in map {
        let pointer = append_pointer("", k);
        out.insert(
            k.clone(),
            parse_config_value_template_at(v, parent_schema, &pointer)?,
        );
    }
    Ok(ConfigNode::Object(out))
}

fn config_error(pointer: &str, error: ConfigError) -> ConfigTemplateError {
    ConfigTemplateError {
        error,
        pointer: pointer.to_string(),
    }
}

fn escape_pointer_segment(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

fn append_pointer(parent: &str, segment: &str) -> String {
    format!("{parent}/{}", escape_pointer_segment(segment))
}

fn parse_string_template(
    s: &str,
    parent_schema: Option<&Value>,
) -> Result<ConfigNode, ConfigError> {
    if let Some(path) = parse_symbolic_config_ref(s, parent_schema)? {
        return Ok(ConfigNode::SymbolicConfigRef(path));
    }

    let parsed: InterpolatedString = s
        .parse::<InterpolatedString>()
        .map_err(|e| ConfigError::interp(e.to_string()))?;

    let has_interp = parsed
        .parts
        .iter()
        .any(|p| matches!(p, InterpolatedPart::Interpolation { .. }));
    if !has_interp {
        return Ok(ConfigNode::String(s.to_string()));
    }

    let mut parts: TemplateString = Vec::new();
    for part in parsed.parts {
        match part {
            InterpolatedPart::Literal(lit) => parts.push(TemplatePart::lit(lit)),
            InterpolatedPart::Interpolation { source, query } => match source {
                InterpolationSource::Config => {
                    validate_config_path(query.as_str(), parent_schema, false)?;
                    parts.push(TemplatePart::config(query));
                }
                InterpolationSource::Slots => {
                    return Err(ConfigError::interp(
                        "slot interpolation is not allowed in component config templates"
                            .to_string(),
                    ));
                }
                other => {
                    return Err(ConfigError::interp(format!(
                        "unsupported interpolation source {other} in component config template"
                    )));
                }
            },
            _ => {
                return Err(ConfigError::interp(
                    "unsupported interpolation part in component config template".to_string(),
                ));
            }
        }
    }

    if parts.len() == 1
        && let TemplatePart::Config { config } = &parts[0]
    {
        return Ok(ConfigNode::ConfigRef(config.clone()));
    }

    Ok(ConfigNode::StringTemplate(parts))
}

fn parse_config_value_template_at(
    v: &Value,
    parent_schema: Option<&Value>,
    pointer: &str,
) -> Result<ConfigNode, ConfigTemplateError> {
    match v {
        Value::Null => Ok(ConfigNode::Null),
        Value::Bool(b) => Ok(ConfigNode::Bool(*b)),
        Value::Number(n) => Ok(ConfigNode::Number(n.clone())),
        Value::String(s) => {
            parse_string_template(s, parent_schema).map_err(|err| config_error(pointer, err))
        }
        Value::Array(items) => parse_config_array_template(items, parent_schema, pointer),
        Value::Object(map) => {
            if let Some(path) = map.get("$symbolic_config") {
                let Value::String(path) = path else {
                    return Err(config_error(
                        &append_pointer(pointer, "$symbolic_config"),
                        ConfigError::validation(
                            "`$symbolic_config` value must be a string".to_string(),
                        ),
                    ));
                };
                return validate_config_path(path, parent_schema, true)
                    .map(|_| ConfigNode::SymbolicConfigRef(path.clone()))
                    .map_err(|err| {
                        config_error(&append_pointer(pointer, "$symbolic_config"), err)
                    });
            }
            if let Some(value) = map.get("$symbolic_string") {
                let Value::String(value) = value else {
                    return Err(config_error(
                        &append_pointer(pointer, "$symbolic_string"),
                        ConfigError::validation(
                            "`$symbolic_string` value must be a string".to_string(),
                        ),
                    ));
                };
                return Ok(ConfigNode::SymbolicString(value.clone()));
            }
            parse_config_object_template(map, parent_schema, pointer)
        }
    }
}

fn parse_config_array_template(
    items: &[Value],
    parent_schema: Option<&Value>,
    pointer: &str,
) -> Result<ConfigNode, ConfigTemplateError> {
    let mut out = Vec::with_capacity(items.len());
    for (idx, item) in items.iter().enumerate() {
        out.push(parse_config_value_template_at(
            item,
            parent_schema,
            &append_pointer(pointer, &idx.to_string()),
        )?);
    }
    Ok(ConfigNode::Array(out))
}

fn parse_config_object_template(
    map: &serde_json::Map<String, Value>,
    parent_schema: Option<&Value>,
    pointer: &str,
) -> Result<ConfigNode, ConfigTemplateError> {
    let mut out = std::collections::BTreeMap::new();
    for (k, vv) in map {
        out.insert(
            k.clone(),
            parse_config_value_template_at(vv, parent_schema, &append_pointer(pointer, k))?,
        );
    }
    Ok(ConfigNode::Object(out))
}

fn validate_config_path(
    path: &str,
    parent_schema: Option<&Value>,
    symbolic: bool,
) -> Result<(), ConfigError> {
    let schema = parent_schema.ok_or_else(|| {
        let sigil = if symbolic { "$$" } else { "$" };
        ConfigError::schema(format!(
            "{} config interpolation {}{{config{}}} is not allowed because the parent component \
             has no `config_schema`",
            if symbolic { "symbolic" } else { "normal" },
            sigil,
            if path.is_empty() {
                "".to_string()
            } else {
                format!(".{path}")
            }
        ))
    })?;

    match schema_lookup(schema, path) {
        Ok(SchemaLookup::Found) | Ok(SchemaLookup::Unknown) => Ok(()),
        Err(e) => Err(ConfigError::schema(format!(
            "invalid parent config reference {path:?}: {e}"
        ))),
    }
}

fn parse_symbolic_config_ref(
    s: &str,
    parent_schema: Option<&Value>,
) -> Result<Option<String>, ConfigError> {
    let Some(inner) = s.strip_prefix("$${") else {
        if s.contains("$${") {
            return Err(ConfigError::interp(
                "symbolic config interpolation must occupy the entire string".to_string(),
            ));
        }
        return Ok(None);
    };
    let Some(inner) = inner.strip_suffix('}') else {
        return Err(ConfigError::interp(format!(
            "invalid symbolic interpolation `{s}`"
        )));
    };
    let Some(path) = inner.strip_prefix("config") else {
        return Err(ConfigError::interp(format!(
            "unsupported symbolic interpolation `{s}`: expected `$${{config.<path>}}`"
        )));
    };
    let path = if path.is_empty() {
        ""
    } else {
        path.strip_prefix('.').ok_or_else(|| {
            ConfigError::interp(format!(
                "unsupported symbolic interpolation `{s}`: expected `$${{config.<path>}}`"
            ))
        })?
    };
    validate_config_path(path, parent_schema, true)?;
    Ok(Some(path.to_string()))
}

#[cfg(test)]
mod tests {
    use amber_config::{ConfigNode, RootConfigTemplate, compose_config_template};
    use serde_json::json;

    use super::parse_instance_config_template;

    #[test]
    fn parses_symbolic_config_ref() {
        let schema = json!({
            "type": "object",
            "properties": {
                "secret": { "type": "string" },
            },
        });
        let config = json!({
            "redaction_term": "$${config.secret}",
        });

        let parsed =
            parse_instance_config_template(Some(&config), Some(&schema)).expect("config parses");

        assert_eq!(
            parsed,
            ConfigNode::Object(
                [(
                    "redaction_term".to_string(),
                    ConfigNode::SymbolicConfigRef("secret".to_string()),
                )]
                .into_iter()
                .collect(),
            )
        );
    }

    #[test]
    fn composes_symbolic_config_ref_against_parent_template() {
        let child = ConfigNode::Object(
            [(
                "redaction_term".to_string(),
                ConfigNode::SymbolicConfigRef("secret".to_string()),
            )]
            .into_iter()
            .collect(),
        );
        let parent = RootConfigTemplate::Node(ConfigNode::Object(
            [(
                "secret".to_string(),
                ConfigNode::ConfigRef("root_secret".to_string()),
            )]
            .into_iter()
            .collect(),
        ));

        let composed = compose_config_template(child, &parent).expect("config composes");

        assert_eq!(
            composed.to_manifest_value(),
            json!({
                "redaction_term": {
                    "$symbolic_config": "root_secret",
                },
            })
        );
    }

    #[test]
    fn rejects_mixed_symbolic_interpolation() {
        let schema = json!({
            "type": "object",
            "properties": {
                "secret": { "type": "string" },
            },
        });
        let config = json!({
            "redaction_term": "prefix $${config.secret}",
        });

        let err = parse_instance_config_template(Some(&config), Some(&schema)).unwrap_err();

        assert!(
            err.to_string()
                .contains("symbolic config interpolation must occupy the entire string"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn rejects_symbolic_non_config_sources() {
        let schema = json!({
            "type": "object",
            "properties": {
                "secret": { "type": "string" },
            },
        });
        let config = json!({
            "redaction_term": "$${slots.api.url}",
        });

        let err = parse_instance_config_template(Some(&config), Some(&schema)).unwrap_err();

        assert!(
            err.to_string().contains("expected `$${config.<path>}`"),
            "unexpected error: {err}",
        );
    }
}
