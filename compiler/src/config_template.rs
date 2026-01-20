use amber_config::{ConfigError, ConfigNode, SchemaLookup, schema_lookup};
use amber_manifest::{InterpolatedPart, InterpolatedString, InterpolationSource};
use amber_template::{TemplatePart, TemplateString};
use serde_json::Value;

use crate::binding_query::parse_binding_query;

pub fn parse_instance_config_template(
    value: Option<&Value>,
    parent_schema: Option<&Value>,
    binding_scope: u64,
) -> Result<ConfigNode, ConfigError> {
    let Some(value) = value else {
        return Ok(ConfigNode::empty_object());
    };

    let Value::Object(map) = value else {
        return Err(ConfigError::validation(
            "component config must be a JSON object".to_string(),
        ));
    };

    let mut out = std::collections::BTreeMap::new();
    for (k, v) in map {
        out.insert(
            k.clone(),
            parse_config_value_template(v, parent_schema, binding_scope)?,
        );
    }
    Ok(ConfigNode::Object(out))
}

fn parse_string_template(
    s: &str,
    parent_schema: Option<&Value>,
    binding_scope: u64,
) -> Result<ConfigNode, ConfigError> {
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
                    let schema = parent_schema.ok_or_else(|| {
                        ConfigError::schema(format!(
                            "config interpolation ${{config{}}} is not allowed because the parent \
                             component has no `config_schema`",
                            if query.is_empty() {
                                "".to_string()
                            } else {
                                format!(".{query}")
                            }
                        ))
                    })?;

                    match schema_lookup(schema, query.as_str()) {
                        Ok(SchemaLookup::Found) | Ok(SchemaLookup::Unknown) => {}
                        Err(e) => {
                            return Err(ConfigError::schema(format!(
                                "invalid parent config reference {query:?}: {e}"
                            )));
                        }
                    }

                    parts.push(TemplatePart::config(query));
                }
                InterpolationSource::Slots => {
                    return Err(ConfigError::interp(
                        "slot interpolation is not allowed in component config templates"
                            .to_string(),
                    ));
                }
                InterpolationSource::Bindings => {
                    let label = if query.is_empty() {
                        "bindings".to_string()
                    } else {
                        format!("bindings.{query}")
                    };
                    parse_binding_query(query.as_str()).map_err(|err| {
                        ConfigError::interp(format!(
                            "invalid bindings interpolation '{label}': {err}"
                        ))
                    })?;
                    parts.push(TemplatePart::binding(binding_scope, query));
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

fn parse_config_value_template(
    v: &Value,
    parent_schema: Option<&Value>,
    binding_scope: u64,
) -> Result<ConfigNode, ConfigError> {
    match v {
        Value::Null => Ok(ConfigNode::Null),
        Value::Bool(b) => Ok(ConfigNode::Bool(*b)),
        Value::Number(n) => Ok(ConfigNode::Number(n.clone())),
        Value::String(s) => parse_string_template(s, parent_schema, binding_scope),
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(parse_config_value_template(
                    item,
                    parent_schema,
                    binding_scope,
                )?);
            }
            Ok(ConfigNode::Array(out))
        }
        Value::Object(map) => {
            let mut out = std::collections::BTreeMap::new();
            for (k, vv) in map {
                out.insert(
                    k.clone(),
                    parse_config_value_template(vv, parent_schema, binding_scope)?,
                );
            }
            Ok(ConfigNode::Object(out))
        }
    }
}
