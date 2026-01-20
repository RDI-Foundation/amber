use amber_template::{ConfigTemplate, ConfigTemplatePayload, TemplatePart, TemplateString};
use serde_json::Value;

use crate::{ConfigError, Result};

pub fn template_string_is_runtime(ts: &TemplateString) -> bool {
    ts.iter().any(|p| p.is_config() || p.is_binding())
}

pub fn stringify_for_interpolation(v: &Value) -> Result<String> {
    match v {
        Value::Null => Err(ConfigError::interp("cannot interpolate null".to_string())),
        Value::String(s) => Ok(s.clone()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Array(_) | Value::Object(_) => serde_json::to_string(v).map_err(|e| {
            ConfigError::interp(format!(
                "failed to serialize value as JSON for interpolation: {e}"
            ))
        }),
    }
}

pub fn get_by_path<'a>(root: &'a Value, path: &str) -> Result<&'a Value> {
    if path.is_empty() {
        return Ok(root);
    }
    let mut cur = root;
    for seg in path.split('.') {
        if seg.is_empty() {
            return Err(ConfigError::interp(format!(
                "invalid config path {path:?}: empty segment"
            )));
        }
        match cur {
            Value::Object(map) => {
                cur = map.get(seg).ok_or_else(|| {
                    ConfigError::interp(format!("config.{path} not found (missing key {seg:?})"))
                })?;
            }
            _ => {
                return Err(ConfigError::interp(format!(
                    "config.{path} not found (encountered non-object before segment {seg:?})"
                )));
            }
        }
    }
    Ok(cur)
}

pub fn eval_config_template(
    template: &ConfigTemplatePayload,
    root_config: &Value,
) -> Result<Value> {
    match template {
        ConfigTemplatePayload::Root => Ok(root_config.clone()),
        ConfigTemplatePayload::Template(node) => eval_config_node(node, root_config),
    }
}

fn eval_config_node(node: &ConfigTemplate, root_config: &Value) -> Result<Value> {
    match node {
        ConfigTemplate::Literal(value) => Ok(value.clone()),
        ConfigTemplate::ConfigRef { path } => Ok(get_by_path(root_config, path)?.clone()),
        ConfigTemplate::TemplateString { parts } => {
            let rendered = render_template_string(parts, root_config)?;
            Ok(Value::String(rendered))
        }
        ConfigTemplate::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                out.push(eval_config_node(item, root_config)?);
            }
            Ok(Value::Array(out))
        }
        ConfigTemplate::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                out.insert(k.clone(), eval_config_node(v, root_config)?);
            }
            Ok(Value::Object(out))
        }
    }
}

pub fn render_template_string(parts: &TemplateString, config: &Value) -> Result<String> {
    let mut out = String::new();
    for p in parts {
        match p {
            TemplatePart::Lit { lit } => out.push_str(lit),
            TemplatePart::Config { config: path } => {
                let v = get_by_path(config, path)?;
                if v.is_null() {
                    return Err(ConfigError::interp(format!(
                        "config.{path} is null; cannot interpolate"
                    )));
                }
                out.push_str(&stringify_for_interpolation(v)?);
            }
            TemplatePart::Binding { binding, .. } => {
                return Err(ConfigError::interp(format!(
                    "binding interpolation bindings.{binding} cannot be rendered at runtime"
                )));
            }
        }
    }
    Ok(out)
}
