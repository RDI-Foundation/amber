use amber_template::{
    ConfigTemplate, ConfigTemplatePayload, RuntimeTemplateContext, TemplatePart, TemplateString,
};
use serde_json::Value;

use crate::{ConfigError, Result};

#[derive(Clone, Copy)]
enum MissingConfigBehavior {
    Error,
    Omit,
}

pub fn template_string_is_runtime(ts: &TemplateString) -> bool {
    ts.iter()
        .any(|p| p.is_config() || p.is_slot() || p.is_item())
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

pub fn stringify_for_mount(v: &Value) -> Result<String> {
    match v {
        Value::Null => Ok(String::new()),
        Value::String(s) => Ok(s.clone()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Array(_) | Value::Object(_) => serde_json::to_string(v).map_err(|e| {
            ConfigError::interp(format!("failed to serialize value as JSON for mount: {e}"))
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

pub fn get_by_path_opt<'a>(root: &'a Value, path: &str) -> Result<Option<&'a Value>> {
    if path.is_empty() {
        return Ok(Some(root));
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
                let Some(next) = map.get(seg) else {
                    return Ok(None);
                };
                cur = next;
            }
            _ => return Ok(None),
        }
    }
    Ok(Some(cur))
}

pub fn eval_config_template(
    template: &ConfigTemplatePayload,
    root_config: &Value,
) -> Result<Value> {
    eval_config_template_with_context(template, root_config, &RuntimeTemplateContext::default())
}

pub fn eval_config_template_with_context(
    template: &ConfigTemplatePayload,
    root_config: &Value,
    runtime_context: &RuntimeTemplateContext,
) -> Result<Value> {
    match template {
        ConfigTemplatePayload::Root => Ok(root_config.clone()),
        ConfigTemplatePayload::Template(node) => eval_config_node_with_behavior(
            node,
            root_config,
            runtime_context,
            MissingConfigBehavior::Error,
        )?
        .ok_or_else(|| ConfigError::interp("config template resolved to no value".to_string())),
    }
}

pub fn eval_config_template_partial_with_context(
    template: &ConfigTemplatePayload,
    root_config: &Value,
    runtime_context: &RuntimeTemplateContext,
) -> Result<Value> {
    match template {
        ConfigTemplatePayload::Root => Ok(root_config.clone()),
        ConfigTemplatePayload::Template(node) => Ok(eval_config_node_with_behavior(
            node,
            root_config,
            runtime_context,
            MissingConfigBehavior::Omit,
        )?
        .unwrap_or(Value::Object(Default::default()))),
    }
}

fn eval_config_node_with_behavior(
    node: &ConfigTemplate,
    root_config: &Value,
    runtime_context: &RuntimeTemplateContext,
    missing_behavior: MissingConfigBehavior,
) -> Result<Option<Value>> {
    match node {
        ConfigTemplate::Literal(value) => Ok(Some(value.clone())),
        ConfigTemplate::ConfigRef { path } => match get_by_path_opt(root_config, path)? {
            Some(value) => Ok(Some(value.clone())),
            None if matches!(missing_behavior, MissingConfigBehavior::Omit) => Ok(None),
            None => Err(ConfigError::interp(format!(
                "config.{path} not found (missing key in runtime config)"
            ))),
        },
        ConfigTemplate::TemplateString { parts } => render_template_string_with_behavior(
            parts,
            root_config,
            runtime_context,
            missing_behavior,
        )
        .map(|value| value.map(Value::String)),
        ConfigTemplate::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                if let Some(value) = eval_config_node_with_behavior(
                    item,
                    root_config,
                    runtime_context,
                    missing_behavior,
                )? {
                    out.push(value);
                }
            }
            Ok(Some(Value::Array(out)))
        }
        ConfigTemplate::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                if let Some(value) = eval_config_node_with_behavior(
                    v,
                    root_config,
                    runtime_context,
                    missing_behavior,
                )? {
                    out.insert(k.clone(), value);
                }
            }
            Ok(Some(Value::Object(out)))
        }
    }
}

pub fn render_template_string(parts: &TemplateString, config: &Value) -> Result<String> {
    render_template_string_with_context(parts, config, &RuntimeTemplateContext::default())
}

pub fn render_template_string_with_context(
    parts: &TemplateString,
    config: &Value,
    runtime_context: &RuntimeTemplateContext,
) -> Result<String> {
    render_template_string_with_behavior(
        parts,
        config,
        runtime_context,
        MissingConfigBehavior::Error,
    )?
    .ok_or_else(|| ConfigError::interp("template resolved to no value".to_string()))
}

fn render_template_string_with_behavior(
    parts: &TemplateString,
    config: &Value,
    runtime_context: &RuntimeTemplateContext,
    missing_behavior: MissingConfigBehavior,
) -> Result<Option<String>> {
    let mut out = String::new();
    for p in parts {
        match p {
            TemplatePart::Lit { lit } => out.push_str(lit),
            TemplatePart::Config { config: path } => {
                let Some(v) = get_by_path_opt(config, path)? else {
                    if matches!(missing_behavior, MissingConfigBehavior::Omit) {
                        return Ok(None);
                    }
                    return Err(ConfigError::interp(format!(
                        "config.{path} not found (missing key in rendered config)"
                    )));
                };
                if v.is_null() {
                    if matches!(missing_behavior, MissingConfigBehavior::Omit) {
                        return Ok(None);
                    }
                    return Err(ConfigError::interp(format!(
                        "config.{path} is null; cannot interpolate"
                    )));
                }
                out.push_str(&stringify_for_interpolation(v)?);
            }
            TemplatePart::Slot { slot, scope } => {
                let value = runtime_context
                    .slots_by_scope
                    .get(scope)
                    .and_then(|slots| slots.get(slot))
                    .ok_or_else(|| {
                        ConfigError::interp(format!(
                            "slot interpolation slots.{slot} cannot be rendered at runtime for \
                             scope {scope}"
                        ))
                    })?;
                out.push_str(value);
            }
            TemplatePart::Item {
                item: path,
                scope,
                slot,
                index,
            } => {
                let item = runtime_context
                    .slot_items_by_scope
                    .get(scope)
                    .and_then(|slots| slots.get(slot))
                    .and_then(|items| items.get(*index))
                    .ok_or_else(|| {
                        ConfigError::interp(format!(
                            "item interpolation item.{path} cannot be rendered at runtime for \
                             scope {scope}, slot {slot}, item {index}"
                        ))
                    })?;
                let item = serde_json::to_value(item).map_err(|err| {
                    ConfigError::interp(format!(
                        "failed to serialize runtime slot item for scope {scope}, slot {slot}, \
                         item {index}: {err}"
                    ))
                })?;
                let value = query_value_opt(&item, path).ok_or_else(|| {
                    ConfigError::interp(format!(
                        "item.{path} not found in runtime slot item for scope {scope}, slot \
                         {slot}, item {index}"
                    ))
                })?;
                out.push_str(&stringify_for_interpolation(value)?);
            }
        }
    }
    Ok(Some(out))
}

fn query_value_opt<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    if path.is_empty() {
        return Some(root);
    }

    let mut current = root;
    for segment in path.split('.') {
        match current {
            Value::Object(map) => current = map.get(segment)?,
            _ => return None,
        }
    }
    Some(current)
}
