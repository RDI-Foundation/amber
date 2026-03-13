use amber_template::{
    ConfigTemplate, ConfigTemplatePayload, MountSpec, MountTemplateSpec, RepeatedTemplateSource,
    RuntimeTemplateContext, TemplatePart, TemplateString,
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
            None,
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
    render_template_string_with_current_item(parts, config, runtime_context, None)
}

pub fn render_template_string_with_current_item(
    parts: &TemplateString,
    config: &Value,
    runtime_context: &RuntimeTemplateContext,
    current_item: Option<&Value>,
) -> Result<String> {
    render_template_string_with_behavior(
        parts,
        config,
        runtime_context,
        current_item,
        MissingConfigBehavior::Error,
    )?
    .ok_or_else(|| ConfigError::interp("template resolved to no value".to_string()))
}

fn render_template_string_with_behavior(
    parts: &TemplateString,
    config: &Value,
    runtime_context: &RuntimeTemplateContext,
    current_item: Option<&Value>,
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
            TemplatePart::CurrentItem { item: path } => {
                let item = current_item.ok_or_else(|| {
                    ConfigError::interp(format!(
                        "item.{path} cannot be rendered without a repeated item context"
                    ))
                })?;
                let value = query_value_opt(item, path).ok_or_else(|| {
                    ConfigError::interp(format!(
                        "item.{path} not found in the current repeated item"
                    ))
                })?;
                out.push_str(&stringify_for_interpolation(value)?);
            }
        }
    }
    Ok(Some(out))
}

pub fn config_path_is_present(config_value: &Value, path: &str) -> Result<bool> {
    Ok(get_by_path_opt(config_value, path)?.is_some_and(|value| !value.is_null()))
}

pub fn repeated_config_items<'a>(component_config: &'a Value, path: &str) -> Result<&'a [Value]> {
    match get_by_path_opt(component_config, path)? {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(items)) => Ok(items.as_slice()),
        Some(other) => Err(ConfigError::interp(format!(
            "config.{path} must resolve to an array for repeated expansion, got {}",
            value_kind(other)
        ))),
    }
}

pub fn render_mount_specs(
    mounts: &[MountSpec],
    component_config: Option<&Value>,
    runtime_context: &RuntimeTemplateContext,
) -> Result<Vec<(String, String)>> {
    if mounts.is_empty() {
        return Ok(Vec::new());
    }

    let mut rendered = Vec::with_capacity(mounts.len());
    for mount in mounts {
        match mount {
            MountSpec::Literal { path, content } => {
                rendered.push((path.clone(), content.clone()));
            }
            MountSpec::Template(spec) => {
                let config_value = component_config.ok_or_else(|| {
                    ConfigError::interp("config payload is required to render mount templates")
                })?;
                if let Some(when) = spec.when.as_deref()
                    && !config_path_is_present(config_value, when)?
                {
                    continue;
                }

                match spec.each.as_ref() {
                    None => rendered.push(render_mount_template_once(
                        spec,
                        config_value,
                        runtime_context,
                        None,
                    )?),
                    Some(RepeatedTemplateSource::Config { path }) => {
                        for item in repeated_config_items(config_value, path)? {
                            rendered.push(render_mount_template_once(
                                spec,
                                config_value,
                                runtime_context,
                                Some(item),
                            )?);
                        }
                    }
                }
            }
        }
    }

    Ok(rendered)
}

fn rendered_mount_source_query(source: &str) -> Result<&str> {
    if source == "config" {
        return Ok("");
    }
    if let Some(path) = source.strip_prefix("config.") {
        return Ok(path);
    }
    if let Some(path) = source.strip_prefix("secret.") {
        return Ok(path);
    }
    if source == "secret" {
        return Err(ConfigError::interp(
            "secret mounts require an explicit path (secret.<path>)".to_string(),
        ));
    }
    Err(ConfigError::interp(format!(
        "mount source must render to config.<path> or secret.<path>, got `{source}`"
    )))
}

fn render_mount_template_once(
    spec: &MountTemplateSpec,
    component_config: &Value,
    runtime_context: &RuntimeTemplateContext,
    current_item: Option<&Value>,
) -> Result<(String, String)> {
    let path = render_template_string_with_current_item(
        &spec.path,
        component_config,
        runtime_context,
        current_item,
    )?;
    let source = render_template_string_with_current_item(
        &spec.source,
        component_config,
        runtime_context,
        current_item,
    )?;
    let query = rendered_mount_source_query(&source)?;
    let value = get_by_path(component_config, query)?;
    let content = stringify_for_mount(value)?;
    Ok((path, content))
}

pub fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
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

#[cfg(test)]
mod tests {
    use amber_template::{
        MountSpec, MountTemplateSpec, RepeatedTemplateSource, RuntimeTemplateContext, TemplatePart,
    };
    use serde_json::json;

    use super::*;

    #[test]
    fn render_template_string_with_current_item_uses_item_context() {
        let rendered = render_template_string_with_current_item(
            &[
                TemplatePart::lit("http://"),
                TemplatePart::current_item("host"),
                TemplatePart::lit(":"),
                TemplatePart::current_item("port"),
            ]
            .to_vec(),
            &json!({}),
            &RuntimeTemplateContext::default(),
            Some(&json!({
                "host": "api.internal",
                "port": 8080
            })),
        )
        .expect("item context should render");

        assert_eq!(rendered, "http://api.internal:8080");
    }

    #[test]
    fn render_template_string_with_current_item_requires_item_context() {
        let err = render_template_string_with_current_item(
            &[TemplatePart::current_item("url")].to_vec(),
            &json!({}),
            &RuntimeTemplateContext::default(),
            None,
        )
        .expect_err("missing item context should fail");

        assert!(err.to_string().contains("repeated item context"), "{}", err);
    }

    #[test]
    fn render_mount_specs_skips_template_when_path_is_absent() {
        let mounts = vec![MountSpec::Template(MountTemplateSpec {
            when: Some("optional".to_string()),
            each: None,
            path: vec![TemplatePart::lit("/tmp/optional.txt")],
            source: vec![TemplatePart::lit("config.app")],
        })];

        let rendered = render_mount_specs(
            &mounts,
            Some(&json!({ "app": "hello" })),
            &RuntimeTemplateContext::default(),
        )
        .expect("mount rendering should succeed");

        assert!(rendered.is_empty());
    }

    #[test]
    fn render_mount_specs_expands_repeated_config_mounts() {
        let mounts = vec![MountSpec::Template(MountTemplateSpec {
            when: None,
            each: Some(RepeatedTemplateSource::Config {
                path: "files".to_string(),
            }),
            path: vec![
                TemplatePart::lit("/tmp/"),
                TemplatePart::current_item("name"),
                TemplatePart::lit(".txt"),
            ],
            source: vec![
                TemplatePart::lit("config."),
                TemplatePart::current_item("source"),
            ],
        })];
        let component_config = json!({
            "files": [
                { "name": "alpha", "source": "content.alpha" },
                { "name": "beta", "source": "content.beta" }
            ],
            "content": {
                "alpha": "A",
                "beta": "B"
            }
        });

        let rendered = render_mount_specs(
            &mounts,
            Some(&component_config),
            &RuntimeTemplateContext::default(),
        )
        .expect("mount rendering should succeed");

        assert_eq!(
            rendered,
            vec![
                ("/tmp/alpha.txt".to_string(), "A".to_string()),
                ("/tmp/beta.txt".to_string(), "B".to_string()),
            ]
        );
    }
}
