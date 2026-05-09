use amber_config as rc;
use serde_json::Value;

use super::template;

pub(crate) const NON_OBJECT_CONFIG_TEMPLATE: &str =
    "component config must be an object (non-object config templates are unsupported)";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConfigValidationError {
    pub(crate) message: String,
    pub(crate) instance_path: Option<String>,
}

impl ConfigValidationError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            instance_path: None,
        }
    }

    fn with_instance_path(message: impl Into<String>, instance_path: String) -> Self {
        Self {
            message: message.into(),
            instance_path: Some(instance_path),
        }
    }
}

pub(crate) fn compose_component_config_template(
    config: Option<&Value>,
    parent_schema: Option<&Value>,
    parent_template: &rc::RootConfigTemplate,
    component_schema: &Value,
) -> Result<rc::ConfigNode, String> {
    let initial = template::parse_instance_config_template(config, parent_schema)
        .map_err(|err| err.to_string())?;
    let mut composed = rc::compose_config_template(initial, parent_template)
        .map_err(|err| err.to_string())?
        .simplify();

    if !composed.is_object() {
        return Err(NON_OBJECT_CONFIG_TEMPLATE.to_string());
    }

    rc::apply_schema_defaults_to_node(component_schema, &mut composed)
        .map_err(|err| err.to_string())?;
    Ok(composed)
}

pub(crate) fn validate_component_config_template_with_validator(
    schema: Option<&Value>,
    template: &rc::RootConfigTemplate,
    config_present: bool,
    validate_jsonschema: &mut impl FnMut(&Value, &Value, &str) -> Result<(), ConfigValidationError>,
) -> Vec<ConfigValidationError> {
    let Some(schema) = schema else {
        if config_present {
            return vec![ConfigValidationError::new(
                "config was provided for a component that does not declare `config_schema`",
            )];
        }
        return Vec::new();
    };

    let Some(composed) = template.node() else {
        // Root config is supplied at runtime when the root component declares config_schema.
        return Vec::new();
    };

    validate_composed_component_config_with_validator(schema, composed, validate_jsonschema)
}

pub(crate) fn validate_composed_component_config(
    schema: &Value,
    composed: &rc::ConfigNode,
) -> Vec<ConfigValidationError> {
    validate_composed_component_config_with_validator(schema, composed, &mut validate_jsonschema)
}

fn validate_composed_component_config_with_validator(
    schema: &Value,
    composed: &rc::ConfigNode,
    validate_jsonschema: &mut impl FnMut(&Value, &Value, &str) -> Result<(), ConfigValidationError>,
) -> Vec<ConfigValidationError> {
    if !composed.is_object() {
        return vec![ConfigValidationError::new(NON_OBJECT_CONFIG_TEMPLATE)];
    }

    let mut errors = Vec::new();
    if let Err(message) = ensure_required_keys_present(schema, composed, "") {
        errors.push(ConfigValidationError::new(message));
    }

    if !composed.contains_runtime() {
        match composed.evaluate_static() {
            Ok(value) => {
                if let Err(err) = validate_jsonschema(schema, &value, "invalid config") {
                    errors.push(err);
                }
            }
            Err(err) => errors.push(ConfigValidationError::new(err.to_string())),
        }
    } else if let Some(partial) = composed.static_subset() {
        let projected = project_schema_for_partial(schema, &partial);
        if let Err(err) = validate_jsonschema(&projected, &partial, "invalid static config values")
        {
            errors.push(err);
        }
    }

    errors
}

fn required_strings(schema: &Value) -> Vec<String> {
    schema
        .get("required")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect()
}

fn properties_map(schema: &Value) -> Option<&serde_json::Map<String, Value>> {
    schema.get("properties")?.as_object()
}

fn ensure_required_keys_present(
    schema: &Value,
    template: &rc::ConfigNode,
    at: &str,
) -> Result<(), String> {
    let Some(props) = properties_map(schema) else {
        return Ok(());
    };
    let rc::ConfigNode::Object(map) = template else {
        return Ok(());
    };

    for req in required_strings(schema) {
        if !map.contains_key(req.as_str()) {
            let full = if at.is_empty() {
                format!("config.{req}")
            } else {
                format!("config.{at}.{req}")
            };
            return Err(format!("missing required field {full}"));
        }
    }

    // Recurse only when both schema and template have an object node; runtime inserts (ConfigRef)
    // have unknown structure until runtime, so we do not check deeper.
    for (key, value) in map {
        let Some(child_schema) = props.get(key) else {
            continue;
        };
        let child_at = if at.is_empty() {
            key.clone()
        } else {
            format!("{at}.{key}")
        };
        if child_schema.get("properties").is_some() && matches!(value, rc::ConfigNode::Object(_)) {
            ensure_required_keys_present(child_schema, value, &child_at)?;
        }
    }
    Ok(())
}

fn project_schema_for_partial(schema: &Value, partial: &Value) -> Value {
    match (schema, partial) {
        (Value::Object(schema_map), Value::Object(partial_map)) => {
            let mut out = schema_map.clone();

            // Prune `required` to keys that exist in the partial object.
            if let Some(Value::Array(required)) = schema_map.get("required") {
                let filtered = required
                    .iter()
                    .filter_map(|v| v.as_str())
                    .filter(|key| partial_map.contains_key(*key))
                    .map(|key| Value::String(key.to_string()))
                    .collect::<Vec<_>>();
                out.insert("required".to_string(), Value::Array(filtered));
            }

            // Recurse into properties that exist in the partial object.
            if let Some(Value::Object(properties)) = schema_map.get("properties") {
                let mut new_properties = properties.clone();
                for (key, child_schema) in properties {
                    if let Some(child_partial) = partial_map.get(key) {
                        new_properties.insert(
                            key.clone(),
                            project_schema_for_partial(child_schema, child_partial),
                        );
                    }
                }
                out.insert("properties".to_string(), Value::Object(new_properties));
            }

            Value::Object(out)
        }
        _ => schema.clone(),
    }
}

fn validate_jsonschema(
    schema: &Value,
    instance: &Value,
    context: &str,
) -> Result<(), ConfigValidationError> {
    let validator = jsonschema::validator_for(schema).map_err(|err| {
        ConfigValidationError::new(format!("{context}: failed to compile schema: {err}"))
    })?;

    validate_jsonschema_instance(&validator, instance, context)
}

pub(crate) fn validate_jsonschema_instance(
    validator: &jsonschema::Validator,
    instance: &Value,
    context: &str,
) -> Result<(), ConfigValidationError> {
    let mut errors = validator.iter_errors(instance);
    let Some(first) = errors.next() else {
        return Ok(());
    };

    let instance_path = first.instance_path().to_string();
    let mut messages = vec![first.to_string()];
    messages.extend(errors.take(7).map(|err| err.to_string()));
    Err(ConfigValidationError::with_instance_path(
        format!("{context}: {}", messages.join("; ")),
        instance_path,
    ))
}
