use serde_json::Value;

use crate::is_valid_config_key;

const CONFIG_KEY_RULE: &str = "must start with a lowercase ASCII letter and contain only \
                               lowercase ASCII letters, digits, and underscores; double \
                               underscores are not allowed";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigSchemaProfileError {
    pub path: String,
    pub message: String,
    pub pointer: Option<String>,
    pub key: Option<String>,
}

impl ConfigSchemaProfileError {
    pub fn from_json_schema_validation(error: &jsonschema::ValidationError<'_>) -> Self {
        let pointer = error.instance_path().as_str().to_string();
        Self {
            path: display_path(path_from_json_pointer(&pointer).as_str()),
            message: error.to_string(),
            pointer: Some(pointer),
            key: None,
        }
    }

    fn at_value(pointer: impl Into<String>, path: impl Into<String>, message: String) -> Self {
        Self {
            path: display_path(path.into().as_str()),
            message,
            pointer: Some(pointer.into()),
            key: None,
        }
    }

    fn at_key(
        object_pointer: impl Into<String>,
        object_path: impl Into<String>,
        key: &str,
        message: String,
    ) -> Self {
        let object_path = object_path.into();
        Self {
            path: display_path(path_child(&object_path, key).as_str()),
            message,
            pointer: Some(object_pointer.into()),
            key: Some(key.to_string()),
        }
    }

    fn at_root(message: String) -> Self {
        Self {
            path: "<root>".to_string(),
            message,
            pointer: Some(String::new()),
            key: None,
        }
    }
}

fn display_path(path: &str) -> String {
    if path.is_empty() {
        "<root>".to_string()
    } else {
        path.to_string()
    }
}

fn path_child(path: &str, segment: &str) -> String {
    if path.is_empty() {
        segment.to_string()
    } else {
        format!("{path}.{segment}")
    }
}

fn path_index(path: &str, index: usize) -> String {
    if path.is_empty() {
        format!("[{index}]")
    } else {
        format!("{path}[{index}]")
    }
}

fn pointer_child(pointer: &str, segment: &str) -> String {
    let escaped = escape_json_pointer_segment(segment);
    if pointer.is_empty() {
        format!("/{escaped}")
    } else {
        format!("{pointer}/{escaped}")
    }
}

fn pointer_index(pointer: &str, index: usize) -> String {
    if pointer.is_empty() {
        format!("/{index}")
    } else {
        format!("{pointer}/{index}")
    }
}

fn escape_json_pointer_segment(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

fn unescape_json_pointer_segment(segment: &str) -> String {
    segment.replace("~1", "/").replace("~0", "~")
}

fn path_from_json_pointer(pointer: &str) -> String {
    let mut path = String::new();
    for segment in pointer.strip_prefix('/').unwrap_or(pointer).split('/') {
        if segment.is_empty() {
            continue;
        }
        let segment = unescape_json_pointer_segment(segment);
        path = match segment.parse::<usize>() {
            Ok(index) => path_index(&path, index),
            Err(_) => path_child(&path, &segment),
        };
    }
    path
}

fn type_includes_object(schema: &Value) -> bool {
    match schema.get("type") {
        Some(Value::String(ty)) => ty == "object",
        Some(Value::Array(types)) => types.iter().any(|ty| ty.as_str() == Some("object")),
        _ => false,
    }
}

fn invalid_config_key_message(kind: &str, key: &str) -> String {
    let mut message = format!("{kind} `{key}` is invalid; config property names {CONFIG_KEY_RULE}");
    if key.chars().any(char::is_uppercase) {
        message.push_str(". Uppercase letters are not allowed");
    }
    let lower = key.to_ascii_lowercase();
    if lower != key && is_valid_config_key(&lower) {
        message.push_str("; use `");
        message.push_str(&lower);
        message.push_str("` instead");
    }
    message
}

fn is_draft_2020_12_schema(uri: &str) -> bool {
    matches!(
        uri,
        "https://json-schema.org/draft/2020-12/schema"
            | "https://json-schema.org/draft/2020-12/schema#"
            | "http://json-schema.org/draft/2020-12/schema"
            | "http://json-schema.org/draft/2020-12/schema#"
    )
}

fn check_object_type_for_keyword(
    schema: &Value,
    pointer: &str,
    path: &str,
    keyword: &str,
) -> Result<(), ConfigSchemaProfileError> {
    if type_includes_object(schema) {
        return Ok(());
    }

    let message = format!(
        "schema objects with `{keyword}` must declare `type: \"object\"` or include \"object\" in \
         their `type` array"
    );
    if schema.get("type").is_some() {
        Err(ConfigSchemaProfileError::at_value(
            pointer_child(pointer, "type"),
            path_child(path, "type"),
            message,
        ))
    } else {
        Err(ConfigSchemaProfileError::at_value(pointer, path, message))
    }
}

fn unsupported_keyword_message(keyword: &str) -> String {
    format!("unsupported config_schema keyword `{keyword}`")
}

fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn keyword_type_error(
    pointer: &str,
    path: &str,
    keyword: &str,
    expected: &str,
    value: &Value,
) -> ConfigSchemaProfileError {
    ConfigSchemaProfileError::at_value(
        pointer_child(pointer, keyword),
        path_child(path, keyword),
        format!(
            "`{keyword}` must be {expected} in Amber config_schema, got {}",
            value_kind(value)
        ),
    )
}

pub fn validate_config_schema_profile(schema: &Value) -> Result<(), ConfigSchemaProfileError> {
    if !schema.is_object() {
        return Err(ConfigSchemaProfileError::at_root(
            "root config_schema must be a JSON Schema object with `type: \"object\"`".to_string(),
        ));
    }
    if !type_includes_object(schema) {
        return Err(ConfigSchemaProfileError::at_value(
            schema
                .get("type")
                .map_or_else(String::new, |_| pointer_child("", "type")),
            schema
                .get("type")
                .map_or_else(String::new, |_| path_child("", "type")),
            "root config_schema must declare `type: \"object\"` or include \"object\" in its \
             `type` array"
                .to_string(),
        ));
    }
    walk_schema(schema, "", "")
}

fn walk_schema(schema: &Value, pointer: &str, path: &str) -> Result<(), ConfigSchemaProfileError> {
    let Some(obj) = schema.as_object() else {
        return Ok(());
    };

    if let Some(schema_uri) = obj.get("$schema") {
        let Some(schema_uri) = schema_uri.as_str() else {
            return Err(keyword_type_error(
                pointer, path, "$schema", "a string", schema_uri,
            ));
        };
        if !is_draft_2020_12_schema(schema_uri) {
            return Err(ConfigSchemaProfileError::at_value(
                pointer_child(pointer, "$schema"),
                path_child(path, "$schema"),
                "`$schema` must be Draft 2020-12 for Amber config_schema".to_string(),
            ));
        }
    }

    if let Some(reference) = obj.get("$ref") {
        let Some(reference) = reference.as_str() else {
            return Err(keyword_type_error(
                pointer, path, "$ref", "a string", reference,
            ));
        };
        if reference != "#" && !reference.starts_with("#/") {
            return Err(ConfigSchemaProfileError::at_value(
                pointer_child(pointer, "$ref"),
                path_child(path, "$ref"),
                "`$ref` must be local to the same config_schema (`#` or `#/...`)".to_string(),
            ));
        }
    }

    for keyword in [
        "anyOf",
        "oneOf",
        "not",
        "if",
        "then",
        "else",
        "patternProperties",
        "propertyNames",
        "dependentSchemas",
        "dependentRequired",
        "unevaluatedProperties",
        "unevaluatedItems",
        "$dynamicRef",
        "$recursiveRef",
    ] {
        if obj.contains_key(keyword) {
            return Err(ConfigSchemaProfileError::at_key(
                pointer,
                path,
                keyword,
                unsupported_keyword_message(keyword),
            ));
        }
    }

    if let Some(secret) = obj.get("secret")
        && !secret.is_boolean()
    {
        return Err(ConfigSchemaProfileError::at_value(
            pointer_child(pointer, "secret"),
            path_child(path, "secret"),
            "`secret` must be a boolean annotation".to_string(),
        ));
    }

    if let Some(additional) = obj.get("additionalProperties")
        && !additional.is_boolean()
    {
        return Err(ConfigSchemaProfileError::at_value(
            pointer_child(pointer, "additionalProperties"),
            path_child(path, "additionalProperties"),
            "`additionalProperties` must be a boolean in Amber config_schema".to_string(),
        ));
    }

    if let Some(properties) = obj.get("properties") {
        check_object_type_for_keyword(schema, pointer, path, "properties")?;
        let Some(properties) = properties.as_object() else {
            return Err(keyword_type_error(
                pointer,
                path,
                "properties",
                "an object",
                properties,
            ));
        };
        let properties_pointer = pointer_child(pointer, "properties");
        let properties_path = path_child(path, "properties");
        for (key, child_schema) in properties {
            if !is_valid_config_key(key) {
                return Err(ConfigSchemaProfileError::at_key(
                    &properties_pointer,
                    &properties_path,
                    key,
                    invalid_config_key_message("config property name", key),
                ));
            }
            walk_schema(
                child_schema,
                &pointer_child(&properties_pointer, key),
                &path_child(&properties_path, key),
            )?;
        }
    }

    if let Some(required) = obj.get("required") {
        check_object_type_for_keyword(schema, pointer, path, "required")?;
        let Some(required) = required.as_array() else {
            return Err(keyword_type_error(
                pointer, path, "required", "an array", required,
            ));
        };
        for (idx, required_key) in required.iter().enumerate() {
            let Some(required_key) = required_key.as_str() else {
                return Err(ConfigSchemaProfileError::at_value(
                    pointer_index(&pointer_child(pointer, "required"), idx),
                    path_index(&path_child(path, "required"), idx),
                    format!(
                        "`required` entries must be strings in Amber config_schema, got {}",
                        value_kind(required_key)
                    ),
                ));
            };
            if !is_valid_config_key(required_key) {
                return Err(ConfigSchemaProfileError::at_value(
                    pointer_index(&pointer_child(pointer, "required"), idx),
                    path_index(&path_child(path, "required"), idx),
                    invalid_config_key_message("required config property name", required_key),
                ));
            }
        }
    }

    for keyword in ["$defs", "definitions"] {
        let Some(defs) = obj.get(keyword) else {
            continue;
        };
        let Some(defs) = defs.as_object() else {
            return Err(keyword_type_error(
                pointer,
                path,
                keyword,
                "an object",
                defs,
            ));
        };
        let defs_pointer = pointer_child(pointer, keyword);
        let defs_path = path_child(path, keyword);
        for (name, child_schema) in defs {
            walk_schema(
                child_schema,
                &pointer_child(&defs_pointer, name),
                &path_child(&defs_path, name),
            )?;
        }
    }

    if let Some(all_of) = obj.get("allOf") {
        let Some(all_of) = all_of.as_array() else {
            return Err(keyword_type_error(
                pointer, path, "allOf", "an array", all_of,
            ));
        };
        let all_of_pointer = pointer_child(pointer, "allOf");
        let all_of_path = path_child(path, "allOf");
        for (idx, child_schema) in all_of.iter().enumerate() {
            walk_schema(
                child_schema,
                &pointer_index(&all_of_pointer, idx),
                &path_index(&all_of_path, idx),
            )?;
        }
    }

    if let Some(items) = obj.get("items") {
        walk_schema(
            items,
            &pointer_child(pointer, "items"),
            &path_child(path, "items"),
        )?;
    }

    if let Some(contains) = obj.get("contains") {
        walk_schema(
            contains,
            &pointer_child(pointer, "contains"),
            &path_child(path, "contains"),
        )?;
    }

    if let Some(prefix_items) = obj.get("prefixItems") {
        let Some(prefix_items) = prefix_items.as_array() else {
            return Err(keyword_type_error(
                pointer,
                path,
                "prefixItems",
                "an array",
                prefix_items,
            ));
        };
        let prefix_pointer = pointer_child(pointer, "prefixItems");
        let prefix_path = path_child(path, "prefixItems");
        for (idx, child_schema) in prefix_items.iter().enumerate() {
            walk_schema(
                child_schema,
                &pointer_index(&prefix_pointer, idx),
                &path_index(&prefix_path, idx),
            )?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn profile_error(schema: Value) -> ConfigSchemaProfileError {
        validate_config_schema_profile(&schema).unwrap_err()
    }

    #[test]
    fn rejects_pattern_properties() {
        let err = profile_error(json!({
            "type": "object",
            "patternProperties": {
                ".*": { "type": "string" }
            }
        }));

        assert_eq!(err.path, "patternProperties");
        assert_eq!(
            err.message,
            "unsupported config_schema keyword `patternProperties`"
        );
        assert_eq!(err.pointer.as_deref(), Some(""));
        assert_eq!(err.key.as_deref(), Some("patternProperties"));
    }

    #[test]
    fn rejects_uppercase_property_name() {
        let err = profile_error(json!({
            "type": "object",
            "properties": {
                "agent_HF_TOKEN": { "type": "string", "secret": true }
            }
        }));

        assert_eq!(err.path, "properties.agent_HF_TOKEN");
        assert!(err.message.contains("Uppercase letters are not allowed"));
        assert!(err.message.contains("use `agent_hf_token` instead"));
        assert_eq!(err.pointer.as_deref(), Some("/properties"));
        assert_eq!(err.key.as_deref(), Some("agent_HF_TOKEN"));
    }

    #[test]
    fn rejects_uppercase_required_name() {
        let err = profile_error(json!({
            "type": "object",
            "properties": {
                "token": { "type": "string" }
            },
            "required": ["HF_TOKEN"]
        }));

        assert_eq!(err.path, "required[0]");
        assert!(err.message.contains("required config property name"));
        assert!(err.message.contains("Uppercase letters are not allowed"));
        assert_eq!(err.pointer.as_deref(), Some("/required/0"));
        assert_eq!(err.key, None);
    }

    #[test]
    fn accepts_secret_and_x_annotations() {
        validate_config_schema_profile(&json!({
            "type": "object",
            "properties": {
                "token": { "type": "string", "secret": true },
                "model": { "type": "string", "x-example-hide": true }
            }
        }))
        .expect("supported profile should pass");
    }

    #[test]
    fn rejects_non_2020_12_draft() {
        let err = profile_error(json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
                "x": { "type": "string" }
            }
        }));

        assert_eq!(err.path, "$schema");
        assert_eq!(
            err.message,
            "`$schema` must be Draft 2020-12 for Amber config_schema"
        );
        assert_eq!(err.pointer.as_deref(), Some("/$schema"));
    }

    #[test]
    fn rejects_non_pointer_ref() {
        let err = profile_error(json!({
            "type": "object",
            "$defs": {
                "x": { "$anchor": "x", "type": "string" }
            },
            "properties": {
                "prop": { "$ref": "#x" }
            }
        }));

        assert_eq!(err.path, "properties.prop.$ref");
        assert_eq!(
            err.message,
            "`$ref` must be local to the same config_schema (`#` or `#/...`)"
        );
        assert_eq!(err.pointer.as_deref(), Some("/properties/prop/$ref"));
    }

    #[test]
    fn accepts_custom_annotation_keywords() {
        validate_config_schema_profile(&json!({
            "type": "object",
            "uiLabel": "Root config",
            "properties": {
                "token": {
                    "type": "string",
                    "uiLabel": "Token"
                }
            }
        }))
        .expect("custom annotation keywords should pass through the profile");
    }

    #[test]
    fn maps_json_schema_validation_error_to_config_schema_path() {
        let schema = json!({
            "type": "object",
            "properties": {
                "token": {
                    "type": 42
                }
            }
        });
        let schema_error = jsonschema::validator_for(&schema).unwrap_err();
        let err = ConfigSchemaProfileError::from_json_schema_validation(&schema_error);

        assert_eq!(err.path, "properties.token.type");
        assert_eq!(err.pointer.as_deref(), Some("/properties/token/type"));
        assert!(err.message.contains("42"));
    }
}
