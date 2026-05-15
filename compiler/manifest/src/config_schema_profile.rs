use std::sync::OnceLock;

use amber_config::is_valid_config_key;
use jsonschema::Validator;
use serde_json::Value;

const PROFILE_ID: &str = "https://amber-protocol.org/json-schema/config-schema-profile";
const CONFIG_KEY_RULE: &str = "must start with a lowercase ASCII letter and contain only \
                               lowercase ASCII letters, digits, and underscores; double \
                               underscores are not allowed";

#[derive(Clone, Debug)]
pub(crate) struct ProfileError {
    pub(crate) path: String,
    pub(crate) message: String,
    pub(crate) pointer: Option<String>,
    pub(crate) key: Option<String>,
}

impl ProfileError {
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

fn pointer_to_path(pointer: &str) -> String {
    let path = pointer
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(unescape_json_pointer_segment)
        .collect::<Vec<_>>()
        .join(".");
    display_path(&path)
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
) -> Result<(), ProfileError> {
    if type_includes_object(schema) {
        return Ok(());
    }

    let message = format!(
        "schema objects with `{keyword}` must declare `type: \"object\"` or include \"object\" in \
         their `type` array"
    );
    if schema.get("type").is_some() {
        Err(ProfileError::at_value(
            pointer_child(pointer, "type"),
            path_child(path, "type"),
            message,
        ))
    } else {
        Err(ProfileError::at_value(pointer, path, message))
    }
}

fn unsupported_keyword_message(keyword: &str) -> String {
    format!("unsupported config_schema keyword `{keyword}`")
}

fn find_profile_violation(schema: &Value) -> Option<ProfileError> {
    if !schema.is_object() {
        return Some(ProfileError::at_root(
            "root config_schema must be a JSON Schema object with `type: \"object\"`".to_string(),
        ));
    }
    if !type_includes_object(schema) {
        return Some(ProfileError::at_value(
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
    walk_schema(schema, "", "").err()
}

fn walk_schema(schema: &Value, pointer: &str, path: &str) -> Result<(), ProfileError> {
    let Some(obj) = schema.as_object() else {
        return Ok(());
    };

    if let Some(schema_uri) = obj.get("$schema")
        && schema_uri
            .as_str()
            .is_some_and(|uri| !is_draft_2020_12_schema(uri))
    {
        return Err(ProfileError::at_value(
            pointer_child(pointer, "$schema"),
            path_child(path, "$schema"),
            "`$schema` must be Draft 2020-12 for Amber config_schema".to_string(),
        ));
    }

    if let Some(reference) = obj.get("$ref")
        && reference
            .as_str()
            .is_some_and(|reference| reference != "#" && !reference.starts_with("#/"))
    {
        return Err(ProfileError::at_value(
            pointer_child(pointer, "$ref"),
            path_child(path, "$ref"),
            "`$ref` must be local to the same config_schema (`#` or `#/...`)".to_string(),
        ));
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
            return Err(ProfileError::at_key(
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
        return Err(ProfileError::at_value(
            pointer_child(pointer, "secret"),
            path_child(path, "secret"),
            "`secret` must be a boolean annotation".to_string(),
        ));
    }

    if let Some(additional) = obj.get("additionalProperties")
        && !additional.is_boolean()
    {
        return Err(ProfileError::at_value(
            pointer_child(pointer, "additionalProperties"),
            path_child(path, "additionalProperties"),
            "`additionalProperties` must be a boolean in Amber config_schema".to_string(),
        ));
    }

    if let Some(properties) = obj.get("properties") {
        check_object_type_for_keyword(schema, pointer, path, "properties")?;
        if let Some(properties) = properties.as_object() {
            let properties_pointer = pointer_child(pointer, "properties");
            let properties_path = path_child(path, "properties");
            for (key, child_schema) in properties {
                if !is_valid_config_key(key) {
                    return Err(ProfileError::at_key(
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
    }

    if let Some(required) = obj.get("required") {
        check_object_type_for_keyword(schema, pointer, path, "required")?;
        if let Some(required) = required.as_array() {
            for (idx, required_key) in required.iter().enumerate() {
                if let Some(required_key) = required_key.as_str()
                    && !is_valid_config_key(required_key)
                {
                    return Err(ProfileError::at_value(
                        pointer_index(&pointer_child(pointer, "required"), idx),
                        path_index(&path_child(path, "required"), idx),
                        invalid_config_key_message("required config property name", required_key),
                    ));
                }
            }
        }
    }

    for keyword in ["$defs", "definitions"] {
        if let Some(defs) = obj.get(keyword).and_then(Value::as_object) {
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
    }

    if let Some(all_of) = obj.get("allOf").and_then(Value::as_array) {
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

    if let Some(prefix_items) = obj.get("prefixItems").and_then(Value::as_array) {
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

fn profile_meta_schema() -> Value {
    // This is a JSON Schema meta-schema (Draft 2020-12) used to validate the `config_schema`
    // objects that Amber accepts in manifests.
    //
    // It intentionally restricts authors to a deterministic subset that Amber tooling supports
    // (static config ref validation, leaf enumeration, env-var mapping, etc.).
    //
    // Note: Avoid internal `$ref`s to `#/$defs/...` here. The `jsonschema` crate's reference
    // resolution can treat in-document refs as relative to a referenced meta-schema in some
    // cases, which makes `#/$defs/...` unexpectedly point at the wrong document.
    let key_name = serde_json::json!({
        "type": "string",
        "pattern": "^(?!.*__)[a-z][a-z0-9_]*$",
    });
    let type_includes_object = serde_json::json!({
        "anyOf": [
            { "const": "object" },
            {
                "type": "array",
                "contains": { "const": "object" },
            },
        ],
    });

    let meta_schema = serde_json::json!({
        "$dynamicAnchor": "meta",
        "anyOf": [
            { "type": "boolean" },
            {
                "$ref": "https://json-schema.org/draft/2020-12/schema",
                "unevaluatedProperties": false,
                "properties": {
                    "$schema": {
                        "type": "string",
                        "pattern": "^https?://json-schema.org/draft/2020-12/schema#?$",
                    },
                    "$ref": {
                        "type": "string",
                        "pattern": "^#($|/.*)$",
                    },
                    "properties": {
                        "type": "object",
                        "propertyNames": key_name.clone(),
                    },
                    "required": {
                        "type": "array",
                        "items": key_name.clone(),
                    },
                    "additionalProperties": { "type": "boolean" },
                    "secret": { "type": "boolean" },

                    "anyOf": false,
                    "oneOf": false,
                    "not": false,
                    "if": false,
                    "then": false,
                    "else": false,
                    "patternProperties": false,
                    "propertyNames": false,
                    "dependentSchemas": false,
                    "dependentRequired": false,
                    "unevaluatedProperties": false,
                    "unevaluatedItems": false,
                    "$dynamicRef": false,
                    "$recursiveRef": false,
                },
                "patternProperties": {
                    "^x-": true,
                },
                "allOf": [
                    {
                        "if": { "required": ["properties"] },
                        "then": {
                            "required": ["type"],
                            "properties": { "type": type_includes_object.clone() },
                        },
                    },
                    {
                        "if": { "required": ["required"] },
                        "then": {
                            "required": ["type"],
                            "properties": { "type": type_includes_object.clone() },
                        },
                    },
                ],
            },
        ],
    });

    let root_schema = serde_json::json!({
        "type": "object",
        "required": ["type"],
        "properties": {
            "type": type_includes_object,
        },
    });

    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": PROFILE_ID,
        "title": "Amber config_schema profile",
        "description": "Restricts JSON Schema to the subset supported by Amber for `config_schema`.",
        "allOf": [meta_schema, root_schema],
    })
}

fn profile_validator() -> Result<&'static Validator, String> {
    static VALIDATOR: OnceLock<Result<Validator, String>> = OnceLock::new();
    let validator = VALIDATOR.get_or_init(|| {
        jsonschema::validator_for(&profile_meta_schema()).map_err(|err| {
            format!("internal error: failed to build Amber config_schema profile validator: {err}")
        })
    });

    match validator {
        Ok(validator) => Ok(validator),
        Err(err) => Err(err.clone()),
    }
}

pub(crate) fn validate(schema: &Value) -> Result<(), ProfileError> {
    if let Some(err) = find_profile_violation(schema) {
        return Err(err);
    }

    let v = profile_validator().map_err(ProfileError::at_root)?;

    let mut errs = v.iter_errors(schema);
    let Some(first) = errs.next() else {
        return Ok(());
    };

    let pointer = first.instance_path().to_string();
    let path = pointer_to_path(&pointer);
    let rejected = errs.take(7).count() + 1;
    let suffix = if rejected == 1 {
        String::new()
    } else {
        format!(" ({rejected} profile violations found)")
    };
    Err(ProfileError::at_value(
        pointer,
        path,
        format!("does not match Amber config_schema profile{suffix}"),
    ))
}

#[cfg(test)]
mod tests {
    use crate::{Error, Manifest};

    fn invalid_config_schema(input: &str) -> (String, String) {
        match input.parse::<Manifest>().unwrap_err() {
            Error::InvalidConfigSchema { path, message, .. } => (path, message),
            other => panic!("expected InvalidConfigSchema error, got: {other}"),
        }
    }

    #[test]
    fn config_schema_profile_rejects_pattern_properties() {
        let input = r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            patternProperties: {
              ".*": { type: "string" },
            },
          },
        }
        "#;
        let (path, message) = invalid_config_schema(input);
        assert_eq!(path, "patternProperties");
        assert_eq!(
            message,
            "unsupported config_schema keyword `patternProperties`"
        );
    }

    #[test]
    fn config_schema_profile_rejects_uppercase_property_name() {
        let input = r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: {
              agent_HF_TOKEN: { type: "string", secret: true },
            },
          },
        }
        "#;
        let (path, message) = invalid_config_schema(input);
        assert_eq!(path, "properties.agent_HF_TOKEN");
        assert!(message.contains("Uppercase letters are not allowed"));
        assert!(message.contains("use `agent_hf_token` instead"));
    }

    #[test]
    fn config_schema_profile_accepts_secret_annotation() {
        let input = r#"
        {
          manifest_version: "0.1.0",
              config_schema: {
                type: "object",
                properties: {
                  token: { type: "string", secret: true },
                  group: {
                    type: "object",
                    secret: true,
                    properties: {
                      url: { type: "string" },
                    },
                  },
                },
              },
            }
            "#;
        let _ = input
            .parse::<Manifest>()
            .expect("schema with secret annotations should parse");
    }

    #[test]
    fn config_schema_profile_accepts_x_annotations() {
        let input = r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: {
              my_config: {
                type: "string",
                "x-example-hide": true,
              },
              nested: {
                type: "object",
                "x-example-section": "advanced",
                properties: {
                  enabled: {
                    type: "boolean",
                    "x-example-label": "Enable advanced mode",
                  },
                },
              },
            },
          },
        }
        "#;
        let _ = input
            .parse::<Manifest>()
            .expect("schema with x-* annotations should parse");
    }

    #[test]
    fn config_schema_profile_rejects_non_2020_12_draft() {
        let input = r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            $schema: "http://json-schema.org/draft-07/schema#",
            type: "object",
            properties: { x: { type: "string" } },
          },
        }
        "#;
        let (path, message) = invalid_config_schema(input);
        assert_eq!(path, "$schema");
        assert_eq!(
            message,
            "`$schema` must be Draft 2020-12 for Amber config_schema"
        );
    }

    #[test]
    fn config_schema_profile_rejects_non_pointer_ref() {
        let input = r##"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            $defs: {
              x: { $anchor: "x", type: "string" },
            },
            properties: {
              prop: { $ref: "#x" },
            },
          },
        }
        "##;
        let (path, message) = invalid_config_schema(input);
        assert_eq!(path, "properties.prop.$ref");
        assert_eq!(
            message,
            "`$ref` must be local to the same config_schema (`#` or `#/...`)"
        );
    }
}
