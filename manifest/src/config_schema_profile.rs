use std::sync::OnceLock;

use jsonschema::Validator;
use serde_json::Value;

const PROFILE_ID: &str = "https://amber-protocol.org/json-schema/config-schema-profile";

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

pub fn validate(schema: &Value) -> Result<(), String> {
    let v = profile_validator()?;

    let mut errs = v.iter_errors(schema);
    let Some(first) = errs.next() else {
        return Ok(());
    };

    let at = first.instance_path().to_string();
    let mut msgs = vec![first.to_string()];
    msgs.extend(errs.take(7).map(|e| e.to_string()));

    let at = if at.is_empty() { "<root>" } else { at.as_str() };
    Err(format!(
        "does not match Amber config_schema profile at {at}: {}",
        msgs.join("; ")
    ))
}
