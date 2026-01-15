mod env;
mod error;
mod node;
mod schema;
mod template;

pub use env::{
    CONFIG_ENV_PREFIX, build_root_config, env_var_for_path, env_var_to_path, parse_env_value,
};
pub use error::{ConfigError, Result};
pub use node::{ConfigNode, RootConfigTemplate, compose_config_template};
pub use schema::{
    SchemaLeaf, SchemaLookup, SchemaWalkResult, canonical_json, collect_leaf_paths,
    collect_schema_leaves, is_valid_config_key, schema_lookup, schema_lookup_ref,
    validate_config_schema,
};
pub use template::{
    eval_config_template, get_by_path, render_template_string, stringify_for_interpolation,
    template_string_is_runtime,
};

#[cfg(test)]
mod tests {
    use amber_template::ConfigTemplatePayload;
    use serde_json::json;

    use super::*;

    #[test]
    fn root_config_skips_empty_env_values() {
        let schema = json!({
            "type": "object",
            "properties": {
                "db": {
                    "type": "object",
                    "properties": {
                        "url": { "type": "string" },
                        "pool": { "type": "integer" }
                    },
                    "required": ["url"]
                }
            },
            "required": ["db"]
        });

        let env = std::collections::BTreeMap::from([
            (
                "AMBER_CONFIG_DB__URL".to_string(),
                "postgres://db".to_string(),
            ),
            ("AMBER_CONFIG_DB__POOL".to_string(), "".to_string()),
        ]);

        let config = build_root_config(&schema, &env).expect("config should parse");
        let url = get_by_path(&config, "db.url").expect("db.url should exist");
        assert_eq!(url, "postgres://db");
        assert!(get_by_path(&config, "db.pool").is_err());
    }

    #[test]
    fn ambiguous_value_requires_disambiguation() {
        let schema = json!({
            "type": ["integer", "string"]
        });

        let err = parse_env_value("123", &schema).expect_err("ambiguous value should error");
        assert!(
            err.to_string().contains("ambiguous value"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn json_string_literal_is_unambiguous() {
        let schema = json!({
            "type": ["integer", "string"]
        });

        let value = parse_env_value("\"123\"", &schema).expect("json string literal should parse");
        assert_eq!(value, serde_json::Value::String("123".to_string()));
    }

    #[test]
    fn component_config_template_inserts_values() {
        let root = json!({
            "api": { "token": "secret" },
            "limits": { "max_jobs": 3 }
        });

        let template_value = json!({
            "token": { "$config": "api.token" },
            "limits": { "$config": "limits" },
            "label": { "$template": [
                { "lit": "token=" },
                { "config": "api.token" }
            ] }
        });

        let template =
            ConfigTemplatePayload::from_value(template_value).expect("template should parse");
        let config = eval_config_template(&template, &root).expect("config should resolve");

        assert_eq!(
            config,
            json!({
                "token": "secret",
                "limits": { "max_jobs": 3 },
                "label": "token=secret"
            })
        );
    }

    #[test]
    fn collect_leaf_paths_accepts_property_only_schema() {
        let schema = json!({
            "properties": {
                "db": {
                    "properties": {
                        "url": { "type": "string" },
                        "pool": { "type": "integer" }
                    },
                    "required": ["url"]
                }
            },
            "required": ["db"]
        });

        let leaves = collect_leaf_paths(&schema).expect("collect leaf paths");
        let mut required_by_path = std::collections::BTreeMap::new();
        let mut secret_by_path = std::collections::BTreeMap::new();
        for leaf in leaves {
            required_by_path.insert(leaf.path.clone(), leaf.required);
            secret_by_path.insert(leaf.path, leaf.secret);
        }

        assert_eq!(required_by_path.len(), 2);
        assert_eq!(required_by_path.get("db.url"), Some(&true));
        assert_eq!(required_by_path.get("db.pool"), Some(&false));
        assert_eq!(secret_by_path.get("db.url"), Some(&false));
        assert_eq!(secret_by_path.get("db.pool"), Some(&false));
    }

    #[test]
    fn collect_leaf_paths_tracks_secrets() {
        let schema = json!({
            "type": "object",
            "properties": {
                "api": {
                    "type": "object",
                    "secret": true,
                    "properties": {
                        "token": { "type": "string" },
                        "endpoint": { "type": "string" }
                    }
                },
                "public": { "type": "string" },
                "token": { "type": "string", "secret": true }
            }
        });

        let leaves = collect_leaf_paths(&schema).expect("collect leaf paths");
        let mut secret_by_path = std::collections::BTreeMap::new();
        for leaf in leaves {
            secret_by_path.insert(leaf.path, leaf.secret);
        }

        assert_eq!(secret_by_path.get("api.token"), Some(&true));
        assert_eq!(secret_by_path.get("api.endpoint"), Some(&true));
        assert_eq!(secret_by_path.get("public"), Some(&false));
        assert_eq!(secret_by_path.get("token"), Some(&true));
    }

    #[test]
    fn collect_leaf_paths_tracks_secrets_through_ref() {
        let schema = json!({
            "type": "object",
            "properties": {
                "api": { "$ref": "#/$defs/api" },
                "api_secret": { "$ref": "#/$defs/api_secret" },
                "auth": { "$ref": "#/$defs/api", "secret": true },
            },
            "$defs": {
                "api": {
                    "type": "object",
                    "properties": {
                        "token": { "type": "string" },
                        "endpoint": { "type": "string" },
                    }
                },
                "api_secret": {
                    "type": "object",
                    "secret": true,
                    "properties": {
                        "token": { "type": "string" },
                        "endpoint": { "type": "string" },
                    }
                },
            }
        });

        let leaves = collect_leaf_paths(&schema).expect("collect leaf paths");
        let mut secret_by_path = std::collections::BTreeMap::new();
        for leaf in leaves {
            secret_by_path.insert(leaf.path, leaf.secret);
        }

        assert_eq!(secret_by_path.get("api.token"), Some(&false));
        assert_eq!(secret_by_path.get("api.endpoint"), Some(&false));
        assert_eq!(secret_by_path.get("api_secret.token"), Some(&true));
        assert_eq!(secret_by_path.get("api_secret.endpoint"), Some(&true));
        assert_eq!(secret_by_path.get("auth.token"), Some(&true));
        assert_eq!(secret_by_path.get("auth.endpoint"), Some(&true));
    }

    #[test]
    fn collect_leaf_paths_tracks_secrets_through_allof() {
        let schema = json!({
            "type": "object",
            "properties": {
                "token": {
                    "allOf": [
                        { "type": "string" },
                        { "secret": true },
                    ]
                },
            }
        });

        let leaves = collect_leaf_paths(&schema).expect("collect leaf paths");
        let mut secret_by_path = std::collections::BTreeMap::new();
        for leaf in leaves {
            secret_by_path.insert(leaf.path, leaf.secret);
        }

        assert_eq!(secret_by_path.get("token"), Some(&true));
    }
}
