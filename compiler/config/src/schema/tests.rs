use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;

use super::*;

#[test]
fn collect_leaf_paths_marks_defaulted_leaves() {
    let schema = json!({
        "type": "object",
        "properties": {
            "api_key": { "type": "string" },
            "system_prompt": {
                "type": "string",
                "default": "You are an agent."
            },
            "model": {
                "type": "object",
                "properties": {
                    "reasoning_effort": {
                        "type": "string",
                        "default": "low"
                    },
                    "name": { "type": "string" }
                }
            }
        },
        "required": ["api_key", "system_prompt"]
    });

    let leaves = collect_leaf_paths(&schema).expect("collect leaf paths");
    let by_path = leaves
        .into_iter()
        .map(|leaf| (leaf.path.clone(), leaf))
        .collect::<BTreeMap<_, _>>();

    assert!(by_path["system_prompt"].has_default());
    assert!(!by_path["api_key"].has_default());
    assert!(!by_path["system_prompt"].runtime_required());
    assert!(by_path["api_key"].runtime_required());
    assert_eq!(
        by_path["system_prompt"].default.as_ref(),
        Some(&json!("You are an agent."))
    );
    assert!(by_path["model.reasoning_effort"].has_default());
    assert!(!by_path["model.name"].has_default());
}

#[test]
fn prune_schema_preserves_x_annotations_on_allowed_leaves() {
    let schema = json!({
        "type": "object",
        "properties": {
            "my_config": {
                "type": "string",
                "x-example-hide": true
            },
            "other_config": {
                "type": "string",
                "x-example-hide": false
            }
        },
        "additionalProperties": false
    });

    let allowed_leaf_paths = BTreeSet::from(["my_config".to_string()]);
    let pruned = prune_schema(&schema, &allowed_leaf_paths).expect("schema with x-* annotations");

    assert_eq!(
        pruned,
        json!({
            "type": "object",
            "properties": {
                "my_config": {
                    "type": "string",
                    "x-example-hide": true
                }
            },
            "additionalProperties": false
        })
    );
}

#[test]
fn apply_schema_defaults_fills_missing_fields_without_overriding_null() {
    let schema = json!({
        "type": "object",
        "properties": {
            "system_prompt": {
                "type": "string",
                "default": "You are an agent."
            },
            "model": {
                "type": "object",
                "properties": {
                    "reasoning_effort": {
                        "type": ["string", "null"],
                        "default": "low"
                    },
                    "temperature": {
                        "type": "number",
                        "default": 0.2
                    }
                }
            }
        }
    });

    let mut value = json!({
        "model": {
            "reasoning_effort": null
        }
    });
    apply_schema_defaults(&schema, &mut value).expect("apply defaults");

    assert_eq!(
        value,
        json!({
            "system_prompt": "You are an agent.",
            "model": {
                "reasoning_effort": null,
                "temperature": 0.2
            }
        })
    );
}

#[test]
fn apply_schema_defaults_merges_object_defaults_with_partial_explicit_values() {
    let schema = json!({
        "type": "object",
        "properties": {
            "model": {
                "type": "object",
                "default": {
                    "reasoning_effort": "low",
                    "temperature": 0.2
                },
                "properties": {
                    "reasoning_effort": { "type": "string" },
                    "temperature": { "type": "number" }
                }
            }
        }
    });

    let mut value = json!({
        "model": {
            "temperature": 0.7
        }
    });
    apply_schema_defaults(&schema, &mut value).expect("apply defaults");

    assert_eq!(
        value,
        json!({
            "model": {
                "reasoning_effort": "low",
                "temperature": 0.7
            }
        })
    );
}

#[test]
fn apply_schema_defaults_fills_missing_fields_inside_array_items() {
    let schema = json!({
        "type": "object",
        "properties": {
            "models": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "reasoning_effort": {
                            "type": "string",
                            "default": "low"
                        }
                    },
                    "required": ["name"]
                }
            }
        }
    });

    let mut value = json!({
        "models": [
            { "name": "gpt-5" },
            { "name": "gpt-4.1", "reasoning_effort": "high" }
        ]
    });
    apply_schema_defaults(&schema, &mut value).expect("apply defaults");

    assert_eq!(
        value,
        json!({
            "models": [
                { "name": "gpt-5", "reasoning_effort": "low" },
                { "name": "gpt-4.1", "reasoning_effort": "high" }
            ]
        })
    );
}

#[test]
fn apply_schema_defaults_to_node_inserts_missing_literals_without_overriding_refs() {
    let schema = json!({
        "type": "object",
        "properties": {
            "api_key": { "type": "string" },
            "system_prompt": {
                "type": "string",
                "default": "You are an agent."
            },
            "model": {
                "type": "object",
                "properties": {
                    "reasoning_effort": {
                        "type": "string",
                        "default": "low"
                    },
                    "name": { "type": "string" }
                }
            }
        }
    });
    let mut node = ConfigNode::Object(BTreeMap::from([
        (
            "api_key".to_string(),
            ConfigNode::ConfigRef("api_key".to_string()),
        ),
        (
            "model".to_string(),
            ConfigNode::Object(BTreeMap::from([(
                "name".to_string(),
                ConfigNode::ConfigRef("model.name".to_string()),
            )])),
        ),
    ]));

    apply_schema_defaults_to_node(&schema, &mut node).expect("apply node defaults");

    assert_eq!(
        node.get_path("api_key").expect("api_key"),
        &ConfigNode::ConfigRef("api_key".to_string())
    );
    assert_eq!(
        node.get_path("system_prompt").expect("system_prompt"),
        &ConfigNode::String("You are an agent.".to_string())
    );
    assert_eq!(
        node.get_path("model.reasoning_effort")
            .expect("reasoning_effort"),
        &ConfigNode::String("low".to_string())
    );
    assert_eq!(
        node.get_path("model.name").expect("model.name"),
        &ConfigNode::ConfigRef("model.name".to_string())
    );
}

#[test]
fn schema_path_kind_queries_track_nullability() {
    let schema = json!({
        "type": "object",
        "properties": {
            "required_string": { "type": "string" },
            "nullable_string": { "type": ["string", "null"] },
            "null_only": { "type": "null" }
        }
    });

    assert!(!schema_path_accepts_null(&schema, "required_string").unwrap());
    assert!(schema_path_may_accept_non_null(&schema, "required_string").unwrap());
    assert!(schema_path_accepts_null(&schema, "nullable_string").unwrap());
    assert!(schema_path_may_accept_non_null(&schema, "nullable_string").unwrap());
    assert!(schema_path_accepts_null(&schema, "null_only").unwrap());
    assert!(!schema_path_may_accept_non_null(&schema, "null_only").unwrap());
}

#[test]
fn schema_path_presence_treats_defaulted_objects_as_present() {
    let schema = json!({
        "type": "object",
        "properties": {
            "settings": {
                "type": "object",
                "default": {},
                "properties": {
                    "profile": { "type": "string" }
                }
            }
        }
    });

    assert_eq!(
        schema_path_presence(&schema, "settings").unwrap(),
        SchemaPresence::Present
    );
}

#[test]
fn schema_path_presence_treats_required_objects_as_present() {
    let schema = json!({
        "type": "object",
        "properties": {
            "settings": {
                "type": "object",
                "properties": {
                    "profile": { "type": "string" }
                }
            }
        },
        "required": ["settings"]
    });

    assert_eq!(
        schema_path_presence(&schema, "settings").unwrap(),
        SchemaPresence::Present
    );
}

#[test]
fn schema_path_presence_treats_nullable_defaulted_objects_as_runtime() {
    let schema = json!({
        "type": "object",
        "properties": {
            "settings": {
                "type": ["object", "null"],
                "default": {},
                "properties": {
                    "profile": { "type": "string" }
                }
            }
        }
    });

    assert_eq!(
        schema_path_presence(&schema, "settings").unwrap(),
        SchemaPresence::Runtime
    );
}

#[test]
fn schema_path_presence_treats_defaulted_leaf_under_nullable_ancestor_as_runtime() {
    let schema = json!({
        "type": "object",
        "properties": {
            "settings": {
                "type": ["object", "null"],
                "properties": {
                    "mode": {
                        "type": "string",
                        "default": "safe"
                    }
                }
            }
        }
    });

    assert_eq!(
        schema_path_presence(&schema, "settings.mode").unwrap(),
        SchemaPresence::Runtime
    );
}

#[test]
fn schema_path_presence_treats_defaulted_leaf_under_non_object_ancestor_as_runtime() {
    let schema = json!({
        "type": "object",
        "properties": {
            "settings": {
                "type": ["object", "string"],
                "properties": {
                    "mode": {
                        "type": "string",
                        "default": "safe"
                    }
                }
            }
        }
    });

    assert_eq!(
        schema_path_presence(&schema, "settings.mode").unwrap(),
        SchemaPresence::Runtime
    );
}

#[test]
fn schema_path_is_required_combines_all_of_required_constraints_across_levels() {
    let schema = json!({
        "type": "object",
        "allOf": [
            {
                "required": ["settings"]
            },
            {
                "properties": {
                    "settings": {
                        "type": "object",
                        "required": ["mode"],
                        "properties": {
                            "mode": { "type": "string" }
                        }
                    }
                }
            }
        ]
    });

    assert!(schema_path_is_required(&schema, "settings").unwrap());
    assert!(schema_path_is_required(&schema, "settings.mode").unwrap());
}

#[test]
fn collect_leaf_paths_combines_all_of_required_constraints_across_levels() {
    let schema = json!({
        "type": "object",
        "allOf": [
            {
                "required": ["settings"]
            },
            {
                "properties": {
                    "settings": {
                        "type": "object",
                        "required": ["mode"],
                        "properties": {
                            "mode": { "type": "string" }
                        }
                    }
                }
            }
        ]
    });

    let leaves = collect_leaf_paths(&schema).expect("collect leaf paths");
    let by_path = leaves
        .into_iter()
        .map(|leaf| (leaf.path.clone(), leaf))
        .collect::<BTreeMap<_, _>>();

    assert!(by_path["settings.mode"].required);
}
