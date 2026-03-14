use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::{ConfigError, Result, collect_leaf_paths, schema_lookup_ref};

pub const CONFIG_ENV_PREFIX: &str = "AMBER_CONFIG_";

pub fn env_var_for_path(path: &str) -> Result<String> {
    if path.is_empty() {
        return Err(ConfigError::schema(
            "config path cannot be empty".to_string(),
        ));
    }
    let mut segs = Vec::new();
    for seg in path.split('.') {
        if seg.is_empty() {
            return Err(ConfigError::schema(format!(
                "invalid config path {path:?}: empty segment"
            )));
        }
        if !crate::is_valid_config_key(seg) {
            return Err(ConfigError::schema(format!(
                "invalid config path segment {seg:?} in {path:?} (must match ^[a-z][a-z0-9_]*$ \
                 and must not contain '__')"
            )));
        }
        segs.push(seg.to_ascii_uppercase());
    }
    Ok(format!("{}{}", CONFIG_ENV_PREFIX, segs.join("__")))
}

pub fn env_var_to_path(var: &str) -> Result<String> {
    let rest = var
        .strip_prefix(CONFIG_ENV_PREFIX)
        .ok_or_else(|| ConfigError::msg("not an AMBER_CONFIG_* var".to_string()))?;
    if rest.is_empty() {
        return Err(ConfigError::msg(format!(
            "invalid env var {var:?}: missing path suffix"
        )));
    }

    let segs = rest
        .split("__")
        .map(|s| s.to_ascii_lowercase())
        .collect::<Vec<_>>();
    Ok(segs.join("."))
}

pub fn parse_env_value(raw: &str, leaf_schema: &Value) -> Result<Value> {
    let validator = jsonschema::validator_for(leaf_schema)
        .map_err(|e| ConfigError::schema(format!("failed to compile leaf schema: {e}")))?;

    let schema_accepts = |value: &Value| {
        let mut it = validator.iter_errors(value);
        it.next().is_none()
    };

    let parsed_json = serde_json::from_str::<Value>(raw).ok();
    if let Some(value) = parsed_json.as_ref()
        && schema_accepts(value)
    {
        return Ok(value.clone());
    }

    let string_value = Value::String(raw.to_string());
    if schema_accepts(&string_value) {
        return Ok(string_value);
    }

    let msg = parsed_json
        .as_ref()
        .and_then(|value| validator.iter_errors(value).next())
        .or_else(|| validator.iter_errors(&string_value).next())
        .map(|err| err.to_string())
        .unwrap_or_else(|| "value does not match schema".to_string());
    Err(ConfigError::validation(msg))
}

pub fn encode_env_value(value: &Value) -> Result<String> {
    serde_json::to_string(value)
        .map_err(|err| ConfigError::msg(format!("failed to encode env value: {err}")))
}

pub fn build_root_config(
    root_schema: &Value,
    config_env: &BTreeMap<String, String>,
) -> Result<Value> {
    let leafs = collect_leaf_paths(root_schema)?;
    let mut leaf_paths = BTreeSet::new();
    for leaf in leafs {
        leaf_paths.insert(leaf.path);
    }

    let mut obj = serde_json::Map::new();

    for (k, v) in config_env {
        let path = env_var_to_path(k)?;
        if !leaf_paths.contains(&path) {
            return Err(ConfigError::schema(format!(
                "{k} does not correspond to a leaf schema path"
            )));
        }

        if v.is_empty() {
            continue;
        }

        let leaf_schema = schema_lookup_ref(root_schema, &path)?;
        let parsed = parse_env_value(v, leaf_schema)?;
        insert_path(&mut obj, &path, parsed)?;
    }

    let mut out = Value::Object(obj);
    crate::apply_schema_defaults(root_schema, &mut out)?;

    let validator = jsonschema::validator_for(root_schema)
        .map_err(|e| ConfigError::schema(format!("failed to compile root schema: {e}")))?;
    {
        let mut it = validator.iter_errors(&out);
        if let Some(first) = it.next() {
            let mut msgs = vec![first.to_string()];
            msgs.extend(it.take(7).map(|e| e.to_string()));
            return Err(ConfigError::validation(msgs.join("; ")));
        }
    }

    Ok(out)
}

fn insert_path(root: &mut serde_json::Map<String, Value>, path: &str, value: Value) -> Result<()> {
    let segs = path.split('.').collect::<Vec<_>>();
    let mut cur = root;
    for (idx, seg) in segs.iter().enumerate() {
        if idx == segs.len() - 1 {
            cur.insert(seg.to_string(), value);
            return Ok(());
        }

        let entry = cur
            .entry(seg.to_string())
            .or_insert_with(|| Value::Object(Default::default()));
        let Value::Object(m) = entry else {
            return Err(ConfigError::schema(format!(
                "cannot set {path:?}: parent segment {seg:?} is not an object"
            )));
        };
        cur = m;
    }
    Ok(())
}
