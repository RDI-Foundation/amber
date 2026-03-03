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
    let mut candidates: Vec<Value> = Vec::new();
    let mut parsed_json = None;

    if let Ok(v) = serde_json::from_str::<Value>(raw) {
        parsed_json = Some(v.clone());
        candidates.push(v);
    }

    if raw == "true" {
        candidates.push(Value::Bool(true));
    } else if raw == "false" {
        candidates.push(Value::Bool(false));
    }

    let mut parsed_integer = false;
    if let Ok(i) = raw.parse::<i64>() {
        candidates.push(Value::Number(i.into()));
        parsed_integer = true;
    }

    if !parsed_integer
        && let Ok(f) = raw.parse::<f64>()
        && let Some(n) = serde_json::Number::from_f64(f)
    {
        candidates.push(Value::Number(n));
    }

    let skip_raw_string = parsed_json
        .as_ref()
        .is_some_and(|value| matches!(value, Value::String(_)));
    if !skip_raw_string {
        candidates.push(Value::String(raw.to_string()));
    }

    let mut deduped: Vec<Value> = Vec::new();
    for c in candidates {
        if !deduped.contains(&c) {
            deduped.push(c);
        }
    }

    let validator = jsonschema::validator_for(leaf_schema)
        .map_err(|e| ConfigError::schema(format!("failed to compile leaf schema: {e}")))?;

    let mut valid: Vec<Value> = Vec::new();
    for c in deduped {
        let is_valid = {
            let mut it = validator.iter_errors(&c);
            it.next().is_none()
        };
        if is_valid {
            valid.push(c);
        }
    }

    match valid.len() {
        1 => Ok(valid.remove(0)),
        0 => {
            let c = Value::String(raw.to_string());
            let mut it = validator.iter_errors(&c);
            let msg = it
                .next()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "value does not match schema".to_string());
            Err(ConfigError::validation(msg))
        }
        _ => Err(ConfigError::validation(format!(
            "ambiguous value {raw:?}: multiple interpretations match the schema; disambiguate by \
             using an explicit JSON literal (e.g. \"\\\"123\\\"\" for strings)"
        ))),
    }
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

    let out = Value::Object(obj);

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
