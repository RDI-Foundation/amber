use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
};

use amber_template::{
    ConfigTemplate, ConfigTemplatePayload, TemplatePart, TemplateSpec, TemplateString,
};
use base64::Engine as _;
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

const ROOT_SCHEMA_ENV: &str = "AMBER_ROOT_CONFIG_SCHEMA_B64";
const COMPONENT_SCHEMA_ENV: &str = "AMBER_COMPONENT_CONFIG_SCHEMA_B64";
const COMPONENT_TEMPLATE_ENV: &str = "AMBER_COMPONENT_CONFIG_TEMPLATE_B64";
const TEMPLATE_SPEC_ENV: &str = "AMBER_TEMPLATE_SPEC_B64";
const CONFIG_PREFIX: &str = "AMBER_CONFIG_";

#[derive(Debug, Error)]
pub enum HelperError {
    #[error("{0}")]
    Msg(String),

    #[error("invalid base64 in {name}: {source}")]
    Base64 {
        name: &'static str,
        #[source]
        source: base64::DecodeError,
    },

    #[error("invalid json in {name}: {source}")]
    Json {
        name: &'static str,
        #[source]
        source: serde_json::Error,
    },

    #[error("schema error: {0}")]
    Schema(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("interpolation error: {0}")]
    Interp(String),
}

pub type Result<T> = std::result::Result<T, HelperError>;

#[derive(Clone, Debug)]
pub struct RunPlan {
    pub entrypoint: Vec<String>,
    pub env: BTreeMap<OsString, OsString>,
}

pub fn build_run_plan(env: impl IntoIterator<Item = (OsString, OsString)>) -> Result<RunPlan> {
    let mut passthrough_env = BTreeMap::new();
    let mut config_env = BTreeMap::new();
    let mut root_schema_b64 = None;
    let mut component_schema_b64 = None;
    let mut component_template_b64 = None;
    let mut template_spec_b64 = None;

    for (key, value) in env {
        let Some(key_str) = key.to_str() else {
            passthrough_env.insert(key, value);
            continue;
        };

        match key_str {
            ROOT_SCHEMA_ENV => {
                let value = value
                    .into_string()
                    .map_err(|_| HelperError::Msg(format!("{ROOT_SCHEMA_ENV} is required")))?;
                root_schema_b64 = Some(value);
            }
            COMPONENT_SCHEMA_ENV => {
                let value = value
                    .into_string()
                    .map_err(|_| HelperError::Msg(format!("{COMPONENT_SCHEMA_ENV} is required")))?;
                component_schema_b64 = Some(value);
            }
            COMPONENT_TEMPLATE_ENV => {
                let value = value.into_string().map_err(|_| {
                    HelperError::Msg(format!("{COMPONENT_TEMPLATE_ENV} is required"))
                })?;
                component_template_b64 = Some(value);
            }
            TEMPLATE_SPEC_ENV => {
                let value = value
                    .into_string()
                    .map_err(|_| HelperError::Msg(format!("{TEMPLATE_SPEC_ENV} is required")))?;
                template_spec_b64 = Some(value);
            }
            _ if key_str.starts_with(CONFIG_PREFIX) => {
                if let Ok(value) = value.into_string() {
                    config_env.insert(key_str.to_string(), value);
                }
            }
            _ => {
                passthrough_env.insert(key, value);
            }
        }
    }

    let root_schema_b64 = root_schema_b64
        .ok_or_else(|| HelperError::Msg(format!("{ROOT_SCHEMA_ENV} is required")))?;
    let component_schema_b64 = component_schema_b64
        .ok_or_else(|| HelperError::Msg(format!("{COMPONENT_SCHEMA_ENV} is required")))?;
    let component_template_b64 = component_template_b64
        .ok_or_else(|| HelperError::Msg(format!("{COMPONENT_TEMPLATE_ENV} is required")))?;
    let template_spec_b64 = template_spec_b64
        .ok_or_else(|| HelperError::Msg(format!("{TEMPLATE_SPEC_ENV} is required")))?;

    let root_schema = decode_b64_json(ROOT_SCHEMA_ENV, &root_schema_b64)?;
    let component_schema = decode_b64_json(COMPONENT_SCHEMA_ENV, &component_schema_b64)?;
    let component_template_value =
        decode_b64_json(COMPONENT_TEMPLATE_ENV, &component_template_b64)?;
    let component_template = ConfigTemplatePayload::from_value(component_template_value)
        .map_err(|err| HelperError::Interp(format!("invalid component config template: {err}")))?;
    let spec = decode_b64_json_t::<TemplateSpec>(TEMPLATE_SPEC_ENV, &template_spec_b64)?;

    // 1) Parse and validate root config from AMBER_CONFIG_* using the root schema.
    let root_config = build_root_config(&root_schema, &config_env)?;

    // 2) Resolve component config from template.
    let component_config = eval_config_template(&component_template, &root_config)?;

    if !component_config.is_object() {
        return Err(HelperError::Schema(
            "resolved component config must be an object".to_string(),
        ));
    }

    // 3) Validate component config against component schema.
    let validator = jsonschema::validator_for(&component_schema)
        .map_err(|e| HelperError::Schema(format!("failed to compile component schema: {e}")))?;
    let mut it = validator.iter_errors(&component_config);
    if let Some(first) = it.next() {
        let mut msgs = vec![first.to_string()];
        msgs.extend(it.take(7).map(|e| e.to_string()));
        return Err(HelperError::Validation(msgs.join("; ")));
    }

    // 4) Render program entrypoint + env.
    if spec.program.entrypoint.is_empty() {
        return Err(HelperError::Interp(
            "program.entrypoint is empty; cannot exec".to_string(),
        ));
    }

    let mut entrypoint: Vec<String> = Vec::with_capacity(spec.program.entrypoint.len());
    for ts in &spec.program.entrypoint {
        entrypoint.push(render_template_string(ts, &component_config)?);
    }

    let mut rendered_env: BTreeMap<String, String> = BTreeMap::new();
    for (k, ts) in &spec.program.env {
        rendered_env.insert(k.clone(), render_template_string(ts, &component_config)?);
    }

    // 5) Build environment for exec: inherit, remove helper-owned, apply rendered env.
    let mut env_out = passthrough_env;
    for (k, v) in rendered_env {
        env_out.insert(OsString::from(k), OsString::from(v));
    }

    Ok(RunPlan {
        entrypoint,
        env: env_out,
    })
}

fn decode_b64_json(name: &'static str, raw: &str) -> Result<Value> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw.as_bytes())
        .map_err(|e| HelperError::Base64 { name, source: e })?;
    serde_json::from_slice::<Value>(&bytes).map_err(|e| HelperError::Json { name, source: e })
}

fn decode_b64_json_t<T: for<'de> Deserialize<'de>>(name: &'static str, raw: &str) -> Result<T> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw.as_bytes())
        .map_err(|e| HelperError::Base64 { name, source: e })?;
    serde_json::from_slice::<T>(&bytes).map_err(|e| HelperError::Json { name, source: e })
}

fn schema_properties(schema: &Value) -> Option<&serde_json::Map<String, Value>> {
    schema.get("properties")?.as_object()
}

fn schema_type_includes(schema: &Value, ty: &str) -> bool {
    match schema.get("type") {
        Some(Value::String(s)) => s == ty,
        Some(Value::Array(arr)) => arr.iter().any(|v| v.as_str() == Some(ty)),
        _ => false,
    }
}

fn collect_leaf_paths(schema: &Value) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let has_children = walk_leaf_paths(schema, schema, "", &mut visited, &mut out)?;
    if !has_children {
        return Err(HelperError::Schema(
            "root config_schema must be an object schema (type: \"object\" or properties: {...})"
                .to_string(),
        ));
    }
    Ok(out)
}

fn walk_leaf_paths(
    schema: &Value,
    root: &Value,
    prefix: &str,
    visited: &mut BTreeSet<String>,
    out: &mut BTreeSet<String>,
) -> Result<bool> {
    let schema = resolve_schema_ref(schema, root, visited)?;
    ensure_schema_supported(schema)?;

    let mut did_traverse = false;

    if let Some(props) = schema_properties(schema) {
        let mut keys = props.keys().collect::<Vec<_>>();
        keys.sort();

        for k in keys {
            let child = props.get(k.as_str()).expect("key exists");
            let path = if prefix.is_empty() {
                k.to_string()
            } else {
                format!("{prefix}.{k}")
            };

            did_traverse = true;
            let _ = walk_leaf_paths(child, root, &path, visited, out)?;
        }
    }

    if let Some(all_of) = schema.get("allOf").and_then(|v| v.as_array()) {
        for subschema in all_of {
            did_traverse = true;
            let _ = walk_leaf_paths(subschema, root, prefix, visited, out)?;
        }
    }

    if !did_traverse && !prefix.is_empty() {
        out.insert(prefix.to_string());
    }

    Ok(did_traverse)
}

fn ensure_schema_supported(schema: &Value) -> Result<()> {
    let Value::Object(map) = schema else {
        return Ok(());
    };
    let unsupported = [
        ("anyOf", "anyOf"),
        ("oneOf", "oneOf"),
        ("not", "not"),
        ("patternProperties", "patternProperties"),
        ("propertyNames", "propertyNames"),
        ("dependentSchemas", "dependentSchemas"),
        ("unevaluatedProperties", "unevaluatedProperties"),
    ];
    for (key, name) in unsupported {
        if map.contains_key(key) {
            return Err(HelperError::Schema(format!(
                "unsupported config_schema feature {name}"
            )));
        }
    }
    if map.contains_key("if") || map.contains_key("then") || map.contains_key("else") {
        return Err(HelperError::Schema(
            "unsupported config_schema feature if/then/else".to_string(),
        ));
    }
    if let Some(additional) = map.get("additionalProperties")
        && !additional.is_boolean()
    {
        return Err(HelperError::Schema(
            "unsupported config_schema feature additionalProperties (schema)".to_string(),
        ));
    }
    Ok(())
}

fn resolve_schema_ref<'a>(
    schema: &'a Value,
    root: &'a Value,
    visited: &mut BTreeSet<String>,
) -> Result<&'a Value> {
    let Value::Object(map) = schema else {
        return Ok(schema);
    };
    let Some(reference) = map.get("$ref").and_then(|v| v.as_str()) else {
        return Ok(schema);
    };
    let (target, pointer) = resolve_local_ref(root, reference)?;
    if !visited.insert(pointer.clone()) {
        return Err(HelperError::Schema(
            "config_schema contains a cyclic $ref".to_string(),
        ));
    }
    let resolved = resolve_schema_ref(target, root, visited);
    visited.remove(&pointer);
    resolved
}

fn resolve_local_ref<'a>(root: &'a Value, reference: &str) -> Result<(&'a Value, String)> {
    if reference == "#" {
        return Ok((root, String::new()));
    }
    let Some(pointer) = reference.strip_prefix("#/") else {
        if reference.starts_with('#') {
            return Err(HelperError::Schema(format!(
                "unsupported $ref pointer {reference:?}"
            )));
        }
        return Err(HelperError::Schema(format!(
            "unsupported non-local $ref {reference:?}"
        )));
    };
    let pointer = format!("/{pointer}");
    let target = root
        .pointer(&pointer)
        .ok_or_else(|| HelperError::Schema(format!("unresolvable $ref pointer {reference:?}")))?;
    Ok((target, pointer))
}

fn env_var_to_path(var: &str) -> Result<String> {
    let rest = var
        .strip_prefix(CONFIG_PREFIX)
        .ok_or_else(|| HelperError::Msg("not an AMBER_CONFIG_* var".to_string()))?;
    if rest.is_empty() {
        return Err(HelperError::Msg(format!(
            "invalid env var {var:?}: missing path suffix"
        )));
    }

    // AMBER_CONFIG_FOO__BAR_BAZ -> foo.bar_baz
    let segs = rest
        .split("__")
        .map(|s| s.to_ascii_lowercase())
        .collect::<Vec<_>>();
    Ok(segs.join("."))
}

fn get_by_path<'a>(root: &'a Value, path: &str) -> Result<&'a Value> {
    if path.is_empty() {
        return Ok(root);
    }
    let mut cur = root;
    for seg in path.split('.') {
        if seg.is_empty() {
            return Err(HelperError::Interp(format!(
                "invalid config path {path:?}: empty segment"
            )));
        }
        match cur {
            Value::Object(map) => {
                cur = map.get(seg).ok_or_else(|| {
                    HelperError::Interp(format!("config.{path} not found (missing key {seg:?})"))
                })?;
            }
            _ => {
                return Err(HelperError::Interp(format!(
                    "config.{path} not found (encountered non-object before segment {seg:?})"
                )));
            }
        }
    }
    Ok(cur)
}

fn stringify_for_interpolation(v: &Value) -> Result<String> {
    match v {
        Value::Null => Err(HelperError::Interp("cannot interpolate null".to_string())),
        Value::String(s) => Ok(s.clone()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Array(_) | Value::Object(_) => serde_json::to_string(v)
            .map_err(|e| HelperError::Interp(format!("failed to serialize value as JSON: {e}"))),
    }
}

fn schema_lookup<'a>(schema: &'a Value, path: &str) -> Result<&'a Value> {
    if path.is_empty() {
        return Ok(schema);
    }
    let segments = path.split('.').collect::<Vec<_>>();
    if segments.iter().any(|seg| seg.is_empty()) {
        return Err(HelperError::Schema(format!(
            "invalid config path {path:?}: empty segment"
        )));
    }
    let mut visited = BTreeSet::new();
    lookup_path(schema, schema, &segments, &mut visited, path)
}

fn lookup_path<'a>(
    schema: &'a Value,
    root: &'a Value,
    segments: &[&str],
    visited: &mut BTreeSet<String>,
    full_path: &str,
) -> Result<&'a Value> {
    let schema = resolve_schema_ref(schema, root, visited)?;
    ensure_schema_supported(schema)?;

    let seg = segments[0];
    let rest = &segments[1..];

    if let Some(props) = schema_properties(schema)
        && let Some(child) = props.get(seg)
    {
        if rest.is_empty() {
            return Ok(child);
        }
        if schema_type_includes(child, "array") {
            return Err(HelperError::Schema(format!(
                "cannot descend into array schema at segment {seg:?} for path {full_path:?}"
            )));
        }
        return lookup_path(child, root, rest, visited, full_path);
    }

    if let Some(all_of) = schema.get("allOf").and_then(|v| v.as_array()) {
        for subschema in all_of {
            if let Ok(found) = lookup_path(subschema, root, segments, visited, full_path) {
                return Ok(found);
            }
        }
    }

    Err(HelperError::Schema(format!(
        "schema path {full_path:?} not found (unknown key {seg:?})"
    )))
}

fn parse_env_value(raw: &str, leaf_schema: &Value) -> Result<Value> {
    // Build candidate values in deterministic order.
    let mut candidates: Vec<Value> = Vec::new();
    let mut parsed_json = None;

    // 1) JSON literal parse
    if let Ok(v) = serde_json::from_str::<Value>(raw) {
        parsed_json = Some(v.clone());
        candidates.push(v);
    }

    // 2) bool
    if raw == "true" {
        candidates.push(Value::Bool(true));
    } else if raw == "false" {
        candidates.push(Value::Bool(false));
    }

    // 3) integer
    let mut parsed_integer = false;
    if let Ok(i) = raw.parse::<i64>() {
        candidates.push(Value::Number(i.into()));
        parsed_integer = true;
    }

    // 4) number
    if !parsed_integer
        && let Ok(f) = raw.parse::<f64>()
        && let Some(n) = serde_json::Number::from_f64(f)
    {
        candidates.push(Value::Number(n));
    }

    // 5) raw string
    let skip_raw_string = parsed_json
        .as_ref()
        .is_some_and(|value| matches!(value, Value::String(_)));
    if !skip_raw_string {
        candidates.push(Value::String(raw.to_string()));
    }

    // Deduplicate by JSON equality, preserving order.
    let mut deduped: Vec<Value> = Vec::new();
    for c in candidates {
        if !deduped.contains(&c) {
            deduped.push(c);
        }
    }

    // Validate candidates against leaf schema.
    let validator = jsonschema::validator_for(leaf_schema)
        .map_err(|e| HelperError::Schema(format!("failed to compile leaf schema: {e}")))?;

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
            // Re-run against the raw string candidate to get a useful error.
            let c = Value::String(raw.to_string());
            let mut it = validator.iter_errors(&c);
            let msg = it
                .next()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "value does not match schema".to_string());
            Err(HelperError::Validation(msg))
        }
        _ => Err(HelperError::Validation(format!(
            "ambiguous value {raw:?}: multiple interpretations match the schema; disambiguate by \
             using an explicit JSON literal (e.g. \"\\\"123\\\"\" for strings)"
        ))),
    }
}

fn build_root_config(root_schema: &Value, config_env: &BTreeMap<String, String>) -> Result<Value> {
    let leaf_paths = collect_leaf_paths(root_schema)?;

    // Validate env var names and build object.
    let mut obj = serde_json::Map::new();

    for (k, v) in config_env {
        let path = env_var_to_path(k)?;
        if !leaf_paths.contains(&path) {
            return Err(HelperError::Schema(format!(
                "{k} does not correspond to a leaf schema path"
            )));
        }

        if v.is_empty() {
            // Treat empty string as "unset".
            continue;
        }

        let leaf_schema = schema_lookup(root_schema, &path)?;
        let parsed = parse_env_value(v, leaf_schema)?;

        // Insert into nested objects.
        insert_path(&mut obj, &path, parsed)?;
    }

    let out = Value::Object(obj);

    // Validate whole object against root schema.
    let validator = jsonschema::validator_for(root_schema)
        .map_err(|e| HelperError::Schema(format!("failed to compile root schema: {e}")))?;
    {
        let mut it = validator.iter_errors(&out);
        if let Some(first) = it.next() {
            let mut msgs = vec![first.to_string()];
            msgs.extend(it.take(7).map(|e| e.to_string()));
            return Err(HelperError::Validation(msgs.join("; ")));
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
            return Err(HelperError::Schema(format!(
                "cannot set {path:?}: parent segment {seg:?} is not an object"
            )));
        };
        cur = m;
    }
    Ok(())
}

fn eval_config_template(template: &ConfigTemplatePayload, root_config: &Value) -> Result<Value> {
    match template {
        ConfigTemplatePayload::Root => Ok(root_config.clone()),
        ConfigTemplatePayload::Template(node) => eval_config_node(node, root_config),
    }
}

fn eval_config_node(node: &ConfigTemplate, root_config: &Value) -> Result<Value> {
    match node {
        ConfigTemplate::Literal(value) => Ok(value.clone()),
        ConfigTemplate::ConfigRef { path } => Ok(get_by_path(root_config, path)?.clone()),
        ConfigTemplate::TemplateString { parts } => {
            let rendered = render_template_string(parts, root_config)?;
            Ok(Value::String(rendered))
        }
        ConfigTemplate::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                out.push(eval_config_node(item, root_config)?);
            }
            Ok(Value::Array(out))
        }
        ConfigTemplate::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                out.insert(k.clone(), eval_config_node(v, root_config)?);
            }
            Ok(Value::Object(out))
        }
    }
}

fn render_template_string(parts: &TemplateString, config: &Value) -> Result<String> {
    let mut out = String::new();
    for p in parts {
        match p {
            TemplatePart::Lit { lit } => out.push_str(lit),
            TemplatePart::Config { config: path } => {
                let v = get_by_path(config, path)?;
                if v.is_null() {
                    return Err(HelperError::Interp(format!(
                        "config.{path} is null; cannot interpolate"
                    )));
                }
                out.push_str(&stringify_for_interpolation(v)?);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD;

    use super::*;

    fn encode_json_b64(value: &Value) -> String {
        let bytes = serde_json::to_vec(value).expect("json should serialize");
        STANDARD.encode(bytes)
    }

    fn encode_spec_b64(spec: &TemplateSpec) -> String {
        let bytes = serde_json::to_vec(spec).expect("spec should serialize");
        STANDARD.encode(bytes)
    }

    #[test]
    fn root_config_skips_empty_env_values() {
        let schema = serde_json::json!({
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

        let env = BTreeMap::from([
            (
                "AMBER_CONFIG_DB__URL".to_string(),
                "postgres://db".to_string(),
            ),
            ("AMBER_CONFIG_DB__POOL".to_string(), "".to_string()),
        ]);

        let config = build_root_config(&schema, &env).expect("config should parse");
        let url = get_by_path(&config, "db.url").unwrap();
        assert_eq!(url, "postgres://db");
        assert!(get_by_path(&config, "db.pool").is_err());
    }

    #[test]
    fn ambiguous_value_requires_disambiguation() {
        let schema = serde_json::json!({
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
        let schema = serde_json::json!({
            "type": ["integer", "string"]
        });

        let value = parse_env_value("\"123\"", &schema).expect("json string literal should parse");
        assert_eq!(value, Value::String("123".to_string()));
    }

    #[test]
    fn build_run_plan_renders_entrypoint_and_env() {
        let root_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "token": { "type": "string" },
                "count": { "type": "integer" }
            },
            "required": ["token"]
        });

        let component_schema = root_schema.clone();

        let template_spec = TemplateSpec {
            program: amber_template::ProgramTemplateSpec {
                entrypoint: vec![
                    vec![TemplatePart::lit("/app/bin/server")],
                    vec![TemplatePart::lit("--token="), TemplatePart::config("token")],
                ],
                env: BTreeMap::from([("COUNT".to_string(), vec![TemplatePart::config("count")])]),
            },
        };

        let env = BTreeMap::from([
            ("PATH".to_string(), "/bin".to_string()),
            (
                TEMPLATE_SPEC_ENV.to_string(),
                encode_spec_b64(&template_spec),
            ),
            (
                COMPONENT_TEMPLATE_ENV.to_string(),
                encode_json_b64(&ConfigTemplatePayload::Root.to_value()),
            ),
            (
                COMPONENT_SCHEMA_ENV.to_string(),
                encode_json_b64(&component_schema),
            ),
            (ROOT_SCHEMA_ENV.to_string(), encode_json_b64(&root_schema)),
            ("AMBER_CONFIG_TOKEN".to_string(), "secret".to_string()),
            ("AMBER_CONFIG_COUNT".to_string(), "3".to_string()),
        ]);

        let os_env = env
            .into_iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        let plan = build_run_plan(os_env).expect("run plan should build");
        assert_eq!(plan.entrypoint[0], "/app/bin/server");
        assert_eq!(plan.entrypoint[1], "--token=secret");
        assert_eq!(
            plan.env.get(&OsString::from("COUNT")),
            Some(&OsString::from("3"))
        );
        assert_eq!(
            plan.env.get(&OsString::from("PATH")),
            Some(&OsString::from("/bin"))
        );
        assert!(
            !plan
                .env
                .keys()
                .any(|k| k.to_string_lossy().starts_with(CONFIG_PREFIX))
        );
        assert!(!plan.env.contains_key(&OsString::from(TEMPLATE_SPEC_ENV)));
    }

    #[test]
    fn component_config_template_inserts_values() {
        let root = serde_json::json!({
            "api": { "token": "secret" },
            "limits": { "max_jobs": 3 }
        });

        let template_value = serde_json::json!({
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
            serde_json::json!({
                "token": "secret",
                "limits": { "max_jobs": 3 },
                "label": "token=secret"
            })
        );
    }
}
