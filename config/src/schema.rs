use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::{ConfigError, Result};

fn schema_type_includes(schema: &Value, ty: &str) -> bool {
    match schema.get("type") {
        Some(Value::String(s)) => s == ty,
        Some(Value::Array(arr)) => arr.iter().any(|v| v.as_str() == Some(ty)),
        _ => false,
    }
}

fn schema_properties(schema: &Value) -> Option<&Map<String, Value>> {
    schema.get("properties")?.as_object()
}

pub fn is_valid_config_key(key: &str) -> bool {
    if key.is_empty() {
        return false;
    }
    if key.contains('.') || key.contains("__") {
        return false;
    }
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    for ch in std::iter::once(first).chain(chars) {
        if !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_') {
            return false;
        }
    }
    true
}

#[derive(Clone, Copy, Debug)]
pub enum SchemaLookup {
    Found,
    Unknown,
}

#[derive(Debug)]
enum LookupStatus {
    Found,
    Missing(String),
    Unknown,
}

fn schema_has_unsupported_features(schema: &Value) -> bool {
    let Value::Object(map) = schema else {
        return false;
    };
    if map.contains_key("anyOf")
        || map.contains_key("oneOf")
        || map.contains_key("not")
        || map.contains_key("if")
        || map.contains_key("then")
        || map.contains_key("else")
        || map.contains_key("patternProperties")
        || map.contains_key("propertyNames")
        || map.contains_key("dependentSchemas")
        || map.contains_key("unevaluatedProperties")
    {
        return true;
    }
    !matches!(map.get("additionalProperties"), Some(Value::Bool(_)) | None)
}

fn resolve_local_ref<'a>(root: &'a Value, reference: &str) -> Result<(&'a Value, String)> {
    if reference == "#" {
        return Ok((root, String::new()));
    }
    let Some(pointer) = reference.strip_prefix("#/") else {
        if reference.starts_with('#') {
            return Err(ConfigError::schema(format!(
                "unsupported $ref pointer {reference:?}"
            )));
        }
        return Err(ConfigError::schema(format!(
            "unsupported non-local $ref {reference:?}"
        )));
    };
    let pointer = format!("/{pointer}");
    let target = root
        .pointer(&pointer)
        .ok_or_else(|| ConfigError::schema(format!("unresolvable $ref pointer {reference:?}")))?;
    Ok((target, pointer))
}

pub fn validate_config_schema(schema: &Value) -> Result<()> {
    if !schema_type_includes(schema, "object") && schema_properties(schema).is_none() {
        return Err(ConfigError::schema(
            "config definition must be object-shaped (type: \"object\" or properties: {...})"
                .to_string(),
        ));
    }

    fn walk(schema: &Value, at: &str) -> Result<()> {
        if let Some(value) = schema.get("secret")
            && !value.is_boolean()
        {
            return Err(ConfigError::schema(format!(
                "config definition at {at} has `secret` but value is not boolean"
            )));
        }
        let Some(props) = schema_properties(schema) else {
            return Ok(());
        };

        if schema.get("type").is_some() && !schema_type_includes(schema, "object") {
            return Err(ConfigError::schema(format!(
                "config definition at {at} has `properties` but is not type \"object\""
            )));
        }

        let mut keys: Vec<&String> = props.keys().collect();
        keys.sort();

        for k in keys {
            if !is_valid_config_key(k.as_str()) {
                return Err(ConfigError::schema(format!(
                    "invalid config property name {k:?} in config definition at {at} (must match \
                     ^[a-z][a-z0-9_]*$ and must not contain '.' or '__')"
                )));
            }
            let child = props.get(k.as_str()).expect("key exists");
            let child_at = if at.is_empty() {
                k.clone()
            } else {
                format!("{at}.{k}")
            };
            walk(child, &child_at)?;
        }
        Ok(())
    }

    walk(schema, "")?;
    Ok(())
}

pub fn schema_lookup(schema: &Value, path: &str) -> Result<SchemaLookup> {
    if path.is_empty() {
        return Ok(SchemaLookup::Found);
    }

    let mut segments = Vec::new();
    for seg in path.split('.') {
        if seg.is_empty() {
            return Err(ConfigError::schema(format!(
                "invalid config path {path:?}: empty segment"
            )));
        }
        if !is_valid_config_key(seg) {
            return Err(ConfigError::schema(format!(
                "invalid config path segment {seg:?} in {path:?}"
            )));
        }
        segments.push(seg);
    }

    let mut visited = BTreeSet::new();
    match lookup_path(schema, schema, &segments, &mut visited, path) {
        LookupStatus::Found => Ok(SchemaLookup::Found),
        LookupStatus::Unknown => Ok(SchemaLookup::Unknown),
        LookupStatus::Missing(msg) => Err(ConfigError::schema(msg)),
    }
}

fn lookup_path(
    schema: &Value,
    root: &Value,
    segments: &[&str],
    visited: &mut BTreeSet<String>,
    full_path: &str,
) -> LookupStatus {
    if segments.is_empty() {
        return LookupStatus::Found;
    }

    if let Some(reference) = schema.get("$ref").and_then(|v| v.as_str()) {
        let Ok((resolved, pointer)) = resolve_local_ref(root, reference) else {
            return LookupStatus::Unknown;
        };
        if !visited.insert(pointer.clone()) {
            return LookupStatus::Unknown;
        }
        let out = lookup_path(resolved, root, segments, visited, full_path);
        visited.remove(&pointer);
        return out;
    }

    let mut unknown = schema_has_unsupported_features(schema);
    let seg = segments[0];
    let rest = &segments[1..];

    let mut outcomes = Vec::new();

    if let Some(props) = schema_properties(schema) {
        if let Some(child) = props.get(seg) {
            if !rest.is_empty() && schema_type_includes(child, "array") {
                outcomes.push(LookupStatus::Missing(format!(
                    "invalid config path {full_path:?}: cannot descend into array at segment \
                     {seg:?}"
                )));
            } else {
                outcomes.push(lookup_path(child, root, rest, visited, full_path));
            }
        } else {
            outcomes.push(LookupStatus::Missing(format!(
                "config path {full_path:?} not found (unknown key {seg:?})"
            )));
        }
    } else {
        outcomes.push(LookupStatus::Missing(format!(
            "config path {full_path:?} not found (schema has no properties at segment {seg:?})"
        )));
    }

    if let Some(all_of) = schema.get("allOf").and_then(|v| v.as_array()) {
        for subschema in all_of {
            outcomes.push(lookup_path(subschema, root, segments, visited, full_path));
        }
    }

    if let Some(any_of) = schema.get("anyOf").and_then(|v| v.as_array()) {
        unknown = true;
        for subschema in any_of {
            outcomes.push(lookup_path(subschema, root, segments, visited, full_path));
        }
    }

    if let Some(one_of) = schema.get("oneOf").and_then(|v| v.as_array()) {
        unknown = true;
        for subschema in one_of {
            outcomes.push(lookup_path(subschema, root, segments, visited, full_path));
        }
    }

    if let Some(subschema) = schema.get("if") {
        unknown = true;
        outcomes.push(lookup_path(subschema, root, segments, visited, full_path));
    }
    if let Some(subschema) = schema.get("then") {
        unknown = true;
        outcomes.push(lookup_path(subschema, root, segments, visited, full_path));
    }
    if let Some(subschema) = schema.get("else") {
        unknown = true;
        outcomes.push(lookup_path(subschema, root, segments, visited, full_path));
    }

    if outcomes
        .iter()
        .any(|outcome| matches!(outcome, LookupStatus::Found))
    {
        return LookupStatus::Found;
    }

    if unknown
        || outcomes
            .iter()
            .any(|outcome| matches!(outcome, LookupStatus::Unknown))
    {
        return LookupStatus::Unknown;
    }

    for outcome in outcomes {
        if let LookupStatus::Missing(msg) = outcome {
            return LookupStatus::Missing(msg);
        }
    }

    LookupStatus::Missing(format!("config path {full_path:?} not found"))
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
        return Err(ConfigError::schema(
            "config_schema contains a cyclic $ref".to_string(),
        ));
    }
    let resolved = resolve_schema_ref(target, root, visited);
    visited.remove(&pointer);
    resolved
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
            return Err(ConfigError::schema(format!(
                "unsupported config_schema feature {name}"
            )));
        }
    }
    if map.contains_key("if") || map.contains_key("then") || map.contains_key("else") {
        return Err(ConfigError::schema(
            "unsupported config_schema feature if/then/else".to_string(),
        ));
    }
    if let Some(additional) = map.get("additionalProperties")
        && !additional.is_boolean()
    {
        return Err(ConfigError::schema(
            "unsupported config_schema feature additionalProperties (schema)".to_string(),
        ));
    }
    Ok(())
}

pub fn schema_lookup_ref<'a>(schema: &'a Value, path: &str) -> Result<&'a Value> {
    if path.is_empty() {
        return Ok(schema);
    }
    let segments = path.split('.').collect::<Vec<_>>();
    if segments.iter().any(|seg| seg.is_empty()) {
        return Err(ConfigError::schema(format!(
            "invalid config path {path:?}: empty segment"
        )));
    }
    let mut visited = BTreeSet::new();
    lookup_ref(schema, schema, &segments, &mut visited, path)
}

fn lookup_ref<'a>(
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
            return Err(ConfigError::schema(format!(
                "cannot descend into array schema at segment {seg:?} for path {full_path:?}"
            )));
        }
        return lookup_ref(child, root, rest, visited, full_path);
    }

    if let Some(all_of) = schema.get("allOf").and_then(|v| v.as_array()) {
        for subschema in all_of {
            if let Ok(found) = lookup_ref(subschema, root, segments, visited, full_path) {
                return Ok(found);
            }
        }
    }

    Err(ConfigError::schema(format!(
        "schema path {full_path:?} not found (unknown key {seg:?})"
    )))
}

fn schema_required_set(schema: &Value) -> BTreeMap<String, ()> {
    let mut out = BTreeMap::new();
    let Some(arr) = schema.get("required").and_then(|v| v.as_array()) else {
        return out;
    };
    for v in arr {
        if let Some(s) = v.as_str() {
            out.insert(s.to_string(), ());
        }
    }
    out
}

fn schema_secret_flag(schema: &Value) -> bool {
    schema
        .get("secret")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

fn push_pointer(base: &str, segment: &str) -> String {
    let escaped = segment.replace('~', "~0").replace('/', "~1");
    if base.is_empty() {
        format!("/{escaped}")
    } else {
        format!("{base}/{escaped}")
    }
}

#[derive(Clone, Debug)]
pub struct SchemaLeaf {
    pub path: String,
    pub required: bool,
    pub secret: bool,
    pub pointer: String,
}

#[derive(Default)]
pub struct SchemaWalkResult {
    pub leaves: Vec<SchemaLeaf>,
    pub unsupported: BTreeSet<String>,
}

#[derive(Default)]
struct LeafMeta {
    required: bool,
    secret: bool,
    pointer: String,
}

fn insert_leaf(
    out: &mut BTreeMap<String, LeafMeta>,
    path: &str,
    required: bool,
    secret: bool,
    pointer: &str,
) {
    match out.get_mut(path) {
        Some(meta) => {
            meta.required |= required;
            meta.secret |= secret;
            if meta.pointer.is_empty() {
                meta.pointer = pointer.to_string();
            }
        }
        None => {
            out.insert(
                path.to_string(),
                LeafMeta {
                    required,
                    secret,
                    pointer: pointer.to_string(),
                },
            );
        }
    }
}

fn finalize_leaves(out: BTreeMap<String, LeafMeta>) -> Vec<SchemaLeaf> {
    out.into_iter()
        .map(|(path, meta)| SchemaLeaf {
            path,
            required: meta.required,
            secret: meta.secret,
            pointer: meta.pointer,
        })
        .collect()
}

#[derive(Clone, Debug)]
struct SchemaCursor<'a> {
    schema: &'a Value,
    pointer: String,
}

struct SchemaWalkContext<'a, 'b> {
    root: &'a Value,
    visited: &'b mut BTreeSet<String>,
    out: &'b mut BTreeMap<String, LeafMeta>,
}

enum WalkMode<'a> {
    Strict,
    Lint {
        unsupported: &'a mut BTreeSet<String>,
    },
}

impl WalkMode<'_> {
    fn record_unsupported(&mut self, message: String) -> Result<()> {
        match self {
            WalkMode::Strict => Err(ConfigError::schema(message)),
            WalkMode::Lint { unsupported } => {
                unsupported.insert(message);
                Ok(())
            }
        }
    }

    fn is_strict(&self) -> bool {
        matches!(self, WalkMode::Strict)
    }
}

pub fn collect_schema_leaves(schema: &Value) -> SchemaWalkResult {
    let mut out = SchemaWalkResult::default();
    let mut visited = BTreeSet::new();
    let mut leafs: BTreeMap<String, LeafMeta> = BTreeMap::new();
    let mut mode = WalkMode::Lint {
        unsupported: &mut out.unsupported,
    };
    {
        let mut ctx = SchemaWalkContext {
            root: schema,
            visited: &mut visited,
            out: &mut leafs,
        };
        let _ = walk_leaf_paths(
            SchemaCursor {
                schema,
                pointer: String::new(),
            },
            &mut ctx,
            "",
            true,
            false,
            &mut mode,
        );
    }
    out.leaves = finalize_leaves(leafs);
    out
}

pub fn collect_leaf_paths(schema: &Value) -> Result<Vec<SchemaLeaf>> {
    validate_config_schema(schema)?;
    let mut out: BTreeMap<String, LeafMeta> = BTreeMap::new();
    let mut visited = BTreeSet::new();
    let mut mode = WalkMode::Strict;
    {
        let mut ctx = SchemaWalkContext {
            root: schema,
            visited: &mut visited,
            out: &mut out,
        };
        let _ = walk_leaf_paths(
            SchemaCursor {
                schema,
                pointer: String::new(),
            },
            &mut ctx,
            "",
            true,
            false,
            &mut mode,
        )?;
    }
    Ok(finalize_leaves(out))
}

fn walk_leaf_paths<'a>(
    cursor: SchemaCursor<'a>,
    ctx: &mut SchemaWalkContext<'a, '_>,
    prefix: &str,
    required_so_far: bool,
    secret_so_far: bool,
    mode: &mut WalkMode<'_>,
) -> Result<bool> {
    let secret_here = secret_so_far || schema_secret_flag(cursor.schema);

    let Value::Object(map) = cursor.schema else {
        if !prefix.is_empty() {
            insert_leaf(
                ctx.out,
                prefix,
                required_so_far,
                secret_here,
                &cursor.pointer,
            );
        }
        return Ok(false);
    };

    if let Some(reference) = map.get("$ref").and_then(|v| v.as_str()) {
        match resolve_local_ref(ctx.root, reference) {
            Ok((resolved, pointer)) => {
                if !ctx.visited.insert(pointer.clone()) {
                    mode.record_unsupported(
                        "config definition contains a cyclic $ref".to_string(),
                    )?;
                    return Ok(false);
                }
                let out = walk_leaf_paths(
                    SchemaCursor {
                        schema: resolved,
                        pointer: pointer.clone(),
                    },
                    ctx,
                    prefix,
                    required_so_far,
                    secret_here,
                    mode,
                );
                ctx.visited.remove(&pointer);
                return out;
            }
            Err(err) => {
                mode.record_unsupported(err.to_string())?;
                if !prefix.is_empty() {
                    insert_leaf(
                        ctx.out,
                        prefix,
                        required_so_far,
                        secret_here,
                        &cursor.pointer,
                    );
                }
                return Ok(false);
            }
        }
    }

    if mode.is_strict() {
        ensure_leaf_schema_supported(map)?;
    }

    let mut did_traverse = false;

    if let Some(props) = schema_properties(cursor.schema) {
        let req = schema_required_set(cursor.schema);

        let mut keys: Vec<&String> = props.keys().collect();
        keys.sort();

        for k in keys {
            let child_schema = props.get(k.as_str()).expect("key exists");
            let is_req_here = req.contains_key(k.as_str());
            let req_path = required_so_far && is_req_here;

            let path = if prefix.is_empty() {
                k.to_string()
            } else {
                format!("{prefix}.{k}")
            };

            let pointer = push_pointer(&push_pointer(&cursor.pointer, "properties"), k.as_str());

            did_traverse = true;
            let _ = walk_leaf_paths(
                SchemaCursor {
                    schema: child_schema,
                    pointer,
                },
                ctx,
                &path,
                req_path,
                secret_here,
                mode,
            )?;
        }
    }

    if let Some(all_of) = cursor.schema.get("allOf").and_then(|v| v.as_array()) {
        for (idx, subschema) in all_of.iter().enumerate() {
            let pointer = push_pointer(&push_pointer(&cursor.pointer, "allOf"), &idx.to_string());
            did_traverse = true;
            let _ = walk_leaf_paths(
                SchemaCursor {
                    schema: subschema,
                    pointer,
                },
                ctx,
                prefix,
                required_so_far,
                secret_here,
                mode,
            )?;
        }
    }

    if !did_traverse && !prefix.is_empty() {
        insert_leaf(
            ctx.out,
            prefix,
            required_so_far,
            secret_here,
            &cursor.pointer,
        );
    }

    Ok(did_traverse)
}

fn ensure_leaf_schema_supported(schema: &Map<String, Value>) -> Result<()> {
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
        if schema.contains_key(key) {
            return Err(ConfigError::schema(format!(
                "config definition uses unsupported feature {name} for leaf enumeration"
            )));
        }
    }
    if schema.contains_key("if") || schema.contains_key("then") || schema.contains_key("else") {
        return Err(ConfigError::schema(
            "config definition uses unsupported feature if/then/else for leaf enumeration"
                .to_string(),
        ));
    }
    if let Some(additional) = schema.get("additionalProperties")
        && !additional.is_boolean()
    {
        return Err(ConfigError::schema(
            "config definition uses unsupported feature additionalProperties (schema) for leaf \
             enumeration"
                .to_string(),
        ));
    }
    Ok(())
}

pub fn canonical_json(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for k in keys {
                out.insert(
                    k.clone(),
                    canonical_json(map.get(k.as_str()).expect("key exists")),
                );
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonical_json).collect()),
        other => other.clone(),
    }
}
