use std::collections::{BTreeMap, BTreeSet};

use jsonptr::PointerBuf;
use serde_json::{Map, Value};

use crate::{ConfigError, ConfigNode, Result};

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
    let pointer = PointerBuf::parse(pointer).map_err(|_| {
        ConfigError::schema(format!(
            "invalid $ref pointer {reference:?}: non-RFC6901 escape sequence"
        ))
    })?;
    let pointer = pointer.to_string();
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

fn push_pointer(base: &str, segment: &str) -> Result<String> {
    let mut pointer = if base.is_empty() {
        PointerBuf::new()
    } else {
        PointerBuf::parse(base.to_string()).map_err(|_| {
            ConfigError::schema(format!(
                "internal error: invalid schema pointer during leaf walk: {base:?}"
            ))
        })?
    };
    pointer.push_back(segment);
    Ok(pointer.to_string())
}

#[derive(Clone, Debug)]
pub struct SchemaLeaf {
    pub path: String,
    pub required: bool,
    pub default: Option<Value>,
    pub secret: bool,
    pub pointer: String,
}

impl SchemaLeaf {
    pub fn has_default(&self) -> bool {
        self.default.is_some()
    }

    pub fn runtime_required(&self) -> bool {
        self.required && !self.has_default()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchemaPresence {
    Present,
    Absent,
    Runtime,
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

fn finalize_leaves(out: BTreeMap<String, LeafMeta>, defaults: Option<&Value>) -> Vec<SchemaLeaf> {
    out.into_iter()
        .map(|(path, meta)| {
            let default = defaults.and_then(|defaults| value_at_path(defaults, &path).cloned());
            SchemaLeaf {
                path,
                required: meta.required,
                default,
                secret: meta.secret,
                pointer: meta.pointer,
            }
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
    let defaults = collect_schema_defaults(schema).ok().flatten();
    out.leaves = finalize_leaves(leafs, defaults.as_ref());
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
    let defaults = collect_schema_defaults(schema)?;
    let mut leaves = finalize_leaves(out, defaults.as_ref());
    for leaf in &mut leaves {
        leaf.required = schema_path_is_required(schema, &leaf.path)?;
    }
    Ok(leaves)
}

pub fn apply_schema_defaults(schema: &Value, value: &mut Value) -> Result<()> {
    validate_config_schema(schema)?;

    let mut slot = Some(value.take());
    let mut visited = BTreeSet::new();
    apply_defaults_to_slot(
        SchemaCursor {
            schema,
            pointer: String::new(),
        },
        schema,
        &mut visited,
        &mut slot,
    )?;
    *value = slot.unwrap_or(Value::Null);
    Ok(())
}

pub fn apply_schema_defaults_to_node(schema: &Value, node: &mut ConfigNode) -> Result<()> {
    validate_config_schema(schema)?;

    let Some(defaults) = collect_schema_defaults(schema)? else {
        return Ok(());
    };

    if !defaults.is_object() {
        return Err(ConfigError::schema(
            "component config defaults must resolve to an object".to_string(),
        ));
    }

    merge_default_value_into_node(node, &defaults);
    Ok(())
}

fn collect_schema_defaults(schema: &Value) -> Result<Option<Value>> {
    validate_config_schema(schema)?;

    let mut slot = None;
    let mut visited = BTreeSet::new();
    apply_defaults_to_slot(
        SchemaCursor {
            schema,
            pointer: String::new(),
        },
        schema,
        &mut visited,
        &mut slot,
    )?;
    Ok(slot)
}

fn apply_defaults_to_slot(
    cursor: SchemaCursor<'_>,
    root: &Value,
    visited: &mut BTreeSet<String>,
    slot: &mut Option<Value>,
) -> Result<()> {
    let Value::Object(map) = cursor.schema else {
        return Ok(());
    };

    if let Some(default) = map.get("default") {
        match slot {
            Some(current) => merge_default_value_into_json(current, default),
            None => *slot = Some(default.clone()),
        }
    }

    if let Some(reference) = map.get("$ref").and_then(|value| value.as_str()) {
        let (resolved, pointer) = resolve_local_ref(root, reference)?;
        if !visited.insert(pointer.clone()) {
            return Err(ConfigError::schema(
                "config_schema contains a cyclic $ref".to_string(),
            ));
        }
        apply_defaults_to_slot(
            SchemaCursor {
                schema: resolved,
                pointer: pointer.clone(),
            },
            root,
            visited,
            slot,
        )?;
        visited.remove(&pointer);
    }

    if let Some(all_of) = map.get("allOf").and_then(|value| value.as_array()) {
        for (idx, subschema) in all_of.iter().enumerate() {
            let pointer = push_pointer(&push_pointer(&cursor.pointer, "allOf")?, &idx.to_string())?;
            apply_defaults_to_slot(
                SchemaCursor {
                    schema: subschema,
                    pointer,
                },
                root,
                visited,
                slot,
            )?;
        }
    }

    if let Some(items_schema) = map.get("items") {
        match (slot.as_mut(), items_schema) {
            (Some(Value::Array(items)), Value::Array(schemas)) => {
                for (idx, item) in items.iter_mut().enumerate() {
                    let Some(schema) = schemas.get(idx) else {
                        continue;
                    };
                    let pointer =
                        push_pointer(&push_pointer(&cursor.pointer, "items")?, &idx.to_string())?;
                    let mut item_slot = Some(item.take());
                    apply_defaults_to_slot(
                        SchemaCursor { schema, pointer },
                        root,
                        visited,
                        &mut item_slot,
                    )?;
                    *item = item_slot.expect("existing array item must remain present");
                }
            }
            (Some(Value::Array(items)), _) => {
                let pointer = push_pointer(&cursor.pointer, "items")?;
                for item in items {
                    let mut item_slot = Some(item.take());
                    apply_defaults_to_slot(
                        SchemaCursor {
                            schema: items_schema,
                            pointer: pointer.clone(),
                        },
                        root,
                        visited,
                        &mut item_slot,
                    )?;
                    *item = item_slot.expect("existing array item must remain present");
                }
            }
            _ => {}
        }
    }

    let Some(props) = schema_properties(cursor.schema) else {
        return Ok(());
    };

    let mut keys: Vec<&String> = props.keys().collect();
    keys.sort();

    match slot {
        Some(Value::Object(current)) => {
            for key in keys {
                let child_schema = props.get(key.as_str()).expect("key exists");
                let pointer =
                    push_pointer(&push_pointer(&cursor.pointer, "properties")?, key.as_str())?;
                let mut child_slot = current.remove(key.as_str());
                apply_defaults_to_slot(
                    SchemaCursor {
                        schema: child_schema,
                        pointer,
                    },
                    root,
                    visited,
                    &mut child_slot,
                )?;
                if let Some(value) = child_slot {
                    current.insert(key.clone(), value);
                }
            }
        }
        None => {
            let mut current = Map::new();
            let mut changed = false;
            for key in keys {
                let child_schema = props.get(key.as_str()).expect("key exists");
                let pointer =
                    push_pointer(&push_pointer(&cursor.pointer, "properties")?, key.as_str())?;
                let mut child_slot = None;
                apply_defaults_to_slot(
                    SchemaCursor {
                        schema: child_schema,
                        pointer,
                    },
                    root,
                    visited,
                    &mut child_slot,
                )?;
                if let Some(value) = child_slot {
                    current.insert(key.clone(), value);
                    changed = true;
                }
            }
            if changed {
                *slot = Some(Value::Object(current));
            }
        }
        Some(_) => {}
    }

    Ok(())
}

fn value_to_config_node(value: Value) -> ConfigNode {
    match value {
        Value::Null => ConfigNode::Null,
        Value::Bool(value) => ConfigNode::Bool(value),
        Value::Number(value) => ConfigNode::Number(value),
        Value::String(value) => ConfigNode::String(value),
        Value::Array(values) => {
            ConfigNode::Array(values.into_iter().map(value_to_config_node).collect())
        }
        Value::Object(values) => ConfigNode::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, value_to_config_node(value)))
                .collect(),
        ),
    }
}

fn merge_default_value_into_json(target: &mut Value, default: &Value) {
    let (Value::Object(target), Value::Object(defaults)) = (target, default) else {
        return;
    };

    for (key, default_child) in defaults {
        match target.get_mut(key) {
            Some(existing) => merge_default_value_into_json(existing, default_child),
            None => {
                target.insert(key.clone(), default_child.clone());
            }
        }
    }
}

fn merge_default_value_into_node(node: &mut ConfigNode, default: &Value) {
    let (ConfigNode::Object(target), Value::Object(defaults)) = (node, default) else {
        return;
    };

    for (key, default_child) in defaults {
        match target.get_mut(key) {
            Some(existing) => merge_default_value_into_node(existing, default_child),
            None => {
                target.insert(key.clone(), value_to_config_node(default_child.clone()));
            }
        }
    }
}

fn value_at_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    if path.is_empty() {
        return Some(value);
    }

    let mut current = value;
    for segment in path.split('.') {
        let Value::Object(map) = current else {
            return None;
        };
        let next = map.get(segment)?;
        current = next;
    }

    Some(current)
}

#[derive(Clone, Copy, Debug, Default)]
struct PossibleKinds {
    null: bool,
    object: bool,
    other_non_null: bool,
}

impl PossibleKinds {
    const fn any() -> Self {
        Self {
            null: true,
            object: true,
            other_non_null: true,
        }
    }

    const fn may_accept_non_null(self) -> bool {
        self.object || self.other_non_null
    }

    const fn must_be_non_null_object(self) -> bool {
        self.object && !self.null && !self.other_non_null
    }

    fn intersect(self, other: Self) -> Self {
        Self {
            null: self.null && other.null,
            object: self.object && other.object,
            other_non_null: self.other_non_null && other.other_non_null,
        }
    }
}

fn possible_kinds_from_type(value: &Value) -> Result<PossibleKinds> {
    fn kind_for_type(ty: &str) -> Result<PossibleKinds> {
        match ty {
            "null" => Ok(PossibleKinds {
                null: true,
                object: false,
                other_non_null: false,
            }),
            "object" => Ok(PossibleKinds {
                null: false,
                object: true,
                other_non_null: false,
            }),
            "string" | "boolean" | "number" | "integer" | "array" => Ok(PossibleKinds {
                null: false,
                object: false,
                other_non_null: true,
            }),
            other => Err(ConfigError::schema(format!(
                "unsupported config_schema type {other:?}"
            ))),
        }
    }

    match value {
        Value::String(ty) => kind_for_type(ty),
        Value::Array(types) => {
            let mut out = PossibleKinds::default();
            for ty in types {
                let Some(ty) = ty.as_str() else {
                    return Err(ConfigError::schema(
                        "config_schema type array must contain only strings".to_string(),
                    ));
                };
                let kinds = kind_for_type(ty)?;
                out.null |= kinds.null;
                out.object |= kinds.object;
                out.other_non_null |= kinds.other_non_null;
            }
            Ok(out)
        }
        _ => Err(ConfigError::schema(
            "config_schema `type` must be a string or string array".to_string(),
        )),
    }
}

fn possible_kinds_from_values(values: &[Value]) -> PossibleKinds {
    let mut out = PossibleKinds::default();
    for value in values {
        match value {
            Value::Null => out.null = true,
            Value::Object(_) => out.object = true,
            _ => out.other_non_null = true,
        }
    }
    out
}

fn schema_possible_kinds(
    schema: &Value,
    root: &Value,
    visited: &mut BTreeSet<String>,
) -> Result<PossibleKinds> {
    let schema = resolve_schema_ref(schema, root, visited)?;
    ensure_schema_supported(schema)?;

    let Value::Object(map) = schema else {
        return Ok(PossibleKinds::any());
    };

    if let Some(values) = map.get("enum").and_then(Value::as_array) {
        return Ok(possible_kinds_from_values(values));
    }
    if let Some(value) = map.get("const") {
        return Ok(PossibleKinds {
            null: value.is_null(),
            object: value.is_object(),
            other_non_null: !value.is_null() && !value.is_object(),
        });
    }

    let mut out = map
        .get("type")
        .map(possible_kinds_from_type)
        .transpose()?
        .unwrap_or_else(PossibleKinds::any);

    if let Some(all_of) = map.get("allOf").and_then(Value::as_array) {
        for subschema in all_of {
            out = out.intersect(schema_possible_kinds(subschema, root, visited)?);
        }
    }

    Ok(out)
}

fn schema_path_possible_kinds(root_schema: &Value, path: &str) -> Result<PossibleKinds> {
    let schema = schema_lookup_ref(root_schema, path)?;
    let mut visited = BTreeSet::new();
    schema_possible_kinds(schema, root_schema, &mut visited)
}

pub fn schema_path_accepts_null(root_schema: &Value, path: &str) -> Result<bool> {
    Ok(schema_path_possible_kinds(root_schema, path)?.null)
}

pub fn schema_path_may_be_object(root_schema: &Value, path: &str) -> Result<bool> {
    Ok(schema_path_possible_kinds(root_schema, path)?.object)
}

pub fn schema_path_may_be_other_non_null(root_schema: &Value, path: &str) -> Result<bool> {
    Ok(schema_path_possible_kinds(root_schema, path)?.other_non_null)
}

pub fn schema_path_may_accept_non_null(root_schema: &Value, path: &str) -> Result<bool> {
    Ok(schema_path_possible_kinds(root_schema, path)?.may_accept_non_null())
}

pub fn schema_path_ancestors_must_be_non_null_objects(
    root_schema: &Value,
    path: &str,
) -> Result<bool> {
    let mut prefix = String::new();
    let mut segments = path.split('.').peekable();

    while let Some(segment) = segments.next() {
        if segments.peek().is_none() {
            break;
        }

        if !prefix.is_empty() {
            prefix.push('.');
        }
        prefix.push_str(segment);

        if !schema_path_possible_kinds(root_schema, &prefix)?.must_be_non_null_object() {
            return Ok(false);
        }
    }

    Ok(true)
}

fn downgrade_present_when_ancestors_are_runtime(
    root_schema: &Value,
    path: &str,
    presence: SchemaPresence,
) -> Result<SchemaPresence> {
    if matches!(presence, SchemaPresence::Present)
        && !schema_path_ancestors_must_be_non_null_objects(root_schema, path)?
    {
        return Ok(SchemaPresence::Runtime);
    }

    Ok(presence)
}

fn schema_value_presence(
    default: Option<&Value>,
    required: bool,
    allows_null: bool,
    may_accept_non_null: bool,
) -> SchemaPresence {
    match default {
        Some(default) if default.is_null() => {
            if may_accept_non_null {
                SchemaPresence::Runtime
            } else {
                SchemaPresence::Absent
            }
        }
        Some(_) => {
            if allows_null {
                SchemaPresence::Runtime
            } else {
                SchemaPresence::Present
            }
        }
        None if required => {
            if allows_null {
                SchemaPresence::Runtime
            } else {
                SchemaPresence::Present
            }
        }
        None => {
            if may_accept_non_null {
                SchemaPresence::Runtime
            } else {
                SchemaPresence::Absent
            }
        }
    }
}

fn leaf_schema_presence(root_schema: &Value, leaf: &SchemaLeaf) -> Result<SchemaPresence> {
    let allows_null = schema_path_accepts_null(root_schema, &leaf.path)?;
    let may_accept_non_null = schema_path_may_accept_non_null(root_schema, &leaf.path)?;
    let presence = schema_value_presence(
        leaf.default.as_ref(),
        leaf.required,
        allows_null,
        may_accept_non_null,
    );
    downgrade_present_when_ancestors_are_runtime(root_schema, &leaf.path, presence)
}

enum RequiredLookup {
    Found(bool),
    Missing,
}

#[derive(Default)]
struct RequiredChildLookup<'a> {
    children: Vec<&'a Value>,
    required_here: bool,
}

pub fn schema_path_is_required(root_schema: &Value, path: &str) -> Result<bool> {
    if path.is_empty() {
        return Ok(true);
    }

    let segments = path.split('.').collect::<Vec<_>>();
    if segments.iter().any(|segment| segment.is_empty()) {
        return Err(ConfigError::schema(format!(
            "invalid config path {path:?}: empty segment"
        )));
    }

    let mut visited = BTreeSet::new();
    match lookup_required(
        root_schema,
        root_schema,
        &segments,
        true,
        &mut visited,
        path,
    )? {
        RequiredLookup::Found(required) => Ok(required),
        RequiredLookup::Missing => Err(ConfigError::schema(format!(
            "schema path {path:?} not found"
        ))),
    }
}

fn lookup_required(
    schema: &Value,
    root: &Value,
    segments: &[&str],
    required_so_far: bool,
    visited: &mut BTreeSet<String>,
    full_path: &str,
) -> Result<RequiredLookup> {
    let seg = segments[0];
    let rest = &segments[1..];
    let Some(child_lookup) = lookup_required_children(schema, root, seg, visited, full_path)?
    else {
        return Ok(RequiredLookup::Missing);
    };
    if child_lookup.children.is_empty() {
        return Ok(RequiredLookup::Missing);
    }

    let required_here = required_so_far && child_lookup.required_here;
    if rest.is_empty() {
        return Ok(RequiredLookup::Found(required_here));
    }

    for child in &child_lookup.children {
        if schema_type_includes(child, "array") {
            return Err(ConfigError::schema(format!(
                "cannot descend into array schema at segment {seg:?} for path {full_path:?}"
            )));
        }
    }

    let merged_child = merge_all_of_children(child_lookup.children);
    lookup_required(&merged_child, root, rest, required_here, visited, full_path)
}

fn lookup_required_children<'a>(
    schema: &'a Value,
    root: &'a Value,
    segment: &str,
    visited: &mut BTreeSet<String>,
    _full_path: &str,
) -> Result<Option<RequiredChildLookup<'a>>> {
    let schema = resolve_schema_ref(schema, root, visited)?;
    ensure_schema_supported(schema)?;

    let mut out = RequiredChildLookup::default();
    out.required_here |= schema_required_set(schema).contains_key(segment);

    if let Some(props) = schema_properties(schema)
        && let Some(child) = props.get(segment)
    {
        out.children.push(child);
    }

    if let Some(all_of) = schema.get("allOf").and_then(Value::as_array) {
        for subschema in all_of {
            if let Some(sub_lookup) =
                lookup_required_children(subschema, root, segment, visited, _full_path)?
            {
                out.required_here |= sub_lookup.required_here;
                out.children.extend(sub_lookup.children);
            }
        }
    }

    if out.children.is_empty() && !out.required_here {
        Ok(None)
    } else {
        Ok(Some(out))
    }
}

fn merge_all_of_children(children: Vec<&Value>) -> Value {
    match children.as_slice() {
        [] => Value::Object(Map::new()),
        [child] => (*child).clone(),
        _ => {
            let mut merged = Map::new();
            merged.insert(
                "allOf".to_string(),
                Value::Array(children.into_iter().cloned().collect()),
            );
            Value::Object(merged)
        }
    }
}

pub fn schema_path_presence(root_schema: &Value, path: &str) -> Result<SchemaPresence> {
    validate_config_schema(root_schema)?;

    if path.is_empty() {
        return Ok(SchemaPresence::Present);
    }

    match schema_lookup(root_schema, path) {
        Ok(SchemaLookup::Found) => {}
        Ok(SchemaLookup::Unknown) => return Ok(SchemaPresence::Runtime),
        Err(_) => return Ok(SchemaPresence::Absent),
    }

    let defaults = collect_schema_defaults(root_schema)?;
    let schema = schema_lookup_ref(root_schema, path)?;
    let is_container = schema_properties(schema).is_some();
    let allows_null = schema_path_accepts_null(root_schema, path)?;
    let may_accept_non_null = schema_path_may_accept_non_null(root_schema, path)?;

    if let Some(default) = defaults
        .as_ref()
        .and_then(|defaults| value_at_path(defaults, path))
    {
        let presence =
            schema_value_presence(Some(default), false, allows_null, may_accept_non_null);
        return downgrade_present_when_ancestors_are_runtime(root_schema, path, presence);
    }

    if is_container && schema_path_is_required(root_schema, path)? {
        let presence = schema_value_presence(None, true, allows_null, may_accept_non_null);
        return downgrade_present_when_ancestors_are_runtime(root_schema, path, presence);
    }

    let leaves = collect_leaf_paths(root_schema)?;
    let prefix = format!("{path}.");
    let matching = leaves
        .iter()
        .filter(|leaf| leaf.path == path || leaf.path.starts_with(&prefix));

    let mut saw_present = false;
    let mut saw_runtime = false;

    for leaf in matching {
        match leaf_schema_presence(root_schema, leaf)? {
            SchemaPresence::Present => saw_present = true,
            SchemaPresence::Runtime => saw_runtime = true,
            SchemaPresence::Absent => {}
        }
    }

    Ok(if saw_present {
        SchemaPresence::Present
    } else if saw_runtime {
        SchemaPresence::Runtime
    } else {
        SchemaPresence::Absent
    })
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

            let pointer = push_pointer(&push_pointer(&cursor.pointer, "properties")?, k.as_str())?;

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
            let pointer = push_pointer(&push_pointer(&cursor.pointer, "allOf")?, &idx.to_string())?;
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
    let canonical_bytes =
        serde_jcs::to_vec(v).expect("serializing config schema to canonical JSON should succeed");
    serde_json::from_slice(&canonical_bytes)
        .expect("canonical JSON bytes should deserialize back into JSON value")
}

// Produce a minimized schema that only includes explicitly allowed leaf paths.
// This is used to avoid exposing unrelated config/schema data to untrusted runtimes.
pub fn prune_schema(schema: &Value, allowed_leaf_paths: &BTreeSet<String>) -> Result<Value> {
    let mut visited = BTreeSet::new();
    prune_schema_inner(schema, schema, allowed_leaf_paths, "", &mut visited)
}

fn prune_schema_inner(
    schema: &Value,
    root: &Value,
    allowed_leaf_paths: &BTreeSet<String>,
    prefix: &str,
    visited: &mut BTreeSet<String>,
) -> Result<Value> {
    let Value::Object(map) = schema else {
        return Ok(schema.clone());
    };

    if let Some(reference) = map.get("$ref").and_then(|v| v.as_str()) {
        if map.len() == 1 {
            let (resolved, pointer) = resolve_local_ref(root, reference)?;
            if !visited.insert(pointer.clone()) {
                return Err(ConfigError::schema(
                    "config_schema contains a cyclic $ref".to_string(),
                ));
            }
            let out = prune_schema_inner(resolved, root, allowed_leaf_paths, prefix, visited)?;
            visited.remove(&pointer);
            return Ok(out);
        }

        let mut rest = map.clone();
        rest.remove("$ref");
        let mut ref_map = Map::new();
        ref_map.insert("$ref".to_string(), Value::String(reference.to_string()));
        let all_of = Value::Array(vec![Value::Object(ref_map), Value::Object(rest)]);
        let mut merged = Map::new();
        merged.insert("allOf".to_string(), all_of);
        let merged = Value::Object(merged);
        return prune_schema_inner(&merged, root, allowed_leaf_paths, prefix, visited);
    }

    let mut out = Map::new();
    let mut kept_keys = BTreeSet::new();

    if let Some(props) = schema_properties(schema) {
        let mut keys: Vec<&String> = props.keys().collect();
        keys.sort();

        let mut pruned_props = Map::new();
        for key in keys {
            let child_path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            if !path_allowed(&child_path, allowed_leaf_paths) {
                continue;
            }
            let child_schema = props.get(key.as_str()).expect("key exists");
            let pruned =
                prune_schema_inner(child_schema, root, allowed_leaf_paths, &child_path, visited)?;
            pruned_props.insert(key.clone(), pruned);
            kept_keys.insert(key.clone());
        }

        if !pruned_props.is_empty() {
            out.insert("properties".to_string(), Value::Object(pruned_props));
        }
    }

    if let Some(required) = map.get("required").and_then(|v| v.as_array()) {
        let mut filtered = Vec::new();
        for item in required {
            let Some(name) = item.as_str() else {
                continue;
            };
            if kept_keys.contains(name) {
                filtered.push(Value::String(name.to_string()));
            }
        }
        if !filtered.is_empty() {
            out.insert("required".to_string(), Value::Array(filtered));
        }
    }

    if let Some(all_of) = map.get("allOf").and_then(|v| v.as_array()) {
        let mut pruned_all_of = Vec::new();
        for subschema in all_of {
            let pruned = prune_schema_inner(subschema, root, allowed_leaf_paths, prefix, visited)?;
            if !is_empty_schema(&pruned) {
                pruned_all_of.push(pruned);
            }
        }
        if !pruned_all_of.is_empty() {
            out.insert("allOf".to_string(), Value::Array(pruned_all_of));
        }
    }

    for (key, value) in map {
        if matches!(
            key.as_str(),
            "$ref" | "properties" | "required" | "allOf" | "definitions" | "$defs"
        ) {
            continue;
        }
        out.insert(key.clone(), value.clone());
    }

    Ok(Value::Object(out))
}

fn path_allowed(path: &str, allowed_leaf_paths: &BTreeSet<String>) -> bool {
    for allowed in allowed_leaf_paths {
        if allowed == path {
            return true;
        }
        if allowed.starts_with(path) && allowed.as_bytes().get(path.len()) == Some(&b'.') {
            return true;
        }
    }
    false
}

fn is_empty_schema(value: &Value) -> bool {
    matches!(value, Value::Object(map) if map.is_empty())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

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
}
