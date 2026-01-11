use std::collections::BTreeMap;

use amber_manifest::{InterpolatedPart, InterpolatedString, InterpolationSource};
use amber_template::{ConfigTemplate, ConfigTemplatePayload};
pub use amber_template::{ProgramTemplateSpec, TemplatePart, TemplateSpec, TemplateString};
use serde_json::{Map, Number, Value};

pub fn template_string_is_runtime(ts: &TemplateString) -> bool {
    ts.iter().any(|p| p.is_config())
}

/// Template IR for component config values (internal to compiler/reporter).
///
/// Can be serialized to the JSON IR described in the design doc:
/// - `{"$config":"path"}`
/// - `{"$template":[{"lit":"..."},{"config":"path"}]}`
/// - ordinary JSON literals/arrays/objects
#[derive(Clone, Debug, PartialEq)]
pub enum ConfigNode {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<ConfigNode>),
    Object(BTreeMap<String, ConfigNode>),

    /// Insert the referenced value from the (root) config at runtime.
    /// Path is relative to the root config (empty means the whole root config object).
    ConfigRef(String),

    /// Render a string by concatenating parts at runtime (resolved against root config).
    StringTemplate(TemplateString),
}

impl ConfigNode {
    pub fn empty_object() -> Self {
        Self::Object(BTreeMap::new())
    }

    pub fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }

    pub fn contains_runtime(&self) -> bool {
        match self {
            Self::ConfigRef(_) => true,
            Self::StringTemplate(parts) => parts.iter().any(|p| p.is_config()),
            Self::Array(items) => items.iter().any(|n| n.contains_runtime()),
            Self::Object(map) => map.values().any(|n| n.contains_runtime()),
            _ => false,
        }
    }

    pub fn to_template(&self) -> ConfigTemplate {
        match self {
            Self::Null => ConfigTemplate::Literal(Value::Null),
            Self::Bool(b) => ConfigTemplate::Literal(Value::Bool(*b)),
            Self::Number(n) => ConfigTemplate::Literal(Value::Number(n.clone())),
            Self::String(s) => ConfigTemplate::Literal(Value::String(s.clone())),
            Self::Array(items) => {
                ConfigTemplate::Array(items.iter().map(|n| n.to_template()).collect())
            }
            Self::Object(map) => ConfigTemplate::Object(
                map.iter()
                    .map(|(k, v)| (k.clone(), v.to_template()))
                    .collect(),
            ),
            Self::ConfigRef(path) => ConfigTemplate::ConfigRef { path: path.clone() },
            Self::StringTemplate(parts) => ConfigTemplate::TemplateString {
                parts: parts.clone(),
            },
        }
    }

    /// Evaluate to a concrete JSON value (only possible if it is fully static).
    pub fn evaluate_static(&self) -> Result<Value, String> {
        match self {
            Self::Null => Ok(Value::Null),
            Self::Bool(b) => Ok(Value::Bool(*b)),
            Self::Number(n) => Ok(Value::Number(n.clone())),
            Self::String(s) => Ok(Value::String(s.clone())),
            Self::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(item.evaluate_static()?);
                }
                Ok(Value::Array(out))
            }
            Self::Object(map) => {
                let mut out = Map::new();
                for (k, v) in map {
                    out.insert(k.clone(), v.evaluate_static()?);
                }
                Ok(Value::Object(out))
            }
            Self::ConfigRef(path) => Err(format!(
                "cannot evaluate runtime config reference {:?} at compile time",
                path
            )),
            Self::StringTemplate(parts) => {
                if template_string_is_runtime(parts) {
                    return Err("cannot evaluate runtime string template at compile time".into());
                }
                let mut s = String::new();
                for part in parts {
                    let TemplatePart::Lit { lit } = part else {
                        unreachable!("no config parts in static template");
                    };
                    s.push_str(lit);
                }
                Ok(Value::String(s))
            }
        }
    }

    /// Build a "static subset" JSON value for compile-time validation.
    ///
    /// Runtime-dependent leaves are omitted from objects. Arrays are all-or-nothing: if any element
    /// depends on runtime config, the whole array is omitted.
    pub fn static_subset(&self) -> Option<Value> {
        match self {
            Self::ConfigRef(_) => None,
            Self::StringTemplate(parts) => {
                if template_string_is_runtime(parts) {
                    None
                } else {
                    let mut s = String::new();
                    for part in parts {
                        let TemplatePart::Lit { lit } = part else {
                            unreachable!("no config parts in static template");
                        };
                        s.push_str(lit);
                    }
                    Some(Value::String(s))
                }
            }
            Self::Null => Some(Value::Null),
            Self::Bool(b) => Some(Value::Bool(*b)),
            Self::Number(n) => Some(Value::Number(n.clone())),
            Self::String(s) => Some(Value::String(s.clone())),
            Self::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(item.static_subset()?);
                }
                Some(Value::Array(out))
            }
            Self::Object(map) => {
                let mut out = Map::new();
                for (k, v) in map {
                    if let Some(child) = v.static_subset() {
                        out.insert(k.clone(), child);
                    }
                }
                Some(Value::Object(out))
            }
        }
    }

    pub fn get_path(&self, path: &str) -> Result<&ConfigNode, String> {
        if path.is_empty() {
            return Ok(self);
        }

        let mut cur = self;
        for seg in path.split('.') {
            if seg.is_empty() {
                return Err("config path contains an empty segment".into());
            }
            match cur {
                Self::Object(map) => {
                    cur = map.get(seg).ok_or_else(|| {
                        format!("config path {:?} not found (missing key {:?})", path, seg)
                    })?;
                }
                Self::ConfigRef(_) => {
                    return Err(format!(
                        "config path {:?} is runtime-derived; cannot descend into {:?} at compile \
                         time",
                        path, seg
                    ));
                }
                _ => {
                    return Err(format!(
                        "config path {:?} not found (encountered non-object before segment {:?})",
                        path, seg
                    ));
                }
            }
        }
        Ok(cur)
    }

    pub fn clone_path(&self, path: &str) -> Result<ConfigNode, String> {
        Ok(self.get_path(path)?.clone())
    }

    /// Simplify away now-static string templates (turn them into literal strings).
    pub fn simplify(self) -> ConfigNode {
        match self {
            Self::Array(items) => Self::Array(items.into_iter().map(|n| n.simplify()).collect()),
            Self::Object(map) => {
                Self::Object(map.into_iter().map(|(k, v)| (k, v.simplify())).collect())
            }
            Self::StringTemplate(parts) => {
                if template_string_is_runtime(&parts) {
                    Self::StringTemplate(parts)
                } else {
                    let mut s = String::new();
                    for part in parts {
                        let TemplatePart::Lit { lit } = part else {
                            unreachable!("no config parts in static template");
                        };
                        s.push_str(&lit);
                    }
                    Self::String(s)
                }
            }
            other => other,
        }
    }
}

#[derive(Clone, Debug)]
pub enum RootConfigTemplate {
    /// Identity mapping: the component's config is the root config.
    /// On-wire, encoded as the JSON literal `null` (root component only).
    Root,
    /// An object template expressed in terms of the root config.
    Node(ConfigNode),
}

impl RootConfigTemplate {
    pub fn to_template_payload(&self) -> ConfigTemplatePayload {
        match self {
            RootConfigTemplate::Root => ConfigTemplatePayload::Root,
            RootConfigTemplate::Node(node) => ConfigTemplatePayload::Template(node.to_template()),
        }
    }

    pub fn to_json_ir(&self) -> Value {
        self.to_template_payload().to_value()
    }
}

/// Return `true` if `key` is a valid Amber config schema property name.
///
/// Required to make `AMBER_CONFIG_*` mapping injective.
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

fn schema_is_object_with_properties(schema: &Value) -> bool {
    schema_type_includes(schema, "object") && schema_properties(schema).is_some()
}

/// Validate that a config schema is object-shaped and that all `properties` keys are valid.
///
/// The manifest layer already ensures it is valid JSON Schema; this adds Amber-specific constraints.
pub fn validate_config_schema(schema: &Value) -> Result<(), String> {
    if !schema_type_includes(schema, "object") {
        return Err("config_schema must have type \"object\"".to_string());
    }

    fn walk(schema: &Value, at: &str) -> Result<(), String> {
        let Some(props) = schema_properties(schema) else {
            return Ok(());
        };

        if !schema_type_includes(schema, "object") {
            return Err(format!(
                "schema at {at} has `properties` but is not type \"object\""
            ));
        }

        // Deterministic ordering.
        let mut keys: Vec<&String> = props.keys().collect();
        keys.sort();

        for k in keys {
            if !is_valid_config_key(k.as_str()) {
                return Err(format!(
                    "invalid config schema property name {k:?} at {at} (must match \
                     ^[a-z][a-z0-9_]*$ and must not contain '.' or '__')"
                ));
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

/// Look up a subschema by a dotted property path (e.g. `db.url`).
///
/// Arrays are treated as leaves: you may not descend into them.
pub fn schema_lookup<'a>(schema: &'a Value, path: &str) -> Result<&'a Value, String> {
    if path.is_empty() {
        return Ok(schema);
    }

    let mut cur = schema;
    let mut it = path.split('.').peekable();

    while let Some(seg) = it.next() {
        if seg.is_empty() {
            return Err(format!("invalid config path {path:?}: empty segment"));
        }
        if !is_valid_config_key(seg) {
            return Err(format!("invalid config path segment {seg:?} in {path:?}"));
        }

        let Some(props) = schema_properties(cur) else {
            return Err(format!(
                "config path {path:?} not found (schema has no properties at segment {seg:?})"
            ));
        };

        let Some(next) = props.get(seg) else {
            return Err(format!(
                "config path {path:?} not found (unknown key {seg:?})"
            ));
        };

        if it.peek().is_some() {
            if schema_type_includes(next, "array") {
                return Err(format!(
                    "invalid config path {path:?}: cannot descend into array at segment {seg:?}"
                ));
            }
            if !schema_is_object_with_properties(next) {
                return Err(format!(
                    "invalid config path {path:?}: cannot descend into non-object schema at \
                     segment {seg:?}"
                ));
            }
        }

        cur = next;
    }

    Ok(cur)
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

/// A leaf property path in an object-shaped config schema.
#[derive(Clone, Debug)]
pub struct SchemaLeaf {
    pub path: String,
    pub required: bool,
}

/// Collect all leaf property paths from an object-shaped schema.
///
/// Leaves are properties whose subschema is not an object-with-properties. Arrays are treated as
/// leaves.
pub fn collect_leaf_paths(schema: &Value) -> Result<Vec<SchemaLeaf>, String> {
    validate_config_schema(schema)?;

    let mut out = Vec::new();

    fn walk(
        schema: &Value,
        prefix: &str,
        required_so_far: bool,
        out: &mut Vec<SchemaLeaf>,
    ) -> Result<(), String> {
        let Some(props) = schema_properties(schema) else {
            return Ok(());
        };
        let req = schema_required_set(schema);

        // Deterministic ordering.
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

            if schema_is_object_with_properties(child_schema) {
                walk(child_schema, &path, req_path, out)?;
            } else {
                out.push(SchemaLeaf {
                    path,
                    required: req_path,
                });
            }
        }

        Ok(())
    }

    walk(schema, "", true, &mut out)?;
    Ok(out)
}

/// Map a config leaf path (like `db.url`) to its corresponding env var name
/// (like `AMBER_CONFIG_DB__URL`).
pub fn env_var_for_path(path: &str) -> Result<String, String> {
    if path.is_empty() {
        return Err("config path cannot be empty".to_string());
    }
    let mut segs = Vec::new();
    for seg in path.split('.') {
        if seg.is_empty() {
            return Err(format!("invalid config path {path:?}: empty segment"));
        }
        if !is_valid_config_key(seg) {
            return Err(format!(
                "invalid config path segment {seg:?} in {path:?} (must match ^[a-z][a-z0-9_]*$ \
                 and must not contain '__')"
            ));
        }
        segs.push(seg.to_ascii_uppercase());
    }
    Ok(format!("AMBER_CONFIG_{}", segs.join("__")))
}

/// Convert a JSON value into the string form used by `${config.*}` interpolation.
///
/// - `null` is an error
/// - strings are used directly
/// - numbers/bools use their JSON text form
/// - arrays/objects are serialized to JSON
pub fn stringify_for_interpolation(v: &Value) -> Result<String, String> {
    match v {
        Value::Null => Err("cannot interpolate null".to_string()),
        Value::String(s) => Ok(s.clone()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Array(_) | Value::Object(_) => serde_json::to_string(v)
            .map_err(|e| format!("failed to serialize value as JSON for interpolation: {e}")),
    }
}

/// Parse a use-site component config value (`components.<name>.config`) into a template tree
/// whose config references are relative to the parent config root.
///
/// `value` must be an object; `None` becomes `{}`.
pub fn parse_instance_config_template(
    value: Option<&Value>,
    parent_schema: Option<&Value>,
) -> Result<ConfigNode, String> {
    let Some(value) = value else {
        return Ok(ConfigNode::empty_object());
    };

    let Value::Object(map) = value else {
        return Err("component config must be a JSON object".to_string());
    };

    let mut out = BTreeMap::new();
    for (k, v) in map {
        out.insert(k.clone(), parse_config_value_template(v, parent_schema)?);
    }
    Ok(ConfigNode::Object(out))
}

fn parse_string_template(s: &str, parent_schema: Option<&Value>) -> Result<ConfigNode, String> {
    let parsed: InterpolatedString = s.parse::<InterpolatedString>().map_err(|e| e.to_string())?;

    // Fast path: no interpolations.
    let has_interp = parsed
        .parts
        .iter()
        .any(|p| matches!(p, InterpolatedPart::Interpolation { .. }));
    if !has_interp {
        return Ok(ConfigNode::String(s.to_string()));
    }

    // Validate + build parts.
    let mut parts: TemplateString = Vec::new();

    for part in parsed.parts {
        match part {
            InterpolatedPart::Literal(lit) => parts.push(TemplatePart::lit(lit)),
            InterpolatedPart::Interpolation { source, query } => match source {
                InterpolationSource::Config => {
                    let schema = parent_schema.ok_or_else(|| {
                        format!(
                            "config interpolation ${{config{}}} is not allowed because the parent \
                             component has no config_schema",
                            if query.is_empty() {
                                "".to_string()
                            } else {
                                format!(".{query}")
                            }
                        )
                    })?;

                    // Validate the referenced path exists in the parent schema.
                    let _ = schema_lookup(schema, query.as_str())
                        .map_err(|e| format!("invalid parent config reference {query:?}: {e}"))?;

                    parts.push(TemplatePart::config(query));
                }
                InterpolationSource::Slots => {
                    return Err(
                        "slot interpolation is not allowed in component config templates"
                            .to_string(),
                    );
                }
                other => {
                    return Err(format!(
                        "unsupported interpolation source {other} in component config template"
                    ));
                }
            },
            _ => {
                return Err(
                    "unsupported interpolation part in component config template".to_string(),
                );
            }
        }
    }

    // If the entire string is exactly one `${config.*}`, use a config ref node so non-scalars can be inserted.
    if parts.len() == 1
        && let TemplatePart::Config { config } = &parts[0]
    {
        return Ok(ConfigNode::ConfigRef(config.clone()));
    }

    Ok(ConfigNode::StringTemplate(parts))
}

fn parse_config_value_template(
    v: &Value,
    parent_schema: Option<&Value>,
) -> Result<ConfigNode, String> {
    match v {
        Value::Null => Ok(ConfigNode::Null),
        Value::Bool(b) => Ok(ConfigNode::Bool(*b)),
        Value::Number(n) => Ok(ConfigNode::Number(n.clone())),
        Value::String(s) => parse_string_template(s, parent_schema),
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(parse_config_value_template(item, parent_schema)?);
            }
            Ok(ConfigNode::Array(out))
        }
        Value::Object(map) => {
            let mut out = BTreeMap::new();
            for (k, vv) in map {
                out.insert(k.clone(), parse_config_value_template(vv, parent_schema)?);
            }
            Ok(ConfigNode::Object(out))
        }
    }
}

fn resolve_against_parent(
    parent: &RootConfigTemplate,
    parent_path: &str,
) -> Result<ConfigNode, String> {
    match parent {
        RootConfigTemplate::Root => Ok(ConfigNode::ConfigRef(parent_path.to_string())),
        RootConfigTemplate::Node(node) => node.clone_path(parent_path),
    }
}

fn inline_as_template_parts(node: &ConfigNode) -> Result<TemplateString, String> {
    match node {
        ConfigNode::ConfigRef(path) => Ok(vec![TemplatePart::config(path.clone())]),
        ConfigNode::StringTemplate(parts) => Ok(parts.clone()),
        _ if !node.contains_runtime() => {
            let value = node.evaluate_static()?;
            let s = stringify_for_interpolation(&value)?;
            Ok(vec![TemplatePart::lit(s)])
        }
        _ => Err(
            "cannot embed a runtime-derived non-string config value into a string template \
             (consider restructuring your config so the referenced value comes directly from root \
             config)"
                .to_string(),
        ),
    }
}

/// Compose a child config template (relative to the parent config) against a parent template (root-only),
/// producing a new template that references only root config.
pub fn compose_config_template(
    child: ConfigNode,
    parent: &RootConfigTemplate,
) -> Result<ConfigNode, String> {
    fn go(node: ConfigNode, parent: &RootConfigTemplate) -> Result<ConfigNode, String> {
        match node {
            ConfigNode::ConfigRef(parent_path) => resolve_against_parent(parent, &parent_path),
            ConfigNode::StringTemplate(parts) => {
                let mut out: TemplateString = Vec::new();
                for part in parts {
                    match part {
                        TemplatePart::Lit { lit } => out.push(TemplatePart::lit(lit)),
                        TemplatePart::Config {
                            config: parent_path,
                        } => {
                            let resolved = resolve_against_parent(parent, &parent_path)?;
                            let inlined = inline_as_template_parts(&resolved)?;
                            out.extend(inlined);
                        }
                    }
                }
                Ok(ConfigNode::StringTemplate(out).simplify())
            }
            ConfigNode::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(go(item, parent)?);
                }
                Ok(ConfigNode::Array(out))
            }
            ConfigNode::Object(map) => {
                let mut out = BTreeMap::new();
                for (k, v) in map {
                    out.insert(k, go(v, parent)?);
                }
                Ok(ConfigNode::Object(out))
            }
            other => Ok(other),
        }
    }

    go(child, parent)
}

/// Produce a canonicalized JSON value with deterministic object key ordering.
///
/// Useful for stable base64 payloads.
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
