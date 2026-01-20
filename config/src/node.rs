use std::collections::BTreeMap;

use amber_template::{ConfigTemplate, ConfigTemplatePayload, TemplatePart, TemplateString};
use serde_json::{Map, Number, Value};

use crate::{ConfigError, Result, stringify_for_interpolation, template_string_is_runtime};

#[derive(Clone, Debug, PartialEq)]
pub enum ConfigNode {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<ConfigNode>),
    Object(BTreeMap<String, ConfigNode>),

    ConfigRef(String),
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
            Self::StringTemplate(parts) => template_string_is_runtime(parts),
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

    pub fn evaluate_static(&self) -> Result<Value> {
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
            Self::ConfigRef(path) => Err(ConfigError::interp(format!(
                "cannot evaluate runtime config reference {:?} at compile time",
                path
            ))),
            Self::StringTemplate(parts) => {
                if template_string_is_runtime(parts) {
                    return Err(ConfigError::interp(
                        "cannot evaluate runtime string template at compile time",
                    ));
                }
                let mut s = String::new();
                for part in parts {
                    let TemplatePart::Lit { lit } = part else {
                        unreachable!("no config or binding parts in static template");
                    };
                    s.push_str(lit);
                }
                Ok(Value::String(s))
            }
        }
    }

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
                            unreachable!("no config or binding parts in static template");
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

    pub fn get_path(&self, path: &str) -> Result<&ConfigNode> {
        if path.is_empty() {
            return Ok(self);
        }

        let mut cur = self;
        for seg in path.split('.') {
            if seg.is_empty() {
                return Err(ConfigError::interp("config path contains an empty segment"));
            }
            match cur {
                Self::Object(map) => {
                    cur = map.get(seg).ok_or_else(|| {
                        ConfigError::interp(format!(
                            "config path {:?} not found (missing key {:?})",
                            path, seg
                        ))
                    })?;
                }
                Self::ConfigRef(_) => {
                    return Err(ConfigError::interp(format!(
                        "config path {:?} is runtime-derived; cannot descend into {:?} at compile \
                         time",
                        path, seg
                    )));
                }
                _ => {
                    return Err(ConfigError::interp(format!(
                        "config path {:?} not found (encountered non-object before segment {:?})",
                        path, seg
                    )));
                }
            }
        }
        Ok(cur)
    }

    pub fn clone_path(&self, path: &str) -> Result<ConfigNode> {
        Ok(self.get_path(path)?.clone())
    }

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
                            unreachable!("no config or binding parts in static template");
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
    Root,
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

fn resolve_against_parent(parent: &RootConfigTemplate, parent_path: &str) -> Result<ConfigNode> {
    match parent {
        RootConfigTemplate::Root => Ok(ConfigNode::ConfigRef(parent_path.to_string())),
        RootConfigTemplate::Node(node) => node.clone_path(parent_path),
    }
}

fn inline_as_template_parts(node: &ConfigNode) -> Result<TemplateString> {
    match node {
        ConfigNode::ConfigRef(path) => Ok(vec![TemplatePart::config(path.clone())]),
        ConfigNode::StringTemplate(parts) => Ok(parts.clone()),
        _ if !node.contains_runtime() => {
            let value = node.evaluate_static()?;
            let s = stringify_for_interpolation(&value)?;
            Ok(vec![TemplatePart::lit(s)])
        }
        _ => Err(ConfigError::interp(
            "cannot embed a runtime-derived non-string config value into a string template \
             (consider restructuring your config so the referenced value comes directly from root \
             config)"
                .to_string(),
        )),
    }
}

pub fn compose_config_template(
    child: ConfigNode,
    parent: &RootConfigTemplate,
) -> Result<ConfigNode> {
    fn go(node: ConfigNode, parent: &RootConfigTemplate) -> Result<ConfigNode> {
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
                        TemplatePart::Binding { binding, scope } => {
                            out.push(TemplatePart::binding(scope, binding));
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
