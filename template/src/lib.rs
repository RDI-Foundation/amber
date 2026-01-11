use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TemplatePart {
    Lit { lit: String },
    Config { config: String },
}

impl TemplatePart {
    pub fn lit(value: impl Into<String>) -> Self {
        Self::Lit { lit: value.into() }
    }

    pub fn config(value: impl Into<String>) -> Self {
        Self::Config {
            config: value.into(),
        }
    }

    pub fn as_lit(&self) -> Option<&str> {
        match self {
            Self::Lit { lit } => Some(lit.as_str()),
            Self::Config { .. } => None,
        }
    }

    pub fn is_config(&self) -> bool {
        matches!(self, Self::Config { .. })
    }
}

pub type TemplateString = Vec<TemplatePart>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateSpec {
    pub program: ProgramTemplateSpec,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramTemplateSpec {
    pub entrypoint: Vec<TemplateString>,
    #[serde(default)]
    pub env: BTreeMap<String, TemplateString>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ConfigTemplatePayload {
    Root,
    Template(ConfigTemplate),
}

impl ConfigTemplatePayload {
    pub fn to_value(&self) -> Value {
        match self {
            Self::Root => Value::Null,
            Self::Template(template) => template.to_value(),
        }
    }

    pub fn from_value(value: Value) -> Result<Self, String> {
        if value.is_null() {
            return Ok(Self::Root);
        }
        Ok(Self::Template(ConfigTemplate::from_value(value)?))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ConfigTemplate {
    Literal(Value),
    ConfigRef { path: String },
    TemplateString { parts: TemplateString },
    Object(BTreeMap<String, ConfigTemplate>),
    Array(Vec<ConfigTemplate>),
}

impl ConfigTemplate {
    pub fn to_value(&self) -> Value {
        match self {
            Self::Literal(value) => value.clone(),
            Self::ConfigRef { path } => {
                let mut map = Map::new();
                map.insert("$config".to_string(), Value::String(path.clone()));
                Value::Object(map)
            }
            Self::TemplateString { parts } => {
                let mut map = Map::new();
                map.insert(
                    "$template".to_string(),
                    serde_json::to_value(parts).expect("template parts should serialize"),
                );
                Value::Object(map)
            }
            Self::Object(values) => Value::Object(
                values
                    .iter()
                    .map(|(k, v)| (k.clone(), v.to_value()))
                    .collect(),
            ),
            Self::Array(values) => Value::Array(values.iter().map(|v| v.to_value()).collect()),
        }
    }

    pub fn from_value(value: Value) -> Result<Self, String> {
        match value {
            Value::Object(map) => Self::from_map(map),
            Value::Array(values) => Ok(Self::Array(
                values
                    .into_iter()
                    .map(Self::from_value)
                    .collect::<Result<_, _>>()?,
            )),
            other => Ok(Self::Literal(other)),
        }
    }

    fn from_map(mut map: Map<String, Value>) -> Result<Self, String> {
        if map.len() == 1 {
            if let Some(value) = map.remove("$config") {
                let Value::String(path) = value else {
                    return Err("$config value must be a string".to_string());
                };
                return Ok(Self::ConfigRef { path });
            }
            if let Some(value) = map.remove("$template") {
                let parts: TemplateString =
                    serde_json::from_value(value).map_err(|err| err.to_string())?;
                return Ok(Self::TemplateString { parts });
            }
        }

        let values = map
            .into_iter()
            .map(|(k, v)| Ok((k, Self::from_value(v)?)))
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        Ok(Self::Object(values))
    }
}
