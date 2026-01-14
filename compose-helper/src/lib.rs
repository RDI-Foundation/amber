use std::{collections::BTreeMap, ffi::OsString};

use amber_config::{self as config, CONFIG_ENV_PREFIX, ConfigError};
use amber_template::{ConfigTemplatePayload, TemplateSpec};
use base64::Engine as _;
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

const ROOT_SCHEMA_ENV: &str = "AMBER_ROOT_CONFIG_SCHEMA_B64";
const COMPONENT_SCHEMA_ENV: &str = "AMBER_COMPONENT_CONFIG_SCHEMA_B64";
const COMPONENT_TEMPLATE_ENV: &str = "AMBER_COMPONENT_CONFIG_TEMPLATE_B64";
const TEMPLATE_SPEC_ENV: &str = "AMBER_TEMPLATE_SPEC_B64";

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

impl From<ConfigError> for HelperError {
    fn from(err: ConfigError) -> Self {
        match err {
            ConfigError::Msg(message) => HelperError::Msg(message),
            ConfigError::Schema(message) => HelperError::Schema(message),
            ConfigError::Validation(message) => HelperError::Validation(message),
            ConfigError::Interp(message) => HelperError::Interp(message),
        }
    }
}

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
            _ if key_str.starts_with(CONFIG_ENV_PREFIX) => {
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
    let root_config = config::build_root_config(&root_schema, &config_env)?;

    // 2) Resolve component config from template.
    let component_config = config::eval_config_template(&component_template, &root_config)?;

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
        entrypoint.push(config::render_template_string(ts, &component_config)?);
    }

    let mut rendered_env: BTreeMap<String, String> = BTreeMap::new();
    for (k, ts) in &spec.program.env {
        rendered_env.insert(
            k.clone(),
            config::render_template_string(ts, &component_config)?,
        );
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

#[cfg(test)]
mod tests {
    use amber_template::TemplatePart;
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
                .any(|k| k.to_string_lossy().starts_with(CONFIG_ENV_PREFIX))
        );
        assert!(!plan.env.contains_key(&OsString::from(TEMPLATE_SPEC_ENV)));
    }
}
