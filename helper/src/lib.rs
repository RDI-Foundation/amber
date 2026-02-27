use std::{collections::BTreeMap, ffi::OsString};

use amber_config::{self as config, CONFIG_ENV_PREFIX, ConfigError};
use amber_template::{ConfigTemplatePayload, TemplateSpec};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

const ROOT_SCHEMA_ENV: &str = "AMBER_ROOT_CONFIG_SCHEMA_B64";
const COMPONENT_SCHEMA_ENV: &str = "AMBER_COMPONENT_CONFIG_SCHEMA_B64";
const COMPONENT_TEMPLATE_ENV: &str = "AMBER_COMPONENT_CONFIG_TEMPLATE_B64";
const TEMPLATE_SPEC_ENV: &str = "AMBER_TEMPLATE_SPEC_B64";
const DIRECT_ENTRYPOINT_ENV: &str = "AMBER_DIRECT_ENTRYPOINT_B64";
const DIRECT_ENV_ENV: &str = "AMBER_DIRECT_ENV_B64";
const MOUNT_SPEC_ENV: &str = "AMBER_MOUNT_SPEC_B64";
const DOCKER_MOUNT_PROXY_SPEC_ENV: &str = "AMBER_DOCKER_MOUNT_PROXY_SPEC_B64";

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum MountSpec {
    Literal { path: String, content: String },
    Config { path: String, config: String },
}

#[derive(Debug, Deserialize, Serialize)]
struct DockerMountProxySpec {
    path: String,
    tcp_host: String,
    tcp_port: u16,
}

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
    pub docker_mount_proxies: Vec<(String, String, u16)>,
}

pub fn build_run_plan(env: impl IntoIterator<Item = (OsString, OsString)>) -> Result<RunPlan> {
    let mut passthrough_env = BTreeMap::new();
    let mut config_env = BTreeMap::new();
    let mut root_schema_b64 = None;
    let mut component_schema_b64 = None;
    let mut component_template_b64 = None;
    let mut template_spec_b64 = None;
    let mut direct_entrypoint_b64 = None;
    let mut direct_env_b64 = None;
    let mut mount_spec_b64 = None;
    let mut docker_mount_proxy_spec_b64 = None;

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
            DIRECT_ENTRYPOINT_ENV => {
                let value = value.into_string().map_err(|_| {
                    HelperError::Msg(format!("{DIRECT_ENTRYPOINT_ENV} is required"))
                })?;
                direct_entrypoint_b64 = Some(value);
            }
            DIRECT_ENV_ENV => {
                let value = value
                    .into_string()
                    .map_err(|_| HelperError::Msg(format!("{DIRECT_ENV_ENV} is required")))?;
                direct_env_b64 = Some(value);
            }
            MOUNT_SPEC_ENV => {
                let value = value
                    .into_string()
                    .map_err(|_| HelperError::Msg(format!("{MOUNT_SPEC_ENV} is required")))?;
                mount_spec_b64 = Some(value);
            }
            DOCKER_MOUNT_PROXY_SPEC_ENV => {
                let value = value.into_string().map_err(|_| {
                    HelperError::Msg(format!("{DOCKER_MOUNT_PROXY_SPEC_ENV} is required"))
                })?;
                docker_mount_proxy_spec_b64 = Some(value);
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

    let mounts = if let Some(raw) = mount_spec_b64.as_deref() {
        decode_b64_json_t::<Vec<MountSpec>>(MOUNT_SPEC_ENV, raw)?
    } else {
        Vec::new()
    };
    let docker_mount_proxies = if let Some(raw) = docker_mount_proxy_spec_b64.as_deref() {
        decode_b64_json_t::<Vec<DockerMountProxySpec>>(DOCKER_MOUNT_PROXY_SPEC_ENV, raw)?
    } else {
        Vec::new()
    };

    let config_payload_present = root_schema_b64.is_some()
        || component_schema_b64.is_some()
        || component_template_b64.is_some();
    let has_template_spec = template_spec_b64.is_some();
    let has_direct_entrypoint = direct_entrypoint_b64.is_some();
    let has_direct_env = direct_env_b64.is_some();
    let has_direct_payload = has_direct_entrypoint || has_direct_env;
    let mount_requires_config = mounts
        .iter()
        .any(|mount| matches!(mount, MountSpec::Config { .. }));

    if has_direct_payload && (!has_direct_entrypoint || !has_direct_env) {
        return Err(HelperError::Msg(format!(
            "{DIRECT_ENTRYPOINT_ENV} and {DIRECT_ENV_ENV} are required together"
        )));
    }

    if has_template_spec && has_direct_payload {
        return Err(HelperError::Msg(
            "helper payload must provide either a template spec or a direct entrypoint/env"
                .to_string(),
        ));
    }

    if !has_template_spec && !has_direct_payload {
        return Err(HelperError::Msg(
            "helper payload must include a program entrypoint/env payload".to_string(),
        ));
    }

    if (has_template_spec || mount_requires_config) && !config_payload_present {
        return Err(HelperError::Msg(format!(
            "config payload is required (missing {ROOT_SCHEMA_ENV}, {COMPONENT_SCHEMA_ENV}, \
             {COMPONENT_TEMPLATE_ENV})"
        )));
    }

    let component_config = if config_payload_present {
        let root_schema_b64 = root_schema_b64
            .ok_or_else(|| HelperError::Msg(format!("{ROOT_SCHEMA_ENV} is required")))?;
        let component_schema_b64 = component_schema_b64
            .ok_or_else(|| HelperError::Msg(format!("{COMPONENT_SCHEMA_ENV} is required")))?;
        let component_template_b64 = component_template_b64
            .ok_or_else(|| HelperError::Msg(format!("{COMPONENT_TEMPLATE_ENV} is required")))?;

        let root_schema = decode_b64_json(ROOT_SCHEMA_ENV, &root_schema_b64)?;
        let component_schema = decode_b64_json(COMPONENT_SCHEMA_ENV, &component_schema_b64)?;
        let component_template_value =
            decode_b64_json(COMPONENT_TEMPLATE_ENV, &component_template_b64)?;
        let component_template = ConfigTemplatePayload::from_value(component_template_value)
            .map_err(|err| {
                HelperError::Interp(format!("invalid component config template: {err}"))
            })?;

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
        {
            let validator = jsonschema::validator_for(&component_schema).map_err(|e| {
                HelperError::Schema(format!("failed to compile component schema: {e}"))
            })?;
            let mut it = validator.iter_errors(&component_config);
            if let Some(first) = it.next() {
                let mut msgs = vec![first.to_string()];
                msgs.extend(it.take(7).map(|e| e.to_string()));
                return Err(HelperError::Validation(msgs.join("; ")));
            }
        }

        Some(component_config)
    } else {
        None
    };

    if mount_requires_config && component_config.is_none() {
        return Err(HelperError::Msg(
            "mount specs require config resolution but no config payload was provided".to_string(),
        ));
    }

    let (entrypoint, rendered_env) = if let Some(template_spec_b64) = template_spec_b64 {
        let spec = decode_b64_json_t::<TemplateSpec>(TEMPLATE_SPEC_ENV, &template_spec_b64)?;
        let component_config = component_config
            .as_ref()
            .ok_or_else(|| HelperError::Msg("template spec requires config payload".to_string()))?;

        if spec.program.entrypoint.is_empty() {
            return Err(HelperError::Interp(
                "program.entrypoint is empty; cannot exec".to_string(),
            ));
        }

        let mut entrypoint: Vec<String> = Vec::with_capacity(spec.program.entrypoint.len());
        for ts in &spec.program.entrypoint {
            entrypoint.push(config::render_template_string(ts, component_config)?);
        }

        let mut rendered_env: BTreeMap<String, String> = BTreeMap::new();
        for (k, ts) in &spec.program.env {
            rendered_env.insert(
                k.clone(),
                config::render_template_string(ts, component_config)?,
            );
        }

        (entrypoint, rendered_env)
    } else {
        let entrypoint_b64 = direct_entrypoint_b64
            .ok_or_else(|| HelperError::Msg(format!("{DIRECT_ENTRYPOINT_ENV} is required")))?;
        let env_b64 = direct_env_b64
            .ok_or_else(|| HelperError::Msg(format!("{DIRECT_ENV_ENV} is required")))?;

        let entrypoint = decode_b64_json_t::<Vec<String>>(DIRECT_ENTRYPOINT_ENV, &entrypoint_b64)?;
        let rendered_env = decode_b64_json_t::<BTreeMap<String, String>>(DIRECT_ENV_ENV, &env_b64)?;

        (entrypoint, rendered_env)
    };

    write_mounts(&mounts, component_config.as_ref())?;

    let mut env_out = passthrough_env;
    for (k, v) in rendered_env {
        env_out.insert(OsString::from(k), OsString::from(v));
    }

    Ok(RunPlan {
        entrypoint,
        env: env_out,
        docker_mount_proxies: docker_mount_proxies
            .into_iter()
            .map(|spec| (spec.path, spec.tcp_host, spec.tcp_port))
            .collect(),
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

fn write_mounts(mounts: &[MountSpec], component_config: Option<&Value>) -> Result<()> {
    if mounts.is_empty() {
        return Ok(());
    }

    for mount in mounts {
        let (path, content) = match mount {
            MountSpec::Literal { path, content } => (path.as_str(), content.clone()),
            MountSpec::Config { path, config } => {
                let config_value = component_config.ok_or_else(|| {
                    HelperError::Msg(format!(
                        "mount {path} requires config resolution but helper is in direct mode"
                    ))
                })?;
                let value = config::get_by_path(config_value, config)?;
                let content = config::stringify_for_mount(value)?;
                (path.as_str(), content)
            }
        };

        let mount_path = std::path::Path::new(path);
        if let Some(parent) = mount_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|err| HelperError::Msg(format!("failed to create {parent:?}: {err}")))?;
        }
        std::fs::write(mount_path, content)
            .map_err(|err| HelperError::Msg(format!("failed to write mount {path}: {err}")))?;
    }

    Ok(())
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

    #[test]
    fn direct_mode_writes_mounts() {
        use base64::engine::general_purpose::STANDARD;
        use tempfile::tempdir;

        let dir = tempdir().expect("temp dir");
        let mount_path = dir.path().join("config.txt");

        let entrypoint = vec!["/bin/echo".to_string(), "ok".to_string()];
        let env = BTreeMap::from([("HELLO".to_string(), "world".to_string())]);
        let mounts = vec![MountSpec::Literal {
            path: mount_path.display().to_string(),
            content: "value".to_string(),
        }];

        let envs = BTreeMap::from([
            (
                DIRECT_ENTRYPOINT_ENV.to_string(),
                STANDARD.encode(serde_json::to_vec(&entrypoint).unwrap()),
            ),
            (
                DIRECT_ENV_ENV.to_string(),
                STANDARD.encode(serde_json::to_vec(&env).unwrap()),
            ),
            (
                MOUNT_SPEC_ENV.to_string(),
                STANDARD.encode(serde_json::to_vec(&mounts).unwrap()),
            ),
        ]);

        let os_env = envs
            .into_iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        let _plan = build_run_plan(os_env).expect("build run plan");
        let contents = std::fs::read_to_string(&mount_path).expect("mount written");
        assert_eq!(contents, "value");
    }

    #[test]
    fn direct_mode_mount_requires_config_payload() {
        use base64::engine::general_purpose::STANDARD;

        let entrypoint = vec!["/bin/echo".to_string(), "ok".to_string()];
        let env = BTreeMap::from([("HELLO".to_string(), "world".to_string())]);
        let mounts = vec![MountSpec::Config {
            path: "/tmp/app.txt".to_string(),
            config: "app".to_string(),
        }];

        let envs = BTreeMap::from([
            (
                DIRECT_ENTRYPOINT_ENV.to_string(),
                STANDARD.encode(serde_json::to_vec(&entrypoint).unwrap()),
            ),
            (
                DIRECT_ENV_ENV.to_string(),
                STANDARD.encode(serde_json::to_vec(&env).unwrap()),
            ),
            (
                MOUNT_SPEC_ENV.to_string(),
                STANDARD.encode(serde_json::to_vec(&mounts).unwrap()),
            ),
        ]);

        let os_env = envs
            .into_iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        let err = build_run_plan(os_env).expect_err("expected missing config payload error");
        assert!(err.to_string().contains("config payload is required"));
    }

    #[test]
    fn direct_mode_mount_with_config_payload() {
        use base64::engine::general_purpose::STANDARD;
        use tempfile::tempdir;

        let dir = tempdir().expect("temp dir");
        let mount_path = dir.path().join("app.txt");

        let entrypoint = vec!["/bin/echo".to_string(), "ok".to_string()];
        let env = BTreeMap::from([("HELLO".to_string(), "world".to_string())]);
        let mounts = vec![MountSpec::Config {
            path: mount_path.display().to_string(),
            config: "app".to_string(),
        }];

        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "app": { "type": "string" }
            },
            "required": ["app"]
        });

        let envs = BTreeMap::from([
            (
                DIRECT_ENTRYPOINT_ENV.to_string(),
                STANDARD.encode(serde_json::to_vec(&entrypoint).unwrap()),
            ),
            (
                DIRECT_ENV_ENV.to_string(),
                STANDARD.encode(serde_json::to_vec(&env).unwrap()),
            ),
            (ROOT_SCHEMA_ENV.to_string(), encode_json_b64(&schema)),
            (COMPONENT_SCHEMA_ENV.to_string(), encode_json_b64(&schema)),
            (
                COMPONENT_TEMPLATE_ENV.to_string(),
                encode_json_b64(&ConfigTemplatePayload::Root.to_value()),
            ),
            (
                MOUNT_SPEC_ENV.to_string(),
                STANDARD.encode(serde_json::to_vec(&mounts).unwrap()),
            ),
            ("AMBER_CONFIG_APP".to_string(), "hello".to_string()),
        ]);

        let os_env = envs
            .into_iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        let plan = build_run_plan(os_env).expect("build run plan");

        assert_eq!(plan.entrypoint, entrypoint);
        assert_eq!(
            plan.env.get(&OsString::from("HELLO")),
            Some(&OsString::from("world"))
        );

        let contents = std::fs::read_to_string(&mount_path).expect("mount written");
        assert_eq!(contents, "hello");
    }

    #[test]
    fn direct_mode_decodes_docker_mount_proxy_specs() {
        use base64::engine::general_purpose::STANDARD;

        let entrypoint = vec!["/bin/echo".to_string(), "ok".to_string()];
        let env = BTreeMap::from([("HELLO".to_string(), "world".to_string())]);
        let proxies = vec![DockerMountProxySpec {
            path: "/var/run/docker.sock".to_string(),
            tcp_host: "127.0.0.1".to_string(),
            tcp_port: 23000,
        }];

        let envs = BTreeMap::from([
            (
                DIRECT_ENTRYPOINT_ENV.to_string(),
                STANDARD.encode(serde_json::to_vec(&entrypoint).unwrap()),
            ),
            (
                DIRECT_ENV_ENV.to_string(),
                STANDARD.encode(serde_json::to_vec(&env).unwrap()),
            ),
            (
                DOCKER_MOUNT_PROXY_SPEC_ENV.to_string(),
                STANDARD.encode(serde_json::to_vec(&proxies).unwrap()),
            ),
        ]);

        let os_env = envs
            .into_iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        let plan = build_run_plan(os_env).expect("build run plan");

        assert_eq!(
            plan.docker_mount_proxies,
            vec![(
                "/var/run/docker.sock".to_string(),
                "127.0.0.1".to_string(),
                23000
            )]
        );
    }
}
