use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    io::ErrorKind,
    path::Path,
    thread,
    time::{Duration, Instant},
};

use amber_config::{self as config, CONFIG_ENV_PREFIX, ConfigError};
use amber_template::{
    ConfigTemplatePayload, ProgramArgTemplate, ProgramEnvTemplate, RuntimeTemplateContext,
    TemplateSpec,
};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

const ROOT_SCHEMA_ENV: &str = "AMBER_ROOT_CONFIG_SCHEMA_B64";
const COMPONENT_SCHEMA_ENV: &str = "AMBER_COMPONENT_CONFIG_SCHEMA_B64";
const COMPONENT_TEMPLATE_ENV: &str = "AMBER_COMPONENT_CONFIG_TEMPLATE_B64";
const TEMPLATE_SPEC_ENV: &str = "AMBER_TEMPLATE_SPEC_B64";
const RESOLVED_ENTRYPOINT_ENV: &str = "AMBER_RESOLVED_ENTRYPOINT_B64";
const RESOLVED_ENV_ENV: &str = "AMBER_RESOLVED_ENV_B64";
const MOUNT_SPEC_ENV: &str = "AMBER_MOUNT_SPEC_B64";
const DOCKER_MOUNT_PROXY_SPEC_ENV: &str = "AMBER_DOCKER_MOUNT_PROXY_SPEC_B64";
const RUNTIME_TEMPLATE_CONTEXT_ENV: &str = "AMBER_RUNTIME_TEMPLATE_CONTEXT_B64";

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

pub fn wait_for_mesh_config_scope(
    config_path: &Path,
    expected_scope: &str,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut last_observation = "mesh config not observed".to_string();

    loop {
        match fs::read_to_string(config_path) {
            Ok(raw) => match mesh_scope_from_config(&raw) {
                Ok(Some(scope)) if scope == expected_scope => return Ok(()),
                Ok(Some(scope)) => {
                    last_observation = format!("observed scope {scope:?}");
                }
                Ok(None) => {
                    last_observation = "mesh_scope is missing".to_string();
                }
                Err(err) => {
                    last_observation = format!("invalid mesh config: {err}");
                }
            },
            Err(err) if err.kind() == ErrorKind::NotFound => {
                last_observation = "mesh config file does not exist yet".to_string();
            }
            Err(err) => {
                last_observation = format!("failed to read mesh config: {err}");
            }
        }

        if Instant::now() >= deadline {
            return Err(HelperError::Msg(format!(
                "timed out after {}s waiting for mesh config {} to reach scenario scope {:?}; {}",
                timeout.as_secs(),
                config_path.display(),
                expected_scope,
                last_observation,
            )));
        }

        thread::sleep(poll_interval);
    }
}

fn mesh_scope_from_config(raw: &str) -> Result<Option<String>> {
    let value: Value = serde_json::from_str(raw).map_err(|source| HelperError::Json {
        name: "mesh config",
        source,
    })?;
    Ok(value
        .pointer("/identity/mesh_scope")
        .and_then(Value::as_str)
        .map(str::to_owned))
}

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
    let mut resolved_entrypoint_b64 = None;
    let mut resolved_env_b64 = None;
    let mut mount_spec_b64 = None;
    let mut docker_mount_proxy_spec_b64 = None;
    let mut runtime_template_context_b64 = None;

    for (key, value) in env {
        let Some(key_str) = key.to_str() else {
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
            RESOLVED_ENTRYPOINT_ENV => {
                let value = value.into_string().map_err(|_| {
                    HelperError::Msg(format!("{RESOLVED_ENTRYPOINT_ENV} is required"))
                })?;
                resolved_entrypoint_b64 = Some(value);
            }
            RESOLVED_ENV_ENV => {
                let value = value
                    .into_string()
                    .map_err(|_| HelperError::Msg(format!("{RESOLVED_ENV_ENV} is required")))?;
                resolved_env_b64 = Some(value);
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
            RUNTIME_TEMPLATE_CONTEXT_ENV => {
                let value = value.into_string().map_err(|_| {
                    HelperError::Msg(format!("{RUNTIME_TEMPLATE_CONTEXT_ENV} is required"))
                })?;
                runtime_template_context_b64 = Some(value);
            }
            _ if key_str.starts_with(CONFIG_ENV_PREFIX) => {
                let value = value
                    .into_string()
                    .map_err(|_| HelperError::Msg(format!("{key_str} must be valid UTF-8")))?;
                config_env.insert(key_str.to_string(), value);
            }
            _ if should_passthrough_env(key_str) => {
                passthrough_env.insert(key, value);
            }
            _ => {}
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
    let runtime_template_context = if let Some(raw) = runtime_template_context_b64.as_deref() {
        decode_b64_json_t::<RuntimeTemplateContext>(RUNTIME_TEMPLATE_CONTEXT_ENV, raw)?
    } else {
        RuntimeTemplateContext::default()
    };

    let config_payload_present = root_schema_b64.is_some()
        || component_schema_b64.is_some()
        || component_template_b64.is_some();
    let has_template_spec = template_spec_b64.is_some();
    let has_resolved_entrypoint = resolved_entrypoint_b64.is_some();
    let has_resolved_env = resolved_env_b64.is_some();
    let has_resolved_payload = has_resolved_entrypoint || has_resolved_env;
    let mount_requires_config = mounts
        .iter()
        .any(|mount| matches!(mount, MountSpec::Config { .. }));

    if has_resolved_payload && (!has_resolved_entrypoint || !has_resolved_env) {
        return Err(HelperError::Msg(format!(
            "{RESOLVED_ENTRYPOINT_ENV} and {RESOLVED_ENV_ENV} are required together"
        )));
    }

    if has_template_spec && has_resolved_payload {
        return Err(HelperError::Msg(
            "helper payload must provide either a template spec or a resolved entrypoint/env"
                .to_string(),
        ));
    }

    if !has_template_spec && !has_resolved_payload {
        return Err(HelperError::Msg(
            "helper payload must include a program entrypoint/env payload".to_string(),
        ));
    }

    if mount_requires_config && !config_payload_present {
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
        let component_config = config::eval_config_template_partial_with_context(
            &component_template,
            &root_config,
            &runtime_template_context,
        )?;

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
        let empty_component_config = Value::Object(serde_json::Map::new());
        let component_config = if template_spec_requires_config(&spec) {
            component_config.as_ref().ok_or_else(|| {
                HelperError::Msg("template spec requires config payload".to_string())
            })?
        } else {
            component_config.as_ref().unwrap_or(&empty_component_config)
        };

        let mut entrypoint: Vec<String> = Vec::new();
        render_program_arg_templates(
            &spec.program.entrypoint,
            component_config,
            &runtime_template_context,
            &mut entrypoint,
        )?;
        if entrypoint.is_empty() {
            return Err(HelperError::Interp(
                "program.entrypoint is empty; cannot exec".to_string(),
            ));
        }

        let mut rendered_env: BTreeMap<String, String> = BTreeMap::new();
        for (k, value) in &spec.program.env {
            let rendered = match value {
                ProgramEnvTemplate::Value(ts) => config::render_template_string_with_context(
                    ts,
                    component_config,
                    &runtime_template_context,
                )?,
                ProgramEnvTemplate::Group(group) => {
                    let present = config_path_is_present(component_config, &group.when)?;
                    if !present {
                        continue;
                    }
                    config::render_template_string_with_context(
                        &group.value,
                        component_config,
                        &runtime_template_context,
                    )?
                }
            };
            rendered_env.insert(k.clone(), rendered);
        }

        (entrypoint, rendered_env)
    } else {
        let entrypoint_b64 = resolved_entrypoint_b64
            .ok_or_else(|| HelperError::Msg(format!("{RESOLVED_ENTRYPOINT_ENV} is required")))?;
        let env_b64 = resolved_env_b64
            .ok_or_else(|| HelperError::Msg(format!("{RESOLVED_ENV_ENV} is required")))?;

        let entrypoint =
            decode_b64_json_t::<Vec<String>>(RESOLVED_ENTRYPOINT_ENV, &entrypoint_b64)?;
        let rendered_env =
            decode_b64_json_t::<BTreeMap<String, String>>(RESOLVED_ENV_ENV, &env_b64)?;

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

fn should_passthrough_env(key: &str) -> bool {
    matches!(key, "PATH" | "HOME" | "TMPDIR")
}

fn template_spec_requires_config(spec: &TemplateSpec) -> bool {
    spec.program
        .entrypoint
        .iter()
        .any(program_arg_template_requires_config)
        || spec
            .program
            .env
            .values()
            .any(program_env_template_requires_config)
}

fn program_arg_template_requires_config(arg: &ProgramArgTemplate) -> bool {
    match arg {
        ProgramArgTemplate::Arg(parts) => template_string_requires_config(parts),
        ProgramArgTemplate::Group(group) => {
            !group.when.is_empty()
                || group
                    .argv
                    .iter()
                    .any(|parts| template_string_requires_config(parts))
        }
    }
}

fn program_env_template_requires_config(value: &ProgramEnvTemplate) -> bool {
    match value {
        ProgramEnvTemplate::Value(parts) => template_string_requires_config(parts),
        ProgramEnvTemplate::Group(group) => {
            !group.when.is_empty() || template_string_requires_config(&group.value)
        }
    }
}

fn template_string_requires_config(parts: &[amber_template::TemplatePart]) -> bool {
    parts
        .iter()
        .any(|part| matches!(part, amber_template::TemplatePart::Config { .. }))
}

fn render_program_arg_templates(
    args: &[ProgramArgTemplate],
    component_config: &Value,
    runtime_template_context: &RuntimeTemplateContext,
    out: &mut Vec<String>,
) -> Result<()> {
    for arg in args {
        match arg {
            ProgramArgTemplate::Arg(parts) => {
                out.push(config::render_template_string_with_context(
                    parts,
                    component_config,
                    runtime_template_context,
                )?);
            }
            ProgramArgTemplate::Group(group) => {
                let present = config_path_is_present(component_config, &group.when)?;
                if !present {
                    continue;
                }
                for parts in &group.argv {
                    out.push(config::render_template_string_with_context(
                        parts,
                        component_config,
                        runtime_template_context,
                    )?);
                }
            }
        }
    }
    Ok(())
}

fn config_path_is_present(config_value: &Value, path: &str) -> Result<bool> {
    config::get_by_path_opt(config_value, path)
        .map(|value| value.is_some_and(|value| !value.is_null()))
        .map_err(HelperError::from)
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
                        "mount {path} requires config resolution but no config payload was \
                         provided"
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
    use std::time::Duration;

    use amber_template::{ProgramArgTemplate, TemplatePart};
    use base64::engine::general_purpose::STANDARD;
    use tempfile::tempdir;

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
                    ProgramArgTemplate::Arg(vec![TemplatePart::lit("/app/bin/server")]),
                    ProgramArgTemplate::Arg(vec![
                        TemplatePart::lit("--token="),
                        TemplatePart::config("token"),
                    ]),
                ],
                env: BTreeMap::from([(
                    "COUNT".to_string(),
                    ProgramEnvTemplate::Value(vec![TemplatePart::config("count")]),
                )]),
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
    fn build_run_plan_skips_conditional_program_arg_group_when_config_is_missing() {
        let root_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "profile": { "type": "string" }
            }
        });

        let component_schema = root_schema.clone();

        let template_spec = TemplateSpec {
            program: amber_template::ProgramTemplateSpec {
                entrypoint: vec![
                    ProgramArgTemplate::Arg(vec![TemplatePart::lit("/app/bin/server")]),
                    ProgramArgTemplate::Group(amber_template::ConditionalProgramArgTemplate {
                        when: "profile".to_string(),
                        argv: vec![
                            vec![TemplatePart::lit("--profile")],
                            vec![TemplatePart::config("profile")],
                        ],
                    }),
                ],
                env: BTreeMap::new(),
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
        ]);

        let os_env = env
            .into_iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        let plan = build_run_plan(os_env).expect("run plan should build");

        assert_eq!(plan.entrypoint, vec!["/app/bin/server".to_string()]);
    }

    #[test]
    fn build_run_plan_renders_conditional_program_arg_group_when_config_is_present() {
        let root_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "profile": { "type": "string" }
            }
        });

        let component_schema = root_schema.clone();

        let template_spec = TemplateSpec {
            program: amber_template::ProgramTemplateSpec {
                entrypoint: vec![
                    ProgramArgTemplate::Arg(vec![TemplatePart::lit("/app/bin/server")]),
                    ProgramArgTemplate::Group(amber_template::ConditionalProgramArgTemplate {
                        when: "profile".to_string(),
                        argv: vec![
                            vec![TemplatePart::lit("--profile")],
                            vec![TemplatePart::config("profile")],
                        ],
                    }),
                ],
                env: BTreeMap::new(),
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
            ("AMBER_CONFIG_PROFILE".to_string(), "dev".to_string()),
        ]);

        let os_env = env
            .into_iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        let plan = build_run_plan(os_env).expect("run plan should build");

        assert_eq!(
            plan.entrypoint,
            vec![
                "/app/bin/server".to_string(),
                "--profile".to_string(),
                "dev".to_string(),
            ]
        );
    }

    #[test]
    fn build_run_plan_drops_unexpected_ambient_env() {
        let entrypoint = vec!["sh".to_string(), "-ceu".to_string(), "echo ok".to_string()];
        let env = BTreeMap::<String, String>::new();

        let envs = BTreeMap::from([
            (
                RESOLVED_ENTRYPOINT_ENV.to_string(),
                base64::engine::general_purpose::STANDARD
                    .encode(serde_json::to_vec(&entrypoint).unwrap()),
            ),
            (
                RESOLVED_ENV_ENV.to_string(),
                base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&env).unwrap()),
            ),
            ("PATH".to_string(), "/usr/bin:/bin".to_string()),
            ("HOME".to_string(), "/tmp/home".to_string()),
            ("HOST_SECRET".to_string(), "top-secret".to_string()),
        ]);

        let os_env = envs
            .into_iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        let plan = build_run_plan(os_env).expect("build run plan");

        assert_eq!(plan.entrypoint[0], "sh");
        assert_eq!(
            plan.env.get(&OsString::from("PATH")),
            Some(&OsString::from("/usr/bin:/bin"))
        );
        assert_eq!(
            plan.env.get(&OsString::from("HOME")),
            Some(&OsString::from("/tmp/home"))
        );
        assert!(
            !plan.env.contains_key(&OsString::from("HOST_SECRET")),
            "unexpected ambient env should not be forwarded"
        );
    }

    #[test]
    fn helper_writes_mounts() {
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
                RESOLVED_ENTRYPOINT_ENV.to_string(),
                STANDARD.encode(serde_json::to_vec(&entrypoint).unwrap()),
            ),
            (
                RESOLVED_ENV_ENV.to_string(),
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
    fn build_run_plan_renders_slot_and_binding_templates_without_config_payload() {
        let template_spec = TemplateSpec {
            program: amber_template::ProgramTemplateSpec {
                entrypoint: vec![
                    ProgramArgTemplate::Arg(vec![TemplatePart::lit("/app/bin/server")]),
                    ProgramArgTemplate::Arg(vec![TemplatePart::slot(7, "api.url")]),
                    ProgramArgTemplate::Arg(vec![TemplatePart::binding(11, "upstream.url")]),
                ],
                env: BTreeMap::from([(
                    "UPSTREAM".to_string(),
                    ProgramEnvTemplate::Value(vec![TemplatePart::binding(11, "upstream.url")]),
                )]),
            },
        };
        let runtime_context = RuntimeTemplateContext {
            slots_by_scope: BTreeMap::from([(
                7,
                BTreeMap::from([("api.url".to_string(), "http://127.0.0.1:31001".to_string())]),
            )]),
            slot_items_by_scope: BTreeMap::new(),
            bindings_by_scope: BTreeMap::from([(
                11,
                BTreeMap::from([(
                    "upstream.url".to_string(),
                    "tcp://127.0.0.1:32002".to_string(),
                )]),
            )]),
        };

        let env = BTreeMap::from([
            (
                TEMPLATE_SPEC_ENV.to_string(),
                encode_spec_b64(&template_spec),
            ),
            (
                RUNTIME_TEMPLATE_CONTEXT_ENV.to_string(),
                STANDARD.encode(serde_json::to_vec(&runtime_context).unwrap()),
            ),
        ]);

        let os_env = env
            .into_iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        let plan = build_run_plan(os_env).expect("run plan should build");

        assert_eq!(plan.entrypoint[1], "http://127.0.0.1:31001");
        assert_eq!(plan.entrypoint[2], "tcp://127.0.0.1:32002");
        assert_eq!(
            plan.env.get(&OsString::from("UPSTREAM")),
            Some(&OsString::from("tcp://127.0.0.1:32002"))
        );
    }

    #[test]
    fn build_run_plan_renders_item_templates_from_slot_items() {
        let template_spec = TemplateSpec {
            program: amber_template::ProgramTemplateSpec {
                entrypoint: vec![
                    ProgramArgTemplate::Arg(vec![TemplatePart::lit("/app/bin/server")]),
                    ProgramArgTemplate::Arg(vec![TemplatePart::item(7, "api", 0, "url")]),
                    ProgramArgTemplate::Arg(vec![TemplatePart::item(7, "api", 1, "url")]),
                ],
                env: BTreeMap::from([(
                    "UPSTREAMS".to_string(),
                    ProgramEnvTemplate::Value(vec![
                        TemplatePart::item(7, "api", 0, "url"),
                        TemplatePart::lit(","),
                        TemplatePart::item(7, "api", 1, "url"),
                    ]),
                )]),
            },
        };
        let runtime_context = RuntimeTemplateContext {
            slots_by_scope: BTreeMap::new(),
            slot_items_by_scope: BTreeMap::from([(
                7,
                BTreeMap::from([(
                    "api".to_string(),
                    vec![
                        amber_template::RuntimeSlotObject {
                            url: "http://127.0.0.1:31001".to_string(),
                        },
                        amber_template::RuntimeSlotObject {
                            url: "http://127.0.0.1:31002".to_string(),
                        },
                    ],
                )]),
            )]),
            bindings_by_scope: BTreeMap::new(),
        };

        let env = BTreeMap::from([
            (
                TEMPLATE_SPEC_ENV.to_string(),
                encode_spec_b64(&template_spec),
            ),
            (
                RUNTIME_TEMPLATE_CONTEXT_ENV.to_string(),
                STANDARD.encode(serde_json::to_vec(&runtime_context).unwrap()),
            ),
        ]);

        let os_env = env
            .into_iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        let plan = build_run_plan(os_env).expect("run plan should build");

        assert_eq!(plan.entrypoint[1], "http://127.0.0.1:31001");
        assert_eq!(plan.entrypoint[2], "http://127.0.0.1:31002");
        assert_eq!(
            plan.env.get(&OsString::from("UPSTREAMS")),
            Some(&OsString::from(
                "http://127.0.0.1:31001,http://127.0.0.1:31002"
            ))
        );
    }

    #[test]
    fn helper_mount_requires_config_payload() {
        use base64::engine::general_purpose::STANDARD;

        let entrypoint = vec!["/bin/echo".to_string(), "ok".to_string()];
        let env = BTreeMap::from([("HELLO".to_string(), "world".to_string())]);
        let mounts = vec![MountSpec::Config {
            path: "/tmp/app.txt".to_string(),
            config: "app".to_string(),
        }];

        let envs = BTreeMap::from([
            (
                RESOLVED_ENTRYPOINT_ENV.to_string(),
                STANDARD.encode(serde_json::to_vec(&entrypoint).unwrap()),
            ),
            (
                RESOLVED_ENV_ENV.to_string(),
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
    fn helper_mount_with_config_payload() {
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
                RESOLVED_ENTRYPOINT_ENV.to_string(),
                STANDARD.encode(serde_json::to_vec(&entrypoint).unwrap()),
            ),
            (
                RESOLVED_ENV_ENV.to_string(),
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
    fn helper_accepts_program_name_without_path_lookup() {
        use base64::engine::general_purpose::STANDARD;

        let entrypoint = vec!["sh".to_string(), "-lc".to_string(), "echo ok".to_string()];
        let env = BTreeMap::<String, String>::new();

        let envs = BTreeMap::from([
            (
                RESOLVED_ENTRYPOINT_ENV.to_string(),
                STANDARD.encode(serde_json::to_vec(&entrypoint).unwrap()),
            ),
            (
                RESOLVED_ENV_ENV.to_string(),
                STANDARD.encode(serde_json::to_vec(&env).unwrap()),
            ),
        ]);

        let os_env = envs
            .into_iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        let plan = build_run_plan(os_env).expect("build run plan");
        assert_eq!(plan.entrypoint, entrypoint);
    }

    #[test]
    fn helper_decodes_docker_mount_proxy_specs() {
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
                RESOLVED_ENTRYPOINT_ENV.to_string(),
                STANDARD.encode(serde_json::to_vec(&entrypoint).unwrap()),
            ),
            (
                RESOLVED_ENV_ENV.to_string(),
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

    #[cfg(unix)]
    #[test]
    fn config_env_values_must_be_utf8() {
        use std::os::unix::ffi::OsStringExt;

        let env = vec![(
            OsString::from("AMBER_CONFIG_INVALID"),
            OsString::from_vec(vec![0xff, 0xfe]),
        )];
        let err = build_run_plan(env).expect_err("invalid utf-8 env value should fail");
        assert!(
            err.to_string()
                .contains("AMBER_CONFIG_INVALID must be valid UTF-8")
        );
    }

    #[test]
    fn wait_for_mesh_config_scope_accepts_matching_scope() {
        let dir = tempdir().expect("temp dir");
        let config_path = dir.path().join("mesh-config.json");
        fs::write(
            &config_path,
            r#"{"identity":{"id":"/app","mesh_scope":"scope-v1"}}"#,
        )
        .expect("write mesh config");

        wait_for_mesh_config_scope(
            &config_path,
            "scope-v1",
            Duration::from_millis(50),
            Duration::from_millis(5),
        )
        .expect("scope should match");
    }

    #[test]
    fn wait_for_mesh_config_scope_observes_secret_update() {
        let dir = tempdir().expect("temp dir");
        let config_path = dir.path().join("mesh-config.json");
        fs::write(
            &config_path,
            r#"{"identity":{"id":"/app","mesh_scope":"scope-v1"}}"#,
        )
        .expect("write mesh config");

        let delayed_path = config_path.clone();
        let updater = thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            fs::write(
                delayed_path,
                r#"{"identity":{"id":"/app","mesh_scope":"scope-v2"}}"#,
            )
            .expect("update mesh config");
        });

        wait_for_mesh_config_scope(
            &config_path,
            "scope-v2",
            Duration::from_secs(1),
            Duration::from_millis(5),
        )
        .expect("scope should update");
        updater.join().expect("updater thread should finish");
    }

    #[test]
    fn wait_for_mesh_config_scope_times_out_on_mismatch() {
        let dir = tempdir().expect("temp dir");
        let config_path = dir.path().join("mesh-config.json");
        fs::write(
            &config_path,
            r#"{"identity":{"id":"/app","mesh_scope":"scope-v1"}}"#,
        )
        .expect("write mesh config");

        let err = wait_for_mesh_config_scope(
            &config_path,
            "scope-v2",
            Duration::from_millis(20),
            Duration::from_millis(5),
        )
        .expect_err("mismatched scope should time out");
        let message = err.to_string();
        assert!(message.contains("scope-v2"), "{message}");
        assert!(message.contains("scope-v1"), "{message}");
    }
}
