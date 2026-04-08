use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    io::ErrorKind,
    net::{IpAddr, ToSocketAddrs},
    path::Path,
    process::Command,
    thread,
    time::{Duration, Instant},
};

use amber_config::{self as config, CONFIG_ENV_PREFIX, ConfigError};
use amber_mesh::DYNAMIC_CAPS_API_URL_ENV;
use amber_template::{
    ConfigTemplatePayload, MountSpec, ProgramArgTemplate, ProgramEnvTemplate,
    RepeatedProgramArgTemplate, RepeatedProgramEnvTemplate, RepeatedTemplateSource,
    RuntimeTemplateContext, TemplateSpec,
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
const IP_BIN: &str = "/usr/sbin/ip";
const IPTABLES_BIN: &str = "/usr/sbin/iptables";
const IP6TABLES_BIN: &str = "/usr/sbin/ip6tables";
const DEFAULT_EGRESS_CHAIN: &str = "AMBER_EGRESS";
const HOST_GATEWAY_NAME: &str = "host.docker.internal";
const BLOCKED_IPV4_CIDRS: &[&str] = &[
    "10.0.0.0/8",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
];
const BLOCKED_IPV6_CIDRS: &[&str] = &["fc00::/7", "fe80::/10"];

#[derive(Debug, Deserialize, Serialize)]
struct DockerMountProxySpec {
    path: String,
    tcp_host: String,
    tcp_port: u16,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct IpRouteEntry {
    #[serde(default)]
    dst: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct EgressRouteSnapshot {
    connected_subnets: Vec<String>,
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

pub fn install_default_egress_guard() -> Result<()> {
    let host_gateway_ips = resolve_host_gateway_ips();
    install_egress_guard_family(IPTABLES_BIN, "-4", BLOCKED_IPV4_CIDRS, &host_gateway_ips)?;
    install_egress_guard_family(IP6TABLES_BIN, "-6", BLOCKED_IPV6_CIDRS, &host_gateway_ips)?;
    Ok(())
}

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

fn install_egress_guard_family(
    iptables_bin: &str,
    family_flag: &str,
    blocked_cidrs: &[&str],
    host_gateway_ips: &BTreeSet<IpAddr>,
) -> Result<()> {
    let snapshot = read_route_snapshot(family_flag)?;
    let blocked_destinations = blocked_destinations_for_family(
        iptables_bin,
        blocked_cidrs,
        host_gateway_ips.iter().copied(),
    );

    run_command_allow_failure(
        iptables_bin,
        ["-w", "-D", "OUTPUT", "-j", DEFAULT_EGRESS_CHAIN],
    )?;
    run_command_allow_failure(iptables_bin, ["-w", "-F", DEFAULT_EGRESS_CHAIN])?;
    run_command_allow_failure(iptables_bin, ["-w", "-X", DEFAULT_EGRESS_CHAIN])?;
    if blocked_destinations.is_empty() {
        return Ok(());
    }
    run_command(iptables_bin, ["-w", "-N", DEFAULT_EGRESS_CHAIN])?;
    run_command(
        iptables_bin,
        ["-w", "-A", "OUTPUT", "-j", DEFAULT_EGRESS_CHAIN],
    )?;
    run_command(
        iptables_bin,
        ["-w", "-A", DEFAULT_EGRESS_CHAIN, "-o", "lo", "-j", "RETURN"],
    )?;
    for subnet in &snapshot.connected_subnets {
        run_command(
            iptables_bin,
            [
                "-w",
                "-A",
                DEFAULT_EGRESS_CHAIN,
                "-d",
                subnet.as_str(),
                "-j",
                "RETURN",
            ],
        )?;
    }
    for blocked_destination in blocked_destinations {
        run_command(
            iptables_bin,
            [
                "-w",
                "-A",
                DEFAULT_EGRESS_CHAIN,
                "-d",
                blocked_destination.as_str(),
                "-j",
                "REJECT",
            ],
        )?;
    }
    Ok(())
}

fn read_route_snapshot(family_flag: &str) -> Result<EgressRouteSnapshot> {
    let output = run_command(
        IP_BIN,
        ["-j", family_flag, "route", "show", "table", "main"],
    )?;
    let routes: Vec<IpRouteEntry> =
        serde_json::from_slice(&output.stdout).map_err(|source| HelperError::Json {
            name: "ip route output",
            source,
        })?;
    Ok(route_snapshot_from_entries(&routes))
}

fn route_snapshot_from_entries(routes: &[IpRouteEntry]) -> EgressRouteSnapshot {
    let mut connected_subnets = BTreeSet::new();

    for route in routes {
        match route.dst.as_deref() {
            Some("default") => {}
            Some(dst) if route.scope.as_deref() == Some("link") && !dst.trim().is_empty() => {
                connected_subnets.insert(dst.to_string());
            }
            _ => {}
        }
    }

    EgressRouteSnapshot {
        connected_subnets: connected_subnets.into_iter().collect(),
    }
}

fn resolve_host_gateway_ips() -> BTreeSet<IpAddr> {
    format!("{HOST_GATEWAY_NAME}:80")
        .to_socket_addrs()
        .map(|socket_addrs| socket_addrs.map(|addr| addr.ip()).collect())
        .unwrap_or_default()
}

fn blocked_ips_for_family(
    iptables_bin: &str,
    blocked_ips: impl IntoIterator<Item = IpAddr>,
) -> BTreeSet<IpAddr> {
    blocked_ips
        .into_iter()
        .filter(|ip| match iptables_bin {
            IPTABLES_BIN => ip.is_ipv4(),
            IP6TABLES_BIN => ip.is_ipv6(),
            _ => false,
        })
        .collect()
}

fn blocked_destinations_for_family(
    iptables_bin: &str,
    blocked_cidrs: &[&str],
    host_gateway_ips: impl IntoIterator<Item = IpAddr>,
) -> BTreeSet<String> {
    let host_gateway_ips = blocked_ips_for_family(iptables_bin, host_gateway_ips);
    let substitute_private_ipv4 = iptables_bin == IPTABLES_BIN
        && host_gateway_ips
            .iter()
            .any(|ip| matches!(ip, IpAddr::V4(addr) if addr.octets()[0] == 192 && addr.octets()[1] == 168));

    // Docker Desktop routes public DNS and host access through 192.168.x infrastructure, so
    // replacing the broad 192.168/16 reject with the concrete host gateway IP preserves the host
    // isolation invariant without cutting off normal internet egress.
    let mut blocked_destinations = blocked_cidrs
        .iter()
        .filter(|cidr| !substitute_private_ipv4 || **cidr != "192.168.0.0/16")
        .map(|cidr| (*cidr).to_string())
        .collect::<BTreeSet<_>>();
    blocked_destinations.extend(host_gateway_ips.into_iter().map(|ip| ip.to_string()));
    blocked_destinations
}

fn run_command<'a>(
    program: &str,
    args: impl IntoIterator<Item = &'a str>,
) -> Result<std::process::Output> {
    let args = args.into_iter().collect::<Vec<_>>();
    let output = Command::new(program).args(&args).output().map_err(|err| {
        HelperError::Msg(format!(
            "failed to run {} {}: {err}",
            program,
            args.join(" ")
        ))
    })?;
    if output.status.success() {
        return Ok(output);
    }

    Err(HelperError::Msg(format!(
        "{} {} failed with status {}\nstdout:\n{}\nstderr:\n{}",
        program,
        args.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )))
}

fn run_command_allow_failure<'a>(
    program: &str,
    args: impl IntoIterator<Item = &'a str>,
) -> Result<()> {
    let args = args.into_iter().collect::<Vec<_>>();
    Command::new(program).args(&args).output().map_err(|err| {
        HelperError::Msg(format!(
            "failed to run {} {}: {err}",
            program,
            args.join(" ")
        ))
    })?;
    Ok(())
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
    let mount_requires_config = mounts.iter().any(MountSpec::requires_config);

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

    let (component_config, component_schema) = if config_payload_present {
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

        let component_config = config::resolve_runtime_component_config(
            &root_schema,
            &component_schema,
            &component_template,
            &config_env,
            &runtime_template_context,
        )?;

        (Some(component_config), Some(component_schema))
    } else {
        (None, None)
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
                ProgramEnvTemplate::Conditional(group) => {
                    let present = config::config_path_is_present(component_config, &group.when)?;
                    if !present {
                        continue;
                    }
                    config::render_template_string_with_context(
                        &group.value,
                        component_config,
                        &runtime_template_context,
                    )?
                }
                ProgramEnvTemplate::Repeated(repeated) => {
                    if let Some(when) = repeated.when.as_deref()
                        && !config::config_path_is_present(component_config, when)?
                    {
                        continue;
                    }
                    let Some(rendered) = render_repeated_program_env_template(
                        repeated,
                        component_config,
                        &runtime_template_context,
                    )?
                    else {
                        continue;
                    };
                    rendered
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

    write_mounts(
        &mounts,
        component_config.as_ref(),
        component_schema.as_ref(),
        &runtime_template_context,
    )?;

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
    matches!(key, "PATH" | "HOME" | "TMPDIR") || key == DYNAMIC_CAPS_API_URL_ENV
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
        ProgramArgTemplate::Conditional(group) => {
            !group.when.is_empty()
                || group
                    .argv
                    .iter()
                    .any(|parts| template_string_requires_config(parts))
        }
        ProgramArgTemplate::Repeated(repeated) => {
            repeated.when.as_ref().is_some_and(|when| !when.is_empty())
                || repeated_template_source_requires_config(&repeated.each)
                || repeated
                    .arg
                    .as_ref()
                    .is_some_and(|parts| template_string_requires_config(parts))
                || repeated
                    .argv
                    .iter()
                    .any(|parts| template_string_requires_config(parts))
        }
    }
}

fn program_env_template_requires_config(value: &ProgramEnvTemplate) -> bool {
    match value {
        ProgramEnvTemplate::Value(parts) => template_string_requires_config(parts),
        ProgramEnvTemplate::Conditional(group) => {
            !group.when.is_empty() || template_string_requires_config(&group.value)
        }
        ProgramEnvTemplate::Repeated(repeated) => {
            repeated.when.as_ref().is_some_and(|when| !when.is_empty())
                || repeated_template_source_requires_config(&repeated.each)
                || template_string_requires_config(&repeated.value)
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
            ProgramArgTemplate::Conditional(group) => {
                let present = config::config_path_is_present(component_config, &group.when)?;
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
            ProgramArgTemplate::Repeated(repeated) => {
                if let Some(when) = repeated.when.as_deref()
                    && !config::config_path_is_present(component_config, when)?
                {
                    continue;
                }
                render_repeated_program_arg_template(
                    repeated,
                    component_config,
                    runtime_template_context,
                    out,
                )?;
            }
        }
    }
    Ok(())
}

fn repeated_template_source_requires_config(source: &RepeatedTemplateSource) -> bool {
    match source {
        RepeatedTemplateSource::Config { .. } => true,
    }
}

fn render_repeated_template_string(
    parts: &amber_template::TemplateString,
    component_config: &Value,
    runtime_template_context: &RuntimeTemplateContext,
    item: &Value,
) -> Result<String> {
    let mut rendered = String::new();
    for part in parts {
        match part {
            amber_template::TemplatePart::Lit { lit } => rendered.push_str(lit),
            amber_template::TemplatePart::Config { config: path } => {
                let value =
                    config::get_by_path(component_config, path).map_err(HelperError::from)?;
                rendered.push_str(
                    &config::stringify_for_interpolation(value).map_err(HelperError::from)?,
                );
            }
            amber_template::TemplatePart::Slot { slot, scope } => {
                let value = runtime_template_context
                    .slots_by_scope
                    .get(scope)
                    .and_then(|slots| slots.get(slot))
                    .ok_or_else(|| {
                        HelperError::Interp(format!(
                            "slot interpolation slots.{slot} cannot be rendered at runtime for \
                             scope {scope}"
                        ))
                    })?;
                rendered.push_str(value);
            }
            amber_template::TemplatePart::Item {
                item: path,
                scope,
                slot,
                index,
            } => {
                let item = runtime_template_context
                    .slot_items_by_scope
                    .get(scope)
                    .and_then(|slots| slots.get(slot))
                    .and_then(|items| items.get(*index))
                    .ok_or_else(|| {
                        HelperError::Interp(format!(
                            "item interpolation item.{path} cannot be rendered at runtime for \
                             scope {scope}, slot {slot}, item {index}"
                        ))
                    })?;
                let item = serde_json::to_value(item).map_err(|err| {
                    HelperError::Interp(format!(
                        "failed to serialize runtime slot item for scope {scope}, slot {slot}, \
                         item {index}: {err}"
                    ))
                })?;
                let value = query_value_opt(&item, path).ok_or_else(|| {
                    HelperError::Interp(format!(
                        "item.{path} not found in runtime slot item for scope {scope}, slot \
                         {slot}, item {index}"
                    ))
                })?;
                rendered.push_str(
                    &config::stringify_for_interpolation(value).map_err(HelperError::from)?,
                );
            }
            amber_template::TemplatePart::CurrentItem { item: path } => {
                let value = query_value_opt(item, path).ok_or_else(|| {
                    HelperError::Interp(format!(
                        "item.{path} not found in the current repeated item"
                    ))
                })?;
                rendered.push_str(
                    &config::stringify_for_interpolation(value).map_err(HelperError::from)?,
                );
            }
        }
    }
    Ok(rendered)
}

fn render_repeated_program_arg_template(
    repeated: &RepeatedProgramArgTemplate,
    component_config: &Value,
    runtime_template_context: &RuntimeTemplateContext,
    out: &mut Vec<String>,
) -> Result<()> {
    let items = match &repeated.each {
        RepeatedTemplateSource::Config { path } => {
            config::repeated_config_items(component_config, path)?
        }
    };

    match (&repeated.arg, repeated.argv.is_empty()) {
        (Some(arg), true) => {
            let mut rendered = Vec::with_capacity(items.len());
            for item in items {
                rendered.push(render_repeated_template_string(
                    arg,
                    component_config,
                    runtime_template_context,
                    item,
                )?);
            }
            if let Some(join) = &repeated.join {
                if !rendered.is_empty() {
                    out.push(rendered.join(join));
                }
            } else {
                out.extend(rendered);
            }
            Ok(())
        }
        (None, false) if repeated.join.is_none() => {
            for item in items {
                for arg in &repeated.argv {
                    out.push(render_repeated_template_string(
                        arg,
                        component_config,
                        runtime_template_context,
                        item,
                    )?);
                }
            }
            Ok(())
        }
        (Some(_), false) | (None, true) => Err(HelperError::Interp(
            "repeated program arg template must use exactly one of `arg` or `argv`".to_string(),
        )),
        (None, false) => Err(HelperError::Interp(
            "repeated program arg template cannot use `join` with `argv`".to_string(),
        )),
    }
}

fn render_repeated_program_env_template(
    repeated: &RepeatedProgramEnvTemplate,
    component_config: &Value,
    runtime_template_context: &RuntimeTemplateContext,
) -> Result<Option<String>> {
    let items = match &repeated.each {
        RepeatedTemplateSource::Config { path } => {
            config::repeated_config_items(component_config, path)?
        }
    };
    let mut rendered = Vec::with_capacity(items.len());
    for item in items {
        rendered.push(render_repeated_template_string(
            &repeated.value,
            component_config,
            runtime_template_context,
            item,
        )?);
    }
    if rendered.is_empty() {
        return Ok(None);
    }
    Ok(Some(rendered.join(&repeated.join)))
}

fn query_value_opt<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    if path.is_empty() {
        return Some(root);
    }

    let mut current = root;
    for segment in path.split('.') {
        match current {
            Value::Object(map) => current = map.get(segment)?,
            _ => return None,
        }
    }
    Some(current)
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

fn write_mounts(
    mounts: &[MountSpec],
    component_config: Option<&Value>,
    component_schema: Option<&Value>,
    runtime_template_context: &RuntimeTemplateContext,
) -> Result<()> {
    for (path, content) in config::render_mount_specs(
        mounts,
        component_config,
        component_schema,
        runtime_template_context,
    )? {
        let mount_path = std::path::Path::new(&path);
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

    use amber_template::{
        MountTemplateSpec, ProgramArgTemplate, ProgramEnvTemplate, RepeatedProgramArgTemplate,
        RepeatedProgramEnvTemplate, RepeatedTemplateSource, TemplatePart,
    };
    use base64::engine::general_purpose::STANDARD;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn blocked_ipv4_addresses_only_apply_to_iptables() {
        let blocked_ips = blocked_ips_for_family(
            IPTABLES_BIN,
            [
                "192.0.2.10".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
            ],
        );

        assert_eq!(blocked_ips, BTreeSet::from(["192.0.2.10".parse().unwrap()]));
    }

    #[test]
    fn blocked_ipv6_addresses_only_apply_to_ip6tables() {
        let blocked_ips = blocked_ips_for_family(
            IP6TABLES_BIN,
            [
                "192.0.2.10".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
            ],
        );

        assert_eq!(
            blocked_ips,
            BTreeSet::from(["2001:db8::1".parse().unwrap()])
        );
    }

    #[test]
    fn route_snapshot_collects_link_subnets() {
        let snapshot = route_snapshot_from_entries(&[
            IpRouteEntry {
                dst: Some("default".to_string()),
                scope: None,
            },
            IpRouteEntry {
                dst: Some("172.19.0.0/16".to_string()),
                scope: Some("link".to_string()),
            },
            IpRouteEntry {
                dst: Some("172.20.0.0/16".to_string()),
                scope: Some("link".to_string()),
            },
        ]);

        assert_eq!(
            snapshot,
            EgressRouteSnapshot {
                connected_subnets: vec!["172.19.0.0/16".to_string(), "172.20.0.0/16".to_string()],
            }
        );
    }

    #[test]
    fn route_snapshot_ignores_non_link_routes_and_missing_values() {
        let snapshot = route_snapshot_from_entries(&[
            IpRouteEntry {
                dst: Some("default".to_string()),
                scope: None,
            },
            IpRouteEntry {
                dst: Some("198.51.100.0/24".to_string()),
                scope: Some("global".to_string()),
            },
            IpRouteEntry {
                dst: None,
                scope: Some("link".to_string()),
            },
        ]);

        assert_eq!(snapshot, EgressRouteSnapshot::default());
    }

    #[test]
    fn desktop_host_gateway_substitutes_for_broad_private_192_block() {
        let blocked_destinations = blocked_destinations_for_family(
            IPTABLES_BIN,
            BLOCKED_IPV4_CIDRS,
            ["192.168.65.254".parse().unwrap()],
        );

        assert!(blocked_destinations.contains("192.168.65.254"));
        assert!(!blocked_destinations.contains("192.168.0.0/16"));
    }

    fn encode_json_b64(value: &Value) -> String {
        let bytes = serde_json::to_vec(value).expect("json should serialize");
        STANDARD.encode(bytes)
    }

    fn encode_spec_b64(spec: &TemplateSpec) -> String {
        let bytes = serde_json::to_vec(spec).expect("spec should serialize");
        STANDARD.encode(bytes)
    }

    fn repeated_targets_template_spec() -> TemplateSpec {
        TemplateSpec {
            program: amber_template::ProgramTemplateSpec {
                entrypoint: vec![
                    ProgramArgTemplate::Arg(vec![TemplatePart::lit("/app/bin/server")]),
                    ProgramArgTemplate::Repeated(RepeatedProgramArgTemplate {
                        when: None,
                        each: RepeatedTemplateSource::Config {
                            path: "targets".to_string(),
                        },
                        arg: Some(vec![TemplatePart::current_item("host")]),
                        argv: Vec::new(),
                        join: Some(",".to_string()),
                    }),
                ],
                env: BTreeMap::from([(
                    "TARGETS".to_string(),
                    ProgramEnvTemplate::Repeated(RepeatedProgramEnvTemplate {
                        when: None,
                        each: RepeatedTemplateSource::Config {
                            path: "targets".to_string(),
                        },
                        value: vec![TemplatePart::current_item("host")],
                        join: ",".to_string(),
                    }),
                )]),
            },
        }
    }

    fn repeated_targets_root_schema(targets_schema: Value) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "targets": targets_schema
            }
        })
    }

    fn build_run_plan_with_repeated_targets(
        root_schema: Value,
        targets_env: Option<&str>,
    ) -> RunPlan {
        let component_schema = root_schema.clone();
        let template_spec = repeated_targets_template_spec();

        let mut env = BTreeMap::from([
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
        if let Some(targets) = targets_env {
            env.insert("AMBER_CONFIG_TARGETS".to_string(), targets.to_string());
        }

        let os_env = env
            .into_iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        build_run_plan(os_env).expect("run plan should build")
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
    fn build_run_plan_skips_conditional_program_arg_item_when_config_is_missing() {
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
                    ProgramArgTemplate::Conditional(
                        amber_template::ConditionalProgramArgTemplate {
                            when: "profile".to_string(),
                            argv: vec![
                                vec![TemplatePart::lit("--profile")],
                                vec![TemplatePart::config("profile")],
                            ],
                        },
                    ),
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
    fn build_run_plan_renders_conditional_program_arg_item_when_config_is_present() {
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
                    ProgramArgTemplate::Conditional(
                        amber_template::ConditionalProgramArgTemplate {
                            when: "profile".to_string(),
                            argv: vec![
                                vec![TemplatePart::lit("--profile")],
                                vec![TemplatePart::config("profile")],
                            ],
                        },
                    ),
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
    fn build_run_plan_renders_slot_templates_without_config_payload() {
        let template_spec = TemplateSpec {
            program: amber_template::ProgramTemplateSpec {
                entrypoint: vec![
                    ProgramArgTemplate::Arg(vec![TemplatePart::lit("/app/bin/server")]),
                    ProgramArgTemplate::Arg(vec![TemplatePart::slot(7, "api.url")]),
                ],
                env: BTreeMap::new(),
            },
        };
        let runtime_context = RuntimeTemplateContext {
            slots_by_scope: BTreeMap::from([(
                7,
                BTreeMap::from([("api.url".to_string(), "http://127.0.0.1:31001".to_string())]),
            )]),
            slot_items_by_scope: BTreeMap::new(),
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
    fn build_run_plan_preserves_dynamic_caps_api_url_for_helper_workloads() {
        let template_spec = TemplateSpec {
            program: amber_template::ProgramTemplateSpec {
                entrypoint: vec![ProgramArgTemplate::Arg(vec![TemplatePart::lit(
                    "/app/bin/server",
                )])],
                env: BTreeMap::from([(
                    "NAME".to_string(),
                    ProgramEnvTemplate::Value(vec![TemplatePart::lit("worker")]),
                )]),
            },
        };

        let env = BTreeMap::from([
            (
                TEMPLATE_SPEC_ENV.to_string(),
                encode_spec_b64(&template_spec),
            ),
            (
                DYNAMIC_CAPS_API_URL_ENV.to_string(),
                "http://127.0.0.1:31077".to_string(),
            ),
        ]);

        let os_env = env
            .into_iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        let plan = build_run_plan(os_env).expect("run plan should build");

        assert_eq!(
            plan.env.get(&OsString::from(DYNAMIC_CAPS_API_URL_ENV)),
            Some(&OsString::from("http://127.0.0.1:31077"))
        );
        assert_eq!(
            plan.env.get(&OsString::from("NAME")),
            Some(&OsString::from("worker"))
        );
    }

    #[test]
    fn build_run_plan_renders_repeated_config_program_args_and_env() {
        let root_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "host": { "type": "string" },
                            "port": { "type": "integer" }
                        },
                        "required": ["host", "port"]
                    }
                }
            }
        });

        let component_schema = root_schema.clone();
        let template_spec = TemplateSpec {
            program: amber_template::ProgramTemplateSpec {
                entrypoint: vec![
                    ProgramArgTemplate::Arg(vec![TemplatePart::lit("/app/bin/server")]),
                    ProgramArgTemplate::Repeated(RepeatedProgramArgTemplate {
                        when: None,
                        each: RepeatedTemplateSource::Config {
                            path: "targets".to_string(),
                        },
                        arg: None,
                        argv: vec![
                            vec![TemplatePart::lit("--target")],
                            vec![
                                TemplatePart::current_item("host"),
                                TemplatePart::lit(":"),
                                TemplatePart::current_item("port"),
                            ],
                        ],
                        join: None,
                    }),
                ],
                env: BTreeMap::from([(
                    "TARGETS".to_string(),
                    ProgramEnvTemplate::Repeated(RepeatedProgramEnvTemplate {
                        when: None,
                        each: RepeatedTemplateSource::Config {
                            path: "targets".to_string(),
                        },
                        value: vec![
                            TemplatePart::current_item("host"),
                            TemplatePart::lit(":"),
                            TemplatePart::current_item("port"),
                        ],
                        join: ",".to_string(),
                    }),
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
            (
                "AMBER_CONFIG_TARGETS".to_string(),
                r#"[{"host":"api-a.internal","port":8080},{"host":"api-b.internal","port":9090}]"#
                    .to_string(),
            ),
        ]);

        let os_env = env
            .into_iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        let plan = build_run_plan(os_env).expect("run plan should build");

        assert_eq!(
            plan.entrypoint,
            vec![
                "/app/bin/server".to_string(),
                "--target".to_string(),
                "api-a.internal:8080".to_string(),
                "--target".to_string(),
                "api-b.internal:9090".to_string(),
            ]
        );
        assert_eq!(
            plan.env.get(&OsString::from("TARGETS")),
            Some(&OsString::from("api-a.internal:8080,api-b.internal:9090"))
        );
    }

    #[test]
    fn build_run_plan_joins_repeated_config_arg_and_skips_missing_optional_repeated_env() {
        let root_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "host": { "type": "string" }
                        },
                        "required": ["host"]
                    }
                },
                "enabled": { "type": "boolean" }
            }
        });

        let component_schema = root_schema.clone();
        let template_spec = TemplateSpec {
            program: amber_template::ProgramTemplateSpec {
                entrypoint: vec![
                    ProgramArgTemplate::Arg(vec![TemplatePart::lit("/app/bin/server")]),
                    ProgramArgTemplate::Repeated(RepeatedProgramArgTemplate {
                        when: None,
                        each: RepeatedTemplateSource::Config {
                            path: "targets".to_string(),
                        },
                        arg: Some(vec![TemplatePart::current_item("host")]),
                        argv: Vec::new(),
                        join: Some(",".to_string()),
                    }),
                ],
                env: BTreeMap::from([(
                    "TARGETS".to_string(),
                    ProgramEnvTemplate::Repeated(RepeatedProgramEnvTemplate {
                        when: Some("enabled".to_string()),
                        each: RepeatedTemplateSource::Config {
                            path: "targets".to_string(),
                        },
                        value: vec![TemplatePart::current_item("host")],
                        join: ",".to_string(),
                    }),
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
            (
                "AMBER_CONFIG_TARGETS".to_string(),
                r#"[{"host":"api-a.internal"},{"host":"api-b.internal"}]"#.to_string(),
            ),
        ]);

        let os_env = env
            .into_iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        let plan = build_run_plan(os_env).expect("run plan should build");

        assert_eq!(
            plan.entrypoint,
            vec![
                "/app/bin/server".to_string(),
                "api-a.internal,api-b.internal".to_string(),
            ]
        );
        assert!(
            !plan.env.contains_key(&OsString::from("TARGETS")),
            "repeated env should be omitted when its config-based `when` is absent"
        );
    }

    #[test]
    fn build_run_plan_skips_joined_repeated_config_arg_and_env_for_empty_array() {
        let plan = build_run_plan_with_repeated_targets(
            repeated_targets_root_schema(serde_json::json!({
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "host": { "type": "string" }
                    },
                    "required": ["host"]
                }
            })),
            Some("[]"),
        );

        assert_eq!(plan.entrypoint, vec!["/app/bin/server".to_string()]);
        assert!(
            !plan.env.contains_key(&OsString::from("TARGETS")),
            "repeated env should be omitted when config expansion is empty"
        );
    }

    #[test]
    fn build_run_plan_skips_joined_repeated_config_arg_and_env_for_missing_path() {
        let plan = build_run_plan_with_repeated_targets(
            repeated_targets_root_schema(serde_json::json!({
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "host": { "type": "string" }
                    },
                    "required": ["host"]
                }
            })),
            None,
        );

        assert_eq!(plan.entrypoint, vec!["/app/bin/server".to_string()]);
        assert!(
            !plan.env.contains_key(&OsString::from("TARGETS")),
            "repeated env should be omitted when config expansion is missing"
        );
    }

    #[test]
    fn build_run_plan_skips_joined_repeated_config_arg_and_env_for_null() {
        let plan = build_run_plan_with_repeated_targets(
            repeated_targets_root_schema(serde_json::json!({
                "type": ["array", "null"],
                "items": {
                    "type": "object",
                    "properties": {
                        "host": { "type": "string" }
                    },
                    "required": ["host"]
                }
            })),
            Some("null"),
        );

        assert_eq!(plan.entrypoint, vec!["/app/bin/server".to_string()]);
        assert!(
            !plan.env.contains_key(&OsString::from("TARGETS")),
            "repeated env should be omitted when config expansion is null"
        );
    }

    #[test]
    fn build_run_plan_rejects_non_array_repeated_config_source() {
        let root_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "targets": { "type": "string" }
            }
        });

        let component_schema = root_schema.clone();
        let template_spec = TemplateSpec {
            program: amber_template::ProgramTemplateSpec {
                entrypoint: vec![
                    ProgramArgTemplate::Arg(vec![TemplatePart::lit("/app/bin/server")]),
                    ProgramArgTemplate::Repeated(RepeatedProgramArgTemplate {
                        when: None,
                        each: RepeatedTemplateSource::Config {
                            path: "targets".to_string(),
                        },
                        arg: Some(vec![TemplatePart::current_item("host")]),
                        argv: Vec::new(),
                        join: None,
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
            (
                "AMBER_CONFIG_TARGETS".to_string(),
                "\"not-an-array\"".to_string(),
            ),
        ]);

        let os_env = env
            .into_iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        let err = build_run_plan(os_env).expect_err("non-array repeated source should fail");
        assert!(
            err.to_string().contains("must resolve to an array"),
            "{}",
            err
        );
    }

    #[test]
    fn helper_mount_requires_config_payload() {
        use base64::engine::general_purpose::STANDARD;

        let entrypoint = vec!["/bin/echo".to_string(), "ok".to_string()];
        let env = BTreeMap::from([("HELLO".to_string(), "world".to_string())]);
        let mounts = vec![MountSpec::Template(MountTemplateSpec {
            when: None,
            each: None,
            path: vec![TemplatePart::lit("/tmp/app.txt")],
            source: vec![TemplatePart::lit("config.app")],
        })];

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
        let mounts = vec![MountSpec::Template(MountTemplateSpec {
            when: None,
            each: None,
            path: vec![TemplatePart::lit(mount_path.display().to_string())],
            source: vec![TemplatePart::lit("config.app")],
        })];

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
