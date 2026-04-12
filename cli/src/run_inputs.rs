use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::{self, Write as _},
    net::SocketAddr,
    path::{Path, PathBuf},
};

use amber_compiler::run_plan::RunPlan;
use amber_config::{self as config, CONFIG_ENV_PREFIX};
use amber_manifest::{CapabilityKind, CapabilityTransport};
use miette::{Context as _, IntoDiagnostic as _, Result};
use rpassword::prompt_password;
use serde_json::Value;
use url::Url;

use crate::site_proxy_metadata::load_site_proxy_metadata;

const GENERATED_ENV_SAMPLE_FILENAME: &str = "env.example";
const PROJECT_ENV_FILENAME: &str = ".env";
pub(crate) const CONFIG_FILE_ENV_PREFIX: &str = "AMBER_CONFIG_FILE_";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RootInputSpec {
    pub(crate) path: String,
    pub(crate) env_var: String,
    pub(crate) required: bool,
    pub(crate) secret: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExternalSlotSpec {
    pub(crate) name: String,
    pub(crate) env_var: String,
    pub(crate) required: bool,
    pub(crate) kind: CapabilityKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExportSpec {
    pub(crate) name: String,
    pub(crate) protocol: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RunInterface {
    pub(crate) root_inputs: Vec<RootInputSpec>,
    pub(crate) external_slots: Vec<ExternalSlotSpec>,
    pub(crate) exports: Vec<ExportSpec>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedRootInputComment {
    required: bool,
    secret: bool,
    path: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RootInputSource {
    Literal(String),
    File(PathBuf),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct RunInputLayer {
    root_inputs: BTreeMap<String, RootInputSource>,
    external_slots: BTreeMap<String, String>,
}

pub(crate) fn resolve_manifest_entry_path(path: &Path) -> Result<PathBuf> {
    if !path.is_dir() {
        return Ok(path.to_path_buf());
    }
    for name in ["scenario.json5", "root.json5"] {
        let candidate = path.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(miette::miette!(
        "directory {} is not a manifest directory; expected scenario.json5 or root.json5",
        path.display()
    ))
}

pub(crate) fn project_env_path(project_root: &Path) -> PathBuf {
    project_root.join(PROJECT_ENV_FILENAME)
}

pub(crate) fn ambient_run_env() -> BTreeMap<String, String> {
    env::vars().filter(|(key, _)| is_run_env_key(key)).collect()
}

pub(crate) fn load_run_env(
    project_root: Option<&Path>,
    env_files: &[PathBuf],
    config_file_overrides: &[String],
    interface: &RunInterface,
) -> Result<BTreeMap<String, String>> {
    let cwd = env::current_dir().into_diagnostic()?;
    let mut merged = RunInputLayer::default();

    if let Some(project_root) = project_root {
        let env_path = project_env_path(project_root);
        if env_path.is_file() {
            merge_run_input_layer(
                &mut merged,
                load_env_file_layer(&env_path, project_root, "project .env")?,
            );
        }
    }

    for env_file in env_files {
        let env_dir = env_file.parent().unwrap_or_else(|| Path::new("."));
        merge_run_input_layer(
            &mut merged,
            load_env_file_layer(
                env_file,
                env_dir,
                &format!("env file {}", env_file.display()),
            )?,
        );
    }

    merge_run_input_layer(
        &mut merged,
        parse_run_input_layer(env::vars(), &cwd, "ambient environment")?,
    );
    merge_run_input_layer(
        &mut merged,
        parse_cli_config_file_overrides(config_file_overrides, &cwd)?,
    );

    resolve_run_input_layer(&merged, interface)
}

fn merge_run_input_layer(target: &mut RunInputLayer, layer: RunInputLayer) {
    target.root_inputs.extend(layer.root_inputs);
    target.external_slots.extend(layer.external_slots);
}

fn load_env_file_layer(path: &Path, base_dir: &Path, label: &str) -> Result<RunInputLayer> {
    let iter = dotenvy::from_path_iter(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read env file {}", path.display()))?;
    let mut pairs = Vec::new();
    for entry in iter {
        let (key, value) = entry
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to parse env file {}", path.display()))?;
        pairs.push((key, value));
    }
    parse_run_input_layer(pairs, base_dir, label)
}

fn parse_run_input_layer(
    entries: impl IntoIterator<Item = (String, String)>,
    base_dir: &Path,
    layer_label: &str,
) -> Result<RunInputLayer> {
    let mut layer = RunInputLayer::default();

    for (key, value) in entries {
        if key.starts_with(CONFIG_FILE_ENV_PREFIX) {
            if value.is_empty() {
                continue;
            }
            let path = config_file_env_var_to_path(&key)?;
            let resolved = resolve_input_file_path(base_dir, &value);
            insert_root_input_source(
                &mut layer.root_inputs,
                &path,
                RootInputSource::File(resolved),
                layer_label,
            )?;
            continue;
        }
        if key.starts_with(CONFIG_ENV_PREFIX) {
            let path = config::env_var_to_path(&key)
                .map_err(|err| miette::miette!("invalid runtime config env var `{key}`: {err}"))?;
            insert_root_input_source(
                &mut layer.root_inputs,
                &path,
                RootInputSource::Literal(value),
                layer_label,
            )?;
            continue;
        }
        if key.starts_with("AMBER_EXTERNAL_SLOT_") {
            layer.external_slots.insert(key, value);
        }
    }

    Ok(layer)
}

fn parse_cli_config_file_overrides(overrides: &[String], cwd: &Path) -> Result<RunInputLayer> {
    let mut layer = RunInputLayer::default();

    for override_spec in overrides {
        let Some((path, raw_file)) = override_spec.split_once('=') else {
            return Err(miette::miette!(
                "invalid `--config-file` value `{override_spec}`; expected config.path=FILE"
            ));
        };
        if raw_file.is_empty() {
            return Err(miette::miette!(
                "invalid `--config-file` value `{override_spec}`; FILE must not be empty"
            ));
        }
        config::env_var_for_path(path).map_err(|err| {
            miette::miette!("invalid config path `{path}` in `--config-file`: {err}")
        })?;
        layer.root_inputs.insert(
            path.to_string(),
            RootInputSource::File(resolve_input_file_path(cwd, raw_file)),
        );
    }

    Ok(layer)
}

fn insert_root_input_source(
    target: &mut BTreeMap<String, RootInputSource>,
    path: &str,
    source: RootInputSource,
    layer_label: &str,
) -> Result<()> {
    if let Some(existing) = target.get(path)
        && !same_root_input_source_kind(existing, &source)
    {
        return Err(miette::miette!(
            "{layer_label} defines both `AMBER_CONFIG_*` and `AMBER_CONFIG_FILE_*` for \
             config.{path}"
        ));
    }
    target.insert(path.to_string(), source);
    Ok(())
}

fn same_root_input_source_kind(left: &RootInputSource, right: &RootInputSource) -> bool {
    matches!(
        (left, right),
        (RootInputSource::Literal(_), RootInputSource::Literal(_))
            | (RootInputSource::File(_), RootInputSource::File(_))
    )
}

fn resolve_run_input_layer(
    layer: &RunInputLayer,
    interface: &RunInterface,
) -> Result<BTreeMap<String, String>> {
    let mut env = BTreeMap::new();

    for input in &interface.root_inputs {
        let Some(source) = layer.root_inputs.get(&input.path) else {
            continue;
        };
        let value = resolve_root_input_source(&input.path, source)?;
        env.insert(input.env_var.clone(), value);
    }

    for slot in &interface.external_slots {
        if let Some(value) = layer.external_slots.get(&slot.env_var) {
            env.insert(slot.env_var.clone(), value.clone());
        }
    }
    Ok(env)
}

fn resolve_root_input_source(path: &str, source: &RootInputSource) -> Result<String> {
    match source {
        RootInputSource::Literal(value) => Ok(value.clone()),
        RootInputSource::File(file_path) => fs::read_to_string(file_path)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "failed to read config file {} for config.{path}",
                    file_path.display()
                )
            }),
    }
}

fn resolve_input_file_path(base_dir: &Path, raw: &str) -> PathBuf {
    let path = Path::new(raw);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
}

pub(crate) fn config_file_env_var_for_path(path: &str) -> Result<String> {
    let env_var = config::env_var_for_path(path)
        .map_err(|err| miette::miette!("invalid config path `{path}`: {err}"))?;
    Ok(env_var.replacen(CONFIG_ENV_PREFIX, CONFIG_FILE_ENV_PREFIX, 1))
}

fn config_file_env_var_to_path(var: &str) -> Result<String> {
    let rest = var
        .strip_prefix(CONFIG_FILE_ENV_PREFIX)
        .ok_or_else(|| miette::miette!("not an AMBER_CONFIG_FILE_* var"))?;
    config::env_var_to_path(&format!("{CONFIG_ENV_PREFIX}{rest}"))
        .map_err(|err| miette::miette!("invalid runtime config file env var `{var}`: {err}"))
}

pub(crate) fn collect_run_interface(run_plan: &RunPlan) -> Result<RunInterface> {
    let mut root_inputs = BTreeMap::<String, RootInputSpec>::new();
    let mut external_slots = BTreeMap::<String, ExternalSlotSpec>::new();
    let mut exports = BTreeMap::<String, ExportSpec>::new();

    for site in run_plan.sites.values() {
        if let Some(env_sample) = site.artifact_files.get(GENERATED_ENV_SAMPLE_FILENAME) {
            merge_root_inputs(&mut root_inputs, parse_env_sample(env_sample)?);
        }

        let metadata = match load_site_proxy_metadata(site) {
            Ok(metadata) => metadata,
            Err(_) if site.assigned_components.is_empty() => continue,
            Err(err) => return Err(err),
        };

        for (name, slot) in metadata.external_slots {
            if is_synthetic_external_slot_name(&name) {
                continue;
            }
            external_slots
                .entry(name.clone())
                .and_modify(|existing| {
                    existing.required |= slot.required;
                })
                .or_insert(ExternalSlotSpec {
                    name,
                    env_var: slot.url_env,
                    required: slot.required,
                    kind: slot.kind,
                });
        }

        for (name, export) in metadata.exports {
            if is_synthetic_export_name(&name) {
                continue;
            }
            match exports.get(&name) {
                Some(existing) if existing.protocol != export.protocol => {
                    return Err(miette::miette!(
                        "run plan contains conflicting protocols for export `{name}`"
                    ));
                }
                Some(_) => {}
                None => {
                    exports.insert(
                        name.clone(),
                        ExportSpec {
                            name,
                            protocol: export.protocol,
                        },
                    );
                }
            }
        }
    }

    Ok(RunInterface {
        root_inputs: root_inputs.into_values().collect(),
        external_slots: external_slots.into_values().collect(),
        exports: exports.into_values().collect(),
    })
}

pub(crate) fn missing_required_root_inputs<'a>(
    env: &BTreeMap<String, String>,
    interface: &'a RunInterface,
) -> Vec<&'a RootInputSpec> {
    interface
        .root_inputs
        .iter()
        .filter(|input| input.required && root_env_var_missing(env, &input.env_var))
        .collect()
}

pub(crate) fn missing_required_external_slots<'a>(
    env: &BTreeMap<String, String>,
    interface: &'a RunInterface,
) -> Vec<&'a ExternalSlotSpec> {
    interface
        .external_slots
        .iter()
        .filter(|slot| slot.required && env_var_missing(env, &slot.env_var))
        .collect()
}

pub(crate) fn missing_promptable_external_slots<'a>(
    env: &BTreeMap<String, String>,
    interface: &'a RunInterface,
) -> Vec<&'a ExternalSlotSpec> {
    interface
        .external_slots
        .iter()
        .filter(|slot| env_var_missing(env, &slot.env_var))
        .collect()
}

pub(crate) fn select_root_env(
    env: &BTreeMap<String, String>,
    interface: &RunInterface,
) -> BTreeMap<String, String> {
    interface
        .root_inputs
        .iter()
        .filter_map(|input| {
            env.get(&input.env_var)
                .filter(|value| !value.is_empty())
                .map(|value| (input.env_var.clone(), value.clone()))
        })
        .collect()
}

pub(crate) fn select_external_slot_env(
    env: &BTreeMap<String, String>,
    interface: &RunInterface,
) -> BTreeMap<String, String> {
    interface
        .external_slots
        .iter()
        .filter_map(|slot| {
            env.get(&slot.env_var)
                .filter(|value| !value.trim().is_empty())
                .map(|value| (slot.env_var.clone(), value.clone()))
        })
        .collect()
}

pub(crate) fn prompt_for_missing_inputs(
    env: &mut BTreeMap<String, String>,
    interface: &RunInterface,
    root_schema: Option<&Value>,
) -> Result<()> {
    let mut prompt_visible = |prompt: &str| prompt_line(prompt);
    let mut prompt_secret = |prompt: &str| prompt_password(prompt).into_diagnostic();
    let mut print_error = |message: &str| {
        eprintln!("{message}");
    };
    prompt_for_missing_inputs_with(
        env,
        interface,
        root_schema,
        &mut prompt_visible,
        &mut prompt_secret,
        &mut print_error,
    )
}

fn prompt_for_missing_inputs_with(
    env: &mut BTreeMap<String, String>,
    interface: &RunInterface,
    root_schema: Option<&Value>,
    prompt_visible: &mut impl FnMut(&str) -> Result<String>,
    prompt_secret: &mut impl FnMut(&str) -> Result<String>,
    print_error: &mut impl FnMut(&str),
) -> Result<()> {
    for input in &interface.root_inputs {
        if !input.required || !root_env_var_missing(env, &input.env_var) {
            continue;
        }
        let prompt = format!("config.{}: ", input.path);
        loop {
            let value = if input.secret {
                prompt_secret(&prompt)?
            } else {
                prompt_visible(&prompt)?
            };
            if value.is_empty() {
                print_error(&format!("config.{} must not be empty", input.path));
                continue;
            }
            if let Some(schema) = root_schema
                && let Err(err) = validate_root_input_value(schema, &input.path, &value)
            {
                print_error(&format!("invalid value for config.{}: {err}", input.path));
                continue;
            }
            env.insert(input.env_var.clone(), value);
            break;
        }
    }

    for slot in missing_promptable_external_slots(env, interface) {
        let prompt = if slot.required {
            format!("slot.{}: ", slot.name)
        } else {
            format!("slot.{} (optional): ", slot.name)
        };
        loop {
            let value = prompt_visible(&prompt)?;
            let trimmed = value.trim();
            if trimmed.is_empty() {
                if slot.required {
                    print_error(&format!("slot.{} must not be empty", slot.name));
                    continue;
                }
                break;
            }
            match normalize_external_slot_value(slot, trimmed) {
                Ok(normalized) => {
                    env.insert(slot.env_var.clone(), normalized);
                    break;
                }
                Err(err) => {
                    print_error(&err.to_string());
                }
            }
        }
    }

    Ok(())
}

pub(crate) fn render_resolved_input_lines(
    env: &BTreeMap<String, String>,
    interface: &RunInterface,
) -> Vec<String> {
    let mut lines = Vec::new();

    for input in &interface.root_inputs {
        let Some(value) = env.get(&input.env_var).filter(|value| !value.is_empty()) else {
            continue;
        };
        lines.push(format!(
            "config.{}: {}",
            input.path,
            if input.secret {
                "*".repeat(value.chars().count().max(8))
            } else if value.contains('\n') || value.chars().count() > 80 {
                format!("<{} bytes>", value.len())
            } else {
                value.clone()
            }
        ));
    }

    for slot in &interface.external_slots {
        let Some(value) = env
            .get(&slot.env_var)
            .filter(|value| !value.trim().is_empty())
        else {
            continue;
        };
        lines.push(format!("slot.{}: {value}", slot.name));
    }

    lines
}

pub(crate) fn render_root_reuse_env(
    env: &BTreeMap<String, String>,
    interface: &RunInterface,
) -> String {
    let mut out = String::new();
    out.push_str("# Root config captured from a successful amber run\n");
    for input in &interface.root_inputs {
        if let Some(value) = env.get(&input.env_var).filter(|value| !value.is_empty()) {
            out.push_str(&input.env_var);
            out.push('=');
            out.push_str(value);
            out.push('\n');
        }
    }
    out
}

pub(crate) fn render_run_env_file(interface: &RunInterface) -> String {
    let mut out = String::new();
    out.push_str("# Runtime inputs for `amber run --env-file`.\n");
    out.push_str(
        "# Fill in the values you need, then pass this file back to `amber run --env-file`.\n",
    );
    if let Some(example) = interface.root_inputs.first() {
        let file_var = config_file_env_var_for_path(&example.path)
            .expect("root input path should map to a config file env var");
        out.push_str(&format!(
            "# For any root config input below, you can replace `AMBER_CONFIG_` with \
             `AMBER_CONFIG_FILE_` to load the value from a UTF-8 file instead, for example \
             `{file_var}=./value.txt`.\n",
        ));
    }

    if interface.root_inputs.is_empty() && interface.external_slots.is_empty() {
        out.push_str("# No env-based runtime inputs are required for this run target.\n");
        return out;
    }

    if !interface.root_inputs.is_empty() {
        out.push_str("\n# Root config inputs\n");
        for input in &interface.root_inputs {
            let required = if input.required {
                "required"
            } else {
                "optional"
            };
            let secret = if input.secret { "secret" } else { "config" };
            out.push_str(&format!(
                "# {required} {secret} config.{}\n{}=\n",
                input.path, input.env_var
            ));
        }
    }

    if !interface.external_slots.is_empty() {
        out.push_str("\n# External slot URLs\n");
        for slot in &interface.external_slots {
            let required = if slot.required {
                "required"
            } else {
                "optional"
            };
            out.push_str(&format!(
                "# {required} {} slot {}\n{}=\n",
                slot.kind, slot.name, slot.env_var
            ));
        }
    }

    out
}

pub(crate) fn slot_url_from_socket(slot: &ExternalSlotSpec, addr: SocketAddr) -> Result<String> {
    let scheme = match slot.kind.transport() {
        CapabilityTransport::Http => "http",
        CapabilityTransport::NonNetwork => {
            return Err(miette::miette!(
                "external slot `{}` is not a network capability and cannot be proxied",
                slot.name
            ));
        }
        _ => {
            return Err(miette::miette!(
                "external slot `{}` is not a supported network capability",
                slot.name
            ));
        }
    };
    Ok(format!("{scheme}://{addr}"))
}

pub(crate) fn validate_export_bindings(
    interface: &RunInterface,
    bindings: &[(String, SocketAddr)],
) -> Result<()> {
    let known = interface
        .exports
        .iter()
        .map(|export| export.name.as_str())
        .collect::<BTreeSet<_>>();
    for (name, _) in bindings {
        if !known.contains(name.as_str()) {
            return Err(miette::miette!(
                "run does not export `{name}`; available exports: {}",
                interface
                    .exports
                    .iter()
                    .map(|export| export.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_slot_bindings(
    interface: &RunInterface,
    bindings: &[(String, String)],
) -> Result<()> {
    let known = interface
        .external_slots
        .iter()
        .map(|slot| slot.name.as_str())
        .collect::<BTreeSet<_>>();
    for (name, value) in bindings {
        let Some(slot) = interface
            .external_slots
            .iter()
            .find(|slot| slot.name == *name)
        else {
            return Err(miette::miette!(
                "run does not declare external slot `{name}`; available external slots: {}",
                interface
                    .external_slots
                    .iter()
                    .map(|slot| slot.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        };
        normalize_external_slot_value(slot, value)?;
        if !known.contains(name.as_str()) {
            unreachable!("slot should be present after lookup");
        }
    }
    Ok(())
}

pub(crate) fn normalize_external_slot_value(slot: &ExternalSlotSpec, raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(miette::miette!("slot.{} must not be empty", slot.name));
    }

    match slot.kind.transport() {
        CapabilityTransport::Http => {
            let parsed = Url::parse(trimmed)
                .into_diagnostic()
                .wrap_err_with(|| format!("slot.{} must be a valid URL", slot.name))?;
            if !matches!(parsed.scheme(), "http" | "https" | "mesh") {
                return Err(miette::miette!(
                    "slot.{} must use http://, https://, or mesh://",
                    slot.name
                ));
            }
            Ok(parsed.to_string())
        }
        CapabilityTransport::NonNetwork => Err(miette::miette!(
            "slot.{} is not a network capability and cannot be wired through amber run",
            slot.name
        )),
        _ => Err(miette::miette!(
            "slot.{} is not a supported network capability",
            slot.name
        )),
    }
}

pub(crate) fn is_run_env_key(key: &str) -> bool {
    key.starts_with(CONFIG_ENV_PREFIX) || key.starts_with("AMBER_EXTERNAL_SLOT_")
}

pub(crate) fn run_interactive() -> bool {
    use std::io::IsTerminal as _;

    io::stdin().is_terminal() && io::stdout().is_terminal()
}

fn merge_root_inputs(target: &mut BTreeMap<String, RootInputSpec>, inputs: Vec<RootInputSpec>) {
    for input in inputs {
        target
            .entry(input.path.clone())
            .and_modify(|existing| {
                existing.required |= input.required;
                existing.secret |= input.secret;
            })
            .or_insert(input);
    }
}

pub(crate) fn parse_env_sample(contents: &str) -> Result<Vec<RootInputSpec>> {
    let mut parsed = Vec::new();
    let mut pending_comment = None;

    for line in contents.lines() {
        let trimmed = line.trim();
        if let Some(comment) = parse_root_input_comment(trimmed) {
            pending_comment = Some(comment);
            continue;
        }
        let Some((env_var, _)) = trimmed.split_once('=') else {
            continue;
        };
        if !env_var.starts_with(CONFIG_ENV_PREFIX) {
            pending_comment = None;
            continue;
        }
        let comment = pending_comment.take();
        let path = comment
            .as_ref()
            .map(|comment| comment.path.clone())
            .unwrap_or_else(|| {
                config::env_var_to_path(env_var).unwrap_or_else(|_| env_var.to_ascii_lowercase())
            });
        parsed.push(RootInputSpec {
            path,
            env_var: env_var.to_string(),
            required: comment.as_ref().is_some_and(|comment| comment.required),
            secret: comment.as_ref().is_some_and(|comment| comment.secret),
        });
    }

    Ok(parsed)
}

fn validate_root_input_value(root_schema: &Value, path: &str, value: &str) -> Result<()> {
    let leaf_schema = config::schema_lookup_ref(root_schema, path)
        .map_err(|err| miette::miette!("invalid root config path config.{path}: {err}"))?;
    config::parse_env_value(value, leaf_schema)
        .map(|_| ())
        .map_err(|err| miette::miette!("{err}"))
}

fn parse_root_input_comment(line: &str) -> Option<ParsedRootInputComment> {
    let line = line.strip_prefix('#')?.trim();
    let (required, rest) = if let Some(rest) = line.strip_prefix("required ") {
        (true, rest)
    } else if let Some(rest) = line.strip_prefix("optional ") {
        (false, rest)
    } else {
        return None;
    };
    let (secret, rest) = if let Some(rest) = rest.strip_prefix("secret ") {
        (true, rest)
    } else if let Some(rest) = rest.strip_prefix("config ") {
        (false, rest)
    } else {
        return None;
    };
    let path = rest.split(" (default:").next()?.trim();
    let path = path.strip_prefix("config.")?.trim();
    Some(ParsedRootInputComment {
        required,
        secret,
        path: path.to_string(),
    })
}

fn prompt_line(prompt: &str) -> Result<String> {
    let mut stdout = io::stdout();
    stdout.write_all(prompt.as_bytes()).into_diagnostic()?;
    stdout.flush().into_diagnostic()?;
    let mut line = String::new();
    if io::stdin().read_line(&mut line).into_diagnostic()? == 0 {
        return Err(miette::miette!("end of input"));
    }
    Ok(strip_trailing_newline(line))
}

fn strip_trailing_newline(mut value: String) -> String {
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    value
}

fn root_env_var_missing(env: &BTreeMap<String, String>, key: &str) -> bool {
    env.get(key).is_none_or(String::is_empty)
}

fn env_var_missing(env: &BTreeMap<String, String>, key: &str) -> bool {
    env.get(key).is_none_or(|value| value.trim().is_empty())
}

fn is_synthetic_export_name(name: &str) -> bool {
    name.starts_with("amber_export_")
}

fn is_synthetic_external_slot_name(name: &str) -> bool {
    name.starts_with("amber_link_")
}

#[cfg(test)]
mod tests {
    use amber_compiler::{
        mesh::PROXY_METADATA_FILENAME,
        run_plan::{
            ActiveSiteCapabilities, PlacementDefaults, RunLink, RunPlan, RunSitePlan,
            SiteDefinition, SiteKind,
        },
    };
    use amber_scenario::{SCENARIO_IR_SCHEMA, SCENARIO_IR_VERSION, ScenarioIr};

    use super::*;

    fn empty_site(kind: SiteKind, artifact_files: BTreeMap<String, String>) -> RunSitePlan {
        RunSitePlan {
            site: SiteDefinition {
                kind,
                context: None,
            },
            router_identity_id: "/site/test/router".to_string(),
            assigned_components: vec!["/app".to_string()],
            scenario_ir: ScenarioIr {
                schema: amber_scenario::SCENARIO_IR_SCHEMA.to_string(),
                version: amber_scenario::SCENARIO_IR_VERSION,
                root: 0,
                components: Vec::new(),
                bindings: Vec::new(),
                exports: Vec::new(),
                manifest_catalog: BTreeMap::new(),
            },
            artifact_files,
        }
    }

    #[test]
    fn resolve_manifest_entry_path_prefers_scenario_json5() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("scenario.json5"), "{}").expect("write scenario");
        std::fs::write(dir.path().join("root.json5"), "{}").expect("write root");

        assert_eq!(
            resolve_manifest_entry_path(dir.path()).expect("manifest entry"),
            dir.path().join("scenario.json5")
        );
    }

    #[test]
    fn collect_run_interface_filters_synthetic_proxy_entries() {
        let proxy_metadata = serde_json::json!({
            "version": "1",
            "exports": {
                "public": {
                    "component": "/app",
                    "provide": "http",
                    "protocol": "http",
                    "router_mesh_port": 24000
                },
                "amber_export_provider_api_http": {
                    "component": "/api",
                    "provide": "http",
                    "protocol": "http",
                    "router_mesh_port": 24000
                }
            },
            "external_slots": {
                "catalog_api": {
                    "required": true,
                    "kind": "http",
                    "url_env": "AMBER_EXTERNAL_SLOT_CATALOG_API_URL"
                },
                "amber_link_consumer_provider_api_http": {
                    "required": true,
                    "kind": "http",
                    "url_env": "AMBER_EXTERNAL_SLOT_AMBER_LINK_CONSUMER_PROVIDER_API_HTTP_URL"
                }
            }
        });
        let env_example = "\
# required config config.tenant\nAMBER_CONFIG_TENANT=\n# required secret \
                           config.catalog_token\nAMBER_CONFIG_CATALOG_TOKEN=\n";
        let run_plan = RunPlan {
            schema: "amber.run.plan".to_string(),
            version: 2,
            mesh_scope: "scope".to_string(),
            base_scenario: ScenarioIr {
                schema: SCENARIO_IR_SCHEMA.to_string(),
                version: SCENARIO_IR_VERSION,
                root: 0,
                components: Vec::new(),
                bindings: Vec::new(),
                exports: Vec::new(),
                manifest_catalog: BTreeMap::new(),
            },
            offered_sites: BTreeMap::from([(
                "direct_local".to_string(),
                SiteDefinition {
                    kind: SiteKind::Direct,
                    context: None,
                },
            )]),
            defaults: PlacementDefaults::default(),
            initial_active_sites: vec!["direct_local".to_string()],
            standby_sites: Vec::new(),
            dynamic_enabled_sites: vec!["direct_local".to_string()],
            control_only_sites: Vec::new(),
            active_site_capabilities: BTreeMap::from([(
                "direct_local".to_string(),
                ActiveSiteCapabilities {
                    cross_site_routing: true,
                    dynamic_workloads: true,
                    privileged_control: true,
                },
            )]),
            placement_components: BTreeMap::new(),
            assignments: BTreeMap::new(),
            dynamic_capabilities: None,
            framework_children: None,
            sites: BTreeMap::from([(
                "direct_local".to_string(),
                empty_site(
                    SiteKind::Direct,
                    BTreeMap::from([
                        (
                            GENERATED_ENV_SAMPLE_FILENAME.to_string(),
                            env_example.to_string(),
                        ),
                        (
                            PROXY_METADATA_FILENAME.to_string(),
                            proxy_metadata.to_string(),
                        ),
                    ]),
                ),
            )]),
            links: vec![RunLink {
                provider_site: "compose_local".to_string(),
                consumer_site: "direct_local".to_string(),
                provider_component: "/api".to_string(),
                provide: "http".to_string(),
                consumer_component: "/web".to_string(),
                slot: "api".to_string(),
                weak: false,
                protocol: amber_manifest::NetworkProtocol::Http,
                export_name: "amber_export_provider_api_http".to_string(),
                external_slot_name: "amber_link_consumer_provider_api_http".to_string(),
            }],
            startup_waves: Vec::new(),
        };

        let interface = collect_run_interface(&run_plan).expect("run interface");
        assert_eq!(
            interface.root_inputs,
            vec![
                RootInputSpec {
                    path: "catalog_token".to_string(),
                    env_var: "AMBER_CONFIG_CATALOG_TOKEN".to_string(),
                    required: true,
                    secret: true,
                },
                RootInputSpec {
                    path: "tenant".to_string(),
                    env_var: "AMBER_CONFIG_TENANT".to_string(),
                    required: true,
                    secret: false,
                },
            ]
        );
        assert_eq!(
            interface.external_slots,
            vec![ExternalSlotSpec {
                name: "catalog_api".to_string(),
                env_var: "AMBER_EXTERNAL_SLOT_CATALOG_API_URL".to_string(),
                required: true,
                kind: CapabilityKind::Http,
            }]
        );
        assert_eq!(
            interface.exports,
            vec![ExportSpec {
                name: "public".to_string(),
                protocol: "http".to_string(),
            }]
        );
    }

    #[test]
    fn collect_run_interface_reads_compose_proxy_metadata_from_compose_yaml() {
        let run_plan: RunPlan = serde_json::from_value(serde_json::json!({
            "schema": "amber.run.plan",
            "version": 2,
            "mesh_scope": "scope",
            "offered_sites": {
                "compose_local": { "kind": "compose" }
            },
            "defaults": {},
            "initial_active_sites": ["compose_local"],
            "standby_sites": [],
            "dynamic_enabled_sites": ["compose_local"],
            "control_only_sites": [],
            "active_site_capabilities": {
                "compose_local": {
                    "cross_site_routing": true,
                    "dynamic_workloads": true,
                    "privileged_control": true
                }
            },
            "assignments": { "/api": "compose_local" },
            "sites": {
                "compose_local": {
                    "site": { "kind": "compose" },
                    "router_identity_id": "/site/compose_local/router",
                    "assigned_components": ["/api"],
                    "scenario_ir": {
                        "schema": amber_scenario::SCENARIO_IR_SCHEMA,
                        "version": amber_scenario::SCENARIO_IR_VERSION,
                        "root": 0,
                        "components": [],
                        "bindings": [],
                        "exports": []
                    },
                    "artifact_files": {
                        "compose.yaml": concat!(
                            "services:\n",
                            "  amber-router:\n",
                            "    image: example/router\n",
                            "x-amber:\n",
                            "  version: \"1\"\n",
                            "  exports:\n",
                            "    api:\n",
                            "      component: /api\n",
                            "      provide: http\n",
                            "      protocol: http\n",
                            "      router_mesh_port: 24000\n",
                            "  external_slots:\n",
                            "    catalog_api:\n",
                            "      required: true\n",
                            "      kind: http\n",
                            "      url_env: AMBER_EXTERNAL_SLOT_CATALOG_API_URL\n"
                        )
                    }
                }
            },
            "links": [],
            "startup_waves": [["compose_local"]]
        }))
        .expect("run plan should deserialize");

        let interface = collect_run_interface(&run_plan).expect("run interface");
        assert_eq!(
            interface.external_slots,
            vec![ExternalSlotSpec {
                name: "catalog_api".to_string(),
                env_var: "AMBER_EXTERNAL_SLOT_CATALOG_API_URL".to_string(),
                required: true,
                kind: CapabilityKind::Http,
            }]
        );
        assert_eq!(
            interface.exports,
            vec![ExportSpec {
                name: "api".to_string(),
                protocol: "http".to_string(),
            }]
        );
    }

    #[test]
    fn collect_run_interface_skips_empty_standby_sites_without_proxy_metadata() {
        let run_plan: RunPlan = serde_json::from_value(serde_json::json!({
            "schema": "amber.run.plan",
            "version": 2,
            "mesh_scope": "scope",
            "offered_sites": {
                "compose_local": { "kind": "compose" },
                "direct_local": { "kind": "direct" }
            },
            "defaults": {
                "path": "direct_local",
                "image": "compose_local"
            },
            "initial_active_sites": ["compose_local", "direct_local"],
            "standby_sites": ["direct_local"],
            "dynamic_enabled_sites": ["compose_local", "direct_local"],
            "control_only_sites": [],
            "active_site_capabilities": {
                "compose_local": {
                    "cross_site_routing": true,
                    "dynamic_workloads": true,
                    "privileged_control": true
                },
                "direct_local": {
                    "cross_site_routing": true,
                    "dynamic_workloads": true,
                    "privileged_control": true
                }
            },
            "assignments": { "/admin": "compose_local" },
            "sites": {
                "compose_local": {
                    "site": { "kind": "compose" },
                    "router_identity_id": "/site/compose_local/router",
                    "assigned_components": ["/admin"],
                    "scenario_ir": {
                        "schema": amber_scenario::SCENARIO_IR_SCHEMA,
                        "version": amber_scenario::SCENARIO_IR_VERSION,
                        "root": 0,
                        "components": [],
                        "bindings": [],
                        "exports": []
                    },
                    "artifact_files": {
                        "compose.yaml": concat!(
                            "services:\n",
                            "  amber-router:\n",
                            "    image: example/router\n",
                            "x-amber:\n",
                            "  version: \"1\"\n",
                            "  exports:\n",
                            "    admin_http:\n",
                            "      component: /admin\n",
                            "      provide: http\n",
                            "      protocol: http\n",
                            "      router_mesh_port: 24000\n"
                        )
                    }
                },
                "direct_local": {
                    "site": { "kind": "direct" },
                    "router_identity_id": "/site/direct_local/router",
                    "assigned_components": [],
                    "scenario_ir": {
                        "schema": amber_scenario::SCENARIO_IR_SCHEMA,
                        "version": amber_scenario::SCENARIO_IR_VERSION,
                        "root": 0,
                        "components": [],
                        "bindings": [],
                        "exports": []
                    },
                    "artifact_files": {}
                }
            },
            "links": [],
            "startup_waves": [["compose_local"], ["direct_local"]]
        }))
        .expect("run plan should deserialize");

        let interface = collect_run_interface(&run_plan).expect("run interface");
        assert!(
            interface.external_slots.is_empty(),
            "empty standby sites should not invent external slot requirements"
        );
        assert_eq!(
            interface.exports,
            vec![ExportSpec {
                name: "admin_http".to_string(),
                protocol: "http".to_string(),
            }]
        );
    }

    #[test]
    fn parse_root_input_comment_understands_generated_format() {
        assert_eq!(
            parse_root_input_comment("# required secret config.catalog_token (default: \"x\")"),
            Some(ParsedRootInputComment {
                required: true,
                secret: true,
                path: "catalog_token".to_string(),
            })
        );
        assert_eq!(
            parse_root_input_comment("# optional config config.tenant"),
            Some(ParsedRootInputComment {
                required: false,
                secret: false,
                path: "tenant".to_string(),
            })
        );
    }

    #[test]
    fn normalize_external_slot_value_requires_httpish_urls() {
        let slot = ExternalSlotSpec {
            name: "catalog_api".to_string(),
            env_var: "AMBER_EXTERNAL_SLOT_CATALOG_API_URL".to_string(),
            required: true,
            kind: CapabilityKind::Http,
        };

        assert_eq!(
            normalize_external_slot_value(&slot, "http://127.0.0.1:9100").expect("url"),
            "http://127.0.0.1:9100/"
        );
        assert!(normalize_external_slot_value(&slot, "tcp://127.0.0.1:9100").is_err());
    }

    #[test]
    fn slot_url_from_socket_uses_http_for_http_capabilities() {
        let slot = ExternalSlotSpec {
            name: "catalog_api".to_string(),
            env_var: "AMBER_EXTERNAL_SLOT_CATALOG_API_URL".to_string(),
            required: true,
            kind: CapabilityKind::Http,
        };
        let addr: SocketAddr = "127.0.0.1:9100".parse().expect("socket addr");
        assert_eq!(
            slot_url_from_socket(&slot, addr).expect("slot url"),
            "http://127.0.0.1:9100"
        );
    }

    #[test]
    fn parse_env_sample_collects_root_inputs() {
        let env = "\
# required config config.tenant\nAMBER_CONFIG_TENANT=\n\n# optional secret \
                   config.catalog_token\nAMBER_CONFIG_CATALOG_TOKEN=\n";
        assert_eq!(
            parse_env_sample(env).expect("env sample"),
            vec![
                RootInputSpec {
                    path: "tenant".to_string(),
                    env_var: "AMBER_CONFIG_TENANT".to_string(),
                    required: true,
                    secret: false,
                },
                RootInputSpec {
                    path: "catalog_token".to_string(),
                    env_var: "AMBER_CONFIG_CATALOG_TOKEN".to_string(),
                    required: false,
                    secret: true,
                },
            ]
        );
    }

    #[test]
    fn validate_slot_bindings_rejects_unknown_slots() {
        let interface = RunInterface {
            external_slots: vec![ExternalSlotSpec {
                name: "catalog_api".to_string(),
                env_var: "AMBER_EXTERNAL_SLOT_CATALOG_API_URL".to_string(),
                required: true,
                kind: CapabilityKind::Http,
            }],
            ..RunInterface::default()
        };
        let err = validate_slot_bindings(
            &interface,
            &[(
                String::from("missing"),
                String::from("http://127.0.0.1:9100"),
            )],
        )
        .expect_err("unknown slot should fail");
        assert!(err.to_string().contains("available external slots"));
    }

    #[test]
    fn missing_promptable_external_slots_include_weak_external_slots() {
        let interface = RunInterface {
            external_slots: vec![ExternalSlotSpec {
                name: "catalog_api".to_string(),
                env_var: "AMBER_EXTERNAL_SLOT_CATALOG_API_URL".to_string(),
                required: false,
                kind: CapabilityKind::Http,
            }],
            ..RunInterface::default()
        };

        assert_eq!(
            missing_promptable_external_slots(&BTreeMap::new(), &interface),
            vec![&ExternalSlotSpec {
                name: "catalog_api".to_string(),
                env_var: "AMBER_EXTERNAL_SLOT_CATALOG_API_URL".to_string(),
                required: false,
                kind: CapabilityKind::Http,
            }]
        );
    }

    #[test]
    fn load_run_env_resolves_file_inputs_relative_to_env_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config_file = temp.path().join("auth.json");
        std::fs::write(&config_file, "{ \"token\": \"demo\" }\n").expect("write config file");
        let env_file = temp.path().join("runtime.env");
        std::fs::write(
            &env_file,
            "\
AMBER_CONFIG_FILE_AUTH__JSON=./auth.json\n\
AMBER_EXTERNAL_SLOT_CATALOG_API_URL=http://127.0.0.1:9100\n",
        )
        .expect("write env file");
        let interface = RunInterface {
            root_inputs: vec![RootInputSpec {
                path: "auth.json".to_string(),
                env_var: "AMBER_CONFIG_AUTH__JSON".to_string(),
                required: true,
                secret: false,
            }],
            external_slots: vec![ExternalSlotSpec {
                name: "catalog_api".to_string(),
                env_var: "AMBER_EXTERNAL_SLOT_CATALOG_API_URL".to_string(),
                required: true,
                kind: CapabilityKind::Http,
            }],
            ..RunInterface::default()
        };

        let env = resolve_run_input_layer(
            &load_env_file_layer(&env_file, temp.path(), "test env file").expect("load env layer"),
            &interface,
        )
        .expect("resolve env");
        assert_eq!(
            env.get("AMBER_CONFIG_AUTH__JSON"),
            Some(&"{ \"token\": \"demo\" }\n".to_string())
        );
        assert_eq!(
            env.get("AMBER_EXTERNAL_SLOT_CATALOG_API_URL"),
            Some(&"http://127.0.0.1:9100".to_string())
        );
        assert!(
            !env.contains_key("AMBER_CONFIG_FILE_AUTH__JSON"),
            "resolved env should only contain canonical AMBER_CONFIG_* keys"
        );
    }

    #[test]
    fn load_run_env_rejects_literal_and_file_for_same_path_in_one_layer() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config_file = temp.path().join("token.txt");
        std::fs::write(&config_file, "demo").expect("write config file");
        let env_file = temp.path().join("runtime.env");
        std::fs::write(
            &env_file,
            "\
AMBER_CONFIG_TOKEN=inline\nAMBER_CONFIG_FILE_TOKEN=./token.txt\n",
        )
        .expect("write env file");

        let err = load_env_file_layer(&env_file, temp.path(), "test env file")
            .expect_err("conflicting env file");
        assert!(
            err.to_string()
                .contains("defines both `AMBER_CONFIG_*` and `AMBER_CONFIG_FILE_*`")
        );
    }

    #[test]
    fn load_run_env_cli_config_file_overrides_earlier_literal_sources() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config_file = temp.path().join("token.txt");
        std::fs::write(&config_file, "from-file").expect("write config file");
        let env_file = temp.path().join("runtime.env");
        std::fs::write(&env_file, "AMBER_CONFIG_TOKEN=inline\n").expect("write env file");

        let mut layer =
            load_env_file_layer(&env_file, temp.path(), "test env file").expect("load env layer");
        merge_run_input_layer(
            &mut layer,
            parse_cli_config_file_overrides(
                &[format!("token={}", config_file.display())],
                temp.path(),
            )
            .expect("load cli overrides"),
        );
        let interface = RunInterface {
            root_inputs: vec![RootInputSpec {
                path: "token".to_string(),
                env_var: "AMBER_CONFIG_TOKEN".to_string(),
                required: true,
                secret: false,
            }],
            ..RunInterface::default()
        };
        let env = resolve_run_input_layer(&layer, &interface).expect("resolve env");
        assert_eq!(
            env.get("AMBER_CONFIG_TOKEN"),
            Some(&"from-file".to_string())
        );
    }

    #[test]
    fn load_run_env_ignores_unselected_file_backed_inputs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let env_file = temp.path().join("runtime.env");
        std::fs::write(
            &env_file,
            "\
AMBER_CONFIG_TOKEN=inline\nAMBER_CONFIG_FILE_UNUSED=./missing.txt\n",
        )
        .expect("write env file");
        let interface = RunInterface {
            root_inputs: vec![RootInputSpec {
                path: "token".to_string(),
                env_var: "AMBER_CONFIG_TOKEN".to_string(),
                required: true,
                secret: false,
            }],
            ..RunInterface::default()
        };

        let env = load_run_env(None, &[env_file], &[], &interface).expect("load env");
        assert_eq!(env.get("AMBER_CONFIG_TOKEN"), Some(&"inline".to_string()));
        assert!(
            !env.contains_key("AMBER_CONFIG_UNUSED"),
            "unselected file-backed inputs should be ignored"
        );
    }

    #[test]
    fn prompt_for_missing_inputs_reprompts_until_root_value_valid() {
        let interface = RunInterface {
            root_inputs: vec![RootInputSpec {
                path: "count".to_string(),
                env_var: "AMBER_CONFIG_COUNT".to_string(),
                required: true,
                secret: false,
            }],
            ..RunInterface::default()
        };
        let root_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "count": { "type": "integer" }
            },
            "required": ["count"]
        });
        let mut env = BTreeMap::new();
        let mut visible = vec!["abc".to_string(), "42".to_string()].into_iter();
        let mut secret = std::iter::empty::<String>();
        let mut errors = Vec::new();

        prompt_for_missing_inputs_with(
            &mut env,
            &interface,
            Some(&root_schema),
            &mut |_| Ok(visible.next().expect("visible input should exist")),
            &mut |_| Ok(secret.next().expect("secret input should not be used")),
            &mut |message| errors.push(message.to_string()),
        )
        .expect("prompt should succeed");

        assert_eq!(env.get("AMBER_CONFIG_COUNT"), Some(&"42".to_string()));
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("invalid value for config.count"));
    }

    #[test]
    fn prompt_for_missing_inputs_preserves_large_single_line_visible_values() {
        let interface = RunInterface {
            root_inputs: vec![RootInputSpec {
                path: "auth_json".to_string(),
                env_var: "AMBER_CONFIG_AUTH_JSON".to_string(),
                required: true,
                secret: false,
            }],
            ..RunInterface::default()
        };
        let root_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "auth_json": { "type": "string" }
            },
            "required": ["auth_json"]
        });
        let large = format!("{{\"tokens\":\"{}\"}}", "x".repeat(8192));
        let mut env = BTreeMap::new();
        let mut visible = vec![large.clone()].into_iter();
        let mut secret = std::iter::empty::<String>();
        let mut errors = Vec::new();

        prompt_for_missing_inputs_with(
            &mut env,
            &interface,
            Some(&root_schema),
            &mut |_| Ok(visible.next().expect("visible input should exist")),
            &mut |_| Ok(secret.next().expect("secret input should not be used")),
            &mut |message| errors.push(message.to_string()),
        )
        .expect("prompt should succeed");

        assert_eq!(env.get("AMBER_CONFIG_AUTH_JSON"), Some(&large));
        assert!(
            errors.is_empty(),
            "prompt should not reject large single-line visible input"
        );
    }

    #[test]
    fn prompt_for_missing_inputs_preserves_large_single_line_secret_values() {
        let interface = RunInterface {
            root_inputs: vec![RootInputSpec {
                path: "auth_json".to_string(),
                env_var: "AMBER_CONFIG_AUTH_JSON".to_string(),
                required: true,
                secret: true,
            }],
            ..RunInterface::default()
        };
        let root_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "auth_json": { "type": "string" }
            },
            "required": ["auth_json"]
        });
        let large = format!("{{\"tokens\":\"{}\"}}", "x".repeat(8192));
        let mut env = BTreeMap::new();
        let mut visible = std::iter::empty::<String>();
        let mut secret = vec![large.clone()].into_iter();
        let mut errors = Vec::new();

        prompt_for_missing_inputs_with(
            &mut env,
            &interface,
            Some(&root_schema),
            &mut |_| Ok(visible.next().expect("visible input should not be used")),
            &mut |_| Ok(secret.next().expect("secret input should exist")),
            &mut |message| errors.push(message.to_string()),
        )
        .expect("prompt should succeed");

        assert_eq!(env.get("AMBER_CONFIG_AUTH_JSON"), Some(&large));
        assert!(
            errors.is_empty(),
            "prompt should not reject large single-line secret input"
        );
    }

    #[test]
    fn strip_trailing_newline_preserves_other_whitespace() {
        assert_eq!(strip_trailing_newline("value\n".to_string()), "value");
        assert_eq!(strip_trailing_newline("value\r\n".to_string()), "value");
        assert_eq!(
            strip_trailing_newline("  value \r\n".to_string()),
            "  value "
        );
    }

    #[test]
    fn render_run_env_file_mentions_file_backed_root_inputs() {
        let interface = RunInterface {
            root_inputs: vec![RootInputSpec {
                path: "auth_json".to_string(),
                env_var: "AMBER_CONFIG_AUTH_JSON".to_string(),
                required: true,
                secret: true,
            }],
            ..RunInterface::default()
        };

        let rendered = render_run_env_file(&interface);
        assert!(rendered.contains("AMBER_CONFIG_FILE_"));
        assert!(rendered.contains("AMBER_CONFIG_AUTH_JSON"));
    }
}
