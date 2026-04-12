use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs, io,
    io::Write as _,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use amber_compiler::run_plan::RunPlan;
use amber_config::{self as config, CONFIG_ENV_PREFIX};
use amber_manifest::{CapabilityKind, CapabilityTransport};
use crossterm::{
    cursor::{MoveToColumn, MoveToPreviousLine},
    event::{
        self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
        KeyModifiers,
    },
    execute, queue,
    style::{Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor},
    terminal::{self, Clear, ClearType},
};
use miette::{Context as _, Diagnostic, IntoDiagnostic as _, Result};
use serde_json::Value;
use url::Url;

use crate::site_proxy_metadata::load_site_proxy_metadata;

const GENERATED_ENV_SAMPLE_FILENAME: &str = "env.example";
const PROJECT_ENV_FILENAME: &str = ".env";
pub(crate) const CONFIG_FILE_ENV_PREFIX: &str = "AMBER_CONFIG_FILE_";
const ROOT_PROMPT_SUGGESTION_LIMIT: usize = 8;
const ROOT_PROMPT_LITERAL_PREVIEW_LIMIT: usize = 96;

#[derive(Debug, Diagnostic)]
pub(crate) struct InteractiveInputCancelled;

impl std::fmt::Display for InteractiveInputCancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("interactive input cancelled")
    }
}

impl std::error::Error for InteractiveInputCancelled {}

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

#[derive(Clone, Debug, PartialEq, Eq)]
enum PromptedRootInput {
    Literal(String),
    File { raw_path: String, from_sigil: bool },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct RunInputLayer {
    root_inputs: BTreeMap<String, RootInputSource>,
    external_slots: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct RootPromptMeta {
    description: Option<String>,
    type_label: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PromptBadge<'a> {
    label: std::borrow::Cow<'a, str>,
    color: Color,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PromptPrefix<'a> {
    label: &'a str,
    prefix_color: Color,
    name_color: Color,
}

trait PromptDriver {
    fn prompt_root(
        &mut self,
        input: &RootInputSpec,
        meta: &RootPromptMeta,
    ) -> Result<PromptedRootInput>;
    fn prompt_external_slot(&mut self, slot: &ExternalSlotSpec) -> Result<String>;
    fn print_error(&mut self, message: &str);
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
    resolve_input_file_path_with_home(base_dir, raw, home_dir().as_deref())
}

fn resolve_input_file_path_with_home(
    base_dir: &Path,
    raw: &str,
    home_dir: Option<&Path>,
) -> PathBuf {
    if let Some(path) = expand_tilde_path(raw, home_dir) {
        return path;
    }
    let path = Path::new(raw);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
}

fn expand_tilde_path(raw: &str, home_dir: Option<&Path>) -> Option<PathBuf> {
    let home_dir = home_dir?;
    if raw == "~" {
        return Some(home_dir.to_path_buf());
    }
    let rest = raw.strip_prefix("~/")?;
    Some(home_dir.join(rest))
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME").map(PathBuf::from)
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
    prompt_optional_external_slots: bool,
) -> Result<()> {
    let cwd = env::current_dir().into_diagnostic()?;
    let home_dir = home_dir();
    let mut driver = InteractivePromptDriver {
        cwd: cwd.clone(),
        home_dir: home_dir.clone(),
        printed_root_prompt_note: false,
    };
    prompt_for_missing_inputs_with(
        env,
        interface,
        root_schema,
        prompt_optional_external_slots,
        &cwd,
        home_dir.as_deref(),
        &mut driver,
    )
}

pub(crate) fn is_interactive_input_cancelled(err: &miette::Report) -> bool {
    err.downcast_ref::<InteractiveInputCancelled>().is_some()
}

fn prompt_for_missing_inputs_with(
    env: &mut BTreeMap<String, String>,
    interface: &RunInterface,
    root_schema: Option<&Value>,
    prompt_optional_external_slots: bool,
    cwd: &Path,
    home_dir: Option<&Path>,
    driver: &mut impl PromptDriver,
) -> Result<()> {
    for input in &interface.root_inputs {
        if !input.required || !root_env_var_missing(env, &input.env_var) {
            continue;
        }
        let meta = root_prompt_meta(root_schema, &input.path);
        loop {
            let prompted = driver.prompt_root(input, &meta)?;
            let value = match resolve_prompted_root_input_value(input, prompted, cwd, home_dir) {
                Ok(value) => value,
                Err(err) => {
                    driver.print_error(&err.to_string());
                    continue;
                }
            };
            if value.is_empty() {
                driver.print_error(&format!("config.{} must not be empty", input.path));
                continue;
            }
            if let Some(schema) = root_schema
                && let Err(err) = validate_root_input_value(schema, &input.path, &value)
            {
                driver.print_error(&format!("invalid value for config.{}: {err}", input.path));
                continue;
            }
            env.insert(input.env_var.clone(), value);
            break;
        }
    }

    for slot in promptable_external_slots(env, interface, prompt_optional_external_slots) {
        loop {
            let value = driver.prompt_external_slot(slot)?;
            let trimmed = value.trim();
            if trimmed.is_empty() {
                if slot.required {
                    driver.print_error(&format!("slot.{} must not be empty", slot.name));
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
                    driver.print_error(&err.to_string());
                }
            }
        }
    }

    Ok(())
}

pub(crate) fn promptable_external_slots<'a>(
    env: &BTreeMap<String, String>,
    interface: &'a RunInterface,
    include_optional: bool,
) -> Vec<&'a ExternalSlotSpec> {
    interface
        .external_slots
        .iter()
        .filter(|slot| env_var_missing(env, &slot.env_var) && (include_optional || slot.required))
        .collect()
}

struct InteractivePromptDriver {
    cwd: PathBuf,
    home_dir: Option<PathBuf>,
    printed_root_prompt_note: bool,
}

impl PromptDriver for InteractivePromptDriver {
    fn prompt_root(
        &mut self,
        input: &RootInputSpec,
        meta: &RootPromptMeta,
    ) -> Result<PromptedRootInput> {
        if !self.printed_root_prompt_note {
            let mut stderr = io::stderr();
            execute!(
                stderr,
                SetForegroundColor(Color::DarkGrey),
                Print("Enter each value directly, or use @file. Use @@ for a literal leading @."),
                ResetColor,
                Print("\n")
            )
            .into_diagnostic()?;
            self.printed_root_prompt_note = true;
        }
        prompt_root_input(input, meta, &self.cwd, self.home_dir.as_deref())
    }

    fn prompt_external_slot(&mut self, slot: &ExternalSlotSpec) -> Result<String> {
        prompt_external_slot_input(slot)
    }

    fn print_error(&mut self, message: &str) {
        eprintln!("\r{message}");
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RootPromptBuffer {
    raw: String,
    secret: bool,
    completion_cycle: Option<CompletionCycle>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompletionCycle {
    suggestions: Vec<String>,
    selected_index: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PromptSuggestion {
    value: String,
    selected: bool,
}

impl RootPromptBuffer {
    fn new(secret: bool) -> Self {
        Self {
            raw: String::new(),
            secret,
            completion_cycle: None,
        }
    }

    fn insert_char(&mut self, ch: char) {
        self.clear_completion_cycle();
        self.raw.push(ch);
    }

    fn insert_str(&mut self, text: &str) {
        self.clear_completion_cycle();
        self.raw.push_str(text);
    }

    fn pop_char(&mut self) {
        self.clear_completion_cycle();
        self.raw.pop();
    }

    fn is_file_mode(&self) -> bool {
        self.raw.starts_with('@') && !self.raw.starts_with("@@")
    }

    fn parse(&self) -> PromptedRootInput {
        parse_interactive_root_input(&self.raw)
    }

    fn display(&self) -> String {
        if self.secret && !self.is_file_mode() {
            return "*".repeat(self.literal_display_len());
        }
        if !self.is_file_mode()
            && (self.raw.contains('\n')
                || self.raw.contains('\r')
                || self.raw.chars().count() > ROOT_PROMPT_LITERAL_PREVIEW_LIMIT)
        {
            return format!("<{} bytes>", self.raw.len());
        }
        self.raw.clone()
    }

    fn literal_display_len(&self) -> usize {
        if self.raw.starts_with("@@") {
            self.raw.chars().count().saturating_sub(1)
        } else {
            self.raw.chars().count()
        }
    }

    fn prompt_suggestions(
        &self,
        base_dir: &Path,
        home_dir: Option<&Path>,
    ) -> Vec<PromptSuggestion> {
        if let Some(cycle) = &self.completion_cycle {
            return cycle
                .suggestions
                .iter()
                .enumerate()
                .map(|(index, suggestion)| PromptSuggestion {
                    value: suggestion.clone(),
                    selected: cycle.selected_index == Some(index),
                })
                .collect();
        }
        if !self.is_file_mode() {
            return Vec::new();
        }
        collect_path_suggestions(&self.raw, base_dir, home_dir)
            .into_iter()
            .take(ROOT_PROMPT_SUGGESTION_LIMIT)
            .map(|suggestion| PromptSuggestion {
                value: suggestion,
                selected: false,
            })
            .collect()
    }

    fn apply_completion(&mut self, base_dir: &Path, home_dir: Option<&Path>) -> bool {
        if let Some(cycle) = &mut self.completion_cycle {
            if cycle.suggestions.is_empty() {
                self.clear_completion_cycle();
                return false;
            }
            let next_index = match cycle.selected_index {
                Some(index) => (index + 1) % cycle.suggestions.len(),
                None => 0,
            };
            cycle.selected_index = Some(next_index);
            self.raw = cycle.suggestions[next_index].clone();
            return true;
        }

        if !self.is_file_mode() {
            return false;
        }

        let suggestions = collect_path_suggestions(&self.raw, base_dir, home_dir)
            .into_iter()
            .take(ROOT_PROMPT_SUGGESTION_LIMIT)
            .collect::<Vec<_>>();
        let completion = completion_from_suggestions(&self.raw, &suggestions)
            .or_else(|| suggestions.first().cloned());
        let Some(completion) = completion else {
            return false;
        };
        if suggestions.len() > 1 {
            let selected_index = suggestions
                .iter()
                .position(|suggestion| suggestion == &completion);
            self.completion_cycle = Some(CompletionCycle {
                suggestions,
                selected_index,
            });
        }
        self.raw = completion;
        true
    }

    fn clear(&mut self) {
        self.clear_completion_cycle();
        self.raw.clear();
    }

    fn clear_completion_cycle(&mut self) {
        self.completion_cycle = None;
    }
}

fn parse_interactive_root_input(raw: &str) -> PromptedRootInput {
    if let Some(rest) = raw.strip_prefix("@@") {
        return PromptedRootInput::Literal(format!("@{rest}"));
    }
    if let Some(raw_path) = raw.strip_prefix('@') {
        return PromptedRootInput::File {
            raw_path: raw_path.to_string(),
            from_sigil: true,
        };
    }
    PromptedRootInput::Literal(raw.to_string())
}

fn resolve_prompted_root_input_value(
    input: &RootInputSpec,
    prompted: PromptedRootInput,
    cwd: &Path,
    home_dir: Option<&Path>,
) -> Result<String> {
    match prompted {
        PromptedRootInput::Literal(value) => Ok(value),
        PromptedRootInput::File {
            raw_path,
            from_sigil,
        } => {
            if raw_path.is_empty() {
                return Err(miette::miette!(
                    "config.{} file path must not be empty",
                    input.path
                ));
            }
            let resolved_path = resolve_input_file_path_with_home(cwd, &raw_path, home_dir);
            resolve_root_input_source(&input.path, &RootInputSource::File(resolved_path)).map_err(
                |err| {
                    if from_sigil {
                        err.wrap_err("use `@@...` to enter a literal value starting with `@`")
                    } else {
                        err
                    }
                },
            )
        }
    }
}

#[derive(Clone, Debug)]
struct DecodedPathInput<'a> {
    raw_path: std::borrow::Cow<'a, str>,
    rendered_prefix: &'static str,
}

fn decode_path_input(input: &str) -> Option<DecodedPathInput<'_>> {
    if input.starts_with("@@") {
        None
    } else {
        input.strip_prefix('@').map(|rest| DecodedPathInput {
            raw_path: std::borrow::Cow::Borrowed(rest),
            rendered_prefix: "@",
        })
    }
}

fn collect_path_suggestions(input: &str, base_dir: &Path, home_dir: Option<&Path>) -> Vec<String> {
    let Some(decoded) = decode_path_input(input) else {
        return Vec::new();
    };
    list_display_path_suggestions(decoded.raw_path.as_ref(), base_dir, home_dir)
        .into_iter()
        .map(|suggestion| format!("{}{}", decoded.rendered_prefix, suggestion))
        .collect()
}

fn prompt_root_input(
    input: &RootInputSpec,
    meta: &RootPromptMeta,
    cwd: &Path,
    home_dir: Option<&Path>,
) -> Result<PromptedRootInput> {
    let mut state = RootPromptBuffer::new(input.secret);
    let mut stderr = io::stderr();
    print_root_prompt_context(&mut stderr, input, meta)?;
    let raw_mode = RawTerminalGuard::new()?;

    loop {
        let suggestions = state.prompt_suggestions(cwd, home_dir);
        let visible_suggestions = visible_prompt_suggestions(&state.raw, &suggestions);
        render_root_prompt(&mut stderr, &state, &visible_suggestions)?;

        let event = event::read().into_diagnostic()?;
        match event {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                match handle_root_prompt_key(&mut state, key, cwd, home_dir) {
                    Ok(true) => {
                        render_root_prompt(&mut stderr, &state, &[])?;
                        stderr.write_all(b"\r\n").into_diagnostic()?;
                        stderr.flush().into_diagnostic()?;
                        drop(raw_mode);
                        return Ok(state.parse());
                    }
                    Ok(false) => {}
                    Err(err) => {
                        stderr.write_all(b"\r\n").into_diagnostic()?;
                        stderr.flush().into_diagnostic()?;
                        drop(raw_mode);
                        return Err(err);
                    }
                }
            }
            Event::Paste(text) => state.insert_str(&text),
            Event::Resize(_, _) => {}
            _ => {}
        }
    }
}

fn handle_root_prompt_key(
    state: &mut RootPromptBuffer,
    key: KeyEvent,
    cwd: &Path,
    home_dir: Option<&Path>,
) -> Result<bool> {
    match key.code {
        KeyCode::Enter => Ok(true),
        KeyCode::Backspace => {
            state.pop_char();
            Ok(false)
        }
        KeyCode::Tab => {
            state.apply_completion(cwd, home_dir);
            Ok(false)
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            state.clear();
            Ok(false)
        }
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            Err(InteractiveInputCancelled.into())
        }
        KeyCode::Char('d')
            if key.modifiers.contains(KeyModifiers::CONTROL) && state.raw.is_empty() =>
        {
            Err(InteractiveInputCancelled.into())
        }
        KeyCode::Char(ch) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            state.insert_char(ch);
            Ok(false)
        }
        _ => Ok(false),
    }
}

fn render_root_prompt(
    writer: &mut impl io::Write,
    state: &RootPromptBuffer,
    suggestions: &[PromptSuggestion],
) -> Result<()> {
    queue!(
        writer,
        MoveToColumn(0),
        Clear(ClearType::FromCursorDown),
        SetForegroundColor(Color::Cyan),
        SetAttribute(Attribute::Bold),
        Print("> "),
        SetAttribute(Attribute::Reset),
        ResetColor,
        Print(state.display())
    )
    .into_diagnostic()?;
    for suggestion in suggestions {
        if suggestion.selected {
            queue!(
                writer,
                Print("\r\n"),
                SetForegroundColor(Color::Cyan),
                SetAttribute(Attribute::Bold),
                Print("> "),
                Print(&suggestion.value),
                SetAttribute(Attribute::Reset),
                ResetColor
            )
            .into_diagnostic()?;
        } else {
            queue!(writer, Print("\r\n  "), Print(&suggestion.value)).into_diagnostic()?;
        }
    }
    if !suggestions.is_empty() {
        queue!(writer, MoveToPreviousLine(suggestions.len() as u16)).into_diagnostic()?;
    }
    queue!(
        writer,
        MoveToColumn((2 + state.display().chars().count()) as u16)
    )
    .into_diagnostic()?;
    writer.flush().into_diagnostic()
}

fn print_root_prompt_context(
    writer: &mut impl io::Write,
    input: &RootInputSpec,
    meta: &RootPromptMeta,
) -> Result<()> {
    let mut badges = Vec::with_capacity(2);
    if input.secret {
        badges.push(PromptBadge {
            label: "secret".into(),
            color: Color::DarkYellow,
        });
    }
    if let Some(type_label) = meta.type_label.as_deref() {
        badges.push(PromptBadge {
            label: type_label.into(),
            color: Color::DarkGrey,
        });
    }
    print_prompt_context(
        writer,
        PromptPrefix {
            label: "config.",
            prefix_color: Color::DarkCyan,
            name_color: Color::Cyan,
        },
        &input.path,
        &badges,
        meta.description.as_deref(),
    )
}

fn visible_prompt_suggestions(
    current_input: &str,
    suggestions: &[PromptSuggestion],
) -> Vec<PromptSuggestion> {
    if matches!(suggestions, [only] if only.value == current_input) {
        Vec::new()
    } else {
        suggestions.to_vec()
    }
}

fn wrap_prompt_description(description: Option<&str>) -> Vec<String> {
    let Some(description) = description
        .map(str::trim)
        .filter(|description| !description.is_empty())
    else {
        return Vec::new();
    };
    let width = terminal::size()
        .ok()
        .map(|(cols, _)| cols as usize)
        .unwrap_or(100)
        .saturating_sub(2)
        .max(24);
    wrap_text(description, width)
}

fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();

    for paragraph in text.lines() {
        let paragraph = paragraph.trim();
        if paragraph.is_empty() {
            if !current.is_empty() {
                lines.push(std::mem::take(&mut current));
            }
            continue;
        }
        for word in paragraph.split_whitespace() {
            let next_len = if current.is_empty() {
                word.len()
            } else {
                current.len() + 1 + word.len()
            };
            if !current.is_empty() && next_len > width {
                lines.push(std::mem::take(&mut current));
            }
            if !current.is_empty() {
                current.push(' ');
            }
            current.push_str(word);
        }
        if !current.is_empty() {
            lines.push(std::mem::take(&mut current));
        }
    }

    lines
}

fn root_prompt_meta(root_schema: Option<&Value>, path: &str) -> RootPromptMeta {
    let Some(schema) = root_schema else {
        return RootPromptMeta::default();
    };
    let Ok(leaf_schema) = config::schema_lookup_ref(schema, path) else {
        return RootPromptMeta::default();
    };
    RootPromptMeta {
        description: leaf_schema
            .get("description")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        type_label: schema_type_label(leaf_schema),
    }
}

fn schema_type_label(schema: &Value) -> Option<String> {
    let ty = schema.get("type")?;
    if let Some(single) = ty.as_str() {
        return Some(single.to_string());
    }
    let types = ty.as_array()?;
    let mut labels = Vec::new();
    let mut saw_null = false;
    for value in types {
        let Some(label) = value.as_str() else {
            continue;
        };
        if label == "null" {
            saw_null = true;
        } else {
            labels.push(label);
        }
    }
    labels.sort_unstable();
    labels.dedup();
    match labels.as_slice() {
        [] if saw_null => Some("null".to_string()),
        [single] if saw_null => Some(format!("{single}?")),
        [single] => Some((*single).to_string()),
        _ => Some("value".to_string()),
    }
}

fn prompt_external_slot_input(slot: &ExternalSlotSpec) -> Result<String> {
    let mut badges = Vec::with_capacity(2);
    badges.push(PromptBadge {
        label: slot.kind.to_string().into(),
        color: Color::DarkGrey,
    });
    if !slot.required {
        badges.push(PromptBadge {
            label: "optional".into(),
            color: Color::DarkGrey,
        });
    }

    let mut stderr = io::stderr();
    print_prompt_context(
        &mut stderr,
        PromptPrefix {
            label: "slots.",
            prefix_color: Color::DarkGreen,
            name_color: Color::Green,
        },
        &slot.name,
        &badges,
        None,
    )?;
    prompt_visible_line()
}

fn print_prompt_context(
    writer: &mut impl io::Write,
    prefix: PromptPrefix<'_>,
    name: &str,
    badges: &[PromptBadge<'_>],
    description: Option<&str>,
) -> Result<()> {
    queue!(
        writer,
        MoveToColumn(0),
        SetForegroundColor(prefix.prefix_color),
        SetAttribute(Attribute::Dim),
        Print(prefix.label),
        SetAttribute(Attribute::Reset),
        ResetColor,
        SetForegroundColor(prefix.name_color),
        SetAttribute(Attribute::Bold),
        Print(name),
        SetAttribute(Attribute::Reset),
        ResetColor
    )
    .into_diagnostic()?;
    for badge in badges {
        queue!(
            writer,
            Print(" "),
            SetForegroundColor(badge.color),
            Print(format!("[{}]", badge.label)),
            ResetColor
        )
        .into_diagnostic()?;
    }
    for line in wrap_prompt_description(description) {
        queue!(
            writer,
            Print("\r\n  "),
            SetForegroundColor(Color::DarkGrey),
            SetAttribute(Attribute::Italic),
            Print(line),
            SetAttribute(Attribute::Reset),
            ResetColor
        )
        .into_diagnostic()?;
    }
    queue!(writer, Print("\r\n")).into_diagnostic()?;
    writer.flush().into_diagnostic()
}

fn prompt_visible_line() -> Result<String> {
    let mut stderr = io::stderr();
    execute!(
        stderr,
        MoveToColumn(0),
        SetForegroundColor(Color::Cyan),
        SetAttribute(Attribute::Bold),
        Print("> "),
        SetAttribute(Attribute::Reset),
        ResetColor
    )
    .into_diagnostic()?;
    stderr.flush().into_diagnostic()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line).into_diagnostic()?;
    stderr.write_all(b"\r").into_diagnostic()?;
    stderr.flush().into_diagnostic()?;
    while matches!(line.as_bytes().last(), Some(b'\n' | b'\r')) {
        line.pop();
    }
    Ok(line)
}

struct RawTerminalGuard;

impl RawTerminalGuard {
    fn new() -> Result<Self> {
        terminal::enable_raw_mode().into_diagnostic()?;
        execute!(io::stderr(), EnableBracketedPaste).into_diagnostic()?;
        Ok(Self)
    }
}

impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(io::stderr(), DisableBracketedPaste);
        let _ = terminal::disable_raw_mode();
    }
}

fn completion_from_suggestions(input: &str, suggestions: &[String]) -> Option<String> {
    let suggestion = if suggestions.len() == 1 {
        suggestions.first().cloned()
    } else {
        let prefix = longest_common_prefix(suggestions);
        (prefix.len() > input.len()).then_some(prefix)
    }?;
    (suggestion != input).then_some(suggestion)
}

fn list_display_path_suggestions(
    raw: &str,
    base_dir: &Path,
    home_dir: Option<&Path>,
) -> Vec<String> {
    let Some((display_dir, basename, resolved_dir)) =
        resolve_display_path_context(raw, base_dir, home_dir)
    else {
        return Vec::new();
    };

    let mut matches = fs::read_dir(&resolved_dir)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(std::result::Result::ok))
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy().into_owned();
            if !basename.is_empty() && !name.starts_with(&basename) {
                return None;
            }
            if !basename.starts_with('.') && name.starts_with('.') {
                return None;
            }
            let is_dir = entry.path().is_dir();
            let suffix = if is_dir {
                std::path::MAIN_SEPARATOR.to_string()
            } else {
                String::new()
            };
            Some((!is_dir, format!("{display_dir}{name}{suffix}")))
        })
        .collect::<Vec<_>>();
    matches.sort();
    matches.dedup();
    matches.into_iter().map(|(_, display)| display).collect()
}

fn resolve_display_path_context(
    raw: &str,
    base_dir: &Path,
    home_dir: Option<&Path>,
) -> Option<(String, String, PathBuf)> {
    if raw == "~" {
        let home_dir = home_dir?;
        return Some(("~/".to_string(), String::new(), home_dir.to_path_buf()));
    }
    if raw.starts_with('~') && !raw.starts_with("~/") {
        return None;
    }

    let (display_dir, basename, resolved_dir) = if let Some(suffix) = raw.strip_prefix("~/") {
        let home_dir = home_dir?;
        let (display_suffix_dir, basename) = split_display_dir_and_basename(suffix);
        let resolved_dir = if display_suffix_dir.is_empty() {
            home_dir.to_path_buf()
        } else {
            home_dir.join(trim_trailing_separators(display_suffix_dir))
        };
        (
            format!("~/{display_suffix_dir}"),
            basename.to_string(),
            resolved_dir,
        )
    } else {
        let (display_dir, basename) = split_display_dir_and_basename(raw);
        let resolved_dir = if display_dir.is_empty() {
            base_dir.to_path_buf()
        } else {
            resolve_display_dir(base_dir, display_dir)
        };
        (display_dir.to_string(), basename.to_string(), resolved_dir)
    };

    Some((display_dir, basename, resolved_dir))
}

fn split_display_dir_and_basename(raw: &str) -> (&str, &str) {
    raw.rfind(std::path::is_separator)
        .map(|index| raw.split_at(index + 1))
        .unwrap_or(("", raw))
}

fn trim_trailing_separators(raw: &str) -> &str {
    raw.trim_end_matches(std::path::is_separator)
}

fn resolve_display_dir(base_dir: &Path, display_dir: &str) -> PathBuf {
    let trimmed = trim_trailing_separators(display_dir);
    if trimmed.is_empty() && display_dir.starts_with(std::path::MAIN_SEPARATOR) {
        PathBuf::from(std::path::MAIN_SEPARATOR.to_string())
    } else {
        let path = Path::new(trimmed);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            base_dir.join(path)
        }
    }
}

fn longest_common_prefix(values: &[String]) -> String {
    let Some(first) = values.first() else {
        return String::new();
    };
    let mut prefix = first.clone();
    for value in &values[1..] {
        let shared_len = prefix
            .chars()
            .zip(value.chars())
            .take_while(|(left, right)| left == right)
            .count();
        prefix = prefix.chars().take(shared_len).collect();
        if prefix.is_empty() {
            break;
        }
    }
    prefix
}

pub(crate) fn render_run_env_file(interface: &RunInterface, root_schema: Option<&Value>) -> String {
    let mut out = String::new();
    let mut root_inputs = interface.root_inputs.iter().collect::<Vec<_>>();
    root_inputs.sort_by(|left, right| {
        right
            .required
            .cmp(&left.required)
            .then_with(|| left.path.cmp(&right.path))
    });
    let mut external_slots = interface.external_slots.iter().collect::<Vec<_>>();
    external_slots.sort_by(|left, right| {
        right
            .required
            .cmp(&left.required)
            .then_with(|| left.name.cmp(&right.name))
    });

    out.push_str("# Runtime inputs for `amber run --env-file`.\n");
    out.push_str(
        "# Fill in the values you need, then pass this file back to `amber run --env-file`.\n",
    );
    if let Some(example) = root_inputs.first() {
        let file_var = config_file_env_var_for_path(&example.path)
            .expect("root input path should map to a config file env var");
        out.push_str(&format!(
            "# For any root config input below, you can replace `AMBER_CONFIG_` with \
             `AMBER_CONFIG_FILE_` to load the value from a UTF-8 file instead, for example \
             `{file_var}=./value.txt`.\n",
        ));
    }

    if root_inputs.is_empty() && external_slots.is_empty() {
        out.push_str("# No env-based runtime inputs are required for this run target.\n");
        return out;
    }

    if !root_inputs.is_empty() {
        out.push_str("\n# Root config inputs\n");
        for input in root_inputs {
            if let Some(description) = root_input_description(root_schema, &input.path) {
                for line in wrap_text(description, 96) {
                    out.push_str(&format!("# {line}\n"));
                }
            }
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

    if !external_slots.is_empty() {
        out.push_str("\n# External slot URLs\n");
        for slot in external_slots {
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

fn root_input_description<'a>(root_schema: Option<&'a Value>, path: &str) -> Option<&'a str> {
    let schema = root_schema?;
    config::schema_lookup_ref(schema, path)
        .ok()?
        .get("description")?
        .as_str()
        .map(str::trim)
        .filter(|description| !description.is_empty())
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
    key.starts_with(CONFIG_ENV_PREFIX)
        || key.starts_with(CONFIG_FILE_ENV_PREFIX)
        || key.starts_with("AMBER_EXTERNAL_SLOT_")
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
    use std::collections::VecDeque;

    use amber_compiler::{
        mesh::PROXY_METADATA_FILENAME,
        run_plan::{
            ActiveSiteCapabilities, PlacementDefaults, RunLink, RunPlan, RunSitePlan,
            SiteDefinition, SiteKind,
        },
    };
    use amber_scenario::{SCENARIO_IR_SCHEMA, SCENARIO_IR_VERSION, ScenarioIr};

    use super::*;

    #[derive(Default)]
    struct TestPromptDriver {
        root_inputs: VecDeque<PromptedRootInput>,
        slot_values: VecDeque<String>,
        errors: Vec<String>,
    }

    impl PromptDriver for TestPromptDriver {
        fn prompt_root(
            &mut self,
            _input: &RootInputSpec,
            _meta: &RootPromptMeta,
        ) -> Result<PromptedRootInput> {
            Ok(self
                .root_inputs
                .pop_front()
                .expect("root input should exist"))
        }

        fn prompt_external_slot(&mut self, _slot: &ExternalSlotSpec) -> Result<String> {
            Ok(self
                .slot_values
                .pop_front()
                .expect("slot value should exist"))
        }

        fn print_error(&mut self, message: &str) {
            self.errors.push(message.to_string());
        }
    }

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
    fn promptable_external_slots_can_include_optional_slots() {
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
            promptable_external_slots(&BTreeMap::new(), &interface, true),
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
    fn parse_interactive_root_input_understands_file_sigils() {
        assert_eq!(
            parse_interactive_root_input("demo"),
            PromptedRootInput::Literal("demo".to_string())
        );
        assert_eq!(
            parse_interactive_root_input("@config.json"),
            PromptedRootInput::File {
                raw_path: "config.json".to_string(),
                from_sigil: true,
            }
        );
        assert_eq!(
            parse_interactive_root_input("@"),
            PromptedRootInput::File {
                raw_path: String::new(),
                from_sigil: true,
            }
        );
        assert_eq!(
            parse_interactive_root_input("@@config.json"),
            PromptedRootInput::Literal("@config.json".to_string())
        );
    }

    #[test]
    fn root_prompt_meta_reads_leaf_schema_description_and_type() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "auth_json": {
                    "type": "string",
                    "description": "JSON auth payload forwarded to the child program."
                }
            }
        });

        assert_eq!(
            root_prompt_meta(Some(&schema), "auth_json"),
            RootPromptMeta {
                description: Some("JSON auth payload forwarded to the child program.".to_string()),
                type_label: Some("string".to_string()),
            }
        );
        assert_eq!(
            root_prompt_meta(Some(&schema), "missing"),
            RootPromptMeta::default()
        );
        assert_eq!(
            root_prompt_meta(None, "auth_json"),
            RootPromptMeta::default()
        );
    }

    #[test]
    fn prompt_context_uses_manifest_style_prefixes() {
        let mut root = Vec::new();
        print_root_prompt_context(
            &mut root,
            &RootInputSpec {
                path: "auth_json".to_string(),
                env_var: "AMBER_CONFIG_AUTH_JSON".to_string(),
                required: true,
                secret: true,
            },
            &RootPromptMeta {
                description: None,
                type_label: Some("string".to_string()),
            },
        )
        .expect("render root prompt");
        let root = String::from_utf8(root).expect("utf8");
        assert!(root.contains("config."));
        assert!(root.contains("auth_json"));
        assert!(root.contains("[secret]"));
        assert!(root.contains("[string]"));

        let mut slot = Vec::new();
        print_prompt_context(
            &mut slot,
            PromptPrefix {
                label: "slots.",
                prefix_color: Color::DarkGreen,
                name_color: Color::Green,
            },
            "catalog_api",
            &[PromptBadge {
                label: "http".into(),
                color: Color::DarkGrey,
            }],
            None,
        )
        .expect("render slot prompt");
        let slot = String::from_utf8(slot).expect("utf8");
        assert!(slot.contains("slots."));
        assert!(slot.contains("catalog_api"));
        assert!(slot.contains("[http]"));
    }

    #[test]
    fn schema_type_label_formats_nullable_scalars() {
        assert_eq!(
            schema_type_label(&serde_json::json!({ "type": ["null", "integer"] })),
            Some("integer?".to_string())
        );
        assert_eq!(
            schema_type_label(&serde_json::json!({ "type": ["string", "integer"] })),
            Some("value".to_string())
        );
    }

    #[test]
    fn visible_prompt_suggestions_hides_single_completion() {
        assert_eq!(
            visible_prompt_suggestions(
                "only",
                &[PromptSuggestion {
                    value: "only".to_string(),
                    selected: false,
                }]
            ),
            Vec::<PromptSuggestion>::new()
        );
        assert_eq!(
            visible_prompt_suggestions(
                "@~/Do",
                &[PromptSuggestion {
                    value: "@~/Documents/".to_string(),
                    selected: false,
                }]
            ),
            vec![PromptSuggestion {
                value: "@~/Documents/".to_string(),
                selected: false,
            }]
        );
        assert_eq!(
            visible_prompt_suggestions(
                "one",
                &[
                    PromptSuggestion {
                        value: "one".to_string(),
                        selected: false,
                    },
                    PromptSuggestion {
                        value: "two".to_string(),
                        selected: true,
                    },
                ]
            ),
            vec![
                PromptSuggestion {
                    value: "one".to_string(),
                    selected: false,
                },
                PromptSuggestion {
                    value: "two".to_string(),
                    selected: true,
                },
            ]
        );
    }

    #[test]
    fn wrap_text_wraps_words_without_dropping_content() {
        assert_eq!(
            wrap_text("one two three four", 9),
            vec![
                "one two".to_string(),
                "three".to_string(),
                "four".to_string()
            ]
        );
    }

    #[test]
    fn root_prompt_buffer_hides_secret_literals_but_shows_file_paths() {
        let mut secret = RootPromptBuffer::new(true);
        secret.insert_str("token");
        assert_eq!(secret.display(), "*****");

        let mut escaped = RootPromptBuffer::new(true);
        escaped.insert_str("@@token");
        assert_eq!(escaped.display(), "******");

        let mut file = RootPromptBuffer::new(true);
        file.insert_str("@config.json");
        assert_eq!(file.display(), "@config.json");
    }

    #[test]
    fn root_prompt_buffer_summarizes_large_visible_literals() {
        let mut visible = RootPromptBuffer::new(false);
        visible.insert_str(&"x".repeat(ROOT_PROMPT_LITERAL_PREVIEW_LIMIT + 1));
        assert_eq!(
            visible.display(),
            format!("<{} bytes>", ROOT_PROMPT_LITERAL_PREVIEW_LIMIT + 1)
        );
    }

    #[test]
    fn resolve_input_file_path_expands_home() {
        let base_dir = Path::new("/tmp/work");
        let home_dir = Path::new("/home/tester");
        assert_eq!(
            resolve_input_file_path_with_home(base_dir, "~/.config/token.txt", Some(home_dir)),
            Path::new("/home/tester/.config/token.txt")
        );
        assert_eq!(
            resolve_input_file_path_with_home(base_dir, "relative.txt", Some(home_dir)),
            Path::new("/tmp/work/relative.txt")
        );
    }

    #[test]
    fn collect_path_suggestions_handles_tilde_and_at_prefix() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().join("home");
        std::fs::create_dir_all(home.join("Documents")).expect("mkdir Documents");
        std::fs::create_dir_all(home.join("Downloads")).expect("mkdir Downloads");
        std::fs::write(home.join("@literal"), "").expect("write literal file");

        assert_eq!(
            collect_path_suggestions("@~/Doc", temp.path(), Some(home.as_path())),
            vec!["@~/Documents/".to_string()]
        );
        assert_eq!(
            collect_path_suggestions("@~", temp.path(), Some(home.as_path())),
            vec![
                "@~/Documents/".to_string(),
                "@~/Downloads/".to_string(),
                "@~/@literal".to_string()
            ]
        );
        assert_eq!(
            collect_path_suggestions("@@literal", temp.path(), Some(home.as_path())),
            Vec::<String>::new()
        );
    }

    #[test]
    fn completion_from_suggestions_uses_longest_common_prefix() {
        assert_eq!(
            completion_from_suggestions(
                "@~/Doc",
                &["@~/Documents/".to_string(), "@~/Documentary/".to_string()]
            ),
            Some("@~/Document".to_string())
        );
        assert_eq!(
            completion_from_suggestions("@~/Documents/", &["@~/Documents/".to_string()]),
            None
        );
    }

    #[test]
    fn root_prompt_buffer_tab_completion_updates_file_query() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().join("home");
        std::fs::create_dir_all(home.join("Documents")).expect("mkdir Documents");
        let mut prompt = RootPromptBuffer::new(false);
        prompt.insert_str("@~/Doc");

        assert!(prompt.apply_completion(temp.path(), Some(home.as_path())));
        assert_eq!(prompt.raw, "@~/Documents/".to_string());
    }

    #[test]
    fn root_prompt_buffer_tab_completion_cycles_file_suggestions() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().join("home");
        std::fs::create_dir_all(home.join("Documents")).expect("mkdir Documents");
        std::fs::create_dir_all(home.join("Downloads")).expect("mkdir Downloads");
        let mut prompt = RootPromptBuffer::new(false);
        prompt.insert_str("@~/Do");

        assert!(prompt.apply_completion(temp.path(), Some(home.as_path())));
        assert_eq!(prompt.raw, "@~/Documents/".to_string());
        assert_eq!(
            prompt.prompt_suggestions(temp.path(), Some(home.as_path())),
            vec![
                PromptSuggestion {
                    value: "@~/Documents/".to_string(),
                    selected: true,
                },
                PromptSuggestion {
                    value: "@~/Downloads/".to_string(),
                    selected: false,
                },
            ]
        );

        assert!(prompt.apply_completion(temp.path(), Some(home.as_path())));
        assert_eq!(prompt.raw, "@~/Downloads/".to_string());
        assert_eq!(
            prompt.prompt_suggestions(temp.path(), Some(home.as_path())),
            vec![
                PromptSuggestion {
                    value: "@~/Documents/".to_string(),
                    selected: false,
                },
                PromptSuggestion {
                    value: "@~/Downloads/".to_string(),
                    selected: true,
                },
            ]
        );

        assert!(prompt.apply_completion(temp.path(), Some(home.as_path())));
        assert_eq!(prompt.raw, "@~/Documents/".to_string());
    }

    #[test]
    fn root_prompt_buffer_editing_clears_completion_cycle() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().join("home");
        std::fs::create_dir_all(home.join("Documents")).expect("mkdir Documents");
        std::fs::create_dir_all(home.join("Downloads")).expect("mkdir Downloads");
        let mut prompt = RootPromptBuffer::new(false);
        prompt.insert_str("@~/Do");

        assert!(prompt.apply_completion(temp.path(), Some(home.as_path())));
        assert_eq!(prompt.raw, "@~/Documents/".to_string());
        assert_eq!(
            prompt.completion_cycle,
            Some(CompletionCycle {
                suggestions: vec!["@~/Documents/".to_string(), "@~/Downloads/".to_string()],
                selected_index: Some(0),
            })
        );

        prompt.pop_char();
        assert_eq!(prompt.completion_cycle, None);
        assert_eq!(prompt.raw, "@~/Documents".to_string());

        assert!(prompt.apply_completion(temp.path(), Some(home.as_path())));
        assert_eq!(prompt.raw, "@~/Documents/".to_string());
    }

    #[test]
    fn handle_root_prompt_key_ctrl_u_clears_the_current_input() {
        let mut prompt = RootPromptBuffer::new(false);
        prompt.insert_str("@~/Documents/token");

        handle_root_prompt_key(
            &mut prompt,
            KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL),
            Path::new("/tmp"),
            None,
        )
        .expect("ctrl-u should succeed");

        assert!(prompt.raw.is_empty());
    }

    #[test]
    fn handle_root_prompt_key_ctrl_c_returns_cancellation_signal() {
        let mut prompt = RootPromptBuffer::new(false);
        let err = handle_root_prompt_key(
            &mut prompt,
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
            Path::new("/tmp"),
            None,
        )
        .expect_err("ctrl-c should cancel interactive input");

        assert!(is_interactive_input_cancelled(&err));
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
        let cwd = tempfile::tempdir().expect("tempdir");
        let mut driver = TestPromptDriver {
            root_inputs: VecDeque::from([
                PromptedRootInput::Literal("abc".to_string()),
                PromptedRootInput::Literal("42".to_string()),
            ]),
            ..Default::default()
        };

        prompt_for_missing_inputs_with(
            &mut env,
            &interface,
            Some(&root_schema),
            true,
            cwd.path(),
            None,
            &mut driver,
        )
        .expect("prompt should succeed");

        assert_eq!(env.get("AMBER_CONFIG_COUNT"), Some(&"42".to_string()));
        assert_eq!(driver.errors.len(), 1);
        assert!(driver.errors[0].contains("invalid value for config.count"));
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
        let cwd = tempfile::tempdir().expect("tempdir");
        let mut driver = TestPromptDriver {
            root_inputs: VecDeque::from([PromptedRootInput::Literal(large.clone())]),
            ..Default::default()
        };

        prompt_for_missing_inputs_with(
            &mut env,
            &interface,
            Some(&root_schema),
            true,
            cwd.path(),
            None,
            &mut driver,
        )
        .expect("prompt should succeed");

        assert_eq!(env.get("AMBER_CONFIG_AUTH_JSON"), Some(&large));
        assert!(
            driver.errors.is_empty(),
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
        let cwd = tempfile::tempdir().expect("tempdir");
        let mut driver = TestPromptDriver {
            root_inputs: VecDeque::from([PromptedRootInput::Literal(large.clone())]),
            ..Default::default()
        };

        prompt_for_missing_inputs_with(
            &mut env,
            &interface,
            Some(&root_schema),
            true,
            cwd.path(),
            None,
            &mut driver,
        )
        .expect("prompt should succeed");

        assert_eq!(env.get("AMBER_CONFIG_AUTH_JSON"), Some(&large));
        assert!(
            driver.errors.is_empty(),
            "prompt should not reject large single-line secret input"
        );
    }

    #[test]
    fn prompt_for_missing_inputs_loads_non_secret_root_from_file_sigils() {
        let temp = tempfile::tempdir().expect("tempdir");
        let file_path = temp.path().join("auth.json");
        std::fs::write(&file_path, "demo-token").expect("write config file");
        let interface = RunInterface {
            root_inputs: vec![RootInputSpec {
                path: "auth_json".to_string(),
                env_var: "AMBER_CONFIG_AUTH_JSON".to_string(),
                required: true,
                secret: false,
            }],
            ..RunInterface::default()
        };
        let mut env = BTreeMap::new();
        let mut driver = TestPromptDriver {
            root_inputs: VecDeque::from([PromptedRootInput::File {
                raw_path: file_path
                    .file_name()
                    .expect("filename")
                    .to_string_lossy()
                    .into_owned(),
                from_sigil: true,
            }]),
            ..Default::default()
        };

        prompt_for_missing_inputs_with(
            &mut env,
            &interface,
            None,
            true,
            temp.path(),
            None,
            &mut driver,
        )
        .expect("prompt should succeed");

        assert_eq!(
            env.get("AMBER_CONFIG_AUTH_JSON"),
            Some(&"demo-token".to_string())
        );
    }

    #[test]
    fn prompt_for_missing_inputs_reprompts_after_bare_at_file_input() {
        let temp = tempfile::tempdir().expect("tempdir");
        let file_path = temp.path().join("api-key.txt");
        std::fs::write(&file_path, "demo-key").expect("write file");
        let interface = RunInterface {
            root_inputs: vec![RootInputSpec {
                path: "api_key".to_string(),
                env_var: "AMBER_CONFIG_API_KEY".to_string(),
                required: true,
                secret: false,
            }],
            ..RunInterface::default()
        };
        let mut env = BTreeMap::new();
        let mut driver = TestPromptDriver {
            root_inputs: VecDeque::from([
                PromptedRootInput::File {
                    raw_path: String::new(),
                    from_sigil: true,
                },
                PromptedRootInput::File {
                    raw_path: file_path
                        .file_name()
                        .expect("filename")
                        .to_string_lossy()
                        .into_owned(),
                    from_sigil: true,
                },
            ]),
            ..Default::default()
        };

        prompt_for_missing_inputs_with(
            &mut env,
            &interface,
            None,
            true,
            temp.path(),
            None,
            &mut driver,
        )
        .expect("prompt should succeed");

        assert_eq!(
            env.get("AMBER_CONFIG_API_KEY"),
            Some(&"demo-key".to_string())
        );
        assert_eq!(
            driver.errors,
            vec!["config.api_key file path must not be empty".to_string()]
        );
    }

    #[test]
    fn prompt_for_missing_inputs_loads_secret_root_from_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let file_path = temp.path().join("secret.txt");
        std::fs::write(&file_path, "shh").expect("write secret file");
        let interface = RunInterface {
            root_inputs: vec![RootInputSpec {
                path: "api_key".to_string(),
                env_var: "AMBER_CONFIG_API_KEY".to_string(),
                required: true,
                secret: true,
            }],
            ..RunInterface::default()
        };
        let mut env = BTreeMap::new();
        let mut driver = TestPromptDriver {
            root_inputs: VecDeque::from([PromptedRootInput::File {
                raw_path: file_path.to_string_lossy().into_owned(),
                from_sigil: true,
            }]),
            ..Default::default()
        };

        prompt_for_missing_inputs_with(
            &mut env,
            &interface,
            None,
            true,
            temp.path(),
            None,
            &mut driver,
        )
        .expect("prompt should succeed");

        assert_eq!(env.get("AMBER_CONFIG_API_KEY"), Some(&"shh".to_string()));
    }

    #[test]
    fn prompt_for_missing_inputs_reprompts_after_missing_file_and_mentions_escape() {
        let temp = tempfile::tempdir().expect("tempdir");
        let interface = RunInterface {
            root_inputs: vec![RootInputSpec {
                path: "name".to_string(),
                env_var: "AMBER_CONFIG_NAME".to_string(),
                required: true,
                secret: false,
            }],
            ..RunInterface::default()
        };
        let mut env = BTreeMap::new();
        let mut driver = TestPromptDriver {
            root_inputs: VecDeque::from([
                PromptedRootInput::File {
                    raw_path: "missing.txt".to_string(),
                    from_sigil: true,
                },
                PromptedRootInput::Literal("@missing.txt".to_string()),
            ]),
            ..Default::default()
        };

        prompt_for_missing_inputs_with(
            &mut env,
            &interface,
            None,
            true,
            temp.path(),
            None,
            &mut driver,
        )
        .expect("prompt should succeed");

        assert_eq!(
            env.get("AMBER_CONFIG_NAME"),
            Some(&"@missing.txt".to_string())
        );
        assert_eq!(driver.errors.len(), 1);
        assert!(driver.errors[0].contains("use `@@...`"));
    }

    #[test]
    fn prompt_for_missing_inputs_skips_optional_external_slots_when_disabled() {
        let interface = RunInterface {
            external_slots: vec![ExternalSlotSpec {
                name: "tool".to_string(),
                env_var: "AMBER_EXTERNAL_SLOT_TOOL_URL".to_string(),
                required: false,
                kind: CapabilityKind::Mcp,
            }],
            ..RunInterface::default()
        };
        let mut env = BTreeMap::new();
        let cwd = tempfile::tempdir().expect("tempdir");
        let mut driver = TestPromptDriver::default();

        prompt_for_missing_inputs_with(
            &mut env,
            &interface,
            None,
            false,
            cwd.path(),
            None,
            &mut driver,
        )
        .expect("prompt should succeed");

        assert!(env.is_empty());
        assert!(driver.slot_values.is_empty());
        assert!(driver.errors.is_empty());
    }

    #[test]
    fn prompt_for_missing_inputs_still_prompts_required_external_slots_when_optional_disabled() {
        let interface = RunInterface {
            external_slots: vec![ExternalSlotSpec {
                name: "catalog_api".to_string(),
                env_var: "AMBER_EXTERNAL_SLOT_CATALOG_API_URL".to_string(),
                required: true,
                kind: CapabilityKind::Http,
            }],
            ..RunInterface::default()
        };
        let mut env = BTreeMap::new();
        let cwd = tempfile::tempdir().expect("tempdir");
        let mut driver = TestPromptDriver {
            slot_values: VecDeque::from([String::from("http://127.0.0.1:8080")]),
            ..Default::default()
        };

        prompt_for_missing_inputs_with(
            &mut env,
            &interface,
            None,
            false,
            cwd.path(),
            None,
            &mut driver,
        )
        .expect("prompt should succeed");

        assert_eq!(
            env.get("AMBER_EXTERNAL_SLOT_CATALOG_API_URL"),
            Some(&"http://127.0.0.1:8080/".to_string())
        );
        assert!(driver.errors.is_empty());
    }

    #[test]
    fn is_run_env_key_includes_file_backed_root_inputs() {
        assert!(is_run_env_key("AMBER_CONFIG_FOO"));
        assert!(is_run_env_key("AMBER_CONFIG_FILE_FOO"));
        assert!(is_run_env_key("AMBER_EXTERNAL_SLOT_API_URL"));
        assert!(!is_run_env_key("PATH"));
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

        let rendered = render_run_env_file(&interface, None);
        assert!(rendered.contains("AMBER_CONFIG_FILE_"));
        assert!(rendered.contains("AMBER_CONFIG_AUTH_JSON"));
    }

    #[test]
    fn render_run_env_file_sorts_required_entries_before_optional_within_sections() {
        let interface = RunInterface {
            root_inputs: vec![
                RootInputSpec {
                    path: "workspace_agents_md".to_string(),
                    env_var: "AMBER_CONFIG_WORKSPACE_AGENTS_MD".to_string(),
                    required: false,
                    secret: false,
                },
                RootInputSpec {
                    path: "auth_json".to_string(),
                    env_var: "AMBER_CONFIG_AUTH_JSON".to_string(),
                    required: true,
                    secret: true,
                },
                RootInputSpec {
                    path: "model".to_string(),
                    env_var: "AMBER_CONFIG_MODEL".to_string(),
                    required: true,
                    secret: false,
                },
                RootInputSpec {
                    path: "agents_md".to_string(),
                    env_var: "AMBER_CONFIG_AGENTS_MD".to_string(),
                    required: false,
                    secret: false,
                },
            ],
            external_slots: vec![
                ExternalSlotSpec {
                    name: "tool".to_string(),
                    env_var: "AMBER_EXTERNAL_SLOT_TOOL_URL".to_string(),
                    required: false,
                    kind: CapabilityKind::Mcp,
                },
                ExternalSlotSpec {
                    name: "catalog_api".to_string(),
                    env_var: "AMBER_EXTERNAL_SLOT_CATALOG_API_URL".to_string(),
                    required: true,
                    kind: CapabilityKind::Http,
                },
            ],
            ..RunInterface::default()
        };

        let rendered = render_run_env_file(&interface, None);

        let auth_index = rendered
            .find("# required secret config.auth_json")
            .expect("required auth entry should exist");
        let model_index = rendered
            .find("# required config config.model")
            .expect("required model entry should exist");
        let agents_index = rendered
            .find("# optional config config.agents_md")
            .expect("optional agents entry should exist");
        let workspace_index = rendered
            .find("# optional config config.workspace_agents_md")
            .expect("optional workspace entry should exist");
        let catalog_slot_index = rendered
            .find("# required http slot catalog_api")
            .expect("required slot entry should exist");
        let tool_slot_index = rendered
            .find("# optional mcp slot tool")
            .expect("optional slot entry should exist");

        assert!(auth_index < model_index);
        assert!(model_index < agents_index);
        assert!(agents_index < workspace_index);
        assert!(catalog_slot_index < tool_slot_index);
    }

    #[test]
    fn render_run_env_file_emits_root_config_descriptions_as_comments() {
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
                "auth_json": {
                    "type": "string",
                    "description": "Forwarded auth payload for the child runtime."
                }
            },
            "required": ["auth_json"]
        });

        let rendered = render_run_env_file(&interface, Some(&root_schema));

        assert!(rendered.contains("# Forwarded auth payload for the child runtime."));
        let description_index = rendered
            .find("# Forwarded auth payload for the child runtime.")
            .expect("description comment should exist");
        let variable_index = rendered
            .find("AMBER_CONFIG_AUTH_JSON=")
            .expect("env variable should exist");
        assert!(description_index < variable_index);
    }
}
