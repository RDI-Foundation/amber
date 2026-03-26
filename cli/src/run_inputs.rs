use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    io::{self, Write as _},
    net::SocketAddr,
    path::{Path, PathBuf},
};

use amber_compiler::run_plan::RunPlan;
use amber_config::{self as config, CONFIG_ENV_PREFIX};
use amber_manifest::{CapabilityKind, CapabilityTransport};
use miette::{Context as _, IntoDiagnostic as _, Result};
use rpassword::prompt_password;
use url::Url;

use crate::site_proxy_metadata::load_site_proxy_metadata;

const GENERATED_ENV_SAMPLE_FILENAME: &str = "env.example";
const PROJECT_ENV_FILENAME: &str = ".env";

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
) -> Result<BTreeMap<String, String>> {
    let mut merged = BTreeMap::new();

    if let Some(project_root) = project_root {
        let env_path = project_env_path(project_root);
        if env_path.is_file() {
            merge_env_file(&mut merged, &env_path)?;
        }
    }

    for env_file in env_files {
        merge_env_file(&mut merged, env_file)?;
    }

    merged.extend(ambient_run_env());
    Ok(merged)
}

pub(crate) fn collect_run_interface(run_plan: &RunPlan) -> Result<RunInterface> {
    let mut root_inputs = BTreeMap::<String, RootInputSpec>::new();
    let mut external_slots = BTreeMap::<String, ExternalSlotSpec>::new();
    let mut exports = BTreeMap::<String, ExportSpec>::new();

    for site in run_plan.sites.values() {
        if let Some(env_sample) = site.artifact_files.get(GENERATED_ENV_SAMPLE_FILENAME) {
            merge_root_inputs(&mut root_inputs, parse_env_sample(env_sample)?);
        }

        let metadata = load_site_proxy_metadata(site)?;

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
        .filter(|input| input.required && env_var_missing(env, &input.env_var))
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
                .filter(|value| !value.trim().is_empty())
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
) -> Result<()> {
    for input in &interface.root_inputs {
        if !input.required || !env_var_missing(env, &input.env_var) {
            continue;
        }
        let prompt = format!("config.{}: ", input.path);
        let value = if input.secret {
            prompt_password(prompt).into_diagnostic()?
        } else {
            prompt_line(&prompt)?
        };
        let trimmed = value.trim().to_string();
        if trimmed.is_empty() {
            return Err(miette::miette!("config.{} must not be empty", input.path));
        }
        env.insert(input.env_var.clone(), trimmed);
    }

    for slot in missing_promptable_external_slots(env, interface) {
        let prompt = if slot.required {
            format!("slot.{}: ", slot.name)
        } else {
            format!("slot.{} (optional): ", slot.name)
        };
        let value = prompt_line(&prompt)?;
        let trimmed = value.trim();
        if trimmed.is_empty() {
            if slot.required {
                return Err(miette::miette!("slot.{} must not be empty", slot.name));
            }
            continue;
        }
        let normalized = normalize_external_slot_value(slot, trimmed)?;
        env.insert(slot.env_var.clone(), normalized);
    }

    Ok(())
}

pub(crate) fn render_resolved_input_lines(
    env: &BTreeMap<String, String>,
    interface: &RunInterface,
) -> Vec<String> {
    let mut lines = Vec::new();

    for input in &interface.root_inputs {
        let Some(value) = env
            .get(&input.env_var)
            .filter(|value| !value.trim().is_empty())
        else {
            continue;
        };
        lines.push(format!(
            "config.{}: {}",
            input.path,
            if input.secret {
                "*".repeat(value.chars().count().max(8))
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
        if let Some(value) = env
            .get(&input.env_var)
            .filter(|value| !value.trim().is_empty())
        {
            out.push_str(&input.env_var);
            out.push('=');
            out.push_str(value);
            out.push('\n');
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

fn merge_env_file(target: &mut BTreeMap<String, String>, path: &Path) -> Result<()> {
    for entry in dotenvy::from_path_iter(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read env file {}", path.display()))?
    {
        let (key, value) = entry
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to parse env file {}", path.display()))?;
        if is_run_env_key(&key) {
            target.insert(key, value);
        }
    }
    Ok(())
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

fn parse_env_sample(contents: &str) -> Result<Vec<RootInputSpec>> {
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
    io::stdin().read_line(&mut line).into_diagnostic()?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
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
        run_plan::{RunLink, RunPlan, RunSitePlan, SiteDefinition, SiteKind},
    };
    use amber_scenario::ScenarioIr;

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
            version: 1,
            mesh_scope: "scope".to_string(),
            assignments: BTreeMap::new(),
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
            "version": 1,
            "mesh_scope": "scope",
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
}
