use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt::Write as _,
};

use amber_config as rc;
use amber_scenario::{ComponentId, Scenario};
use miette::LabeledSpan;
use serde::Serialize;

use super::{Reporter, ReporterError};
use crate::{
    CompileOutput,
    binding_query::BindingObject,
    mesh::{
        MeshOptions, component_label,
        config::{ProgramPlan, encode_helper_payload, encode_schema_b64},
    },
    slot_query::SlotObject,
};

const MESH_NETWORK_NAME: &str = "amber_mesh";

const SIDECAR_IMAGE: &str = "ghcr.io/rdi-foundation/amber-sidecar:main";
const HELPER_IMAGE: &str = "ghcr.io/rdi-foundation/amber-helper:v1";
const HELPER_VOLUME_NAME: &str = "amber-helper-bin";
const HELPER_INIT_SERVICE: &str = "amber-init";
const HELPER_BIN_DIR: &str = "/amber/bin";
const HELPER_BIN_PATH: &str = "/amber/bin/amber-helper";

const LOCAL_PROXY_PORT_BASE: u16 = 20000;
const EXPORT_PORT_BASE: u16 = 18000;
const EXPORT_HOST: &str = "127.0.0.1";

#[derive(Clone, Copy, Debug, Default)]
pub struct DockerComposeReporter;

impl Reporter for DockerComposeReporter {
    type Artifact = String;

    fn emit(&self, output: &CompileOutput) -> Result<Self::Artifact, ReporterError> {
        render_docker_compose(output)
    }
}

#[derive(Clone, Debug)]
struct ServiceNames {
    program: String,
    sidecar: String,
}

#[derive(Clone, Debug)]
struct SlotProxy {
    local_port: u16,
    remote_host: String,
    remote_port: u16,
}

#[derive(Clone, Debug, Serialize)]
struct ExportMetadata {
    published_host: String,
    published_port: u16,
    target_port: u16,
    component: String,
    provide: String,
    endpoint: String,
}

#[derive(Debug)]
struct PortConflict {
    component: ComponentId,
    port: u16,
    first_provide: String,
    first_endpoint: String,
    provide: String,
    endpoint: String,
}

#[derive(Debug)]
enum DockerComposeError {
    Other(String),
    PortConflict(Box<PortConflict>),
}

impl From<String> for DockerComposeError {
    fn from(value: String) -> Self {
        Self::Other(value)
    }
}

impl DockerComposeError {
    fn into_reporter_error(self, output: &CompileOutput) -> ReporterError {
        match self {
            DockerComposeError::Other(message) => ReporterError::new(message),
            DockerComposeError::PortConflict(conflict) => {
                let PortConflict {
                    component,
                    port,
                    first_provide,
                    first_endpoint,
                    provide,
                    endpoint,
                } = *conflict;
                let component_moniker = output.scenario.component(component).moniker.as_str();
                let message = format!(
                    "docker-compose output cannot enforce separate capabilities for provides \
                     `{first_provide}` and `{provide}` in component `{component_moniker}`: both \
                     route to port {port} via endpoints `{first_endpoint}` and `{endpoint}`"
                );
                let help = "Expose each capability on its own port, or add an explicit L7 proxy \
                            component that maps each capability to a separate port.";

                let prov = output.provenance.for_component(component);
                let Some((src, spans)) = output.store.diagnostic_source(&prov.resolved_url) else {
                    return ReporterError::new(message).with_help(help);
                };

                let mut labels = Vec::new();
                let mut has_primary = false;

                let provide_span = |name: &str| {
                    spans
                        .provides
                        .get(name)
                        .map(|s| s.capability.name)
                        .or_else(|| spans.provides.get(name).map(|s| s.capability.whole))
                };

                let endpoint_span = |name: &str| {
                    spans
                        .program
                        .as_ref()?
                        .endpoints
                        .iter()
                        .find(|endpoint| endpoint.name.as_ref() == name)
                };

                if let Some(endpoint) = endpoint_span(&first_endpoint) {
                    let span = endpoint.port_span.unwrap_or(endpoint.whole);

                    labels.push(LabeledSpan::new_primary_with_span(
                        Some(format!("port used by provide `{first_provide}`")),
                        span,
                    ));
                    has_primary = true;
                }
                if let Some(endpoint) = endpoint_span(&endpoint) {
                    let span = endpoint.port_span.unwrap_or(endpoint.whole);

                    let label = Some(format!("port used by provide `{provide}`"));
                    if has_primary {
                        labels.push(LabeledSpan::new_with_span(label, span));
                    } else {
                        labels.push(LabeledSpan::new_primary_with_span(label, span));
                        has_primary = true;
                    }
                }

                if !has_primary {
                    if let Some(span) = provide_span(&first_provide) {
                        labels.push(LabeledSpan::new_primary_with_span(
                            Some(format!("provide `{first_provide}`")),
                            span,
                        ));
                        has_primary = true;
                    }
                    if let Some(span) = provide_span(&provide) {
                        let label = Some(format!("provide `{provide}`"));
                        if has_primary {
                            labels.push(LabeledSpan::new_with_span(label, span));
                        } else {
                            labels.push(LabeledSpan::new_primary_with_span(label, span));
                        }
                    }
                }

                ReporterError::new(message)
                    .with_help(help)
                    .with_source_code(src)
                    .with_labels(labels)
            }
        }
    }
}

type DcResult<T> = Result<T, DockerComposeError>;

fn render_docker_compose(output: &CompileOutput) -> Result<String, ReporterError> {
    render_docker_compose_inner(output).map_err(|err| err.into_reporter_error(output))
}

fn render_docker_compose_inner(output: &CompileOutput) -> DcResult<String> {
    let s = &output.scenario;

    let mesh_plan = crate::mesh::build_mesh_plan(
        s,
        &output.store,
        MeshOptions {
            backend_label: "docker-compose reporter",
        },
    )
    .map_err(|e| DockerComposeError::Other(e.to_string()))?;

    let program_components = mesh_plan.program_components.as_slice();

    // Precompute service names (injective & stable).
    let mut names: HashMap<ComponentId, ServiceNames> = HashMap::new();
    for id in program_components {
        let c = s.component(*id);
        let base = service_base_name(*id, c.moniker.local_name().unwrap_or("component"));
        let sidecar = format!("{base}-net");
        names.insert(
            *id,
            ServiceNames {
                program: base,
                sidecar,
            },
        );
    }

    // Allocate stable local proxy ports per (component, slot), avoiding colliding with program listens.
    let slot_ports_by_component = allocate_local_proxy_ports(s, program_components)?;

    // Build per-component slot-values, binding-values, and per-component slot-proxy processes.
    let mut slot_values_by_component: HashMap<ComponentId, BTreeMap<String, SlotObject>> =
        HashMap::new();
    let mut binding_values_by_component: HashMap<ComponentId, BTreeMap<String, BindingObject>> =
        HashMap::new();
    for id in program_components {
        slot_values_by_component.insert(*id, BTreeMap::new());
        binding_values_by_component.insert(*id, BTreeMap::new());
    }
    let mut slot_proxies_by_component: HashMap<ComponentId, Vec<SlotProxy>> = HashMap::new();

    // Inbound allowlist: (provider_component, port) -> set of consumer sidecar hosts
    let mut inbound_allow: HashMap<(ComponentId, u16), BTreeSet<String>> = HashMap::new();

    // Track (component,port) -> (first_provide_name, first_endpoint_name) to detect
    // distinct endpoints sharing a port.
    let mut port_owner: HashMap<(ComponentId, u16), (String, String)> = HashMap::new();

    for binding in &mesh_plan.bindings {
        let provider = binding.provider;
        let consumer = binding.consumer;
        let endpoint = &binding.endpoint;

        // Port conflict check (L4 backend cannot separate endpoints on the same port).
        enforce_single_endpoint_per_port(
            &mut port_owner,
            provider,
            endpoint.port,
            &binding.provide,
            &endpoint.name,
        )?;

        let consumer_host = names
            .get(&consumer)
            .ok_or_else(|| {
                format!(
                    "internal error: missing sidecar name for consumer {}",
                    component_label(s, consumer)
                )
            })?
            .sidecar
            .clone();
        inbound_allow
            .entry((provider, endpoint.port))
            .or_default()
            .insert(consumer_host);

        // Create local loopback proxy in consumer namespace.
        let local_port = *slot_ports_by_component
            .get(&consumer)
            .and_then(|m| m.get(&binding.slot))
            .ok_or_else(|| {
                format!(
                    "internal error: missing local port allocation for {}.{}",
                    component_label(s, consumer),
                    binding.slot
                )
            })?;

        let remote_host = if provider == consumer {
            "127.0.0.1".to_string()
        } else {
            names
                .get(&provider)
                .ok_or_else(|| {
                    format!(
                        "internal error: missing sidecar name for provider {}",
                        component_label(s, provider)
                    )
                })?
                .sidecar
                .clone()
        };

        slot_proxies_by_component
            .entry(consumer)
            .or_default()
            .push(SlotProxy {
                local_port,
                remote_host,
                remote_port: endpoint.port,
            });

        let url = format!("http://127.0.0.1:{local_port}");

        slot_values_by_component
            .entry(consumer)
            .or_default()
            .insert(binding.slot.clone(), SlotObject { url: url.clone() });

        if let Some(name) = binding.binding_name.as_ref() {
            binding_values_by_component
                .entry(consumer)
                .or_default()
                .insert(name.clone(), BindingObject { url });
        }
    }

    // Scenario exports => publish to host loopback with stable host ports.
    // Also, allow inbound on that target port from host loopback / docker gateway.
    let mut exported_ports: HashMap<ComponentId, BTreeSet<u16>> = HashMap::new();
    let mut exports_by_provider: HashMap<ComponentId, BTreeMap<String, ExportMetadata>> =
        HashMap::new();
    let mut exports_by_name: BTreeMap<String, ExportMetadata> = BTreeMap::new();
    {
        let mut next_host_port = EXPORT_PORT_BASE;
        for ex in &mesh_plan.exports {
            let provider = ex.provider;
            let endpoint = &ex.endpoint;

            enforce_single_endpoint_per_port(
                &mut port_owner,
                provider,
                endpoint.port,
                &ex.provide,
                &endpoint.name,
            )?;

            let published = next_host_port;
            next_host_port = next_host_port.checked_add(1).ok_or_else(|| {
                "ran out of host ports while allocating scenario exports".to_string()
            })?;

            exported_ports
                .entry(provider)
                .or_default()
                .insert(endpoint.port);

            let metadata = ExportMetadata {
                published_host: EXPORT_HOST.to_string(),
                published_port: published,
                target_port: endpoint.port,
                component: component_label(s, provider),
                provide: ex.provide.clone(),
                endpoint: endpoint.name.clone(),
            };

            exports_by_provider
                .entry(provider)
                .or_default()
                .insert(ex.name.clone(), metadata.clone());
            exports_by_name.insert(ex.name.clone(), metadata);
        }
    }

    // Compose YAML
    let mut out = String::new();

    // ---- runtime config / helper decision ----
    let config_plan = crate::mesh::config::build_config_plan(
        s,
        &mesh_plan.manifests,
        program_components,
        &slot_values_by_component,
        &binding_values_by_component,
    )
    .map_err(|e| DockerComposeError::Other(e.to_string()))?;

    // Root schema payloads + AMBER_CONFIG_* env list are only needed if at least one service uses the helper.
    let mut root_schema_b64: Option<String> = None;
    let mut root_env_entries: Vec<String> = Vec::new();

    if config_plan.uses_helper {
        let root_schema = config_plan
            .root_schema
            .as_ref()
            .expect("helper usage implies root schema");
        root_schema_b64 = Some(
            encode_schema_b64("root config definition", root_schema)
                .map_err(|e| DockerComposeError::Other(e.to_string()))?,
        );

        for leaf in &config_plan.root_leaves {
            let var = rc::env_var_for_path(&leaf.path)
                .map_err(|e| format!("failed to map config path {} to env var: {e}", leaf.path))?;
            if leaf.required {
                root_env_entries.push(format!("{var}=${{{var}?missing config.{}}}", leaf.path));
            } else {
                root_env_entries.push(var);
            }
        }
    }

    let program_plans = &config_plan.program_plans;
    let any_helper = config_plan.uses_helper;

    // ---- YAML headers ----
    if any_helper {
        writeln!(&mut out, "volumes:").unwrap();
        push_line(&mut out, 2, &format!("{HELPER_VOLUME_NAME}: {{}}"));
    }

    writeln!(&mut out, "services:").unwrap();

    if any_helper {
        push_line(&mut out, 2, &format!("{HELPER_INIT_SERVICE}:"));
        push_line(&mut out, 4, &format!("image: {}", yaml_str(HELPER_IMAGE)));
        push_line(&mut out, 4, "entrypoint:");
        push_line(&mut out, 6, &format!("- {}", yaml_str("/amber-helper")));
        push_line(&mut out, 6, &format!("- {}", yaml_str("install")));
        push_line(
            &mut out,
            6,
            &format!("- {}", yaml_str(&format!("{HELPER_BIN_DIR}/amber-helper"))),
        );
        push_line(&mut out, 4, "volumes:");
        push_line(
            &mut out,
            6,
            &format!("- {}:{}", HELPER_VOLUME_NAME, HELPER_BIN_DIR),
        );
        push_line(&mut out, 4, &format!("restart: {}", yaml_str("no")));
    }

    // Emit services in stable (component id) order, sidecar then program.
    for id in program_components {
        let c = s.component(*id);
        let svc = names.get(id).unwrap();

        // ---- sidecar ----
        push_line(&mut out, 2, &format!("{}:", svc.sidecar));

        push_line(&mut out, 4, &format!("image: {}", yaml_str(SIDECAR_IMAGE)));

        push_line(&mut out, 4, "cap_add:");
        push_line(&mut out, 6, "- NET_ADMIN");
        push_line(&mut out, 4, "cap_drop:");
        push_line(&mut out, 6, "- ALL");
        push_line(&mut out, 4, "security_opt:");
        push_line(&mut out, 6, "- no-new-privileges:true");

        // Attach sidecar to mesh network (Compose assigns IPs + DNS names).
        push_line(&mut out, 4, "networks:");
        push_line(&mut out, 6, &format!("{MESH_NETWORK_NAME}: {{}}"));

        // Host port publishes for scenario exports (loopback-only for MVP)
        if let Some(mappings) = exports_by_provider.get(id) {
            push_line(&mut out, 4, "ports:");
            for m in mappings.values() {
                // Published on host loopback only.
                let spec = format!(
                    "{}:{}:{}",
                    m.published_host, m.published_port, m.target_port
                );
                push_line(&mut out, 6, &format!("- {}", yaml_str(&spec)));
            }

            let labels_json = serde_json::to_string(mappings).map_err(|err| {
                format!(
                    "failed to serialize export labels for {}: {err}",
                    c.moniker.as_str()
                )
            })?;
            push_line(&mut out, 4, "labels:");
            push_line(
                &mut out,
                6,
                &format!("amber.exports: {}", yaml_str(&labels_json)),
            );
        }

        // Sidecar command script
        let script = build_sidecar_script(
            *id,
            inbound_allow
                .iter()
                .filter_map(|((prov, port), srcs)| (*prov == *id).then_some((*port, srcs)))
                .collect(),
            exported_ports.get(id),
            slot_proxies_by_component.get(id),
        );

        push_line(&mut out, 4, "command:");
        push_line(&mut out, 6, "- /bin/sh");
        push_line(&mut out, 6, "- -lc");
        push_line(&mut out, 6, "- |-");
        for line in script.lines() {
            let escaped = escape_compose_interpolation(line);
            push_line(&mut out, 8, escaped.as_ref());
        }

        // ---- program ----
        push_line(&mut out, 2, &format!("{}:", svc.program));

        let program = c.program.as_ref().unwrap();
        push_line(
            &mut out,
            4,
            &format!("image: {}", yaml_str(program.image.as_ref())),
        );
        push_line(
            &mut out,
            4,
            &format!(
                "network_mode: {}",
                yaml_str(&format!("service:{}", svc.sidecar))
            ),
        );

        // depends_on: own sidecar + strong deps provider programs (+ amber-init for helper-backed services)
        let program_plan = program_plans.get(id).expect("program plan computed");
        let mut deps: Vec<(String, &'static str)> = Vec::new();
        if any_helper && matches!(program_plan, ProgramPlan::Helper { .. }) {
            deps.push((
                HELPER_INIT_SERVICE.to_string(),
                "service_completed_successfully",
            ));
        }
        deps.push((svc.sidecar.clone(), "service_started"));
        if let Some(ds) = mesh_plan.strong_deps.get(id) {
            for dep in ds {
                if let Some(dep_names) = names.get(dep) {
                    deps.push((dep_names.program.clone(), "service_started"));
                } else {
                    return Err(format!(
                        "internal error: missing service name for dependency {}",
                        component_label(s, *dep)
                    )
                    .into());
                }
            }
        }
        if !deps.is_empty() {
            push_line(&mut out, 4, "depends_on:");
            if any_helper {
                for (name, cond) in deps {
                    push_line(&mut out, 6, &format!("{name}:"));
                    push_line(&mut out, 8, &format!("condition: {cond}"));
                }
            } else {
                for (name, _) in deps {
                    push_line(&mut out, 6, &format!("- {}", name));
                }
            }
        }

        match program_plan {
            ProgramPlan::Direct { entrypoint, env } => {
                // Use entrypoint so image entrypoints are ignored.
                push_line(&mut out, 4, "entrypoint:");
                for a in entrypoint {
                    push_line(&mut out, 6, &format!("- {}", yaml_str(a)));
                }

                if !env.is_empty() {
                    push_line(&mut out, 4, "environment:");
                    for (k, v) in env {
                        push_line(&mut out, 6, &format!("{k}: {}", yaml_str(v)));
                    }
                }
            }
            ProgramPlan::Helper {
                template_spec,
                component_template,
                component_schema,
            } => {
                let label = component_label(s, *id);
                let payload = encode_helper_payload(
                    &label,
                    template_spec,
                    component_template,
                    component_schema,
                )
                .map_err(|e| DockerComposeError::Other(e.to_string()))?;

                // Mount helper binary and run it as PID1; it execs the program entrypoint.
                push_line(&mut out, 4, "volumes:");
                push_line(
                    &mut out,
                    6,
                    &format!("- {}:{}:ro", HELPER_VOLUME_NAME, HELPER_BIN_DIR),
                );
                push_line(&mut out, 4, "entrypoint:");
                push_line(&mut out, 6, &format!("- {}", yaml_str(HELPER_BIN_PATH)));
                push_line(&mut out, 6, &format!("- {}", yaml_str("run")));

                push_line(&mut out, 4, "environment:");
                // Emit as list so pass-through entries can remain unset.
                for entry in &root_env_entries {
                    push_line(&mut out, 6, &format!("- {}", yaml_str(entry)));
                }

                let root_schema_b64 = root_schema_b64.as_ref().expect("helper enabled");
                push_line(
                    &mut out,
                    6,
                    &format!(
                        "- {}",
                        yaml_str(&format!("AMBER_ROOT_CONFIG_SCHEMA_B64={root_schema_b64}"))
                    ),
                );
                push_line(
                    &mut out,
                    6,
                    &format!(
                        "- {}",
                        yaml_str(&format!(
                            "AMBER_COMPONENT_CONFIG_SCHEMA_B64={}",
                            payload.component_schema_b64
                        ))
                    ),
                );
                push_line(
                    &mut out,
                    6,
                    &format!(
                        "- {}",
                        yaml_str(&format!(
                            "AMBER_COMPONENT_CONFIG_TEMPLATE_B64={}",
                            payload.component_cfg_template_b64
                        ))
                    ),
                );
                push_line(
                    &mut out,
                    6,
                    &format!(
                        "- {}",
                        yaml_str(&format!(
                            "AMBER_TEMPLATE_SPEC_B64={}",
                            payload.template_spec_b64
                        ))
                    ),
                );
            }
        }
    }

    // Networks
    writeln!(&mut out, "networks:").unwrap();
    push_line(&mut out, 2, &format!("{MESH_NETWORK_NAME}:"));
    push_line(&mut out, 4, "driver: bridge");

    if !exports_by_name.is_empty() {
        writeln!(&mut out, "x-amber:").unwrap();
        push_line(&mut out, 2, "exports:");
        for (export_name, meta) in &exports_by_name {
            push_line(&mut out, 4, &format!("{}:", yaml_str(export_name)));
            push_line(
                &mut out,
                6,
                &format!("published_host: {}", yaml_str(&meta.published_host)),
            );
            push_line(
                &mut out,
                6,
                &format!("published_port: {}", meta.published_port),
            );
            push_line(&mut out, 6, &format!("target_port: {}", meta.target_port));
            push_line(
                &mut out,
                6,
                &format!("component: {}", yaml_str(&meta.component)),
            );
            push_line(
                &mut out,
                6,
                &format!("provide: {}", yaml_str(&meta.provide)),
            );
            push_line(
                &mut out,
                6,
                &format!("endpoint: {}", yaml_str(&meta.endpoint)),
            );
        }
    }

    Ok(out)
}

// ---- helpers ----

fn service_base_name(id: ComponentId, local_name: &str) -> String {
    // Ensure injective via numeric prefix; keep human-readable suffix.
    let slug = sanitize_service_suffix(local_name);
    format!("c{}-{}", id.0, slug)
}

fn sanitize_service_suffix(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        let ch = ch.to_ascii_lowercase();
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    let out = out.trim_matches('-');
    if out.is_empty() {
        "component".to_string()
    } else {
        out.to_string()
    }
}

fn enforce_single_endpoint_per_port(
    owner: &mut HashMap<(ComponentId, u16), (String, String)>,
    component: ComponentId,
    port: u16,
    provide_name: &str,
    endpoint_name: &str,
) -> Result<(), DockerComposeError> {
    match owner.get(&(component, port)) {
        None => {
            owner.insert(
                (component, port),
                (provide_name.to_string(), endpoint_name.to_string()),
            );
            Ok(())
        }
        Some((_first_provide, first_endpoint)) if *first_endpoint == endpoint_name => Ok(()),
        Some((first_provide, first_endpoint)) => {
            Err(DockerComposeError::PortConflict(Box::new(PortConflict {
                component,
                port,
                first_provide: first_provide.clone(),
                first_endpoint: first_endpoint.clone(),
                provide: provide_name.to_string(),
                endpoint: endpoint_name.to_string(),
            })))
        }
    }
}

fn allocate_local_proxy_ports(
    s: &Scenario,
    program_components: &[ComponentId],
) -> Result<HashMap<ComponentId, BTreeMap<String, u16>>, String> {
    let mut out: HashMap<ComponentId, BTreeMap<String, u16>> = HashMap::new();

    for id in program_components {
        let c = s.component(*id);
        let program = c.program.as_ref().unwrap();

        // Reserved: any ports the program listens on itself.
        let mut reserved: HashSet<u16> = HashSet::new();
        if let Some(net) = program.network.as_ref() {
            for ep in &net.endpoints {
                reserved.insert(ep.port);
            }
        }

        let mut slot_ports: BTreeMap<String, u16> = BTreeMap::new();
        let mut next = LOCAL_PROXY_PORT_BASE;

        // Stable ordering by slot name.
        for slot_name in c.slots.keys() {
            while reserved.contains(&next) || slot_ports.values().any(|p| *p == next) {
                next = next.checked_add(1).ok_or_else(|| {
                    format!(
                        "ran out of local proxy ports allocating for {}",
                        component_label(s, *id)
                    )
                })?;
            }
            slot_ports.insert(slot_name.clone(), next);
            next = next.checked_add(1).ok_or_else(|| {
                format!(
                    "ran out of local proxy ports allocating for {}",
                    component_label(s, *id)
                )
            })?;
        }

        out.insert(*id, slot_ports);
    }

    Ok(out)
}

// NOTE: template interpolation is now handled structurally via `amber_manifest::InterpolatedString`
// parts and the runtime helper payload IR. The old string re-parser has been removed.

fn build_sidecar_script(
    _component: ComponentId,
    inbound: Vec<(u16, &BTreeSet<String>)>,
    exported_ports: Option<&BTreeSet<u16>>,
    proxies: Option<&Vec<SlotProxy>>,
) -> String {
    let mut script = String::new();

    // Minimal, explicit, deterministic.
    writeln!(&mut script, "set -eu").unwrap();

    // Firewall baseline
    writeln!(&mut script, "iptables -w -F").unwrap();
    writeln!(&mut script, "iptables -w -X").unwrap();
    writeln!(&mut script, "iptables -w -P INPUT DROP").unwrap();
    writeln!(&mut script, "iptables -w -P FORWARD DROP").unwrap();
    writeln!(&mut script, "iptables -w -P OUTPUT ACCEPT").unwrap();
    writeln!(&mut script, "iptables -w -A INPUT -i lo -j ACCEPT").unwrap();
    writeln!(
        &mut script,
        "iptables -w -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    )
    .unwrap();
    writeln!(&mut script, "iptables -w -N AMBER-ALLOW").unwrap();
    writeln!(&mut script, "iptables -w -A INPUT -j AMBER-ALLOW").unwrap();

    writeln!(&mut script, "resolve_ipv4() {{").unwrap();
    writeln!(
        &mut script,
        "  getent hosts \"$1\" | awk '$1 ~ /^[0-9]+(\\.[0-9]+){{3}}$/ {{print $1}}' || true"
    )
    .unwrap();
    writeln!(&mut script, "}}").unwrap();
    writeln!(&mut script, "add_rule() {{").unwrap();
    writeln!(&mut script, "  if [ -n \"$1\" ]; then").unwrap();
    writeln!(
        &mut script,
        "    printf '%s\\n' \"$1\" >> \"$desired_rules\""
    )
    .unwrap();
    writeln!(&mut script, "  fi").unwrap();
    writeln!(&mut script, "}}").unwrap();
    writeln!(&mut script, "refresh_allowlist() {{").unwrap();
    writeln!(&mut script, "  set +e").unwrap();
    writeln!(&mut script, "  desired_rules=\"/tmp/amber-allowlist\"").unwrap();
    writeln!(&mut script, "  : > \"$desired_rules\"").unwrap();
    writeln!(
        &mut script,
        "  gateway=\"$(ip -4 route show default | awk 'NR==1 {{print $3}}')\""
    )
    .unwrap();

    // Allow inbound from bound consumers (resolved via DNS).
    let mut inbound_sorted = inbound;
    inbound_sorted.sort_by_key(|(port, _)| *port);
    for (port, srcs) in inbound_sorted {
        for src in srcs {
            writeln!(&mut script, "  for ip in $(resolve_ipv4 \"{src}\"); do").unwrap();
            writeln!(
                &mut script,
                "    add_rule \"-s $ip/32 -p tcp -m tcp --dport {port} -j ACCEPT\""
            )
            .unwrap();
            writeln!(&mut script, "  done").unwrap();
        }
    }

    // Allow inbound from host (exports): loopback + docker gateway.
    if let Some(ports) = exported_ports {
        for port in ports {
            writeln!(
                &mut script,
                "  add_rule \"-s {EXPORT_HOST}/32 -p tcp -m tcp --dport {port} -j ACCEPT\""
            )
            .unwrap();
            writeln!(&mut script, "  if [ -n \"$gateway\" ]; then").unwrap();
            writeln!(
                &mut script,
                "    add_rule \"-s $gateway/32 -p tcp -m tcp --dport {port} -j ACCEPT\""
            )
            .unwrap();
            writeln!(&mut script, "  fi").unwrap();
        }
    }
    writeln!(&mut script, "  if [ -s \"$desired_rules\" ]; then").unwrap();
    writeln!(&mut script, "    iptables -w -F AMBER-ALLOW").unwrap();
    writeln!(&mut script, "    while read -r rule; do").unwrap();
    writeln!(&mut script, "      [ -z \"$rule\" ] && continue").unwrap();
    writeln!(&mut script, "      iptables -w -A AMBER-ALLOW $rule").unwrap();
    writeln!(&mut script, "    done < \"$desired_rules\"").unwrap();
    writeln!(&mut script, "  fi").unwrap();
    writeln!(&mut script, "  set -e").unwrap();
    writeln!(&mut script, "  return 0").unwrap();
    writeln!(&mut script, "}}").unwrap();
    writeln!(&mut script, "fast_refresh=1").unwrap();
    writeln!(&mut script, "slow_refresh=5").unwrap();
    writeln!(&mut script, "warmup_rounds=10").unwrap();
    writeln!(&mut script, "refresh_allowlist || true").unwrap();
    writeln!(
        &mut script,
        "while true; do refresh_allowlist || true; if [ \"$warmup_rounds\" -gt 0 ]; then \
         warmup_rounds=$((warmup_rounds-1)); sleep \"$fast_refresh\"; else sleep \
         \"$slow_refresh\"; fi; done &"
    )
    .unwrap();

    // Start local TCP proxies for slots.
    if let Some(ps) = proxies {
        // Stable ordering
        let mut ps = ps.clone();
        ps.sort_by_key(|p| p.local_port);

        for p in ps {
            // socat forwards raw TCP; higher-level schemes are handled by the program.
            writeln!(
                &mut script,
                "socat TCP-LISTEN:{},fork,reuseaddr,bind=127.0.0.1 TCP:{}:{} &",
                p.local_port, p.remote_host, p.remote_port
            )
            .unwrap();
        }
    }

    // Keep the sidecar alive; program shares this netns.
    writeln!(&mut script, "exec tail -f /dev/null").unwrap();

    script
}

fn push_line(out: &mut String, indent: usize, line: &str) {
    for _ in 0..indent {
        out.push(' ');
    }
    out.push_str(line);
    out.push('\n');
}

fn yaml_str(s: &str) -> String {
    // Double-quoted YAML scalar with minimal escaping.
    let mut out = String::new();
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn escape_compose_interpolation<'a>(line: &'a str) -> Cow<'a, str> {
    if line.contains('$') {
        Cow::Owned(line.replace('$', "$$"))
    } else {
        Cow::Borrowed(line)
    }
}

#[cfg(test)]
mod tests;
