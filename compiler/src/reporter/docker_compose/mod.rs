use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt::Write as _,
    sync::Arc,
};

use amber_config as rc;
use amber_manifest::{BindingTarget, InterpolatedPart, InterpolationSource, Manifest};
use amber_scenario::{BindingFrom, ComponentId, ProvideRef, Scenario};
use amber_template::{ProgramTemplateSpec, TemplatePart, TemplateSpec, TemplateString};
use base64::Engine as _;
use miette::LabeledSpan;
use serde::Serialize;

use super::{Reporter, ReporterError};
use crate::{
    CompileOutput,
    binding_query::{BindingObject, resolve_binding_query},
    config_templates,
    slot_query::{SlotObject, resolve_slot_query},
};

const MESH_NETWORK_NAME: &str = "amber_mesh";

const SIDECAR_IMAGE: &str = "ghcr.io/rdi-foundation/amber-sidecar:main";
const HELPER_IMAGE: &str = "ghcr.io/rdi-foundation/amber-compose-helper:v1";
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
struct Endpoint {
    name: String,
    port: u16,
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

    for b in &s.bindings {
        if let BindingFrom::Framework(name) = &b.from {
            return Err(format!(
                "docker-compose reporter does not support framework binding `framework.{name}` \
                 (bound to {}.{})",
                component_label(s, b.to.component),
                b.to.name
            )
            .into());
        }
    }

    let manifests = crate::manifest_table::build_manifest_table(&s.components, &output.store)
        .map_err(|e| {
            format!(
                "internal error: missing manifest content for {} (digest {})",
                component_label(s, e.component),
                e.digest
            )
        })?;

    // Backend prerequisite: strong dependency graph must be acyclic.
    // (Ignoring weak edges is the semantics you described.)
    if let Err(cycle) = amber_scenario::graph::topo_order(s) {
        let cycle_str = cycle
            .cycle
            .iter()
            .map(|id| format!("c{}", id.0))
            .collect::<Vec<_>>()
            .join(" -> ");
        return Err(format!(
            "docker-compose reporter requires an acyclic dependency graph (ignoring weak \
             bindings). Found a cycle: {cycle_str}"
        )
        .into());
    }

    // Collect program components (these become runnable services).
    let program_components: Vec<ComponentId> = s
        .components_iter()
        .filter_map(|(id, c)| c.program.as_ref().map(|_| id))
        .collect();

    // Precompute service names (injective & stable).
    let mut names: HashMap<ComponentId, ServiceNames> = HashMap::new();
    for id in &program_components {
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

    // Validate: every binding endpoint is between program components.
    for b in &s.bindings {
        let from = binding_from_component(&b.from);
        if s.component(from.component).program.is_none() {
            return Err(format!(
                "binding source {}.{} is not runnable (component has no program)",
                component_label(s, from.component),
                from.name
            )
            .into());
        }
        if s.component(b.to.component).program.is_none() {
            return Err(format!(
                "binding target {}.{} is not runnable (component has no program)",
                component_label(s, b.to.component),
                b.to.name
            )
            .into());
        }
    }
    for ex in &s.exports {
        if s.component(ex.from.component).program.is_none() {
            return Err(format!(
                "scenario export '{}' points at {}.{} which is not runnable (component has no \
                 program)",
                ex.name,
                component_label(s, ex.from.component),
                ex.from.name
            )
            .into());
        }
    }

    // Strong deps for compose ordering (weak edges do not order).
    let mut strong_deps: HashMap<ComponentId, BTreeSet<ComponentId>> = HashMap::new();
    for b in &s.bindings {
        if b.weak {
            continue;
        }
        let from = binding_from_component(&b.from);
        if from.component == b.to.component {
            continue;
        }
        strong_deps
            .entry(b.to.component)
            .or_default()
            .insert(from.component);
    }

    // Allocate stable local proxy ports per (component, slot), avoiding colliding with program listens.
    let slot_ports_by_component = allocate_local_proxy_ports(s, &program_components)?;

    // Build per-component slot-values, binding-values, and per-component slot-proxy processes.
    let mut slot_values_by_component: HashMap<ComponentId, BTreeMap<String, SlotObject>> =
        HashMap::new();
    let mut binding_values_by_component: HashMap<ComponentId, BTreeMap<String, BindingObject>> =
        HashMap::new();
    for id in &program_components {
        slot_values_by_component.insert(*id, BTreeMap::new());
        binding_values_by_component.insert(*id, BTreeMap::new());
    }
    let mut slot_proxies_by_component: HashMap<ComponentId, Vec<SlotProxy>> = HashMap::new();

    // Inbound allowlist: (provider_component, port) -> set of consumer sidecar hosts
    let mut inbound_allow: HashMap<(ComponentId, u16), BTreeSet<String>> = HashMap::new();

    // Track (component,port) -> (first_provide_name, first_endpoint_name) to detect
    // distinct endpoints sharing a port.
    let mut port_owner: HashMap<(ComponentId, u16), (String, String)> = HashMap::new();

    for b in &s.bindings {
        let from = binding_from_component(&b.from);
        let provider = from.component;
        let consumer = b.to.component;

        let endpoint = resolve_provide_endpoint(s, provider, &from.name)?;

        // Port conflict check (L4 backend cannot separate endpoints on the same port).
        enforce_single_endpoint_per_port(
            &mut port_owner,
            provider,
            endpoint.port,
            &from.name,
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
            .and_then(|m| m.get(&b.to.name))
            .ok_or_else(|| {
                format!(
                    "internal error: missing local port allocation for {}.{}",
                    component_label(s, consumer),
                    b.to.name
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
            .insert(b.to.name.clone(), SlotObject { url: url.clone() });

        if let Some(name) = b.name.as_ref() {
            binding_values_by_component
                .entry(consumer)
                .or_default()
                .insert(name.clone(), BindingObject { url });
        }
    }

    // Ensure all declared slots on runnable components got bound (this should already be true after linking).
    for id in &program_components {
        let c = s.component(*id);
        for slot_name in c.slots.keys() {
            let ok = slot_values_by_component
                .get(id)
                .and_then(|m| m.get(slot_name))
                .is_some();
            if !ok {
                return Err(format!(
                    "slot {}.{} has no resolved binding (linker should have rejected this)",
                    component_label(s, *id),
                    slot_name
                )
                .into());
            }
        }
    }

    let binding_urls_by_scope = binding_urls_by_scope(s, &manifests, &slot_values_by_component)?;

    // Scenario exports => publish to host loopback with stable host ports.
    // Also, allow inbound on that target port from host loopback / docker gateway.
    let mut exported_ports: HashMap<ComponentId, BTreeSet<u16>> = HashMap::new();
    let mut exports_by_provider: HashMap<ComponentId, BTreeMap<String, ExportMetadata>> =
        HashMap::new();
    let mut exports_by_name: BTreeMap<String, ExportMetadata> = BTreeMap::new();
    {
        let mut next_host_port = EXPORT_PORT_BASE;
        for ex in &s.exports {
            let provider = ex.from.component;
            let endpoint = resolve_provide_endpoint(s, provider, &ex.from.name)?;

            enforce_single_endpoint_per_port(
                &mut port_owner,
                provider,
                endpoint.port,
                &ex.from.name,
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
                provide: ex.from.name.clone(),
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
    // Compose root-only config templates for all components so we can decide which services need the helper.
    let root_id = s.root;
    let root_schema = manifests[root_id.0]
        .as_ref()
        .and_then(|m| m.config_schema())
        .map(|s| &s.0);

    let composed =
        config_templates::compose_root_config_templates(s.root, &s.components, &manifests);
    if let Some(err) = composed.errors.first() {
        return Err(format!(
            "failed to compose component config templates: {}",
            err.message
        )
        .into());
    }

    let resolved_templates =
        resolve_binding_templates(composed.templates, &binding_urls_by_scope, s)?;

    // Build per-program service mode (direct vs helper) + payloads.
    #[derive(Clone, Debug)]
    enum ProgramMode {
        Direct {
            entrypoint: Vec<String>,
            env: BTreeMap<String, String>,
        },
        Helper {
            template_spec_b64: String,
            component_cfg_template_b64: String,
            component_schema_b64: String,
        },
    }

    let mut program_mode: HashMap<ComponentId, ProgramMode> = HashMap::new();
    let mut any_helper = false;

    // Attempt to resolve a config interpolation to a static string; otherwise keep it as runtime.
    #[derive(Debug)]
    enum ConfigResolution {
        Static(String),
        Runtime,
    }

    fn resolve_config_query_for_program(
        template: Option<&rc::ConfigNode>,
        query: &str,
    ) -> Result<ConfigResolution, String> {
        let Some(template) = template else {
            return Ok(ConfigResolution::Runtime);
        };

        // Empty query means "the whole config".
        if query.is_empty() {
            return if !template.contains_runtime() {
                let v = template.evaluate_static().map_err(|e| e.to_string())?;
                Ok(ConfigResolution::Static(
                    rc::stringify_for_interpolation(&v).map_err(|e| e.to_string())?,
                ))
            } else {
                Ok(ConfigResolution::Runtime)
            };
        }

        // Traverse until we either:
        // - reach the node (resolved)
        // - hit a runtime insert (ConfigRef) before path ends (runtime)
        // - find a missing key (error)
        let mut cur = template;
        for seg in query.split('.') {
            if seg.is_empty() {
                return Err(format!("invalid config path {query:?}: empty segment"));
            }
            match cur {
                rc::ConfigNode::Object(map) => {
                    let Some(next) = map.get(seg) else {
                        return Err(format!("config.{query} not found (missing key {seg:?})"));
                    };
                    cur = next;
                }
                rc::ConfigNode::ConfigRef(_) => return Ok(ConfigResolution::Runtime),
                _ => {
                    return Err(format!(
                        "config.{query} not found (encountered non-object before segment {seg:?})"
                    ));
                }
            }
        }

        if !cur.contains_runtime() {
            let v = cur.evaluate_static().map_err(|e| e.to_string())?;
            Ok(ConfigResolution::Static(
                rc::stringify_for_interpolation(&v).map_err(|e| e.to_string())?,
            ))
        } else {
            Ok(ConfigResolution::Runtime)
        }
    }

    fn render_template_string_static(ts: &TemplateString) -> Result<String, String> {
        if rc::template_string_is_runtime(ts) {
            return Err(
                "internal error: attempted to render a runtime template string statically"
                    .to_string(),
            );
        }
        let mut out = String::new();
        for part in ts {
            match part {
                TemplatePart::Lit { lit } => out.push_str(lit),
                TemplatePart::Config { .. } => unreachable!(),
                TemplatePart::Binding { .. } => unreachable!(),
            }
        }
        Ok(out)
    }

    for id in &program_components {
        let c = s.component(*id);
        let program = c.program.as_ref().unwrap();

        let slots = slot_values_by_component.get(id).unwrap();
        let bindings = binding_values_by_component.get(id).unwrap();

        // Root-only composed config template (if available). Root component uses runtime root config.
        let template_opt: Option<&rc::ConfigNode> = match resolved_templates.get(id) {
            Some(rc::RootConfigTemplate::Node(node)) => Some(node),
            _ => None,
        };

        // Build template spec with slots resolved and config either resolved (static) or preserved.
        let mut entrypoint_ts: Vec<TemplateString> = Vec::new();
        let mut needs_helper = false;

        for (idx, arg) in program.args.0.iter().enumerate() {
            let mut ts: TemplateString = Vec::new();
            for part in &arg.parts {
                match part {
                    InterpolatedPart::Literal(lit) => ts.push(TemplatePart::lit(lit)),
                    InterpolatedPart::Interpolation { source, query } => match source {
                        InterpolationSource::Slots => {
                            let v = resolve_slot_query(slots, query)?;
                            ts.push(TemplatePart::lit(v));
                        }
                        InterpolationSource::Bindings => {
                            let v = resolve_binding_query(bindings, query)?;
                            ts.push(TemplatePart::lit(v));
                        }
                        InterpolationSource::Config => {
                            match resolve_config_query_for_program(template_opt, query)? {
                                ConfigResolution::Static(v) => ts.push(TemplatePart::lit(v)),
                                ConfigResolution::Runtime => {
                                    ts.push(TemplatePart::config(query.clone()));
                                    needs_helper = true;
                                }
                            }
                        }
                        other => {
                            return Err(format!(
                                "unsupported interpolation source {other} in {} \
                                 program.entrypoint[{idx}]",
                                component_label(s, *id)
                            )
                            .into());
                        }
                    },
                    _ => {
                        return Err(format!(
                            "unsupported interpolation part in {} program.entrypoint[{idx}]",
                            component_label(s, *id)
                        )
                        .into());
                    }
                }
            }
            if ts.is_empty() {
                return Err(format!(
                    "internal error: produced empty template for {} program.entrypoint[{idx}]",
                    component_label(s, *id)
                )
                .into());
            }
            entrypoint_ts.push(ts);
        }

        // program.env
        let mut env_ts: BTreeMap<String, TemplateString> = BTreeMap::new();
        for (k, v) in &program.env {
            let mut ts: TemplateString = Vec::new();
            for part in &v.parts {
                match part {
                    InterpolatedPart::Literal(lit) => ts.push(TemplatePart::lit(lit)),
                    InterpolatedPart::Interpolation { source, query } => match source {
                        InterpolationSource::Slots => {
                            let vv = resolve_slot_query(slots, query)?;
                            ts.push(TemplatePart::lit(vv));
                        }
                        InterpolationSource::Bindings => {
                            let vv = resolve_binding_query(bindings, query)?;
                            ts.push(TemplatePart::lit(vv));
                        }
                        InterpolationSource::Config => {
                            match resolve_config_query_for_program(template_opt, query)? {
                                ConfigResolution::Static(vv) => ts.push(TemplatePart::lit(vv)),
                                ConfigResolution::Runtime => {
                                    ts.push(TemplatePart::config(query.clone()));
                                    needs_helper = true;
                                }
                            }
                        }
                        other => {
                            return Err(format!(
                                "unsupported interpolation source {other} in {} program.env.{k}",
                                component_label(s, *id)
                            )
                            .into());
                        }
                    },
                    _ => {
                        return Err(format!(
                            "unsupported interpolation part in {} program.env.{k}",
                            component_label(s, *id)
                        )
                        .into());
                    }
                }
            }
            env_ts.insert(k.clone(), ts);
        }

        if needs_helper {
            any_helper = true;

            let m = manifests[id.0].as_ref().expect("manifest should exist");
            let schema = m
                .config_schema()
                .ok_or_else(|| {
                    format!(
                        "internal error: helper-needed service {} has no `config_schema`",
                        component_label(s, *id)
                    )
                })?
                .0
                .clone();

            let cfg_template_value = resolved_templates
                .get(id)
                .expect("template exists")
                .to_json_ir();

            let spec = TemplateSpec {
                program: ProgramTemplateSpec {
                    entrypoint: entrypoint_ts,
                    env: env_ts,
                },
            };

            let b64 = base64::engine::general_purpose::STANDARD;

            let spec_json = serde_json::to_vec(&spec).map_err(|e| {
                format!(
                    "failed to serialize template spec for {}: {e}",
                    component_label(s, *id)
                )
            })?;
            let spec_b64 = b64.encode(spec_json);

            let template_json = serde_json::to_vec(&cfg_template_value).map_err(|e| {
                format!(
                    "failed to serialize component config template for {}: {e}",
                    component_label(s, *id)
                )
            })?;
            let template_b64 = b64.encode(template_json);

            let schema_json = serde_json::to_vec(&rc::canonical_json(&schema)).map_err(|e| {
                format!(
                    "failed to serialize component config definition for {}: {e}",
                    component_label(s, *id)
                )
            })?;
            let schema_b64 = b64.encode(schema_json);

            program_mode.insert(
                *id,
                ProgramMode::Helper {
                    template_spec_b64: spec_b64,
                    component_cfg_template_b64: template_b64,
                    component_schema_b64: schema_b64,
                },
            );
        } else {
            // Fully resolved: render to concrete entrypoint/env.
            let mut rendered_entrypoint: Vec<String> = Vec::new();
            for ts in entrypoint_ts {
                rendered_entrypoint.push(render_template_string_static(&ts)?);
            }

            let mut rendered_env: BTreeMap<String, String> = BTreeMap::new();
            for (k, ts) in env_ts {
                rendered_env.insert(k, render_template_string_static(&ts)?);
            }

            program_mode.insert(
                *id,
                ProgramMode::Direct {
                    entrypoint: rendered_entrypoint,
                    env: rendered_env,
                },
            );
        }
    }

    // Root schema payloads + AMBER_CONFIG_* env list are only needed if at least one service uses the helper.
    let mut root_schema_b64: Option<String> = None;
    let mut root_env_entries: Vec<String> = Vec::new();

    if any_helper {
        let root_schema = root_schema.ok_or_else(|| {
            "root component must declare `config_schema` when runtime config interpolation is \
             required"
                .to_string()
        })?;
        let b64 = base64::engine::general_purpose::STANDARD;
        let root_schema_json = serde_json::to_vec(&rc::canonical_json(root_schema))
            .map_err(|e| format!("failed to serialize root config definition: {e}"))?;
        root_schema_b64 = Some(b64.encode(root_schema_json));

        let leafs = rc::collect_leaf_paths(root_schema)
            .map_err(|e| format!("failed to enumerate root config definition leaf paths: {e}"))?;

        for leaf in leafs {
            let var = rc::env_var_for_path(&leaf.path)
                .map_err(|e| format!("failed to map config path {} to env var: {e}", leaf.path))?;
            if leaf.required {
                // Compose-enforced required variable with helpful message.
                root_env_entries.push(format!("{var}=${{{var}?missing config.{}}}", leaf.path));
            } else {
                // Pass-through: can be set or omitted.
                root_env_entries.push(var);
            }
        }
    }

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
    for id in &program_components {
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
        let mode = program_mode.get(id).expect("program mode computed");
        let mut deps: Vec<(String, &'static str)> = Vec::new();
        if any_helper && matches!(mode, ProgramMode::Helper { .. }) {
            deps.push((
                HELPER_INIT_SERVICE.to_string(),
                "service_completed_successfully",
            ));
        }
        deps.push((svc.sidecar.clone(), "service_started"));
        if let Some(ds) = strong_deps.get(id) {
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

        match mode {
            ProgramMode::Direct { entrypoint, env } => {
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
            ProgramMode::Helper {
                template_spec_b64,
                component_cfg_template_b64,
                component_schema_b64,
            } => {
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
                            "AMBER_COMPONENT_CONFIG_SCHEMA_B64={component_schema_b64}"
                        ))
                    ),
                );
                push_line(
                    &mut out,
                    6,
                    &format!(
                        "- {}",
                        yaml_str(&format!(
                            "AMBER_COMPONENT_CONFIG_TEMPLATE_B64={component_cfg_template_b64}"
                        ))
                    ),
                );
                push_line(
                    &mut out,
                    6,
                    &format!(
                        "- {}",
                        yaml_str(&format!("AMBER_TEMPLATE_SPEC_B64={template_spec_b64}"))
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

fn binding_urls_by_scope(
    s: &Scenario,
    manifests: &[Option<Arc<Manifest>>],
    slot_values_by_component: &HashMap<ComponentId, BTreeMap<String, SlotObject>>,
) -> Result<HashMap<u64, BTreeMap<String, BindingObject>>, String> {
    let mut out: HashMap<u64, BTreeMap<String, BindingObject>> = HashMap::new();

    for (idx, manifest) in manifests.iter().enumerate() {
        let Some(manifest) = manifest else {
            continue;
        };
        let realm = ComponentId(idx);
        let mut by_name = BTreeMap::new();

        for (target, binding) in manifest.bindings() {
            let Some(name) = binding.name.as_ref() else {
                continue;
            };

            let (target_component, slot_name) = match target {
                BindingTarget::SelfSlot(slot) => (realm, slot.as_str()),
                BindingTarget::ChildSlot { child, slot } => {
                    let child_id = child_component_id_for_name(s, realm, child.as_str())?;
                    (child_id, slot.as_str())
                }
                _ => {
                    return Err(format!(
                        "unsupported binding target {:?} in {}",
                        target,
                        component_label(s, realm)
                    ));
                }
            };

            let slot_values = slot_values_by_component
                .get(&target_component)
                .ok_or_else(|| {
                    format!(
                        "internal error: missing slot values for {}",
                        component_label(s, target_component)
                    )
                })?;
            let slot = slot_values.get(slot_name).ok_or_else(|| {
                format!(
                    "internal error: missing slot url for {}.{}",
                    component_label(s, target_component),
                    slot_name
                )
            })?;

            by_name.insert(
                name.to_string(),
                BindingObject {
                    url: slot.url.clone(),
                },
            );
        }

        out.insert(realm.0 as u64, by_name);
    }

    Ok(out)
}

fn resolve_binding_templates(
    templates: HashMap<ComponentId, rc::RootConfigTemplate>,
    bindings_by_scope: &HashMap<u64, BTreeMap<String, BindingObject>>,
    s: &Scenario,
) -> Result<HashMap<ComponentId, rc::RootConfigTemplate>, String> {
    let mut out = HashMap::with_capacity(templates.len());
    for (id, template) in templates {
        let resolved = match template {
            rc::RootConfigTemplate::Root => rc::RootConfigTemplate::Root,
            rc::RootConfigTemplate::Node(node) => {
                let resolved =
                    resolve_binding_parts_in_config(&node, bindings_by_scope).map_err(|err| {
                        format!(
                            "failed to resolve binding interpolation in config for {}: {err}",
                            component_label(s, id)
                        )
                    })?;
                rc::RootConfigTemplate::Node(resolved)
            }
        };
        out.insert(id, resolved);
    }
    Ok(out)
}

fn resolve_binding_parts_in_config(
    node: &rc::ConfigNode,
    bindings_by_scope: &HashMap<u64, BTreeMap<String, BindingObject>>,
) -> Result<rc::ConfigNode, String> {
    match node {
        rc::ConfigNode::StringTemplate(parts) => {
            let mut out = Vec::with_capacity(parts.len());
            for part in parts {
                match part {
                    TemplatePart::Lit { lit } => out.push(TemplatePart::lit(lit)),
                    TemplatePart::Config { config } => out.push(TemplatePart::config(config)),
                    TemplatePart::Binding { binding, scope } => {
                        let bindings = bindings_by_scope
                            .get(scope)
                            .ok_or_else(|| format!("bindings scope {scope} is missing"))?;
                        let url = resolve_binding_query(bindings, binding)?;
                        out.push(TemplatePart::lit(url));
                    }
                }
            }
            Ok(rc::ConfigNode::StringTemplate(out).simplify())
        }
        rc::ConfigNode::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(resolve_binding_parts_in_config(item, bindings_by_scope)?);
            }
            Ok(rc::ConfigNode::Array(out))
        }
        rc::ConfigNode::Object(map) => {
            let mut out = BTreeMap::new();
            for (k, v) in map {
                out.insert(
                    k.clone(),
                    resolve_binding_parts_in_config(v, bindings_by_scope)?,
                );
            }
            Ok(rc::ConfigNode::Object(out))
        }
        other => Ok(other.clone()),
    }
}

fn child_component_id_for_name(
    s: &Scenario,
    parent: ComponentId,
    child_name: &str,
) -> Result<ComponentId, String> {
    let parent_component = s.component(parent);
    for child_id in &parent_component.children {
        let child = s.component(*child_id);
        if child.moniker.local_name() == Some(child_name) {
            return Ok(*child_id);
        }
    }
    Err(format!(
        "internal error: missing child {child_name:?} for {}",
        component_label(s, parent)
    ))
}

fn component_label(s: &Scenario, id: ComponentId) -> String {
    s.component(id).moniker.as_str().to_string()
}

fn binding_from_component(from: &BindingFrom) -> &ProvideRef {
    match from {
        BindingFrom::Component(provide) => provide,
        BindingFrom::Framework(name) => {
            unreachable!("framework binding framework.{name} should be rejected earlier")
        }
    }
}

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

fn resolve_provide_endpoint(
    s: &Scenario,
    component_id: ComponentId,
    provide_name: &str,
) -> Result<Endpoint, String> {
    let component = s.component(component_id);

    let provide = component.provides.get(provide_name).ok_or_else(|| {
        format!(
            "provide {}.{} not found (linker invariant broken)",
            component_label(s, component_id),
            provide_name
        )
    })?;

    let program = component.program.as_ref().ok_or_else(|| {
        format!(
            "provide {}.{} requires a program/network, but component has no program",
            component_label(s, component_id),
            provide_name
        )
    })?;

    let network = program.network.as_ref().ok_or_else(|| {
        format!(
            "provide {}.{} requires program.network, but network is missing",
            component_label(s, component_id),
            provide_name
        )
    })?;

    let endpoint_name = provide.endpoint.as_deref().ok_or_else(|| {
        format!(
            "provide {}.{} is missing an endpoint reference",
            component_label(s, component_id),
            provide_name
        )
    })?;

    let endpoint = network
        .endpoints
        .iter()
        .find(|e| e.name == endpoint_name)
        .ok_or_else(|| {
            format!(
                "provide {}.{} references endpoint {:?}, but it was not found in \
                 program.network.endpoints",
                component_label(s, component_id),
                provide_name,
                endpoint_name
            )
        })?;

    Ok(Endpoint {
        name: endpoint.name.clone(),
        port: endpoint.port,
    })
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
