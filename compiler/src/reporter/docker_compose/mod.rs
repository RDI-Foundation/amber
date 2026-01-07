use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt::Write as _,
    net::Ipv4Addr,
};

use amber_scenario::{ComponentId, Scenario};
use miette::LabeledSpan;
use serde_json::Value;

use super::{Reporter, ReporterError};
use crate::CompileOutput;

const MESH_NETWORK_NAME: &str = "amber_mesh";
const MESH_SUBNET: &str = "10.88.0.0/16";
const MESH_GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 1);

const SIDECAR_IMAGE: &str = "ghcr.io/rdi-foundation/amber-sidecar:main";

const LOCAL_PROXY_PORT_BASE: u16 = 20000;
const EXPORT_PORT_BASE: u16 = 18000;

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
    path: String,
}

#[derive(Clone, Debug)]
struct SlotProxy {
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
}

#[derive(Clone, Debug)]
struct SlotValue {
    url: String,
    host: String,
    port: u16,
    path: String,
}

#[derive(Clone, Debug)]
struct ExportMapping {
    export_name: String,
    published_port: u16,
    target_port: u16,
}

#[derive(Debug)]
struct PortPathConflict {
    component: ComponentId,
    port: u16,
    first_provide: String,
    first_endpoint: String,
    first_path: String,
    provide: String,
    endpoint: String,
    path: String,
}

#[derive(Debug)]
enum DockerComposeError {
    Other(String),
    PortPathConflict(Box<PortPathConflict>),
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
            DockerComposeError::PortPathConflict(conflict) => {
                let PortPathConflict {
                    component,
                    port,
                    first_provide,
                    first_endpoint,
                    first_path,
                    provide,
                    endpoint,
                    path,
                } = *conflict;
                let component_moniker = output.scenario.component(component).moniker.as_str();
                let message = format!(
                    "docker-compose output cannot enforce separate capabilities for provides \
                     `{first_provide}` and `{provide}` in component `{component_moniker}`: both \
                     route to port {port} but have different HTTP paths ({first_path} vs {path})"
                );
                let help = "Split the endpoints onto different ports, or route both paths through \
                            an L7 proxy and expose a single provide per port.";

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
                    let span = endpoint
                        .path_span
                        .or(endpoint.port_span)
                        .unwrap_or(endpoint.whole);

                    labels.push(LabeledSpan::new_primary_with_span(
                        Some(format!("path used by provide `{first_provide}`")),
                        span,
                    ));
                    has_primary = true;
                }
                if let Some(endpoint) = endpoint_span(&endpoint) {
                    let span = endpoint
                        .path_span
                        .or(endpoint.port_span)
                        .unwrap_or(endpoint.whole);

                    let label = Some(format!("path used by provide `{provide}`"));
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
    render_docker_compose_inner(&output.scenario).map_err(|err| err.into_reporter_error(output))
}

fn render_docker_compose_inner(s: &Scenario) -> DcResult<String> {
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

    // Precompute service names + sidecar IPs (injective & stable).
    let mut names: HashMap<ComponentId, ServiceNames> = HashMap::new();
    let mut ips: HashMap<ComponentId, Ipv4Addr> = HashMap::new();
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
        ips.insert(*id, sidecar_ipv4(*id)?);
    }

    // Validate: every binding endpoint is between program components.
    for b in &s.bindings {
        if s.component(b.from.component).program.is_none() {
            return Err(format!(
                "binding source {}.{} is not runnable (component has no program)",
                component_label(s, b.from.component),
                b.from.name
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
        if b.from.component == b.to.component {
            continue;
        }
        strong_deps
            .entry(b.to.component)
            .or_default()
            .insert(b.from.component);
    }

    // Allocate stable local proxy ports per (component, slot), avoiding colliding with program listens.
    let slot_ports_by_component = allocate_local_proxy_ports(s, &program_components)?;

    // Build per-component slot-values and per-component slot-proxy processes.
    let mut slot_values_by_component: HashMap<ComponentId, BTreeMap<String, SlotValue>> =
        HashMap::new();
    for id in &program_components {
        slot_values_by_component.insert(*id, BTreeMap::new());
    }
    let mut slot_proxies_by_component: HashMap<ComponentId, Vec<SlotProxy>> = HashMap::new();

    // Inbound allowlist: (provider_component, port) -> set of consumer sidecar IPs
    let mut inbound_allow: HashMap<(ComponentId, u16), BTreeSet<Ipv4Addr>> = HashMap::new();

    // Track (component,port) -> (first_provide_name, first_endpoint_name, first_path) to detect
    // path conflicts on shared ports.
    let mut port_path_owner: HashMap<(ComponentId, u16), (String, String, String)> = HashMap::new();

    for b in &s.bindings {
        let provider = b.from.component;
        let consumer = b.to.component;

        let endpoint = resolve_provide_endpoint(s, provider, &b.from.name)?;

        // Port/path conflict check (L4 backend cannot separate paths on same port).
        enforce_single_path_per_port(
            &mut port_path_owner,
            provider,
            endpoint.port,
            &b.from.name,
            &endpoint.name,
            &endpoint.path,
        )?;

        let consumer_ip = *ips.get(&consumer).ok_or_else(|| {
            format!(
                "internal error: missing sidecar IP for consumer {}",
                component_label(s, consumer)
            )
        })?;
        inbound_allow
            .entry((provider, endpoint.port))
            .or_default()
            .insert(consumer_ip);

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

        let remote_ip = if provider == consumer {
            Ipv4Addr::new(127, 0, 0, 1)
        } else {
            *ips.get(&provider).ok_or_else(|| {
                format!(
                    "internal error: missing sidecar IP for provider {}",
                    component_label(s, provider)
                )
            })?
        };

        slot_proxies_by_component
            .entry(consumer)
            .or_default()
            .push(SlotProxy {
                local_port,
                remote_ip,
                remote_port: endpoint.port,
            });

        let path = normalize_path(&endpoint.path);
        let url = format!("http://127.0.0.1:{local_port}{path}");

        slot_values_by_component
            .entry(consumer)
            .or_default()
            .insert(
                b.to.name.clone(),
                SlotValue {
                    url,
                    host: "127.0.0.1".to_string(),
                    port: local_port,
                    path,
                },
            );
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

    // Scenario exports => publish to host loopback with stable host ports.
    // Also, allow inbound on that target port from host loopback / docker gateway.
    let mut exported_ports: HashMap<ComponentId, BTreeSet<u16>> = HashMap::new();
    let mut exports_by_provider: HashMap<ComponentId, Vec<ExportMapping>> = HashMap::new();
    {
        let mut next_host_port = EXPORT_PORT_BASE;
        for ex in &s.exports {
            let provider = ex.from.component;
            let endpoint = resolve_provide_endpoint(s, provider, &ex.from.name)?;

            enforce_single_path_per_port(
                &mut port_path_owner,
                provider,
                endpoint.port,
                &ex.from.name,
                &endpoint.name,
                &endpoint.path,
            )?;

            let published = next_host_port;
            next_host_port = next_host_port.checked_add(1).ok_or_else(|| {
                "ran out of host ports while allocating scenario exports".to_string()
            })?;

            exported_ports
                .entry(provider)
                .or_default()
                .insert(endpoint.port);

            exports_by_provider
                .entry(provider)
                .or_default()
                .push(ExportMapping {
                    export_name: ex.name.clone(),
                    published_port: published,
                    target_port: endpoint.port,
                });
        }

        // stable ordering
        for v in exports_by_provider.values_mut() {
            v.sort_by(|a, b| a.export_name.cmp(&b.export_name));
        }
    }

    // Compose YAML
    let mut out = String::new();

    writeln!(&mut out, "services:").unwrap();

    let empty_config = Value::Object(Default::default());

    // Emit services in stable (component id) order, sidecar then program.
    for id in &program_components {
        let c = s.component(*id);
        let svc = names.get(id).unwrap();
        let ip = ips.get(id).unwrap();

        // ---- sidecar ----
        push_line(&mut out, 2, &format!("{}:", svc.sidecar));

        push_line(&mut out, 4, &format!("image: {}", yaml_str(SIDECAR_IMAGE)));

        push_line(&mut out, 4, "cap_add:");
        push_line(&mut out, 6, "- NET_ADMIN");
        push_line(&mut out, 4, "cap_drop:");
        push_line(&mut out, 6, "- ALL");
        push_line(&mut out, 4, "security_opt:");
        push_line(&mut out, 6, "- no-new-privileges:true");

        // Networks with static IPv4
        push_line(&mut out, 4, "networks:");
        push_line(&mut out, 6, &format!("{MESH_NETWORK_NAME}:"));
        push_line(&mut out, 8, &format!("ipv4_address: {ip}"));

        // Host port publishes for scenario exports (loopback-only for MVP)
        if let Some(mappings) = exports_by_provider.get(id) {
            push_line(&mut out, 4, "ports:");
            for m in mappings {
                // Published on host loopback only.
                let spec = format!("127.0.0.1:{}:{}", m.published_port, m.target_port);
                push_line(&mut out, 6, &format!("- {}", yaml_str(&spec)));
            }
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
            push_line(&mut out, 8, line);
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

        // depends_on: own sidecar + strong deps provider programs
        let mut depends = Vec::<String>::new();
        depends.push(svc.sidecar.clone());
        if let Some(ds) = strong_deps.get(id) {
            for dep in ds {
                if let Some(dep_names) = names.get(dep) {
                    depends.push(dep_names.program.clone());
                } else {
                    return Err(format!(
                        "internal error: missing service name for dependency {}",
                        component_label(s, *dep)
                    )
                    .into());
                }
            }
        }
        if !depends.is_empty() {
            push_line(&mut out, 4, "depends_on:");
            for d in depends {
                push_line(&mut out, 6, &format!("- {}", d));
            }
        }

        // Render args/env with interpolation.
        let config = c.config.as_ref().unwrap_or(&empty_config);
        let slots = slot_values_by_component.get(id).unwrap();

        let mut rendered_args: Vec<String> = Vec::new();
        for arg in &program.args.0 {
            let raw = arg.to_string();
            let rendered = interpolate_template(&raw, config, slots).map_err(|e| {
                format!(
                    "interpolation error in {} args {:?}: {e}",
                    component_label(s, *id),
                    raw
                )
            })?;
            rendered_args.push(rendered);
        }

        if !rendered_args.is_empty() {
            push_line(&mut out, 4, "command:");
            for a in rendered_args {
                push_line(&mut out, 6, &format!("- {}", yaml_str(&a)));
            }
        }

        // Environment: emit in stable key order
        if !program.env.is_empty() {
            let mut env_sorted: BTreeMap<String, String> = BTreeMap::new();
            for (k, v) in &program.env {
                let raw = v.to_string();
                let rendered = interpolate_template(&raw, config, slots).map_err(|e| {
                    format!(
                        "interpolation error in {} env {}={:?}: {e}",
                        component_label(s, *id),
                        k,
                        raw
                    )
                })?;
                env_sorted.insert(k.clone(), rendered);
            }

            push_line(&mut out, 4, "environment:");
            for (k, v) in env_sorted {
                push_line(&mut out, 6, &format!("{k}: {}", yaml_str(&v)));
            }
        }
    }

    // Networks
    writeln!(&mut out, "networks:").unwrap();
    push_line(&mut out, 2, &format!("{MESH_NETWORK_NAME}:"));
    push_line(&mut out, 4, "driver: bridge");
    push_line(&mut out, 4, "ipam:");
    push_line(&mut out, 6, "config:");
    push_line(&mut out, 8, &format!("- subnet: {MESH_SUBNET}"));

    Ok(out)
}

// ---- helpers ----

fn component_label(s: &Scenario, id: ComponentId) -> String {
    s.component(id).moniker.as_str().to_string()
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
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("component");
    }
    out
}

fn sidecar_ipv4(id: ComponentId) -> Result<Ipv4Addr, String> {
    // Stable mapping within 10.88.0.0/16.
    let offset: u32 = (id.0 as u32)
        .checked_add(10)
        .ok_or_else(|| "component id overflow while assigning sidecar IP".to_string())?;

    if offset >= 65535 {
        return Err(format!(
            "too many components for subnet {MESH_SUBNET}; component id {} overflows",
            id.0
        ));
    }

    let third = (offset / 256) as u8;
    let fourth = (offset % 256) as u8;
    Ok(Ipv4Addr::new(10, 88, third, fourth))
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
        path: endpoint.path.clone(),
    })
}

fn normalize_path(p: &str) -> String {
    let p = p.trim();
    if p.is_empty() {
        return "/".to_string();
    }
    if p.starts_with('/') {
        p.to_string()
    } else {
        format!("/{p}")
    }
}

fn enforce_single_path_per_port(
    owner: &mut HashMap<(ComponentId, u16), (String, String, String)>,
    component: ComponentId,
    port: u16,
    provide_name: &str,
    endpoint_name: &str,
    path: &str,
) -> Result<(), DockerComposeError> {
    let path = normalize_path(path);

    match owner.get(&(component, port)) {
        None => {
            owner.insert(
                (component, port),
                (provide_name.to_string(), endpoint_name.to_string(), path),
            );
            Ok(())
        }
        Some((_first_provide, _first_endpoint, first_path)) if *first_path == path => Ok(()),
        Some((first_provide, first_endpoint, first_path)) => Err(
            DockerComposeError::PortPathConflict(Box::new(PortPathConflict {
                component,
                port,
                first_provide: first_provide.clone(),
                first_endpoint: first_endpoint.clone(),
                first_path: first_path.clone(),
                provide: provide_name.to_string(),
                endpoint: endpoint_name.to_string(),
                path,
            })),
        ),
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

fn interpolate_template(
    template: &str,
    config: &Value,
    slots: &BTreeMap<String, SlotValue>,
) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = template;

    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let tail = &rest[start + 2..];
        let end = tail.find('}').ok_or_else(|| {
            format!(
                "unterminated interpolation starting at: {:?}",
                &rest[start..]
            )
        })?;
        let expr = tail[..end].trim();
        let value = resolve_interpolation_expr(expr, config, slots)?;
        out.push_str(&value);
        rest = &tail[end + 1..];
    }

    out.push_str(rest);
    Ok(out)
}

fn resolve_interpolation_expr(
    expr: &str,
    config: &Value,
    slots: &BTreeMap<String, SlotValue>,
) -> Result<String, String> {
    if let Some(path) = expr.strip_prefix("config.") {
        return resolve_config_path(config, path);
    }
    if let Some(path) = expr.strip_prefix("slots.") {
        return resolve_slots_path(slots, path);
    }
    Err(format!(
        "unsupported interpolation source in ${{{expr}}}; expected config.<path> or slots.<path>"
    ))
}

fn resolve_config_path(config: &Value, path: &str) -> Result<String, String> {
    let mut cur = config;
    for seg in path.split('.') {
        if seg.is_empty() {
            return Err(format!(
                "invalid config path 'config.{path}': empty segment"
            ));
        }
        match cur {
            Value::Object(m) => {
                cur = m
                    .get(seg)
                    .ok_or_else(|| format!("config.{path} not found (missing key {seg:?})"))?;
            }
            _ => {
                return Err(format!(
                    "config.{path} not found (encountered non-object before segment {seg:?})"
                ));
            }
        }
    }

    match cur {
        Value::Null => Err(format!("config.{path} is null; cannot interpolate")),
        Value::String(s) => Ok(s.clone()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Array(_) | Value::Object(_) => serde_json::to_string(cur)
            .map_err(|e| format!("failed to serialize config.{path} as JSON: {e}")),
    }
}

fn resolve_slots_path(slots: &BTreeMap<String, SlotValue>, path: &str) -> Result<String, String> {
    let mut it = path.split('.');
    let slot_name = it
        .next()
        .ok_or_else(|| "invalid slots path: missing slot name".to_string())?;
    let field = it.next().ok_or_else(|| {
        format!("invalid slots.{slot_name} interpolation: expected a field like url")
    })?;

    if it.next().is_some() {
        return Err(format!(
            "unsupported slots interpolation 'slots.{path}': only slots.<slot>.<field> is \
             supported (url/host/port/path)"
        ));
    }

    let slot = slots
        .get(slot_name)
        .ok_or_else(|| format!("slots.{slot_name} not found"))?;

    match field {
        "url" => Ok(slot.url.clone()),
        "host" => Ok(slot.host.clone()),
        "port" => Ok(slot.port.to_string()),
        "path" => Ok(slot.path.clone()),
        other => Err(format!(
            "unsupported slots field slots.{slot_name}.{other} (supported: url/host/port/path)"
        )),
    }
}

fn build_sidecar_script(
    _component: ComponentId,
    inbound: Vec<(u16, &BTreeSet<Ipv4Addr>)>,
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

    // Allow inbound from bound consumers.
    let mut inbound_sorted = inbound;
    inbound_sorted.sort_by_key(|(port, _)| *port);

    for (port, srcs) in inbound_sorted {
        for src in srcs {
            writeln!(
                &mut script,
                "iptables -w -A INPUT -p tcp -s {src} --dport {port} -j ACCEPT"
            )
            .unwrap();
        }
    }

    // Allow inbound from host (exports): loopback + docker gateway.
    if let Some(ports) = exported_ports {
        for port in ports {
            writeln!(
                &mut script,
                "iptables -w -A INPUT -p tcp -s 127.0.0.1 --dport {port} -j ACCEPT"
            )
            .unwrap();
            writeln!(
                &mut script,
                "iptables -w -A INPUT -p tcp -s {MESH_GATEWAY} --dport {port} -j ACCEPT"
            )
            .unwrap();
        }
    }

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
                p.local_port, p.remote_ip, p.remote_port
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

#[cfg(test)]
mod tests;
