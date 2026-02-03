use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt::Write as _,
};

use amber_config as rc;
use amber_images::{AMBER_HELPER, AMBER_ROUTER, AMBER_SIDECAR};
use amber_scenario::{ComponentId, Scenario};
use miette::LabeledSpan;
use serde::{Deserialize, Serialize};

use crate::{
    CompileOutput,
    binding_query::BindingObject,
    reporter::{Reporter, ReporterError},
    slot_query::SlotObject,
    targets::mesh::{
        config::{ProgramPlan, encode_helper_payload, encode_schema_b64},
        plan::{MeshOptions, component_label},
        router_config::{
            RouterConfig, RouterExport, RouterExternalSlot, allocate_external_slot_ports,
            build_router_external_slots, encode_router_config_b64,
        },
    },
};

const MESH_NETWORK_NAME: &str = "amber_mesh";

const SIDECAR_IMAGE: &str = AMBER_SIDECAR.reference;
const HELPER_IMAGE: &str = AMBER_HELPER.reference;
const ROUTER_IMAGE: &str = AMBER_ROUTER.reference;
const ROUTER_SERVICE_NAME: &str = "amber-router";
const HELPER_VOLUME_NAME: &str = "amber-helper-bin";
const HELPER_INIT_SERVICE: &str = "amber-init";
const HELPER_BIN_DIR: &str = "/amber/bin";
const HELPER_BIN_PATH: &str = "/amber/bin/amber-helper";

const LOCAL_PROXY_PORT_BASE: u16 = 20000;
const ROUTER_EXTERNAL_PORT_BASE: u16 = 21000;
const ROUTER_EXPORT_PORT_BASE: u16 = 22000;
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

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct DockerComposeFile {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    volumes: BTreeMap<String, EmptyMap>,
    services: BTreeMap<String, Service>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    networks: BTreeMap<String, Network>,
    #[serde(rename = "x-amber", default, skip_serializing_if = "Option::is_none")]
    x_amber: Option<AmberExtension>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct AmberExtension {
    exports: BTreeMap<String, ExportMetadata>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct EmptyMap {}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct Network {
    driver: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct Service {
    image: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    cap_add: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    cap_drop: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    security_opt: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    networks: BTreeMap<String, EmptyMap>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    entrypoint: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    environment: Option<Environment>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    ports: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    volumes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    depends_on: Option<DependsOn>,
    #[serde(skip_serializing_if = "Option::is_none")]
    restart: Option<String>,
}

impl Service {
    fn new(image: impl Into<String>) -> Self {
        Self {
            image: image.into(),
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum Environment {
    List(Vec<String>),
    Map(BTreeMap<String, String>),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum DependsOn {
    List(Vec<String>),
    Conditions(BTreeMap<String, DependsOnCondition>),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct DependsOnCondition {
    condition: String,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
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

    let mesh_plan = crate::targets::mesh::plan::build_mesh_plan(
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
    let needs_router = !mesh_plan.external_bindings.is_empty() || !mesh_plan.exports.is_empty();
    let router_names = ServiceNames {
        program: ROUTER_SERVICE_NAME.to_string(),
        sidecar: format!("{ROUTER_SERVICE_NAME}-net"),
    };

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
    let mut router_inbound_allow: BTreeMap<u16, BTreeSet<String>> = BTreeMap::new();

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

    let root_manifest = mesh_plan.manifests[s.root.0]
        .as_ref()
        .expect("root manifest should exist");

    let external_slot_ports =
        allocate_external_slot_ports(&mesh_plan.external_bindings, ROUTER_EXTERNAL_PORT_BASE)
            .map_err(DockerComposeError::Other)?;

    for binding in &mesh_plan.external_bindings {
        let consumer = binding.consumer;
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

        let remote_port = *external_slot_ports
            .get(&binding.external_slot)
            .ok_or_else(|| {
                format!(
                    "internal error: missing router port for external slot {}",
                    binding.external_slot
                )
            })?;

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
        router_inbound_allow
            .entry(remote_port)
            .or_default()
            .insert(consumer_host);

        slot_proxies_by_component
            .entry(consumer)
            .or_default()
            .push(SlotProxy {
                local_port,
                remote_host: router_names.sidecar.clone(),
                remote_port,
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

    // Scenario exports => publish to host loopback with stable host ports (via router).
    let mut router_export_ports: BTreeSet<u16> = BTreeSet::new();
    let mut export_ports_by_name: BTreeMap<String, u16> = BTreeMap::new();
    let mut exports_by_name: BTreeMap<String, ExportMetadata> = BTreeMap::new();
    {
        let mut next_host_port = EXPORT_PORT_BASE;
        let mut next_router_port = ROUTER_EXPORT_PORT_BASE;
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

            inbound_allow
                .entry((provider, endpoint.port))
                .or_default()
                .insert(router_names.sidecar.clone());

            let published = next_host_port;
            next_host_port = next_host_port.checked_add(1).ok_or_else(|| {
                "ran out of host ports while allocating scenario exports".to_string()
            })?;

            let listen_port = next_router_port;
            next_router_port = next_router_port.checked_add(1).ok_or_else(|| {
                "ran out of router ports while allocating scenario exports".to_string()
            })?;

            router_export_ports.insert(listen_port);
            export_ports_by_name.insert(ex.name.clone(), listen_port);

            let metadata = ExportMetadata {
                published_host: EXPORT_HOST.to_string(),
                published_port: published,
                target_port: endpoint.port,
                component: component_label(s, provider),
                provide: ex.provide.clone(),
                endpoint: endpoint.name.clone(),
            };

            exports_by_name.insert(ex.name.clone(), metadata);
        }
    }

    let mut router_external_slots: Vec<RouterExternalSlot> = Vec::new();
    let mut router_exports: Vec<RouterExport> = Vec::new();
    let mut router_env_passthrough: Vec<String> = Vec::new();
    let mut router_config_b64: Option<String> = None;

    if needs_router {
        router_external_slots = build_router_external_slots(root_manifest, &external_slot_ports);
        router_env_passthrough = router_external_slots
            .iter()
            .map(|slot| slot.url_env.clone())
            .collect();

        for ex in &mesh_plan.exports {
            let listen_port = *export_ports_by_name.get(&ex.name).ok_or_else(|| {
                format!("internal error: missing router port for export {}", ex.name)
            })?;
            let provider_sidecar = names
                .get(&ex.provider)
                .ok_or_else(|| {
                    format!(
                        "internal error: missing sidecar name for export provider {}",
                        component_label(s, ex.provider)
                    )
                })?
                .sidecar
                .clone();
            let target_url = format!("http://{}:{}", provider_sidecar, ex.endpoint.port);
            router_exports.push(RouterExport {
                name: ex.name.clone(),
                listen_port,
                target_url,
            });
        }

        let router_config = RouterConfig {
            external_slots: router_external_slots.clone(),
            exports: router_exports.clone(),
        };
        let b64 = encode_router_config_b64(&router_config)
            .map_err(|err| format!("failed to serialize router config: {err}"))?;
        router_config_b64 = Some(b64);
    }

    // Compose YAML
    // ---- runtime config / helper decision ----
    let config_plan = crate::targets::mesh::config::build_config_plan(
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

    let mut compose = DockerComposeFile::default();

    if any_helper {
        compose
            .volumes
            .insert(HELPER_VOLUME_NAME.to_string(), EmptyMap::default());

        let mut helper_init = Service::new(HELPER_IMAGE);
        helper_init.entrypoint = Some(vec![
            "/amber-helper".to_string(),
            "install".to_string(),
            format!("{HELPER_BIN_DIR}/amber-helper"),
        ]);
        helper_init
            .volumes
            .push(format!("{HELPER_VOLUME_NAME}:{HELPER_BIN_DIR}"));
        helper_init.restart = Some("no".to_string());
        compose
            .services
            .insert(HELPER_INIT_SERVICE.to_string(), helper_init);
    }

    if needs_router {
        let router_inbound: Vec<(u16, &BTreeSet<String>)> = router_inbound_allow
            .iter()
            .map(|(port, srcs)| (*port, srcs))
            .collect();
        let router_script = build_sidecar_script(
            s.root,
            router_inbound,
            if router_export_ports.is_empty() {
                None
            } else {
                Some(&router_export_ports)
            },
            None,
            false,
        );
        let router_script = escape_compose_interpolation(&router_script).into_owned();

        let mut router_sidecar = sidecar_service(router_script);
        if !exports_by_name.is_empty() {
            for (export_name, meta) in &exports_by_name {
                let router_port = export_ports_by_name
                    .get(export_name)
                    .expect("router export port missing");
                let spec = format!(
                    "{}:{}:{}",
                    meta.published_host, meta.published_port, router_port
                );
                router_sidecar.ports.push(spec);
            }

            let labels_json = serde_json::to_string(&exports_by_name)
                .map_err(|err| format!("failed to serialize router export labels: {err}"))?;
            router_sidecar
                .labels
                .insert("amber.exports".to_string(), labels_json);
        }

        compose
            .services
            .insert(router_names.sidecar.clone(), router_sidecar);

        let mut router_program = Service::new(ROUTER_IMAGE);
        router_program.network_mode = Some(format!("service:{}", router_names.sidecar));

        let mut env_entries = router_env_passthrough.clone();
        let router_config_b64 = router_config_b64
            .as_ref()
            .expect("router config should be computed");
        env_entries.push(format!("AMBER_ROUTER_CONFIG_B64={router_config_b64}"));
        router_program.environment = Some(Environment::List(env_entries));

        let mut depends = BTreeMap::new();
        depends.insert(
            router_names.sidecar.clone(),
            DependsOnCondition {
                condition: "service_started".to_string(),
            },
        );
        router_program.depends_on = Some(DependsOn::Conditions(depends));

        compose
            .services
            .insert(router_names.program.clone(), router_program);
    }

    // Emit services in stable (component id) order, sidecar then program.
    for id in program_components {
        let c = s.component(*id);
        let svc = names.get(id).unwrap();

        let script = build_sidecar_script(
            *id,
            inbound_allow
                .iter()
                .filter_map(|((prov, port), srcs)| (*prov == *id).then_some((*port, srcs)))
                .collect(),
            None,
            slot_proxies_by_component.get(id),
            true,
        );
        let script = escape_compose_interpolation(&script).into_owned();
        compose
            .services
            .insert(svc.sidecar.clone(), sidecar_service(script));

        let program = c.program.as_ref().unwrap();
        let mut program_service = Service::new(program.image.as_str());
        program_service.network_mode = Some(format!("service:{}", svc.sidecar));

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
        program_service.depends_on = build_depends_on(any_helper, deps);

        match program_plan {
            ProgramPlan::Direct { entrypoint, env } => {
                // Use entrypoint so image entrypoints are ignored.
                let entrypoint = entrypoint
                    .iter()
                    .map(|a| escape_compose_interpolation(a).into_owned())
                    .collect::<Vec<_>>();
                program_service.entrypoint = Some(entrypoint);

                if !env.is_empty() {
                    let env_map = env
                        .iter()
                        .map(|(k, v)| (k.clone(), escape_compose_interpolation(v).into_owned()))
                        .collect::<BTreeMap<_, _>>();
                    program_service.environment = Some(Environment::Map(env_map));
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
                program_service
                    .volumes
                    .push(format!("{HELPER_VOLUME_NAME}:{HELPER_BIN_DIR}:ro"));
                program_service.entrypoint =
                    Some(vec![HELPER_BIN_PATH.to_string(), "run".to_string()]);

                let mut env_entries = root_env_entries.clone();
                let root_schema_b64 = root_schema_b64.as_ref().expect("helper enabled");
                env_entries.push(format!("AMBER_ROOT_CONFIG_SCHEMA_B64={root_schema_b64}"));
                env_entries.push(format!(
                    "AMBER_COMPONENT_CONFIG_SCHEMA_B64={}",
                    payload.component_schema_b64
                ));
                env_entries.push(format!(
                    "AMBER_COMPONENT_CONFIG_TEMPLATE_B64={}",
                    payload.component_cfg_template_b64
                ));
                env_entries.push(format!(
                    "AMBER_TEMPLATE_SPEC_B64={}",
                    payload.template_spec_b64
                ));
                program_service.environment = Some(Environment::List(env_entries));
            }
        }

        compose
            .services
            .insert(svc.program.clone(), program_service);
    }

    compose.networks.insert(
        MESH_NETWORK_NAME.to_string(),
        Network {
            driver: "bridge".to_string(),
        },
    );

    if !exports_by_name.is_empty() {
        compose.x_amber = Some(AmberExtension {
            exports: exports_by_name.clone(),
        });
    }

    serde_yaml::to_string(&compose).map_err(|e| {
        DockerComposeError::Other(format!("failed to serialize docker-compose yaml: {e}"))
    })
}

// ---- helpers ----

fn sidecar_service(script: String) -> Service {
    let mut service = Service::new(SIDECAR_IMAGE);
    service.cap_add = vec!["NET_ADMIN".to_string()];
    service.cap_drop = vec!["ALL".to_string()];
    service.security_opt = vec!["no-new-privileges:true".to_string()];
    service
        .networks
        .insert(MESH_NETWORK_NAME.to_string(), EmptyMap::default());
    service.command = Some(vec!["/bin/sh".to_string(), "-lc".to_string(), script]);
    service
}

fn build_depends_on(any_helper: bool, deps: Vec<(String, &'static str)>) -> Option<DependsOn> {
    if deps.is_empty() {
        return None;
    }
    if any_helper {
        let mut map = BTreeMap::new();
        for (name, cond) in deps {
            map.insert(
                name,
                DependsOnCondition {
                    condition: cond.to_string(),
                },
            );
        }
        Some(DependsOn::Conditions(map))
    } else {
        Some(DependsOn::List(
            deps.into_iter().map(|(name, _)| name).collect(),
        ))
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
    restrict_egress: bool,
) -> String {
    let mut script = String::new();

    let mut egress_targets: Vec<(String, u16)> = Vec::new();
    if restrict_egress && let Some(ps) = proxies {
        let mut seen: BTreeSet<(String, u16)> = BTreeSet::new();
        for p in ps {
            seen.insert((p.remote_host.clone(), p.remote_port));
        }
        egress_targets.extend(seen);
    }

    // Minimal, explicit, deterministic.
    writeln!(&mut script, "set -eu").unwrap();

    // Firewall baseline
    writeln!(&mut script, "iptables -w -F").unwrap();
    writeln!(&mut script, "iptables -w -X").unwrap();
    writeln!(&mut script, "iptables -w -P INPUT DROP").unwrap();
    writeln!(&mut script, "iptables -w -P FORWARD DROP").unwrap();
    writeln!(
        &mut script,
        "iptables -w -P OUTPUT {}",
        if restrict_egress { "DROP" } else { "ACCEPT" }
    )
    .unwrap();
    writeln!(&mut script, "iptables -w -A INPUT -i lo -j ACCEPT").unwrap();
    writeln!(
        &mut script,
        "iptables -w -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    )
    .unwrap();
    if restrict_egress {
        writeln!(&mut script, "iptables -w -A OUTPUT -o lo -j ACCEPT").unwrap();
        writeln!(
            &mut script,
            "iptables -w -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        )
        .unwrap();
        writeln!(
            &mut script,
            "for ns in $(awk '/^nameserver/{{print $2}}' /etc/resolv.conf | awk '$1 ~ \
             /^[0-9]+(\\.[0-9]+){{3}}$/ {{print $1}}'); do"
        )
        .unwrap();
        writeln!(
            &mut script,
            "  iptables -w -A OUTPUT -p udp -m udp --dport 53 -d \"$ns\" -j ACCEPT"
        )
        .unwrap();
        writeln!(
            &mut script,
            "  iptables -w -A OUTPUT -p tcp -m tcp --dport 53 -d \"$ns\" -j ACCEPT"
        )
        .unwrap();
        writeln!(&mut script, "done").unwrap();
        writeln!(&mut script, "iptables -w -N AMBER-ALLOW-OUT").unwrap();
        writeln!(&mut script, "iptables -w -A OUTPUT -j AMBER-ALLOW-OUT").unwrap();
    }
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
    if restrict_egress {
        writeln!(&mut script, "add_out_rule() {{").unwrap();
        writeln!(&mut script, "  if [ -n \"$1\" ]; then").unwrap();
        writeln!(&mut script, "    printf '%s\\n' \"$1\" >> \"$desired_out\"").unwrap();
        writeln!(&mut script, "  fi").unwrap();
        writeln!(&mut script, "}}").unwrap();
    }
    writeln!(&mut script, "refresh_allowlist() {{").unwrap();
    writeln!(&mut script, "  set +e").unwrap();
    writeln!(&mut script, "  desired_rules=\"/tmp/amber-allowlist\"").unwrap();
    writeln!(&mut script, "  : > \"$desired_rules\"").unwrap();
    if restrict_egress {
        writeln!(&mut script, "  desired_out=\"/tmp/amber-allowlist-out\"").unwrap();
        writeln!(&mut script, "  : > \"$desired_out\"").unwrap();
    }
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
    if restrict_egress {
        for (host, port) in &egress_targets {
            writeln!(&mut script, "  for ip in $(resolve_ipv4 \"{host}\"); do").unwrap();
            writeln!(
                &mut script,
                "    add_out_rule \"-d $ip/32 -p tcp -m tcp --dport {port} -j ACCEPT\""
            )
            .unwrap();
            writeln!(&mut script, "  done").unwrap();
        }
        writeln!(&mut script, "  if [ -s \"$desired_out\" ]; then").unwrap();
        writeln!(&mut script, "    iptables -w -F AMBER-ALLOW-OUT").unwrap();
        writeln!(&mut script, "    while read -r rule; do").unwrap();
        writeln!(&mut script, "      [ -z \"$rule\" ] && continue").unwrap();
        writeln!(&mut script, "      iptables -w -A AMBER-ALLOW-OUT $rule").unwrap();
        writeln!(&mut script, "    done < \"$desired_out\"").unwrap();
        writeln!(&mut script, "  fi").unwrap();
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

fn escape_compose_interpolation<'a>(line: &'a str) -> Cow<'a, str> {
    if line.contains('$') {
        Cow::Owned(line.replace('$', "$$"))
    } else {
        Cow::Borrowed(line)
    }
}

#[cfg(test)]
mod tests;
