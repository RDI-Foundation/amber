use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::PathBuf,
};

use amber_manifest::MountSource;
use amber_mesh::{MESH_CONFIG_FILENAME, MESH_IDENTITY_FILENAME, MeshProvisionOutput};
use amber_scenario::{ComponentId, Scenario};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    reporter::{
        CompiledScenario, Reporter, ReporterError,
        execution_guide::{
            GENERATED_ENV_SAMPLE_FILENAME, GENERATED_README_FILENAME, build_execution_guide,
        },
    },
    targets::{
        common::{TargetError as MeshError, component_label},
        mesh::{
            addressing::{
                DockerFrameworkBindingPolicy, LocalAddressing, LocalAddressingOptions,
                build_address_plan,
            },
            mesh_config::{
                MeshAddressing, MeshConfigBuildInput, MeshConfigBuildOptions, RouterPorts,
                build_mesh_config_plan,
            },
            plan::{MeshOptions, MeshPlan, build_mesh_plan, map_program_components},
            provision::build_mesh_provision_plan,
            proxy_metadata::{
                DEFAULT_EXTERNAL_ENV_FILE, PROXY_METADATA_FILENAME, RouterMetadata,
                build_proxy_metadata,
            },
        },
        program_config::{
            ComponentExecutionPlan, ProgramSupport, RuntimeConfigPayload,
            build_component_runtime_plan, build_config_plan,
        },
    },
};

pub const DIRECT_PLAN_VERSION: &str = "1";
pub const DIRECT_PLAN_FILENAME: &str = "direct-plan.json";
pub const RUN_SCRIPT_FILENAME: &str = "run.sh";
pub const MESH_PROVISION_PLAN_FILENAME: &str = "mesh-provision-plan.json";
pub const ROUTER_IDENTITY_ID: &str = "/router/direct";
pub const DIRECT_CONTROL_SOCKET_RELATIVE_PATH: &str = ".amber/control/router-control.sock";

const ROUTER_MESH_DIR: &str = "mesh/router";

#[derive(Clone, Copy, Debug, Default)]
pub struct DirectReporter;

#[derive(Clone, Debug)]
pub struct DirectArtifact {
    pub files: BTreeMap<PathBuf, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectPlan {
    pub version: String,
    pub mesh_provision_plan: String,
    pub startup_order: Vec<usize>,
    pub components: Vec<DirectComponentPlan>,
    #[serde(default, skip_serializing_if = "DirectRuntimeAddressPlan::is_empty")]
    pub runtime_addresses: DirectRuntimeAddressPlan,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router: Option<DirectRouterPlan>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DirectRuntimeAddressPlan {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub slots_by_scope: BTreeMap<usize, BTreeMap<String, DirectRuntimeUrlSource>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub bindings_by_scope: BTreeMap<usize, BTreeMap<String, DirectRuntimeUrlSource>>,
}

impl DirectRuntimeAddressPlan {
    fn is_empty(&self) -> bool {
        self.slots_by_scope.is_empty() && self.bindings_by_scope.is_empty()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectRuntimeUrlSource {
    pub component_id: usize,
    pub slot: String,
    pub scheme: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectComponentPlan {
    pub id: usize,
    pub moniker: String,
    pub log_name: String,
    pub manifest_url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<usize>,
    pub sidecar: DirectSidecarPlan,
    pub program: DirectProgramPlan,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectSidecarPlan {
    pub log_name: String,
    pub mesh_port: u16,
    pub mesh_config_path: String,
    pub mesh_identity_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectProgramPlan {
    pub log_name: String,
    pub work_dir: String,
    pub execution: DirectProgramExecutionPlan,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum DirectProgramExecutionPlan {
    Direct {
        entrypoint: Vec<String>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        env: BTreeMap<String, String>,
    },
    HelperRunner {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        entrypoint_b64: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        env_b64: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        template_spec_b64: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        runtime_config: Option<DirectRuntimeConfigPayload>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mount_spec_b64: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectRuntimeConfigPayload {
    pub root_schema_b64: String,
    pub component_cfg_template_b64: String,
    pub component_schema_b64: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_root_leaf_paths: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectRouterPlan {
    pub identity_id: String,
    pub mesh_port: u16,
    pub control_port: u16,
    pub control_socket_path: String,
    pub mesh_config_path: String,
    pub mesh_identity_path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_passthrough: Vec<String>,
}

#[derive(Clone, Debug)]
struct DirectComponentNames {
    base: String,
    mesh_dir: String,
    work_dir: String,
}

impl Reporter for DirectReporter {
    type Artifact = DirectArtifact;

    fn emit(&self, compiled: &CompiledScenario) -> Result<Self::Artifact, ReporterError> {
        render_direct(compiled)
    }
}

fn render_direct(compiled: &CompiledScenario) -> Result<DirectArtifact, ReporterError> {
    render_direct_inner(compiled).map_err(|err| ReporterError::new(err.to_string()))
}

fn render_direct_inner(compiled: &CompiledScenario) -> Result<DirectArtifact, MeshError> {
    let scenario = compiled.scenario();
    let mesh_plan = build_mesh_plan(
        scenario,
        MeshOptions {
            backend_label: "direct reporter",
        },
    )?;
    let program_components = mesh_plan.program_components.as_slice();
    ensure_direct_mount_sources_supported(scenario, program_components)?;
    ensure_no_endpoint_port_conflicts(scenario, program_components)?;

    let component_names: HashMap<ComponentId, DirectComponentNames> =
        map_program_components(scenario, program_components, |id, local_name| {
            let base = direct_base_name(id, local_name);
            DirectComponentNames {
                mesh_dir: format!("mesh/components/{base}"),
                work_dir: format!("work/components/{base}"),
                base,
            }
        });

    let slot_ports_by_component = placeholder_slot_ports(scenario, program_components);
    let mesh_ports_by_component = placeholder_mesh_ports(program_components);

    let needs_router = !mesh_plan.external_bindings.is_empty() || !mesh_plan.exports.is_empty();
    let router_ports = needs_router.then_some(RouterPorts {
        mesh: 0,
        control: 0,
    });

    let addressing = LocalAddressing::new(
        scenario,
        &slot_ports_by_component,
        LocalAddressingOptions {
            backend_label: "direct reporter",
            docker_binding: DockerFrameworkBindingPolicy::Unsupported {
                reason: "does not support framework.docker bindings",
            },
        },
    );
    let address_plan = build_address_plan(&mesh_plan, addressing)?;
    let config_plan = build_config_plan(
        scenario,
        program_components,
        ProgramSupport::PathOnly {
            backend_label: "direct output",
        },
        crate::targets::program_config::RuntimeAddressResolution::Deferred,
        &address_plan.slot_values_by_component,
        &address_plan.binding_values_by_component,
    )?;
    let runtime_addresses = build_runtime_address_plan(
        scenario,
        &address_plan.slot_values_by_component,
        &address_plan.binding_values_by_component,
        &config_plan.binding_values_by_scope,
    )?;

    let router_mesh_port = router_ports.map_or(0, |ports| ports.mesh);
    let mesh_addressing = LoopbackMeshAddressing {
        mesh_ports_by_component: &mesh_ports_by_component,
        router_mesh_port,
    };
    let mesh_config_plan = build_mesh_config_plan(MeshConfigBuildInput {
        scenario,
        mesh_plan: &mesh_plan,
        slot_ports_by_component: &slot_ports_by_component,
        mesh_ports_by_component: &mesh_ports_by_component,
        router_ports,
        addressing: &mesh_addressing,
        options: MeshConfigBuildOptions {
            router_identity_id: ROUTER_IDENTITY_ID,
            component_mesh_listen_addr: "127.0.0.1",
            router_mesh_listen_addr: "127.0.0.1",
            router_control_listen_addr: "127.0.0.1",
        },
    })?;

    let mesh_provision_plan = build_mesh_provision_plan(
        &mesh_config_plan,
        program_components,
        &component_names,
        |name: &DirectComponentNames| MeshProvisionOutput::Filesystem {
            dir: name.mesh_dir.clone(),
        },
        || MeshProvisionOutput::Filesystem {
            dir: ROUTER_MESH_DIR.to_string(),
        },
        |_router_config| {},
    )?;

    let router_metadata = router_ports.map(|ports| RouterMetadata {
        mesh_port: ports.mesh,
        control_port: 0,
        control_socket: Some(DIRECT_CONTROL_SOCKET_RELATIVE_PATH.to_string()),
        control_socket_volume: None,
    });
    let proxy_metadata =
        needs_router.then_some(build_proxy_metadata(scenario, &mesh_plan, router_metadata));

    let startup_order = topological_startup_order(program_components, &mesh_plan)?;
    let startup_order_ids = startup_order.iter().map(|id| id.0).collect::<Vec<_>>();
    let components = build_component_plans(
        compiled,
        scenario,
        &mesh_plan,
        &config_plan,
        &component_names,
        &mesh_ports_by_component,
        program_components,
    )?;

    let router_plan = router_ports.map(|ports| DirectRouterPlan {
        identity_id: ROUTER_IDENTITY_ID.to_string(),
        mesh_port: ports.mesh,
        control_port: 0,
        control_socket_path: DIRECT_CONTROL_SOCKET_RELATIVE_PATH.to_string(),
        mesh_config_path: mesh_config_relative_path(ROUTER_MESH_DIR),
        mesh_identity_path: mesh_identity_relative_path(ROUTER_MESH_DIR),
        env_passthrough: mesh_config_plan.router_env_passthrough.clone(),
    });

    let direct_plan = DirectPlan {
        version: DIRECT_PLAN_VERSION.to_string(),
        mesh_provision_plan: MESH_PROVISION_PLAN_FILENAME.to_string(),
        startup_order: startup_order_ids,
        components,
        runtime_addresses,
        router: router_plan,
    };

    let mut files = BTreeMap::new();
    files.insert(PathBuf::from(RUN_SCRIPT_FILENAME), render_run_script());
    files.insert(
        PathBuf::from(DIRECT_PLAN_FILENAME),
        serde_json::to_string_pretty(&direct_plan)
            .map_err(|err| MeshError::new(format!("failed to serialize direct plan: {err}")))?,
    );
    files.insert(
        PathBuf::from(MESH_PROVISION_PLAN_FILENAME),
        serde_json::to_string_pretty(&mesh_provision_plan).map_err(|err| {
            MeshError::new(format!("failed to serialize mesh provision plan: {err}"))
        })?,
    );

    if let Some(proxy_metadata) = proxy_metadata {
        files.insert(
            PathBuf::from(PROXY_METADATA_FILENAME),
            serde_json::to_string_pretty(&proxy_metadata).map_err(|err| {
                MeshError::new(format!("failed to serialize proxy metadata: {err}"))
            })?,
        );
    }

    if needs_router && !mesh_config_plan.router_env_passthrough.is_empty() {
        let mut env_content = String::new();
        env_content.push_str("# Router external slot URLs - fill in values before running\n");
        for env_var in mesh_config_plan.router_env_passthrough {
            env_content.push_str(&format!("{env_var}=\n"));
        }
        files.insert(PathBuf::from(DEFAULT_EXTERNAL_ENV_FILE), env_content);
    }

    let execution_guide = build_execution_guide(scenario, &mesh_plan, &config_plan)
        .map_err(|err: ReporterError| MeshError::new(err.to_string()))?;
    files.insert(
        PathBuf::from(GENERATED_ENV_SAMPLE_FILENAME),
        execution_guide.render_env_sample(false, "direct"),
    );
    files.insert(
        PathBuf::from(GENERATED_README_FILENAME),
        execution_guide
            .render_direct_readme(files.contains_key(&PathBuf::from(DEFAULT_EXTERNAL_ENV_FILE))),
    );

    Ok(DirectArtifact { files })
}

fn build_component_plans(
    compiled: &CompiledScenario,
    scenario: &Scenario,
    mesh_plan: &MeshPlan,
    config_plan: &crate::targets::program_config::ConfigPlan,
    component_names: &HashMap<ComponentId, DirectComponentNames>,
    mesh_ports_by_component: &HashMap<ComponentId, u16>,
    program_components: &[ComponentId],
) -> Result<Vec<DirectComponentPlan>, MeshError> {
    let mut out = Vec::with_capacity(program_components.len());
    for id in program_components {
        let component = scenario.component(*id);
        let program_plan = config_plan.program_plans.get(id).ok_or_else(|| {
            MeshError::new(format!(
                "internal error: missing program plan for {}",
                component_label(scenario, *id)
            ))
        })?;
        let runtime_plan = build_component_runtime_plan(
            component.moniker.as_str(),
            program_plan,
            config_plan.mount_specs.get(id).map(Vec::as_slice),
            config_plan.runtime_views.get(id),
            false,
        )?;
        let names = component_names.get(id).ok_or_else(|| {
            MeshError::new(format!(
                "internal error: missing direct component names for {}",
                component.moniker.as_str()
            ))
        })?;
        let mesh_port = *mesh_ports_by_component.get(id).ok_or_else(|| {
            MeshError::new(format!(
                "internal error: missing sidecar mesh port for {}",
                component.moniker.as_str()
            ))
        })?;
        let depends_on = mesh_plan
            .strong_deps
            .get(id)
            .map(|deps| deps.iter().map(|dep| dep.0).collect::<Vec<_>>())
            .unwrap_or_default();

        out.push(DirectComponentPlan {
            id: id.0,
            moniker: component.moniker.as_str().to_string(),
            log_name: names.base.clone(),
            manifest_url: compiled.resolved_url_for_component(*id).to_string(),
            depends_on,
            sidecar: DirectSidecarPlan {
                log_name: format!("{}-sidecar", names.base),
                mesh_port,
                mesh_config_path: mesh_config_relative_path(&names.mesh_dir),
                mesh_identity_path: mesh_identity_relative_path(&names.mesh_dir),
            },
            program: DirectProgramPlan {
                log_name: format!("{}-program", names.base),
                work_dir: names.work_dir.clone(),
                execution: direct_execution_plan(runtime_plan.execution),
            },
        });
    }
    Ok(out)
}

fn direct_execution_plan(execution: ComponentExecutionPlan<'_>) -> DirectProgramExecutionPlan {
    match execution {
        ComponentExecutionPlan::Resolved { entrypoint, env } => {
            DirectProgramExecutionPlan::Direct {
                entrypoint: entrypoint.to_vec(),
                env: env.clone(),
            }
        }
        ComponentExecutionPlan::HelperRunner {
            entrypoint_b64,
            env_b64,
            template_spec_b64,
            runtime_config,
            mount_spec_b64,
        } => DirectProgramExecutionPlan::HelperRunner {
            entrypoint_b64,
            env_b64,
            template_spec_b64,
            runtime_config: runtime_config.map(direct_runtime_config_payload),
            mount_spec_b64,
        },
    }
}

fn direct_runtime_config_payload(payload: RuntimeConfigPayload<'_>) -> DirectRuntimeConfigPayload {
    DirectRuntimeConfigPayload {
        root_schema_b64: payload.root_schema_b64,
        component_cfg_template_b64: payload.component_cfg_template_b64,
        component_schema_b64: payload.component_schema_b64,
        allowed_root_leaf_paths: payload.allowed_root_leaf_paths.iter().cloned().collect(),
    }
}

fn mesh_config_relative_path(dir: &str) -> String {
    format!("{dir}/{MESH_CONFIG_FILENAME}")
}

fn mesh_identity_relative_path(dir: &str) -> String {
    format!("{dir}/{MESH_IDENTITY_FILENAME}")
}

fn render_run_script() -> String {
    r#"#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec amber run "$SCRIPT_DIR" "$@"
"#
    .to_string()
}

fn direct_base_name(id: ComponentId, local_name: &str) -> String {
    let mut out = format!("c{}-", id.0);
    for ch in local_name.chars() {
        let ch = ch.to_ascii_lowercase();
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.ends_with(':') {
        out.pop();
    }
    if out == format!("c{}-", id.0) {
        out.push_str("component");
    }
    out
}

fn ensure_direct_mount_sources_supported(
    scenario: &Scenario,
    program_components: &[ComponentId],
) -> Result<(), MeshError> {
    for id in program_components {
        let component = scenario.component(*id);
        let program = component.program.as_ref().ok_or_else(|| {
            MeshError::new(format!(
                "internal error: missing program for {}",
                component.moniker.as_str()
            ))
        })?;
        for mount in program.mounts() {
            if let MountSource::Framework(capability) = &mount.source {
                return Err(MeshError::new(format!(
                    "component {} uses framework mount source `framework.{}`, which is not \
                     supported by direct output",
                    component.moniker.as_str(),
                    capability.as_str()
                )));
            }
        }
    }
    Ok(())
}

fn ensure_no_endpoint_port_conflicts(
    scenario: &Scenario,
    program_components: &[ComponentId],
) -> Result<(), MeshError> {
    let mut by_port: BTreeMap<u16, Vec<String>> = BTreeMap::new();
    for id in program_components {
        let component = scenario.component(*id);
        let Some(program) = component.program.as_ref() else {
            continue;
        };
        let Some(network) = program.network() else {
            continue;
        };
        for endpoint in &network.endpoints {
            by_port.entry(endpoint.port).or_default().push(format!(
                "{}:{}",
                component.moniker.as_str(),
                endpoint.name
            ));
        }
    }

    let mut conflicts = Vec::new();
    for (port, uses) in by_port {
        if uses.len() > 1 {
            conflicts.push(format!("port {port}: {}", uses.join(", ")));
        }
    }
    if conflicts.is_empty() {
        return Ok(());
    }

    Err(MeshError::new(format!(
        "direct output requires unique program endpoint ports across all components; found \
         conflicts:\n{}",
        conflicts.join("\n")
    )))
}

fn placeholder_slot_ports(
    scenario: &Scenario,
    program_components: &[ComponentId],
) -> HashMap<ComponentId, BTreeMap<String, u16>> {
    let mut out = HashMap::new();
    for id in program_components {
        let mut slot_ports = BTreeMap::new();
        for slot_name in scenario.component(*id).slots.keys() {
            slot_ports.insert(slot_name.clone(), 0);
        }
        out.insert(*id, slot_ports);
    }
    out
}

fn placeholder_mesh_ports(program_components: &[ComponentId]) -> HashMap<ComponentId, u16> {
    let mut out = HashMap::new();
    for id in program_components {
        out.insert(*id, 0);
    }
    out
}

fn build_runtime_address_plan(
    scenario: &Scenario,
    slot_values_by_component: &HashMap<
        ComponentId,
        BTreeMap<String, crate::slot_query::SlotObject>,
    >,
    binding_values_by_component: &HashMap<
        ComponentId,
        BTreeMap<String, crate::binding_query::BindingObject>,
    >,
    binding_values_by_scope: &HashMap<u64, BTreeMap<String, crate::binding_query::BindingObject>>,
) -> Result<DirectRuntimeAddressPlan, MeshError> {
    let mut slots_by_scope = BTreeMap::new();
    for (scope, slots) in slot_values_by_component {
        let mut scope_entries = BTreeMap::new();
        for (slot, value) in slots {
            scope_entries.insert(
                slot.clone(),
                DirectRuntimeUrlSource {
                    component_id: scope.0,
                    slot: slot.clone(),
                    scheme: url_scheme(&value.url)?,
                },
            );
        }
        if !scope_entries.is_empty() {
            slots_by_scope.insert(scope.0, scope_entries);
        }
    }

    let mut bindings_by_scope = BTreeMap::new();
    for (scope, bindings) in binding_values_by_component {
        let component = scenario.component(*scope);
        let scope_entries = bindings_by_scope
            .entry(scope.0)
            .or_insert_with(BTreeMap::new);
        for binding_name in bindings.keys() {
            let slot_ref = component
                .binding_decls
                .get(binding_name.as_str())
                .ok_or_else(|| {
                    MeshError::new(format!(
                        "internal error: missing binding declaration {} in {}",
                        binding_name, component.moniker
                    ))
                })?;
            let slot_url = slot_values_by_component
                .get(&slot_ref.component)
                .and_then(|slots| slots.get(slot_ref.name.as_str()))
                .ok_or_else(|| {
                    MeshError::new(format!(
                        "internal error: missing slot value for {}.{}",
                        component_label(scenario, slot_ref.component),
                        slot_ref.name
                    ))
                })?;
            scope_entries.insert(
                binding_name.clone(),
                DirectRuntimeUrlSource {
                    component_id: slot_ref.component.0,
                    slot: slot_ref.name.clone(),
                    scheme: url_scheme(&slot_url.url)?,
                },
            );
        }
    }

    for (&scope, bindings) in binding_values_by_scope {
        let component = scenario.component(ComponentId(scope as usize));
        let scope_entries = bindings_by_scope
            .entry(scope as usize)
            .or_insert_with(BTreeMap::new);
        for binding_name in bindings.keys() {
            let slot_ref = component
                .binding_decls
                .get(binding_name.as_str())
                .ok_or_else(|| {
                    MeshError::new(format!(
                        "internal error: missing binding declaration {} in {}",
                        binding_name, component.moniker
                    ))
                })?;
            let slot_url = slot_values_by_component
                .get(&slot_ref.component)
                .and_then(|slots| slots.get(slot_ref.name.as_str()))
                .ok_or_else(|| {
                    MeshError::new(format!(
                        "internal error: missing slot value for {}.{}",
                        component_label(scenario, slot_ref.component),
                        slot_ref.name
                    ))
                })?;
            scope_entries.insert(
                binding_name.clone(),
                DirectRuntimeUrlSource {
                    component_id: slot_ref.component.0,
                    slot: slot_ref.name.clone(),
                    scheme: url_scheme(&slot_url.url)?,
                },
            );
        }
    }

    Ok(DirectRuntimeAddressPlan {
        slots_by_scope,
        bindings_by_scope,
    })
}

fn url_scheme(raw: &str) -> Result<String, MeshError> {
    Url::parse(raw)
        .map_err(|err| MeshError::new(format!("invalid direct runtime URL {raw}: {err}")))
        .map(|url| url.scheme().to_string())
}

fn topological_startup_order(
    program_components: &[ComponentId],
    mesh_plan: &MeshPlan,
) -> Result<Vec<ComponentId>, MeshError> {
    let mut indegree: HashMap<ComponentId, usize> = HashMap::new();
    let mut dependents: HashMap<ComponentId, BTreeSet<ComponentId>> = HashMap::new();
    for id in program_components {
        indegree.insert(*id, 0);
    }

    for (consumer, deps) in &mesh_plan.strong_deps {
        if !indegree.contains_key(consumer) {
            continue;
        }
        for dep in deps {
            if !indegree.contains_key(dep) {
                continue;
            }
            *indegree.get_mut(consumer).expect("consumer should exist") += 1;
            dependents.entry(*dep).or_default().insert(*consumer);
        }
    }

    let mut ready: BTreeSet<ComponentId> = indegree
        .iter()
        .filter_map(|(id, &count)| (count == 0).then_some(*id))
        .collect();
    let mut order = Vec::with_capacity(indegree.len());

    while let Some(next) = ready.pop_first() {
        order.push(next);
        if let Some(consumers) = dependents.get(&next) {
            for consumer in consumers {
                let degree = indegree
                    .get_mut(consumer)
                    .expect("consumer indegree should exist");
                *degree -= 1;
                if *degree == 0 {
                    ready.insert(*consumer);
                }
            }
        }
    }

    if order.len() != indegree.len() {
        return Err(MeshError::new(
            "internal error: component dependency graph contains a cycle",
        ));
    }
    Ok(order)
}

struct LoopbackMeshAddressing<'a> {
    mesh_ports_by_component: &'a HashMap<ComponentId, u16>,
    router_mesh_port: u16,
}

impl MeshAddressing for LoopbackMeshAddressing<'_> {
    fn mesh_addr_for_component(&self, id: ComponentId) -> Result<String, MeshError> {
        let port = self
            .mesh_ports_by_component
            .get(&id)
            .ok_or_else(|| MeshError::new(format!("missing mesh port for component {id:?}")))?;
        Ok(format!("127.0.0.1:{port}"))
    }

    fn mesh_addr_for_router(&self) -> Result<String, MeshError> {
        Ok(format!("127.0.0.1:{}", self.router_mesh_port))
    }
}
