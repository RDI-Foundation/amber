use amber_manifest::NetworkProtocol;
use amber_scenario::Scenario;

pub use crate::targets::mesh::proxy_metadata::{
    DEFAULT_EXTERNAL_ENV_FILE, PROXY_METADATA_FILENAME, PROXY_METADATA_VERSION, ProxyMetadata,
    RouterMetadata, external_slot_env_var,
};
use crate::targets::{
    mesh::{
        plan::{MeshOptions, build_mesh_plan},
        ports::allocate_local_route_ports,
    },
    program_config::build_endpoint_plan,
};

#[derive(Clone, Debug)]
pub struct MeshExportInfo {
    pub name: String,
    pub protocol: NetworkProtocol,
}

#[derive(Clone, Debug)]
pub struct MeshFrameworkBindingInfo {
    pub consumer_component_id: usize,
    pub consumer_moniker: String,
    pub slot: String,
    pub capability: String,
    pub capability_kind: String,
    pub capability_profile: Option<String>,
    pub authority_realm_id: usize,
    pub authority_realm_moniker: String,
    pub listen_port: u16,
}

pub fn mesh_exports(
    scenario: &Scenario,
    backend_label: &'static str,
) -> Result<Vec<MeshExportInfo>, String> {
    let endpoint_plan = build_endpoint_plan(scenario).map_err(|err| err.to_string())?;
    let plan = build_mesh_plan(scenario, &endpoint_plan, MeshOptions { backend_label })
        .map_err(|err| err.to_string())?;
    Ok(plan
        .exports()
        .iter()
        .map(|ex| MeshExportInfo {
            name: ex.name.clone(),
            protocol: ex.endpoint.protocol,
        })
        .collect())
}

pub fn framework_binding_routes(
    scenario: &Scenario,
    backend_label: &'static str,
) -> Result<Vec<MeshFrameworkBindingInfo>, String> {
    let endpoint_plan = build_endpoint_plan(scenario).map_err(|err| err.to_string())?;
    let plan = build_mesh_plan(scenario, &endpoint_plan, MeshOptions { backend_label })
        .map_err(|err| err.to_string())?;
    let route_ports = allocate_local_route_ports(scenario, &endpoint_plan, &plan)
        .map_err(|err| err.to_string())?;

    plan.bindings()
        .iter()
        .filter_map(|binding| binding.as_framework())
        .map(|binding| {
            let slot_decl = scenario
                .component(binding.consumer)
                .slots
                .get(binding.slot.as_str())
                .ok_or_else(|| {
                    format!(
                        "framework binding {}.{} is missing its target slot",
                        scenario.component(binding.consumer).moniker,
                        binding.slot
                    )
                })?;
            let listen_port = route_ports.framework_binding_port(binding).ok_or_else(|| {
                format!(
                    "framework binding {}.{} is missing its local route port",
                    scenario.component(binding.consumer).moniker,
                    binding.slot
                )
            })?;
            Ok(MeshFrameworkBindingInfo {
                consumer_component_id: binding.consumer.0,
                consumer_moniker: scenario.component(binding.consumer).moniker.to_string(),
                slot: binding.slot.clone(),
                capability: binding.capability.to_string(),
                capability_kind: slot_decl.decl.kind.to_string(),
                capability_profile: slot_decl.decl.profile.clone(),
                authority_realm_id: binding.authority_realm.0,
                authority_realm_moniker: scenario
                    .component(binding.authority_realm)
                    .moniker
                    .to_string(),
                listen_port,
            })
        })
        .collect()
}
