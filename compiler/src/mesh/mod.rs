use amber_manifest::NetworkProtocol;
use amber_scenario::Scenario;

pub use crate::targets::mesh::proxy_metadata::{
    DEFAULT_EXTERNAL_ENV_FILE, PROXY_METADATA_FILENAME, PROXY_METADATA_VERSION, ProxyMetadata,
    RouterMetadata, external_slot_env_var,
};
use crate::targets::{
    mesh::plan::{MeshOptions, build_mesh_plan},
    program_config::build_endpoint_plan,
};

#[derive(Clone, Debug)]
pub struct MeshExportInfo {
    pub name: String,
    pub protocol: NetworkProtocol,
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
