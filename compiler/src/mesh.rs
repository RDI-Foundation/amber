use amber_manifest::NetworkProtocol;
use amber_scenario::Scenario;

pub use crate::targets::mesh::proxy_metadata::{
    DEFAULT_EXTERNAL_ENV_FILE, PROXY_METADATA_FILENAME, PROXY_METADATA_VERSION, ProxyMetadata,
    RouterMetadata, external_slot_env_var,
};
use crate::{
    DigestStore,
    targets::mesh::plan::{MeshOptions, build_mesh_plan},
};

#[derive(Clone, Debug)]
pub struct MeshExportInfo {
    pub name: String,
    pub protocol: NetworkProtocol,
}

pub fn mesh_exports(
    scenario: &Scenario,
    store: &DigestStore,
    backend_label: &'static str,
) -> Result<Vec<MeshExportInfo>, String> {
    let plan = build_mesh_plan(scenario, store, MeshOptions { backend_label })
        .map_err(|err| err.to_string())?;
    Ok(plan
        .exports
        .into_iter()
        .map(|ex| MeshExportInfo {
            name: ex.name,
            protocol: ex.endpoint.protocol,
        })
        .collect())
}
