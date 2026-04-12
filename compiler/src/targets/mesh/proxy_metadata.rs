use std::collections::BTreeMap;

use amber_manifest::CapabilityKind;
use amber_mesh::{MeshProtocol, router_export_route_id};
use amber_scenario::Scenario;
use serde::{Deserialize, Serialize};

use super::plan::MeshPlan;
use crate::runtime_interface::{collect_exports, collect_external_slots};

pub const PROXY_METADATA_VERSION: &str = "1";
pub const PROXY_METADATA_FILENAME: &str = "amber-proxy.json";
pub const DEFAULT_EXTERNAL_ENV_FILE: &str = "router-external.env";
pub use crate::runtime_interface::external_slot_env_var;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ProxyMetadata {
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router: Option<RouterMetadata>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub exports: BTreeMap<String, ExportMetadata>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub external_slots: BTreeMap<String, ExternalSlotMetadata>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RouterMetadata {
    pub mesh_port: u16,
    pub control_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compose_project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_socket: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_socket_volume: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExportMetadata {
    pub component: String,
    pub provide: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_profile: Option<String>,
    pub protocol: String,
    pub router_mesh_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExternalSlotMetadata {
    pub required: bool,
    pub kind: CapabilityKind,
    pub url_env: String,
}

pub fn build_proxy_metadata(
    scenario: &Scenario,
    mesh_plan: &MeshPlan,
    router: Option<RouterMetadata>,
) -> ProxyMetadata {
    let exports = match router.as_ref() {
        Some(router) => collect_exports_metadata(scenario, mesh_plan, router.mesh_port),
        None => BTreeMap::new(),
    };
    let external_slots = collect_external_slot_metadata(scenario, mesh_plan);

    ProxyMetadata {
        version: PROXY_METADATA_VERSION.to_string(),
        router,
        exports,
        external_slots,
    }
}

pub fn collect_exports_metadata(
    scenario: &Scenario,
    mesh_plan: &MeshPlan,
    router_mesh_port: u16,
) -> BTreeMap<String, ExportMetadata> {
    collect_exports(scenario, mesh_plan)
        .into_iter()
        .map(|(name, export)| {
            let route_protocol = match export.protocol {
                amber_manifest::NetworkProtocol::Http | amber_manifest::NetworkProtocol::Https => {
                    MeshProtocol::Http
                }
                amber_manifest::NetworkProtocol::Tcp => MeshProtocol::Tcp,
                other => panic!("unsupported mesh export protocol in proxy metadata: {other}"),
            };
            let route_id = router_export_route_id(&name, route_protocol);
            (
                name,
                ExportMetadata {
                    component: export.component,
                    provide: export.provide,
                    capability_kind: export.capability_kind,
                    capability_profile: export.capability_profile,
                    protocol: export.protocol.to_string(),
                    router_mesh_port,
                    route_id: Some(route_id),
                },
            )
        })
        .collect()
}

pub fn collect_external_slot_metadata(
    scenario: &Scenario,
    mesh_plan: &MeshPlan,
) -> BTreeMap<String, ExternalSlotMetadata> {
    collect_external_slots(
        scenario,
        mesh_plan
            .external_bindings()
            .map(|binding| binding.external_slot.as_str()),
    )
    .into_iter()
    .map(|(name, slot)| {
        (
            name,
            ExternalSlotMetadata {
                required: slot.required,
                kind: slot.decl.kind,
                url_env: slot.url_env,
            },
        )
    })
    .collect()
}
