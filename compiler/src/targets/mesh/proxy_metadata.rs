use std::collections::{BTreeMap, BTreeSet};

use amber_manifest::Manifest;
use amber_scenario::Scenario;
use serde::{Deserialize, Serialize};

use super::plan::{MeshPlan, component_label};

pub const PROXY_METADATA_VERSION: &str = "2";
pub const PROXY_METADATA_FILENAME: &str = "amber-proxy.json";
pub const DEFAULT_EXTERNAL_ENV_FILE: &str = "router-external.env";

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
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExportMetadata {
    pub component: String,
    pub provide: String,
    pub protocol: String,
    pub router_mesh_port: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExternalSlotMetadata {
    pub required: bool,
    pub kind: String,
    pub url_env: String,
}

pub fn build_proxy_metadata(
    scenario: &Scenario,
    mesh_plan: &MeshPlan,
    root_manifest: &Manifest,
    router: Option<RouterMetadata>,
) -> ProxyMetadata {
    let exports = match router.as_ref() {
        Some(router) => collect_exports_metadata(scenario, mesh_plan, router.mesh_port),
        None => BTreeMap::new(),
    };
    let external_slots = collect_external_slot_metadata(root_manifest, mesh_plan);

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
    let mut exports = BTreeMap::new();
    for ex in &mesh_plan.exports {
        exports.insert(
            ex.name.clone(),
            ExportMetadata {
                component: component_label(scenario, ex.provider),
                provide: ex.provide.clone(),
                protocol: ex.endpoint.protocol.to_string(),
                router_mesh_port,
            },
        );
    }
    exports
}

pub fn collect_external_slot_metadata(
    root_manifest: &Manifest,
    mesh_plan: &MeshPlan,
) -> BTreeMap<String, ExternalSlotMetadata> {
    let mut external_slot_names = BTreeSet::new();
    for binding in &mesh_plan.external_bindings {
        external_slot_names.insert(binding.external_slot.clone());
    }

    let mut external_slots = BTreeMap::new();
    for slot_name in external_slot_names {
        let decl = root_manifest
            .slots()
            .get(slot_name.as_str())
            .expect("external slot should exist on root");
        external_slots.insert(
            slot_name.clone(),
            ExternalSlotMetadata {
                required: !decl.optional,
                kind: format!("{}", decl.decl.kind),
                url_env: external_slot_env_var(&slot_name),
            },
        );
    }

    external_slots
}

pub fn external_slot_env_var(slot: &str) -> String {
    let mut out = String::from("AMBER_EXTERNAL_SLOT_");
    for ch in slot.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }
    out.push_str("_URL");
    out
}
