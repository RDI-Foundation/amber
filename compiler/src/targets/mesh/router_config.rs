use std::collections::{BTreeMap, BTreeSet};

use amber_manifest::Manifest;
use base64::Engine as _;
use serde::Serialize;

use crate::targets::mesh::plan::ResolvedExternalBinding;

#[derive(Clone, Debug, Serialize)]
pub(crate) struct RouterConfig {
    pub(crate) external_slots: Vec<RouterExternalSlot>,
    pub(crate) exports: Vec<RouterExport>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct RouterExternalSlot {
    pub(crate) name: String,
    pub(crate) listen_port: u16,
    pub(crate) url_env: String,
    pub(crate) optional: bool,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct RouterExport {
    pub(crate) name: String,
    pub(crate) listen_port: u16,
    pub(crate) target_url: String,
}

pub(crate) fn allocate_external_slot_ports(
    bindings: &[ResolvedExternalBinding],
    base_port: u16,
) -> Result<BTreeMap<String, u16>, String> {
    if bindings.is_empty() {
        return Ok(BTreeMap::new());
    }

    let mut slot_names = BTreeSet::new();
    for binding in bindings {
        slot_names.insert(binding.external_slot.clone());
    }

    let mut external_slot_ports = BTreeMap::new();
    let mut next_port = base_port;
    for slot in slot_names {
        external_slot_ports.insert(slot, next_port);
        next_port = next_port
            .checked_add(1)
            .ok_or_else(|| "ran out of router external ports".to_string())?;
    }

    Ok(external_slot_ports)
}

pub(crate) fn build_router_external_slots(
    root_manifest: &Manifest,
    external_slot_ports: &BTreeMap<String, u16>,
) -> Vec<RouterExternalSlot> {
    let mut router_external_slots = Vec::with_capacity(external_slot_ports.len());
    for (slot_name, listen_port) in external_slot_ports {
        let decl = root_manifest
            .slots()
            .get(slot_name.as_str())
            .expect("external slot should exist on root");
        let url_env = external_slot_env_var(slot_name);
        router_external_slots.push(RouterExternalSlot {
            name: slot_name.clone(),
            listen_port: *listen_port,
            url_env,
            optional: decl.optional,
        });
    }

    router_external_slots
}

pub(crate) fn encode_router_config_b64(config: &RouterConfig) -> Result<String, serde_json::Error> {
    let json = serde_json::to_vec(config)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(json))
}

fn external_slot_env_var(slot: &str) -> String {
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
