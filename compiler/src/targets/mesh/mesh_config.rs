use std::collections::{BTreeMap, BTreeSet, HashMap};

use amber_manifest::{CapabilityKind, Manifest, NetworkProtocol};
use amber_mesh::{
    HttpRoutePlugin, InboundRoute, InboundTarget, MeshConfigTemplate, MeshIdentityTemplate,
    MeshPeerTemplate, MeshProtocol, OutboundRoute, component_route_id, router_export_route_id,
    router_external_route_id,
};
use amber_scenario::{ComponentId, Scenario};
use base64::Engine as _;
use sha2::Digest as _;

use super::{
    plan::{MeshError, MeshPlan, ResolvedExternalBinding, component_label},
    proxy_metadata::external_slot_env_var,
};

pub(crate) const ROUTER_ID: &str = "/router";

#[derive(Clone, Copy, Debug)]
pub(crate) struct RouterPorts {
    pub(crate) mesh: u16,
    pub(crate) control: u16,
}

#[derive(Clone, Debug)]
pub(crate) struct MeshConfigPlan {
    pub(crate) component_configs: HashMap<ComponentId, MeshConfigTemplate>,
    pub(crate) router_config: Option<MeshConfigTemplate>,
    pub(crate) router_env_passthrough: Vec<String>,
}

pub(crate) trait MeshAddressing {
    fn mesh_addr_for_component(&self, id: ComponentId) -> Result<String, MeshError>;
    fn mesh_addr_for_router(&self) -> Result<String, MeshError>;
}

pub(crate) trait MeshServiceName {
    fn mesh_service_name(&self) -> &str;
}

pub(crate) struct ServiceMeshAddressing<'a, Names> {
    names: &'a HashMap<ComponentId, Names>,
    namespace: Option<&'a str>,
    mesh_ports_by_component: &'a HashMap<ComponentId, u16>,
    router_service_name: &'a str,
    router_mesh_port: u16,
}

impl<'a, Names: MeshServiceName> ServiceMeshAddressing<'a, Names> {
    pub(crate) fn new(
        names: &'a HashMap<ComponentId, Names>,
        namespace: Option<&'a str>,
        mesh_ports_by_component: &'a HashMap<ComponentId, u16>,
        router_service_name: &'a str,
        router_mesh_port: u16,
    ) -> Self {
        Self {
            names,
            namespace,
            mesh_ports_by_component,
            router_service_name,
            router_mesh_port,
        }
    }

    fn format_addr(&self, service: &str, port: u16) -> String {
        match self.namespace {
            Some(namespace) => format!("{service}.{namespace}.svc.cluster.local:{port}"),
            None => format!("{service}:{port}"),
        }
    }
}

impl<Names: MeshServiceName> MeshAddressing for ServiceMeshAddressing<'_, Names> {
    fn mesh_addr_for_component(&self, id: ComponentId) -> Result<String, MeshError> {
        let service_name = self
            .names
            .get(&id)
            .ok_or_else(|| MeshError::new(format!("missing mesh service name for {id:?}")))?
            .mesh_service_name();
        let port = *self
            .mesh_ports_by_component
            .get(&id)
            .ok_or_else(|| MeshError::new(format!("missing mesh port for component {id:?}")))?;
        Ok(self.format_addr(service_name, port))
    }

    fn mesh_addr_for_router(&self) -> Result<String, MeshError> {
        Ok(self.format_addr(self.router_service_name, self.router_mesh_port))
    }
}

pub(crate) fn build_mesh_config_plan(
    scenario: &Scenario,
    mesh_plan: &MeshPlan,
    root_manifest: &Manifest,
    slot_ports_by_component: &HashMap<ComponentId, BTreeMap<String, u16>>,
    mesh_ports_by_component: &HashMap<ComponentId, u16>,
    router_ports: Option<RouterPorts>,
    addressing: &impl MeshAddressing,
) -> Result<MeshConfigPlan, MeshError> {
    let needs_router = !mesh_plan.external_bindings.is_empty() || !mesh_plan.exports.is_empty();
    if needs_router && router_ports.is_none() {
        return Err(MeshError::new("router ports missing"));
    }

    let mesh_scope = scenario_mesh_scope(scenario)?;

    let mut identities_by_component: HashMap<ComponentId, MeshIdentityTemplate> = HashMap::new();
    for id in &mesh_plan.program_components {
        let identity = MeshIdentityTemplate {
            id: scenario.component(*id).moniker.as_str().to_string(),
            mesh_scope: Some(mesh_scope.clone()),
        };
        identities_by_component.insert(*id, identity);
    }

    let router_identity = if needs_router {
        Some(MeshIdentityTemplate {
            id: ROUTER_ID.to_string(),
            mesh_scope: Some(mesh_scope.clone()),
        })
    } else {
        None
    };

    let mut consumers_by_provider: HashMap<(ComponentId, String), BTreeSet<ComponentId>> =
        HashMap::new();
    for binding in &mesh_plan.bindings {
        consumers_by_provider
            .entry((binding.provider, binding.provide.clone()))
            .or_default()
            .insert(binding.consumer);
    }

    let mut external_consumers: HashMap<String, BTreeSet<ComponentId>> = HashMap::new();
    for binding in &mesh_plan.external_bindings {
        external_consumers
            .entry(binding.external_slot.clone())
            .or_default()
            .insert(binding.consumer);
    }

    let mut exported_provides: BTreeSet<(ComponentId, String)> = BTreeSet::new();
    for export in &mesh_plan.exports {
        exported_provides.insert((export.provider, export.provide.clone()));
    }

    let mut component_configs: HashMap<ComponentId, MeshConfigTemplate> = HashMap::new();
    for id in &mesh_plan.program_components {
        let identity = identities_by_component
            .get(id)
            .expect("identity should exist")
            .clone();
        let mesh_port = *mesh_ports_by_component.get(id).ok_or_else(|| {
            MeshError::new(format!(
                "mesh port missing for {}",
                component_label(scenario, *id)
            ))
        })?;

        let mut inbound = Vec::new();
        for (provide_name, provide_decl) in &scenario.component(*id).provides {
            let endpoint = mesh_plan
                .bindings
                .iter()
                .find(|b| b.provider == *id && b.provide == *provide_name)
                .map(|b| b.endpoint.clone())
                .or_else(|| {
                    mesh_plan
                        .exports
                        .iter()
                        .find(|ex| ex.provider == *id && ex.provide == *provide_name)
                        .map(|ex| ex.endpoint.clone())
                });
            let Some(endpoint) = endpoint else {
                continue;
            };

            let mut issuers: BTreeSet<String> = BTreeSet::new();
            if let Some(consumers) = consumers_by_provider.get(&(*id, provide_name.clone())) {
                for consumer in consumers {
                    let consumer_id = identities_by_component
                        .get(consumer)
                        .expect("consumer identity missing")
                        .id
                        .clone();
                    issuers.insert(consumer_id);
                }
            }
            if exported_provides.contains(&(*id, provide_name.clone()))
                && let Some(router_identity) = router_identity.as_ref()
            {
                issuers.insert(router_identity.id.clone());
            }
            if issuers.is_empty() {
                continue;
            }

            let protocol = mesh_protocol(endpoint.protocol)?;
            inbound.push(InboundRoute {
                route_id: component_route_id(&identity.id, provide_name, protocol),
                capability: provide_name.clone(),
                protocol,
                http_plugins: matches!(
                    (provide_decl.decl.kind, protocol),
                    (CapabilityKind::A2a, MeshProtocol::Http)
                )
                .then_some(HttpRoutePlugin::A2a)
                .into_iter()
                .collect(),
                target: InboundTarget::Local {
                    port: endpoint.port,
                },
                allowed_issuers: issuers.into_iter().collect(),
            });
        }

        let mut outbound = Vec::new();
        for binding in &mesh_plan.bindings {
            if binding.consumer != *id {
                continue;
            }
            let slot_ports = slot_ports_by_component.get(id).ok_or_else(|| {
                MeshError::new(format!(
                    "slot ports missing for {}",
                    component_label(scenario, *id)
                ))
            })?;
            let listen_port = *slot_ports.get(&binding.slot).ok_or_else(|| {
                MeshError::new(format!(
                    "slot port missing for {}.{}",
                    component_label(scenario, *id),
                    binding.slot
                ))
            })?;
            let peer_addr = addressing.mesh_addr_for_component(binding.provider)?;
            let peer_id = identities_by_component
                .get(&binding.provider)
                .expect("provider identity missing")
                .id
                .clone();
            let protocol = mesh_protocol(binding.endpoint.protocol)?;
            outbound.push(OutboundRoute {
                route_id: component_route_id(&peer_id, &binding.provide, protocol),
                slot: binding.slot.clone(),
                listen_port,
                listen_addr: None,
                protocol,
                peer_addr,
                peer_id: peer_id.clone(),
                capability: binding.provide.clone(),
            });
        }

        for binding in &mesh_plan.external_bindings {
            if binding.consumer != *id {
                continue;
            }
            let slot_ports = slot_ports_by_component.get(id).ok_or_else(|| {
                MeshError::new(format!(
                    "slot ports missing for {}",
                    component_label(scenario, *id)
                ))
            })?;
            let listen_port = *slot_ports.get(&binding.slot).ok_or_else(|| {
                MeshError::new(format!(
                    "slot port missing for {}.{}",
                    component_label(scenario, *id),
                    binding.slot
                ))
            })?;
            let router_identity = router_identity
                .as_ref()
                .ok_or_else(|| MeshError::new("external bindings require router identity"))?;
            let router_addr = addressing.mesh_addr_for_router()?;
            let protocol = MeshProtocol::Http;
            outbound.push(OutboundRoute {
                route_id: router_external_route_id(&binding.external_slot),
                slot: binding.slot.clone(),
                listen_port,
                listen_addr: None,
                protocol,
                peer_addr: router_addr,
                peer_id: router_identity.id.clone(),
                capability: binding.external_slot.clone(),
            });
        }

        let mesh_listen = format!("0.0.0.0:{mesh_port}").parse().expect("mesh listen");
        let config_peers = required_peers(&identity.id, &inbound, &outbound);

        let config = MeshConfigTemplate {
            identity,
            mesh_listen,
            control_listen: None,
            control_allow: None,
            peers: config_peers,
            inbound,
            outbound,
            transport: amber_mesh::TransportConfig::NoiseIk {},
        };
        component_configs.insert(*id, config);
    }

    let mut router_env_passthrough = Vec::new();
    let router_config = if needs_router {
        let router_identity = router_identity.expect("router identity should exist");
        let router_ports = router_ports.expect("router ports missing");
        let router_mesh_port = router_ports.mesh;
        let mut inbound = Vec::new();

        let external_slots =
            build_router_external_slots(root_manifest, &mesh_plan.external_bindings);
        for slot in &external_slots {
            router_env_passthrough.push(slot.url_env.clone());
            let mut issuers = BTreeSet::new();
            if let Some(consumers) = external_consumers.get(&slot.name) {
                for consumer in consumers {
                    let consumer_id = identities_by_component
                        .get(consumer)
                        .expect("consumer identity missing")
                        .id
                        .clone();
                    issuers.insert(consumer_id);
                }
            }
            if issuers.is_empty() {
                continue;
            }
            inbound.push(InboundRoute {
                route_id: router_external_route_id(&slot.name),
                capability: slot.name.clone(),
                protocol: MeshProtocol::Http,
                http_plugins: Vec::new(),
                target: InboundTarget::External {
                    url_env: slot.url_env.clone(),
                    optional: slot.optional,
                },
                allowed_issuers: issuers.into_iter().collect(),
            });
        }

        for export in &mesh_plan.exports {
            let peer_addr = addressing.mesh_addr_for_component(export.provider)?;
            let peer_id = identities_by_component
                .get(&export.provider)
                .expect("export provider identity missing")
                .id
                .clone();
            let protocol = mesh_protocol(export.endpoint.protocol)?;
            let provider_route_id = component_route_id(&peer_id, &export.provide, protocol);
            inbound.push(InboundRoute {
                route_id: router_export_route_id(&export.name, protocol),
                capability: export.name.clone(),
                protocol,
                http_plugins: Vec::new(),
                target: InboundTarget::MeshForward {
                    peer_addr,
                    peer_id,
                    route_id: provider_route_id,
                    capability: export.provide.clone(),
                },
                allowed_issuers: vec![router_identity.id.clone()],
            });
        }

        let mesh_listen = format!("0.0.0.0:{router_mesh_port}")
            .parse()
            .expect("mesh listen");
        let control_listen = Some(
            format!("0.0.0.0:{}", router_ports.control)
                .parse()
                .expect("control listen"),
        );
        let outbound = Vec::new();
        let config_peers = required_peers(&router_identity.id, &inbound, &outbound);

        Some(MeshConfigTemplate {
            identity: router_identity,
            mesh_listen,
            control_listen,
            control_allow: None,
            peers: config_peers,
            inbound,
            outbound,
            transport: amber_mesh::TransportConfig::NoiseIk {},
        })
    } else {
        None
    };

    Ok(MeshConfigPlan {
        component_configs,
        router_config,
        router_env_passthrough,
    })
}

fn mesh_protocol(protocol: NetworkProtocol) -> Result<MeshProtocol, MeshError> {
    let mapped = match protocol {
        NetworkProtocol::Http | NetworkProtocol::Https => MeshProtocol::Http,
        NetworkProtocol::Tcp => MeshProtocol::Tcp,
        _ => {
            return Err(MeshError::new(
                "unsupported network protocol for mesh routing",
            ));
        }
    };
    Ok(mapped)
}

fn required_peers(
    identity_id: &str,
    inbound: &[InboundRoute],
    outbound: &[OutboundRoute],
) -> Vec<MeshPeerTemplate> {
    let mut peer_ids = BTreeSet::new();
    for route in inbound {
        for issuer in &route.allowed_issuers {
            if issuer != identity_id {
                peer_ids.insert(issuer.clone());
            }
        }
        if let InboundTarget::MeshForward { peer_id, .. } = &route.target
            && peer_id != identity_id
        {
            peer_ids.insert(peer_id.clone());
        }
    }
    for route in outbound {
        if route.peer_id != identity_id {
            peer_ids.insert(route.peer_id.clone());
        }
    }
    peer_ids
        .into_iter()
        .map(|id| MeshPeerTemplate { id })
        .collect()
}

struct RouterExternalSlot {
    name: String,
    url_env: String,
    optional: bool,
}

fn build_router_external_slots(
    root_manifest: &Manifest,
    bindings: &[ResolvedExternalBinding],
) -> Vec<RouterExternalSlot> {
    let mut slot_names = BTreeSet::new();
    for binding in bindings {
        slot_names.insert(binding.external_slot.clone());
    }

    let mut out = Vec::with_capacity(slot_names.len());
    for name in slot_names {
        let decl = root_manifest
            .slots()
            .get(name.as_str())
            .expect("external slot should exist on root");
        out.push(RouterExternalSlot {
            name: name.clone(),
            url_env: external_slot_env_var(&name),
            optional: decl.optional,
        });
    }
    out
}

pub(crate) fn scenario_ir_digest(scenario: &Scenario) -> Result<[u8; 32], MeshError> {
    let ir = amber_scenario::ScenarioIr::from(scenario);
    let json = serde_json::to_vec(&ir)
        .map_err(|err| MeshError::new(format!("failed to serialize scenario IR: {err}")))?;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&json);
    Ok(hasher.finalize().into())
}

fn scenario_mesh_scope(scenario: &Scenario) -> Result<String, MeshError> {
    let digest = scenario_ir_digest(scenario)?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(digest);
    Ok(format!("sha256:{encoded}"))
}
