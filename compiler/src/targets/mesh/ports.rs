use std::{
    collections::{BTreeMap, HashMap, HashSet},
    hash::{Hash, Hasher},
};

use amber_scenario::{ComponentId, Scenario};

use super::plan::{
    MeshError, MeshPlan, ResolvedBinding, ResolvedComponentBinding, ResolvedExternalBinding,
    ResolvedFrameworkBinding, component_label,
};
use crate::targets::program_config::EndpointPlan;

const LOCAL_INTERNAL_PORT_BASE: u16 = 19000;
const LOCAL_SLOT_PORT_BASE: u16 = 20000;

#[derive(Clone, Debug, Default)]
pub(crate) struct LocalRoutePorts {
    slot_ports_by_component: HashMap<ComponentId, BTreeMap<String, u16>>,
    reserved_ports_by_component: HashMap<ComponentId, Vec<u16>>,
    dynamic_caps_ports_by_component: HashMap<ComponentId, u16>,
    component_binding_ports: HashMap<BindingIdentity<ResolvedComponentBinding>, u16>,
    external_binding_ports: HashMap<BindingIdentity<ResolvedExternalBinding>, u16>,
    framework_binding_ports: HashMap<BindingIdentity<ResolvedFrameworkBinding>, u16>,
}

impl LocalRoutePorts {
    pub(crate) fn slot_port(&self, component: ComponentId, slot: &str) -> Option<u16> {
        self.slot_ports_by_component
            .get(&component)
            .and_then(|ports| ports.get(slot))
            .copied()
    }

    pub(crate) fn reserved_ports(&self, component: ComponentId) -> &[u16] {
        self.reserved_ports_by_component
            .get(&component)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub(crate) fn dynamic_caps_port(&self, component: ComponentId) -> Option<u16> {
        self.dynamic_caps_ports_by_component
            .get(&component)
            .copied()
    }

    pub(crate) fn component_binding_port(&self, binding: &ResolvedComponentBinding) -> Option<u16> {
        self.component_binding_ports
            .get(&BindingIdentity::from(binding))
            .copied()
    }

    pub(crate) fn external_binding_port(&self, binding: &ResolvedExternalBinding) -> Option<u16> {
        self.external_binding_ports
            .get(&BindingIdentity::from(binding))
            .copied()
    }

    pub(crate) fn framework_binding_port(&self, binding: &ResolvedFrameworkBinding) -> Option<u16> {
        self.framework_binding_ports
            .get(&BindingIdentity::from(binding))
            .copied()
    }
}

#[derive(Clone, Copy, Debug)]
struct BindingIdentity<T>(*const T);

impl<T> From<&T> for BindingIdentity<T> {
    fn from(value: &T) -> Self {
        Self(value as *const T)
    }
}

impl<T> PartialEq for BindingIdentity<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T> Eq for BindingIdentity<T> {}

impl<T> Hash for BindingIdentity<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

struct ComponentRoutePortAllocator {
    reserved: HashSet<u16>,
    internal_next: u16,
    slot_next: u16,
    slot_ports: BTreeMap<String, Vec<u16>>,
}

impl ComponentRoutePortAllocator {
    fn new(endpoint_plan: &EndpointPlan, component_id: ComponentId) -> Self {
        let mut reserved = HashSet::new();
        for endpoint in endpoint_plan.component_endpoints(component_id) {
            reserved.insert(endpoint.port);
        }

        Self {
            reserved,
            internal_next: LOCAL_INTERNAL_PORT_BASE,
            slot_next: LOCAL_SLOT_PORT_BASE,
            slot_ports: BTreeMap::new(),
        }
    }

    fn allocate(
        &mut self,
        scenario: &Scenario,
        component_id: ComponentId,
        slot_name: &str,
    ) -> Result<u16, MeshError> {
        while self.reserved.contains(&self.slot_next) {
            self.slot_next = self.slot_next.checked_add(1).ok_or_else(|| {
                MeshError::new(format!(
                    "ran out of local slot ports allocating for {}",
                    component_label(scenario, component_id)
                ))
            })?;
        }

        let port = self.slot_next;
        self.reserved.insert(port);
        self.slot_ports
            .entry(slot_name.to_string())
            .or_default()
            .push(port);
        self.slot_next = self.slot_next.checked_add(1).ok_or_else(|| {
            MeshError::new(format!(
                "ran out of local slot ports allocating for {}",
                component_label(scenario, component_id)
            ))
        })?;
        Ok(port)
    }

    fn allocate_reserved(
        &mut self,
        scenario: &Scenario,
        component_id: ComponentId,
        purpose: &str,
    ) -> Result<u16, MeshError> {
        while self.reserved.contains(&self.internal_next) {
            self.internal_next = self.internal_next.checked_add(1).ok_or_else(|| {
                MeshError::new(format!(
                    "ran out of local reserved ports allocating {purpose} for {}",
                    component_label(scenario, component_id)
                ))
            })?;
        }
        if self.internal_next >= LOCAL_SLOT_PORT_BASE {
            return Err(MeshError::new(format!(
                "ran out of local internal ports allocating {purpose} for {}",
                component_label(scenario, component_id)
            )));
        }

        let port = self.internal_next;
        self.reserved.insert(port);
        self.internal_next = self.internal_next.checked_add(1).ok_or_else(|| {
            MeshError::new(format!(
                "ran out of local reserved ports allocating {purpose} for {}",
                component_label(scenario, component_id)
            ))
        })?;
        Ok(port)
    }

    fn finish(self) -> (Vec<u16>, BTreeMap<String, u16>) {
        let mut reserved_ports: Vec<u16> = self.reserved.into_iter().collect();
        reserved_ports.sort_unstable();

        let slot_ports = self
            .slot_ports
            .into_iter()
            .filter_map(|(slot, ports)| match ports.as_slice() {
                [port] => Some((slot, *port)),
                _ => None,
            })
            .collect();

        (reserved_ports, slot_ports)
    }
}

pub(crate) fn allocate_local_route_ports(
    scenario: &Scenario,
    endpoint_plan: &EndpointPlan,
    mesh_plan: &MeshPlan,
) -> Result<LocalRoutePorts, MeshError> {
    let mut out = LocalRoutePorts::default();

    for id in mesh_plan.program_components() {
        let mut allocator = ComponentRoutePortAllocator::new(endpoint_plan, *id);
        let dynamic_caps_port = allocator.allocate_reserved(scenario, *id, "dynamic caps api")?;

        for binding in mesh_plan.bindings_for_consumer(*id) {
            let port = allocator.allocate(scenario, *id, binding.slot())?;
            match binding {
                ResolvedBinding::Component(binding) => {
                    out.component_binding_ports
                        .insert(BindingIdentity::from(binding), port);
                }
                ResolvedBinding::External(binding) => {
                    out.external_binding_ports
                        .insert(BindingIdentity::from(binding), port);
                }
                ResolvedBinding::Framework(binding) => {
                    out.framework_binding_ports
                        .insert(BindingIdentity::from(binding), port);
                }
            }
        }

        let (reserved_ports, slot_ports) = allocator.finish();
        out.dynamic_caps_ports_by_component
            .insert(*id, dynamic_caps_port);
        out.reserved_ports_by_component.insert(*id, reserved_ports);
        out.slot_ports_by_component.insert(*id, slot_ports);
    }

    Ok(out)
}

pub(crate) fn placeholder_local_route_ports(
    scenario: &Scenario,
    endpoint_plan: &EndpointPlan,
    mesh_plan: &MeshPlan,
) -> LocalRoutePorts {
    let mut out = LocalRoutePorts::default();

    for id in mesh_plan.program_components() {
        let mut allocator = ComponentRoutePortAllocator::new(endpoint_plan, *id);
        let dynamic_caps_port = allocator
            .allocate_reserved(scenario, *id, "dynamic caps api")
            .expect("dynamic caps api port allocation should not overflow");

        for binding in mesh_plan.bindings_for_consumer(*id) {
            let port = allocator
                .allocate(scenario, *id, binding.slot())
                .expect("local route port allocation should not overflow");
            match binding {
                ResolvedBinding::Component(binding) => {
                    out.component_binding_ports
                        .insert(BindingIdentity::from(binding), port);
                }
                ResolvedBinding::External(binding) => {
                    out.external_binding_ports
                        .insert(BindingIdentity::from(binding), port);
                }
                ResolvedBinding::Framework(binding) => {
                    out.framework_binding_ports
                        .insert(BindingIdentity::from(binding), port);
                }
            }
        }

        let (reserved, slot_ports) = allocator.finish();
        out.dynamic_caps_ports_by_component
            .insert(*id, dynamic_caps_port);
        out.reserved_ports_by_component.insert(*id, reserved);
        out.slot_ports_by_component.insert(*id, slot_ports);
    }

    out
}

pub(crate) fn allocate_mesh_ports(
    scenario: &Scenario,
    endpoint_plan: &EndpointPlan,
    program_components: &[ComponentId],
    base_port: u16,
    route_ports: &LocalRoutePorts,
) -> Result<HashMap<ComponentId, u16>, MeshError> {
    let mut out: HashMap<ComponentId, u16> = HashMap::new();

    for id in program_components {
        let mut reserved: HashSet<u16> = HashSet::new();
        for endpoint in endpoint_plan.component_endpoints(*id) {
            reserved.insert(endpoint.port);
        }
        for &port in route_ports.reserved_ports(*id) {
            reserved.insert(port);
        }

        let mut next = base_port;
        while reserved.contains(&next) {
            next = next.checked_add(1).ok_or_else(|| {
                MeshError::new(format!(
                    "ran out of mesh ports allocating for {}",
                    component_label(scenario, *id)
                ))
            })?;
        }
        out.insert(*id, next);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use amber_manifest::{FrameworkCapabilityName, ManifestDigest};
    use amber_scenario::{BindingEdge, Component, Moniker, Scenario};

    use super::*;
    use crate::targets::{
        mesh::plan::{
            EndpointInfo, MeshPlan, ResolvedBinding, ResolvedComponentBinding,
            ResolvedExternalBinding, ResolvedFrameworkBinding,
        },
        program_config::build_endpoint_plan,
    };

    fn component(id: usize, moniker: &str, program: serde_json::Value) -> Component {
        Component {
            id: ComponentId(id),
            parent: None,
            moniker: Moniker::from(Arc::<str>::from(moniker)),
            digest: ManifestDigest::new([id as u8; 32]),
            config: None,
            config_schema: None,
            program: serde_json::from_value(program).ok(),
            slots: BTreeMap::new(),
            provides: BTreeMap::new(),
            resources: BTreeMap::new(),
            metadata: None,
            child_templates: BTreeMap::new(),
            children: Vec::new(),
        }
    }

    #[test]
    fn allocate_local_route_ports_keeps_duplicate_repeated_bindings_distinct() {
        let mut consumer = component(
            0,
            "/consumer",
            serde_json::json!({
                "image": "consumer",
                "entrypoint": ["consumer"],
            }),
        );
        consumer.slots.insert(
            "upstream".to_string(),
            serde_json::from_value(serde_json::json!({
                "kind": "http",
                "optional": true,
                "multiple": true,
            }))
            .expect("slot decl"),
        );

        let mut provider = component(
            1,
            "/provider",
            serde_json::json!({
                "image": "provider",
                "entrypoint": ["provider"],
                "network": { "endpoints": [{ "name": "api", "port": 80 }] },
            }),
        );
        provider.provides.insert(
            "api".to_string(),
            serde_json::from_value(serde_json::json!({
                "kind": "http",
                "endpoint": "api",
            }))
            .expect("provide decl"),
        );

        let scenario = Scenario {
            root: ComponentId(0),
            components: vec![Some(consumer), Some(provider)],
            bindings: Vec::<BindingEdge>::new(),
            exports: Vec::new(),
            manifest_catalog: BTreeMap::new(),
        };

        let mesh_plan = MeshPlan::new(
            vec![ComponentId(0), ComponentId(1)],
            vec![
                ResolvedBinding::Component(ResolvedComponentBinding {
                    provider: ComponentId(1),
                    consumer: ComponentId(0),
                    provide: "api".to_string(),
                    endpoint: EndpointInfo {
                        port: 80,
                        protocol: amber_manifest::NetworkProtocol::Http,
                    },
                    slot: "upstream".to_string(),
                    weak: false,
                }),
                ResolvedBinding::Component(ResolvedComponentBinding {
                    provider: ComponentId(1),
                    consumer: ComponentId(0),
                    provide: "api".to_string(),
                    endpoint: EndpointInfo {
                        port: 80,
                        protocol: amber_manifest::NetworkProtocol::Http,
                    },
                    slot: "upstream".to_string(),
                    weak: false,
                }),
            ],
            Vec::new(),
            HashMap::new(),
        );

        let endpoint_plan = build_endpoint_plan(&scenario).expect("endpoint plan");
        let route_ports = allocate_local_route_ports(&scenario, &endpoint_plan, &mesh_plan)
            .expect("local route ports");
        let ResolvedBinding::Component(first) = &mesh_plan.bindings()[0] else {
            panic!("expected component binding");
        };
        let ResolvedBinding::Component(second) = &mesh_plan.bindings()[1] else {
            panic!("expected component binding");
        };

        assert_eq!(route_ports.component_binding_port(first), Some(20000));
        assert_eq!(route_ports.component_binding_port(second), Some(20001));
        assert_eq!(route_ports.slot_port(ComponentId(0), "upstream"), None);
    }

    #[test]
    fn placeholder_local_route_ports_preserve_authored_binding_order() {
        let mut root = component(
            0,
            "/",
            serde_json::json!({
                "image": "root",
                "entrypoint": ["root"],
            }),
        );
        root.slots.insert(
            "ext".to_string(),
            serde_json::from_value(serde_json::json!({
                "kind": "http",
                "optional": true,
            }))
            .expect("root slot decl"),
        );

        let mut consumer = component(
            1,
            "/consumer",
            serde_json::json!({
                "image": "consumer",
                "entrypoint": ["consumer"],
                "network": { "endpoints": [{ "name": "reserved", "port": 20000 }] },
            }),
        );
        consumer.slots.insert(
            "upstream".to_string(),
            serde_json::from_value(serde_json::json!({
                "kind": "http",
                "optional": true,
                "multiple": true,
            }))
            .expect("slot decl"),
        );

        let mut provider = component(
            2,
            "/provider",
            serde_json::json!({
                "image": "provider",
                "entrypoint": ["provider"],
                "network": { "endpoints": [{ "name": "api", "port": 80 }] },
            }),
        );
        provider.provides.insert(
            "api".to_string(),
            serde_json::from_value(serde_json::json!({
                "kind": "http",
                "endpoint": "api",
            }))
            .expect("provide decl"),
        );

        let scenario = Scenario {
            root: ComponentId(0),
            components: vec![Some(root), Some(consumer), Some(provider)],
            bindings: Vec::<BindingEdge>::new(),
            exports: Vec::new(),
            manifest_catalog: BTreeMap::new(),
        };

        let mesh_plan = MeshPlan::new(
            vec![ComponentId(0), ComponentId(1), ComponentId(2)],
            vec![
                ResolvedBinding::Framework(ResolvedFrameworkBinding {
                    consumer: ComponentId(1),
                    slot: "upstream".to_string(),
                    authority_realm: ComponentId(0),
                    capability: FrameworkCapabilityName::try_from("docker")
                        .expect("framework capability"),
                }),
                ResolvedBinding::External(ResolvedExternalBinding {
                    consumer: ComponentId(1),
                    slot: "upstream".to_string(),
                    external_slot: "ext".to_string(),
                }),
                ResolvedBinding::Component(ResolvedComponentBinding {
                    provider: ComponentId(2),
                    consumer: ComponentId(1),
                    provide: "api".to_string(),
                    endpoint: EndpointInfo {
                        port: 80,
                        protocol: amber_manifest::NetworkProtocol::Http,
                    },
                    slot: "upstream".to_string(),
                    weak: false,
                }),
            ],
            Vec::new(),
            HashMap::new(),
        );

        let endpoint_plan = build_endpoint_plan(&scenario).expect("endpoint plan");
        let route_ports = placeholder_local_route_ports(&scenario, &endpoint_plan, &mesh_plan);
        let ResolvedBinding::Framework(first) = &mesh_plan.bindings()[0] else {
            panic!("expected framework binding");
        };
        let ResolvedBinding::External(second) = &mesh_plan.bindings()[1] else {
            panic!("expected external binding");
        };
        let ResolvedBinding::Component(third) = &mesh_plan.bindings()[2] else {
            panic!("expected component binding");
        };

        assert_eq!(route_ports.framework_binding_port(first), Some(20001));
        assert_eq!(route_ports.external_binding_port(second), Some(20002));
        assert_eq!(route_ports.component_binding_port(third), Some(20003));
        assert_eq!(route_ports.slot_port(ComponentId(1), "upstream"), None);
    }
}
