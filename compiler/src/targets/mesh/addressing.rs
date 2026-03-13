use std::collections::{BTreeMap, BTreeSet, HashMap};

use amber_manifest::NetworkProtocol;
use amber_scenario::{ComponentId, Scenario};

use crate::{
    slot_query::{SlotObject, SlotValue},
    targets::mesh::{
        plan::{
            MeshError, MeshPlan, ResolvedBinding, ResolvedComponentBinding,
            ResolvedExternalBinding, ResolvedFrameworkBinding, component_label,
        },
        ports::LocalRoutePorts,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum WorkloadId {
    Component(ComponentId),
    Router,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct AllowPlan {
    pub(crate) by_provider: HashMap<WorkloadId, BTreeMap<u16, BTreeSet<WorkloadId>>>,
}

impl AllowPlan {
    pub(crate) fn allow(&mut self, provider: WorkloadId, consumer: WorkloadId, port: u16) {
        if provider == consumer {
            return;
        }
        self.by_provider
            .entry(provider)
            .or_default()
            .entry(port)
            .or_default()
            .insert(consumer);
    }

    pub(crate) fn for_component(
        &self,
        component: ComponentId,
    ) -> Option<&BTreeMap<u16, BTreeSet<WorkloadId>>> {
        self.by_provider.get(&WorkloadId::Component(component))
    }

    pub(crate) fn for_router(&self) -> Option<&BTreeMap<u16, BTreeSet<WorkloadId>>> {
        self.by_provider.get(&WorkloadId::Router)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct MeshAddressPlan {
    pub(crate) slot_values_by_component: HashMap<ComponentId, BTreeMap<String, SlotValue>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DockerFrameworkBindingPolicy {
    LoopbackTcp,
    Unsupported { reason: &'static str },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LocalAddressingOptions {
    pub(crate) backend_label: &'static str,
    pub(crate) docker_binding: DockerFrameworkBindingPolicy,
}

pub(crate) struct LocalAddressing<'a> {
    scenario: &'a Scenario,
    route_ports: &'a LocalRoutePorts,
    options: LocalAddressingOptions,
}

impl<'a> LocalAddressing<'a> {
    pub(crate) fn new(
        scenario: &'a Scenario,
        route_ports: &'a LocalRoutePorts,
        options: LocalAddressingOptions,
    ) -> Self {
        Self {
            scenario,
            route_ports,
            options,
        }
    }

    fn local_component_binding_port(
        &self,
        binding: &ResolvedComponentBinding,
    ) -> Result<u16, MeshError> {
        self.route_ports
            .component_binding_port(binding)
            .ok_or_else(|| {
                MeshError::new(format!(
                    "internal error: missing local route port allocation for {}.{}",
                    component_label(self.scenario, binding.consumer),
                    binding.slot
                ))
            })
    }

    fn local_external_binding_port(
        &self,
        binding: &ResolvedExternalBinding,
    ) -> Result<u16, MeshError> {
        self.route_ports
            .external_binding_port(binding)
            .ok_or_else(|| {
                MeshError::new(format!(
                    "internal error: missing local route port allocation for {}.{}",
                    component_label(self.scenario, binding.consumer),
                    binding.slot
                ))
            })
    }

    fn local_framework_binding_port(
        &self,
        binding: &ResolvedFrameworkBinding,
    ) -> Result<u16, MeshError> {
        self.route_ports
            .framework_binding_port(binding)
            .ok_or_else(|| {
                MeshError::new(format!(
                    "internal error: missing local route port allocation for {}.{}",
                    component_label(self.scenario, binding.consumer),
                    binding.slot
                ))
            })
    }

    fn unsupported_framework_error(&self, capability: &str) -> MeshError {
        MeshError::new(format!(
            "{} does not support framework capability `framework.{capability}`",
            self.options.backend_label
        ))
    }
}

pub(crate) trait Addressing {
    type Error: From<MeshError>;

    fn resolve_component_binding_url(
        &mut self,
        binding: &ResolvedComponentBinding,
    ) -> Result<String, Self::Error>;
    fn resolve_external_binding_url(
        &mut self,
        binding: &ResolvedExternalBinding,
    ) -> Result<String, Self::Error>;
    fn resolve_framework_binding_url(
        &mut self,
        binding: &ResolvedFrameworkBinding,
    ) -> Result<String, Self::Error>;
}

impl Addressing for LocalAddressing<'_> {
    type Error = MeshError;

    fn resolve_component_binding_url(
        &mut self,
        binding: &ResolvedComponentBinding,
    ) -> Result<String, Self::Error> {
        let local_port = self.local_component_binding_port(binding)?;
        let scheme = match binding.endpoint.protocol {
            NetworkProtocol::Tcp => "tcp",
            _ => "http",
        };
        Ok(format!("{scheme}://127.0.0.1:{local_port}"))
    }

    fn resolve_external_binding_url(
        &mut self,
        binding: &ResolvedExternalBinding,
    ) -> Result<String, Self::Error> {
        let local_port = self.local_external_binding_port(binding)?;
        Ok(format!("http://127.0.0.1:{local_port}"))
    }

    fn resolve_framework_binding_url(
        &mut self,
        binding: &ResolvedFrameworkBinding,
    ) -> Result<String, Self::Error> {
        if binding.capability.as_str() != "docker" {
            return Err(self.unsupported_framework_error(binding.capability.as_str()));
        }

        match self.options.docker_binding {
            DockerFrameworkBindingPolicy::LoopbackTcp => {
                let local_port = self.local_framework_binding_port(binding)?;
                Ok(format!("tcp://127.0.0.1:{local_port}"))
            }
            DockerFrameworkBindingPolicy::Unsupported { reason } => Err(MeshError::new(format!(
                "{} {reason}",
                self.options.backend_label
            ))),
        }
    }
}

pub(crate) fn build_address_plan<A: Addressing>(
    mesh_plan: &MeshPlan,
    mut addressing: A,
) -> Result<MeshAddressPlan, A::Error> {
    let mut slot_values_by_component: HashMap<ComponentId, BTreeMap<String, SlotValue>> =
        HashMap::new();
    for &id in mesh_plan.program_components() {
        slot_values_by_component.insert(id, BTreeMap::new());
    }

    let mut insert_url = |consumer: ComponentId, slot: &str, url: String| {
        let slot_values = slot_values_by_component.entry(consumer).or_default();
        match slot_values.get_mut(slot) {
            Some(SlotValue::One(existing)) => {
                let existing = existing.clone();
                slot_values.insert(
                    slot.to_string(),
                    SlotValue::Many(vec![existing, SlotObject { url }]),
                );
            }
            Some(SlotValue::Many(values)) => {
                values.push(SlotObject { url });
            }
            None => {
                slot_values.insert(slot.to_string(), SlotValue::One(SlotObject { url }));
            }
        }
    };

    for binding in mesh_plan.bindings() {
        match binding {
            ResolvedBinding::Component(binding) => {
                let url = addressing.resolve_component_binding_url(binding)?;
                insert_url(binding.consumer, &binding.slot, url);
            }
            ResolvedBinding::External(binding) => {
                let url = addressing.resolve_external_binding_url(binding)?;
                insert_url(binding.consumer, &binding.slot, url);
            }
            ResolvedBinding::Framework(binding) => {
                let url = addressing.resolve_framework_binding_url(binding)?;
                insert_url(binding.consumer, &binding.slot, url);
            }
        }
    }

    Ok(MeshAddressPlan {
        slot_values_by_component,
    })
}

pub(crate) type ComponentEgressAllow = HashMap<ComponentId, BTreeMap<ComponentId, BTreeSet<u16>>>;
pub(crate) type RouterEgressAllow = HashMap<ComponentId, BTreeSet<u16>>;

pub(crate) fn build_component_egress_allow(
    allow_plan: &AllowPlan,
) -> (ComponentEgressAllow, RouterEgressAllow) {
    let mut egress_allow: ComponentEgressAllow = HashMap::new();
    let mut egress_router_allow: RouterEgressAllow = HashMap::new();

    for (provider, by_port) in &allow_plan.by_provider {
        match provider {
            WorkloadId::Component(provider_id) => {
                for (port, consumers) in by_port {
                    for consumer in consumers {
                        if let WorkloadId::Component(consumer_id) = consumer {
                            egress_allow
                                .entry(*consumer_id)
                                .or_default()
                                .entry(*provider_id)
                                .or_default()
                                .insert(*port);
                        }
                    }
                }
            }
            WorkloadId::Router => {
                for (port, consumers) in by_port {
                    for consumer in consumers {
                        if let WorkloadId::Component(consumer_id) = consumer {
                            egress_router_allow
                                .entry(*consumer_id)
                                .or_default()
                                .insert(*port);
                        }
                    }
                }
            }
        }
    }

    (egress_allow, egress_router_allow)
}

pub(crate) fn build_allow_plan(
    mesh_plan: &MeshPlan,
    mesh_ports_by_component: &HashMap<ComponentId, u16>,
    router_mesh_port: Option<u16>,
) -> Result<AllowPlan, MeshError> {
    let mut allow = AllowPlan::default();

    for binding in mesh_plan.component_bindings() {
        let port = *mesh_ports_by_component
            .get(&binding.provider)
            .ok_or_else(|| {
                MeshError::new(format!(
                    "mesh port missing for provider {}",
                    binding.provider.0
                ))
            })?;
        allow.allow(
            WorkloadId::Component(binding.provider),
            WorkloadId::Component(binding.consumer),
            port,
        );
    }

    if mesh_plan.needs_router() {
        let router_port =
            router_mesh_port.ok_or_else(|| MeshError::new("router mesh port missing"))?;
        for binding in mesh_plan.external_bindings() {
            allow.allow(
                WorkloadId::Router,
                WorkloadId::Component(binding.consumer),
                router_port,
            );
        }
        for export in mesh_plan.exports() {
            let provider_port =
                *mesh_ports_by_component
                    .get(&export.provider)
                    .ok_or_else(|| {
                        MeshError::new(format!(
                            "mesh port missing for export provider {}",
                            export.provider.0
                        ))
                    })?;
            allow.allow(
                WorkloadId::Component(export.provider),
                WorkloadId::Router,
                provider_port,
            );
        }
    }

    Ok(allow)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use amber_manifest::{FrameworkCapabilityName, ManifestDigest, NetworkProtocol};
    use amber_scenario::{BindingEdge, Component, Moniker, Scenario};

    use super::*;
    use crate::targets::{
        mesh::{
            plan::{
                EndpointInfo, MeshPlan, ResolvedBinding, ResolvedComponentBinding,
                ResolvedExternalBinding, ResolvedFrameworkBinding,
            },
            ports::allocate_local_route_ports,
        },
        program_config::build_endpoint_plan,
    };

    fn component(id: usize, moniker: &str, program_image: &str) -> Component {
        Component {
            id: ComponentId(id),
            parent: None,
            moniker: Moniker::from(Arc::<str>::from(moniker)),
            digest: ManifestDigest::new([id as u8; 32]),
            config: None,
            config_schema: None,
            program: Some(
                serde_json::json!({
                    "image": program_image,
                    "entrypoint": [program_image],
                })
                .as_object()
                .cloned()
                .map(serde_json::Value::Object)
                .and_then(|value| serde_json::from_value(value).ok())
                .expect("program"),
            ),
            slots: BTreeMap::new(),
            provides: BTreeMap::new(),
            resources: BTreeMap::new(),
            metadata: None,
            children: Vec::new(),
        }
    }

    #[test]
    fn build_address_plan_assigns_distinct_urls_per_concrete_edge() {
        let mut consumer = component(0, "/consumer", "consumer");
        consumer.slots.insert(
            "upstream".to_string(),
            serde_json::from_value(serde_json::json!({
                "kind": "http",
                "optional": true,
                "multiple": true,
            }))
            .expect("slot decl"),
        );

        let scenario = Scenario {
            root: ComponentId(0),
            components: vec![
                Some(consumer),
                Some(component(1, "/provider-a", "provider-a")),
                Some(component(2, "/provider-b", "provider-b")),
            ],
            bindings: Vec::<BindingEdge>::new(),
            exports: Vec::new(),
        };

        let mesh_plan = MeshPlan::new(
            vec![ComponentId(0), ComponentId(1), ComponentId(2)],
            vec![
                ResolvedBinding::Component(ResolvedComponentBinding {
                    provider: ComponentId(1),
                    consumer: ComponentId(0),
                    provide: "api".to_string(),
                    endpoint: EndpointInfo {
                        port: 80,
                        protocol: NetworkProtocol::Http,
                    },
                    slot: "upstream".to_string(),
                }),
                ResolvedBinding::Component(ResolvedComponentBinding {
                    provider: ComponentId(2),
                    consumer: ComponentId(0),
                    provide: "api".to_string(),
                    endpoint: EndpointInfo {
                        port: 80,
                        protocol: NetworkProtocol::Http,
                    },
                    slot: "upstream".to_string(),
                }),
            ],
            Vec::new(),
            HashMap::new(),
        );

        let endpoint_plan = build_endpoint_plan(&scenario).expect("endpoint plan");
        let route_ports = allocate_local_route_ports(&scenario, &endpoint_plan, &mesh_plan)
            .expect("local route ports");
        let addressing = LocalAddressing::new(
            &scenario,
            &route_ports,
            LocalAddressingOptions {
                backend_label: "test",
                docker_binding: DockerFrameworkBindingPolicy::LoopbackTcp,
            },
        );
        let plan = build_address_plan(&mesh_plan, addressing).expect("address plan");

        let slot_values = plan
            .slot_values_by_component
            .get(&ComponentId(0))
            .and_then(|slots| slots.get("upstream"))
            .expect("slot values");
        let SlotValue::Many(values) = slot_values else {
            panic!("expected repeated slot values, got {slot_values:?}");
        };
        assert_eq!(values.len(), 2);
        assert_ne!(values[0].url, values[1].url);
        assert_eq!(values[0].url, "http://127.0.0.1:20000");
        assert_eq!(values[1].url, "http://127.0.0.1:20001");
    }

    #[test]
    fn build_address_plan_preserves_authored_order_for_mixed_source_variadic_slots() {
        let mut root = component(0, "/", "root");
        root.slots.insert(
            "ext".to_string(),
            serde_json::from_value(serde_json::json!({
                "kind": "http",
                "optional": true,
            }))
            .expect("slot decl"),
        );
        let mut consumer = component(1, "/consumer", "consumer");
        consumer.slots.insert(
            "upstream".to_string(),
            serde_json::from_value(serde_json::json!({
                "kind": "http",
                "optional": true,
                "multiple": true,
            }))
            .expect("slot decl"),
        );
        let mut provider = component(2, "/provider", "provider");
        provider.provides.insert(
            "api".to_string(),
            serde_json::from_value(serde_json::json!({
                "kind": "http",
                "endpoint": "api",
            }))
            .expect("provide decl"),
        );
        provider.program = Some(
            serde_json::from_value(serde_json::json!({
                "image": "provider",
                "entrypoint": ["provider"],
                "network": { "endpoints": [{ "name": "api", "port": 80 }] },
            }))
            .expect("program"),
        );

        let scenario = Scenario {
            root: ComponentId(0),
            components: vec![Some(root), Some(consumer), Some(provider)],
            bindings: Vec::<BindingEdge>::new(),
            exports: Vec::new(),
        };

        let mesh_plan = MeshPlan::new(
            vec![ComponentId(0), ComponentId(1), ComponentId(2)],
            vec![
                ResolvedBinding::Framework(ResolvedFrameworkBinding {
                    consumer: ComponentId(1),
                    slot: "upstream".to_string(),
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
                        protocol: NetworkProtocol::Http,
                    },
                    slot: "upstream".to_string(),
                }),
            ],
            Vec::new(),
            HashMap::new(),
        );

        let endpoint_plan = build_endpoint_plan(&scenario).expect("endpoint plan");
        let route_ports = allocate_local_route_ports(&scenario, &endpoint_plan, &mesh_plan)
            .expect("local route ports");
        let addressing = LocalAddressing::new(
            &scenario,
            &route_ports,
            LocalAddressingOptions {
                backend_label: "test",
                docker_binding: DockerFrameworkBindingPolicy::LoopbackTcp,
            },
        );
        let plan = build_address_plan(&mesh_plan, addressing).expect("address plan");

        let slot_values = plan
            .slot_values_by_component
            .get(&ComponentId(1))
            .and_then(|slots| slots.get("upstream"))
            .expect("slot values");
        let SlotValue::Many(values) = slot_values else {
            panic!("expected repeated slot values, got {slot_values:?}");
        };
        assert_eq!(
            values
                .iter()
                .map(|value| value.url.as_str())
                .collect::<Vec<_>>(),
            vec![
                "tcp://127.0.0.1:20000",
                "http://127.0.0.1:20001",
                "http://127.0.0.1:20002",
            ]
        );
    }
}
