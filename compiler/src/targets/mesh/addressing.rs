use std::collections::{BTreeMap, BTreeSet, HashMap};

use amber_manifest::Manifest;
use amber_scenario::ComponentId;

use crate::{
    binding_query::BindingObject,
    slot_query::SlotObject,
    targets::mesh::{
        plan::{MeshError, MeshPlan, ResolvedBinding, ResolvedExport, ResolvedExternalBinding},
        router_config::{
            RouterConfig, RouterExport, RouterExternalSlot, allocate_external_slot_ports,
            build_router_external_slots, encode_router_config_b64,
        },
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
pub(crate) struct RouterPlan {
    pub(crate) needs_router: bool,
    pub(crate) external_slot_ports: BTreeMap<String, u16>,
    pub(crate) export_ports_by_name: BTreeMap<String, u16>,
    pub(crate) export_ports: BTreeSet<u16>,
    pub(crate) router_external_slots: Vec<RouterExternalSlot>,
    pub(crate) router_exports: Vec<RouterExport>,
    pub(crate) router_env_passthrough: Vec<String>,
    pub(crate) router_config_b64: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct MeshAddressPlan<E> {
    pub(crate) slot_values_by_component: HashMap<ComponentId, BTreeMap<String, SlotObject>>,
    pub(crate) binding_values_by_component: HashMap<ComponentId, BTreeMap<String, BindingObject>>,
    pub(crate) allow: AllowPlan,
    pub(crate) router: RouterPlan,
    pub(crate) extra: E,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RouterPortBases {
    pub(crate) external: u16,
    pub(crate) export: u16,
}

pub(crate) trait Addressing {
    type Extra;
    type Error: From<MeshError>;

    fn resolve_binding_url(&mut self, binding: &ResolvedBinding) -> Result<String, Self::Error>;
    fn resolve_external_binding_url(
        &mut self,
        binding: &ResolvedExternalBinding,
        router_port: u16,
    ) -> Result<String, Self::Error>;
    fn resolve_export_target_url(&mut self, export: &ResolvedExport)
    -> Result<String, Self::Error>;
    fn finalize(self) -> Self::Extra;
}

pub(crate) fn build_address_plan<A: Addressing>(
    mesh_plan: &MeshPlan,
    root_manifest: &Manifest,
    router_ports: RouterPortBases,
    mut addressing: A,
) -> Result<MeshAddressPlan<A::Extra>, A::Error> {
    let mut slot_values_by_component: HashMap<ComponentId, BTreeMap<String, SlotObject>> =
        HashMap::new();
    let mut binding_values_by_component: HashMap<ComponentId, BTreeMap<String, BindingObject>> =
        HashMap::new();
    for id in &mesh_plan.program_components {
        slot_values_by_component.insert(*id, BTreeMap::new());
        binding_values_by_component.insert(*id, BTreeMap::new());
    }

    let mut allow = AllowPlan::default();

    for binding in &mesh_plan.bindings {
        let url = addressing.resolve_binding_url(binding)?;

        slot_values_by_component
            .entry(binding.consumer)
            .or_default()
            .insert(binding.slot.clone(), SlotObject { url: url.clone() });

        if let Some(name) = binding.binding_name.as_ref() {
            binding_values_by_component
                .entry(binding.consumer)
                .or_default()
                .insert(name.clone(), BindingObject { url });
        }

        allow.allow(
            WorkloadId::Component(binding.provider),
            WorkloadId::Component(binding.consumer),
            binding.endpoint.port,
        );
    }

    let needs_router = !mesh_plan.external_bindings.is_empty() || !mesh_plan.exports.is_empty();

    let external_slot_ports =
        allocate_external_slot_ports(&mesh_plan.external_bindings, router_ports.external)
            .map_err(MeshError::new)?;

    for binding in &mesh_plan.external_bindings {
        let router_port = *external_slot_ports
            .get(&binding.external_slot)
            .expect("external slot port missing");
        let url = addressing.resolve_external_binding_url(binding, router_port)?;

        slot_values_by_component
            .entry(binding.consumer)
            .or_default()
            .insert(binding.slot.clone(), SlotObject { url: url.clone() });

        if let Some(name) = binding.binding_name.as_ref() {
            binding_values_by_component
                .entry(binding.consumer)
                .or_default()
                .insert(name.clone(), BindingObject { url });
        }

        allow.allow(
            WorkloadId::Router,
            WorkloadId::Component(binding.consumer),
            router_port,
        );
    }

    let mut export_ports_by_name: BTreeMap<String, u16> = BTreeMap::new();
    let mut export_ports: BTreeSet<u16> = BTreeSet::new();

    if !mesh_plan.exports.is_empty() {
        let mut next_port = router_ports.export;
        for ex in &mesh_plan.exports {
            let listen_port = next_port;
            next_port = next_port
                .checked_add(1)
                .ok_or_else(|| MeshError::new("ran out of router export ports".to_string()))?;
            export_ports_by_name.insert(ex.name.clone(), listen_port);
            export_ports.insert(listen_port);
        }
    }

    let mut router_external_slots: Vec<RouterExternalSlot> = Vec::new();
    let mut router_exports: Vec<RouterExport> = Vec::new();
    let mut router_env_passthrough: Vec<String> = Vec::new();
    let mut router_config_b64: Option<String> = None;

    if needs_router {
        router_external_slots = build_router_external_slots(root_manifest, &external_slot_ports);
        router_env_passthrough = router_external_slots
            .iter()
            .map(|slot| slot.url_env.clone())
            .collect();

        for ex in &mesh_plan.exports {
            let listen_port = *export_ports_by_name
                .get(&ex.name)
                .expect("missing router port for export");
            let target_url = addressing.resolve_export_target_url(ex)?;
            router_exports.push(RouterExport {
                name: ex.name.clone(),
                listen_port,
                target_url,
            });

            allow.allow(
                WorkloadId::Component(ex.provider),
                WorkloadId::Router,
                ex.endpoint.port,
            );
        }

        let router_config = RouterConfig {
            external_slots: router_external_slots.clone(),
            exports: router_exports.clone(),
        };
        let b64 = encode_router_config_b64(&router_config)
            .map_err(|err| MeshError::new(format!("failed to serialize router config: {err}")))?;
        router_config_b64 = Some(b64);
    }

    let router = RouterPlan {
        needs_router,
        external_slot_ports,
        export_ports_by_name,
        export_ports,
        router_external_slots,
        router_exports,
        router_env_passthrough,
        router_config_b64,
    };

    Ok(MeshAddressPlan {
        slot_values_by_component,
        binding_values_by_component,
        allow,
        router,
        extra: addressing.finalize(),
    })
}
