use std::collections::{BTreeMap, HashMap};

use amber_manifest::{CapabilityKind, MountSource};
use amber_scenario::{BindingFrom, ComponentId, Scenario};

use crate::targets::common::{TargetError, component_label};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct StorageIdentity {
    pub(crate) consumer: ComponentId,
    pub(crate) consumer_moniker: String,
    pub(crate) root_slot: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StorageMount {
    pub(crate) identity: StorageIdentity,
    pub(crate) slot: String,
    pub(crate) mount_path: String,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct StoragePlan {
    pub(crate) mounts_by_component: HashMap<ComponentId, Vec<StorageMount>>,
}

impl StoragePlan {
    pub(crate) fn is_empty(&self) -> bool {
        self.mounts_by_component.is_empty()
    }
}

pub(crate) fn build_storage_plan(
    scenario: &Scenario,
    program_components: &[ComponentId],
) -> Result<StoragePlan, TargetError> {
    let mut root_storage_by_target: BTreeMap<(ComponentId, String), String> = BTreeMap::new();
    for binding in &scenario.bindings {
        let Some(slot_decl) = scenario
            .component(binding.to.component)
            .slots
            .get(binding.to.name.as_str())
        else {
            continue;
        };
        if slot_decl.decl.kind != CapabilityKind::Storage {
            continue;
        }

        let BindingFrom::External(root_slot) = &binding.from else {
            return Err(TargetError::new(format!(
                "storage slot {}.{} must resolve from a routed root storage slot",
                component_label(scenario, binding.to.component),
                binding.to.name
            )));
        };

        root_storage_by_target.insert(
            (binding.to.component, binding.to.name.clone()),
            root_slot.name.clone(),
        );
    }

    let mut mounts_by_component: HashMap<ComponentId, Vec<StorageMount>> = HashMap::new();
    for component_id in program_components {
        let component = scenario.component(*component_id);
        let Some(program) = component.program.as_ref() else {
            continue;
        };

        let mut mounts = Vec::new();
        for mount in program.mounts() {
            let MountSource::Slot(slot) = &mount.source else {
                continue;
            };
            let Some(slot_decl) = component.slots.get(slot.as_str()) else {
                continue;
            };
            if slot_decl.decl.kind != CapabilityKind::Storage {
                continue;
            }

            let Some(root_slot) = root_storage_by_target.get(&(*component_id, slot.clone())) else {
                let suffix = if slot_decl.optional {
                    " Optional storage mounts are not supported."
                } else {
                    ""
                };
                return Err(TargetError::new(format!(
                    "component {} mounts storage slot `slots.{slot}`, but that slot is not bound \
                     to a root storage slot.{suffix}",
                    component_label(scenario, *component_id)
                )));
            };

            mounts.push(StorageMount {
                identity: StorageIdentity {
                    consumer: *component_id,
                    consumer_moniker: component.moniker.as_str().to_string(),
                    root_slot: root_slot.clone(),
                },
                slot: slot.clone(),
                mount_path: mount.path.clone(),
            });
        }

        if !mounts.is_empty() {
            mounts_by_component.insert(*component_id, mounts);
        }
    }

    Ok(StoragePlan {
        mounts_by_component,
    })
}
