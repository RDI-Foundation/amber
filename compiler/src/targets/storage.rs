use std::collections::{BTreeMap, HashMap};

use amber_manifest::CapabilityKind;
use amber_scenario::{BindingFrom, ComponentId, ProgramMount, Scenario};
use sha2::Digest as _;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct StorageIdentity {
    pub(crate) owner: ComponentId,
    pub(crate) owner_moniker: String,
    pub(crate) resource: String,
}

impl StorageIdentity {
    pub(crate) fn hash_suffix(&self) -> String {
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.owner_moniker.as_bytes());
        hasher.update([0]);
        hasher.update(self.resource.as_bytes());

        let digest = hasher.finalize();
        digest[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
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
) -> StoragePlan {
    let mut resource_by_target: BTreeMap<(ComponentId, String), StorageIdentity> = BTreeMap::new();
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

        let BindingFrom::Resource(resource) = &binding.from else {
            unreachable!(
                "linker should reject non-resource storage bindings before storage planning: {}.{}",
                scenario.component(binding.to.component).moniker,
                binding.to.name
            );
        };

        let owner = scenario.component(resource.component);
        resource_by_target.insert(
            (binding.to.component, binding.to.name.clone()),
            StorageIdentity {
                owner: resource.component,
                owner_moniker: owner.moniker.as_str().to_string(),
                resource: resource.name.clone(),
            },
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
            let (identity, source_name, mount_path) = match mount {
                ProgramMount::Slot { path, slot } => {
                    let Some(slot_decl) = component.slots.get(slot.as_str()) else {
                        continue;
                    };
                    if slot_decl.decl.kind != CapabilityKind::Storage {
                        continue;
                    }

                    let identity = resource_by_target
                        .get(&(*component_id, slot.clone()))
                        .cloned()
                        .unwrap_or_else(|| {
                            unreachable!(
                                "linker should reject mounted storage without a resource binding \
                                 before storage planning: {}.{}",
                                component.moniker, slot
                            )
                        });
                    (identity, slot.clone(), path.clone())
                }
                ProgramMount::Resource { path, resource } => {
                    let Some(resource_decl) = component.resources.get(resource.as_str()) else {
                        unreachable!(
                            "manifest validation should reject unknown mounted resource before \
                             storage planning: {}.{}",
                            component.moniker, resource
                        );
                    };
                    if resource_decl.kind != CapabilityKind::Storage {
                        continue;
                    }

                    (
                        StorageIdentity {
                            owner: *component_id,
                            owner_moniker: component.moniker.as_str().to_string(),
                            resource: resource.clone(),
                        },
                        resource.clone(),
                        path.clone(),
                    )
                }
                ProgramMount::File(_) | ProgramMount::Framework { .. } => continue,
            };

            mounts.push(StorageMount {
                identity,
                slot: source_name,
                mount_path,
            });
        }

        if !mounts.is_empty() {
            mounts_by_component.insert(*component_id, mounts);
        }
    }

    StoragePlan {
        mounts_by_component,
    }
}
