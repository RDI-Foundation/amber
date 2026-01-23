use amber_manifest::Manifest;
use amber_scenario::{BindingFrom, Component, ComponentId, Scenario};

use super::{PassError, ScenarioPass};
use crate::{DigestStore, Provenance};

#[derive(Clone, Copy, Debug, Default)]
pub struct FlattenPass;

impl ScenarioPass for FlattenPass {
    fn name(&self) -> &'static str {
        "flatten"
    }

    fn run(
        &self,
        scenario: Scenario,
        provenance: Provenance,
        store: &DigestStore,
    ) -> Result<(Scenario, Provenance), PassError> {
        let mut scenario = scenario;
        scenario.assert_invariants();

        let manifests = crate::manifest_table::build_manifest_table(&scenario.components, store)
            .map_err(|e| PassError::Failed {
                pass: self.name(),
                message: format!(
                    "missing manifest for digest {} (component {})",
                    e.digest, e.component.0
                ),
            })?;

        let n = scenario.components.len();
        let mut referenced_by_binding = vec![false; n];
        for b in &scenario.bindings {
            if let BindingFrom::Component(from) = &b.from {
                referenced_by_binding[from.component.0] = true;
            }
            referenced_by_binding[b.to.component.0] = true;
        }

        let root = scenario.root;
        let mut remove = vec![false; n];
        for idx in 0..n {
            let id = ComponentId(idx);
            if id == root {
                continue;
            }
            let Some(component) = scenario.components[idx].as_ref() else {
                remove[idx] = true;
                continue;
            };
            if referenced_by_binding[idx] {
                continue;
            }
            let manifest = manifests[idx].as_ref().expect("manifest should exist");
            if is_pure_routing(component, manifest) {
                remove[idx] = true;
            }
        }

        let mut new_parent: Vec<Option<ComponentId>> = vec![None; n];
        for idx in 0..n {
            if remove[idx] {
                continue;
            }
            let Some(component) = scenario.components[idx].as_ref() else {
                continue;
            };
            new_parent[idx] =
                nearest_kept_ancestor(&scenario.components, &remove, component.parent);
        }

        scenario = super::prune_and_rebuild_scenario(
            scenario,
            &remove,
            |id, component| {
                component.parent = new_parent[id.0];
            },
            |_, _| true,
        );
        scenario.assert_invariants();

        Ok((scenario, provenance))
    }
}

fn is_pure_routing(component: &Component, manifest: &Manifest) -> bool {
    component.program.is_none()
        && component.config.is_none()
        && !component.children.is_empty()
        && component.slots.is_empty()
        && component.provides.is_empty()
        && manifest.bindings().is_empty()
}

fn nearest_kept_ancestor(
    components: &[Option<Component>],
    remove: &[bool],
    mut cur: Option<ComponentId>,
) -> Option<ComponentId> {
    while let Some(id) = cur {
        if !remove[id.0] && components[id.0].is_some() {
            break;
        }
        cur = components[id.0].as_ref().and_then(|c| c.parent);
    }
    cur
}

#[cfg(test)]
mod tests;
