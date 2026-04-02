use std::collections::HashMap;

use amber_mesh::{
    MESH_PROVISION_PLAN_VERSION, MeshConfigTemplate, MeshProvisionOutput, MeshProvisionPlan,
    MeshProvisionTarget, MeshProvisionTargetKind,
};
use amber_scenario::ComponentId;

use super::{mesh_config::MeshConfigPlan, plan::MeshError};

pub(crate) fn build_mesh_provision_plan<Name>(
    mesh_config_plan: &MeshConfigPlan,
    program_components: &[ComponentId],
    names: &HashMap<ComponentId, Name>,
    mut component_output: impl FnMut(&Name) -> MeshProvisionOutput,
    mut router_output: impl FnMut() -> MeshProvisionOutput,
    mut rewrite_router_config: impl FnMut(&mut MeshConfigTemplate),
) -> Result<MeshProvisionPlan, MeshError> {
    let mut targets = Vec::with_capacity(
        program_components.len() + usize::from(mesh_config_plan.router_config.is_some()),
    );

    for component_id in program_components {
        let name = names.get(component_id).ok_or_else(|| {
            MeshError::new(format!(
                "missing provision target name for component {component_id:?}"
            ))
        })?;
        let config = mesh_config_plan
            .component_configs
            .get(component_id)
            .ok_or_else(|| {
                MeshError::new(format!(
                    "missing config template for component {component_id:?}"
                ))
            })?
            .clone();
        targets.push(MeshProvisionTarget {
            kind: MeshProvisionTargetKind::Component,
            config,
            output: component_output(name),
        });
    }

    if let Some(router_template) = mesh_config_plan.router_config.as_ref() {
        let mut config = router_template.clone();
        rewrite_router_config(&mut config);
        targets.push(MeshProvisionTarget {
            kind: MeshProvisionTargetKind::Router,
            config,
            output: router_output(),
        });
    }

    Ok(MeshProvisionPlan {
        version: MESH_PROVISION_PLAN_VERSION.to_string(),
        identity_seed: None,
        targets,
    })
}
