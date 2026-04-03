use std::collections::BTreeMap;

use amber_manifest::ExportTarget;
use amber_scenario::{ComponentId, Scenario, ScenarioIr, ir::ComponentExportTargetIr};

use super::{CompiledScenario, Reporter, ReporterError};
use crate::CompileOutput;

#[derive(Clone, Copy, Debug, Default)]
pub struct ScenarioIrReporter;

impl Reporter for ScenarioIrReporter {
    type Artifact = String;

    fn emit(&self, compiled: &CompiledScenario) -> Result<Self::Artifact, ReporterError> {
        render_scenario_ir_document(compiled.scenario_ir())
    }
}

pub fn scenario_ir_from_compile_output(output: &CompileOutput) -> ScenarioIr {
    let mut ir = ScenarioIr::from(&output.scenario);
    for component in &mut ir.components {
        component.resolved_url = output
            .provenance
            .components
            .get(component.id)
            .map(|provenance| provenance.resolved_url.to_string());
        component.exports = live_component_exports(output, ComponentId(component.id));
    }
    ir
}

fn live_component_exports(
    output: &CompileOutput,
    component_id: ComponentId,
) -> BTreeMap<String, ComponentExportTargetIr> {
    let Some(manifest) = output.manifest_for_component(component_id) else {
        return BTreeMap::new();
    };

    manifest
        .exports()
        .iter()
        .filter(|(name, _)| {
            export_target_is_resolvable(output, component_id, name.as_str(), &mut Vec::new())
        })
        .map(|(name, target)| (name.to_string(), export_target_ir(target)))
        .collect()
}

fn export_target_is_resolvable(
    output: &CompileOutput,
    component_id: ComponentId,
    export_name: &str,
    visited: &mut Vec<(usize, String)>,
) -> bool {
    let visit_key = (component_id.0, export_name.to_string());
    if visited.contains(&visit_key) {
        return false;
    }
    visited.push(visit_key);

    let Some(manifest) = output.manifest_for_component(component_id) else {
        visited.pop();
        return false;
    };
    let Some(target) = manifest.exports().get(export_name) else {
        visited.pop();
        return false;
    };

    let component = output.scenario.component(component_id);
    let result = match target {
        ExportTarget::SelfProvide(provide) => component.provides.contains_key(provide.as_str()),
        ExportTarget::SelfSlot(slot) => component.slots.contains_key(slot.as_str()),
        ExportTarget::ChildExport { child, export } => {
            let child_id = component.children.iter().copied().find(|child_id| {
                child_alias(
                    component.moniker.as_str(),
                    output.scenario.component(*child_id).moniker.as_str(),
                ) == Some(child.as_str())
            });
            child_id.is_some_and(|child_id| {
                export_target_is_resolvable(output, child_id, export.as_str(), visited)
            })
        }
        _ => unreachable!("unsupported export targets should be rejected before reporting"),
    };

    visited.pop();
    result
}

fn export_target_ir(target: &ExportTarget) -> ComponentExportTargetIr {
    match target {
        ExportTarget::SelfProvide(provide) => ComponentExportTargetIr::SelfProvide {
            provide: provide.to_string(),
        },
        ExportTarget::SelfSlot(slot) => ComponentExportTargetIr::SelfSlot {
            slot: slot.to_string(),
        },
        ExportTarget::ChildExport { child, export } => ComponentExportTargetIr::ChildExport {
            child: child.to_string(),
            export: export.to_string(),
        },
        _ => unreachable!("unsupported export targets should be rejected before reporting"),
    }
}

fn child_alias<'a>(parent_moniker: &str, child_moniker: &'a str) -> Option<&'a str> {
    if child_moniker == "/" {
        return None;
    }
    let remainder = if parent_moniker == "/" {
        child_moniker.strip_prefix('/')?
    } else {
        child_moniker
            .strip_prefix(parent_moniker)?
            .strip_prefix('/')?
    };
    remainder.split('/').find(|segment| !segment.is_empty())
}

/// Render a Scenario graph as a stable JSON IR artifact.
pub fn render_scenario_ir(s: &Scenario) -> Result<String, ReporterError> {
    let ir = ScenarioIr::from(s);
    render_scenario_ir_document(&ir)
}

fn render_scenario_ir_document(ir: &ScenarioIr) -> Result<String, ReporterError> {
    let mut out = serde_json::to_string_pretty(&ir)
        .map_err(|e| ReporterError::new(format!("failed to render scenario IR: {e}")))?;
    out.push('\n');
    Ok(out)
}
