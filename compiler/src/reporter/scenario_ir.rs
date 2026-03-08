use amber_scenario::{Scenario, ScenarioIr};

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
    }
    ir
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
