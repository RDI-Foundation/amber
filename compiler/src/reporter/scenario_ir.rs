use amber_scenario::{Scenario, ScenarioIr};

use super::{Reporter, ReporterError};

#[derive(Clone, Copy, Debug, Default)]
pub struct ScenarioIrReporter;

impl Reporter for ScenarioIrReporter {
    type Artifact = String;

    fn emit(&self, scenario: &Scenario) -> Result<Self::Artifact, ReporterError> {
        render_scenario_ir(scenario)
    }
}

/// Render a Scenario graph as a stable JSON IR artifact.
pub fn render_scenario_ir(s: &Scenario) -> Result<String, ReporterError> {
    let ir = ScenarioIr::from(s);
    let mut out = serde_json::to_string_pretty(&ir)
        .map_err(|e| ReporterError::new(format!("failed to render scenario IR: {e}")))?;
    out.push('\n');
    Ok(out)
}
