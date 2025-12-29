use amber_scenario::Scenario;
use miette::Diagnostic;
use thiserror::Error;

use crate::{DigestStore, Provenance};

pub mod dce;

pub use dce::DcePass;

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum PassError {
    #[error("pass `{pass}` failed: {message}")]
    #[diagnostic(code(compiler::pass_failed))]
    Failed { pass: &'static str, message: String },
}

pub trait ScenarioPass {
    fn name(&self) -> &'static str;

    fn run(
        &self,
        scenario: Scenario,
        provenance: Provenance,
        store: &DigestStore,
    ) -> Result<(Scenario, Provenance), PassError>;
}

#[derive(Default)]
pub struct PassManager {
    passes: Vec<Box<dyn ScenarioPass>>,
}

impl PassManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push<P>(&mut self, pass: P)
    where
        P: ScenarioPass + 'static,
    {
        self.passes.push(Box::new(pass));
    }

    pub fn run(
        &self,
        mut scenario: Scenario,
        mut provenance: Provenance,
        store: &DigestStore,
    ) -> Result<(Scenario, Provenance), PassError> {
        for pass in &self.passes {
            (scenario, provenance) = pass.run(scenario, provenance, store)?;
        }
        Ok((scenario, provenance))
    }
}
