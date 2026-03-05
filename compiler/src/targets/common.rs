use std::fmt;

use amber_scenario::{ComponentId, Scenario};

#[derive(Debug)]
pub(crate) struct TargetError {
    message: String,
}

impl TargetError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for TargetError {}

impl From<String> for TargetError {
    fn from(message: String) -> Self {
        Self::new(message)
    }
}

pub(crate) fn component_label(scenario: &Scenario, id: ComponentId) -> String {
    scenario.component(id).moniker.as_str().to_string()
}
