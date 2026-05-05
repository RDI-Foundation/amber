use std::{collections::BTreeMap, future::Future, pin::Pin};

use amber_manifest::ExportName;
use serde_json::Value;
use thiserror::Error;

pub type ScenarioRunnerFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScenarioRunOptions {
    pub export_display_names: BTreeMap<String, String>,
}

impl ScenarioRunOptions {
    pub fn display_name_for<'a>(&'a self, export_name: &'a str) -> &'a str {
        self.export_display_names
            .get(export_name)
            .map(String::as_str)
            .unwrap_or(export_name)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ScenarioRunnerError {
    #[error("{message}")]
    Message { message: String },
}

impl ScenarioRunnerError {
    pub fn message(message: impl Into<String>) -> Self {
        Self::Message {
            message: message.into(),
        }
    }
}

pub trait ScenarioRunner<Compiled>: Send + Sync {
    fn start<'a>(
        &'a self,
        compiled: &'a Compiled,
        options: ScenarioRunOptions,
    ) -> ScenarioRunnerFuture<'a, Result<Box<dyn RunningScenario>, ScenarioRunnerError>>;
}

pub trait RunningScenario: Send + Sync {
    fn post_json_export<'a>(
        &'a self,
        export: &'a ExportName,
        request: &'a Value,
    ) -> ScenarioRunnerFuture<'a, Result<String, ScenarioRunnerError>>;

    fn finish(self: Box<Self>) -> ScenarioRunnerFuture<'static, Result<(), ScenarioRunnerError>>;
}
