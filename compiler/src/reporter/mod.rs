use std::sync::Arc;

use amber_scenario::Scenario;
use miette::{Diagnostic, LabeledSpan, NamedSource, Severity};

pub mod dot;
pub mod metadata;
pub mod scenario_ir;

pub use docker_compose::DockerComposeReporter;

pub use crate::targets::mesh::{docker_compose, kubernetes};

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct ReporterError {
    message: String,
    src: Option<Box<NamedSource<Arc<str>>>>,
    labels: Vec<LabeledSpan>,
    help: Option<String>,
}

impl ReporterError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            src: None,
            labels: Vec::new(),
            help: None,
        }
    }

    pub fn with_source_code(mut self, src: NamedSource<Arc<str>>) -> Self {
        self.src = Some(Box::new(src));
        self
    }

    pub fn with_labels(mut self, labels: Vec<LabeledSpan>) -> Self {
        self.labels = labels;
        self
    }

    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }
}

impl Diagnostic for ReporterError {
    fn severity(&self) -> Option<Severity> {
        Some(Severity::Error)
    }

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        self.help
            .as_deref()
            .map(|help| Box::new(help) as Box<dyn std::fmt::Display + 'a>)
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        self.src
            .as_ref()
            .map(|src| src.as_ref() as &dyn miette::SourceCode)
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        (!self.labels.is_empty()).then(|| Box::new(self.labels.iter().cloned()) as _)
    }
}

pub trait Reporter {
    type Artifact;

    fn emit(&self, scenario: &Scenario) -> Result<Self::Artifact, ReporterError>;
}
