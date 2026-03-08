use std::sync::Arc;

use amber_scenario::{ComponentId, Scenario, ScenarioIr, ScenarioIrError};
use miette::{Diagnostic, LabeledSpan, NamedSource, Severity};
use thiserror::Error;
use url::Url;

use crate::{CompileOutput, DigestStore, Provenance};

pub mod dot;
pub(crate) mod execution_guide;
pub mod metadata;
pub mod scenario_ir;

pub use direct::DirectReporter;
pub use docker_compose::DockerComposeReporter;

pub use crate::targets::{
    direct,
    mesh::{docker_compose, kubernetes},
};

#[derive(Clone, Debug)]
pub struct CompiledScenario {
    scenario: Scenario,
    scenario_ir: ScenarioIr,
    resolved_urls: Vec<Option<Url>>,
    source_context: Option<CompiledScenarioSourceContext>,
}

impl CompiledScenario {
    pub fn from_compile_output(output: &CompileOutput) -> Result<Self, CompiledScenarioError> {
        let mut compiled = Self::from_ir(scenario_ir::scenario_ir_from_compile_output(output))?;
        compiled.source_context = Some(CompiledScenarioSourceContext {
            store: output.store.clone(),
            provenance: output.provenance.clone(),
        });
        Ok(compiled)
    }

    pub fn from_ir(scenario_ir: ScenarioIr) -> Result<Self, CompiledScenarioError> {
        let max_id = scenario_ir
            .components
            .iter()
            .map(|component| component.id)
            .chain(std::iter::once(scenario_ir.root))
            .max()
            .expect("Scenario IR root id should always be present");
        let mut resolved_urls = vec![None; max_id + 1];
        for component in &scenario_ir.components {
            resolved_urls[component.id] = match component.resolved_url.as_deref() {
                Some(raw) => Some(Url::parse(raw).map_err(|source| {
                    CompiledScenarioError::InvalidResolvedUrl {
                        component: component.moniker.clone(),
                        raw: raw.to_string(),
                        source,
                    }
                })?),
                None => None,
            };
        }
        let scenario = Scenario::try_from(scenario_ir.clone())
            .map_err(CompiledScenarioError::InvalidScenarioIr)?;
        Ok(Self {
            scenario,
            scenario_ir,
            resolved_urls,
            source_context: None,
        })
    }

    pub fn scenario(&self) -> &Scenario {
        &self.scenario
    }

    pub fn scenario_ir(&self) -> &ScenarioIr {
        &self.scenario_ir
    }

    pub fn resolved_url_for_component(&self, id: ComponentId) -> Option<&Url> {
        self.resolved_urls
            .get(id.0)
            .expect("resolved URL slot should exist for each component id")
            .as_ref()
    }

    pub(crate) fn source_context(&self) -> Option<(&DigestStore, &Provenance)> {
        self.source_context
            .as_ref()
            .map(|context| (&context.store, &context.provenance))
    }
}

#[derive(Clone, Debug)]
struct CompiledScenarioSourceContext {
    store: DigestStore,
    provenance: Provenance,
}

#[derive(Debug, Error)]
pub enum CompiledScenarioError {
    #[error(transparent)]
    InvalidScenarioIr(#[from] ScenarioIrError),

    #[error("invalid resolved_url `{raw}` for Scenario IR component `{component}`: {source}")]
    InvalidResolvedUrl {
        component: String,
        raw: String,
        source: url::ParseError,
    },
}

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

    fn emit(&self, compiled: &CompiledScenario) -> Result<Self::Artifact, ReporterError>;
}
