use miette::Diagnostic;
use thiserror::Error;

use crate::CompileOutput;

pub mod dot;

pub use dot::DotReporter;

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum ReporterError {
    #[error("reporter error: {0}")]
    #[diagnostic(code(reporter::error))]
    Other(String),
}

pub trait Reporter {
    type Artifact;

    fn emit(&self, output: &CompileOutput) -> Result<Self::Artifact, ReporterError>;
}
