use miette::Diagnostic;
use thiserror::Error;

use crate::CompileOutput;

pub mod dot;

pub use dot::DotBackend;

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum BackendError {
    #[error("backend error: {0}")]
    #[diagnostic(code(backend::error))]
    Other(String),
}

pub trait Backend {
    type Artifact;

    fn emit(&self, output: &CompileOutput) -> Result<Self::Artifact, BackendError>;
}
