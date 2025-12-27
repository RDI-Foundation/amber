use crate::CompileOutput;

pub mod dot;

pub use dot::DotBackend;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BackendError {
    #[error("backend error: {0}")]
    Other(String),
}

pub trait Backend {
    type Artifact;

    fn emit(&self, output: &CompileOutput) -> Result<Self::Artifact, BackendError>;
}
