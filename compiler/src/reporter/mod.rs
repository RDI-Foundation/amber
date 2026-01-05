use crate::CompileOutput;

pub mod docker_compose;
pub mod dot;
pub mod scenario_ir;

pub use docker_compose::DockerComposeReporter;

#[derive(Debug)]
pub enum ReporterError {
    Other(String),
}

impl std::fmt::Display for ReporterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReporterError::Other(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for ReporterError {}

pub trait Reporter {
    type Artifact;

    fn emit(&self, output: &CompileOutput) -> Result<Self::Artifact, ReporterError>;
}
