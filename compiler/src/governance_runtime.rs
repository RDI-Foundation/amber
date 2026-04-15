use std::{future::Future, pin::Pin};

use amber_manifest::ExportName;
use thiserror::Error;

use crate::{
    policy::{PolicyInput, PolicyOutput},
    reporter::CompiledScenario,
};

pub type GovernanceFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GovernanceRuntimeError {
    #[error("{message}")]
    Message { message: String },
}

impl GovernanceRuntimeError {
    pub fn message(message: impl Into<String>) -> Self {
        Self::Message {
            message: message.into(),
        }
    }
}

pub trait GovernanceRuntime: Send + Sync {
    fn start<'a>(
        &'a self,
        compiled: &'a CompiledScenario,
    ) -> GovernanceFuture<'a, Result<Box<dyn GovernanceSession>, GovernanceRuntimeError>>;
}

pub trait GovernanceSession: Send + Sync {
    fn invoke_policy<'a>(
        &'a self,
        policy_export: &'a ExportName,
        input: &'a PolicyInput,
    ) -> GovernanceFuture<'a, Result<PolicyOutput, GovernanceRuntimeError>>;

    fn finish(self: Box<Self>) -> GovernanceFuture<'static, Result<(), GovernanceRuntimeError>>;
}
