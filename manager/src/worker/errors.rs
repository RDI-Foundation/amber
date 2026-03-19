use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    compiler,
    domain::{ObservedState, ServiceProtocol},
};

#[derive(Clone, Debug)]
pub(super) struct OperationError {
    pub(super) message: String,
    pub(super) retryable: bool,
    pub(super) cleanup_runtime: bool,
    pub(super) observed_state: Option<ObservedState>,
    pub(super) affects_scenario: bool,
}

pub(super) fn parse_protocol(raw: &str) -> Result<ServiceProtocol, OperationError> {
    match raw {
        "http" => Ok(ServiceProtocol::Http),
        "tcp" => Ok(ServiceProtocol::Tcp),
        other => Err(invalid_error(format!(
            "unsupported service protocol {}",
            other
        ))),
    }
}

pub(super) fn backoff_ms(base_backoff_ms: u64, retry_count: u32) -> i64 {
    let shift = retry_count.saturating_sub(1).min(16);
    let delay = base_backoff_ms.saturating_mul(1u64 << shift);
    i64::try_from(delay).unwrap_or(i64::MAX)
}

pub(super) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

pub(super) fn retryable_error(err: impl std::fmt::Display) -> OperationError {
    OperationError {
        message: err.to_string(),
        retryable: true,
        cleanup_runtime: true,
        observed_state: Some(ObservedState::Failed),
        affects_scenario: true,
    }
}

pub(super) fn retryable_scenario_error(message: impl Into<String>) -> OperationError {
    OperationError {
        message: message.into(),
        retryable: true,
        cleanup_runtime: false,
        observed_state: Some(ObservedState::Failed),
        affects_scenario: true,
    }
}

pub(super) fn retryable_operation_error(message: impl Into<String>) -> OperationError {
    OperationError {
        message: message.into(),
        retryable: true,
        cleanup_runtime: false,
        observed_state: None,
        affects_scenario: false,
    }
}

pub(super) fn classify_create_compile_error(err: compiler::CompileError) -> OperationError {
    match err {
        compiler::CompileError::InvalidSourceUrl(_)
        | compiler::CompileError::InvalidRootConfig(_)
        | compiler::CompileError::UnknownExternalSlot(_)
        | compiler::CompileError::MissingRequiredExternalSlot(_)
        | compiler::CompileError::UnknownExport(_)
        | compiler::CompileError::InvalidStoredIr(_)
        | compiler::CompileError::MissingProxyMetadata => invalid_scenario_error(err.to_string()),
        compiler::CompileError::Compile(_)
        | compiler::CompileError::Bundle(_)
        | compiler::CompileError::WriteOutput(_) => retryable_scenario_error(err.to_string()),
    }
}

pub(super) fn classify_upgrade_compile_error(err: compiler::CompileError) -> OperationError {
    match err {
        compiler::CompileError::InvalidSourceUrl(_)
        | compiler::CompileError::InvalidRootConfig(_)
        | compiler::CompileError::UnknownExternalSlot(_)
        | compiler::CompileError::MissingRequiredExternalSlot(_)
        | compiler::CompileError::UnknownExport(_)
        | compiler::CompileError::InvalidStoredIr(_)
        | compiler::CompileError::MissingProxyMetadata => invalid_error(err.to_string()),
        compiler::CompileError::Compile(_)
        | compiler::CompileError::Bundle(_)
        | compiler::CompileError::WriteOutput(_) => retryable_operation_error(err.to_string()),
    }
}

pub(super) fn classify_reconcile_compile_error(err: compiler::CompileError) -> OperationError {
    match err {
        compiler::CompileError::InvalidSourceUrl(_)
        | compiler::CompileError::InvalidRootConfig(_)
        | compiler::CompileError::UnknownExternalSlot(_)
        | compiler::CompileError::MissingRequiredExternalSlot(_)
        | compiler::CompileError::UnknownExport(_)
        | compiler::CompileError::InvalidStoredIr(_)
        | compiler::CompileError::MissingProxyMetadata => invalid_scenario_error(err.to_string()),
        compiler::CompileError::Compile(_)
        | compiler::CompileError::Bundle(_)
        | compiler::CompileError::WriteOutput(_) => retryable_scenario_error(err.to_string()),
    }
}

pub(super) fn degraded_error(message: impl Into<String>) -> OperationError {
    OperationError {
        message: message.into(),
        retryable: true,
        cleanup_runtime: false,
        observed_state: Some(ObservedState::Degraded),
        affects_scenario: true,
    }
}

pub(super) fn invalid_error(message: impl Into<String>) -> OperationError {
    OperationError {
        message: message.into(),
        retryable: false,
        cleanup_runtime: false,
        observed_state: None,
        affects_scenario: false,
    }
}

pub(super) fn invalid_scenario_error(message: impl Into<String>) -> OperationError {
    OperationError {
        message: message.into(),
        retryable: false,
        cleanup_runtime: false,
        observed_state: Some(ObservedState::Failed),
        affects_scenario: true,
    }
}
