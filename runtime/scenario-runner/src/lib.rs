use std::{collections::BTreeMap, future::Future, pin::Pin};

use amber_manifest::ExportName;
use serde_json::Value;
use thiserror::Error;

pub type ScenarioRunnerFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub const JSON_EXPORT_RESPONSE_MAX_BYTES: usize = 1024 * 1024;
pub const JSON_EXPORT_RESPONSE_PREVIEW_BYTES: usize = 4 * 1024;

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
    #[error(
        "response body from export `{export}` exceeds max size {max_bytes} bytes (got at least \
         {size} bytes)"
    )]
    ResponseTooLarge {
        export: String,
        size: u64,
        max_bytes: usize,
    },
}

impl ScenarioRunnerError {
    pub fn message(message: impl Into<String>) -> Self {
        Self::Message {
            message: message.into(),
        }
    }
}

pub fn response_body_preview(body: &str, max_bytes: usize) -> String {
    let body = body.trim();
    if body.len() <= max_bytes {
        return body.to_string();
    }

    let mut end = max_bytes;
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}\n... <truncated; showing first {end} of {} bytes>",
        &body[..end],
        body.len()
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_body_preview_truncates_at_utf8_boundary() {
        let preview = response_body_preview("abcdéSECRET", 5);

        assert!(preview.starts_with("abcd\n... <truncated"));
        assert!(!preview.contains('é'));
        assert!(!preview.contains("SECRET"));
    }

    #[test]
    fn response_body_preview_trims_without_truncating_short_bodies() {
        assert_eq!(
            response_body_preview("  policy failed  \n", 64),
            "policy failed"
        );
    }
}
