use amber_mesh::component_protocol::{ProtocolErrorCode, ProtocolErrorResponse};
use rmcp::{
    ErrorData as McpError, Json,
    schemars::{self, JsonSchema},
};
use serde::Serialize;
use serde_json::Value;

use super::orchestration::ProtocolApiError;

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) struct McpOperationResponse {
    pub(crate) op: String,
    pub(crate) data: Value,
}

pub(crate) fn json_response(
    op: &'static str,
    data: impl Serialize,
) -> Result<Json<McpOperationResponse>, McpError> {
    let data = serde_json::to_value(data).map_err(|err| {
        McpError::internal_error(
            format!("failed to serialize `{op}` MCP result: {err}"),
            None,
        )
    })?;
    Ok(Json(McpOperationResponse {
        op: op.to_string(),
        data,
    }))
}

pub(crate) fn map_protocol_api_error(error: ProtocolApiError) -> McpError {
    map_protocol_error(error.0)
}

pub(crate) fn map_protocol_error(error: ProtocolErrorResponse) -> McpError {
    let data = Some(serde_json::to_value(&error).expect("protocol errors should serialize"));
    match error.code {
        ProtocolErrorCode::UnknownTemplate
        | ProtocolErrorCode::UnknownChild
        | ProtocolErrorCode::BindingSourceNotFound
        | ProtocolErrorCode::UnknownSource
        | ProtocolErrorCode::UnknownRef
        | ProtocolErrorCode::UnknownHandle => McpError::resource_not_found(error.message, data),
        ProtocolErrorCode::Unauthorized
        | ProtocolErrorCode::CallerLacksAuthority
        | ProtocolErrorCode::RecipientMismatch => McpError::invalid_request(error.message, data),
        ProtocolErrorCode::ControlStateUnavailable
        | ProtocolErrorCode::PrepareFailed
        | ProtocolErrorCode::PublishFailed
        | ProtocolErrorCode::SiteNotActive
        | ProtocolErrorCode::OriginUnavailable
        | ProtocolErrorCode::PathEstablishmentFailed => {
            McpError::internal_error(error.message, data)
        }
        _ => McpError::invalid_params(error.message, data),
    }
}
