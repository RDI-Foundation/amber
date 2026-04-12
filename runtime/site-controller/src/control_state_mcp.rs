use axum::http::request::Parts;
use rmcp::{
    ErrorData as McpError, Json, RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        AnnotateAble, Implementation, InitializeRequestParams, ListResourceTemplatesResult,
        ListResourcesResult, PaginatedRequestParams, ProtocolVersion, RawResource,
        RawResourceTemplate, ReadResourceRequestParams, ReadResourceResult, ResourceContents,
        ServerCapabilities, ServerInfo,
    },
    schemars::{self, JsonSchema},
    service::RequestContext,
    tool, tool_handler, tool_router,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
use serde::Deserialize;
use serde_json::Value;

use super::{
    control_state_api::{
        DynamicCapsInspectRequest, DynamicCapsInspectResponse, DynamicCapsMutateRequest,
        DynamicCapsMutateResponse,
    },
    dynamic_caps,
    mcp_common::{McpOperationResponse, json_response, map_protocol_api_error},
    planner::SiteControllerApp,
    site_controller::{
        execute_site_controller_dynamic_caps_inspect, execute_site_controller_dynamic_caps_mutate,
    },
};

const HELP_RESOURCE_URI: &str = "amber://framework-dynamic-caps";
const OPERATION_RESOURCE_PREFIX: &str = "amber://framework-dynamic-caps/op/";

pub(crate) fn service(
    app: SiteControllerApp,
) -> StreamableHttpService<FrameworkDynamicCapsMcp, LocalSessionManager> {
    StreamableHttpService::new(
        move || Ok(FrameworkDynamicCapsMcp::new(app.clone())),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default(),
    )
}

#[derive(Clone)]
pub(crate) struct FrameworkDynamicCapsMcp {
    app: SiteControllerApp,
    tool_router: ToolRouter<Self>,
}

impl FrameworkDynamicCapsMcp {
    fn new(app: SiteControllerApp) -> Self {
        Self {
            app,
            tool_router: Self::tool_router(),
        }
    }

    fn authorize(&self, context: &RequestContext<RoleServer>) -> Result<(), McpError> {
        let parts = context
            .extensions
            .get::<Parts>()
            .ok_or_else(|| McpError::invalid_request("missing HTTP request context", None))?;
        super::http::authorize_framework_auth_header(
            &parts.headers,
            self.app.control.control_state_auth_token.as_ref(),
        )
        .map_err(map_protocol_api_error)
    }

    fn help_resource(&self) -> String {
        "# framework dynamic caps MCP\n\n- `amber.v1.framework_dynamic_caps.inspect`\n- \
         `amber.v1.framework_dynamic_caps.mutate`\n"
            .to_string()
    }

    fn operation_resource(&self, name: &str) -> Result<String, McpError> {
        let doc = match name {
            "held_list" => {
                "# `held_list`\n\nTool: `amber.v1.framework_dynamic_caps.inspect`\n\n```json\n{ \
                 \"op\": \"held_list\", \"holder_component_id\": \"components./alice\" }\n```"
            }
            "held_detail" => {
                "# `held_detail`\n\nTool: `amber.v1.framework_dynamic_caps.inspect`\n\n```json\n{ \
                 \"op\": \"held_detail\", \"holder_component_id\": \"components./alice\", \
                 \"held_id\": \"held_root_...\" }\n```"
            }
            "inspect_ref" => {
                "# `inspect_ref`\n\nTool: `amber.v1.framework_dynamic_caps.inspect`\n\n```json\n{ \
                 \"op\": \"inspect_ref\", \"holder_component_id\": \"components./carol\", \"ref\": \
                 \"amber://ref/...\" }\n```"
            }
            "resolve_origin" => {
                "# `resolve_origin`\n\nTool: \
                 `amber.v1.framework_dynamic_caps.inspect`\n\n```json\n{\n  \"op\": \
                 \"resolve_origin\",\n  \"holder_component_id\": \"components./alice\",\n  \
                 \"source\": { \"kind\": \"grant\", \"grant_id\": \"g_...\" }\n}\n```"
            }
            "share" => {
                "# `share`\n\nTool: `amber.v1.framework_dynamic_caps.mutate`\n\n```json\n{\n  \
                 \"op\": \"share\",\n  \"caller_component_id\": \"components./alice\",\n  \
                 \"source\": { \"kind\": \"grant\", \"grant_id\": \"g_...\" },\n  \
                 \"recipient_component_id\": \"components./carol\"\n}\n```"
            }
            "revoke" => {
                "# `revoke`\n\nTool: `amber.v1.framework_dynamic_caps.mutate`\n\n```json\n{\n  \
                 \"op\": \"revoke\",\n  \"caller_component_id\": \"components./alice\",\n  \
                 \"target\": { \"kind\": \"grant\", \"grant_id\": \"g_...\" }\n}\n```"
            }
            _ => {
                return Err(McpError::resource_not_found(
                    format!("framework dynamic caps operation `{name}` not found"),
                    None,
                ));
            }
        };
        Ok(doc.to_string())
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum RootAuthoritySelectorArg {
    SelfProvide {
        component_id: String,
        provide_name: String,
    },
    Binding {
        consumer_component_id: String,
        slot_name: String,
        provider_component_id: String,
        provider_capability_name: String,
    },
    ExternalSlotBinding {
        consumer_component_id: String,
        slot_name: String,
        external_slot_component_id: String,
        external_slot_name: String,
    },
}

impl From<RootAuthoritySelectorArg> for amber_mesh::dynamic_caps::RootAuthoritySelectorIr {
    fn from(value: RootAuthoritySelectorArg) -> Self {
        match value {
            RootAuthoritySelectorArg::SelfProvide {
                component_id,
                provide_name,
            } => Self::SelfProvide {
                component_id,
                provide_name,
            },
            RootAuthoritySelectorArg::Binding {
                consumer_component_id,
                slot_name,
                provider_component_id,
                provider_capability_name,
            } => Self::Binding {
                consumer_component_id,
                slot_name,
                provider_component_id,
                provider_capability_name,
            },
            RootAuthoritySelectorArg::ExternalSlotBinding {
                consumer_component_id,
                slot_name,
                external_slot_component_id,
                external_slot_name,
            } => Self::ExternalSlotBinding {
                consumer_component_id,
                slot_name,
                external_slot_component_id,
                external_slot_name,
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum DynamicCapabilitySourceArg {
    RootAuthority {
        root_authority_selector: RootAuthoritySelectorArg,
    },
    Grant {
        grant_id: String,
    },
}

impl From<DynamicCapabilitySourceArg> for dynamic_caps::DynamicCapabilityControlSourceRequest {
    fn from(value: DynamicCapabilitySourceArg) -> Self {
        match value {
            DynamicCapabilitySourceArg::RootAuthority {
                root_authority_selector,
            } => Self::RootAuthority {
                root_authority_selector: root_authority_selector.into(),
            },
            DynamicCapabilitySourceArg::Grant { grant_id } => Self::Grant { grant_id },
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case")]
enum InspectArgs {
    HeldList {
        holder_component_id: String,
    },
    HeldDetail {
        holder_component_id: String,
        held_id: String,
    },
    InspectRef {
        holder_component_id: String,
        r#ref: String,
    },
    ResolveOrigin {
        holder_component_id: String,
        source: DynamicCapabilitySourceArg,
    },
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case")]
enum MutateArgs {
    Share {
        caller_component_id: String,
        source: DynamicCapabilitySourceArg,
        recipient_component_id: String,
        #[serde(default)]
        idempotency_key: Option<String>,
        #[serde(default)]
        options: Value,
    },
    Revoke {
        caller_component_id: String,
        target: DynamicCapabilitySourceArg,
    },
}

#[tool_router]
impl FrameworkDynamicCapsMcp {
    #[tool(
        name = "amber.v1.framework_dynamic_caps.inspect",
        description = "Read dynamic capability state.",
        annotations(read_only_hint = true)
    )]
    async fn inspect(
        &self,
        Parameters(args): Parameters<InspectArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<McpOperationResponse>, McpError> {
        self.authorize(&context)?;
        let response = execute_site_controller_dynamic_caps_inspect(
            &self.app,
            match args {
                InspectArgs::HeldList {
                    holder_component_id,
                } => DynamicCapsInspectRequest::HeldList(
                    dynamic_caps::ControlDynamicHeldListRequest {
                        holder_component_id,
                    },
                ),
                InspectArgs::HeldDetail {
                    holder_component_id,
                    held_id,
                } => DynamicCapsInspectRequest::HeldDetail(
                    dynamic_caps::ControlDynamicHeldDetailRequest {
                        holder_component_id,
                        held_id,
                    },
                ),
                InspectArgs::InspectRef {
                    holder_component_id,
                    r#ref,
                } => DynamicCapsInspectRequest::InspectRef(
                    dynamic_caps::ControlDynamicInspectRefRequest {
                        holder_component_id,
                        r#ref,
                    },
                ),
                InspectArgs::ResolveOrigin {
                    holder_component_id,
                    source,
                } => DynamicCapsInspectRequest::ResolveOrigin(
                    dynamic_caps::ControlDynamicResolveOriginRequest {
                        holder_component_id,
                        source: source.into(),
                    },
                ),
            },
            false,
        )
        .await
        .map_err(map_protocol_api_error)?;
        match response {
            DynamicCapsInspectResponse::HeldList(data) => json_response("held_list", data),
            DynamicCapsInspectResponse::HeldDetail(data) => json_response("held_detail", data),
            DynamicCapsInspectResponse::InspectRef(data) => json_response("inspect_ref", data),
            DynamicCapsInspectResponse::ResolveOrigin(data) => {
                json_response("resolve_origin", data)
            }
        }
    }

    #[tool(
        name = "amber.v1.framework_dynamic_caps.mutate",
        description = "Share or revoke dynamic capabilities."
    )]
    async fn mutate(
        &self,
        Parameters(args): Parameters<MutateArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<McpOperationResponse>, McpError> {
        self.authorize(&context)?;
        let response = execute_site_controller_dynamic_caps_mutate(
            &self.app,
            match args {
                MutateArgs::Share {
                    caller_component_id,
                    source,
                    recipient_component_id,
                    idempotency_key,
                    options,
                } => DynamicCapsMutateRequest::Share(dynamic_caps::ControlDynamicShareRequest {
                    caller_component_id,
                    source: source.into(),
                    recipient_component_id,
                    idempotency_key,
                    options,
                }),
                MutateArgs::Revoke {
                    caller_component_id,
                    target,
                } => DynamicCapsMutateRequest::Revoke(dynamic_caps::ControlDynamicRevokeRequest {
                    caller_component_id,
                    target: target.into(),
                }),
            },
            false,
        )
        .await
        .map_err(map_protocol_api_error)?;
        match response {
            DynamicCapsMutateResponse::Share(data) => json_response("share", data),
            DynamicCapsMutateResponse::Revoke(data) => json_response("revoke", data),
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for FrameworkDynamicCapsMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_server_info(Implementation::new("amber-framework-dynamic-caps", "dev"))
        .with_protocol_version(ProtocolVersion::V_2025_06_18)
        .with_instructions(
            "Use the framework_dynamic_caps tools. Read the amber:// help resources only when \
             needed."
                .to_string(),
        )
    }

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ServerInfo, McpError> {
        self.authorize(&context)?;
        if context.peer.peer_info().is_none() {
            context.peer.set_peer_info(request);
        }
        Ok(self.get_info())
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        self.authorize(&context)?;
        Ok(ListResourcesResult {
            resources: vec![
                RawResource::new(HELP_RESOURCE_URI, "framework dynamic caps MCP").no_annotation(),
            ],
            next_cursor: None,
            meta: None,
        })
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        self.authorize(&context)?;
        Ok(ListResourceTemplatesResult {
            resource_templates: vec![
                RawResourceTemplate::new(
                    "amber://framework-dynamic-caps/op/{name}",
                    "framework dynamic caps operation",
                )
                .no_annotation(),
            ],
            next_cursor: None,
            meta: None,
        })
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        self.authorize(&context)?;
        let uri = request.uri;
        let text = if uri.as_str() == HELP_RESOURCE_URI {
            self.help_resource()
        } else if let Some(name) = uri.as_str().strip_prefix(OPERATION_RESOURCE_PREFIX) {
            self.operation_resource(name)?
        } else {
            return Err(McpError::resource_not_found(
                format!("resource {uri} not found"),
                None,
            ));
        };
        Ok(ReadResourceResult::new(vec![ResourceContents::text(
            text, uri,
        )]))
    }
}
