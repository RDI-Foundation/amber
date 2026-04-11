use std::{collections::BTreeMap, str::FromStr};

use amber_manifest::ManifestRef;
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
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    api::*,
    http::*,
    orchestration::ProtocolApiError,
    planner::CcsApp,
    state::{CapabilityInstanceRecord, FrameworkControlState},
    *,
};

const HELP_RESOURCE_URI: &str = "amber://framework-component";
const OPERATION_RESOURCE_PREFIX: &str = "amber://framework-component/op/";

pub(crate) fn service(
    app: CcsApp,
) -> StreamableHttpService<FrameworkComponentMcp, LocalSessionManager> {
    StreamableHttpService::new(
        move || Ok(FrameworkComponentMcp::new(app.clone())),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default(),
    )
}

#[derive(Clone)]
pub(crate) struct FrameworkComponentMcp {
    app: CcsApp,
    tool_router: ToolRouter<Self>,
}

impl FrameworkComponentMcp {
    fn new(app: CcsApp) -> Self {
        Self {
            app,
            tool_router: Self::tool_router(),
        }
    }

    async fn authorize(
        &self,
        context: &RequestContext<RoleServer>,
    ) -> Result<(CapabilityInstanceRecord, FrameworkControlState), McpError> {
        let parts = context
            .extensions
            .get::<Parts>()
            .ok_or_else(|| McpError::invalid_request("missing HTTP request context", None))?;
        authorize_request(&self.app, &parts.headers)
            .await
            .map_err(map_protocol_api_error)
    }

    fn json_response(
        &self,
        op: &'static str,
        data: impl Serialize,
    ) -> Result<Json<FrameworkMcpResponse>, McpError> {
        let data = serde_json::to_value(data).map_err(|err| {
            McpError::internal_error(
                format!("failed to serialize framework.component `{op}` result: {err}"),
                None,
            )
        })?;
        Ok(Json(FrameworkMcpResponse {
            op: op.to_string(),
            data,
        }))
    }

    fn render_help_resource(&self) -> String {
        let mut out = String::from("# framework.component MCP\n\n");
        out.push_str(
            "This MCP surface is intentionally compact. Use \
             `amber.v1.framework_component.inspect` for reads and \
             `amber.v1.framework_component.mutate` for create or destroy. Read a specific \
             operation resource only when you need field-level detail.\n\n",
        );
        out.push_str("## Transport\n\n");
        out.push_str(
            "- Base control URL: the existing `framework.component` slot URL\n- MCP endpoint: \
             append `/mcp`\n- Existing HTTP routes under `/v1/...` remain unchanged\n\n",
        );
        out.push_str("## Inspect operations\n\n");
        for op in [
            "list_templates",
            "get_template",
            "resolve_template",
            "list_children",
            "get_child",
            "get_snapshot",
        ] {
            out.push_str(&format!(
                "- `{op}`: read `{}{op}` for arguments, output shape, and caveats\n",
                OPERATION_RESOURCE_PREFIX
            ));
        }
        out.push_str("\n## Mutate operations\n\n");
        for op in ["create_child", "destroy_child"] {
            out.push_str(&format!(
                "- `{op}`: read `{}{op}` for arguments, output shape, and caveats\n",
                OPERATION_RESOURCE_PREFIX
            ));
        }
        out.push_str(
            "\n`get_snapshot` can return a large payload. Prefer narrower reads unless you \
             specifically need the full live graph snapshot.\n",
        );
        out
    }

    fn render_operation_resource(&self, name: &str) -> Result<String, McpError> {
        let doc = match name {
            "list_templates" => {
                "# `list_templates`\n\nTool: `amber.v1.framework_component.inspect`\n\nArguments:\n\
                 ```json\n{ \"op\": \"list_templates\" }\n```\n\nReturns `data` matching HTTP \
                 `GET /v1/templates`."
            }
            "get_template" => {
                "# `get_template`\n\nTool: `amber.v1.framework_component.inspect`\n\nArguments:\n\
                 ```json\n{ \"op\": \"get_template\", \"template\": \"worker\" }\n```\n\nReturns \
                 `data` matching HTTP `GET /v1/templates/{template}`."
            }
            "resolve_template" => {
                "# `resolve_template`\n\nTool: `amber.v1.framework_component.inspect`\n\nArguments:\n\
                 ```json\n{ \"op\": \"resolve_template\", \"template\": \"worker\", \"manifest\": \"https://example.invalid/worker.json5\" }\n```\n\n\
                 `manifest` may be omitted, a URL string, or an object `{ \"url\": ..., \"digest\": ... }`. \
                 Returns `data` matching HTTP `POST /v1/templates/{template}/resolve`."
            }
            "list_children" => {
                "# `list_children`\n\nTool: `amber.v1.framework_component.inspect`\n\nArguments:\n\
                 ```json\n{ \"op\": \"list_children\" }\n```\n\nReturns `data` matching HTTP \
                 `GET /v1/children`."
            }
            "get_child" => {
                "# `get_child`\n\nTool: `amber.v1.framework_component.inspect`\n\nArguments:\n\
                 ```json\n{ \"op\": \"get_child\", \"child\": \"job\" }\n```\n\nReturns `data` \
                 matching HTTP `GET /v1/children/{child}`."
            }
            "get_snapshot" => {
                "# `get_snapshot`\n\nTool: `amber.v1.framework_component.inspect`\n\nArguments:\n\
                 ```json\n{ \"op\": \"get_snapshot\" }\n```\n\nReturns `data` matching HTTP \
                 `POST /v1/snapshot`. Only the root authority may call this, and the result can \
                 be large."
            }
            "create_child" => {
                "# `create_child`\n\nTool: `amber.v1.framework_component.mutate`\n\nArguments:\n\
                 ```json\n{\n  \"op\": \"create_child\",\n  \"template\": \"worker\",\n  \"name\": \"job\",\n  \"manifest\": \"https://example.invalid/worker.json5\",\n  \"config\": { \"label\": \"hello\" },\n  \"bindings\": { \"realm\": { \"selector\": \"slots.realm\" } }\n}\n```\n\n\
                 `manifest` may be omitted, a URL string, or an object `{ \"url\": ..., \"digest\": ... }`. \
                 Returns `data` matching HTTP `POST /v1/children`."
            }
            "destroy_child" => {
                "# `destroy_child`\n\nTool: `amber.v1.framework_component.mutate`\n\nArguments:\n\
                 ```json\n{ \"op\": \"destroy_child\", \"child\": \"job\" }\n```\n\nReturns a \
                 small confirmation object instead of the HTTP 204 empty body."
            }
            _ => {
                return Err(McpError::resource_not_found(
                    format!("framework.component operation `{name}` not found"),
                    None,
                ));
            }
        };
        Ok(doc.to_string())
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(untagged)]
enum ManifestArg {
    Url(String),
    Pinned(ManifestArgObject),
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ManifestArgObject {
    url: String,
    #[serde(default)]
    digest: Option<String>,
}

impl ManifestArg {
    fn into_manifest_ref(self) -> Result<ManifestRef, McpError> {
        match self {
            Self::Url(url) => ManifestRef::from_str(&url)
                .map_err(|err| McpError::invalid_params(err.to_string(), None)),
            Self::Pinned(input) => serde_json::from_value(serde_json::json!({
                "url": input.url,
                "digest": input.digest,
            }))
            .map_err(|err| McpError::invalid_params(err.to_string(), None)),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
struct BindingInputArg {
    #[serde(default)]
    selector: Option<String>,
    #[serde(default)]
    handle: Option<String>,
}

impl From<BindingInputArg> for amber_mesh::component_protocol::BindingInput {
    fn from(value: BindingInputArg) -> Self {
        Self {
            selector: value.selector,
            handle: value.handle,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case")]
enum InspectArgs {
    ListTemplates,
    GetTemplate {
        template: String,
    },
    ResolveTemplate {
        template: String,
        #[serde(default)]
        manifest: Option<ManifestArg>,
    },
    ListChildren,
    GetChild {
        child: String,
    },
    GetSnapshot,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case")]
enum MutateArgs {
    CreateChild {
        template: String,
        name: String,
        #[serde(default)]
        manifest: Option<ManifestArg>,
        #[serde(default)]
        config: BTreeMap<String, Value>,
        #[serde(default)]
        bindings: BTreeMap<String, BindingInputArg>,
    },
    DestroyChild {
        child: String,
    },
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
struct FrameworkMcpResponse {
    op: String,
    data: Value,
}

#[tool_router]
impl FrameworkComponentMcp {
    #[tool(
        name = "amber.v1.framework_component.inspect",
        description = "Read framework.component state.",
        annotations(read_only_hint = true)
    )]
    async fn inspect(
        &self,
        Parameters(args): Parameters<InspectArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<FrameworkMcpResponse>, McpError> {
        let (record, state) = self.authorize(&context).await?;
        match args {
            InspectArgs::ListTemplates => self.json_response(
                "list_templates",
                list_templates(&state, record.authority_realm_id).map_err(map_protocol_error)?,
            ),
            InspectArgs::GetTemplate { template } => self.json_response(
                "get_template",
                describe_template(&state, record.authority_realm_id, &template)
                    .map_err(map_protocol_error)?,
            ),
            InspectArgs::ResolveTemplate { template, manifest } => self.json_response(
                "resolve_template",
                resolve_template(
                    &state,
                    record.authority_realm_id,
                    &template,
                    TemplateResolveRequest {
                        manifest: manifest.map(ManifestArg::into_manifest_ref).transpose()?,
                    },
                )
                .await
                .map_err(map_protocol_error)?,
            ),
            InspectArgs::ListChildren => self.json_response(
                "list_children",
                list_children(&state, record.authority_realm_id),
            ),
            InspectArgs::GetChild { child } => self.json_response(
                "get_child",
                describe_child(&state, record.authority_realm_id, &child)
                    .map_err(map_protocol_error)?,
            ),
            InspectArgs::GetSnapshot => self.json_response(
                "get_snapshot",
                snapshot(&state, record.authority_realm_id).map_err(map_protocol_error)?,
            ),
        }
    }

    #[tool(
        name = "amber.v1.framework_component.mutate",
        description = "Create or destroy framework.component children."
    )]
    async fn mutate(
        &self,
        Parameters(args): Parameters<MutateArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<FrameworkMcpResponse>, McpError> {
        let (record, _) = self.authorize(&context).await?;
        match args {
            MutateArgs::CreateChild {
                template,
                name,
                manifest,
                config,
                bindings,
            } => self.json_response(
                "create_child",
                forward_create_child(
                    &self.app,
                    &record.cap_instance_id,
                    CreateChildRequest {
                        template,
                        name,
                        manifest: manifest.map(ManifestArg::into_manifest_ref).transpose()?,
                        config,
                        bindings: bindings
                            .into_iter()
                            .map(|(name, input)| (name, input.into()))
                            .collect(),
                    },
                )
                .await
                .map_err(map_protocol_api_error)?,
            ),
            MutateArgs::DestroyChild { child } => {
                forward_destroy_child(&self.app, &record.cap_instance_id, &child)
                    .await
                    .map_err(map_protocol_api_error)?;
                self.json_response(
                    "destroy_child",
                    serde_json::json!({
                        "child": child,
                        "destroyed": true,
                    }),
                )
            }
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for FrameworkComponentMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_server_info(Implementation::new("amber-framework-component", "dev"))
        .with_protocol_version(ProtocolVersion::V_2025_06_18)
        .with_instructions(
            "Use `amber.v1.framework_component.inspect` for reads and \
             `amber.v1.framework_component.mutate` for create or destroy. Read \
             `amber://framework-component` only when you need more detail."
                .to_string(),
        )
    }

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ServerInfo, McpError> {
        self.authorize(&context).await?;
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
        self.authorize(&context).await?;
        Ok(ListResourcesResult {
            resources: vec![
                RawResource::new(HELP_RESOURCE_URI, "framework.component MCP").no_annotation(),
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
        self.authorize(&context).await?;
        Ok(ListResourceTemplatesResult {
            resource_templates: vec![
                RawResourceTemplate::new(
                    "amber://framework-component/op/{name}",
                    "framework.component operation",
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
        self.authorize(&context).await?;
        let uri = request.uri;
        let text = if uri.as_str() == HELP_RESOURCE_URI {
            self.render_help_resource()
        } else if let Some(name) = uri.as_str().strip_prefix(OPERATION_RESOURCE_PREFIX) {
            self.render_operation_resource(name)?
        } else {
            return Err(McpError::resource_not_found(
                format!("resource {} not found", uri),
                None,
            ));
        };

        Ok(ReadResourceResult::new(vec![ResourceContents::text(
            text, uri,
        )]))
    }
}

fn map_protocol_api_error(error: ProtocolApiError) -> McpError {
    map_protocol_error(error.0)
}

fn map_protocol_error(error: ProtocolErrorResponse) -> McpError {
    let data = Some(
        serde_json::to_value(&error).expect("framework component protocol errors should serialize"),
    );
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
