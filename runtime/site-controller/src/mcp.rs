use std::collections::BTreeMap;

use amber_manifest::ManifestRef;
use amber_mesh::component_protocol::{CreateChildRequest, TemplateResolveRequest};
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
    ccs_api::{
        FrameworkComponentInspectRequest, FrameworkComponentInspectResponse,
        FrameworkComponentMutateRequest, FrameworkComponentMutateResponse,
    },
    mcp_common::{McpOperationResponse, json_response, map_protocol_api_error},
    planner::SiteControllerApp,
    site_controller::{
        authorize_public_request, execute_site_controller_framework_inspect,
        execute_site_controller_framework_mutate,
    },
};

const HELP_RESOURCE_URI: &str = "amber://framework-component";
const OPERATION_RESOURCE_PREFIX: &str = "amber://framework-component/op/";

pub(crate) fn service(
    app: SiteControllerApp,
) -> StreamableHttpService<FrameworkComponentMcp, LocalSessionManager> {
    StreamableHttpService::new(
        move || Ok(FrameworkComponentMcp::new(app.clone())),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default(),
    )
}

#[derive(Clone)]
pub(crate) struct FrameworkComponentMcp {
    app: SiteControllerApp,
    tool_router: ToolRouter<Self>,
}

impl FrameworkComponentMcp {
    fn new(app: SiteControllerApp) -> Self {
        Self {
            app,
            tool_router: Self::tool_router(),
        }
    }

    async fn authorize(
        &self,
        context: &RequestContext<RoleServer>,
    ) -> Result<
        (
            super::state::CapabilityInstanceRecord,
            super::state::FrameworkControlState,
        ),
        McpError,
    > {
        let parts = context
            .extensions
            .get::<Parts>()
            .ok_or_else(|| McpError::invalid_request("missing HTTP request context", None))?;
        authorize_public_request(&self.app, &parts.headers)
            .await
            .map_err(map_protocol_api_error)
    }

    fn help_resource(&self) -> String {
        let mut out = String::from("# framework.component MCP\n\n");
        out.push_str("Tools:\n");
        out.push_str("- `amber.v1.framework_component.inspect`\n");
        out.push_str("- `amber.v1.framework_component.mutate`\n\n");
        out.push_str("Transport:\n");
        out.push_str("- Base control URL: the `framework.component` slot URL\n");
        out.push_str("- MCP endpoint: append `/mcp`\n");
        out.push_str("- HTTP routes remain under `/v1/...`\n\n");
        out.push_str("Inspect operations:\n");
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
        out.push_str("\nMutate operations:\n");
        for op in ["create_child", "destroy_child"] {
            out.push_str(&format!(
                "- `{op}`: read `{}{op}` for arguments, output shape, and caveats\n",
                OPERATION_RESOURCE_PREFIX
            ));
        }
        out
    }

    fn operation_resource(&self, name: &str) -> Result<String, McpError> {
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

fn optional_manifest_ref_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "oneOf": [
            {
                "type": "string",
                "minLength": 1
            },
            {
                "type": "object",
                "additionalProperties": false,
                "required": ["url"],
                "properties": {
                    "url": {
                        "type": "string",
                        "minLength": 1
                    },
                    "digest": {
                        "type": ["string", "null"]
                    }
                }
            },
            {
                "type": "null"
            }
        ]
    })
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
        #[schemars(schema_with = "optional_manifest_ref_schema")]
        manifest: Option<ManifestRef>,
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
        #[schemars(schema_with = "optional_manifest_ref_schema")]
        manifest: Option<ManifestRef>,
        #[serde(default)]
        config: BTreeMap<String, Value>,
        #[serde(default)]
        bindings: BTreeMap<String, BindingInputArg>,
    },
    DestroyChild {
        child: String,
    },
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
    ) -> Result<Json<McpOperationResponse>, McpError> {
        let (record, state) = self.authorize(&context).await?;
        let response = execute_site_controller_framework_inspect(
            &self.app,
            &record,
            &state,
            match args {
                InspectArgs::ListTemplates => FrameworkComponentInspectRequest::ListTemplates,
                InspectArgs::GetTemplate { template } => {
                    FrameworkComponentInspectRequest::GetTemplate { template }
                }
                InspectArgs::ResolveTemplate { template, manifest } => {
                    FrameworkComponentInspectRequest::ResolveTemplate {
                        template,
                        request: TemplateResolveRequest { manifest },
                    }
                }
                InspectArgs::ListChildren => FrameworkComponentInspectRequest::ListChildren,
                InspectArgs::GetChild { child } => {
                    FrameworkComponentInspectRequest::GetChild { child }
                }
                InspectArgs::GetSnapshot => FrameworkComponentInspectRequest::GetSnapshot,
            },
        )
        .await
        .map_err(map_protocol_api_error)?;
        match response {
            FrameworkComponentInspectResponse::ListTemplates(data) => {
                json_response("list_templates", data)
            }
            FrameworkComponentInspectResponse::GetTemplate(data) => {
                json_response("get_template", data)
            }
            FrameworkComponentInspectResponse::ResolveTemplate(data) => {
                json_response("resolve_template", data)
            }
            FrameworkComponentInspectResponse::ListChildren(data) => {
                json_response("list_children", data)
            }
            FrameworkComponentInspectResponse::GetChild(data) => json_response("get_child", data),
            FrameworkComponentInspectResponse::GetSnapshot(data) => {
                json_response("get_snapshot", data)
            }
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
    ) -> Result<Json<McpOperationResponse>, McpError> {
        let (record, state) = self.authorize(&context).await?;
        let response = execute_site_controller_framework_mutate(
            &self.app,
            &record,
            &state,
            match args {
                MutateArgs::CreateChild {
                    template,
                    name,
                    manifest,
                    config,
                    bindings,
                } => FrameworkComponentMutateRequest::CreateChild(CreateChildRequest {
                    template,
                    name,
                    manifest,
                    config,
                    bindings: bindings
                        .into_iter()
                        .map(|(name, input)| (name, input.into()))
                        .collect(),
                }),
                MutateArgs::DestroyChild { child } => {
                    FrameworkComponentMutateRequest::DestroyChild { child }
                }
            },
        )
        .await
        .map_err(map_protocol_api_error)?;
        match response {
            FrameworkComponentMutateResponse::CreateChild(data) => {
                json_response("create_child", data)
            }
            FrameworkComponentMutateResponse::DestroyChild(data) => {
                json_response("destroy_child", data)
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
        let _ = self.authorize(&context).await?;
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
        let _ = self.authorize(&context).await?;
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
        let _ = self.authorize(&context).await?;
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
        let _ = self.authorize(&context).await?;
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn resolve_template_manifest_rejects_unknown_fields() {
        let err = serde_json::from_value::<InspectArgs>(json!({
            "op": "resolve_template",
            "template": "worker",
            "manifest": {
                "url": "worker.json5",
                "digset": "sha256:dGVzdA=="
            }
        }))
        .expect_err("unknown manifest fields should be rejected");
        assert!(
            err.to_string().contains("unknown field `digset`"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn create_child_manifest_uses_shared_manifest_parser() {
        let args = serde_json::from_value::<MutateArgs>(json!({
            "op": "create_child",
            "template": "worker",
            "name": "job",
            "manifest": {
                "url": "worker.json5"
            }
        }))
        .expect("manifest object should deserialize through ManifestRef");
        match args {
            MutateArgs::CreateChild {
                manifest: Some(manifest),
                ..
            } => {
                assert_eq!(manifest.url.as_str(), "worker.json5");
                assert!(manifest.digest.is_none());
            }
            _ => panic!("expected create_child args"),
        }
    }
}
