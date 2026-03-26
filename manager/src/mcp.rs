use std::{collections::BTreeMap, sync::Arc};

use rmcp::{
    ErrorData as McpError, Json, RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        AnnotateAble, Implementation, ListResourceTemplatesResult, ListResourcesResult,
        PaginatedRequestParams, ProtocolVersion, RawResource, RawResourceTemplate,
        ReadResourceRequestParams, ReadResourceResult, ResourceContents, ServerCapabilities,
        ServerInfo,
    },
    schemars::{self, JsonSchema},
    service::RequestContext,
    tool, tool_handler, tool_router,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::{
    domain::{
        BindableServiceProviderKind, BindableServiceSourceKind, CreateScenarioRequest,
        DesiredState, ObservedState, ScenarioSourceAllowlistEntryRequest, ServiceProtocol,
        UpgradeScenarioRequest,
    },
    service::{
        BindableServiceFilter, ExportFilter, ExportLookup, ManagerError, ManagerService,
        ScenarioConfigSchemaLookup, ScenarioFilter,
    },
};

pub(crate) fn service(
    core: Arc<ManagerService>,
) -> StreamableHttpService<AmberManagerMcp, LocalSessionManager> {
    StreamableHttpService::new(
        move || Ok(AmberManagerMcp::new(core.clone())),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default(),
    )
}

#[derive(Clone)]
pub(crate) struct AmberManagerMcp {
    core: Arc<ManagerService>,
    tool_router: ToolRouter<Self>,
}

impl AmberManagerMcp {
    fn new(core: Arc<ManagerService>) -> Self {
        Self {
            core,
            tool_router: Self::tool_router(),
        }
    }

    fn tools_by_name(&self) -> BTreeMap<String, rmcp::model::Tool> {
        self.tool_router
            .list_all()
            .into_iter()
            .map(|tool| (tool.name.to_string(), tool))
            .collect()
    }
}

#[derive(Debug, Deserialize, JsonSchema, Default)]
struct BindableServicesListArgs {
    #[serde(default)]
    source_kind: Option<BindableServiceSourceKind>,
    #[serde(default)]
    provider_kind: Option<BindableServiceProviderKind>,
    #[serde(default)]
    scenario_id: Option<String>,
    #[serde(default)]
    export: Option<String>,
    #[serde(default)]
    available: Option<bool>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, JsonSchema)]
pub(crate) struct BindableServicesListResponse {
    pub bindable_services: Vec<crate::domain::BindableServiceResponse>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, JsonSchema)]
pub(crate) struct BindableConfigsListResponse {
    pub bindable_configs: Vec<crate::domain::BindableConfigResponse>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct BindableServicesGetArgs {
    bindable_service_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct BindableConfigsGetArgs {
    bindable_config_id: String,
}

#[derive(Debug, Deserialize, JsonSchema, Default)]
struct ScenariosListArgs {
    #[serde(default)]
    scenario_id: Option<String>,
    #[serde(default)]
    source_url: Option<String>,
    #[serde(default)]
    desired_state: Option<DesiredState>,
    #[serde(default)]
    observed_state: Option<ObservedState>,
    #[serde(default)]
    active_revision: Option<i64>,
    #[serde(default)]
    metadata_exact: Option<Map<String, Value>>,
    #[serde(default)]
    metadata_contains: Option<Map<String, Value>>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, JsonSchema)]
pub(crate) struct ScenariosListResponse {
    pub scenarios: Vec<crate::domain::ScenarioSummaryResponse>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ScenarioIdArgs {
    scenario_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DeleteScenarioArgs {
    scenario_id: String,
    #[serde(default)]
    destroy_storage: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct UpgradeScenarioArgs {
    scenario_id: String,
    #[serde(flatten)]
    request: UpgradeScenarioRequest,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct OperationIdArgs {
    operation_id: String,
}

#[derive(Debug, Deserialize, JsonSchema, Default)]
struct OperationWaitArgs {
    operation_id: String,
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    poll_interval_ms: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema, Default)]
struct ExportsListArgs {
    #[serde(default)]
    scenario_id: Option<String>,
    #[serde(default)]
    available: Option<bool>,
    #[serde(default)]
    protocol: Option<ServiceProtocol>,
}

#[derive(Debug, Deserialize, JsonSchema, Default)]
struct ExportsGetArgs {
    #[serde(default)]
    scenario_id: Option<String>,
    #[serde(default)]
    export: Option<String>,
    #[serde(default)]
    bindable_service_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema, Default)]
struct ExportWaitArgs {
    scenario_id: String,
    export: String,
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    poll_interval_ms: Option<u64>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, JsonSchema)]
pub(crate) struct ScenarioRevisionsListResponse {
    pub revisions: Vec<crate::domain::ScenarioRevisionSummaryResponse>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, JsonSchema)]
pub(crate) struct ExportsListResponse {
    pub exports: Vec<crate::service::ExportDetailResponse>,
}

#[derive(Debug, Deserialize, JsonSchema, Default)]
struct ConfigSchemaArgs {
    #[serde(default)]
    source_url: Option<String>,
    #[serde(default)]
    scenario_id: Option<String>,
}

#[tool_router]
impl AmberManagerMcp {
    #[tool(
        name = "amber.v1.manager.health.get",
        description = "Read manager liveness status."
    )]
    async fn manager_health_get(
        &self,
    ) -> Result<Json<crate::service::ManagerHealthResponse>, McpError> {
        Ok(Json(crate::service::ManagerHealthResponse {
            ok: self.core.health(),
        }))
    }

    #[tool(
        name = "amber.v1.manager.ready.get",
        description = "Read manager readiness status."
    )]
    async fn manager_ready_get(
        &self,
    ) -> Result<Json<crate::service::ManagerReadyResponse>, McpError> {
        Ok(Json(crate::service::ManagerReadyResponse {
            ready: self.core.ready().await,
        }))
    }

    #[tool(
        name = "amber.v1.manager.scenario_source_allowlist.remove",
        description = "Remove one scenario source URL from the operator-managed allowlist."
    )]
    async fn manager_scenario_source_allowlist_remove(
        &self,
        Parameters(request): Parameters<ScenarioSourceAllowlistEntryRequest>,
    ) -> Result<Json<crate::domain::ScenarioSourceAllowlistEntryResponse>, McpError> {
        self.core
            .remove_scenario_source_allowlist_entry(request)
            .map(Json)
            .map_err(map_manager_error)
    }

    #[tool(
        name = "amber.v1.bindable_services.list",
        description = "List bindable services."
    )]
    async fn bindable_services_list(
        &self,
        Parameters(args): Parameters<BindableServicesListArgs>,
    ) -> Result<Json<BindableServicesListResponse>, McpError> {
        self.core
            .list_bindable_services(BindableServiceFilter {
                source_kind: args.source_kind,
                provider_kind: args.provider_kind,
                scenario_id: args.scenario_id,
                export: args.export,
                available: args.available,
            })
            .await
            .map(|bindable_services| Json(BindableServicesListResponse { bindable_services }))
            .map_err(map_manager_error)
    }

    #[tool(
        name = "amber.v1.bindable_services.get",
        description = "Read one bindable service."
    )]
    async fn bindable_services_get(
        &self,
        Parameters(args): Parameters<BindableServicesGetArgs>,
    ) -> Result<Json<crate::domain::BindableServiceResponse>, McpError> {
        self.core
            .get_bindable_service(&args.bindable_service_id)
            .await
            .map(Json)
            .map_err(map_manager_error)
    }

    #[tool(
        name = "amber.v1.bindable_configs.list",
        description = "List bindable configs."
    )]
    async fn bindable_configs_list(&self) -> Result<Json<BindableConfigsListResponse>, McpError> {
        Ok(Json(BindableConfigsListResponse {
            bindable_configs: self.core.list_bindable_configs(),
        }))
    }

    #[tool(
        name = "amber.v1.bindable_configs.get",
        description = "Read one bindable config."
    )]
    async fn bindable_configs_get(
        &self,
        Parameters(args): Parameters<BindableConfigsGetArgs>,
    ) -> Result<Json<crate::domain::BindableConfigResponse>, McpError> {
        self.core
            .get_bindable_config(&args.bindable_config_id)
            .map(Json)
            .map_err(map_manager_error)
    }

    #[tool(name = "amber.v1.scenarios.list", description = "List scenarios.")]
    async fn scenarios_list(
        &self,
        Parameters(args): Parameters<ScenariosListArgs>,
    ) -> Result<Json<ScenariosListResponse>, McpError> {
        self.core
            .list_scenarios(ScenarioFilter {
                scenario_id: args.scenario_id,
                source_url: args.source_url,
                desired_state: args.desired_state,
                observed_state: args.observed_state,
                active_revision: args.active_revision,
                metadata_exact: args.metadata_exact,
                metadata_contains: args.metadata_contains,
            })
            .await
            .map(|scenarios| Json(ScenariosListResponse { scenarios }))
            .map_err(map_manager_error)
    }

    #[tool(name = "amber.v1.scenarios.get", description = "Read one scenario.")]
    async fn scenarios_get(
        &self,
        Parameters(args): Parameters<ScenarioIdArgs>,
    ) -> Result<Json<crate::domain::ScenarioDetailResponse>, McpError> {
        self.core
            .get_scenario(&args.scenario_id)
            .await
            .map(Json)
            .map_err(map_manager_error)
    }

    #[tool(name = "amber.v1.scenarios.create", description = "Create a scenario.")]
    async fn scenarios_create(
        &self,
        Parameters(request): Parameters<CreateScenarioRequest>,
    ) -> Result<Json<crate::domain::EnqueueOperationResponse>, McpError> {
        self.core
            .create_scenario(request)
            .await
            .map(Json)
            .map_err(map_manager_error)
    }

    #[tool(
        name = "amber.v1.scenarios.upgrade",
        description = "Upgrade a scenario."
    )]
    async fn scenarios_upgrade(
        &self,
        Parameters(args): Parameters<UpgradeScenarioArgs>,
    ) -> Result<Json<crate::domain::EnqueueOperationResponse>, McpError> {
        self.core
            .upgrade_scenario(&args.scenario_id, args.request)
            .await
            .map(Json)
            .map_err(map_manager_error)
    }

    #[tool(name = "amber.v1.scenarios.pause", description = "Pause a scenario.")]
    async fn scenarios_pause(
        &self,
        Parameters(args): Parameters<ScenarioIdArgs>,
    ) -> Result<Json<crate::domain::EnqueueOperationResponse>, McpError> {
        self.core
            .pause_scenario(&args.scenario_id)
            .await
            .map(Json)
            .map_err(map_manager_error)
    }

    #[tool(name = "amber.v1.scenarios.resume", description = "Resume a scenario.")]
    async fn scenarios_resume(
        &self,
        Parameters(args): Parameters<ScenarioIdArgs>,
    ) -> Result<Json<crate::domain::EnqueueOperationResponse>, McpError> {
        self.core
            .resume_scenario(&args.scenario_id)
            .await
            .map(Json)
            .map_err(map_manager_error)
    }

    #[tool(name = "amber.v1.scenarios.delete", description = "Delete a scenario.")]
    async fn scenarios_delete(
        &self,
        Parameters(args): Parameters<DeleteScenarioArgs>,
    ) -> Result<Json<crate::domain::EnqueueOperationResponse>, McpError> {
        self.core
            .delete_scenario(&args.scenario_id, args.destroy_storage)
            .await
            .map(Json)
            .map_err(map_manager_error)
    }

    #[tool(
        name = "amber.v1.scenarios.revisions.list",
        description = "List scenario revisions."
    )]
    async fn scenarios_revisions_list(
        &self,
        Parameters(args): Parameters<ScenarioIdArgs>,
    ) -> Result<Json<ScenarioRevisionsListResponse>, McpError> {
        self.core
            .list_revisions(&args.scenario_id)
            .await
            .map(|revisions| Json(ScenarioRevisionsListResponse { revisions }))
            .map_err(map_manager_error)
    }

    #[tool(
        name = "amber.v1.scenarios.config_schema.get",
        description = "Read scenario config schema."
    )]
    async fn scenarios_config_schema_get(
        &self,
        Parameters(args): Parameters<ConfigSchemaArgs>,
    ) -> Result<Json<crate::service::ScenarioConfigSchemaResponse>, McpError> {
        let lookup = match (args.source_url, args.scenario_id) {
            (Some(source_url), None) => ScenarioConfigSchemaLookup::SourceUrl(source_url),
            (None, Some(scenario_id)) => ScenarioConfigSchemaLookup::ScenarioId(scenario_id),
            _ => {
                return Err(McpError::invalid_params(
                    "exactly one of source_url or scenario_id is required",
                    None,
                ));
            }
        };
        self.core
            .get_config_schema(lookup)
            .await
            .map(Json)
            .map_err(map_manager_error)
    }

    #[tool(name = "amber.v1.operations.get", description = "Read one operation.")]
    async fn operations_get(
        &self,
        Parameters(args): Parameters<OperationIdArgs>,
    ) -> Result<Json<crate::domain::OperationStatusResponse>, McpError> {
        self.core
            .get_operation(&args.operation_id)
            .await
            .map(Json)
            .map_err(map_manager_error)
    }

    #[tool(
        name = "amber.v1.operations.wait",
        description = "Wait for one operation."
    )]
    async fn operations_wait(
        &self,
        Parameters(args): Parameters<OperationWaitArgs>,
    ) -> Result<Json<crate::service::OperationWaitResult>, McpError> {
        self.core
            .wait_operation(&args.operation_id, args.timeout_ms, args.poll_interval_ms)
            .await
            .map(Json)
            .map_err(map_manager_error)
    }

    #[tool(name = "amber.v1.exports.list", description = "List scenario exports.")]
    async fn exports_list(
        &self,
        Parameters(args): Parameters<ExportsListArgs>,
    ) -> Result<Json<ExportsListResponse>, McpError> {
        self.core
            .list_exports(ExportFilter {
                scenario_id: args.scenario_id,
                available: args.available,
                protocol: args.protocol,
            })
            .await
            .map(|exports| Json(ExportsListResponse { exports }))
            .map_err(map_manager_error)
    }

    #[tool(
        name = "amber.v1.exports.get",
        description = "Read one scenario export."
    )]
    async fn exports_get(
        &self,
        Parameters(args): Parameters<ExportsGetArgs>,
    ) -> Result<Json<crate::service::ExportDetailResponse>, McpError> {
        let lookup = match (args.scenario_id, args.export, args.bindable_service_id) {
            (Some(scenario_id), Some(export), None) => ExportLookup::ScenarioExport {
                scenario_id,
                export,
            },
            (None, None, Some(bindable_service_id)) => {
                ExportLookup::BindableServiceId(bindable_service_id)
            }
            _ => {
                return Err(McpError::invalid_params(
                    "provide either scenario_id and export, or bindable_service_id",
                    None,
                ));
            }
        };
        self.core
            .get_export(lookup)
            .await
            .map(Json)
            .map_err(map_manager_error)
    }

    #[tool(
        name = "amber.v1.exports.wait",
        description = "Wait for one export to become available."
    )]
    async fn exports_wait(
        &self,
        Parameters(args): Parameters<ExportWaitArgs>,
    ) -> Result<Json<crate::service::ExportWaitResult>, McpError> {
        self.core
            .wait_export(
                &args.scenario_id,
                &args.export,
                args.timeout_ms,
                args.poll_interval_ms,
            )
            .await
            .map(Json)
            .map_err(map_manager_error)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for AmberManagerMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_server_info(Implementation::new("amber-manager", "dev"))
        .with_protocol_version(ProtocolVersion::V_2025_06_18)
        .with_instructions(
            "If you already know the tool name, call it directly. Otherwise read amber://modules \
             and then amber://module/{name}. Use amber://tool/{name} for detailed help, examples, \
             and failure cases."
                .to_string(),
        )
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _cx: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Ok(ListResourcesResult {
            resources: vec![RawResource::new("amber://modules", "amber modules").no_annotation()],
            next_cursor: None,
            meta: None,
        })
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _cx: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        Ok(ListResourceTemplatesResult {
            resource_templates: vec![
                RawResourceTemplate::new("amber://module/{name}", "amber module").no_annotation(),
                RawResourceTemplate::new("amber://tool/{name}", "amber tool").no_annotation(),
            ],
            next_cursor: None,
            meta: None,
        })
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _cx: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        let uri = request.uri;
        let text = if uri.as_str() == "amber://modules" {
            self.render_modules_resource()
        } else if let Some(name) = uri.as_str().strip_prefix("amber://module/") {
            self.render_module_resource(name)?
        } else if let Some(name) = uri.as_str().strip_prefix("amber://tool/") {
            self.render_tool_resource(name)?
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

impl AmberManagerMcp {
    fn render_modules_resource(&self) -> String {
        let modules = module_docs();
        let mut out = String::from("# Amber manager MCP modules\n\n");
        out.push_str(
            "If you already know the tool you want, call it directly. If you are exploring, read \
             one module resource first and then a tool resource only when you need lower-level \
             detail.\n\n",
        );
        for module in modules {
            out.push_str(&format!("- `{}`: {}\n", module.name, module.description));
        }
        out
    }

    fn render_module_resource(&self, name: &str) -> Result<String, McpError> {
        let module = module_docs()
            .iter()
            .find(|module| module.name == name)
            .ok_or_else(|| {
                McpError::resource_not_found(format!("module {} not found", name), None)
            })?;
        let mut tools = self
            .tools_by_name()
            .into_values()
            .filter(|tool| tool_module(tool.name.as_ref()) == name)
            .collect::<Vec<_>>();
        tools.sort_by(|left, right| left.name.cmp(&right.name));

        let mut out = format!(
            "# Module `{}`\n\n{}\n\nWhen to use it: {}\n\n",
            module.name, module.description, module.when_to_use
        );
        out.push_str("## Tools\n\n");
        for tool in tools {
            out.push_str(&format!(
                "- `{}`: {}\n",
                tool.name,
                tool.description
                    .as_deref()
                    .expect("amber MCP tools must define descriptions")
            ));
        }
        Ok(out)
    }

    fn render_tool_resource(&self, name: &str) -> Result<String, McpError> {
        let tools = self.tools_by_name();
        let tool = tools.get(name).ok_or_else(|| {
            McpError::resource_not_found(format!("tool {} not found", name), None)
        })?;
        let extras = tool_doc_extra(name);
        let input_schema = serde_json::to_string_pretty(&tool.input_schema)
            .expect("amber MCP input schemas must serialize");
        let output_schema = serde_json::to_string_pretty(
            tool.output_schema
                .as_ref()
                .expect("amber MCP tools must define output schemas"),
        )
        .expect("amber MCP output schemas must serialize");

        let mut out = format!(
            "# Tool `{}`\n\nModule: `{}`\n\n{}\n\n## Input schema\n\n```json\n{}\n```\n\n## \
             Output schema\n\n```json\n{}\n```\n",
            tool.name,
            tool_module(tool.name.as_ref()),
            tool.description
                .as_deref()
                .expect("amber MCP tools must define descriptions"),
            input_schema,
            output_schema,
        );
        out.push_str("\n## Examples\n\n");
        for example in extras.examples {
            out.push_str(&format!("- {}\n", example));
        }
        out.push_str("\n## Failure cases\n\n");
        for failure in extras.failure_cases {
            out.push_str(&format!("- {}\n", failure));
        }
        Ok(out)
    }
}

fn map_manager_error(error: ManagerError) -> McpError {
    match error.status_code() {
        axum::http::StatusCode::BAD_REQUEST => {
            McpError::invalid_params(error.message().to_string(), None)
        }
        axum::http::StatusCode::NOT_FOUND => {
            McpError::resource_not_found(error.message().to_string(), None)
        }
        axum::http::StatusCode::CONFLICT => {
            McpError::invalid_params(error.message().to_string(), None)
        }
        _ => McpError::internal_error(error.message().to_string(), None),
    }
}

struct ModuleDoc {
    name: &'static str,
    description: &'static str,
    when_to_use: &'static str,
}

struct ToolDocExtra {
    examples: &'static [&'static str],
    failure_cases: &'static [&'static str],
}

fn module_docs() -> &'static [ModuleDoc] {
    &[
        ModuleDoc {
            name: "manager",
            description: "Manager liveness, readiness, and operator policy controls.",
            when_to_use: "Use this before assuming the manager can accept lifecycle operations or \
                          when changing runtime manager policy.",
        },
        ModuleDoc {
            name: "bindable_services",
            description: "Bindable-service discovery for composition.",
            when_to_use: "Use this when you need bindable service identity or availability.",
        },
        ModuleDoc {
            name: "bindable_configs",
            description: "Bindable-config discovery for operator-provided root config values.",
            when_to_use: "Use this when you need bindable config identity before create or \
                          upgrade.",
        },
        ModuleDoc {
            name: "scenarios",
            description: "Scenario inspection, lifecycle, revision history, and config schema \
                          discovery.",
            when_to_use: "Use this for most management actions on scenarios.",
        },
        ModuleDoc {
            name: "operations",
            description: "Operation status and waiting.",
            when_to_use: "Use this after create, pause, resume, upgrade, or delete when you need \
                          completion.",
        },
        ModuleDoc {
            name: "exports",
            description: "Export identity, readiness, and composition-state discovery.",
            when_to_use: "Use this when binding one scenario to another or waiting for a provider \
                          to become ready.",
        },
    ]
}

fn tool_module(name: &str) -> &'static str {
    let module = name
        .strip_prefix("amber.v1.")
        .and_then(|name| name.split('.').next())
        .expect("amber MCP tool names must start with amber.v1.<module>.");
    module_docs()
        .iter()
        .find(|doc| doc.name == module)
        .map(|doc| doc.name)
        .expect("amber MCP tool names must use a known module")
}

fn tool_doc_extra(name: &str) -> ToolDocExtra {
    match name {
        "amber.v1.manager.health.get" => ToolDocExtra {
            examples: &["Call this to check basic liveness before deeper exploration."],
            failure_cases: &["This should only fail on transport or server failure."],
        },
        "amber.v1.manager.ready.get" => ToolDocExtra {
            examples: &["Call this before create or lifecycle operations."],
            failure_cases: &["A false readiness result is normal and not a tool-call error."],
        },
        "amber.v1.manager.scenario_source_allowlist.remove" => ToolDocExtra {
            examples: &[
                "Remove a bootstrap-only manifest URL after the required scenarios have already \
                 been created.",
                "Use the same source_url string you allowed initially; equivalent URLs are \
                 normalized before removal.",
            ],
            failure_cases: &[
                "Removing from a manager with no scenario_source_allowlist is a tool-call failure.",
                "Unknown or invalid source_url values are tool-call failures.",
            ],
        },
        "amber.v1.bindable_services.list" => ToolDocExtra {
            examples: &[
                "List all bindable services.",
                "Filter by scenario_id and available when looking for one export service.",
            ],
            failure_cases: &["Invalid enum values are invalid-params errors."],
        },
        "amber.v1.bindable_services.get" => ToolDocExtra {
            examples: &["Use the bindable_service_id from exports.get or bindable_services.list."],
            failure_cases: &["Unknown bindable service IDs are tool-call failures."],
        },
        "amber.v1.bindable_configs.list" => ToolDocExtra {
            examples: &[
                "List all bindable configs before constructing external_root_config.",
                "Use this with scenarios.config_schema.get when brokering root config choices.",
            ],
            failure_cases: &["This should only fail on transport or server failure."],
        },
        "amber.v1.bindable_configs.get" => ToolDocExtra {
            examples: &["Use the bindable_config_id from bindable_configs.list."],
            failure_cases: &["Unknown bindable config IDs are tool-call failures."],
        },
        "amber.v1.scenarios.list" => ToolDocExtra {
            examples: &[
                "Filter by metadata_exact to find policy-tagged scenarios.",
                "Filter by metadata_contains for simple substring matching on top-level metadata \
                 values.",
            ],
            failure_cases: &["Metadata filters must be JSON objects with top-level keys only."],
        },
        "amber.v1.scenarios.get" => ToolDocExtra {
            examples: &["Read detailed scenario state after operations.wait completes."],
            failure_cases: &["Unknown scenario IDs are tool-call failures."],
        },
        "amber.v1.scenarios.create" => ToolDocExtra {
            examples: &[
                "Read scenarios.config_schema.get first if you do not already know root_config \
                 shape.",
                "Use metadata to tag controller, provider, or consumer scenarios for later lookup.",
            ],
            failure_cases: &[
                "Invalid source_url, invalid slots, or invalid exports surface as tool-call \
                 failures.",
                "scenario_source_allowlist rejections surface as tool-call failures.",
            ],
        },
        "amber.v1.scenarios.upgrade" => ToolDocExtra {
            examples: &[
                "Use this to update source_url, root_config, metadata, telemetry, or publish \
                 settings.",
            ],
            failure_cases: &[
                "Unknown scenario IDs, conflicting in-flight operations, and \
                 scenario_source_allowlist rejections are tool-call failures.",
            ],
        },
        "amber.v1.scenarios.pause" => ToolDocExtra {
            examples: &["Pause consumers before pausing their providers when dependencies matter."],
            failure_cases: &[
                "Conflicts are reported if active dependents still require the scenario.",
            ],
        },
        "amber.v1.scenarios.resume" => ToolDocExtra {
            examples: &["Resume a paused scenario after dependencies are ready."],
            failure_cases: &["Resuming a scenario with no active revision is a tool-call failure."],
        },
        "amber.v1.scenarios.delete" => ToolDocExtra {
            examples: &["Delete a scenario after dependents have been cleaned up."],
            failure_cases: &["Deleting a provider with active dependents is a conflict error."],
        },
        "amber.v1.scenarios.revisions.list" => ToolDocExtra {
            examples: &["Use this after upgrade to inspect revision history."],
            failure_cases: &["Unknown scenario IDs are tool-call failures."],
        },
        "amber.v1.scenarios.config_schema.get" => ToolDocExtra {
            examples: &[
                "Call with source_url before create when root_config shape is unknown.",
                "Call with scenario_id to inspect an existing scenario’s active config schema.",
            ],
            failure_cases: &[
                "Exactly one of source_url or scenario_id must be supplied.",
                "Disallowed or invalid source_url values are tool-call failures.",
            ],
        },
        "amber.v1.operations.get" => ToolDocExtra {
            examples: &["Read raw operation state when you need phase or retry-count details."],
            failure_cases: &["Unknown operation IDs are tool-call failures."],
        },
        "amber.v1.operations.wait" => ToolDocExtra {
            examples: &[
                "Use this after create, pause, resume, upgrade, or delete to wait for terminal \
                 state.",
            ],
            failure_cases: &[
                "Timeouts are normal results with timed_out = true, not tool-call failures.",
            ],
        },
        "amber.v1.exports.list" => ToolDocExtra {
            examples: &["Use this to discover composition-ready exports across scenarios."],
            failure_cases: &["Invalid enum values are invalid-params errors."],
        },
        "amber.v1.exports.get" => ToolDocExtra {
            examples: &[
                "Look up an export by scenario_id and export name.",
                "Look up an export from a bindable_service_id when you already have the service \
                 identity.",
            ],
            failure_cases: &["Provide either scenario_id and export, or bindable_service_id."],
        },
        "amber.v1.exports.wait" => ToolDocExtra {
            examples: &[
                "Wait for a provider export to become available before binding or consuming it.",
            ],
            failure_cases: &["Timeouts are normal results with timed_out = true."],
        },
        _ => panic!("missing MCP tool documentation extras for {name}"),
    }
}
