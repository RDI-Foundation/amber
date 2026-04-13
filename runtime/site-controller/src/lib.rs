use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use amber_compiler::{
    CompileOptions, Compiler, DigestStore,
    reporter::CompiledScenario,
    run_plan::{
        ActiveSiteCapabilities, PlacementDefaults, PlacementFile, RunLink, RunPlan,
        RunPlanActivationState, SiteDefinition, SiteKind, build_site_plan_subset,
        plan_dynamic_fragment,
    },
};
use amber_manifest::{
    CapabilityDecl, CapabilityTransport, ComponentDecl, ComponentRef, FrameworkCapabilityName,
    Manifest, ManifestRef, ManifestSpans, NetworkProtocol, RawBinding, RawExportTarget, SlotDecl,
};
use amber_mesh::{
    MeshIdentity, MeshProtocol,
    component_protocol::{
        BindingInputDescription, ChildDescribeResponse, ChildHandle, ChildListResponse, ChildState,
        ChildSummary, ConfigFieldDescription, CreateChildRequest, CreateChildResponse, InputState,
        ProtocolErrorCode, ProtocolErrorResponse, SnapshotResponse, TemplateDescribeResponse,
        TemplateExportsDescription, TemplateLimits, TemplateListResponse,
        TemplateManifestDescription, TemplateMode, TemplateResolveRequest, TemplateSummary,
    },
    dynamic_caps::{
        DescriptorIr, DynamicCapabilitiesSnapshotIr, GrantSnapshotIr, HeldEntryDetail,
        HeldEntryKind, HeldEntryState, HeldEntrySummary, RootAuthoritySelectorIr,
    },
    framework_cap_instance_id, router_dynamic_export_route_id, router_export_route_id,
};
use amber_proxy::{
    apply_route_overlay_with_retry, clear_external_slot_with_retry,
    register_export_peer_with_retry, register_external_slot_with_retry,
    revoke_route_overlay_with_retry, unregister_export_peer_with_retry,
};
use amber_resolver::{Backend, RemoteResolver, Resolution, Resolver};
use amber_scenario::{
    BindingFrom, ChildTemplate, Component, ComponentId, FrameworkRef, ProvideRef, ResourceRef,
    Scenario, ScenarioIr, SlotRef, TemplateBinding, TemplateConfigField,
    ir::{BindingFromIr, BindingIr, ComponentExportTargetIr, ComponentIr, ManifestCatalogEntryIr},
};
use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::Engine as _;
use miette::{IntoDiagnostic as _, Result, WrapErr as _};
use reqwest::Client as ReqwestClient;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::{signal, sync::Mutex};

mod api;
mod ccs_api;
mod control_state_api;
mod control_state_mcp;
mod default_runtime;
mod dynamic_caps;
mod http;
mod mcp;
mod mcp_common;
mod orchestration;
mod planner;
mod runtime_api;
mod site_controller;
mod state;
#[cfg(test)]
mod tests;

pub use self::{
    default_runtime::{
        SiteControllerPeerRouterRoute, add_compose_router_published_route_ports,
        assign_compose_egress_network_subnets, cleanup_dynamic_site_children,
        host_service_bind_addr_for_consumer, inject_compose_site_controller,
        inject_kubernetes_site_controller, inject_site_controller_peer_router_routes,
        observability_endpoint_for_site, prepare_kubernetes_artifact_namespace,
        router_mesh_addr_for_consumer, set_compose_router_published_mesh_port,
        set_site_artifact_mesh_identity_seed, walk_files,
    },
    runtime_api::{
        DesiredExportPeerOverlay, DesiredExternalSlotOverlay, DesiredRouteOverlay, LaunchedSite,
        LiveComponentRuntimeMetadata, SiteControllerRuntimeFuture, SiteControllerRuntimePlan,
        SiteReceipt, launched_site_from_receipt, parse_control_endpoint,
        project_kubernetes_dynamic_child_artifact_files, site_controller_plan_path,
        site_controller_runtime_child_root_for_site,
        site_controller_runtime_plan_from_controller_plan, site_state_path,
    },
    state::{
        DynamicInputDirectRecord, DynamicInputRouteRecord, DynamicInputRouteTarget,
        DynamicProxyExportRecord, SITE_CONTROLLER_INTERNAL_CAPABILITY, SITE_CONTROLLER_PORT,
        SITE_CONTROLLER_SERVICE_NAME, SiteControllerPlan, authority_url_for_listen_addr,
        build_site_controller_state, generate_framework_auth_token,
        site_controller_internal_route_id, write_control_state, write_site_controller_plan,
    },
};

pub async fn run_site_controller_default(plan_path: PathBuf) -> Result<()> {
    site_controller::run_site_controller(
        plan_path,
        default_runtime::default_site_controller_runtime(),
    )
    .await
}
