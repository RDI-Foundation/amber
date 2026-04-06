use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    future::Future,
    io::Write as _,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
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
        TemplateManifestDescription, TemplateMode, TemplateSummary,
    },
    framework_cap_instance_id, router_dynamic_export_route_id, router_export_route_id,
};
use amber_proxy::{
    clear_external_slot_with_retry, register_export_peer_with_retry,
    register_external_slot_with_retry, unregister_export_peer_with_retry,
};
use amber_resolver::{Backend, RemoteResolver, Resolution, Resolver};
use amber_scenario::{
    BindingFrom, ChildTemplate, Component, ComponentId, FrameworkRef, ProvideRef, ResourceRef,
    Scenario, ScenarioIr, SlotRef, TemplateBinding, TemplateConfigField,
    ir::{BindingFromIr, BindingIr, ComponentExportTargetIr, ComponentIr, ManifestCatalogEntryIr},
};
use axum::{
    Json, Router,
    extract::{Path as AxumPath, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine as _;
use miette::{IntoDiagnostic as _, Result, WrapErr as _};
use reqwest::Client as ReqwestClient;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::{net::TcpListener, signal, sync::Mutex};

use crate::mixed_run::{
    BridgeProxyHandle, BridgeProxyKey, DesiredExportPeerOverlay, DesiredExternalSlotOverlay,
    LaunchedSite, SiteActuatorPlan, SiteReceipt, clear_desired_overlay_for_consumer,
    clear_desired_overlay_for_provider, host_service_bind_addr_for_consumer,
    host_service_host_for_consumer, launched_site_from_receipt,
    project_kubernetes_dynamic_child_artifact_files, read_json as read_run_json,
    resolve_link_external_url_for_output, site_actuator_child_root_for_site, site_state_path,
    stop_bridge_proxies, update_desired_overlay_for_consumer, update_desired_overlay_for_provider,
};

include!("state.rs");
include!("api.rs");
include!("planner.rs");
include!("orchestration.rs");
include!("http.rs");

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
