use std::{
    fs,
    future::Future,
    io::{Read, Write},
    sync::OnceLock,
    time::Duration as StdDuration,
};

use amber_compiler::run_plan::build_run_plan;
use amber_mesh::{
    InboundRoute, InboundTarget, MeshConfigPublic, MeshIdentityPublic, MeshPeer, MeshProtocol,
    OutboundRoute, TransportConfig,
    component_protocol::BindingInput,
    dynamic_caps::{
        self as mesh_dynamic_caps, DynamicCapabilitiesSnapshotIr, DynamicCapabilityRefClaims,
        HeldEntryKind, HeldEntryState, RootAuthoritySelectorIr,
    },
};
use axum::{Router, http::HeaderMap};
use reqwest::{Client, StatusCode};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use tempfile::TempDir;
use url::Url;

use super::{api::*, http::*, orchestration::*, planner::*, state::*, *};
use crate::{
    ccs_api::FrameworkComponentInspectRequest,
    runtime_api::{SharedSiteControllerRuntime, SiteControllerRuntime},
    site_controller::RouterIdentityResponse,
};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct DirectRuntimeState {
    #[serde(default)]
    slot_ports_by_component: BTreeMap<usize, BTreeMap<String, u16>>,
    #[serde(default)]
    slot_route_ports_by_component: BTreeMap<usize, BTreeMap<String, Vec<u16>>>,
    #[serde(default)]
    dynamic_caps_port_by_component: BTreeMap<usize, u16>,
    #[serde(default)]
    component_mesh_port_by_id: BTreeMap<usize, u16>,
    #[serde(default)]
    router_mesh_port: Option<u16>,
}

fn direct_runtime_state_path(plan_root: &Path) -> PathBuf {
    plan_root.join(".amber").join("direct-runtime.json")
}

#[derive(Clone, Default)]
struct TestSiteControllerRuntime;

fn ready_site_controller_flag() -> Arc<std::sync::atomic::AtomicBool> {
    Arc::new(std::sync::atomic::AtomicBool::new(true))
}

impl SiteControllerRuntime for TestSiteControllerRuntime {
    fn cleanup<'a>(&'a self) -> SiteControllerRuntimeFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn resolve_link_external_url<'a>(
        &'a self,
        _provider: &'a LaunchedSite,
        _provider_output_dir: &'a Path,
        link: &'a amber_compiler::run_plan::RunLink,
        _consumer_kind: SiteKind,
        _run_root: &'a Path,
    ) -> SiteControllerRuntimeFuture<'a, String> {
        Box::pin(async move {
            Ok(match link.protocol {
                amber_manifest::NetworkProtocol::Tcp => "tcp://127.0.0.1:1".to_string(),
                _ => "http://127.0.0.1:1".to_string(),
            })
        })
    }

    fn prepare_child<'a>(
        &'a self,
        _plan: &'a SiteControllerPlan,
        _state: FrameworkControlState,
        _child: LiveChildRecord,
    ) -> SiteControllerRuntimeFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn publish_child<'a>(
        &'a self,
        _plan: &'a SiteControllerPlan,
        _state: FrameworkControlState,
        _child: LiveChildRecord,
    ) -> SiteControllerRuntimeFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn rollback_child<'a>(
        &'a self,
        _plan: &'a SiteControllerPlan,
        _child_id: u64,
    ) -> SiteControllerRuntimeFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn destroy_child<'a>(
        &'a self,
        _plan: &'a SiteControllerPlan,
        _state: FrameworkControlState,
        _child: LiveChildRecord,
    ) -> SiteControllerRuntimeFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn collect_live_component_runtime_metadata(
        &self,
        plan: &SiteControllerRuntimePlan,
    ) -> miette::Result<BTreeMap<String, LiveComponentRuntimeMetadata>> {
        if plan.kind != SiteKind::Direct {
            return Err(miette::miette!(
                "test runtime only implements direct site runtime metadata"
            ));
        }
        let artifact_dir = PathBuf::from(&plan.artifact_dir);
        let runtime_root = PathBuf::from(
            plan.runtime_root
                .as_deref()
                .ok_or_else(|| miette::miette!("direct test site is missing its runtime root"))?,
        );
        let direct_plan: serde_json::Value =
            read_json(&artifact_dir.join("direct-plan.json"), "direct plan")?;
        let runtime_state: DirectRuntimeState = read_json(
            &direct_runtime_state_path(&artifact_dir),
            "direct runtime state",
        )?;
        let mut components = BTreeMap::new();
        for component in direct_plan["components"].as_array().into_iter().flatten() {
            let Some(component_id) = component.get("id").and_then(serde_json::Value::as_u64) else {
                continue;
            };
            let Some(moniker) = component.get("moniker").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let Some(port) = runtime_state
                .component_mesh_port_by_id
                .get(&(component_id as usize))
                .copied()
            else {
                continue;
            };
            let Some(mesh_config_path) = component
                .get("sidecar")
                .and_then(|value| value.get("mesh_config_path"))
                .and_then(serde_json::Value::as_str)
            else {
                continue;
            };
            let mesh_config = read_json(
                &runtime_root.join(mesh_config_path),
                "component mesh config",
            )?;
            components.insert(
                moniker.to_string(),
                LiveComponentRuntimeMetadata {
                    moniker: moniker.to_string(),
                    host_mesh_addr: format!("127.0.0.1:{port}"),
                    control_endpoint: None,
                    mesh_config,
                },
            );
        }
        Ok(components)
    }

    fn load_live_site_router_mesh_config(
        &self,
        plan: &SiteControllerRuntimePlan,
    ) -> miette::Result<MeshConfigPublic> {
        if plan.kind != SiteKind::Direct {
            return Err(miette::miette!(
                "test runtime only implements direct site router metadata"
            ));
        }
        let artifact_dir = PathBuf::from(&plan.artifact_dir);
        let runtime_root = PathBuf::from(
            plan.runtime_root
                .as_deref()
                .ok_or_else(|| miette::miette!("direct test site is missing its runtime root"))?,
        );
        let direct_plan: serde_json::Value =
            read_json(&artifact_dir.join("direct-plan.json"), "direct plan")?;
        let mesh_config_path = direct_plan["router"]["mesh_config_path"]
            .as_str()
            .ok_or_else(|| {
                miette::miette!("direct test site is missing router mesh config path")
            })?;
        read_json(&runtime_root.join(mesh_config_path), "router mesh config")
    }

    fn router_mesh_addr_for_consumer(
        &self,
        _provider_kind: SiteKind,
        _consumer_kind: SiteKind,
        router_mesh_addr: &str,
    ) -> miette::Result<String> {
        Ok(router_mesh_addr.to_string())
    }

    fn update_desired_overlay_for_consumer(
        &self,
        _site_state_root: &Path,
        _overlay_id: &str,
        _overlay: DesiredExternalSlotOverlay,
    ) -> miette::Result<()> {
        Ok(())
    }

    fn update_desired_overlay_for_provider(
        &self,
        _site_state_root: &Path,
        _overlay_id: &str,
        _overlay: DesiredExportPeerOverlay,
    ) -> miette::Result<()> {
        Ok(())
    }

    fn clear_desired_overlay_for_consumer(
        &self,
        _site_state_root: &Path,
        _overlay_id: &str,
    ) -> miette::Result<()> {
        Ok(())
    }

    fn clear_desired_overlay_for_provider(
        &self,
        _site_state_root: &Path,
        _overlay_id: &str,
    ) -> miette::Result<()> {
        Ok(())
    }
}

fn test_runtime() -> SharedSiteControllerRuntime {
    Arc::new(TestSiteControllerRuntime)
}

type DestroyCalls = Arc<std::sync::Mutex<Vec<(u64, String)>>>;
type PublishCalls = Arc<std::sync::Mutex<Vec<(u64, String)>>>;

#[derive(Clone, Default)]
struct FailingPublishRuntime {
    destroy_calls: DestroyCalls,
}

impl SiteControllerRuntime for FailingPublishRuntime {
    fn cleanup<'a>(&'a self) -> SiteControllerRuntimeFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn resolve_link_external_url<'a>(
        &'a self,
        _provider: &'a LaunchedSite,
        _provider_output_dir: &'a Path,
        _link: &'a amber_compiler::run_plan::RunLink,
        _consumer_kind: SiteKind,
        _run_root: &'a Path,
    ) -> SiteControllerRuntimeFuture<'a, String> {
        Box::pin(async { Ok("http://127.0.0.1:1".to_string()) })
    }

    fn prepare_child<'a>(
        &'a self,
        _plan: &'a SiteControllerPlan,
        _state: FrameworkControlState,
        _child: LiveChildRecord,
    ) -> SiteControllerRuntimeFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn publish_child<'a>(
        &'a self,
        _plan: &'a SiteControllerPlan,
        _state: FrameworkControlState,
        _child: LiveChildRecord,
    ) -> SiteControllerRuntimeFuture<'a, ()> {
        Box::pin(async { Err(miette::miette!("publish exploded")) })
    }

    fn rollback_child<'a>(
        &'a self,
        _plan: &'a SiteControllerPlan,
        _child_id: u64,
    ) -> SiteControllerRuntimeFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn destroy_child<'a>(
        &'a self,
        _plan: &'a SiteControllerPlan,
        _state: FrameworkControlState,
        child: LiveChildRecord,
    ) -> SiteControllerRuntimeFuture<'a, ()> {
        let destroy_calls = self.destroy_calls.clone();
        Box::pin(async move {
            let site_id = child_runtime_site_id(&child).expect("child site id");
            destroy_calls
                .lock()
                .expect("destroy call log mutex should lock")
                .push((child.child_id, site_id));
            Ok(())
        })
    }

    fn collect_live_component_runtime_metadata(
        &self,
        _plan: &SiteControllerRuntimePlan,
    ) -> miette::Result<BTreeMap<String, LiveComponentRuntimeMetadata>> {
        Ok(BTreeMap::new())
    }

    fn load_live_site_router_mesh_config(
        &self,
        _plan: &SiteControllerRuntimePlan,
    ) -> miette::Result<MeshConfigPublic> {
        Err(miette::miette!(
            "failing publish runtime should not load live site router mesh config"
        ))
    }

    fn router_mesh_addr_for_consumer(
        &self,
        _provider_kind: SiteKind,
        _consumer_kind: SiteKind,
        router_mesh_addr: &str,
    ) -> miette::Result<String> {
        Ok(router_mesh_addr.to_string())
    }

    fn update_desired_overlay_for_consumer(
        &self,
        _site_state_root: &Path,
        _overlay_id: &str,
        _overlay: DesiredExternalSlotOverlay,
    ) -> miette::Result<()> {
        Ok(())
    }

    fn update_desired_overlay_for_provider(
        &self,
        _site_state_root: &Path,
        _overlay_id: &str,
        _overlay: DesiredExportPeerOverlay,
    ) -> miette::Result<()> {
        Ok(())
    }

    fn clear_desired_overlay_for_consumer(
        &self,
        _site_state_root: &Path,
        _overlay_id: &str,
    ) -> miette::Result<()> {
        Ok(())
    }

    fn clear_desired_overlay_for_provider(
        &self,
        _site_state_root: &Path,
        _overlay_id: &str,
    ) -> miette::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Default)]
struct RecordingPublishRuntime {
    publish_calls: PublishCalls,
}

impl SiteControllerRuntime for RecordingPublishRuntime {
    fn cleanup<'a>(&'a self) -> SiteControllerRuntimeFuture<'a, ()> {
        TestSiteControllerRuntime.cleanup()
    }

    fn resolve_link_external_url<'a>(
        &'a self,
        provider: &'a LaunchedSite,
        provider_output_dir: &'a Path,
        link: &'a amber_compiler::run_plan::RunLink,
        consumer_kind: SiteKind,
        run_root: &'a Path,
    ) -> SiteControllerRuntimeFuture<'a, String> {
        TestSiteControllerRuntime.resolve_link_external_url(
            provider,
            provider_output_dir,
            link,
            consumer_kind,
            run_root,
        )
    }

    fn prepare_child<'a>(
        &'a self,
        _plan: &'a SiteControllerPlan,
        _state: FrameworkControlState,
        _child: LiveChildRecord,
    ) -> SiteControllerRuntimeFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn publish_child<'a>(
        &'a self,
        _plan: &'a SiteControllerPlan,
        _state: FrameworkControlState,
        child: LiveChildRecord,
    ) -> SiteControllerRuntimeFuture<'a, ()> {
        let publish_calls = self.publish_calls.clone();
        Box::pin(async move {
            let site_id = child_runtime_site_id(&child).expect("child site id");
            publish_calls
                .lock()
                .expect("publish call log mutex should lock")
                .push((child.child_id, site_id));
            Ok(())
        })
    }

    fn rollback_child<'a>(
        &'a self,
        _plan: &'a SiteControllerPlan,
        _child_id: u64,
    ) -> SiteControllerRuntimeFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn destroy_child<'a>(
        &'a self,
        _plan: &'a SiteControllerPlan,
        _state: FrameworkControlState,
        _child: LiveChildRecord,
    ) -> SiteControllerRuntimeFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn collect_live_component_runtime_metadata(
        &self,
        plan: &SiteControllerRuntimePlan,
    ) -> miette::Result<BTreeMap<String, LiveComponentRuntimeMetadata>> {
        TestSiteControllerRuntime.collect_live_component_runtime_metadata(plan)
    }

    fn load_live_site_router_mesh_config(
        &self,
        plan: &SiteControllerRuntimePlan,
    ) -> miette::Result<MeshConfigPublic> {
        TestSiteControllerRuntime.load_live_site_router_mesh_config(plan)
    }

    fn router_mesh_addr_for_consumer(
        &self,
        provider_kind: SiteKind,
        consumer_kind: SiteKind,
        router_mesh_addr: &str,
    ) -> miette::Result<String> {
        TestSiteControllerRuntime.router_mesh_addr_for_consumer(
            provider_kind,
            consumer_kind,
            router_mesh_addr,
        )
    }

    fn update_desired_overlay_for_consumer(
        &self,
        site_state_root: &Path,
        overlay_id: &str,
        overlay: DesiredExternalSlotOverlay,
    ) -> miette::Result<()> {
        TestSiteControllerRuntime.update_desired_overlay_for_consumer(
            site_state_root,
            overlay_id,
            overlay,
        )
    }

    fn update_desired_overlay_for_provider(
        &self,
        site_state_root: &Path,
        overlay_id: &str,
        overlay: DesiredExportPeerOverlay,
    ) -> miette::Result<()> {
        TestSiteControllerRuntime.update_desired_overlay_for_provider(
            site_state_root,
            overlay_id,
            overlay,
        )
    }

    fn clear_desired_overlay_for_consumer(
        &self,
        site_state_root: &Path,
        overlay_id: &str,
    ) -> miette::Result<()> {
        TestSiteControllerRuntime.clear_desired_overlay_for_consumer(site_state_root, overlay_id)
    }

    fn clear_desired_overlay_for_provider(
        &self,
        site_state_root: &Path,
        overlay_id: &str,
    ) -> miette::Result<()> {
        TestSiteControllerRuntime.clear_desired_overlay_for_provider(site_state_root, overlay_id)
    }
}

#[derive(Clone, Default)]
struct FailingRollbackRuntime;

impl SiteControllerRuntime for FailingRollbackRuntime {
    fn cleanup<'a>(&'a self) -> SiteControllerRuntimeFuture<'a, ()> {
        TestSiteControllerRuntime.cleanup()
    }

    fn resolve_link_external_url<'a>(
        &'a self,
        provider: &'a LaunchedSite,
        provider_output_dir: &'a Path,
        link: &'a amber_compiler::run_plan::RunLink,
        consumer_kind: SiteKind,
        run_root: &'a Path,
    ) -> SiteControllerRuntimeFuture<'a, String> {
        TestSiteControllerRuntime.resolve_link_external_url(
            provider,
            provider_output_dir,
            link,
            consumer_kind,
            run_root,
        )
    }

    fn prepare_child<'a>(
        &'a self,
        _plan: &'a SiteControllerPlan,
        _state: FrameworkControlState,
        _child: LiveChildRecord,
    ) -> SiteControllerRuntimeFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn publish_child<'a>(
        &'a self,
        _plan: &'a SiteControllerPlan,
        _state: FrameworkControlState,
        _child: LiveChildRecord,
    ) -> SiteControllerRuntimeFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn rollback_child<'a>(
        &'a self,
        _plan: &'a SiteControllerPlan,
        _child_id: u64,
    ) -> SiteControllerRuntimeFuture<'a, ()> {
        Box::pin(async { Err(miette::miette!("rollback exploded")) })
    }

    fn destroy_child<'a>(
        &'a self,
        _plan: &'a SiteControllerPlan,
        _state: FrameworkControlState,
        _child: LiveChildRecord,
    ) -> SiteControllerRuntimeFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn collect_live_component_runtime_metadata(
        &self,
        plan: &SiteControllerRuntimePlan,
    ) -> miette::Result<BTreeMap<String, LiveComponentRuntimeMetadata>> {
        TestSiteControllerRuntime.collect_live_component_runtime_metadata(plan)
    }

    fn load_live_site_router_mesh_config(
        &self,
        plan: &SiteControllerRuntimePlan,
    ) -> miette::Result<MeshConfigPublic> {
        TestSiteControllerRuntime.load_live_site_router_mesh_config(plan)
    }

    fn router_mesh_addr_for_consumer(
        &self,
        provider_kind: SiteKind,
        consumer_kind: SiteKind,
        router_mesh_addr: &str,
    ) -> miette::Result<String> {
        TestSiteControllerRuntime.router_mesh_addr_for_consumer(
            provider_kind,
            consumer_kind,
            router_mesh_addr,
        )
    }

    fn update_desired_overlay_for_consumer(
        &self,
        site_state_root: &Path,
        overlay_id: &str,
        overlay: DesiredExternalSlotOverlay,
    ) -> miette::Result<()> {
        TestSiteControllerRuntime.update_desired_overlay_for_consumer(
            site_state_root,
            overlay_id,
            overlay,
        )
    }

    fn update_desired_overlay_for_provider(
        &self,
        site_state_root: &Path,
        overlay_id: &str,
        overlay: DesiredExportPeerOverlay,
    ) -> miette::Result<()> {
        TestSiteControllerRuntime.update_desired_overlay_for_provider(
            site_state_root,
            overlay_id,
            overlay,
        )
    }

    fn clear_desired_overlay_for_consumer(
        &self,
        site_state_root: &Path,
        overlay_id: &str,
    ) -> miette::Result<()> {
        TestSiteControllerRuntime.clear_desired_overlay_for_consumer(site_state_root, overlay_id)
    }

    fn clear_desired_overlay_for_provider(
        &self,
        site_state_root: &Path,
        overlay_id: &str,
    ) -> miette::Result<()> {
        TestSiteControllerRuntime.clear_desired_overlay_for_provider(site_state_root, overlay_id)
    }
}

fn with_runtime(app: &ControlStateApp, runtime: SharedSiteControllerRuntime) -> ControlStateApp {
    ControlStateApp {
        control_state: app.control_state.clone(),
        client: app.client.clone(),
        state_path: app.state_path.clone(),
        run_root: app.run_root.clone(),
        state_root: app.state_root.clone(),
        mesh_scope: app.mesh_scope.clone(),
        control_state_auth_token: app.control_state_auth_token.clone(),
        controller_plan: app.controller_plan.clone(),
        authority_locks: app.authority_locks.clone(),
        runtime,
    }
}

fn write_file(path: &Path, contents: &str) {
    fs::write(path, contents).expect("test fixture should write");
}

fn file_url(path: &Path) -> String {
    Url::from_file_path(path)
        .expect("test path should convert to file URL")
        .to_string()
}

fn accept_with_deadline(
    listener: &std::net::TcpListener,
    deadline: std::time::Instant,
) -> std::net::TcpStream {
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .expect("accepted manifest stream should be blocking");
                return stream;
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    panic!("timed out waiting for manifest request");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(err) => panic!("accept failed: {err}"),
        }
    }
}

fn read_request_path(stream: &mut std::net::TcpStream) -> String {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("request read timeout should set");

    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = std::io::Read::read(stream, &mut chunk).expect("request should read");
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
    }

    let text = std::str::from_utf8(&buf).expect("request should be valid UTF-8");
    let first_line = text
        .lines()
        .next()
        .expect("request should have a request line");
    let mut parts = first_line.split_whitespace();
    let _method = parts.next().expect("request should have a method");
    parts
        .next()
        .expect("request should have a path")
        .to_string()
}

fn manifest_response(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json5\r\nContent-Length: {}\r\nConnection: \
         close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn spawn_redirecting_runtime_manifest_server(
    leaf_manifest: String,
) -> (String, String, String, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("manifest listener");
    listener
        .set_nonblocking(true)
        .expect("manifest listener should be nonblocking");
    let addr = listener.local_addr().expect("manifest listener address");
    let base = format!("http://{addr}");
    let requested_url = format!("{base}/alias/worker.json5");
    let canonical_root_url = format!("{base}/canonical/worker.json5");
    let canonical_leaf_url = format!("{base}/canonical/leaf.json5");
    let root_manifest = format!(
        r##"
            {{
              manifest_version: "0.3.0",
              components: {{
                leaf: "{canonical_leaf_url}"
              }},
              exports: {{
                leaf: "#leaf.out"
              }}
            }}
        "##
    );
    let server_root_url = canonical_root_url.clone();
    let server = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        for _ in 0..3 {
            let mut stream = accept_with_deadline(&listener, deadline);
            let path = read_request_path(&mut stream);
            let response = match path.as_str() {
                "/alias/worker.json5" => format!(
                    "HTTP/1.1 302 Found\r\nLocation: {server_root_url}\r\nConnection: \
                     close\r\nContent-Length: 0\r\n\r\n"
                ),
                "/canonical/worker.json5" => manifest_response(&root_manifest),
                "/canonical/leaf.json5" => manifest_response(&leaf_manifest),
                _ => "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                    .to_string(),
            };
            std::io::Write::write_all(&mut stream, response.as_bytes())
                .expect("response should write");
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    });
    (
        requested_url,
        canonical_root_url,
        canonical_leaf_url,
        server,
    )
}

async fn compile_control_state_with_placement(
    root_path: &Path,
    placement: Option<&PlacementFile>,
) -> FrameworkControlState {
    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let output = compiler
        .compile(
            ManifestRef::from_url(
                Url::from_file_path(root_path).expect("root path should convert to URL"),
            ),
            CompileOptions::default(),
        )
        .await
        .expect("fixture should compile");
    let compiled = CompiledScenario::from_compile_output(&output)
        .expect("fixture should materialize compiled scenario");
    let run_plan = build_run_plan(&compiled, placement).expect("fixture should produce run plan");
    build_control_state("test-run", &run_plan).expect("fixture should build control state")
}

async fn compile_control_state(root_path: &Path) -> FrameworkControlState {
    compile_control_state_with_placement(root_path, None).await
}

async fn compile_control_state_from_ir_with_run_id(
    scenario_ir: ScenarioIr,
    placement: Option<&PlacementFile>,
    run_id: &str,
) -> FrameworkControlState {
    let compiled = CompiledScenario::from_ir(scenario_ir).expect("fixture should load from ir");
    let run_plan =
        build_run_plan(&compiled, placement).expect("fixture should produce replay run plan");
    build_control_state(run_id, &run_plan).expect("fixture should build replay state")
}

#[derive(Deserialize)]
struct SnapshotPlacementFixture {
    offered_sites: BTreeMap<String, SiteDefinition>,
    defaults: PlacementDefaults,
    #[serde(default)]
    assignments: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dynamic_capabilities: Option<DynamicCapabilitiesSnapshotIr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    framework_children: Option<serde_json::Value>,
}

fn placement_from_snapshot(snapshot: &SnapshotResponse) -> PlacementFile {
    let placement: SnapshotPlacementFixture =
        serde_json::from_value(snapshot.placement.clone()).expect("snapshot placement");
    let dynamic_capabilities = if snapshot.dynamic_capabilities.is_null() {
        placement.dynamic_capabilities
    } else {
        Some(
            serde_json::from_value(snapshot.dynamic_capabilities.clone())
                .expect("snapshot dynamic capabilities"),
        )
    };
    PlacementFile {
        schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
        version: amber_compiler::run_plan::PLACEMENT_VERSION,
        sites: placement.offered_sites,
        defaults: placement.defaults,
        components: placement.assignments,
        dynamic_capabilities,
        framework_children: placement.framework_children,
    }
}

async fn compile_control_state_from_snapshot(snapshot: &SnapshotResponse) -> FrameworkControlState {
    compile_control_state_from_snapshot_with_run_id(snapshot, "test-run").await
}

async fn compile_control_state_from_snapshot_with_run_id(
    snapshot: &SnapshotResponse,
    run_id: &str,
) -> FrameworkControlState {
    let scenario_ir: ScenarioIr =
        serde_json::from_value(snapshot.scenario.clone()).expect("snapshot scenario");
    let placement = placement_from_snapshot(snapshot);
    compile_control_state_from_ir_with_run_id(scenario_ir, Some(&placement), run_id).await
}

fn held_entries_for(
    state: &FrameworkControlState,
    holder_component_id: &str,
) -> Vec<mesh_dynamic_caps::HeldEntrySummary> {
    super::dynamic_caps::live_held_entries(state, holder_component_id)
        .expect("held entries should resolve")
}

fn root_held_id_for(state: &FrameworkControlState, holder_component_id: &str) -> String {
    let held = held_entries_for(state, holder_component_id);
    held.clone()
        .into_iter()
        .find(|entry| entry.entry_kind == HeldEntryKind::RootAuthority)
        .map(|entry| entry.held_id)
        .unwrap_or_else(|| {
            panic!(
                "holder `{holder_component_id}` should have a root authority; held entries: \
                 {held:?}"
            )
        })
}

fn delegated_entry_for(
    state: &FrameworkControlState,
    holder_component_id: &str,
    grant_id: &str,
) -> mesh_dynamic_caps::HeldEntryDetail {
    super::dynamic_caps::held_entry_detail(
        state,
        holder_component_id,
        &super::dynamic_caps::held_id_for_grant(grant_id),
    )
    .expect("delegated held entry should resolve")
}

async fn compile_dynamic_caps_binding_state() -> FrameworkControlState {
    fn path_program() -> amber_scenario::Program {
        serde_json::from_value(serde_json::json!({
            "path": "/usr/bin/env",
            "args": ["python3", "-c", "print('ok')"]
        }))
        .expect("path program should parse")
    }

    fn http_provider_program(port: u16) -> amber_scenario::Program {
        serde_json::from_value(serde_json::json!({
            "path": "/usr/bin/env",
            "args": ["python3", "-c", "print('ok')"],
            "network": {
                "endpoints": [
                    { "name": "http", "port": port, "protocol": "http" }
                ]
            }
        }))
        .expect("provider program should parse")
    }

    fn http_slot() -> SlotDecl {
        serde_json::from_value(serde_json::json!({ "kind": "http" }))
            .expect("slot decl should parse")
    }

    fn http_provide() -> amber_manifest::ProvideDecl {
        serde_json::from_value(serde_json::json!({ "kind": "http", "endpoint": "http" }))
            .expect("provide decl should parse")
    }

    fn component(
        id: usize,
        moniker: &str,
        parent: Option<usize>,
        children: Vec<usize>,
        program: Option<amber_scenario::Program>,
        slots: BTreeMap<String, SlotDecl>,
        provides: BTreeMap<String, amber_manifest::ProvideDecl>,
    ) -> ComponentIr {
        ComponentIr {
            id,
            moniker: moniker.to_string(),
            parent,
            children,
            resolved_url: None,
            digest: amber_manifest::ManifestDigest::new([id as u8; 32]),
            config: None,
            config_schema: None,
            program,
            slots,
            provides,
            exports: BTreeMap::new(),
            resources: BTreeMap::new(),
            child_templates: BTreeMap::new(),
            metadata: None,
        }
    }

    let scenario = ScenarioIr {
        schema: amber_scenario::SCENARIO_IR_SCHEMA.to_string(),
        version: amber_scenario::SCENARIO_IR_VERSION,
        root: 0,
        components: vec![
            component(
                0,
                "/",
                None,
                vec![1, 2, 3, 4, 5, 6],
                None,
                BTreeMap::new(),
                BTreeMap::new(),
            ),
            component(
                1,
                "/provider",
                Some(0),
                Vec::new(),
                Some(http_provider_program(8080)),
                BTreeMap::new(),
                BTreeMap::from([("http".to_string(), http_provide())]),
            ),
            component(
                2,
                "/alice",
                Some(0),
                Vec::new(),
                Some(path_program()),
                BTreeMap::from([("upstream".to_string(), http_slot())]),
                BTreeMap::new(),
            ),
            component(
                3,
                "/bob",
                Some(0),
                Vec::new(),
                Some(path_program()),
                BTreeMap::from([("upstream".to_string(), http_slot())]),
                BTreeMap::new(),
            ),
            component(
                4,
                "/carol",
                Some(0),
                Vec::new(),
                Some(path_program()),
                BTreeMap::new(),
                BTreeMap::new(),
            ),
            component(
                5,
                "/dave",
                Some(0),
                Vec::new(),
                Some(path_program()),
                BTreeMap::new(),
                BTreeMap::new(),
            ),
            component(
                6,
                "/eve",
                Some(0),
                Vec::new(),
                Some(path_program()),
                BTreeMap::new(),
                BTreeMap::new(),
            ),
        ],
        bindings: vec![
            BindingIr {
                name: None,
                from: BindingFromIr::Component {
                    component: 1,
                    provide: "http".to_string(),
                },
                to: amber_scenario::ir::SlotRefIr {
                    component: 2,
                    slot: "upstream".to_string(),
                },
                weak: false,
            },
            BindingIr {
                name: None,
                from: BindingFromIr::Component {
                    component: 1,
                    provide: "http".to_string(),
                },
                to: amber_scenario::ir::SlotRefIr {
                    component: 3,
                    slot: "upstream".to_string(),
                },
                weak: false,
            },
        ],
        exports: Vec::new(),
        manifest_catalog: BTreeMap::new(),
    };
    let placement = PlacementFile {
        schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
        version: amber_compiler::run_plan::PLACEMENT_VERSION,
        sites: BTreeMap::from([(
            "direct_local".to_string(),
            SiteDefinition {
                kind: SiteKind::Direct,
                context: None,
            },
        )]),
        defaults: PlacementDefaults {
            path: Some("direct_local".to_string()),
            ..PlacementDefaults::default()
        },
        components: BTreeMap::from([("/".to_string(), "direct_local".to_string())]),
        dynamic_capabilities: None,
        framework_children: None,
    };
    compile_control_state_from_ir_with_run_id(scenario, Some(&placement), "test-run").await
}

fn test_live_component_runtime(
    moniker: &str,
    peer_id: &str,
    host_mesh_addr: &str,
    inbound: Vec<InboundRoute>,
    outbound: Vec<OutboundRoute>,
) -> LiveComponentRuntimeMetadata {
    LiveComponentRuntimeMetadata {
        moniker: moniker.to_string(),
        host_mesh_addr: host_mesh_addr.to_string(),
        control_endpoint: None,
        mesh_config: MeshConfigPublic {
            identity: MeshIdentityPublic {
                id: peer_id.to_string(),
                public_key: [7; 32],
                mesh_scope: None,
            },
            mesh_listen: "127.0.0.1:0".parse().expect("mesh listen addr"),
            control_listen: None,
            dynamic_caps_listen: None,
            control_allow: None,
            peers: Vec::new(),
            inbound,
            outbound,
            transport: TransportConfig::NoiseIk {},
        },
    }
}

fn test_live_site_router(inbound: Vec<InboundRoute>) -> MeshConfigPublic {
    MeshConfigPublic {
        identity: MeshIdentityPublic {
            id: "/router".to_string(),
            public_key: [11; 32],
            mesh_scope: None,
        },
        mesh_listen: "127.0.0.1:0".parse().expect("mesh listen addr"),
        control_listen: None,
        dynamic_caps_listen: None,
        control_allow: None,
        peers: Vec::new(),
        inbound,
        outbound: Vec::new(),
        transport: TransportConfig::NoiseIk {},
    }
}

#[test]
fn dynamic_capability_origin_self_provide_routes_via_component_mesh() {
    let runtime = test_live_component_runtime(
        "/provider",
        "/provider",
        "127.0.0.1:24001",
        vec![InboundRoute {
            route_id: "provider-route".to_string(),
            capability: "provider.api".to_string(),
            capability_kind: Some("http".to_string()),
            capability_profile: None,
            protocol: MeshProtocol::Http,
            http_plugins: Vec::new(),
            target: InboundTarget::Local { port: 20000 },
            allowed_issuers: Vec::new(),
        }],
        Vec::new(),
    );
    let site_components = BTreeMap::from([(runtime.moniker.clone(), runtime.clone())]);
    let site_router = test_live_site_router(Vec::new());

    let (route, capability, protocol) = dynamic_capability_origin_route_surface(
        &runtime,
        &site_components,
        &site_router,
        SiteKind::Direct,
        "dynamic-origin",
        &RootAuthoritySelectorIr::SelfProvide {
            component_id: "/provider".to_string(),
            provide_name: "provider.api".to_string(),
        },
        vec!["peer-consumer".to_string()],
    )
    .expect("self-provide origin surface should resolve");

    assert_eq!(capability, "provider.api");
    assert_eq!(protocol, MeshProtocol::Http);
    assert_eq!(route.route_id, "dynamic-origin");
    assert_eq!(route.allowed_issuers, vec!["peer-consumer".to_string()]);
    assert_eq!(route.http_plugins, Vec::new());
    assert_eq!(
        route.target,
        InboundTarget::MeshForward {
            peer_addr: "127.0.0.1:24001".to_string(),
            peer_id: "/provider".to_string(),
            route_id: "provider-route".to_string(),
            capability: "provider.api".to_string(),
        }
    );
}

#[test]
fn dynamic_capability_origin_binding_routes_same_site_provider_via_mesh() {
    let holder_runtime = test_live_component_runtime(
        "/consumer",
        "/consumer",
        "127.0.0.1:24002",
        Vec::new(),
        vec![OutboundRoute {
            route_id: "provider-route".to_string(),
            rewrite_route_id: None,
            slot: "provider".to_string(),
            capability_kind: Some("http".to_string()),
            capability_profile: None,
            listen_port: 20000,
            listen_addr: None,
            protocol: MeshProtocol::Http,
            http_plugins: Vec::new(),
            peer_addr: "10.0.2.2:24099".to_string(),
            peer_id: "/provider".to_string(),
            capability: "provider.api".to_string(),
        }],
    );
    let provider_runtime = test_live_component_runtime(
        "/provider",
        "/provider",
        "127.0.0.1:24001",
        Vec::new(),
        Vec::new(),
    );
    let site_components = BTreeMap::from([
        (holder_runtime.moniker.clone(), holder_runtime.clone()),
        (provider_runtime.moniker.clone(), provider_runtime.clone()),
    ]);
    let site_router = test_live_site_router(Vec::new());

    let (route, capability, protocol) = dynamic_capability_origin_route_surface(
        &holder_runtime,
        &site_components,
        &site_router,
        SiteKind::Direct,
        "dynamic-origin",
        &RootAuthoritySelectorIr::Binding {
            consumer_component_id: "components./consumer".to_string(),
            slot_name: "provider".to_string(),
            provider_component_id: "components./provider".to_string(),
            provider_capability_name: "provider.api".to_string(),
        },
        vec!["peer-consumer".to_string()],
    )
    .expect("binding origin surface should resolve");

    assert_eq!(capability, "provider.api");
    assert_eq!(protocol, MeshProtocol::Http);
    assert_eq!(
        route.target,
        InboundTarget::MeshForward {
            peer_addr: "127.0.0.1:24001".to_string(),
            peer_id: "/provider".to_string(),
            route_id: "provider-route".to_string(),
            capability: "provider.api".to_string(),
        }
    );
}

#[test]
fn dynamic_capability_origin_external_slot_routes_via_router_external_target() {
    let runtime = test_live_component_runtime(
        "/consumer",
        "/consumer",
        "127.0.0.1:24002",
        Vec::new(),
        vec![OutboundRoute {
            route_id: "router:external:catalog_api:http".to_string(),
            rewrite_route_id: None,
            slot: "catalog_api".to_string(),
            capability_kind: Some("http".to_string()),
            capability_profile: Some("debug-external".to_string()),
            listen_port: 20000,
            listen_addr: None,
            protocol: MeshProtocol::Http,
            http_plugins: Vec::new(),
            peer_addr: "10.0.2.2:24077".to_string(),
            peer_id: "/router".to_string(),
            capability: "catalog_api".to_string(),
        }],
    );
    let site_components = BTreeMap::from([(runtime.moniker.clone(), runtime.clone())]);
    let site_router = test_live_site_router(vec![InboundRoute {
        route_id: "router:external:catalog_api:http".to_string(),
        capability: "catalog_api".to_string(),
        capability_kind: Some("http".to_string()),
        capability_profile: Some("debug-external".to_string()),
        protocol: MeshProtocol::Http,
        http_plugins: Vec::new(),
        target: InboundTarget::External {
            url_env: "AMBER_EXTERNAL_SLOT_CATALOG_API_URL".to_string(),
            optional: false,
        },
        allowed_issuers: vec!["/consumer".to_string()],
    }]);

    let (route, capability, protocol) = dynamic_capability_origin_route_surface(
        &runtime,
        &site_components,
        &site_router,
        SiteKind::Direct,
        "dynamic-origin",
        &RootAuthoritySelectorIr::ExternalSlotBinding {
            consumer_component_id: "components./consumer".to_string(),
            slot_name: "catalog_api".to_string(),
            external_slot_component_id: "components./".to_string(),
            external_slot_name: "catalog_api".to_string(),
        },
        vec!["peer-consumer".to_string()],
    )
    .expect("external slot origin surface should resolve");

    assert_eq!(capability, "catalog_api");
    assert_eq!(protocol, MeshProtocol::Http);
    assert_eq!(route.route_id, "router:external:catalog_api:http");
    assert_eq!(route.allowed_issuers, vec!["peer-consumer".to_string()]);
    assert_eq!(
        route.target,
        InboundTarget::External {
            url_env: "AMBER_EXTERNAL_SLOT_CATALOG_API_URL".to_string(),
            optional: false,
        }
    );
}

#[test]
fn dynamic_capability_origin_binding_rewrites_linux_slirp_peer_addr_for_host_router() {
    let runtime = test_live_component_runtime(
        "/consumer",
        "/consumer",
        "127.0.0.1:24002",
        Vec::new(),
        vec![OutboundRoute {
            route_id: "remote-route".to_string(),
            rewrite_route_id: None,
            slot: "provider".to_string(),
            capability_kind: Some("http".to_string()),
            capability_profile: None,
            listen_port: 20000,
            listen_addr: None,
            protocol: MeshProtocol::Http,
            http_plugins: Vec::new(),
            peer_addr: "10.0.2.2:24077".to_string(),
            peer_id: "/remote".to_string(),
            capability: "provider.api".to_string(),
        }],
    );
    let site_components = BTreeMap::from([(runtime.moniker.clone(), runtime.clone())]);
    let site_router = test_live_site_router(Vec::new());

    let (route, _, _) = dynamic_capability_origin_route_surface(
        &runtime,
        &site_components,
        &site_router,
        SiteKind::Direct,
        "dynamic-origin",
        &RootAuthoritySelectorIr::Binding {
            consumer_component_id: "components./consumer".to_string(),
            slot_name: "provider".to_string(),
            provider_component_id: "components./remote".to_string(),
            provider_capability_name: "provider.api".to_string(),
        },
        vec!["peer-consumer".to_string()],
    )
    .expect("binding origin surface should resolve");

    let InboundTarget::MeshForward { peer_addr, .. } = route.target else {
        panic!("dynamic origin route should forward through mesh");
    };
    #[cfg(target_os = "linux")]
    assert_eq!(peer_addr, "127.0.0.1:24077");
    #[cfg(not(target_os = "linux"))]
    assert_eq!(peer_addr, "10.0.2.2:24077");
}

#[test]
fn dynamic_capability_origin_target_mesh_peer_uses_self_identity_for_self_provide() {
    let runtime = test_live_component_runtime(
        "/provider",
        "/provider",
        "127.0.0.1:24001",
        vec![InboundRoute {
            route_id: "provider-route".to_string(),
            capability: "provider.api".to_string(),
            capability_kind: Some("http".to_string()),
            capability_profile: None,
            protocol: MeshProtocol::Http,
            http_plugins: Vec::new(),
            target: InboundTarget::Local { port: 20000 },
            allowed_issuers: Vec::new(),
        }],
        Vec::new(),
    );
    let site_components = BTreeMap::from([(runtime.moniker.clone(), runtime.clone())]);
    let site_router = test_live_site_router(Vec::new());
    let (route, _, _) = dynamic_capability_origin_route_surface(
        &runtime,
        &site_components,
        &site_router,
        SiteKind::Direct,
        "dynamic-origin",
        &RootAuthoritySelectorIr::SelfProvide {
            component_id: "/provider".to_string(),
            provide_name: "provider.api".to_string(),
        },
        vec!["peer-consumer".to_string()],
    )
    .expect("self-provide origin surface should resolve");

    let peer = dynamic_capability_origin_target_mesh_peer(&runtime, &site_components, &route)
        .expect("self-provide target peer should resolve")
        .expect("mesh-forward targets should expose a peer");

    assert_eq!(peer.id, "/provider");
    assert_eq!(peer.public_key, [7; 32]);
}

#[test]
fn dynamic_capability_origin_target_mesh_peer_uses_runtime_peer_catalog_for_binding() {
    let provider_identity = MeshIdentityPublic {
        id: "/provider".to_string(),
        public_key: [9; 32],
        mesh_scope: None,
    };
    let runtime = LiveComponentRuntimeMetadata {
        moniker: "/consumer".to_string(),
        host_mesh_addr: "127.0.0.1:24002".to_string(),
        control_endpoint: None,
        mesh_config: MeshConfigPublic {
            identity: MeshIdentityPublic {
                id: "/consumer".to_string(),
                public_key: [7; 32],
                mesh_scope: None,
            },
            mesh_listen: "127.0.0.1:0".parse().expect("mesh listen addr"),
            control_listen: None,
            dynamic_caps_listen: None,
            control_allow: None,
            peers: vec![MeshPeer {
                id: provider_identity.id.clone(),
                public_key: provider_identity.public_key,
            }],
            inbound: Vec::new(),
            outbound: vec![OutboundRoute {
                route_id: "provider-route".to_string(),
                rewrite_route_id: None,
                slot: "provider".to_string(),
                capability_kind: Some("http".to_string()),
                capability_profile: None,
                listen_port: 20000,
                listen_addr: None,
                protocol: MeshProtocol::Http,
                http_plugins: Vec::new(),
                peer_addr: "10.0.2.2:24099".to_string(),
                peer_id: "/provider".to_string(),
                capability: "provider.api".to_string(),
            }],
            transport: TransportConfig::NoiseIk {},
        },
    };
    let site_components = BTreeMap::from([(runtime.moniker.clone(), runtime.clone())]);
    let site_router = test_live_site_router(Vec::new());
    let (route, _, _) = dynamic_capability_origin_route_surface(
        &runtime,
        &site_components,
        &site_router,
        SiteKind::Direct,
        "dynamic-origin",
        &RootAuthoritySelectorIr::Binding {
            consumer_component_id: "components./consumer".to_string(),
            slot_name: "provider".to_string(),
            provider_component_id: "components./provider".to_string(),
            provider_capability_name: "provider.api".to_string(),
        },
        vec!["peer-consumer".to_string()],
    )
    .expect("binding origin surface should resolve");

    let peer = dynamic_capability_origin_target_mesh_peer(&runtime, &site_components, &route)
        .expect("binding target peer should resolve")
        .expect("mesh-forward targets should expose a peer");

    assert_eq!(peer.id, provider_identity.id);
    assert_eq!(peer.public_key, provider_identity.public_key);
}

async fn compile_dynamic_caps_external_root_state() -> FrameworkControlState {
    let program: amber_scenario::Program = serde_json::from_value(serde_json::json!({
        "path": "/usr/bin/env",
        "args": ["python3", "-c", "print('ok')"]
    }))
    .expect("path program should parse");
    let http_slot: SlotDecl = serde_json::from_value(serde_json::json!({ "kind": "http" }))
        .expect("slot decl should parse");
    let scenario = ScenarioIr {
        schema: amber_scenario::SCENARIO_IR_SCHEMA.to_string(),
        version: amber_scenario::SCENARIO_IR_VERSION,
        root: 0,
        components: vec![
            ComponentIr {
                id: 0,
                moniker: "/".to_string(),
                parent: None,
                children: vec![1, 2],
                resolved_url: None,
                digest: amber_manifest::ManifestDigest::new([0; 32]),
                config: None,
                config_schema: None,
                program: None,
                slots: BTreeMap::from([("catalog_api".to_string(), http_slot.clone())]),
                provides: BTreeMap::new(),
                exports: BTreeMap::new(),
                resources: BTreeMap::new(),
                child_templates: BTreeMap::new(),
                metadata: None,
            },
            ComponentIr {
                id: 1,
                moniker: "/alice".to_string(),
                parent: Some(0),
                children: Vec::new(),
                resolved_url: None,
                digest: amber_manifest::ManifestDigest::new([1; 32]),
                config: None,
                config_schema: None,
                program: Some(program.clone()),
                slots: BTreeMap::from([("catalog_api".to_string(), http_slot)]),
                provides: BTreeMap::new(),
                exports: BTreeMap::new(),
                resources: BTreeMap::new(),
                child_templates: BTreeMap::new(),
                metadata: None,
            },
            ComponentIr {
                id: 2,
                moniker: "/bob".to_string(),
                parent: Some(0),
                children: Vec::new(),
                resolved_url: None,
                digest: amber_manifest::ManifestDigest::new([2; 32]),
                config: None,
                config_schema: None,
                program: Some(program),
                slots: BTreeMap::new(),
                provides: BTreeMap::new(),
                exports: BTreeMap::new(),
                resources: BTreeMap::new(),
                child_templates: BTreeMap::new(),
                metadata: None,
            },
        ],
        bindings: vec![BindingIr {
            name: None,
            from: BindingFromIr::External {
                slot: amber_scenario::ir::SlotRefIr {
                    component: 0,
                    slot: "catalog_api".to_string(),
                },
            },
            to: amber_scenario::ir::SlotRefIr {
                component: 1,
                slot: "catalog_api".to_string(),
            },
            weak: true,
        }],
        exports: Vec::new(),
        manifest_catalog: BTreeMap::new(),
    };
    let placement = PlacementFile {
        schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
        version: amber_compiler::run_plan::PLACEMENT_VERSION,
        sites: BTreeMap::from([(
            "direct_local".to_string(),
            SiteDefinition {
                kind: SiteKind::Direct,
                context: None,
            },
        )]),
        defaults: PlacementDefaults {
            path: Some("direct_local".to_string()),
            ..PlacementDefaults::default()
        },
        components: BTreeMap::new(),
        dynamic_capabilities: None,
        framework_children: None,
    };
    compile_control_state_from_ir_with_run_id(scenario, Some(&placement), "test-run").await
}

#[tokio::test]
async fn same_site_dynamic_child_output_bindings_reuse_provider_component_routes() {
    let dir = TempDir::new().expect("temp dir");
    let required_path = dir.path().join("required.json5");
    let consumer_path = dir.path().join("consumer.json5");
    let root_path = dir.path().join("root.json5");
    write_file(
        &required_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: {
                image: "python:3.13-alpine",
                entrypoint: ["python3", "-c", "print('required')"],
                network: {
                  endpoints: [{ name: "http", port: 8080, protocol: "http" }]
                }
              },
              provides: {
                http: { kind: "http", endpoint: "http" }
              },
              exports: {
                http: "http"
              }
            }
            "#,
    );
    write_file(
        &consumer_path,
        r#"
            {
              manifest_version: "0.3.0",
              slots: {
                required_api: { kind: "http" }
              },
              program: {
                image: "python:3.13-alpine",
                entrypoint: ["python3", "-c", "print('consumer')"],
                network: {
                  endpoints: [{ name: "http", port: 8081, protocol: "http" }]
                }
              },
              provides: {
                http: { kind: "http", endpoint: "http" }
              },
              exports: {
                http: "http"
              }
            }
            "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  program: {{
                    image: "python:3.13-alpine",
                    entrypoint: ["python3", "-c", "print('root')"]
                  }},
                  child_templates: {{
                    required: {{
                      manifest: "{required}"
                    }},
                    consumer: {{
                      manifest: "{consumer}"
                    }}
                  }}
                }}
                "##,
            required = file_url(&required_path),
            consumer = file_url(&consumer_path),
        ),
    );
    let placement = PlacementFile {
        schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
        version: amber_compiler::run_plan::PLACEMENT_VERSION,
        sites: BTreeMap::from([(
            "compose_local".to_string(),
            SiteDefinition {
                kind: SiteKind::Compose,
                context: None,
            },
        )]),
        defaults: PlacementDefaults {
            image: Some("compose_local".to_string()),
            ..PlacementDefaults::default()
        },
        components: BTreeMap::new(),
        dynamic_capabilities: None,
        framework_children: None,
    };
    let state = compile_control_state_with_placement(&root_path, Some(&placement)).await;
    let state_path = dir.path().join("control-state.json");
    write_control_state(&state_path, &state).expect("state should write");
    let root_authority = state.base_scenario.root;
    let app = test_control_state_app(&dir, state, state_path);

    execute_create_child(
        &app,
        root_authority,
        CreateChildRequest {
            template: "required".to_string(),
            name: "required".to_string(),
            manifest: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        },
    )
    .await
    .expect("required child should create");
    execute_create_child(
        &app,
        root_authority,
        CreateChildRequest {
            template: "consumer".to_string(),
            name: "consumer".to_string(),
            manifest: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::from([(
                "required_api".to_string(),
                BindingInput {
                    selector: Some("children.required.exports.http".to_string()),
                    handle: None,
                },
            )]),
        },
    )
    .await
    .expect("consumer child should create");

    let state = app.control_state.lock().await.clone();
    let consumer = state
        .live_children
        .iter()
        .find(|child| child.name == "consumer")
        .expect("consumer child should be recorded");
    let site_id = child_runtime_site_id(consumer).expect("consumer site id");
    let runtime_spec =
        build_local_child_runtime_spec(&state, consumer, &site_id).expect("runtime spec");
    assert_eq!(runtime_spec.direct_inputs.len(), 1);
    assert!(runtime_spec.routed_inputs.is_empty());
    assert_eq!(runtime_spec.direct_inputs[0].component, "/consumer");
    assert_eq!(runtime_spec.direct_inputs[0].slot, "required_api");
    assert_eq!(
        runtime_spec.direct_inputs[0].provider_component,
        "/required"
    );
    assert_eq!(runtime_spec.direct_inputs[0].protocol, "http");
    assert_eq!(runtime_spec.direct_inputs[0].capability_kind, "http");
    assert_eq!(
        runtime_spec.direct_inputs[0].target,
        DynamicInputRouteTarget::ComponentProvide {
            provide: "http".to_string()
        },
        "same-site child exports should reuse the provider component route without routing \
         through the site router",
    );
}

#[tokio::test]
async fn same_site_static_child_export_bindings_reuse_provider_component_routes() {
    let dir = TempDir::new().expect("temp dir");
    let provider_path = dir.path().join("provider.json5");
    let consumer_path = dir.path().join("consumer.json5");
    let root_path = dir.path().join("root.json5");
    write_file(
        &provider_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: {
                image: "python:3.13-alpine",
                entrypoint: ["python3", "-c", "print('provider')"],
                network: {
                  endpoints: [{ name: "http", port: 8080, protocol: "http" }]
                }
              },
              provides: {
                http: { kind: "http", endpoint: "http" }
              },
              exports: {
                http: "http"
              }
            }
            "#,
    );
    write_file(
        &consumer_path,
        r#"
            {
              manifest_version: "0.3.0",
              slots: {
                upstream: { kind: "http" }
              },
              program: {
                image: "python:3.13-alpine",
                entrypoint: ["python3", "-c", "print('consumer')"],
                network: {
                  endpoints: [{ name: "http", port: 8081, protocol: "http" }]
                }
              },
              provides: {
                http: { kind: "http", endpoint: "http" }
              },
              exports: {
                http: "http"
              }
            }
            "#,
    );
    write_json(
        &root_path,
        &json!({
            "manifest_version": "0.3.0",
            "slots": {
                "realm": { "kind": "component", "optional": true }
            },
            "components": {
                "provider": file_url(&provider_path)
            },
            "child_templates": {
                "consumer": {
                    "manifest": file_url(&consumer_path)
                }
            },
            "exports": {
                "provider_http": "#provider.http"
            }
        }),
    )
    .expect("root manifest should write");
    let placement = PlacementFile {
        schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
        version: amber_compiler::run_plan::PLACEMENT_VERSION,
        sites: BTreeMap::from([(
            "compose_local".to_string(),
            SiteDefinition {
                kind: SiteKind::Compose,
                context: None,
            },
        )]),
        defaults: PlacementDefaults {
            image: Some("compose_local".to_string()),
            ..PlacementDefaults::default()
        },
        components: BTreeMap::new(),
        dynamic_capabilities: None,
        framework_children: None,
    };
    let state = compile_control_state_with_placement(&root_path, Some(&placement)).await;
    let state_path = dir.path().join("control-state.json");
    write_control_state(&state_path, &state).expect("state should write");
    let root_authority = state.base_scenario.root;
    let app = test_control_state_app(&dir, state, state_path);

    execute_create_child(
        &app,
        root_authority,
        CreateChildRequest {
            template: "consumer".to_string(),
            name: "consumer".to_string(),
            manifest: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::from([(
                "upstream".to_string(),
                BindingInput {
                    selector: Some("children.provider.exports.http".to_string()),
                    handle: None,
                },
            )]),
        },
    )
    .await
    .expect("consumer child should create");

    let state = app.control_state.lock().await.clone();
    let consumer = state
        .live_children
        .iter()
        .find(|child| child.name == "consumer")
        .expect("consumer child should be recorded");
    let site_id = child_runtime_site_id(consumer).expect("consumer site id");
    let runtime_spec =
        build_local_child_runtime_spec(&state, consumer, &site_id).expect("runtime spec");
    assert_eq!(runtime_spec.direct_inputs.len(), 1);
    assert!(runtime_spec.routed_inputs.is_empty());
    assert_eq!(runtime_spec.direct_inputs[0].component, "/consumer");
    assert_eq!(runtime_spec.direct_inputs[0].slot, "upstream");
    assert_eq!(
        runtime_spec.direct_inputs[0].provider_component,
        "/provider"
    );
    assert_eq!(runtime_spec.direct_inputs[0].protocol, "http");
    assert_eq!(runtime_spec.direct_inputs[0].capability_kind, "http");
    assert_eq!(
        runtime_spec.direct_inputs[0].target,
        DynamicInputRouteTarget::ComponentProvide {
            provide: "http".to_string()
        },
        "same-site static child exports should reuse the provider component route without routing \
         through the site router",
    );
}

#[test]
fn controller_authority_url_normalizes_unspecified_bind_addresses() {
    assert_eq!(
        authority_url_for_listen_addr(SocketAddr::from(([127, 0, 0, 1], 41000))),
        "http://127.0.0.1:41000"
    );
    assert_eq!(
        authority_url_for_listen_addr(SocketAddr::from(([0, 0, 0, 0], 42000))),
        "http://127.0.0.1:42000"
    );
}

#[tokio::test]
async fn dynamic_grant_routes_to_holder_site_not_offered_site_order() {
    let mut state = compile_dynamic_caps_binding_state().await;
    state.placement.offered_sites.insert(
        "compose_local".to_string(),
        SiteDefinition {
            kind: SiteKind::Compose,
            context: None,
        },
    );
    let share = super::dynamic_caps::share_dynamic_capability(
        &mut state,
        "components./provider",
        &super::dynamic_caps::source_key_from_control_request(
            &dynamic_caps::DynamicCapabilityControlSourceRequest::RootAuthority {
                root_authority_selector: RootAuthoritySelectorIr::SelfProvide {
                    component_id: "components./provider".to_string(),
                    provide_name: "http".to_string(),
                },
            },
        ),
        "components./alice",
        None,
        &json!({}),
    )
    .expect("share should succeed");
    let grant_id = match share {
        super::dynamic_caps::DynamicCapabilityShareOutcome::Created { grant_id, .. }
        | super::dynamic_caps::DynamicCapabilityShareOutcome::Deduplicated { grant_id, .. } => {
            grant_id
        }
        super::dynamic_caps::DynamicCapabilityShareOutcome::Noop { reason } => {
            panic!("share should not noop: {reason}");
        }
    };
    assert_eq!(
        site_id_for_dynamic_grant(&state, &grant_id).expect("grant site should resolve"),
        "direct_local",
    );
}

#[tokio::test]
async fn dynamic_caps_cross_site_share_syncs_holder_authority_through_site_router() {
    let dir = TempDir::new().expect("temp dir");
    let base = compile_dynamic_caps_binding_state().await;
    let placement = PlacementFile {
        schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
        version: amber_compiler::run_plan::PLACEMENT_VERSION,
        sites: BTreeMap::from([
            (
                "direct_a".to_string(),
                SiteDefinition {
                    kind: SiteKind::Direct,
                    context: None,
                },
            ),
            (
                "direct_b".to_string(),
                SiteDefinition {
                    kind: SiteKind::Direct,
                    context: None,
                },
            ),
        ]),
        defaults: PlacementDefaults {
            path: Some("direct_a".to_string()),
            ..PlacementDefaults::default()
        },
        components: BTreeMap::from([
            ("/provider".to_string(), "direct_a".to_string()),
            ("/alice".to_string(), "direct_a".to_string()),
            ("/bob".to_string(), "direct_b".to_string()),
        ]),
        dynamic_capabilities: None,
        framework_children: None,
    };
    let mut authority_state = compile_control_state_from_ir_with_run_id(
        base.base_scenario.clone(),
        Some(&placement),
        "test-run",
    )
    .await;
    localize_framework_control_state(&mut authority_state, "direct_a")
        .expect("authority site state should localize");
    let alice_root = super::dynamic_caps::source_key_from_held_id(
        &authority_state,
        "components./alice",
        &root_held_id_for(&authority_state, "components./alice"),
    )
    .expect("alice root source should resolve");
    let dynamic_caps::DynamicCapabilitySourceKey::RootAuthority(root_authority_selector) =
        alice_root
    else {
        panic!("alice root held id should resolve to a root authority selector");
    };
    let state_path = dir.path().join("control-state.json");
    write_control_state(&state_path, &authority_state).expect("authority state should write");

    let sync_requests = Arc::new(std::sync::Mutex::new(Vec::<
        dynamic_caps::ControlDynamicGrantAuthoritySyncRequest,
    >::new()));
    let router = Router::new().route(
        "/v1/controller/dynamic-caps/grant-authorities/sync",
        axum::routing::post({
            let sync_requests = sync_requests.clone();
            move |headers: HeaderMap,
                  Json(request): Json<dynamic_caps::ControlDynamicGrantAuthoritySyncRequest>| {
                let sync_requests = sync_requests.clone();
                async move {
                    assert_eq!(
                        headers
                            .get(super::site_controller::CONTROLLER_LOCAL_ONLY_HEADER)
                            .and_then(|value| value.to_str().ok()),
                        Some("1"),
                        "cross-site share sync should stay local on the destination controller",
                    );
                    sync_requests
                        .lock()
                        .expect("sync request log poisoned")
                        .push(request.clone());
                    Json(dynamic_caps::ControlDynamicGrantAuthoritySyncResponse {
                        synced: request.authority_sites.len(),
                    })
                }
            }
        }),
    );
    let (holder_base_url, _holder_handle) = spawn_test_router(router).await;

    let mut app = test_control_state_app(&dir, authority_state, state_path);
    let controller_plan = Arc::make_mut(&mut app.controller_plan);
    controller_plan.site_id = "direct_a".to_string();
    controller_plan.router_identity_id = "/site/direct_a/router".to_string();
    controller_plan.peer_site_router_urls =
        BTreeMap::from([("direct_b".to_string(), holder_base_url)]);
    let controller_app = SiteControllerApp {
        control: app,
        router_auth_token: Arc::<str>::from("test-router-auth"),
        ready: ready_site_controller_flag(),
    };

    let response = super::site_controller::execute_site_controller_dynamic_caps_mutate(
        &controller_app,
        super::control_state_api::DynamicCapsMutateRequest::Share(
            dynamic_caps::ControlDynamicShareRequest {
                caller_component_id: "components./alice".to_string(),
                source: dynamic_caps::DynamicCapabilityControlSourceRequest::RootAuthority {
                    root_authority_selector,
                },
                recipient_component_id: "components./bob".to_string(),
                idempotency_key: None,
                options: json!({}),
            },
        ),
        false,
    )
    .await
    .expect("authority site should create the share and sync it through the holder router");

    let super::control_state_api::DynamicCapsMutateResponse::Share(response) = response else {
        panic!("share should return a share response");
    };
    let grant_id = response
        .grant_id
        .clone()
        .expect("cross-site share should create a concrete grant id");
    assert_eq!(response.outcome, "created");

    let sync_requests = sync_requests.lock().expect("sync request log poisoned");
    assert_eq!(sync_requests.len(), 1, "expected exactly one holder sync");
    assert_eq!(
        sync_requests[0].authority_sites,
        BTreeMap::from([(grant_id, "direct_a".to_string())]),
        "the holder site should learn that direct_a remains authoritative for the shared grant",
    );
}

async fn compile_empty_control_state() -> (TempDir, FrameworkControlState, PathBuf) {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    write_file(
        &root_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: { path: "/bin/echo", args: ["root"] },
            }
            "#,
    );
    let placement = PlacementFile {
        schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
        version: amber_compiler::run_plan::PLACEMENT_VERSION,
        sites: BTreeMap::from([(
            "direct_local".to_string(),
            SiteDefinition {
                kind: SiteKind::Direct,
                context: None,
            },
        )]),
        defaults: PlacementDefaults {
            path: Some("direct_local".to_string()),
            ..PlacementDefaults::default()
        },
        components: BTreeMap::new(),
        dynamic_capabilities: None,
        framework_children: None,
    };
    let state = compile_control_state_with_placement(&root_path, Some(&placement)).await;
    let state_path = dir.path().join("control-state.json");
    write_control_state(&state_path, &state).expect("state should write");
    (dir, state, state_path)
}

async fn compile_exact_template_control_state() -> (TempDir, FrameworkControlState, PathBuf) {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");
    write_file(
        &child_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["child"],
                network: { endpoints: [{ name: "out", port: 8080, protocol: "http" }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
    );
    write_file(
        &root_path,
        &format!(
            r#"
                {{
                  manifest_version: "0.3.0",
                  program: {{ path: "/bin/echo", args: ["root"] }},
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{ manifest: "{child}" }}
                  }},
                }}
                "#,
            child = file_url(&child_path),
        ),
    );
    let placement = PlacementFile {
        schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
        version: amber_compiler::run_plan::PLACEMENT_VERSION,
        sites: BTreeMap::from([(
            "direct_local".to_string(),
            SiteDefinition {
                kind: SiteKind::Direct,
                context: None,
            },
        )]),
        defaults: PlacementDefaults {
            path: Some("direct_local".to_string()),
            ..PlacementDefaults::default()
        },
        components: BTreeMap::from([("/".to_string(), "direct_local".to_string())]),
        dynamic_capabilities: None,
        framework_children: None,
    };
    let state = compile_control_state_with_placement(&root_path, Some(&placement)).await;
    let state_path = dir.path().join("control-state.json");
    write_control_state(&state_path, &state).expect("state should write");
    (dir, state, state_path)
}

async fn compile_framework_binding_control_state() -> (
    TempDir,
    FrameworkControlState,
    PathBuf,
    CapabilityInstanceRecord,
) {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let admin_path = dir.path().join("admin.json5");
    let worker_path = dir.path().join("worker.json5");
    write_file(
        &admin_path,
        r#"
            {
              manifest_version: "0.3.0",
              slots: {
                ctl: { kind: "component" }
              },
              program: { path: "/bin/echo", args: ["admin", "${slots.ctl.url}"] }
            }
            "#,
    );
    write_file(
        &worker_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/usr/bin/env",
                args: ["python3", "-m", "http.server", "8080"],
                network: { endpoints: [{ name: "out", port: 8080, protocol: "http" }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  components: {{
                    admin: "{admin}"
                  }},
                  child_templates: {{
                    worker: {{ manifest: "{worker}" }}
                  }},
                  bindings: [
                    {{ to: "#admin.ctl", from: "framework.component" }}
                  ],
                }}
                "##,
            admin = file_url(&admin_path),
            worker = file_url(&worker_path),
        ),
    );

    let placement = PlacementFile {
        schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
        version: amber_compiler::run_plan::PLACEMENT_VERSION,
        sites: BTreeMap::from([(
            "direct_local".to_string(),
            SiteDefinition {
                kind: SiteKind::Direct,
                context: None,
            },
        )]),
        defaults: PlacementDefaults {
            path: Some("direct_local".to_string()),
            ..PlacementDefaults::default()
        },
        components: BTreeMap::from([("/".to_string(), "direct_local".to_string())]),
        dynamic_capabilities: None,
        framework_children: None,
    };
    let state = compile_control_state_with_placement(&root_path, Some(&placement)).await;
    let state_path = dir.path().join("control-state.json");
    write_control_state(&state_path, &state).expect("state should write");
    let record = state
        .capability_instances
        .values()
        .find(|record| record.recipient_component_moniker == "/admin")
        .cloned()
        .expect("admin should receive a framework capability instance");
    (dir, state, state_path, record)
}

fn empty_live_child(
    authority_realm_id: usize,
    name: &str,
    child_id: u64,
    state: ChildState,
) -> LiveChildRecord {
    let child_moniker = format!("/{name}");
    LiveChildRecord {
        child_id,
        authority_realm_id,
        name: name.to_string(),
        state,
        template_name: Some("worker".to_string()),
        selected_manifest_catalog_key: None,
        fragment: Some(LiveScenarioFragment {
            root_component_id: child_id as usize + 10_000,
            components: vec![ComponentIr {
                id: child_id as usize + 10_000,
                moniker: child_moniker.clone(),
                parent: Some(authority_realm_id),
                children: Vec::new(),
                resolved_url: Some(format!("file:///tmp/{name}.json5")),
                digest: amber_manifest::ManifestDigest::new([0; 32]),
                config: None,
                config_schema: None,
                program: None,
                slots: BTreeMap::new(),
                provides: BTreeMap::new(),
                exports: BTreeMap::new(),
                resources: BTreeMap::new(),
                child_templates: BTreeMap::new(),
                metadata: None,
            }],
            bindings: Vec::new(),
        }),
        input_bindings: Vec::new(),
        assignments: BTreeMap::from([(child_moniker, "direct_local".to_string())]),
        overlay_ids: Vec::new(),
        overlays: Vec::new(),
        outputs: BTreeMap::new(),
    }
}

fn pending_create(tx_id: u64, child: LiveChildRecord) -> PendingCreateRecord {
    PendingCreateRecord { tx_id, child }
}

fn pending_destroy(tx_id: u64, child: LiveChildRecord) -> PendingDestroyRecord {
    PendingDestroyRecord { tx_id, child }
}

fn test_router_control_addr() -> String {
    static ROUTER_CONTROL_ADDR: OnceLock<String> = OnceLock::new();
    ROUTER_CONTROL_ADDR
        .get_or_init(|| {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
                .expect("mock router control listener should bind");
            let addr = listener
                .local_addr()
                .expect("mock router control listener addr");
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else {
                        continue;
                    };
                    stream
                        .set_read_timeout(Some(StdDuration::from_millis(100)))
                        .expect("mock router control read timeout should set");
                    let mut request = Vec::new();
                    let mut buf = [0u8; 4096];
                    loop {
                        match stream.read(&mut buf) {
                            Ok(0) => break,
                            Ok(read) => request.extend_from_slice(&buf[..read]),
                            Err(err)
                                if matches!(
                                    err.kind(),
                                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                                ) =>
                            {
                                break;
                            }
                            Err(_) => break,
                        }
                    }
                    let request = String::from_utf8_lossy(&request);
                    let response = if request.starts_with("GET /identity ") {
                        let body = serde_json::to_string(&json!({
                            "id": "/site/test/router",
                            "public_key": vec![9u8; 32],
                            "mesh_scope": "test-mesh",
                        }))
                        .expect("mock router identity should serialize");
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \
                             {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                    } else {
                        "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_string()
                    };
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                }
            });
            addr.to_string()
        })
        .clone()
}

fn test_control_state_app(
    dir: &TempDir,
    state: FrameworkControlState,
    state_path: PathBuf,
) -> ControlStateApp {
    let run_root = dir.path().join("run");
    let state_root = dir.path().join("state");
    fs::create_dir_all(&run_root).expect("run root should exist");
    fs::create_dir_all(&state_root).expect("state root should exist");
    let offered_sites = if state.placement.offered_sites.is_empty() {
        BTreeMap::from([(
            "direct_local".to_string(),
            SiteDefinition {
                kind: SiteKind::Direct,
                context: None,
            },
        )])
    } else {
        state.placement.offered_sites.clone()
    };
    let router_control = test_router_control_addr();
    let router_public_key_b64 = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let site_id = offered_sites
        .keys()
        .next()
        .cloned()
        .expect("offered sites should contain at least one site");
    for (site_id, site_definition) in &offered_sites {
        let site_state_root = state_root.join(site_id);
        let artifact_dir = dir.path().join("artifact").join(site_id);
        let storage_root = dir.path().join("storage").join(site_id);
        let runtime_root = dir.path().join("runtime").join(site_id);
        fs::create_dir_all(&site_state_root).expect("site state root should exist");
        fs::create_dir_all(&artifact_dir).expect("artifact dir should exist");
        fs::create_dir_all(&storage_root).expect("storage root should exist");
        fs::create_dir_all(&runtime_root).expect("runtime root should exist");
        write_json(
            &site_state_root.join("manager-state.json"),
            &json!({
                "status": "running",
                "kind": site_definition.kind,
                "artifact_dir": artifact_dir.display().to_string(),
                "supervisor_pid": 1u32,
                "router_control": router_control.clone(),
                "router_mesh_addr": "127.0.0.1:24000",
                "router_identity_id": format!("/site/{site_id}/router"),
                "router_public_key_b64": router_public_key_b64.clone(),
                "site_controller_url": "http://127.0.0.1:0",
            }),
        )
        .expect("site manager state should write");
    }
    let site_state_root = state_root.join(&site_id);
    let artifact_dir = dir.path().join("artifact").join(&site_id);
    let storage_root = dir.path().join("storage").join(&site_id);
    let runtime_root = dir.path().join("runtime").join(&site_id);
    ControlStateApp {
        control_state: Arc::new(Mutex::new(state)),
        client: ReqwestClient::new(),
        state_path: state_path.clone(),
        run_root: run_root.clone(),
        state_root: state_root.clone(),
        mesh_scope: Arc::<str>::from("test-mesh"),
        control_state_auth_token: Arc::<str>::from("test-control-state-auth"),
        controller_plan: Arc::new(SiteControllerPlan {
            schema: "amber.framework_component.site_controller_plan".to_string(),
            version: 1,
            run_id: "test-run".to_string(),
            mesh_scope: "test-mesh".to_string(),
            site_id: site_id.clone(),
            kind: SiteKind::Direct,
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            authority_url: "http://127.0.0.1:0".to_string(),
            router_identity_id: format!("/site/{site_id}/router"),
            peer_site_router_urls: BTreeMap::new(),
            peer_router_identities: BTreeMap::new(),
            peer_router_mesh_addrs: BTreeMap::new(),
            local_router_control: None,
            published_router_mesh_addr: Some("127.0.0.1:24000".to_string()),
            state_path: state_path.display().to_string(),
            run_root: run_root.display().to_string(),
            state_root: state_root.display().to_string(),
            site_state_root: site_state_root.display().to_string(),
            artifact_dir: artifact_dir.display().to_string(),
            auth_token: "test-control-state-auth".to_string(),
            dynamic_caps_token_verify_key_b64: String::new(),
            storage_root: Some(storage_root.display().to_string()),
            runtime_root: Some(runtime_root.display().to_string()),
            router_mesh_port: Some(24000),
            compose_project: None,
            kubernetes_namespace: None,
            context: None,
            observability_endpoint: None,
            launch_env: BTreeMap::new(),
        }),
        authority_locks: Arc::new(Mutex::new(BTreeMap::new())),
        runtime: test_runtime(),
    }
}

fn sse_json_rpc_message(body: &str) -> Value {
    let normalized = body.replace("\r\n", "\n");
    let payload = normalized
        .split("\n\n")
        .filter_map(|event| {
            let data = event
                .lines()
                .filter_map(|line| line.strip_prefix("data:"))
                .map(str::trim_start)
                .collect::<Vec<_>>()
                .join("\n");
            (!data.is_empty()).then_some(data)
        })
        .last()
        .unwrap_or_else(|| panic!("SSE response did not contain JSON-RPC data: {body}"));
    serde_json::from_str(&payload)
        .unwrap_or_else(|err| panic!("parse JSON-RPC payload from SSE: {err}; {payload}"))
}

async fn spawn_test_router(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test listener");
    spawn_test_router_on(listener, router)
}

fn spawn_test_router_on(
    listener: tokio::net::TcpListener,
    router: Router,
) -> (String, tokio::task::JoinHandle<()>) {
    let addr = listener.local_addr().expect("test listener addr");
    let handle = tokio::spawn(async move {
        axum::serve(listener, router.into_make_service())
            .await
            .expect("test server should run");
    });
    (format!("http://{addr}"), handle)
}

fn apply_headers(
    mut request: reqwest::RequestBuilder,
    headers: &[(String, String)],
) -> reqwest::RequestBuilder {
    for (name, value) in headers {
        request = request.header(name, value);
    }
    request
}

async fn http_get_json<T: DeserializeOwned>(
    client: &Client,
    url: &str,
    headers: &[(String, String)],
) -> T {
    let response = with_test_timeout(
        format!("GET {url}"),
        apply_headers(client.get(url), headers).send(),
    )
    .await
    .unwrap_or_else(|err| panic!("send GET {url}: {err}"));
    let status = response.status();
    let body = with_test_timeout(format!("read GET {url}"), response.text())
        .await
        .unwrap_or_else(|err| panic!("read GET {url}: {err}"));
    assert_eq!(status, StatusCode::OK, "GET {url} failed: {body}");
    serde_json::from_str(&body)
        .unwrap_or_else(|err| panic!("decode GET {url} response: {err}; {body}"))
}

async fn http_post_json<Req: Serialize, T: DeserializeOwned>(
    client: &Client,
    url: &str,
    headers: &[(String, String)],
    body: &Req,
) -> T {
    let response = with_test_timeout(
        format!("POST {url}"),
        apply_headers(client.post(url), headers).json(body).send(),
    )
    .await
    .unwrap_or_else(|err| panic!("send POST {url}: {err}"));
    let status = response.status();
    let body = with_test_timeout(format!("read POST {url}"), response.text())
        .await
        .unwrap_or_else(|err| panic!("read POST {url}: {err}"));
    assert_eq!(status, StatusCode::OK, "POST {url} failed: {body}");
    serde_json::from_str(&body)
        .unwrap_or_else(|err| panic!("decode POST {url} response: {err}; {body}"))
}

async fn http_post_empty_json<T: DeserializeOwned>(
    client: &Client,
    url: &str,
    headers: &[(String, String)],
) -> T {
    let response = with_test_timeout(
        format!("POST {url}"),
        apply_headers(client.post(url), headers).send(),
    )
    .await
    .unwrap_or_else(|err| panic!("send POST {url}: {err}"));
    let status = response.status();
    let body = with_test_timeout(format!("read POST {url}"), response.text())
        .await
        .unwrap_or_else(|err| panic!("read POST {url}: {err}"));
    assert_eq!(status, StatusCode::OK, "POST {url} failed: {body}");
    serde_json::from_str(&body)
        .unwrap_or_else(|err| panic!("decode POST {url} response: {err}; {body}"))
}

async fn http_delete_empty(client: &Client, url: &str, headers: &[(String, String)]) {
    let response = with_test_timeout(
        format!("DELETE {url}"),
        apply_headers(client.delete(url), headers).send(),
    )
    .await
    .unwrap_or_else(|err| panic!("send DELETE {url}: {err}"));
    let status = response.status();
    let body = with_test_timeout(format!("read DELETE {url}"), response.text())
        .await
        .unwrap_or_else(|err| panic!("read DELETE {url}: {err}"));
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "DELETE {url} failed: {body}"
    );
}

fn normalize_template_description_manifest_urls(value: &mut Value) {
    if let Some(url) = value.pointer_mut("/manifest/manifest/url") {
        *url = Value::String("<manifest>".to_string());
    }
    if let Some(manifests) = value
        .pointer_mut("/manifest/manifests")
        .and_then(Value::as_array_mut)
    {
        for manifest in manifests {
            if let Some(url) = manifest.get_mut("url") {
                *url = Value::String("<manifest>".to_string());
            }
        }
    }
}

fn normalize_dynamic_share_ref(value: &mut Value) {
    if let Some(r#ref) = value.get_mut("ref") {
        *r#ref = Value::String("<dynamic_ref>".to_string());
    }
}

const TEST_SITE_STATE_SCHEMA: &str = "amber.run.site_state";
const TEST_SITE_STATE_VERSION: u32 = 3;
const TEST_REQUEST_TIMEOUT: StdDuration = StdDuration::from_secs(15);

async fn with_test_timeout<T>(label: impl Into<String>, future: impl Future<Output = T>) -> T {
    let label = label.into();
    tokio::time::timeout(TEST_REQUEST_TIMEOUT, future)
        .await
        .unwrap_or_else(|_| panic!("{label} timed out after {:?}", TEST_REQUEST_TIMEOUT))
}

fn with_controller_endpoint(
    app: &ControlStateApp,
    authority_url: &str,
    listen_addr: SocketAddr,
) -> ControlStateApp {
    let mut controller_plan = app.controller_plan.as_ref().clone();
    controller_plan.authority_url = authority_url.to_string();
    controller_plan.listen_addr = listen_addr;
    ControlStateApp {
        control_state: app.control_state.clone(),
        client: app.client.clone(),
        state_path: app.state_path.clone(),
        run_root: app.run_root.clone(),
        state_root: app.state_root.clone(),
        mesh_scope: app.mesh_scope.clone(),
        control_state_auth_token: app.control_state_auth_token.clone(),
        controller_plan: Arc::new(controller_plan),
        authority_locks: app.authority_locks.clone(),
        runtime: app.runtime.clone(),
    }
}

async fn install_framework_site_controller_fixture(
    app: &ControlStateApp,
) -> Vec<tokio::task::JoinHandle<()>> {
    let plan = app.controller_plan.as_ref();
    let site_state_root = PathBuf::from(&plan.site_state_root);
    let artifact_dir = PathBuf::from(&plan.artifact_dir);
    let runtime_root = PathBuf::from(
        plan.runtime_root
            .as_deref()
            .expect("test controller plan should include runtime root"),
    );
    fs::create_dir_all(artifact_dir.join(".amber").join("control"))
        .expect("artifact control dir should exist");
    fs::create_dir_all(&runtime_root).expect("runtime root should exist");
    fs::create_dir_all(&site_state_root).expect("site state root should exist");
    write_json(&site_controller_plan_path(&site_state_root), plan)
        .expect("site controller plan should write");

    let overlay_router = Router::new().route(
        "/overlays/{overlay_id}",
        axum::routing::put(|| async { StatusCode::NO_CONTENT })
            .delete(|| async { StatusCode::NO_CONTENT }),
    );
    let (router_base_url, overlay_handle) = spawn_test_router(overlay_router).await;
    let router_control = router_base_url
        .strip_prefix("http://")
        .expect("router control URL should be absolute HTTP")
        .to_string();

    write_json(
        &site_state_path(&app.state_root, &plan.site_id),
        &json!({
            "schema": TEST_SITE_STATE_SCHEMA,
            "version": TEST_SITE_STATE_VERSION,
            "run_id": plan.run_id,
            "site_id": plan.site_id,
            "kind": plan.kind,
            "status": "running",
            "artifact_dir": plan.artifact_dir,
            "supervisor_pid": 1,
            "router_control": router_control,
            "router_mesh_addr": format!("127.0.0.1:{}", plan.router_mesh_port.expect("router mesh port")),
            "router_identity_id": plan.router_identity_id,
            "router_public_key_b64": base64::engine::general_purpose::STANDARD.encode([11; 32]),
            "site_controller_pid": 1,
            "site_controller_url": plan.authority_url,
        }),
    )
    .expect("manager state should write");
    write_json(
        &artifact_dir.join("direct-plan.json"),
        &json!({
            "version": "3",
            "mesh_provision_plan": "mesh-provision-plan.json",
            "startup_order": [],
            "components": [],
            "router": {
                "identity_id": plan.router_identity_id,
                "mesh_port": plan.router_mesh_port.expect("router mesh port"),
                "control_port": 39011,
                "control_socket_path": "router.sock",
                "mesh_config_path": "router-mesh.json",
                "mesh_identity_path": "router-identity.json",
            },
        }),
    )
    .expect("direct plan should write");
    write_json(
        &direct_runtime_state_path(&artifact_dir),
        &DirectRuntimeState {
            router_mesh_port: plan.router_mesh_port,
            ..Default::default()
        },
    )
    .expect("direct runtime state should write");
    let mut router_mesh = test_live_site_router(Vec::new());
    router_mesh.identity.id = plan.router_identity_id.clone();
    router_mesh.mesh_listen = format!(
        "127.0.0.1:{}",
        plan.router_mesh_port.expect("router mesh port")
    )
    .parse()
    .expect("router mesh listen should parse");
    write_json(&runtime_root.join("router-mesh.json"), &router_mesh)
        .expect("router mesh config should write");

    vec![overlay_handle]
}

struct TestMcpClient {
    client: Client,
    endpoint: String,
    session_id: String,
    headers: Vec<(String, String)>,
    next_id: u64,
}

impl TestMcpClient {
    async fn connect(base_url: &str, client_name: &str, headers: Vec<(String, String)>) -> Self {
        Self::connect_endpoint(&format!("{base_url}/mcp"), client_name, headers).await
    }

    async fn connect_endpoint(
        endpoint: &str,
        client_name: &str,
        headers: Vec<(String, String)>,
    ) -> Self {
        let client = Client::new();
        let initialize = json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {
                    "name": client_name,
                    "version": "0.0.0",
                },
            },
        });
        let response = with_test_timeout(
            format!("MCP initialize request to {endpoint}"),
            apply_headers(client.post(endpoint), &headers)
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .json(&initialize)
                .send(),
        )
        .await
        .expect("send initialize request");
        let status = response.status();
        let response_headers = response.headers().clone();
        let body = with_test_timeout(
            format!("read MCP initialize response from {endpoint}"),
            response.text(),
        )
        .await
        .expect("read initialize response");
        assert_eq!(status, StatusCode::OK, "initialize failed: {body}");
        let session_id = response_headers
            .get("mcp-session-id")
            .expect("initialize should return MCP session ID")
            .to_str()
            .expect("session ID should be valid UTF-8")
            .to_string();
        let payload = sse_json_rpc_message(&body);
        assert!(
            payload.get("error").is_none(),
            "initialize returned error: {payload:#?}"
        );
        assert_eq!(
            payload["result"]["protocolVersion"].as_str(),
            Some("2025-06-18")
        );

        let notification = with_test_timeout(
            format!("MCP initialized notification to {endpoint}"),
            apply_headers(client.post(endpoint), &headers)
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .header("mcp-session-id", &session_id)
                .json(&json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                }))
                .send(),
        )
        .await
        .expect("send initialized notification");
        assert_eq!(notification.status(), StatusCode::ACCEPTED);

        Self {
            client,
            endpoint: endpoint.to_string(),
            session_id,
            headers,
            next_id: 1,
        }
    }

    async fn tools_list(&mut self) -> Vec<Value> {
        self.request("tools/list", json!({}))
            .await
            .get("tools")
            .and_then(Value::as_array)
            .cloned()
            .expect("tools/list should return tools array")
    }

    async fn resources_list(&mut self) -> Vec<Value> {
        self.request("resources/list", json!({}))
            .await
            .get("resources")
            .and_then(Value::as_array)
            .cloned()
            .expect("resources/list should return resources array")
    }

    async fn read_resource_text(&mut self, uri: &str) -> String {
        self.request("resources/read", json!({ "uri": uri }))
            .await
            .get("contents")
            .and_then(Value::as_array)
            .and_then(|contents| contents.first())
            .and_then(|content| content.get("text"))
            .and_then(Value::as_str)
            .expect("resources/read should return text content")
            .to_string()
    }

    async fn call_tool<T: DeserializeOwned>(&mut self, name: &str, arguments: Value) -> T {
        let result = self
            .request(
                "tools/call",
                json!({
                    "name": name,
                    "arguments": arguments,
                }),
            )
            .await;
        assert_ne!(
            result.get("isError").and_then(Value::as_bool),
            Some(true),
            "tool {name} returned isError: {result:#?}"
        );
        serde_json::from_value(
            result
                .get("structuredContent")
                .cloned()
                .expect("tool result should include structuredContent"),
        )
        .unwrap_or_else(|err| panic!("deserialize tool result for {name}: {err}; {result:#?}"))
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let response = apply_headers(
            self.client
                .post(&self.endpoint)
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .header("mcp-session-id", &self.session_id),
            &self.headers,
        )
        .json(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .send();
        let response = with_test_timeout(
            format!("MCP request {method} to {}", self.endpoint),
            response,
        )
        .await
        .unwrap_or_else(|err| panic!("send MCP request {method}: {err}"));
        let status = response.status();
        let body = with_test_timeout(
            format!("read MCP response for {method} from {}", self.endpoint),
            response.text(),
        )
        .await
        .unwrap_or_else(|err| panic!("read MCP response for {method}: {err}"));
        assert_eq!(
            status,
            StatusCode::OK,
            "MCP request {method} failed with status {status}: {body}"
        );
        let payload = sse_json_rpc_message(&body);
        assert_eq!(payload["id"].as_u64(), Some(id));
        assert!(
            payload.get("error").is_none(),
            "MCP request {method} returned error: {payload:#?}"
        );
        payload
            .get("result")
            .cloned()
            .expect("MCP response should include result")
    }
}

struct FrameworkMcpHarness {
    _dir: TempDir,
    client: Client,
    base_url: String,
    route_id: String,
    peer_id: String,
    auth_token: String,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl FrameworkMcpHarness {
    async fn start(with_live_site_runtime: bool) -> Self {
        let (dir, state, state_path, record) = compile_framework_binding_control_state().await;
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("site controller listener");
        let listen_addr = listener.local_addr().expect("site controller addr");
        let base_url = format!("http://{listen_addr}");
        let app = with_controller_endpoint(
            &test_control_state_app(&dir, state, state_path),
            &base_url,
            listen_addr,
        );
        assert_eq!(app.controller_plan.site_id, record.recipient_site_id);
        let mut handles = if with_live_site_runtime {
            install_framework_site_controller_fixture(&app).await
        } else {
            Vec::new()
        };
        let auth_token = "test-router-auth".to_string();
        let controller_app = SiteControllerApp {
            control: app,
            router_auth_token: Arc::<str>::from(auth_token.clone()),
            ready: ready_site_controller_flag(),
        };
        handles.push(tokio::spawn(async move {
            axum::serve(
                listener,
                super::site_controller::site_controller_router(controller_app).into_make_service(),
            )
            .await
            .expect("site controller should serve");
        }));

        Self {
            _dir: dir,
            client: Client::new(),
            base_url,
            route_id: record.cap_instance_id,
            peer_id: record.recipient_peer_id,
            auth_token,
            handles,
        }
    }

    fn http_headers(&self) -> Vec<(String, String)> {
        vec![
            (FRAMEWORK_AUTH_HEADER.to_string(), self.auth_token.clone()),
            (FRAMEWORK_ROUTE_ID_HEADER.to_string(), self.route_id.clone()),
            (FRAMEWORK_PEER_ID_HEADER.to_string(), self.peer_id.clone()),
        ]
    }

    async fn connect(&self) -> TestMcpClient {
        TestMcpClient::connect(
            &self.base_url,
            "framework-component-test",
            self.http_headers(),
        )
        .await
    }

    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> T {
        http_get_json(
            &self.client,
            &format!("{}{}", self.base_url, path),
            &self.http_headers(),
        )
        .await
    }

    async fn post_json<Req: Serialize, T: DeserializeOwned>(&self, path: &str, body: &Req) -> T {
        http_post_json(
            &self.client,
            &format!("{}{}", self.base_url, path),
            &self.http_headers(),
            body,
        )
        .await
    }

    async fn post_empty_json<T: DeserializeOwned>(&self, path: &str) -> T {
        http_post_empty_json(
            &self.client,
            &format!("{}{}", self.base_url, path),
            &self.http_headers(),
        )
        .await
    }

    async fn delete_empty(&self, path: &str) {
        http_delete_empty(
            &self.client,
            &format!("{}{}", self.base_url, path),
            &self.http_headers(),
        )
        .await
    }
}

impl Drop for FrameworkMcpHarness {
    fn drop(&mut self) {
        for handle in &self.handles {
            handle.abort();
        }
    }
}

#[tokio::test]
async fn framework_component_mcp_discovers_compact_surface() {
    let harness = FrameworkMcpHarness::start(false).await;
    let mut mcp = harness.connect().await;

    let tool_names = mcp
        .tools_list()
        .await
        .into_iter()
        .filter_map(|tool| {
            tool.get("name")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        tool_names,
        vec![
            "amber.v1.framework_component.inspect".to_string(),
            "amber.v1.framework_component.mutate".to_string(),
        ]
    );

    let resources = mcp.resources_list().await;
    assert_eq!(resources.len(), 1, "expected one top-level help resource");
    assert_eq!(
        resources[0].get("uri").and_then(Value::as_str),
        Some("amber://framework-component")
    );

    let help = mcp.read_resource_text("amber://framework-component").await;
    assert!(
        help.contains("amber.v1.framework_component.inspect"),
        "help resource should point callers to the inspect tool"
    );
}

#[tokio::test]
async fn framework_component_mcp_matches_http_surface() {
    let http = with_test_timeout(
        "start framework HTTP harness",
        FrameworkMcpHarness::start(true),
    )
    .await;
    let mcp_harness = with_test_timeout(
        "start framework MCP harness",
        FrameworkMcpHarness::start(true),
    )
    .await;
    let mut mcp = with_test_timeout("connect framework MCP client", mcp_harness.connect()).await;
    let mut same_state_mcp =
        with_test_timeout("connect same-state MCP client", http.connect()).await;

    let http_templates: TemplateListResponse = http.get_json("/v1/templates").await;
    let mcp_templates: Value = mcp
        .call_tool(
            "amber.v1.framework_component.inspect",
            json!({ "op": "list_templates" }),
        )
        .await;
    assert_eq!(
        serde_json::to_value(&http_templates).expect("template list should serialize"),
        mcp_templates["data"],
    );

    let http_template: TemplateDescribeResponse = http.get_json("/v1/templates/worker").await;
    let mcp_template: Value = mcp
        .call_tool(
            "amber.v1.framework_component.inspect",
            json!({ "op": "get_template", "template": "worker" }),
        )
        .await;
    let mut http_template_value =
        serde_json::to_value(&http_template).expect("template should serialize");
    let mut mcp_template_value = mcp_template["data"].clone();
    normalize_template_description_manifest_urls(&mut http_template_value);
    normalize_template_description_manifest_urls(&mut mcp_template_value);
    assert_eq!(http_template_value, mcp_template_value,);

    let resolve_request = TemplateResolveRequest { manifest: None };
    let http_resolved: TemplateDescribeResponse = http
        .post_json("/v1/templates/worker/resolve", &resolve_request)
        .await;
    let mcp_resolved: Value = mcp
        .call_tool(
            "amber.v1.framework_component.inspect",
            json!({ "op": "resolve_template", "template": "worker" }),
        )
        .await;
    let mut http_resolved_value =
        serde_json::to_value(&http_resolved).expect("resolved template should serialize");
    let mut mcp_resolved_value = mcp_resolved["data"].clone();
    normalize_template_description_manifest_urls(&mut http_resolved_value);
    normalize_template_description_manifest_urls(&mut mcp_resolved_value);
    assert_eq!(http_resolved_value, mcp_resolved_value,);

    let create_request = CreateChildRequest {
        template: "worker".to_string(),
        name: "job".to_string(),
        manifest: None,
        config: BTreeMap::new(),
        bindings: BTreeMap::new(),
    };
    let http_created: CreateChildResponse = http.post_json("/v1/children", &create_request).await;
    let mcp_created: Value = mcp
        .call_tool(
            "amber.v1.framework_component.mutate",
            json!({
                "op": "create_child",
                "template": "worker",
                "name": "job",
            }),
        )
        .await;
    assert_eq!(
        serde_json::to_value(&http_created).expect("create response should serialize"),
        mcp_created["data"],
    );

    let http_children: ChildListResponse = http.get_json("/v1/children").await;
    let mcp_children: Value = mcp
        .call_tool(
            "amber.v1.framework_component.inspect",
            json!({ "op": "list_children" }),
        )
        .await;
    assert_eq!(
        serde_json::to_value(&http_children).expect("child list should serialize"),
        mcp_children["data"],
    );

    let http_child: ChildDescribeResponse = http.get_json("/v1/children/job").await;
    let mcp_child: Value = mcp
        .call_tool(
            "amber.v1.framework_component.inspect",
            json!({ "op": "get_child", "child": "job" }),
        )
        .await;
    assert_eq!(
        serde_json::to_value(&http_child).expect("child should serialize"),
        mcp_child["data"],
    );

    let http_snapshot: SnapshotResponse = http.post_empty_json("/v1/snapshot").await;
    let mcp_snapshot: Value = same_state_mcp
        .call_tool(
            "amber.v1.framework_component.inspect",
            json!({ "op": "get_snapshot" }),
        )
        .await;
    assert_eq!(
        serde_json::to_value(&http_snapshot).expect("snapshot should serialize"),
        mcp_snapshot["data"],
    );

    http.delete_empty("/v1/children/job").await;
    let mcp_destroyed: Value = mcp
        .call_tool(
            "amber.v1.framework_component.mutate",
            json!({
                "op": "destroy_child",
                "child": "job",
            }),
        )
        .await;
    assert_eq!(mcp_destroyed["data"]["destroyed"].as_bool(), Some(true));

    let http_children_after: ChildListResponse = http.get_json("/v1/children").await;
    let mcp_children_after: Value = mcp
        .call_tool(
            "amber.v1.framework_component.inspect",
            json!({ "op": "list_children" }),
        )
        .await;
    assert!(
        http_children_after.children.is_empty(),
        "HTTP destroy should remove the child"
    );
    assert_eq!(
        serde_json::to_value(&http_children_after).expect("child list should serialize"),
        mcp_children_after["data"],
    );
}

#[tokio::test]
async fn framework_component_rejects_stale_nonlocal_controller_delivery() {
    let (_dir, state, state_path, record) = compile_framework_binding_control_state().await;
    let app = test_control_state_app(&_dir, state.clone(), state_path);
    let mut controller_plan = app.controller_plan.as_ref().clone();
    controller_plan.site_id = "wrong-site".to_string();
    let controller_app = SiteControllerApp {
        control: ControlStateApp {
            control_state: app.control_state.clone(),
            client: app.client.clone(),
            state_path: app.state_path.clone(),
            run_root: app.run_root.clone(),
            state_root: app.state_root.clone(),
            mesh_scope: app.mesh_scope.clone(),
            control_state_auth_token: app.control_state_auth_token.clone(),
            controller_plan: Arc::new(controller_plan),
            authority_locks: app.authority_locks.clone(),
            runtime: app.runtime.clone(),
        },
        router_auth_token: Arc::<str>::from("test-router-auth"),
        ready: ready_site_controller_flag(),
    };

    let err = match super::site_controller::execute_site_controller_framework_inspect(
        &controller_app,
        &record,
        &state,
        FrameworkComponentInspectRequest::ListTemplates,
    )
    .await
    {
        Ok(_) => panic!("stale controller delivery should be rejected"),
        Err(err) => err,
    };
    assert_eq!(err.0.code, ProtocolErrorCode::ControlStateUnavailable);
    assert!(
        err.0
            .message
            .contains("router framework route overlays are stale"),
        "unexpected error: {}",
        err.0.message
    );
}

#[tokio::test]
async fn framework_component_rejects_requests_while_controller_recovers() {
    let (_dir, state, state_path, record) = compile_framework_binding_control_state().await;
    let controller_app = SiteControllerApp {
        control: test_control_state_app(&_dir, state.clone(), state_path),
        router_auth_token: Arc::<str>::from("test-router-auth"),
        ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };

    let err = match super::site_controller::execute_site_controller_framework_inspect(
        &controller_app,
        &record,
        &state,
        FrameworkComponentInspectRequest::ListTemplates,
    )
    .await
    {
        Ok(_) => panic!("recovering controller should reject public framework requests"),
        Err(err) => err,
    };

    assert_eq!(err.0.code, ProtocolErrorCode::ControlStateUnavailable);
    assert_eq!(err.0.message, "site controller is still recovering");
}

#[tokio::test]
async fn framework_component_cross_site_routes_forward_through_site_routers() {
    let (dir, mut state, _state_path, _) = compile_framework_binding_control_state().await;
    state.placement.offered_sites = BTreeMap::from([
        (
            "authority".to_string(),
            SiteDefinition {
                kind: SiteKind::Direct,
                context: None,
            },
        ),
        (
            "consumer".to_string(),
            SiteDefinition {
                kind: SiteKind::Direct,
                context: None,
            },
        ),
    ]);
    state.placement.defaults = PlacementDefaults {
        path: Some("authority".to_string()),
        ..PlacementDefaults::default()
    };
    state.placement.placement_components = BTreeMap::from([
        ("/".to_string(), "authority".to_string()),
        ("/admin".to_string(), "consumer".to_string()),
    ]);
    state.placement.assignments = state.placement.placement_components.clone();
    refresh_capability_instances(&mut state).expect("framework routes should refresh");
    let state_path = dir.path().join("control-state.json");
    write_control_state(&state_path, &state).expect("state should write");
    let app = test_control_state_app(&dir, state, state_path);
    let router_public_key_b64 = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
    let authority_router = Router::new().route(
        "/v1/controller/router-identity",
        axum::routing::get({
            let router_public_key_b64 = router_public_key_b64.clone();
            move || {
                let router_public_key_b64 = router_public_key_b64.clone();
                async move {
                    Json(RouterIdentityResponse {
                        id: "/site/authority/router".to_string(),
                        public_key_b64: router_public_key_b64,
                    })
                }
            }
        }),
    );
    let consumer_router = Router::new().route(
        "/v1/controller/router-identity",
        axum::routing::get({
            let router_public_key_b64 = router_public_key_b64.clone();
            move || {
                let router_public_key_b64 = router_public_key_b64.clone();
                async move {
                    Json(RouterIdentityResponse {
                        id: "/site/consumer/router".to_string(),
                        public_key_b64: router_public_key_b64,
                    })
                }
            }
        }),
    );
    let (authority_base_url, _authority_handle) = spawn_test_router(authority_router).await;
    let (consumer_base_url, _consumer_handle) = spawn_test_router(consumer_router).await;

    let mut authority_plan = app.controller_plan.as_ref().clone();
    authority_plan.peer_site_router_urls =
        BTreeMap::from([("consumer".to_string(), consumer_base_url)]);
    let authority_app = ControlStateApp {
        controller_plan: Arc::new(authority_plan),
        ..app.clone()
    };

    let mut consumer_plan = app.controller_plan.as_ref().clone();
    consumer_plan.site_id = "consumer".to_string();
    consumer_plan.router_identity_id = "/site/consumer/router".to_string();
    consumer_plan.peer_site_router_urls =
        BTreeMap::from([("authority".to_string(), authority_base_url)]);
    consumer_plan.peer_router_mesh_addrs =
        BTreeMap::from([("authority".to_string(), "127.0.0.1:24000".to_string())]);
    let consumer_app = ControlStateApp {
        controller_plan: Arc::new(consumer_plan),
        ..app.clone()
    };

    let authority_overlay = framework_route_overlay_payload(&authority_app)
        .await
        .expect("authority framework routes should materialize")
        .expect("authority site should get a framework route overlay");
    let consumer_overlay = framework_route_overlay_payload(&consumer_app)
        .await
        .expect("consumer framework routes should materialize")
        .expect("consumer site should get a framework route overlay");

    assert!(
        authority_overlay
            .peers
            .iter()
            .any(|peer| peer.id == "/site/consumer/router"),
        "authority router should accept framework traffic from the consumer router",
    );
    assert!(
        consumer_overlay
            .peers
            .iter()
            .any(|peer| peer.id == "/site/authority/router"),
        "consumer router should forward framework traffic to the authority router",
    );

    assert!(
        consumer_overlay.inbound_routes.iter().any(|route| matches!(
            &route.target,
            InboundTarget::MeshForward {
                peer_id,
                peer_addr,
                route_id,
                capability,
            } if peer_id == "/site/authority/router"
                && peer_addr == "127.0.0.1:24000"
                && route_id == &route.route_id
                && capability == &route.capability
        )),
        "cross-site framework requests must enter the consumer router and cross the router mesh",
    );

    assert!(
        authority_overlay
            .inbound_routes
            .iter()
            .any(|route| matches!(
                &route.target,
                InboundTarget::External { url_env, optional }
                    if url_env == amber_mesh::FRAMEWORK_COMPONENT_CONTROLLER_URL_ENV && !optional
            )),
        "the authority router should hand framework requests to its local site controller only \
         after the router hop",
    );
}

#[tokio::test]
async fn framework_route_overlay_payload_uses_planned_peer_router_identities() {
    let (dir, mut state, state_path, _) = compile_framework_binding_control_state().await;
    state.placement.offered_sites = BTreeMap::from([
        (
            "authority".to_string(),
            SiteDefinition {
                kind: SiteKind::Direct,
                context: None,
            },
        ),
        (
            "consumer".to_string(),
            SiteDefinition {
                kind: SiteKind::Direct,
                context: None,
            },
        ),
    ]);
    state.placement.defaults = PlacementDefaults {
        path: Some("authority".to_string()),
        ..PlacementDefaults::default()
    };
    state.placement.placement_components = BTreeMap::from([
        ("/".to_string(), "authority".to_string()),
        ("/admin".to_string(), "consumer".to_string()),
    ]);
    state.placement.assignments = state.placement.placement_components.clone();
    refresh_capability_instances(&mut state).expect("framework routes should refresh");
    write_control_state(&state_path, &state).expect("state should write");
    let app = test_control_state_app(&dir, state, state_path);

    let mut consumer_plan = app.controller_plan.as_ref().clone();
    consumer_plan.site_id = "consumer".to_string();
    consumer_plan.router_identity_id = "/site/consumer/router".to_string();
    consumer_plan.peer_router_identities = BTreeMap::from([(
        "authority".to_string(),
        MeshIdentityPublic {
            id: "/site/authority/router".to_string(),
            public_key: [9u8; 32],
            mesh_scope: Some("test-mesh".to_string()),
        },
    )]);
    consumer_plan.peer_router_mesh_addrs =
        BTreeMap::from([("authority".to_string(), "127.0.0.1:24000".to_string())]);
    let consumer_app = ControlStateApp {
        controller_plan: Arc::new(consumer_plan),
        ..app
    };

    let overlay = framework_route_overlay_payload(&consumer_app)
        .await
        .expect("consumer framework routes should materialize")
        .expect("consumer site should get a framework route overlay");

    assert!(
        overlay
            .peers
            .iter()
            .any(|peer| peer.id == "/site/authority/router" && peer.public_key == [9u8; 32]),
        "consumer overlay should use the planned authority router identity without a peer \
         controller round trip",
    );
}

#[tokio::test]
async fn recover_control_state_reconciles_framework_routes_without_live_peer_controllers() {
    let (dir, mut state, state_path, _) = compile_framework_binding_control_state().await;
    state.placement.offered_sites = BTreeMap::from([
        (
            "authority".to_string(),
            SiteDefinition {
                kind: SiteKind::Direct,
                context: None,
            },
        ),
        (
            "consumer".to_string(),
            SiteDefinition {
                kind: SiteKind::Direct,
                context: None,
            },
        ),
    ]);
    state.placement.defaults = PlacementDefaults {
        path: Some("authority".to_string()),
        ..PlacementDefaults::default()
    };
    state.placement.placement_components = BTreeMap::from([
        ("/".to_string(), "authority".to_string()),
        ("/admin".to_string(), "consumer".to_string()),
    ]);
    state.placement.assignments = state.placement.placement_components.clone();
    refresh_capability_instances(&mut state).expect("framework routes should refresh");
    write_control_state(&state_path, &state).expect("state should write");
    let app = test_control_state_app(&dir, state, state_path);

    let mut authority_plan = app.controller_plan.as_ref().clone();
    authority_plan.site_id = "authority".to_string();
    authority_plan.router_identity_id = "/site/authority/router".to_string();
    authority_plan.peer_router_identities = BTreeMap::from([(
        "consumer".to_string(),
        MeshIdentityPublic {
            id: "/site/consumer/router".to_string(),
            public_key: [8u8; 32],
            mesh_scope: Some("test-mesh".to_string()),
        },
    )]);
    let authority_app = ControlStateApp {
        controller_plan: Arc::new(authority_plan),
        ..app
    };

    recover_control_state(&authority_app).await.expect(
        "recovery should not require a live peer controller when peer router identities were \
         already planned",
    );
}

#[test]
fn inject_site_controller_peer_router_routes_records_peer_router_identities() {
    let temp = TempDir::new().expect("tempdir");
    let artifact_root = temp.path();
    write_json(
        &artifact_root.join("mesh-provision-plan.json"),
        &amber_mesh::MeshProvisionPlan {
            version: amber_mesh::MESH_PROVISION_PLAN_VERSION.to_string(),
            identity_seed: None,
            existing_peer_identities: Vec::new(),
            targets: vec![amber_mesh::MeshProvisionTarget {
                kind: amber_mesh::MeshProvisionTargetKind::Router,
                config: amber_mesh::MeshConfigTemplate {
                    identity: amber_mesh::MeshIdentityTemplate {
                        id: "/site/local/router".to_string(),
                        mesh_scope: Some("test-mesh".to_string()),
                    },
                    mesh_listen: "127.0.0.1:24000".parse().expect("mesh listen"),
                    control_listen: None,
                    dynamic_caps_listen: None,
                    control_allow: None,
                    peers: Vec::new(),
                    inbound: Vec::new(),
                    outbound: Vec::new(),
                    transport: TransportConfig::NoiseIk {},
                },
                output: amber_mesh::MeshProvisionOutput::Filesystem {
                    dir: "mesh/router".to_string(),
                },
            }],
        },
    )
    .expect("mesh provision plan should write");

    inject_site_controller_peer_router_routes(
        artifact_root,
        "local",
        &["/site/peer/router".to_string()],
        &[SiteControllerPeerRouterRoute {
            site_id: "peer".to_string(),
            peer_router: MeshIdentityPublic {
                id: "/site/peer/router".to_string(),
                public_key: [5u8; 32],
                mesh_scope: Some("test-mesh".to_string()),
            },
            peer_addr: "10.0.0.2:24000".to_string(),
            listen_addr: "127.0.0.1".to_string(),
            listen_port: 24123,
        }],
    )
    .expect("site controller peer routes should inject");

    let plan: amber_mesh::MeshProvisionPlan = read_json(
        &artifact_root.join("mesh-provision-plan.json"),
        "mesh provision plan",
    )
    .expect("mesh provision plan should read");
    assert!(
        plan.existing_peer_identities
            .iter()
            .any(|identity| identity.id == "/site/peer/router" && identity.public_key == [5u8; 32]),
        "the injected router plan should carry peer router identities so startup does not need \
         runtime discovery",
    );
    let router = plan
        .targets
        .iter()
        .find(|target| matches!(target.kind, amber_mesh::MeshProvisionTargetKind::Router))
        .expect("router target should remain present");
    assert!(
        router
            .config
            .outbound
            .iter()
            .any(|route| route.route_id == "site-controller:peer"
                && route.peer_id == "/site/peer/router"),
        "the router plan should include the site-controller forwarding route for the peer site",
    );
}

#[tokio::test]
async fn prepare_child_on_site_rejects_nonlocal_site_plan() {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let worker_path = dir.path().join("worker.json5");
    write_file(
        &worker_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["worker"],
                network: { endpoints: [{ name: "http", port: 8080 }] }
              }
            }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r#"
                {{
                  manifest_version: "0.3.0",
                  program: {{ path: "/bin/echo", args: ["root"] }},
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{
                      manifest: "{worker}"
                    }}
                  }}
                }}
            "#,
            worker = file_url(&worker_path),
        ),
    );
    let state = compile_control_state(&root_path).await;
    let state_path = dir.path().join("control-state.json");
    write_control_state(&state_path, &state).expect("state should write");
    let app = test_control_state_app(&dir, state, state_path);
    let mut child = empty_live_child(1, "remote", 1, ChildState::CreatePrepared);
    child.assignments = BTreeMap::from([("/remote".to_string(), "other-site".to_string())]);
    let err = prepare_child_on_site(&app, &app.control_state.lock().await.clone(), &child)
        .await
        .expect_err("nonlocal children should be rejected");
    assert_eq!(err.code, ProtocolErrorCode::PrepareFailed);
    assert!(
        err.message.contains("only creates local children"),
        "unexpected error: {}",
        err.message
    );
}

struct DynamicCapsMcpHarness {
    _dir: TempDir,
    client: Client,
    base_url: String,
    auth_token: String,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl DynamicCapsMcpHarness {
    async fn start() -> Self {
        let dir = TempDir::new().expect("temp dir");
        let state = compile_dynamic_caps_binding_state().await;
        let state_path = dir.path().join("control-state.json");
        write_control_state(&state_path, &state).expect("state should write");
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("site controller listener");
        let listen_addr = listener.local_addr().expect("site controller addr");
        let base_url = format!("http://{listen_addr}");
        let app = with_controller_endpoint(
            &test_control_state_app(&dir, state, state_path),
            &base_url,
            listen_addr,
        );
        let mut handles = vec![install_dynamic_caps_origin_fixture(&app).await];
        let controller_app = SiteControllerApp {
            control: app,
            router_auth_token: Arc::<str>::from("test-router-auth"),
            ready: ready_site_controller_flag(),
        };
        handles.push(tokio::spawn(async move {
            axum::serve(
                listener,
                super::site_controller::site_controller_router(controller_app).into_make_service(),
            )
            .await
            .expect("site controller should serve");
        }));
        Self {
            _dir: dir,
            client: Client::new(),
            base_url,
            auth_token: "test-control-state-auth".to_string(),
            handles,
        }
    }

    fn http_headers(&self) -> Vec<(String, String)> {
        vec![(FRAMEWORK_AUTH_HEADER.to_string(), self.auth_token.clone())]
    }

    async fn connect(&self) -> TestMcpClient {
        TestMcpClient::connect_endpoint(
            &format!("{}/v1/controller/dynamic-caps/mcp", self.base_url),
            "framework-dynamic-caps-test",
            self.http_headers(),
        )
        .await
    }

    async fn post_json<Req: Serialize, T: DeserializeOwned>(&self, path: &str, body: &Req) -> T {
        http_post_json(
            &self.client,
            &format!("{}{}", self.base_url, path),
            &self.http_headers(),
            body,
        )
        .await
    }
}

impl Drop for DynamicCapsMcpHarness {
    fn drop(&mut self) {
        for handle in &self.handles {
            handle.abort();
        }
    }
}

async fn install_dynamic_caps_origin_fixture(app: &ControlStateApp) -> tokio::task::JoinHandle<()> {
    let plan = app.controller_plan.as_ref();
    let site_state_root = PathBuf::from(&plan.site_state_root);
    let artifact_dir = PathBuf::from(&plan.artifact_dir);
    let runtime_root = PathBuf::from(
        plan.runtime_root
            .as_deref()
            .expect("test controller plan should include runtime root"),
    );
    fs::create_dir_all(artifact_dir.join(".amber").join("control"))
        .expect("artifact control dir should exist");
    fs::create_dir_all(&runtime_root).expect("runtime root should exist");
    fs::create_dir_all(&site_state_root).expect("site state root should exist");

    write_json(&site_controller_plan_path(&site_state_root), plan)
        .expect("site controller plan should write");

    let overlay_router = Router::new().route(
        "/overlays/{overlay_id}",
        axum::routing::put(|| async { StatusCode::NO_CONTENT })
            .delete(|| async { StatusCode::NO_CONTENT }),
    );
    let (router_base_url, overlay_handle) = spawn_test_router(overlay_router).await;
    let router_control = router_base_url
        .strip_prefix("http://")
        .expect("router control URL should be absolute HTTP")
        .to_string();

    write_json(
        &site_state_path(&app.state_root, &plan.site_id),
        &json!({
            "status": "running",
            "kind": plan.kind,
            "artifact_dir": artifact_dir.display().to_string(),
            "supervisor_pid": 1,
            "router_control": router_control,
            "router_mesh_addr": "127.0.0.1:39001",
            "router_identity_id": plan.router_identity_id,
            "router_public_key_b64": "dGVzdC1yb3V0ZXIta2V5",
            "site_controller_pid": 1,
            "site_controller_url": plan.authority_url,
        }),
    )
    .expect("manager state should write");
    write_json(
        &site_state_root.join("site-controller-runtime-state.json"),
        &json!({
            "schema": "amber.run.site_controller_runtime_state",
            "version": 1,
            "run_id": plan.run_id,
            "site_id": plan.site_id,
            "kind": plan.kind,
            "children": {},
        }),
    )
    .expect("site controller runtime state should write");
    write_json(
        &artifact_dir.join("direct-plan.json"),
        &json!({
            "version": "3",
            "mesh_provision_plan": "mesh-provision-plan.json",
            "startup_order": [1, 2],
            "components": [
                {
                    "id": 1,
                    "moniker": "/provider",
                    "log_name": "provider",
                    "sidecar": {
                        "log_name": "provider-sidecar",
                        "mesh_port": 24001,
                        "mesh_config_path": "provider-mesh.json",
                        "mesh_identity_path": "provider-identity.json",
                    },
                    "program": {
                        "log_name": "provider-program",
                        "work_dir": ".",
                        "execution": {
                            "kind": "direct",
                            "entrypoint": ["/bin/true"],
                        },
                    },
                },
                {
                    "id": 2,
                    "moniker": "/alice",
                    "log_name": "alice",
                    "sidecar": {
                        "log_name": "alice-sidecar",
                        "mesh_port": 24002,
                        "mesh_config_path": "alice-mesh.json",
                        "mesh_identity_path": "alice-identity.json",
                    },
                    "program": {
                        "log_name": "alice-program",
                        "work_dir": ".",
                        "execution": {
                            "kind": "direct",
                            "entrypoint": ["/bin/true"],
                        },
                    },
                },
            ],
            "router": {
                "identity_id": plan.router_identity_id,
                "mesh_port": 39001,
                "control_port": 39011,
                "control_socket_path": "router.sock",
                "mesh_config_path": "router-mesh.json",
                "mesh_identity_path": "router-identity.json",
            },
        }),
    )
    .expect("direct plan should write");
    write_json(
        &direct_runtime_state_path(&artifact_dir),
        &DirectRuntimeState {
            component_mesh_port_by_id: BTreeMap::from([(1, 24001), (2, 24002)]),
            ..Default::default()
        },
    )
    .expect("direct runtime state should write");
    write_json(
        &runtime_root.join("provider-mesh.json"),
        &test_live_component_runtime(
            "/provider",
            "/provider",
            "127.0.0.1:24001",
            Vec::new(),
            Vec::new(),
        )
        .mesh_config,
    )
    .expect("provider mesh config should write");
    write_json(
        &runtime_root.join("alice-mesh.json"),
        &test_live_component_runtime(
            "/alice",
            "/alice",
            "127.0.0.1:24002",
            Vec::new(),
            vec![OutboundRoute {
                route_id: "provider-route".to_string(),
                rewrite_route_id: None,
                slot: "upstream".to_string(),
                capability_kind: Some("http".to_string()),
                capability_profile: None,
                listen_port: 20000,
                listen_addr: None,
                protocol: MeshProtocol::Http,
                http_plugins: Vec::new(),
                peer_addr: "127.0.0.1:24001".to_string(),
                peer_id: "/provider".to_string(),
                capability: "http".to_string(),
            }],
        )
        .mesh_config,
    )
    .expect("alice mesh config should write");
    write_json(&runtime_root.join("router-mesh.json"), &{
        let mut router = test_live_site_router(Vec::new());
        router.identity.id = plan.router_identity_id.clone();
        router
    })
    .expect("router mesh config should write");

    overlay_handle
}

#[tokio::test]
async fn dynamic_caps_held_list_ignores_unrouted_offered_sites() {
    let dir = TempDir::new().expect("temp dir");
    let mut state = compile_dynamic_caps_binding_state().await;
    state.placement.offered_sites.insert(
        "compose_local".to_string(),
        SiteDefinition {
            kind: SiteKind::Compose,
            context: None,
        },
    );
    state.placement.offered_sites.insert(
        "vm_local".to_string(),
        SiteDefinition {
            kind: SiteKind::Vm,
            context: None,
        },
    );
    let state_path = dir.path().join("control-state.json");
    write_control_state(&state_path, &state).expect("state should write");
    let controller_app = SiteControllerApp {
        control: test_control_state_app(&dir, state, state_path),
        router_auth_token: Arc::<str>::from("test-router-auth"),
        ready: ready_site_controller_flag(),
    };

    let response = super::site_controller::execute_site_controller_dynamic_caps_inspect(
        &controller_app,
        super::control_state_api::DynamicCapsInspectRequest::HeldList(
            dynamic_caps::ControlDynamicHeldListRequest {
                holder_component_id: "components./alice".to_string(),
            },
        ),
        false,
    )
    .await
    .expect("held list should stay local when no peer controller routes exist");

    let super::control_state_api::DynamicCapsInspectResponse::HeldList(held) = response else {
        panic!("held list request should return a held list response");
    };
    assert!(
        held.held
            .iter()
            .any(|entry| entry.entry_kind == HeldEntryKind::RootAuthority),
        "local held roots should still be returned",
    );
}

#[tokio::test]
async fn localize_framework_control_state_tracks_remote_grant_authority_sites() {
    let base = compile_dynamic_caps_binding_state().await;
    let placement = PlacementFile {
        schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
        version: amber_compiler::run_plan::PLACEMENT_VERSION,
        sites: BTreeMap::from([
            (
                "direct_a".to_string(),
                SiteDefinition {
                    kind: SiteKind::Direct,
                    context: None,
                },
            ),
            (
                "direct_b".to_string(),
                SiteDefinition {
                    kind: SiteKind::Direct,
                    context: None,
                },
            ),
        ]),
        defaults: PlacementDefaults {
            path: Some("direct_a".to_string()),
            ..PlacementDefaults::default()
        },
        components: BTreeMap::from([
            ("/provider".to_string(), "direct_a".to_string()),
            ("/alice".to_string(), "direct_a".to_string()),
            ("/bob".to_string(), "direct_b".to_string()),
        ]),
        dynamic_capabilities: None,
        framework_children: None,
    };
    let mut state = compile_control_state_from_ir_with_run_id(
        base.base_scenario.clone(),
        Some(&placement),
        "test-run",
    )
    .await;
    let alice_root = super::dynamic_caps::source_key_from_held_id(
        &state,
        "components./alice",
        &root_held_id_for(&state, "components./alice"),
    )
    .expect("alice root source should resolve");
    let share = super::dynamic_caps::share_dynamic_capability(
        &mut state,
        "components./alice",
        &alice_root,
        "components./bob",
        None,
        &json!({}),
    )
    .expect("cross-site share should succeed");
    let super::dynamic_caps::DynamicCapabilityShareOutcome::Created { grant_id, .. } = share else {
        panic!("cross-site share should create a grant");
    };

    localize_framework_control_state(&mut state, "direct_b")
        .expect("recipient site state should localize");

    assert!(
        state.dynamic_capability_grants.is_empty(),
        "recipient site should not retain the authoritative grant record",
    );
    assert_eq!(
        state
            .dynamic_capability_grant_authority_sites
            .get(&grant_id),
        Some(&"direct_a".to_string()),
        "recipient site should retain a lightweight authority index for delegated grants",
    );
}

#[tokio::test]
async fn inspect_ref_routes_remote_grants_via_synced_authority_site() {
    let dir = TempDir::new().expect("temp dir");
    let base = compile_dynamic_caps_binding_state().await;
    let placement = PlacementFile {
        schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
        version: amber_compiler::run_plan::PLACEMENT_VERSION,
        sites: BTreeMap::from([
            (
                "direct_a".to_string(),
                SiteDefinition {
                    kind: SiteKind::Direct,
                    context: None,
                },
            ),
            (
                "direct_b".to_string(),
                SiteDefinition {
                    kind: SiteKind::Direct,
                    context: None,
                },
            ),
        ]),
        defaults: PlacementDefaults {
            path: Some("direct_a".to_string()),
            ..PlacementDefaults::default()
        },
        components: BTreeMap::from([
            ("/provider".to_string(), "direct_a".to_string()),
            ("/alice".to_string(), "direct_a".to_string()),
            ("/bob".to_string(), "direct_b".to_string()),
        ]),
        dynamic_capabilities: None,
        framework_children: None,
    };
    let mut authoritative = compile_control_state_from_ir_with_run_id(
        base.base_scenario.clone(),
        Some(&placement),
        "test-run",
    )
    .await;
    let alice_root = super::dynamic_caps::source_key_from_held_id(
        &authoritative,
        "components./alice",
        &root_held_id_for(&authoritative, "components./alice"),
    )
    .expect("alice root source should resolve");
    let share = super::dynamic_caps::share_dynamic_capability(
        &mut authoritative,
        "components./alice",
        &alice_root,
        "components./bob",
        None,
        &json!({}),
    )
    .expect("cross-site share should succeed");
    let (grant_id, shared_ref) = match share {
        super::dynamic_caps::DynamicCapabilityShareOutcome::Created { grant_id, r#ref } => {
            (grant_id, r#ref)
        }
        _ => panic!("cross-site share should create a grant"),
    };

    let mut holder_state = authoritative.clone();
    localize_framework_control_state(&mut holder_state, "direct_b")
        .expect("holder site state should localize");
    let state_path = dir.path().join("control-state.json");
    write_control_state(&state_path, &holder_state).expect("holder state should write");

    let hits = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let remote_grant_id = grant_id.clone();
    let router = Router::new().route(
        "/v1/controller/dynamic-caps/inspect-ref",
        axum::routing::post({
            let hits = hits.clone();
            let remote_grant_id = remote_grant_id.clone();
            move |headers: HeaderMap,
                  Json(request): Json<dynamic_caps::ControlDynamicInspectRefRequest>| {
                let hits = hits.clone();
                let remote_grant_id = remote_grant_id.clone();
                async move {
                    assert_eq!(
                        headers
                            .get(super::site_controller::CONTROLLER_LOCAL_ONLY_HEADER)
                            .and_then(|value| value.to_str().ok()),
                        Some("1"),
                        "peer-routed inspect_ref should stay local on the destination controller",
                    );
                    hits.lock()
                        .expect("inspect-ref hit log poisoned")
                        .push(request.r#ref.clone());
                    Json(amber_mesh::dynamic_caps::InspectRefResponse {
                        state: HeldEntryState::Live,
                        grant_id: remote_grant_id,
                        holder_component_id: "components./bob".to_string(),
                        descriptor: DescriptorIr {
                            kind: "http".to_string(),
                            label: "provider.http".to_string(),
                            profile: None,
                        },
                        held_id: Some(super::dynamic_caps::held_id_for_grant("g_0000000000000000")),
                    })
                }
            }
        }),
    );
    let (authority_base_url, _authority_handle) = spawn_test_router(router).await;

    let mut app = test_control_state_app(&dir, holder_state, state_path);
    let controller_plan = Arc::make_mut(&mut app.controller_plan);
    controller_plan.site_id = "direct_b".to_string();
    controller_plan.router_identity_id = "/site/direct_b/router".to_string();
    controller_plan.peer_site_router_urls =
        BTreeMap::from([("direct_a".to_string(), authority_base_url)]);
    let controller_app = SiteControllerApp {
        control: app,
        router_auth_token: Arc::<str>::from("test-router-auth"),
        ready: ready_site_controller_flag(),
    };

    let response = super::site_controller::execute_site_controller_dynamic_caps_inspect(
        &controller_app,
        super::control_state_api::DynamicCapsInspectRequest::InspectRef(
            dynamic_caps::ControlDynamicInspectRefRequest {
                holder_component_id: "components./bob".to_string(),
                r#ref: shared_ref.clone(),
            },
        ),
        false,
    )
    .await
    .expect("holder site should route inspect_ref through the authority site");

    let super::control_state_api::DynamicCapsInspectResponse::InspectRef(response) = response
    else {
        panic!("inspect_ref should return inspect response");
    };
    assert_eq!(response.state, HeldEntryState::Live);
    assert_eq!(response.grant_id, grant_id);
    assert_eq!(
        hits.lock()
            .expect("inspect-ref hit log poisoned")
            .as_slice(),
        &[shared_ref],
        "inspect_ref should route exactly once through the authority site router",
    );
}

#[tokio::test]
async fn dynamic_caps_mcp_discovers_compact_surface() {
    let harness = DynamicCapsMcpHarness::start().await;
    let mut mcp = harness.connect().await;

    let tool_names = mcp
        .tools_list()
        .await
        .into_iter()
        .filter_map(|tool| {
            tool.get("name")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        tool_names,
        vec![
            "amber.v1.framework_dynamic_caps.inspect".to_string(),
            "amber.v1.framework_dynamic_caps.mutate".to_string(),
        ]
    );

    let resources = mcp.resources_list().await;
    assert_eq!(resources.len(), 1, "expected one top-level help resource");
    assert_eq!(
        resources[0].get("uri").and_then(Value::as_str),
        Some("amber://framework-dynamic-caps")
    );

    let help = mcp
        .read_resource_text("amber://framework-dynamic-caps")
        .await;
    assert!(
        help.contains("amber.v1.framework_dynamic_caps.inspect"),
        "help resource should point callers to the inspect tool"
    );
}

#[tokio::test]
async fn dynamic_caps_mcp_matches_http_surface() {
    let http = DynamicCapsMcpHarness::start().await;
    let mcp_harness = DynamicCapsMcpHarness::start().await;
    let mut mcp = mcp_harness.connect().await;

    let held_list_request = dynamic_caps::ControlDynamicHeldListRequest {
        holder_component_id: "components./alice".to_string(),
    };
    let http_held: amber_mesh::dynamic_caps::HeldListResponse = http
        .post_json("/v1/controller/dynamic-caps/held", &held_list_request)
        .await;
    let mcp_held: Value = mcp
        .call_tool(
            "amber.v1.framework_dynamic_caps.inspect",
            json!({
                "op": "held_list",
                "holder_component_id": "components./alice",
            }),
        )
        .await;
    assert_eq!(
        serde_json::to_value(&http_held).expect("held list should serialize"),
        mcp_held["data"],
    );
    let root_held_id = http_held
        .held
        .iter()
        .find(|entry| entry.entry_kind == HeldEntryKind::RootAuthority)
        .map(|entry| entry.held_id.clone())
        .expect("alice should have a root authority");

    let held_detail_request = dynamic_caps::ControlDynamicHeldDetailRequest {
        holder_component_id: "components./alice".to_string(),
        held_id: root_held_id.clone(),
    };
    let http_detail: HeldEntryDetail = http
        .post_json(
            "/v1/controller/dynamic-caps/held/detail",
            &held_detail_request,
        )
        .await;
    let mcp_detail: Value = mcp
        .call_tool(
            "amber.v1.framework_dynamic_caps.inspect",
            json!({
                "op": "held_detail",
                "holder_component_id": "components./alice",
                "held_id": root_held_id,
            }),
        )
        .await;
    assert_eq!(
        serde_json::to_value(&http_detail).expect("held detail should serialize"),
        mcp_detail["data"],
    );
    let root_authority_selector = http_detail
        .summary
        .root_authority_selector
        .clone()
        .expect("root detail should include selector");

    let share_request = dynamic_caps::ControlDynamicShareRequest {
        caller_component_id: "components./alice".to_string(),
        source: dynamic_caps::DynamicCapabilityControlSourceRequest::RootAuthority {
            root_authority_selector: root_authority_selector.clone(),
        },
        recipient_component_id: "components./carol".to_string(),
        idempotency_key: Some("share-carol".to_string()),
        options: Value::Null,
    };
    let http_share: amber_mesh::dynamic_caps::ShareResponse = http
        .post_json("/v1/controller/dynamic-caps/share", &share_request)
        .await;
    let mcp_share: Value = mcp
        .call_tool(
            "amber.v1.framework_dynamic_caps.mutate",
            json!({
                "op": "share",
                "caller_component_id": "components./alice",
                "source": {
                    "kind": "root_authority",
                    "root_authority_selector": serde_json::to_value(&root_authority_selector)
                        .expect("root authority selector should serialize"),
                },
                "recipient_component_id": "components./carol",
                "idempotency_key": "share-carol",
            }),
        )
        .await;
    let mcp_share_ref = mcp_share["data"]["ref"]
        .as_str()
        .expect("MCP share should return a ref")
        .to_string();
    let mut http_share_value =
        serde_json::to_value(&http_share).expect("share response should serialize");
    let mut mcp_share_value = mcp_share["data"].clone();
    normalize_dynamic_share_ref(&mut http_share_value);
    normalize_dynamic_share_ref(&mut mcp_share_value);
    assert_eq!(http_share_value, mcp_share_value,);
    let grant_id = http_share
        .grant_id
        .clone()
        .expect("share should produce a grant");
    let shared_ref = http_share
        .r#ref
        .clone()
        .expect("share should produce a ref");

    let carol_held_request = dynamic_caps::ControlDynamicHeldListRequest {
        holder_component_id: "components./carol".to_string(),
    };
    let http_carol_held: amber_mesh::dynamic_caps::HeldListResponse = http
        .post_json("/v1/controller/dynamic-caps/held", &carol_held_request)
        .await;
    let mcp_carol_held: Value = mcp
        .call_tool(
            "amber.v1.framework_dynamic_caps.inspect",
            json!({
                "op": "held_list",
                "holder_component_id": "components./carol",
            }),
        )
        .await;
    assert_eq!(
        serde_json::to_value(&http_carol_held).expect("held list should serialize"),
        mcp_carol_held["data"],
    );

    let inspect_ref_request = dynamic_caps::ControlDynamicInspectRefRequest {
        holder_component_id: "components./carol".to_string(),
        r#ref: shared_ref.clone(),
    };
    let http_inspect_ref: amber_mesh::dynamic_caps::InspectRefResponse = http
        .post_json(
            "/v1/controller/dynamic-caps/inspect-ref",
            &inspect_ref_request,
        )
        .await;
    let mcp_inspect_ref: Value = mcp
        .call_tool(
            "amber.v1.framework_dynamic_caps.inspect",
            json!({
                "op": "inspect_ref",
                "holder_component_id": "components./carol",
                "ref": mcp_share_ref,
            }),
        )
        .await;
    assert_eq!(
        serde_json::to_value(&http_inspect_ref).expect("inspect ref should serialize"),
        mcp_inspect_ref["data"],
    );

    let resolve_origin_request = dynamic_caps::ControlDynamicResolveOriginRequest {
        holder_component_id: "components./alice".to_string(),
        source: dynamic_caps::DynamicCapabilityControlSourceRequest::RootAuthority {
            root_authority_selector: root_authority_selector.clone(),
        },
    };
    let http_resolve_origin: dynamic_caps::ControlDynamicResolveOriginResponse = http
        .post_json(
            "/v1/controller/dynamic-caps/resolve-origin",
            &resolve_origin_request,
        )
        .await;
    let mcp_resolve_origin: Value = mcp
        .call_tool(
            "amber.v1.framework_dynamic_caps.inspect",
            json!({
                "op": "resolve_origin",
                "holder_component_id": "components./alice",
                "source": {
                    "kind": "root_authority",
                    "root_authority_selector": serde_json::to_value(&root_authority_selector)
                        .expect("root authority selector should serialize"),
                },
            }),
        )
        .await;
    assert_eq!(
        serde_json::to_value(&http_resolve_origin).expect("resolve origin should serialize"),
        mcp_resolve_origin["data"],
    );

    let revoke_request = dynamic_caps::ControlDynamicRevokeRequest {
        caller_component_id: "components./alice".to_string(),
        target: dynamic_caps::DynamicCapabilityControlSourceRequest::Grant {
            grant_id: grant_id.clone(),
        },
    };
    let http_revoke: amber_mesh::dynamic_caps::RevokeResponse = http
        .post_json("/v1/controller/dynamic-caps/revoke", &revoke_request)
        .await;
    let mcp_revoke: Value = mcp
        .call_tool(
            "amber.v1.framework_dynamic_caps.mutate",
            json!({
                "op": "revoke",
                "caller_component_id": "components./alice",
                "target": {
                    "kind": "grant",
                    "grant_id": grant_id.clone(),
                },
            }),
        )
        .await;
    assert_eq!(
        serde_json::to_value(&http_revoke).expect("revoke response should serialize"),
        mcp_revoke["data"],
    );

    let revoked_detail_request = dynamic_caps::ControlDynamicHeldDetailRequest {
        holder_component_id: "components./carol".to_string(),
        held_id: super::dynamic_caps::held_id_for_grant(&grant_id),
    };
    let http_revoked_detail: HeldEntryDetail = http
        .post_json(
            "/v1/controller/dynamic-caps/held/detail",
            &revoked_detail_request,
        )
        .await;
    let mcp_revoked_detail: Value = mcp
        .call_tool(
            "amber.v1.framework_dynamic_caps.inspect",
            json!({
                "op": "held_detail",
                "holder_component_id": "components./carol",
                "held_id": revoked_detail_request.held_id,
            }),
        )
        .await;
    assert_eq!(
        serde_json::to_value(&http_revoked_detail).expect("held detail should serialize"),
        mcp_revoked_detail["data"],
    );
}

#[tokio::test]
async fn dynamic_caps_resolve_origin_tolerates_missing_static_runtime_state_file() {
    let harness = DynamicCapsMcpHarness::start().await;

    let held: amber_mesh::dynamic_caps::HeldListResponse = harness
        .post_json(
            "/v1/controller/dynamic-caps/held",
            &dynamic_caps::ControlDynamicHeldListRequest {
                holder_component_id: "components./alice".to_string(),
            },
        )
        .await;
    let root_held_id = held
        .held
        .iter()
        .find(|entry| entry.entry_kind == HeldEntryKind::RootAuthority)
        .map(|entry| entry.held_id.clone())
        .expect("alice should have a root authority");
    let detail: HeldEntryDetail = harness
        .post_json(
            "/v1/controller/dynamic-caps/held/detail",
            &dynamic_caps::ControlDynamicHeldDetailRequest {
                holder_component_id: "components./alice".to_string(),
                held_id: root_held_id,
            },
        )
        .await;
    let selector = detail
        .summary
        .root_authority_selector
        .clone()
        .expect("root held detail should include a root authority selector");

    fs::remove_file(
        harness
            ._dir
            .path()
            .join("state")
            .join("direct_local")
            .join("site-controller-runtime-state.json"),
    )
    .expect("fixture runtime state should be removable");

    let resolve_origin: dynamic_caps::ControlDynamicResolveOriginResponse = harness
        .post_json(
            "/v1/controller/dynamic-caps/resolve-origin",
            &dynamic_caps::ControlDynamicResolveOriginRequest {
                holder_component_id: "components./alice".to_string(),
                source: dynamic_caps::DynamicCapabilityControlSourceRequest::RootAuthority {
                    root_authority_selector: selector,
                },
            },
        )
        .await;

    assert!(
        !resolve_origin.origin_peer_addr.is_empty(),
        "static components should still resolve a live origin even when the dynamic runtime state \
         file is absent",
    );
}

#[tokio::test]
async fn create_snapshot_and_destroy_exact_child() {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");
    write_file(
        &child_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["child"],
                network: { endpoints: [{ name: "out", port: 8080 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
    );
    write_file(
        &root_path,
        &format!(
            r#"
                {{
                  manifest_version: "0.3.0",
                  program: {{ path: "/bin/echo", args: ["root"] }},
                  slots: {{
                    ctl: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{ manifest: "{child}" }}
                  }},
                }}
                "#,
            child = file_url(&child_path),
        ),
    );

    let placement = PlacementFile {
        schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
        version: amber_compiler::run_plan::PLACEMENT_VERSION,
        sites: BTreeMap::from([
            (
                "direct_a".to_string(),
                SiteDefinition {
                    kind: SiteKind::Direct,
                    context: None,
                },
            ),
            (
                "direct_b".to_string(),
                SiteDefinition {
                    kind: SiteKind::Direct,
                    context: None,
                },
            ),
        ]),
        defaults: PlacementDefaults {
            path: Some("direct_a".to_string()),
            ..PlacementDefaults::default()
        },
        components: BTreeMap::from([("/job-b".to_string(), "direct_b".to_string())]),
        dynamic_capabilities: None,
        framework_children: None,
    };

    let mut state = compile_control_state_with_placement(&root_path, Some(&placement)).await;
    let state_path = dir.path().join("control-state.json");
    write_control_state(&state_path, &state).expect("state should write");
    let root_authority = state.base_scenario.root;

    let response = create_child(
        &mut state,
        root_authority,
        CreateChildRequest {
            template: "worker".to_string(),
            name: "job-1".to_string(),
            manifest: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        },
        &state_path,
    )
    .await
    .expect("create should succeed");

    assert_eq!(response.child.selector, "children.job-1");
    assert!(
        state
            .live_children
            .iter()
            .any(|child| child.name == "job-1")
    );

    let snapshot_response =
        snapshot(&state, state.base_scenario.root).expect("snapshot should succeed");
    let scenario_ir: ScenarioIr = serde_json::from_value(snapshot_response.scenario)
        .expect("snapshot scenario should decode");
    assert!(
        scenario_ir
            .components
            .iter()
            .any(|component| component.moniker == "/job-1"),
        "snapshot should contain the created child root"
    );

    destroy_child(&mut state, root_authority, "job-1", &state_path)
        .await
        .expect("destroy should succeed");
    assert!(
        state.live_children.is_empty(),
        "destroy should remove the live child record"
    );
    let snapshot_response =
        snapshot(&state, state.base_scenario.root).expect("snapshot should succeed");
    let scenario_ir: ScenarioIr = serde_json::from_value(snapshot_response.scenario)
        .expect("snapshot scenario should decode");
    assert!(
        !scenario_ir
            .components
            .iter()
            .any(|component| component.moniker == "/job-1"),
        "destroyed child should be absent from snapshots"
    );
}

#[tokio::test]
async fn open_template_admits_requested_manifest_ref() {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let alpha_path = dir.path().join("alpha.json5");
    let beta_path = dir.path().join("beta.json5");
    write_file(
        &alpha_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["alpha"],
                network: { endpoints: [{ name: "out", port: 8080 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
    );
    write_file(
        &beta_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["beta"],
                network: { endpoints: [{ name: "out", port: 8080 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
    );
    write_file(
        &root_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: { path: "/bin/echo", args: ["root"] },
              slots: {
                ctl: { kind: "component", optional: true }
              },
              child_templates: {
                worker: {}
              },
            }
            "#,
    );

    let mut state = compile_control_state(&root_path).await;
    let state_path = dir.path().join("control-state.json");
    write_control_state(&state_path, &state).expect("state should write");
    let beta_key = file_url(&beta_path);
    let root_authority = state.base_scenario.root;

    create_child(
        &mut state,
        root_authority,
        CreateChildRequest {
            template: "worker".to_string(),
            name: "job-open".to_string(),
            manifest: Some(beta_key.parse().expect("manifest ref")),
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        },
        &state_path,
    )
    .await
    .expect("open-template create should succeed");

    assert_eq!(
        state.live_children[0]
            .selected_manifest_catalog_key
            .as_deref(),
        Some(beta_key.as_str())
    );
    let snapshot_response =
        snapshot(&state, state.base_scenario.root).expect("snapshot should succeed");
    let scenario_ir: ScenarioIr = serde_json::from_value(snapshot_response.scenario)
        .expect("snapshot scenario should decode");
    let child = scenario_ir
        .components
        .iter()
        .find(|component| component.moniker == "/job-open")
        .expect("snapshot should contain the created child");
    let rendered_program = serde_json::to_string(&child.program).expect("program should encode");
    assert!(
        rendered_program.contains("beta"),
        "snapshot should contain the selected manifest, got {rendered_program}"
    );
}

#[tokio::test]
async fn open_template_replay_uses_admitted_manifest_after_source_mutation() {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let alpha_path = dir.path().join("alpha.json5");
    let beta_path = dir.path().join("beta.json5");
    let beta_leaf_path = dir.path().join("beta-leaf.json5");
    write_file(
        &alpha_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["alpha-original"],
                network: { endpoints: [{ name: "out", port: 8081 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
    );
    write_file(
        &beta_path,
        r##"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["beta-original"],
                network: { endpoints: [{ name: "out", port: 8082 }] }
              },
              components: {
                leaf: "./beta-leaf.json5"
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: {
                out: "provides.out",
                leaf: "#leaf.out"
              },
            }
            "##,
    );
    write_file(
        &beta_leaf_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["beta-leaf-original"],
                network: { endpoints: [{ name: "out", port: 8083 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
    );
    write_file(
        &root_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: { path: "/bin/echo", args: ["root"] },
              slots: {
                realm: { kind: "component", optional: true }
              },
              child_templates: {
                worker: {}
              },
            }
            "#,
    );

    let mut state = compile_control_state(&root_path).await;
    let state_path = dir.path().join("control-state.json");
    write_control_state(&state_path, &state).expect("state should write");
    let root_authority = state.base_scenario.root;
    let beta_key = file_url(&beta_path);

    create_child(
        &mut state,
        root_authority,
        CreateChildRequest {
            template: "worker".to_string(),
            name: "job-open".to_string(),
            manifest: Some(beta_key.parse().expect("manifest ref")),
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        },
        &state_path,
    )
    .await
    .expect("open-template create should admit the selected manifest");

    write_file(
        &beta_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["beta-mutated-on-disk"],
                network: { endpoints: [{ name: "out", port: 8082 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
    );
    fs::remove_file(&alpha_path).expect("alpha source should be removable after compile");

    let snapshot_response =
        snapshot(&state, root_authority).expect("snapshot should succeed after create");
    let scenario_ir: ScenarioIr = serde_json::from_value(snapshot_response.scenario.clone())
        .expect("snapshot scenario should decode");
    let created_child = scenario_ir
        .components
        .iter()
        .find(|component| component.moniker == "/job-open")
        .expect("snapshot should contain the created child");
    let created_leaf = scenario_ir
        .components
        .iter()
        .find(|component| component.moniker == "/job-open/leaf")
        .expect("snapshot should contain the admitted transitive child");
    let created_program =
        serde_json::to_string(&created_child.program).expect("program should encode");
    let created_leaf_program =
        serde_json::to_string(&created_leaf.program).expect("leaf program should encode");
    assert!(
        created_program.contains("beta-original"),
        "snapshot should preserve the frozen selected manifest, got {created_program}"
    );
    assert!(
        !created_program.contains("beta-mutated-on-disk"),
        "snapshot must not reread the current disk manifest, got {created_program}"
    );
    assert!(
        created_leaf_program.contains("beta-leaf-original"),
        "snapshot should preserve admitted transitive manifests, got {created_leaf_program}"
    );

    fs::remove_file(&beta_path).expect("beta source should be removable before replay");
    fs::remove_file(&beta_leaf_path).expect("beta leaf source should be removable before replay");

    let replay_scenario_ir: ScenarioIr = serde_json::from_value(snapshot_response.scenario.clone())
        .expect("snapshot scenario should decode for replay run plan");
    let replay_placement = placement_from_snapshot(&snapshot_response);
    let replay_compiled =
        CompiledScenario::from_ir(replay_scenario_ir).expect("snapshot replay should compile");
    let replay_run_plan =
        build_run_plan(&replay_compiled, Some(&replay_placement)).expect("replay run plan");
    let mut localized_replay = build_site_controller_state(
        "replay-run",
        &replay_run_plan,
        "direct_local",
        0,
        1,
        &mesh_dynamic_caps::signing_seed_b64(&mesh_dynamic_caps::signing_key_from_seed(
            mesh_dynamic_caps::generate_dynamic_capability_signing_seed(),
        )),
    )
    .expect("site-local replay state should build");
    assert!(
        localized_replay
            .live_children
            .iter()
            .any(|child| child.name == "job-open" && child.state == ChildState::Live),
        "site-local replay should preserve live children even when the root authority has no \
         explicit assignment"
    );
    let replayed_live_child_id = localized_replay
        .live_children
        .iter()
        .map(|child| child.child_id)
        .max()
        .expect("site-local replay should keep the restored live child id");
    assert_eq!(
        localized_replay.next_child_id, replayed_live_child_id,
        "site-local replay must preserve the child id allocator after restoring live children"
    );
    let replay_next_child_id = allocate_child_id(&mut localized_replay);
    assert!(
        replay_next_child_id > replayed_live_child_id,
        "site-local replay must allocate a fresh child id instead of colliding with restored \
         children"
    );

    let mut replayed = compile_control_state_from_snapshot(&snapshot_response).await;
    let replay_state_path = dir.path().join("replay-control-state.json");
    write_control_state(&replay_state_path, &replayed).expect("replay state should write");
    let replay_root_authority = replayed.base_scenario.root;
    assert_eq!(replayed.live_children.len(), 1);
    assert_eq!(replayed.live_children[0].name, "job-open");
    assert_eq!(replayed.live_children[0].state, ChildState::Live);
    assert!(
        replayed.live_children[0].fragment.is_some(),
        "replay should restore the child fragment as authoritative semantic state",
    );
    assert!(
        build_local_child_runtime_spec(
            &replayed,
            &replayed.live_children[0],
            &child_runtime_site_id(&replayed.live_children[0]).expect("replayed child site id"),
        )
        .is_ok(),
        "replay should rebuild local runtime realization from the restored child fragment",
    );
    assert!(
        list_children(&replayed, replay_root_authority)
            .children
            .iter()
            .any(|child| child.name == "job-open" && child.state == ChildState::Live),
        "replay should rebuild authoritative live child records",
    );
    assert!(
        Scenario::try_from(replayed.base_scenario.clone())
            .expect("replayed base scenario")
            .components_iter()
            .any(|(_, component)| component.moniker.as_str() == "/job-open"),
        "replay should treat the resumed child as part of the authoritative base scenario",
    );

    let replay_scenario = decode_live_scenario(&replayed).expect("replayed scenario");
    assert_eq!(
        replay_scenario
            .components_iter()
            .filter(|(_, component)| component.moniker.as_str() == "/job-open")
            .count(),
        1,
        "replay should not duplicate live child fragments into the snapshot scenario",
    );
    let replay_child = replay_scenario
        .components_iter()
        .find(|(_, component)| component.moniker.as_str() == "/job-open")
        .map(|(_, component)| component)
        .expect("replay should restore the admitted child");
    let replay_program =
        serde_json::to_string(&replay_child.program).expect("program should encode");
    assert!(
        replay_program.contains("beta-original"),
        "replay should still use the admitted manifest content, got {replay_program}"
    );
    assert!(
        !replay_program.contains("beta-mutated-on-disk"),
        "replay must not fall back to mutated on-disk content, got {replay_program}"
    );
    let replay_leaf = replay_scenario
        .components_iter()
        .find(|(_, component)| component.moniker.as_str() == "/job-open/leaf")
        .map(|(_, component)| component)
        .expect("replay should restore admitted transitive children");
    let replay_leaf_program =
        serde_json::to_string(&replay_leaf.program).expect("leaf program should encode");
    assert!(
        replay_leaf_program.contains("beta-leaf-original"),
        "replay should still use admitted transitive manifests, got {replay_leaf_program}"
    );

    let resolved = resolve_template(
        &replayed,
        replay_root_authority,
        "worker",
        TemplateResolveRequest {
            manifest: Some(beta_key.parse().expect("manifest ref")),
        },
    )
    .await
    .expect("replayed snapshot should preserve admitted manifest affordances");
    assert!(
        resolved
            .manifest
            .manifest
            .expect("resolved template should report the selected manifest")
            .url
            .as_url()
            .expect("manifest should be absolute")
            .as_str()
            == beta_key,
        "resolve should continue to use the admitted manifest ref"
    );

    destroy_child(
        &mut replayed,
        replay_root_authority,
        "job-open",
        &replay_state_path,
    )
    .await
    .expect("destroy should succeed after replay");
    assert!(
        replayed.live_children.is_empty(),
        "destroy after replay should remove the child record",
    );
    assert!(
        !decode_live_scenario(&replayed)
            .expect("live scenario after replayed destroy")
            .components_iter()
            .any(|(_, component)| component.moniker.as_str() == "/job-open"),
        "destroy after replay must fully remove the resumed child from the live graph",
    );
    assert!(
        !Scenario::try_from(replayed.base_scenario.clone())
            .expect("base scenario after replayed destroy")
            .components_iter()
            .any(|(_, component)| component.moniker.as_str() == "/job-open"),
        "destroy after replay must also remove the child from the authoritative base scenario",
    );
}

#[tokio::test]
async fn open_template_admission_uses_canonical_manifest_url_and_freezes_redirected_dependencies() {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    write_file(
        &root_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: { path: "/bin/echo", args: ["root"] },
              slots: {
                realm: { kind: "component", optional: true }
              },
              child_templates: {
                worker: {}
              },
            }
            "#,
    );

    let leaf_manifest = r#"
        {
          manifest_version: "0.3.0",
          program: {
            path: "/bin/echo",
            args: ["redirect-leaf"],
            network: { endpoints: [{ name: "out", port: 8084 }] }
          },
          provides: { out: { kind: "http", endpoint: "out" } },
          exports: { out: "provides.out" }
        }
    "#;
    let (requested_url, canonical_root_url, canonical_leaf_url, server) =
        spawn_redirecting_runtime_manifest_server(leaf_manifest.to_string());

    let mut state = compile_control_state(&root_path).await;
    let state_path = dir.path().join("control-state.json");
    write_control_state(&state_path, &state).expect("state should write");
    let root_authority = state.base_scenario.root;

    create_child(
        &mut state,
        root_authority,
        CreateChildRequest {
            template: "worker".to_string(),
            name: "job-open".to_string(),
            manifest: Some(requested_url.parse().expect("manifest ref")),
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        },
        &state_path,
    )
    .await
    .expect("redirected open-template create should succeed");
    server.join().expect("manifest server should stop cleanly");

    assert_eq!(
        state.live_children[0]
            .selected_manifest_catalog_key
            .as_deref(),
        Some(canonical_root_url.as_str())
    );
    assert!(
        state
            .base_scenario
            .manifest_catalog
            .contains_key(canonical_root_url.as_str()),
        "admitted runtime manifests should be keyed by the resolver's final URL"
    );
    assert!(
        state
            .base_scenario
            .manifest_catalog
            .contains_key(canonical_leaf_url.as_str()),
        "admitting an open template should freeze transitive redirected dependencies"
    );

    let snapshot_response =
        snapshot(&state, root_authority).expect("snapshot should succeed after redirected create");
    let scenario_ir: ScenarioIr = serde_json::from_value(snapshot_response.scenario)
        .expect("snapshot scenario should decode");
    assert!(
        scenario_ir
            .components
            .iter()
            .any(|component| component.moniker == "/job-open/leaf"),
        "snapshot should contain the redirected transitive child component"
    );
}

#[tokio::test]
async fn dynamic_framework_bindings_refresh_capability_instances_and_preserve_origin_realm() {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let parent_path = dir.path().join("parent.json5");
    let worker_path = dir.path().join("worker.json5");
    let root_worker_path = dir.path().join("root-worker.json5");
    write_file(
        &worker_path,
        r#"
            {
              manifest_version: "0.3.0",
              slots: {
                realm: { kind: "component", optional: true }
              },
              program: {
                path: "/bin/echo",
                args: ["worker", "${slots.realm.url}"],
                network: { endpoints: [{ name: "http", port: 8080 }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
    );
    write_file(
        &root_worker_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["root-worker"],
                network: { endpoints: [{ name: "http", port: 8082 }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
    );
    write_file(
        &parent_path,
        &format!(
            r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  program: {{
                    path: "/bin/echo",
                    args: ["parent", "${{slots.realm.url}}"],
                    network: {{ endpoints: [{{ name: "http", port: 8081 }}] }}
                  }},
                  provides: {{ http: {{ kind: "http", endpoint: "http" }} }},
                  exports: {{ http: "provides.http" }},
                  child_templates: {{
                    worker: {{
                      manifest: "{worker}",
                      bindings: {{
                        realm: "slots.realm"
                      }}
                    }}
                  }},
                }}
                "#,
            worker = file_url(&worker_path),
        ),
    );
    write_file(
        &root_path,
        &format!(
            r##"
                {{
                  manifest_version: "0.3.0",
                  program: {{ path: "/bin/echo", args: ["root"] }},
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    root_worker: {{
                      manifest: "{root_worker}"
                    }}
                  }},
                  components: {{
                    parent: "{parent}"
                  }},
                  bindings: [
                    {{ to: "#parent.realm", from: "framework.component" }}
                  ],
                  exports: {{
                    parent_http: "#parent.http"
                  }},
                }}
                "##,
            root_worker = file_url(&root_worker_path),
            parent = file_url(&parent_path),
        ),
    );

    let mut state = compile_control_state(&root_path).await;
    let state_path = dir.path().join("control-state.json");
    write_control_state(&state_path, &state).expect("state should write");
    let base = Scenario::try_from(state.base_scenario.clone()).expect("base scenario");
    let parent_id = base
        .components_iter()
        .find(|(_, component)| component.moniker.as_str() == "/parent")
        .map(|(id, _)| id.0)
        .expect("parent component should exist");
    let static_parent_record = state
        .capability_instances
        .values()
        .find(|record| record.recipient_component_moniker == "/parent")
        .cloned()
        .expect("static parent should have a realm capability instance");
    assert_eq!(static_parent_record.authority_realm_moniker, "/");

    create_child(
        &mut state,
        parent_id,
        CreateChildRequest {
            template: "worker".to_string(),
            name: "delegate".to_string(),
            manifest: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        },
        &state_path,
    )
    .await
    .expect("delegate child should be created");

    let dynamic_record = state
        .capability_instances
        .values()
        .find(|record| record.recipient_component_moniker == "/parent/delegate")
        .cloned()
        .expect("dynamic child should receive its own realm capability instance");
    let root_authority = state.base_scenario.root;
    assert_eq!(dynamic_record.authority_realm_id, root_authority);
    assert_eq!(dynamic_record.authority_realm_moniker, "/");
    let authorized =
        authorize_capability_instance(&state, &dynamic_record.cap_instance_id, "/parent/delegate")
            .expect("dynamic child capability instance should authorize for its own peer");
    let delegated_authority_realm_id = authorized.authority_realm_id;
    assert_eq!(delegated_authority_realm_id, root_authority);

    create_child(
        &mut state,
        delegated_authority_realm_id,
        CreateChildRequest {
            template: "root_worker".to_string(),
            name: "sibling".to_string(),
            manifest: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        },
        &state_path,
    )
    .await
    .expect("forwarded realm authority should create a sibling in the parent realm");

    let live_scenario = live_scenario_ir(&state).expect("live scenario should materialize");
    let live = Scenario::try_from(live_scenario).expect("live scenario should decode");
    assert!(
        live.components_iter()
            .any(|(_, component)| component.moniker.as_str() == "/parent/delegate"),
        "delegate should live under the parent realm"
    );
    assert!(
        live.components_iter()
            .any(|(_, component)| component.moniker.as_str() == "/sibling"),
        "forwarded realm capability should create in the origin realm, not under the caller"
    );

    destroy_child(&mut state, parent_id, "delegate", &state_path)
        .await
        .expect("destroy should succeed");
    assert!(
        !state
            .capability_instances
            .values()
            .any(|record| record.recipient_component_moniker == "/parent/delegate"),
        "destroy should revoke dynamic capability instances owned by the removed child"
    );
}

#[tokio::test]
async fn delegated_cross_site_framework_requests_route_to_the_forwarded_authority_site() {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let parent_path = dir.path().join("parent.json5");
    let worker_path = dir.path().join("worker.json5");
    let root_worker_path = dir.path().join("root-worker.json5");
    write_file(
        &worker_path,
        r#"
            {
              manifest_version: "0.3.0",
              slots: {
                realm: { kind: "component", optional: true }
              },
              program: {
                path: "/bin/echo",
                args: ["worker", "${slots.realm.url}"],
                network: { endpoints: [{ name: "http", port: 8080 }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
    );
    write_file(
        &root_worker_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["root-worker"],
                network: { endpoints: [{ name: "http", port: 8082 }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
    );
    write_file(
        &parent_path,
        &format!(
            r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  program: {{
                    path: "/bin/echo",
                    args: ["parent", "${{slots.realm.url}}"]
                  }},
                  child_templates: {{
                    worker: {{
                      manifest: "{worker}",
                      bindings: {{
                        realm: "slots.realm"
                      }}
                    }}
                  }},
                }}
                "#,
            worker = file_url(&worker_path),
        ),
    );
    write_file(
        &root_path,
        &format!(
            r##"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    root_worker: {{
                      manifest: "{root_worker}"
                    }}
                  }},
                  components: {{
                    parent: "{parent}"
                  }},
                  bindings: [
                    {{ to: "#parent.realm", from: "framework.component" }}
                  ],
                }}
                "##,
            root_worker = file_url(&root_worker_path),
            parent = file_url(&parent_path),
        ),
    );
    let placement = PlacementFile {
        schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
        version: amber_compiler::run_plan::PLACEMENT_VERSION,
        sites: BTreeMap::from([
            (
                "compose_local".to_string(),
                SiteDefinition {
                    kind: SiteKind::Direct,
                    context: None,
                },
            ),
            (
                "direct_local".to_string(),
                SiteDefinition {
                    kind: SiteKind::Direct,
                    context: None,
                },
            ),
        ]),
        defaults: PlacementDefaults {
            path: Some("direct_local".to_string()),
            ..PlacementDefaults::default()
        },
        components: BTreeMap::from([
            ("/parent".to_string(), "compose_local".to_string()),
            ("/parent/delegate".to_string(), "direct_local".to_string()),
            ("/sibling".to_string(), "compose_local".to_string()),
        ]),
        dynamic_capabilities: None,
        framework_children: None,
    };

    let mut authoritative =
        compile_control_state_with_placement(&root_path, Some(&placement)).await;
    let authoritative_state_path = dir.path().join("authoritative-state.json");
    write_control_state(&authoritative_state_path, &authoritative).expect("state should write");
    let base = Scenario::try_from(authoritative.base_scenario.clone()).expect("base scenario");
    let parent_id = base
        .components_iter()
        .find(|(_, component)| component.moniker.as_str() == "/parent")
        .map(|(id, _)| id.0)
        .expect("parent component should exist");
    create_child(
        &mut authoritative,
        parent_id,
        CreateChildRequest {
            template: "worker".to_string(),
            name: "delegate".to_string(),
            manifest: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        },
        &authoritative_state_path,
    )
    .await
    .expect("delegate child should be created");

    let mut direct_state = authoritative.clone();
    localize_framework_control_state(&mut direct_state, "direct_local")
        .expect("direct-local state should localize");
    direct_state.placement.assignments =
        BTreeMap::from([("/parent/delegate".to_string(), "direct_local".to_string())]);
    let direct_record = direct_state
        .capability_instances
        .values()
        .find(|record| record.recipient_component_moniker == "/parent/delegate")
        .cloned()
        .expect("delegate should have a forwarded framework capability instance");
    assert_eq!(
        framework_authority_site_id(&direct_state, &direct_record)
            .expect("authority site should resolve through composite placement"),
        "compose_local",
        "delegated root authority should stay anchored at the forwarded realm site",
    );
    let router_public_key_b64 = base64::engine::general_purpose::STANDARD.encode([11u8; 32]);
    let peer_router_attempts = std::sync::Arc::new(std::sync::Mutex::new(0usize));
    let peer_router = Router::new().route(
        "/v1/controller/router-identity",
        axum::routing::get({
            let router_public_key_b64 = router_public_key_b64.clone();
            let peer_router_attempts = peer_router_attempts.clone();
            move || {
                let router_public_key_b64 = router_public_key_b64.clone();
                let peer_router_attempts = peer_router_attempts.clone();
                async move {
                    let mut attempts = peer_router_attempts
                        .lock()
                        .expect("peer router attempt log poisoned");
                    *attempts += 1;
                    if *attempts == 1 {
                        return Err(StatusCode::BAD_GATEWAY);
                    }
                    Ok(Json(RouterIdentityResponse {
                        id: "/site/direct_local/router".to_string(),
                        public_key_b64: router_public_key_b64,
                    }))
                }
            }
        }),
    );
    let (peer_router_base_url, _peer_router_handle) = spawn_test_router(peer_router).await;
    let direct_state_path = dir.path().join("direct-state.json");
    write_control_state(&direct_state_path, &direct_state).expect("direct state should write");
    let mut direct_plan = test_control_state_app(&dir, direct_state.clone(), direct_state_path)
        .controller_plan
        .as_ref()
        .clone();
    direct_plan.site_id = "direct_local".to_string();
    direct_plan.kind = SiteKind::Direct;
    direct_plan.peer_site_router_urls =
        BTreeMap::from([("compose_local".to_string(), peer_router_base_url.clone())]);
    direct_plan.peer_router_mesh_addrs =
        BTreeMap::from([("compose_local".to_string(), "127.0.0.1:25000".to_string())]);
    let direct_controller_app = SiteControllerApp {
        control: ControlStateApp {
            control_state: Arc::new(Mutex::new(direct_state.clone())),
            controller_plan: Arc::new(direct_plan),
            ..test_control_state_app(
                &dir,
                direct_state.clone(),
                dir.path().join("direct-state.json"),
            )
        },
        router_auth_token: Arc::<str>::from("test-router-auth"),
        ready: ready_site_controller_flag(),
    };
    reconcile_local_framework_routes(&direct_controller_app.control)
        .await
        .expect("direct-local controller should publish delegated framework routes");
    let stale_err = match super::site_controller::execute_site_controller_framework_mutate(
        &direct_controller_app,
        &direct_record,
        &direct_state,
        super::ccs_api::FrameworkComponentMutateRequest::CreateChild(CreateChildRequest {
            template: "root_worker".to_string(),
            name: "sibling".to_string(),
            manifest: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        }),
    )
    .await
    {
        Ok(_) => panic!("the delegated caller site should reject stale local delivery"),
        Err(err) => err,
    };
    assert_eq!(stale_err.0.code, ProtocolErrorCode::ControlStateUnavailable);
    assert!(
        stale_err
            .0
            .message
            .contains("router framework route overlays are stale"),
        "unexpected stale-delivery error: {}",
        stale_err.0.message
    );

    let mut compose_state = authoritative;
    localize_framework_control_state(&mut compose_state, "compose_local")
        .expect("compose-local state should localize");
    let compose_record = compose_state
        .capability_instances
        .values()
        .find(|record| record.recipient_component_moniker == "/parent/delegate")
        .cloned()
        .expect("compose-local controller should retain the delegated capability instance");
    let compose_state_path = dir.path().join("compose-state.json");
    write_control_state(&compose_state_path, &compose_state).expect("compose state should write");
    let mut compose_plan =
        test_control_state_app(&dir, compose_state.clone(), compose_state_path.clone())
            .controller_plan
            .as_ref()
            .clone();
    compose_plan.site_id = "compose_local".to_string();
    compose_plan.kind = SiteKind::Direct;
    compose_plan.peer_site_router_urls =
        BTreeMap::from([("direct_local".to_string(), peer_router_base_url)]);
    compose_plan.peer_router_mesh_addrs =
        BTreeMap::from([("direct_local".to_string(), "127.0.0.1:24000".to_string())]);
    let compose_controller_app = SiteControllerApp {
        control: ControlStateApp {
            control_state: Arc::new(Mutex::new(compose_state.clone())),
            controller_plan: Arc::new(compose_plan),
            ..test_control_state_app(&dir, compose_state.clone(), compose_state_path)
        },
        router_auth_token: Arc::<str>::from("test-router-auth"),
        ready: ready_site_controller_flag(),
    };
    let response = super::site_controller::execute_site_controller_framework_mutate(
        &compose_controller_app,
        &compose_record,
        &compose_state,
        super::ccs_api::FrameworkComponentMutateRequest::CreateChild(CreateChildRequest {
            template: "root_worker".to_string(),
            name: "sibling".to_string(),
            manifest: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        }),
    )
    .await
    .expect("forwarded realm create should succeed on the authority site controller");
    let super::ccs_api::FrameworkComponentMutateResponse::CreateChild(response) = response else {
        panic!("framework mutate response should be a create result");
    };
    assert_eq!(
        response.child.selector, "children.sibling",
        "the authority controller should create the child under the forwarded root realm",
    );
    let persisted = compose_controller_app
        .control
        .control_state
        .lock()
        .await
        .clone();
    assert!(
        persisted
            .live_children
            .iter()
            .any(|child| child.name == "sibling"
                && child_runtime_site_id(child)
                    .as_deref()
                    .is_ok_and(|site_id| site_id == "compose_local")),
        "the forwarded root child should be owned by the compose-local controller state"
    );
}

#[tokio::test]
async fn capability_instance_auth_and_snapshot_scope_are_enforced() {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let parent_path = dir.path().join("parent.json5");
    write_file(
        &parent_path,
        r#"
            {
              manifest_version: "0.3.0",
              slots: {
                realm: { kind: "component", optional: true }
              },
              program: {
                path: "/bin/echo",
                args: ["parent", "${slots.realm.url}"],
                network: { endpoints: [{ name: "http", port: 8081 }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
                {{
                  manifest_version: "0.3.0",
                  program: {{ path: "/bin/echo", args: ["root"] }},
                  components: {{
                    parent: "{parent}"
                  }},
                  bindings: [
                    {{ to: "#parent.realm", from: "framework.component" }}
                  ],
                  exports: {{
                    parent_http: "#parent.http"
                  }},
                }}
                "##,
            parent = file_url(&parent_path),
        ),
    );

    let state = compile_control_state(&root_path).await;
    let base = Scenario::try_from(state.base_scenario.clone()).expect("base scenario");
    let parent_id = base
        .components_iter()
        .find(|(_, component)| component.moniker.as_str() == "/parent")
        .map(|(id, _)| id.0)
        .expect("parent component should exist");
    let record = state
        .capability_instances
        .values()
        .find(|record| record.recipient_component_moniker == "/parent")
        .expect("parent should have a realm capability instance");

    let wrong_peer = authorize_capability_instance(&state, &record.cap_instance_id, "/root")
        .expect_err("peer mismatch should be rejected");
    assert_eq!(wrong_peer.code, ProtocolErrorCode::Unauthorized);

    let unknown = authorize_capability_instance(&state, "cap.missing", "/parent")
        .expect_err("unknown capability instance should be rejected");
    assert_eq!(unknown.code, ProtocolErrorCode::Unauthorized);

    let snapshot_err =
        snapshot(&state, parent_id).expect_err("non-root authority should not be able to snapshot");
    assert_eq!(snapshot_err.code, ProtocolErrorCode::ScopeNotAllowed);
}

#[tokio::test]
async fn destroy_and_recreate_same_child_name_gets_a_new_capability_instance_id() {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let parent_path = dir.path().join("parent.json5");
    let worker_path = dir.path().join("worker.json5");
    write_file(
        &worker_path,
        r#"
            {
              manifest_version: "0.3.0",
              slots: {
                realm: { kind: "component", optional: true }
              },
              program: {
                path: "/bin/echo",
                args: ["worker", "${slots.realm.url}"],
                network: { endpoints: [{ name: "http", port: 8080 }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
    );
    write_file(
        &parent_path,
        &format!(
            r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  program: {{
                    path: "/bin/echo",
                    args: ["parent", "${{slots.realm.url}}"],
                    network: {{ endpoints: [{{ name: "http", port: 8081 }}] }}
                  }},
                  provides: {{ http: {{ kind: "http", endpoint: "http" }} }},
                  exports: {{ http: "provides.http" }},
                  child_templates: {{
                    worker: {{
                      manifest: "{worker}",
                      bindings: {{
                        realm: "slots.realm"
                      }}
                    }}
                  }},
                }}
                "#,
            worker = file_url(&worker_path),
        ),
    );
    write_file(
        &root_path,
        &format!(
            r##"
                {{
                  manifest_version: "0.3.0",
                  program: {{ path: "/bin/echo", args: ["root"] }},
                  components: {{
                    parent: "{parent}"
                  }},
                  bindings: [
                    {{ to: "#parent.realm", from: "framework.component" }}
                  ],
                }}
                "##,
            parent = file_url(&parent_path),
        ),
    );

    let mut state = compile_control_state(&root_path).await;
    let state_path = dir.path().join("control-state.json");
    write_control_state(&state_path, &state).expect("state should write");
    let base = Scenario::try_from(state.base_scenario.clone()).expect("base scenario");
    let parent_id = base
        .components_iter()
        .find(|(_, component)| component.moniker.as_str() == "/parent")
        .map(|(id, _)| id.0)
        .expect("parent component should exist");

    create_child(
        &mut state,
        parent_id,
        CreateChildRequest {
            template: "worker".to_string(),
            name: "delegate".to_string(),
            manifest: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        },
        &state_path,
    )
    .await
    .expect("first delegate create should succeed");
    let first_cap_instance_id = state
        .capability_instances
        .values()
        .find(|record| record.recipient_component_moniker == "/parent/delegate")
        .map(|record| record.cap_instance_id.clone())
        .expect("first delegate capability instance should exist");

    destroy_child(&mut state, parent_id, "delegate", &state_path)
        .await
        .expect("destroy should succeed");
    assert!(
        !state
            .capability_instances
            .values()
            .any(|record| record.recipient_component_moniker == "/parent/delegate"),
        "destroy should revoke the first child lifetime's capability instance",
    );

    create_child(
        &mut state,
        parent_id,
        CreateChildRequest {
            template: "worker".to_string(),
            name: "delegate".to_string(),
            manifest: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        },
        &state_path,
    )
    .await
    .expect("second delegate create should succeed");
    let second_cap_instance_id = state
        .capability_instances
        .values()
        .find(|record| record.recipient_component_moniker == "/parent/delegate")
        .map(|record| record.cap_instance_id.clone())
        .expect("second delegate capability instance should exist");

    assert_ne!(
        first_cap_instance_id, second_cap_instance_id,
        "recreating the same child name must mint a new framework capability instance id",
    );
}

#[test]
fn framework_auth_header_must_match_expected_token() {
    let mut headers = HeaderMap::new();
    let missing = authorize_framework_auth_header(&headers, "expected")
        .expect_err("missing auth header should be rejected");
    assert_eq!(missing.0.code, ProtocolErrorCode::Unauthorized);

    headers.insert(
        FRAMEWORK_AUTH_HEADER,
        "wrong".parse().expect("header should parse"),
    );
    let wrong = authorize_framework_auth_header(&headers, "expected")
        .expect_err("mismatched auth header should be rejected");
    assert_eq!(wrong.0.code, ProtocolErrorCode::Unauthorized);

    headers.insert(
        FRAMEWORK_AUTH_HEADER,
        "expected".parse().expect("header should parse"),
    );
    authorize_framework_auth_header(&headers, "expected")
        .expect("matching auth header should succeed");
}

#[tokio::test]
async fn dynamic_authority_templates_are_listed_and_created_from_live_realm() {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let worker_path = dir.path().join("worker.json5");
    let admin_path = dir.path().join("admin.json5");
    let nested_path = dir.path().join("nested.json5");

    write_file(
        &admin_path,
        r#"
            {
              manifest_version: "0.3.0",
              slots: {
                realm: { kind: "component", optional: true }
              },
              program: {
                path: "/bin/echo",
                args: ["admin", "${slots.realm.url}"],
                network: { endpoints: [{ name: "http", port: 8081, protocol: "http" }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
    );
    write_file(
        &nested_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["nested"],
                network: { endpoints: [{ name: "http", port: 8082, protocol: "http" }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
    );
    write_file(
        &worker_path,
        &format!(
            r##"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm_cap: {{ kind: "component", optional: true }}
                  }},
                  program: {{
                    path: "/bin/echo",
                    args: ["worker"],
                    network: {{ endpoints: [{{ name: "http", port: 8080, protocol: "http" }}] }}
                  }},
                  provides: {{ http: {{ kind: "http", endpoint: "http" }} }},
                  exports: {{ http: "provides.http" }},
                  components: {{
                    admin: "{admin}"
                  }},
                  child_templates: {{
                    nested: {{ manifest: "{nested}" }}
                  }},
                  bindings: [
                    {{ to: "#admin.realm", from: "framework.component" }}
                  ],
                }}
                "##,
            admin = file_url(&admin_path),
            nested = file_url(&nested_path),
        ),
    );
    write_file(
        &root_path,
        &format!(
            r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{ manifest: "{worker}" }}
                  }},
                }}
                "#,
            worker = file_url(&worker_path),
        ),
    );

    let mut state = compile_control_state(&root_path).await;
    let state_path = dir.path().join("control-state.json");
    write_control_state(&state_path, &state).expect("state should write");
    let root_authority = state.base_scenario.root;

    create_child(
        &mut state,
        root_authority,
        CreateChildRequest {
            template: "worker".to_string(),
            name: "delegate".to_string(),
            manifest: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        },
        &state_path,
    )
    .await
    .expect("delegate child should be created");

    let delegated_realm = state
        .capability_instances
        .values()
        .find(|record| record.recipient_component_moniker == "/delegate/admin")
        .cloned()
        .expect("dynamic admin should receive a framework capability instance");
    assert_eq!(
        delegated_realm.authority_realm_moniker, "/delegate",
        "delegated capability should originate from the dynamic child realm",
    );

    let listed = list_templates(&state, delegated_realm.authority_realm_id)
        .expect("dynamic realm templates should be available");
    assert_eq!(
        listed
            .templates
            .iter()
            .map(|template| template.name.as_str())
            .collect::<Vec<_>>(),
        vec!["nested"],
    );
    let described = describe_template(&state, delegated_realm.authority_realm_id, "nested")
        .expect("dynamic realm template description should use the live realm");
    assert_eq!(described.name, "nested");

    create_child(
        &mut state,
        delegated_realm.authority_realm_id,
        CreateChildRequest {
            template: "nested".to_string(),
            name: "inner".to_string(),
            manifest: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        },
        &state_path,
    )
    .await
    .expect("dynamic delegated authority should create inside the live child realm");

    let live = decode_live_scenario(&state).expect("live scenario should decode");
    assert!(
        live.components_iter()
            .any(|(_, component)| component.moniker.as_str() == "/delegate/inner"),
        "nested child should be created under the dynamic authority realm",
    );
    assert!(
        !live
            .components_iter()
            .any(|(_, component)| component.moniker.as_str() == "/inner"),
        "delegated dynamic authority must not fall back to the base realm",
    );
}

#[test]
fn shared_cross_site_link_is_retained_while_another_child_still_needs_it() {
    let link = RunLink {
        provider_site: "provider".to_string(),
        consumer_site: "consumer".to_string(),
        provider_component: "/provider".to_string(),
        provide: "api".to_string(),
        consumer_component: "/consumer-a".to_string(),
        slot: "api".to_string(),
        weak: false,
        protocol: NetworkProtocol::Http,
        export_name: "amber_export_shared".to_string(),
        external_slot_name: "amber_link_shared".to_string(),
    };
    let mut first = empty_live_child(0, "a", 1, ChildState::Live);
    first.overlays = vec![DynamicOverlayRecord {
        overlay_id: "a".to_string(),
        site_id: "consumer".to_string(),
        action: DynamicOverlayAction::ExternalSlot { link: link.clone() },
    }];
    let mut second = empty_live_child(0, "b", 2, ChildState::Live);
    second.overlays = vec![DynamicOverlayRecord {
        overlay_id: "b".to_string(),
        site_id: "consumer".to_string(),
        action: DynamicOverlayAction::ExternalSlot { link: link.clone() },
    }];
    let state = FrameworkControlState {
        schema: CONTROL_STATE_SCHEMA.to_string(),
        version: CONTROL_STATE_VERSION,
        run_id: "test".to_string(),
        base_scenario: ScenarioIr {
            schema: amber_scenario::SCENARIO_IR_SCHEMA.to_string(),
            version: amber_scenario::SCENARIO_IR_VERSION,
            root: 0,
            components: Vec::new(),
            bindings: Vec::new(),
            exports: Vec::new(),
            manifest_catalog: BTreeMap::new(),
        },
        run_links: Vec::new(),
        placement: FrozenPlacementState {
            offered_sites: BTreeMap::new(),
            defaults: PlacementDefaults::default(),
            standby_sites: Vec::new(),
            initial_active_sites: Vec::new(),
            dynamic_enabled_sites: Vec::new(),
            control_only_sites: Vec::new(),
            active_site_capabilities: BTreeMap::new(),
            placement_components: BTreeMap::new(),
            assignments: BTreeMap::new(),
        },
        generation: 0,
        next_child_id: 2,
        next_tx_id: 0,
        id_stride: 1,
        next_component_id: 0,
        dynamic_capability_signing_seed_b64: mesh_dynamic_caps::signing_seed_b64(
            &mesh_dynamic_caps::signing_key_from_seed(
                mesh_dynamic_caps::generate_dynamic_capability_signing_seed(),
            ),
        ),
        next_dynamic_capability_grant_id: 0,
        dynamic_capability_grants: BTreeMap::new(),
        dynamic_capability_grant_authority_sites: BTreeMap::new(),
        dynamic_capability_journal: Vec::new(),
        capability_instances: BTreeMap::new(),
        journal: Vec::new(),
        live_children: vec![first, second],
        pending_creates: Vec::new(),
        pending_destroys: Vec::new(),
    };

    assert!(
        link_still_required(&state, 1, &link),
        "retracting one child must keep a shared cross-site link in place for the survivor",
    );
    assert!(
        !link_still_required(
            &state,
            2,
            &RunLink {
                consumer_component: "/different".to_string(),
                ..link
            }
        ),
        "different links should not be retained accidentally",
    );
}

#[tokio::test]
async fn create_rejects_duplicate_names_and_destroy_is_idempotent() {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");
    write_file(
        &child_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["child"],
                network: { endpoints: [{ name: "out", port: 8080 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
    );
    write_file(
        &root_path,
        &format!(
            r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{ manifest: "{child}" }}
                  }},
                }}
                "#,
            child = file_url(&child_path),
        ),
    );

    let mut state = compile_control_state(&root_path).await;
    let state_path = dir.path().join("control-state.json");
    write_control_state(&state_path, &state).expect("state should write");
    let root_authority = state.base_scenario.root;

    create_child(
        &mut state,
        root_authority,
        CreateChildRequest {
            template: "worker".to_string(),
            name: "job".to_string(),
            manifest: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        },
        &state_path,
    )
    .await
    .expect("first create should succeed");

    let duplicate = create_child(
        &mut state,
        root_authority,
        CreateChildRequest {
            template: "worker".to_string(),
            name: "job".to_string(),
            manifest: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        },
        &state_path,
    )
    .await
    .expect_err("duplicate child name should be rejected");
    assert_eq!(duplicate.code, ProtocolErrorCode::NameConflict);

    destroy_child(&mut state, root_authority, "job", &state_path)
        .await
        .expect("first destroy should succeed");
    destroy_child(&mut state, root_authority, "job", &state_path)
        .await
        .expect("destroy should be idempotent once the child is gone");
    assert!(
        state.live_children.is_empty(),
        "destroy should remove the child"
    );
}

#[tokio::test]
async fn create_aborts_and_destroys_partially_published_child_when_publish_fails() {
    let (dir, state, state_path) = compile_exact_template_control_state().await;
    let authority_realm_id = state.base_scenario.root;
    let base_app = test_control_state_app(&dir, state, state_path);
    let runtime = Arc::new(FailingPublishRuntime::default());
    let app = with_runtime(&base_app, runtime.clone());

    let err = execute_create_child(
        &app,
        authority_realm_id,
        CreateChildRequest {
            template: "worker".to_string(),
            name: "broken".to_string(),
            manifest: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        },
    )
    .await
    .expect_err("publish failure should abort the create");
    assert_eq!(err.0.code, ProtocolErrorCode::PublishFailed);
    assert!(
        err.0.message.contains("publish exploded"),
        "publish failure should preserve the underlying detail, got: {}",
        err.0.message
    );

    let state = app.control_state.lock().await.clone();
    assert!(
        state.pending_creates.is_empty(),
        "failed publish cleanup must remove the pending create"
    );
    assert!(
        state
            .live_children
            .iter()
            .all(|child| child.name != "broken"),
        "failed publish cleanup must not leave a live child behind"
    );
    assert_eq!(
        state.journal.last().map(|entry| entry.state),
        Some(ChildState::CreateAborted),
        "failed publish cleanup must record an aborted transaction"
    );

    let destroy_calls = runtime
        .destroy_calls
        .lock()
        .expect("destroy call log mutex should lock")
        .clone();
    assert_eq!(
        destroy_calls.len(),
        1,
        "failed publish cleanup must destroy the prepared site-local child"
    );
    assert_eq!(destroy_calls[0].0, 1);
    assert_eq!(
        Some(destroy_calls[0].1.as_str()),
        Some("direct_local"),
        "failed publish cleanup must reconcile the child site back to the desired plan",
    );
}

#[tokio::test]
async fn max_live_children_is_scoped_per_template() {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    write_file(
        &root_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: { path: "/bin/echo", args: ["root"] },
              slots: {
                realm: { kind: "component", optional: true }
              }
            }
            "#,
    );

    let mut state = compile_control_state(&root_path).await;
    let root_authority = state.base_scenario.root;
    let mut alpha_child = empty_live_child(root_authority, "job-a", 1, ChildState::Live);
    alpha_child.template_name = Some("alpha".to_string());
    state.live_children = vec![alpha_child];

    let template = ChildTemplate {
        manifests: Some(vec!["file:///templates/worker.json5".to_string()]),
        config: BTreeMap::new(),
        bindings: BTreeMap::new(),
        visible_exports: None,
        limits: Some(amber_scenario::ChildTemplateLimits {
            max_live_children: Some(1),
            name_pattern: None,
        }),
        possible_backends: Vec::new(),
    };

    validate_template_limits(&state, root_authority, "beta", "job-c", &template)
        .expect("beta should still have capacity when only alpha is full");

    let err = validate_template_limits(&state, root_authority, "alpha", "job-c", &template)
        .expect_err("second alpha child should hit the per-template limit");
    assert_eq!(err.code, ProtocolErrorCode::NameConflict);
    assert!(
        err.message.contains("template `alpha`"),
        "error should name the saturated template, got: {}",
        err.message
    );
}

#[tokio::test]
async fn snapshot_is_stable_across_dynamic_create_order() {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");
    write_file(
        &child_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["child"],
                network: { endpoints: [{ name: "out", port: 8080, protocol: "http" }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
    );
    write_file(
        &root_path,
        &format!(
            r#"
                {{
                  manifest_version: "0.3.0",
                  program: {{ path: "/bin/echo", args: ["root"] }},
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{ manifest: "{child}" }}
                  }},
                }}
                "#,
            child = file_url(&child_path),
        ),
    );
    let placement = PlacementFile {
        schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
        version: amber_compiler::run_plan::PLACEMENT_VERSION,
        sites: BTreeMap::from([
            (
                "direct_a".to_string(),
                SiteDefinition {
                    kind: SiteKind::Direct,
                    context: None,
                },
            ),
            (
                "direct_b".to_string(),
                SiteDefinition {
                    kind: SiteKind::Direct,
                    context: None,
                },
            ),
        ]),
        defaults: PlacementDefaults {
            path: Some("direct_a".to_string()),
            ..PlacementDefaults::default()
        },
        components: BTreeMap::from([
            ("/job-a".to_string(), "direct_a".to_string()),
            ("/job-b".to_string(), "direct_b".to_string()),
        ]),
        dynamic_capabilities: None,
        framework_children: None,
    };
    let mut state_a = compile_control_state_with_placement(&root_path, Some(&placement)).await;
    let mut state_b = compile_control_state_with_placement(&root_path, Some(&placement)).await;
    let state_path_a = dir.path().join("control-state-a.json");
    let state_path_b = dir.path().join("control-state-b.json");
    write_control_state(&state_path_a, &state_a).expect("state A should write");
    write_control_state(&state_path_b, &state_b).expect("state B should write");
    let root_authority = state_a.base_scenario.root;

    for (state, state_path, names) in [
        (&mut state_a, &state_path_a, ["job-a", "job-b"]),
        (&mut state_b, &state_path_b, ["job-b", "job-a"]),
    ] {
        for name in names {
            create_child(
                state,
                root_authority,
                CreateChildRequest {
                    template: "worker".to_string(),
                    name: name.to_string(),
                    manifest: None,
                    config: BTreeMap::new(),
                    bindings: BTreeMap::new(),
                },
                state_path,
            )
            .await
            .unwrap_or_else(|err| panic!("create {name} should succeed: {err:?}"));
        }
    }

    let snapshot_a = snapshot(&state_a, root_authority).expect("snapshot A should succeed");
    let snapshot_b = snapshot(&state_b, root_authority).expect("snapshot B should succeed");
    assert_eq!(
        snapshot_a.scenario, snapshot_b.scenario,
        "snapshot scenario should be normalized independent of create order",
    );
    assert_eq!(
        snapshot_a.placement, snapshot_b.placement,
        "snapshot placement should be normalized independent of create order",
    );
}

#[tokio::test]
async fn create_rejects_unoffered_backend_without_committing_child_state() {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let direct_child_path = dir.path().join("child-direct.json5");
    let compose_child_path = dir.path().join("child-compose.json5");
    write_file(
        &direct_child_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["direct-only"],
                network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
    );
    write_file(
        &compose_child_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: {
                image: "busybox:1.36.1",
                entrypoint: ["/bin/sh", "-c", "sleep 1"],
                network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
    );
    write_file(
        &root_path,
        &format!(
            r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{
                      manifest: ["{compose_child}", "{direct_child}"]
                    }}
                  }},
                }}
                "#,
            compose_child = file_url(&compose_child_path),
            direct_child = file_url(&direct_child_path),
        ),
    );
    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let output = compiler
        .compile(
            ManifestRef::from_url(
                Url::from_file_path(&root_path).expect("root path should convert to URL"),
            ),
            CompileOptions::default(),
        )
        .await
        .expect("fixture should compile");
    let compiled = CompiledScenario::from_compile_output(&output)
        .expect("fixture should materialize compiled scenario");
    let placement = PlacementFile {
        schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
        version: amber_compiler::run_plan::PLACEMENT_VERSION,
        sites: BTreeMap::from([(
            "compose_local".to_string(),
            SiteDefinition {
                kind: SiteKind::Compose,
                context: None,
            },
        )]),
        defaults: PlacementDefaults {
            image: Some("compose_local".to_string()),
            ..PlacementDefaults::default()
        },
        components: BTreeMap::new(),
        dynamic_capabilities: None,
        framework_children: None,
    };
    let err = build_run_plan(&compiled, Some(&placement))
        .expect_err("run planning should reject future direct children without a direct site");
    let message = err.to_string();
    assert!(
        message.contains("program.path"),
        "placement failure should point operators at the missing future direct site, got {message}"
    );
}

#[tokio::test]
async fn concurrent_same_name_creates_serialize_to_one_live_child() {
    let (dir, state, state_path) = compile_exact_template_control_state().await;
    let root_authority = state.base_scenario.root;
    let app = test_control_state_app(&dir, state, state_path);
    let request = CreateChildRequest {
        template: "worker".to_string(),
        name: "job".to_string(),
        manifest: None,
        config: BTreeMap::new(),
        bindings: BTreeMap::new(),
    };

    let (left, right) = tokio::join!(
        execute_create_child(&app, root_authority, request.clone()),
        execute_create_child(&app, root_authority, request),
    );
    let results = [left, right];
    assert_eq!(
        results.iter().filter(|result| result.is_ok()).count(),
        1,
        "exactly one racing create should succeed",
    );
    assert_eq!(
        results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .filter(|err| err.0.code == ProtocolErrorCode::NameConflict)
            .count(),
        1,
        "exactly one racing create should fail with name_conflict",
    );

    let state = app.control_state.lock().await.clone();
    assert_eq!(
        state.live_children.len(),
        1,
        "only one child should be committed"
    );
    assert_eq!(state.live_children[0].name, "job");
    let snapshot_response =
        snapshot(&state, root_authority).expect("snapshot should succeed after the race");
    let scenario_ir: ScenarioIr = serde_json::from_value(snapshot_response.scenario)
        .expect("snapshot scenario should decode");
    assert_eq!(
        scenario_ir
            .components
            .iter()
            .filter(|component| component.moniker == "/job")
            .count(),
        1,
        "snapshot should remain clean after the same-name race",
    );
}

#[tokio::test]
async fn concurrent_distinct_creates_commit_both_children() {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");
    write_file(
        &child_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: {
                image: "busybox:1.36.1",
                entrypoint: ["/bin/sh", "-c", "sleep 1"],
                network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
    );
    write_file(
        &root_path,
        &format!(
            r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{ manifest: "{child}" }}
                  }},
                }}
                "#,
            child = file_url(&child_path),
        ),
    );
    let placement = PlacementFile {
        schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
        version: amber_compiler::run_plan::PLACEMENT_VERSION,
        sites: BTreeMap::from([(
            "compose_local".to_string(),
            SiteDefinition {
                kind: SiteKind::Compose,
                context: None,
            },
        )]),
        defaults: PlacementDefaults {
            image: Some("compose_local".to_string()),
            ..PlacementDefaults::default()
        },
        components: BTreeMap::new(),
        dynamic_capabilities: None,
        framework_children: None,
    };
    let state = compile_control_state_with_placement(&root_path, Some(&placement)).await;
    let state_path = dir.path().join("control-state.json");
    write_control_state(&state_path, &state).expect("state should write");
    let root_authority = state.base_scenario.root;
    let app = test_control_state_app(&dir, state, state_path);

    let (left, right) = tokio::join!(
        execute_create_child(
            &app,
            root_authority,
            CreateChildRequest {
                template: "worker".to_string(),
                name: "job-a".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
        ),
        execute_create_child(
            &app,
            root_authority,
            CreateChildRequest {
                template: "worker".to_string(),
                name: "job-b".to_string(),
                manifest: None,
                config: BTreeMap::new(),
                bindings: BTreeMap::new(),
            },
        ),
    );
    left.expect("first distinct create should succeed");
    right.expect("second distinct create should succeed");

    let state = app.control_state.lock().await.clone();
    assert_eq!(
        state.live_children.len(),
        2,
        "both children should be committed"
    );
    assert_eq!(
        state
            .live_children
            .iter()
            .map(|child| child.name.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["job-a", "job-b"]),
    );
    let snapshot_response =
        snapshot(&state, root_authority).expect("snapshot should succeed after both creates");
    let scenario_ir: ScenarioIr = serde_json::from_value(snapshot_response.scenario)
        .expect("snapshot scenario should decode");
    assert!(
        scenario_ir
            .components
            .iter()
            .any(|component| component.moniker == "/job-a"),
        "snapshot should contain the first child",
    );
    assert!(
        scenario_ir
            .components
            .iter()
            .any(|component| component.moniker == "/job-b"),
        "snapshot should contain the second child",
    );
}

#[tokio::test]
async fn prepare_child_record_uses_frozen_dynamic_placement_assignments() {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");
    write_file(
        &child_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: {
                image: "busybox:1.36.1",
                entrypoint: ["/bin/sh", "-c", "sleep 1"],
                network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
    );
    write_file(
        &root_path,
        &format!(
            r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{ manifest: "{child}" }}
                  }},
                }}
                "#,
            child = file_url(&child_path),
        ),
    );

    let placement = PlacementFile {
        schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
        version: amber_compiler::run_plan::PLACEMENT_VERSION,
        sites: BTreeMap::from([
            (
                "compose_local".to_string(),
                SiteDefinition {
                    kind: SiteKind::Compose,
                    context: None,
                },
            ),
            (
                "kind_local".to_string(),
                SiteDefinition {
                    kind: SiteKind::Kubernetes,
                    context: None,
                },
            ),
        ]),
        defaults: PlacementDefaults {
            image: Some("compose_local".to_string()),
            ..PlacementDefaults::default()
        },
        components: BTreeMap::from([("/job".to_string(), "kind_local".to_string())]),
        dynamic_capabilities: None,
        framework_children: None,
    };

    let mut state = compile_control_state_with_placement(&root_path, Some(&placement)).await;
    let root_authority = state.base_scenario.root;
    let child = prepare_child_record(
        &mut state,
        root_authority,
        &CreateChildRequest {
            template: "worker".to_string(),
            name: "job".to_string(),
            manifest: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        },
    )
    .await
    .expect("child should plan successfully");

    assert_eq!(
        child.assignments.get("/job").map(String::as_str),
        Some("kind_local"),
        "dynamic create must honor frozen placement entries for future child monikers",
    );
}

#[tokio::test]
async fn prepare_child_record_rejects_cross_site_dynamic_fragments() {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child-compose.json5");
    let child_root_path = dir.path().join("child-compose-root.json5");
    let direct_helper_path = dir.path().join("direct-helper.json5");
    let kind_helper_path = dir.path().join("kind-helper.json5");
    let vm_helper_path = dir.path().join("vm-helper.json5");
    let vm_helper_root_path = dir.path().join("vm-helper-root.json5");

    write_file(
        &direct_helper_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/sh",
                args: ["-c", "sleep 1"],
                network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
    );
    write_file(
        &kind_helper_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: {
                image: "busybox:1.36.1",
                entrypoint: ["/bin/sh", "-c", "sleep 1"],
                network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
    );
    write_file(
        &vm_helper_root_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: {
                vm: {
                  image: "/tmp/base.img",
                  cpus: 1,
                  memory_mib: 256,
                  cloud_init: {
                    user_data: "IyBjbG91ZC1jb25maWcK"
                  },
                  network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
                }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
    );
    write_file(
        &vm_helper_path,
        &format!(
            r##"
                {{
                  manifest_version: "0.3.0",
                  components: {{
                    root: "{vm_helper_root}"
                  }},
                  exports: {{
                    http: "#root.http"
                  }}
                }}
                "##,
            vm_helper_root = file_url(&vm_helper_root_path),
        ),
    );
    write_file(
        &child_root_path,
        r#"
            {
              manifest_version: "0.3.0",
              slots: {
                direct: { kind: "http" },
                kind: { kind: "http" },
                vm: { kind: "http" }
              },
              program: {
                image: "busybox:1.36.1",
                entrypoint: ["/bin/sh", "-c", "sleep 1"],
                env: {
                  DIRECT_URL: "${slots.direct.url}",
                  KIND_URL: "${slots.kind.url}",
                  VM_URL: "${slots.vm.url}"
                },
                network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
              },
              provides: { http: { kind: "http", endpoint: "http" } },
              exports: { http: "provides.http" },
            }
            "#,
    );
    write_file(
        &child_path,
        &format!(
            r##"
                {{
                  manifest_version: "0.3.0",
                  components: {{
                    direct_helper: "{direct_helper}",
                    kind_helper: "{kind_helper}",
                    root: "{child_root}",
                    vm_helper: "{vm_helper}"
                  }},
                  bindings: [
                    {{ from: "#kind_helper.http", to: "#root.kind" }},
                    {{ from: "#direct_helper.http", to: "#root.direct" }},
                    {{ from: "#vm_helper.http", to: "#root.vm" }}
                  ],
                  exports: {{
                    direct_http: "#direct_helper.http",
                    http: "#root.http",
                    kind_http: "#kind_helper.http",
                    vm_http: "#vm_helper.http"
                  }}
                }}
                "##,
            direct_helper = file_url(&direct_helper_path),
            kind_helper = file_url(&kind_helper_path),
            child_root = file_url(&child_root_path),
            vm_helper = file_url(&vm_helper_path),
        ),
    );
    write_file(
        &root_path,
        &format!(
            r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    child_compose: {{ manifest: "{child}" }}
                  }},
                }}
                "#,
            child = file_url(&child_path),
        ),
    );

    let placement = PlacementFile {
        schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
        version: amber_compiler::run_plan::PLACEMENT_VERSION,
        sites: BTreeMap::from([
            (
                "compose_local".to_string(),
                SiteDefinition {
                    kind: SiteKind::Compose,
                    context: None,
                },
            ),
            (
                "direct_local".to_string(),
                SiteDefinition {
                    kind: SiteKind::Direct,
                    context: None,
                },
            ),
            (
                "kind_local".to_string(),
                SiteDefinition {
                    kind: SiteKind::Kubernetes,
                    context: None,
                },
            ),
            (
                "vm_local".to_string(),
                SiteDefinition {
                    kind: SiteKind::Vm,
                    context: None,
                },
            ),
        ]),
        defaults: PlacementDefaults {
            image: Some("compose_local".to_string()),
            path: Some("direct_local".to_string()),
            vm: Some("vm_local".to_string()),
        },
        components: BTreeMap::from([
            ("/job-compose/root".to_string(), "compose_local".to_string()),
            (
                "/job-compose/kind_helper".to_string(),
                "kind_local".to_string(),
            ),
            (
                "/job-compose/direct_helper".to_string(),
                "direct_local".to_string(),
            ),
            ("/job-compose/vm_helper".to_string(), "vm_local".to_string()),
        ]),
        dynamic_capabilities: None,
        framework_children: None,
    };

    let mut state = compile_control_state_with_placement(&root_path, Some(&placement)).await;
    let root_authority = state.base_scenario.root;
    let err = prepare_child_record(
        &mut state,
        root_authority,
        &CreateChildRequest {
            template: "child_compose".to_string(),
            name: "job-compose".to_string(),
            manifest: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        },
    )
    .await
    .expect_err("site controllers must reject dynamic children that span multiple sites");
    assert_eq!(err.code, ProtocolErrorCode::PlacementUnsatisfied);
    assert!(
        err.message.contains("spans multiple sites"),
        "cross-site dynamic child placement should be rejected explicitly, got: {}",
        err.message
    );
}

#[tokio::test]
async fn describe_template_exposes_dynamic_child_exports_as_binding_candidates() {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let producer_path = dir.path().join("producer.json5");
    let consumer_path = dir.path().join("consumer.json5");
    write_file(
        &producer_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["producer"],
                network: { endpoints: [{ name: "out", port: 8080 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
    );
    write_file(
        &consumer_path,
        r#"
            {
              manifest_version: "0.3.0",
              slots: {
                upstream: { kind: "http" }
              },
              program: {
                path: "/bin/echo",
                args: ["consumer", "${slots.upstream.url}"]
              },
            }
            "#,
    );
    write_file(
        &root_path,
        &format!(
            r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    producer: {{ manifest: "{producer}" }},
                    consumer: {{ manifest: "{consumer}" }}
                  }},
                }}
                "#,
            producer = file_url(&producer_path),
            consumer = file_url(&consumer_path),
        ),
    );

    let mut state = compile_control_state(&root_path).await;
    let state_path = dir.path().join("control-state.json");
    write_control_state(&state_path, &state).expect("state should write");
    let root_authority = state.base_scenario.root;

    create_child(
        &mut state,
        root_authority,
        CreateChildRequest {
            template: "producer".to_string(),
            name: "source".to_string(),
            manifest: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        },
        &state_path,
    )
    .await
    .expect("producer child should be created");

    let authored =
        describe_template(&state, root_authority, "consumer").expect("template should exist");
    assert!(
        authored.bindings.is_empty(),
        "authored inspection should not invent unresolved binding fields",
    );

    let description = resolve_template(
        &state,
        root_authority,
        "consumer",
        TemplateResolveRequest { manifest: None },
    )
    .await
    .expect("exact template should resolve without an explicit manifest");
    let upstream = description
        .bindings
        .get("upstream")
        .expect("consumer should expose the upstream binding");
    assert_eq!(upstream.state, InputState::Open);
    assert!(
        upstream
            .candidates
            .iter()
            .any(|candidate| candidate == "children.source.exports.out"),
        "dynamic child exports should enter the authority realm bindable source set"
    );
}

#[tokio::test]
async fn describe_template_exposes_static_child_exports_as_binding_candidates() {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let provider_path = dir.path().join("provider.json5");
    let consumer_path = dir.path().join("consumer.json5");
    write_file(
        &provider_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/echo",
                args: ["provider"],
                network: { endpoints: [{ name: "out", port: 8080 }] }
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { out: "provides.out" },
            }
            "#,
    );
    write_file(
        &consumer_path,
        r#"
            {
              manifest_version: "0.3.0",
              slots: {
                upstream: { kind: "http" }
              },
              program: {
                path: "/bin/echo",
                args: ["consumer", "${slots.upstream.url}"]
              },
            }
            "#,
    );
    write_file(
        &root_path,
        &format!(
            r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  components: {{
                    provider: "{provider}"
                  }},
                  child_templates: {{
                    consumer: {{ manifest: "{consumer}" }}
                  }},
                }}
                "#,
            provider = file_url(&provider_path),
            consumer = file_url(&consumer_path),
        ),
    );

    let state = compile_control_state(&root_path).await;
    let authored = describe_template(&state, state.base_scenario.root, "consumer")
        .expect("template should exist");
    assert!(
        authored.bindings.is_empty(),
        "authored inspection should not expose unresolved binding fields",
    );

    let description = resolve_template(
        &state,
        state.base_scenario.root,
        "consumer",
        TemplateResolveRequest { manifest: None },
    )
    .await
    .expect("exact template should resolve without an explicit manifest");
    let upstream = description
        .bindings
        .get("upstream")
        .expect("consumer should expose the upstream binding");
    assert_eq!(upstream.state, InputState::Open);
    assert!(
        upstream
            .candidates
            .iter()
            .any(|candidate| candidate == "children.provider.exports.out"),
        "static child exports should enter the authority realm bindable source set"
    );
}

#[tokio::test]
async fn root_external_bindable_sources_are_listed_and_weak() {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let worker_path = dir.path().join("worker.json5");
    write_file(
        &worker_path,
        r#"
            {
              manifest_version: "0.3.0",
              slots: {
                catalog_api: { kind: "http" }
              },
              program: {
                path: "/bin/echo",
                args: ["worker", "${slots.catalog_api.url}"]
              }
            }
            "#,
    );
    write_file(
        &root_path,
        &format!(
            r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }},
                    catalog_api: {{ kind: "http" }}
                  }},
                  program: {{
                    path: "/bin/echo",
                    args: ["root"]
                  }},
                  child_templates: {{
                    worker: {{
                      manifest: "{worker}"
                    }}
                  }}
                }}
                "#,
            worker = file_url(&worker_path),
        ),
    );

    let state = compile_control_state(&root_path).await;
    let scenario = Scenario::try_from(state.base_scenario.clone()).expect("base scenario");
    let candidates =
        bindable_source_candidates(&scenario, &state.base_scenario, &state, scenario.root)
            .expect("candidates");
    let external = candidates
        .iter()
        .find(|candidate| candidate.selector == "external.catalog_api")
        .expect("root external source should be listed");
    assert_eq!(external.sources.len(), 1);
    assert!(
        external.sources[0].weak,
        "root external bindable sources must remain weak because they depend on the external site"
    );
}

#[tokio::test]
async fn bounded_template_rejects_manifest_outside_frozen_allowed_set() {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let alpha_path = dir.path().join("alpha.json5");
    let beta_path = dir.path().join("beta.json5");
    let gamma_path = dir.path().join("gamma.json5");
    for (path, label) in [
        (&alpha_path, "alpha"),
        (&beta_path, "beta"),
        (&gamma_path, "gamma"),
    ] {
        write_file(
            path,
            &format!(
                r#"
                    {{
                      manifest_version: "0.3.0",
                      program: {{ path: "/bin/echo", args: ["{label}"] }},
                    }}
                    "#
            ),
        );
    }
    write_file(
        &root_path,
        &format!(
            r#"
                {{
                  manifest_version: "0.3.0",
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{
                      manifest: ["{alpha}", "{beta}"]
                    }}
                  }},
                }}
                "#,
            alpha = file_url(&alpha_path),
            beta = file_url(&beta_path),
        ),
    );

    let mut state = compile_control_state(&root_path).await;
    let state_path = dir.path().join("control-state.json");
    write_control_state(&state_path, &state).expect("state should write");
    let root_authority = state.base_scenario.root;

    let err = create_child(
        &mut state,
        root_authority,
        CreateChildRequest {
            template: "worker".to_string(),
            name: "job".to_string(),
            manifest: Some(file_url(&gamma_path).parse().expect("manifest ref")),
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        },
        &state_path,
    )
    .await
    .expect_err("unexpected manifest selection should be rejected");
    assert_eq!(err.code, ProtocolErrorCode::ManifestNotAllowed);
}

#[tokio::test]
async fn execute_create_child_write_failure_rolls_back_authoritative_state() {
    let (dir, state, _) = compile_exact_template_control_state().await;
    let bad_state_path = dir.path().join("control-state-dir");
    fs::create_dir_all(&bad_state_path).expect("bad state path should exist as a directory");
    let root_authority = state.base_scenario.root;
    let app = test_control_state_app(&dir, state, bad_state_path);

    let err = execute_create_child(
        &app,
        root_authority,
        CreateChildRequest {
            template: "worker".to_string(),
            name: "job".to_string(),
            manifest: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        },
    )
    .await
    .expect_err("create should fail when control-state writes fail");
    assert_eq!(err.0.code, ProtocolErrorCode::ControlStateUnavailable);

    let recovered = app.control_state.lock().await.clone();
    assert!(
        recovered.live_children.is_empty(),
        "failed create must not leave an in-memory child record behind"
    );
    assert!(
        recovered.journal.is_empty(),
        "failed create must not append durable journal entries in memory"
    );
}

#[tokio::test]
async fn execute_destroy_child_write_failure_preserves_live_state() {
    let (dir, mut state, state_path) = compile_exact_template_control_state().await;
    let root_authority = state.base_scenario.root;
    create_child(
        &mut state,
        root_authority,
        CreateChildRequest {
            template: "worker".to_string(),
            name: "job".to_string(),
            manifest: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        },
        &state_path,
    )
    .await
    .expect("setup create should succeed");

    let bad_state_path = dir.path().join("control-state-dir");
    fs::create_dir_all(&bad_state_path).expect("bad state path should exist as a directory");
    let app = test_control_state_app(&dir, state, bad_state_path);

    let err = execute_destroy_child(&app, root_authority, "job")
        .await
        .expect_err("destroy should fail when control-state writes fail");
    assert_eq!(err.0.code, ProtocolErrorCode::ControlStateUnavailable);

    let recovered = app.control_state.lock().await.clone();
    let live_child = recovered
        .live_children
        .iter()
        .find(|child| child.name == "job")
        .expect("failed destroy must keep the live child present");
    assert_eq!(live_child.state, ChildState::Live);
}

#[tokio::test]
async fn execute_destroy_child_resumes_pending_destroy_transactions() {
    let (dir, mut state, state_path) = compile_empty_control_state().await;
    let root_authority = state.base_scenario.root;
    state.pending_destroys.push(pending_destroy(
        1,
        empty_live_child(root_authority, "doomed", 1, ChildState::DestroyRequested),
    ));
    write_control_state(&state_path, &state).expect("state should write");
    let app = test_control_state_app(&dir, state, state_path);

    execute_destroy_child(&app, root_authority, "doomed")
        .await
        .expect("destroy should resume the pending transaction");

    let recovered = app.control_state.lock().await.clone();
    assert!(
        recovered.pending_destroys.is_empty(),
        "resumed destroy should consume pending destroy state"
    );
    let states = recovered
        .journal
        .iter()
        .map(|entry| entry.state)
        .collect::<Vec<_>>();
    assert!(
        states.contains(&ChildState::DestroyRetracted),
        "resumed destroy should continue the existing transaction"
    );
    assert_eq!(states.last().copied(), Some(ChildState::DestroyCommitted));
}

#[tokio::test]
async fn describe_template_returns_authored_prefills_only() {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let worker_path = dir.path().join("worker.json5");
    write_file(
        &worker_path,
        r#"
            {
              manifest_version: "0.3.0",
              slots: {
                realm: { kind: "component", optional: true }
              },
              program: {
                path: "/bin/echo",
                args: ["worker", "${slots.realm.url}"]
              }
            }
            "#,
    );
    write_file(
        &root_path,
        &format!(
            r#"
                {{
                  manifest_version: "0.3.0",
                  program: {{ path: "/bin/echo", args: ["root"] }},
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    worker: {{
                      manifest: "{worker}",
                      bindings: {{
                        realm: "slots.realm"
                      }},
                      limits: {{
                        max_live_children: 2
                      }}
                    }}
                  }},
                }}
                "#,
            worker = file_url(&worker_path),
        ),
    );

    let state = compile_control_state(&root_path).await;
    let description = describe_template(&state, state.base_scenario.root, "worker")
        .expect("template should exist");
    assert_eq!(description.manifest.mode, TemplateMode::Exact);
    let manifest = description
        .manifest
        .manifest
        .expect("exact template should expose its manifest ref");
    assert_eq!(
        manifest
            .url
            .as_url()
            .expect("manifest url should be absolute")
            .as_str(),
        file_url(&worker_path)
    );
    assert!(
        manifest.digest.is_some(),
        "authored exact template refs should surface the frozen digest",
    );
    assert_eq!(
        description.bindings.get("realm"),
        Some(&BindingInputDescription {
            state: InputState::Prefilled,
            selector: Some("slots.realm".to_string()),
            optional: None,
            compatible_kind: None,
            candidates: Vec::new(),
        })
    );
    assert!(description.config.is_empty());
    assert_eq!(description.limits.max_live_children, Some(2));
}

#[tokio::test]
async fn recover_control_state_aborts_create_requested_children() {
    let (dir, mut state, state_path) = compile_empty_control_state().await;
    let root_authority = state.base_scenario.root;
    state.pending_creates.push(pending_create(
        1,
        empty_live_child(root_authority, "requested", 1, ChildState::CreateRequested),
    ));
    write_control_state(&state_path, &state).expect("state should write");
    let app = test_control_state_app(&dir, state, state_path);

    recover_control_state(&app)
        .await
        .expect("recovery should succeed");

    let recovered = app.control_state.lock().await.clone();
    assert!(
        recovered.live_children.is_empty(),
        "create_requested recovery should discard the stale child"
    );
    assert!(
        recovered.pending_creates.is_empty(),
        "create_requested recovery should clear pending create state"
    );
    assert_eq!(
        recovered.journal.last().map(|entry| entry.state),
        Some(ChildState::CreateAborted)
    );
}

#[tokio::test]
async fn recover_control_state_aborts_create_prepared_children() {
    let (dir, mut state, state_path) = compile_empty_control_state().await;
    let root_authority = state.base_scenario.root;
    state.pending_creates.push(pending_create(
        1,
        empty_live_child(root_authority, "prepared", 1, ChildState::CreatePrepared),
    ));
    write_control_state(&state_path, &state).expect("state should write");
    let app = test_control_state_app(&dir, state, state_path);

    recover_control_state(&app)
        .await
        .expect("recovery should succeed");

    let recovered = app.control_state.lock().await.clone();
    assert!(
        recovered.live_children.is_empty(),
        "create_prepared recovery should remove the child"
    );
    assert!(
        recovered.pending_creates.is_empty(),
        "create_prepared recovery should clear pending create state"
    );
    assert_eq!(
        recovered.journal.last().map(|entry| entry.state),
        Some(ChildState::CreateAborted)
    );
}

#[tokio::test]
async fn recover_control_state_surfaces_create_prepared_rollback_failures() {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    write_file(
        &root_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: { path: "/bin/echo", args: ["root"] },
            }
            "#,
    );
    let placement = PlacementFile {
        schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
        version: amber_compiler::run_plan::PLACEMENT_VERSION,
        sites: BTreeMap::from([(
            "direct_local".to_string(),
            SiteDefinition {
                kind: SiteKind::Direct,
                context: None,
            },
        )]),
        defaults: PlacementDefaults {
            path: Some("direct_local".to_string()),
            ..PlacementDefaults::default()
        },
        components: BTreeMap::new(),
        dynamic_capabilities: None,
        framework_children: None,
    };
    let mut state = compile_control_state_with_placement(&root_path, Some(&placement)).await;
    let state_path = dir.path().join("control-state.json");
    let root_authority = state.base_scenario.root;
    let app = with_runtime(
        &test_control_state_app(&dir, state.clone(), state_path.clone()),
        Arc::new(FailingRollbackRuntime),
    );
    state.pending_creates.push(pending_create(
        1,
        empty_live_child(root_authority, "prepared", 1, ChildState::CreatePrepared),
    ));
    write_control_state(&state_path, &state).expect("state should write");
    *app.control_state.lock().await = state;

    let err = recover_control_state(&app)
        .await
        .expect_err("recovery should fail when prepared rollback fails");
    let message = err.to_string();
    assert!(
        message.contains("failed to rollback prepared child `prepared`"),
        "error should identify the blocked transaction, got: {message}"
    );

    let recovered = app.control_state.lock().await.clone();
    assert_eq!(
        recovered.pending_creates.len(),
        1,
        "failed recovery must retain the prepared child transaction"
    );
    assert!(
        recovered.journal.is_empty(),
        "failed rollback must not pretend the child was aborted"
    );
}

#[tokio::test]
async fn recover_control_state_promotes_create_committed_hidden_children_to_live() {
    let (dir, mut state, state_path) = compile_exact_template_control_state().await;
    let root_authority = state.base_scenario.root;
    let mut child = prepare_child_record(
        &mut state,
        root_authority,
        &CreateChildRequest {
            template: "worker".to_string(),
            name: "hidden".to_string(),
            manifest: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        },
    )
    .await
    .expect("child should plan successfully");
    child.state = ChildState::CreateCommittedHidden;
    state.pending_creates.push(pending_create(1, child));
    write_control_state(&state_path, &state).expect("state should write");
    let app = test_control_state_app(&dir, state, state_path);

    recover_control_state(&app)
        .await
        .expect("recovery should succeed");

    let recovered = app.control_state.lock().await.clone();
    assert_eq!(
        recovered
            .live_children
            .iter()
            .find(|child| child.name == "hidden")
            .map(|child| child.state),
        Some(ChildState::Live)
    );
    assert!(
        recovered.pending_creates.is_empty(),
        "create_committed_hidden recovery should consume pending create state"
    );
    assert_eq!(
        recovered.journal.last().map(|entry| entry.state),
        Some(ChildState::Live)
    );
}

#[tokio::test]
async fn recover_control_state_does_not_republish_live_children() {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    write_file(
        &root_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: { path: "/bin/echo", args: ["root"] },
            }
            "#,
    );
    let placement = PlacementFile {
        schema: amber_compiler::run_plan::PLACEMENT_SCHEMA.to_string(),
        version: amber_compiler::run_plan::PLACEMENT_VERSION,
        sites: BTreeMap::from([(
            "direct_local".to_string(),
            SiteDefinition {
                kind: SiteKind::Direct,
                context: None,
            },
        )]),
        defaults: PlacementDefaults {
            path: Some("direct_local".to_string()),
            ..PlacementDefaults::default()
        },
        components: BTreeMap::new(),
        dynamic_capabilities: None,
        framework_children: None,
    };
    let mut state = compile_control_state_with_placement(&root_path, Some(&placement)).await;
    let state_path = dir.path().join("control-state.json");
    let root_authority = state.base_scenario.root;
    state.live_children.push(LiveChildRecord {
        child_id: 1,
        authority_realm_id: root_authority,
        name: "live".to_string(),
        state: ChildState::Live,
        template_name: Some("worker".to_string()),
        selected_manifest_catalog_key: None,
        fragment: None,
        input_bindings: Vec::new(),
        assignments: BTreeMap::new(),
        overlay_ids: Vec::new(),
        overlays: Vec::new(),
        outputs: BTreeMap::new(),
    });
    write_control_state(&state_path, &state).expect("state should write");
    let runtime = Arc::new(RecordingPublishRuntime::default());
    let app = with_runtime(
        &test_control_state_app(&dir, state, state_path),
        runtime.clone(),
    );

    recover_control_state(&app)
        .await
        .expect("recovery should leave live children alone");

    assert!(
        runtime
            .publish_calls
            .lock()
            .expect("publish call log mutex should lock")
            .is_empty(),
        "live recovery should not call publish again",
    );
    let recovered = app.control_state.lock().await.clone();
    assert_eq!(recovered.live_children.len(), 1);
    assert_eq!(recovered.live_children[0].name, "live");
    assert_eq!(recovered.live_children[0].state, ChildState::Live);
    assert!(
        recovered.journal.is_empty(),
        "live recovery should not append synthetic journal entries",
    );
}

#[tokio::test]
async fn recover_control_state_completes_destroy_requested_children() {
    let (dir, mut state, state_path) = compile_empty_control_state().await;
    let root_authority = state.base_scenario.root;
    state.pending_destroys.push(pending_destroy(
        1,
        empty_live_child(root_authority, "doomed", 1, ChildState::DestroyRequested),
    ));
    write_control_state(&state_path, &state).expect("state should write");
    let app = test_control_state_app(&dir, state, state_path);

    recover_control_state(&app)
        .await
        .expect("recovery should succeed");

    let recovered = app.control_state.lock().await.clone();
    assert!(
        recovered.live_children.is_empty(),
        "destroy_requested recovery should commit the removal"
    );
    assert!(
        recovered.pending_destroys.is_empty(),
        "destroy_requested recovery should clear pending destroy state"
    );
    let states = recovered
        .journal
        .iter()
        .map(|entry| entry.state)
        .collect::<Vec<_>>();
    assert!(
        states.contains(&ChildState::DestroyRetracted),
        "recovery should retract bindings before commit"
    );
    assert_eq!(states.last().copied(), Some(ChildState::DestroyCommitted));
}

#[tokio::test]
async fn recover_control_state_completes_destroy_retracted_children() {
    let (dir, mut state, state_path) = compile_empty_control_state().await;
    let root_authority = state.base_scenario.root;
    state.pending_destroys.push(pending_destroy(
        1,
        empty_live_child(root_authority, "retracted", 1, ChildState::DestroyRetracted),
    ));
    write_control_state(&state_path, &state).expect("state should write");
    let app = test_control_state_app(&dir, state, state_path);

    recover_control_state(&app)
        .await
        .expect("recovery should succeed");

    let recovered = app.control_state.lock().await.clone();
    assert!(
        recovered.live_children.is_empty(),
        "destroy_retracted recovery should commit the removal"
    );
    assert!(
        recovered.pending_destroys.is_empty(),
        "destroy_retracted recovery should clear pending destroy state"
    );
    assert_eq!(
        recovered.journal.last().map(|entry| entry.state),
        Some(ChildState::DestroyCommitted)
    );
}

#[tokio::test]
async fn dynamic_capabilities_derive_distinct_binding_roots_per_live_holder() {
    let state = compile_dynamic_caps_binding_state().await;
    let live = decode_live_scenario(&state).expect("live scenario should decode");
    let roots = super::dynamic_caps::derive_root_authorities(&state).expect("roots should derive");
    assert!(
        roots.values().any(|root| {
            root.selector
                == RootAuthoritySelectorIr::Binding {
                    consumer_component_id: "components./alice".to_string(),
                    slot_name: "upstream".to_string(),
                    provider_component_id: "components./provider".to_string(),
                    provider_capability_name: "http".to_string(),
                }
        }),
        "alice should hold a binding-derived root authority; live components: {live:#?}; roots: \
         {roots:#?}"
    );
    assert!(
        roots.values().any(|root| {
            root.selector
                == RootAuthoritySelectorIr::Binding {
                    consumer_component_id: "components./bob".to_string(),
                    slot_name: "upstream".to_string(),
                    provider_component_id: "components./provider".to_string(),
                    provider_capability_name: "http".to_string(),
                }
        }),
        "bob should hold an independent binding-derived root authority; live components: \
         {live:#?}; roots: {roots:#?}"
    );
}

#[tokio::test]
async fn dynamic_capabilities_derive_external_slot_roots_for_cross_site_bindings() {
    let mut state = compile_dynamic_caps_binding_state().await;
    let external_slot_name = "amber_link_test".to_string();
    state.run_links = vec![RunLink {
        provider_site: "direct_a".to_string(),
        consumer_site: "direct_b".to_string(),
        provider_component: "/provider".to_string(),
        provide: "http".to_string(),
        consumer_component: "/alice".to_string(),
        slot: "upstream".to_string(),
        weak: false,
        protocol: NetworkProtocol::Http,
        export_name: "amber_export_test".to_string(),
        external_slot_name: external_slot_name.clone(),
    }];
    let roots = super::dynamic_caps::derive_root_authorities(&state).expect("roots should derive");

    assert!(
        roots.values().any(|root| {
            root.selector
                == RootAuthoritySelectorIr::ExternalSlotBinding {
                    consumer_component_id: "components./alice".to_string(),
                    slot_name: "upstream".to_string(),
                    external_slot_component_id: "components./provider".to_string(),
                    external_slot_name: external_slot_name.clone(),
                }
        }),
        "cross-site binding should derive an external-slot-backed root authority; run links: \
         {:#?}; roots: {roots:#?}",
        state.run_links,
    );
}

#[tokio::test]
async fn dynamic_capabilities_grant_graph_obeys_distinct_idempotent_noop_and_revocation_rules() {
    let mut state = compile_dynamic_caps_binding_state().await;
    let alice_root = super::dynamic_caps::source_key_from_held_id(
        &state,
        "components./alice",
        &root_held_id_for(&state, "components./alice"),
    )
    .expect("alice root source should resolve");

    let first = super::dynamic_caps::share_dynamic_capability(
        &mut state,
        "components./alice",
        &alice_root,
        "components./carol",
        None,
        &serde_json::Value::Null,
    )
    .expect("first share should succeed");
    let second = super::dynamic_caps::share_dynamic_capability(
        &mut state,
        "components./alice",
        &alice_root,
        "components./carol",
        None,
        &serde_json::Value::Null,
    )
    .expect("second distinct share should succeed");
    let (grant_a, ref_a) = match first {
        super::dynamic_caps::DynamicCapabilityShareOutcome::Created { grant_id, r#ref } => {
            (grant_id, r#ref)
        }
        other => panic!("unexpected first share outcome: {other:?}"),
    };
    let grant_b = match second {
        super::dynamic_caps::DynamicCapabilityShareOutcome::Created { grant_id, .. } => grant_id,
        other => panic!("unexpected second share outcome: {other:?}"),
    };
    assert_ne!(
        grant_a, grant_b,
        "shares without idempotency must stay distinct"
    );

    let idempotent_created = super::dynamic_caps::share_dynamic_capability(
        &mut state,
        "components./alice",
        &alice_root,
        "components./dave",
        Some("share-dave"),
        &serde_json::Value::Null,
    )
    .expect("idempotent create should succeed");
    let (grant_c, ref_c) = match idempotent_created {
        super::dynamic_caps::DynamicCapabilityShareOutcome::Created { grant_id, r#ref } => {
            (grant_id, r#ref)
        }
        other => panic!("unexpected idempotent create outcome: {other:?}"),
    };
    let idempotent_repeat = super::dynamic_caps::share_dynamic_capability(
        &mut state,
        "components./alice",
        &alice_root,
        "components./dave",
        Some("share-dave"),
        &serde_json::Value::Null,
    )
    .expect("idempotent repeat should succeed");
    match idempotent_repeat {
        super::dynamic_caps::DynamicCapabilityShareOutcome::Deduplicated { grant_id, r#ref } => {
            assert_eq!(grant_id, grant_c);
            assert_eq!(r#ref, ref_c);
        }
        other => panic!("unexpected idempotent repeat outcome: {other:?}"),
    }

    match super::dynamic_caps::share_dynamic_capability(
        &mut state,
        "components./alice",
        &alice_root,
        "components./alice",
        None,
        &serde_json::Value::Null,
    )
    .expect("self share should resolve as a no-op")
    {
        super::dynamic_caps::DynamicCapabilityShareOutcome::Noop { reason } => {
            assert_eq!(reason, "recipient_already_has_authority");
        }
        other => panic!("unexpected self-share outcome: {other:?}"),
    }

    let grant_d = match super::dynamic_caps::share_dynamic_capability(
        &mut state,
        "components./carol",
        &super::dynamic_caps::DynamicCapabilitySourceKey::Grant(grant_a.clone()),
        "components./eve",
        None,
        &serde_json::Value::Null,
    )
    .expect("re-share without prior materialization should succeed")
    {
        super::dynamic_caps::DynamicCapabilityShareOutcome::Created { grant_id, .. } => grant_id,
        other => panic!("unexpected re-share outcome: {other:?}"),
    };

    match super::dynamic_caps::share_dynamic_capability(
        &mut state,
        "components./carol",
        &super::dynamic_caps::DynamicCapabilitySourceKey::Grant(grant_a.clone()),
        "components./alice",
        None,
        &serde_json::Value::Null,
    )
    .expect("share back to an ancestor should become a no-op")
    {
        super::dynamic_caps::DynamicCapabilityShareOutcome::Noop { reason } => {
            assert_eq!(reason, "recipient_already_has_authority");
        }
        other => panic!("unexpected ancestor-share outcome: {other:?}"),
    }

    let revoked = super::dynamic_caps::revoke_dynamic_capability(
        &mut state,
        "components./alice",
        &super::dynamic_caps::DynamicCapabilitySourceKey::Grant(grant_a.clone()),
    )
    .expect("ancestor revoke should succeed");
    assert_eq!(
        revoked.revoked_grant_ids,
        vec![grant_a.clone(), grant_d.clone()],
        "revocation must remove the target subtree only"
    );
    assert_eq!(
        delegated_entry_for(&state, "components./carol", &grant_a)
            .summary
            .state,
        HeldEntryState::Revoked
    );
    assert_eq!(
        delegated_entry_for(&state, "components./eve", &grant_d)
            .summary
            .state,
        HeldEntryState::Revoked
    );
    assert_eq!(
        delegated_entry_for(&state, "components./carol", &grant_b)
            .summary
            .state,
        HeldEntryState::Live,
        "independent sibling grant must remain live"
    );
    assert_eq!(
        delegated_entry_for(&state, "components./dave", &grant_c)
            .summary
            .state,
        HeldEntryState::Live,
        "independent idempotent branch must remain live"
    );

    let grant_e = match super::dynamic_caps::share_dynamic_capability(
        &mut state,
        "components./alice",
        &alice_root,
        "components./carol",
        None,
        &serde_json::Value::Null,
    )
    .expect("reacquisition after revoke should create a fresh grant")
    {
        super::dynamic_caps::DynamicCapabilityShareOutcome::Created { grant_id, .. } => grant_id,
        other => panic!("unexpected reacquisition outcome: {other:?}"),
    };
    assert_ne!(
        grant_e, grant_a,
        "reacquisition must not resurrect the dead grant"
    );
    assert_eq!(
        delegated_entry_for(&state, "components./carol", &grant_a)
            .summary
            .state,
        HeldEntryState::Revoked
    );
    assert_eq!(
        delegated_entry_for(&state, "components./carol", &grant_e)
            .summary
            .state,
        HeldEntryState::Live
    );

    let inspect = super::dynamic_caps::inspect_dynamic_ref(&state, "components./carol", &ref_a)
        .expect_err("revoked refs must fail inspection");
    assert_eq!(inspect.code, ProtocolErrorCode::RevokedRef);
}

#[tokio::test]
async fn dynamic_capabilities_external_root_revokes_descendants_without_killing_root() {
    let mut state = compile_dynamic_caps_external_root_state().await;
    let alice_root_held_id = root_held_id_for(&state, "components./alice");
    let alice_root = super::dynamic_caps::source_key_from_held_id(
        &state,
        "components./alice",
        &alice_root_held_id,
    )
    .expect("external root source should resolve");
    let grant_id = match super::dynamic_caps::share_dynamic_capability(
        &mut state,
        "components./alice",
        &alice_root,
        "components./bob",
        None,
        &serde_json::Value::Null,
    )
    .expect("external root share should succeed")
    {
        super::dynamic_caps::DynamicCapabilityShareOutcome::Created { grant_id, .. } => grant_id,
        other => panic!("unexpected external-root share outcome: {other:?}"),
    };

    super::dynamic_caps::revoke_dynamic_capability(
        &mut state,
        "components./alice",
        &super::dynamic_caps::DynamicCapabilitySourceKey::Grant(grant_id.clone()),
    )
    .expect("external-root descendant revoke should succeed");

    let root_detail =
        super::dynamic_caps::held_entry_detail(&state, "components./alice", &alice_root_held_id)
            .expect("external root should remain inspectable");
    assert_eq!(root_detail.summary.entry_kind, HeldEntryKind::RootAuthority);
    assert_eq!(root_detail.summary.state, HeldEntryState::Live);
    assert_eq!(
        delegated_entry_for(&state, "components./bob", &grant_id)
            .summary
            .state,
        HeldEntryState::Revoked
    );
}

#[tokio::test]
async fn dynamic_capabilities_reconcile_revokes_descendants_in_same_pass() {
    let mut state = compile_dynamic_caps_binding_state().await;
    let alice_root = super::dynamic_caps::source_key_from_held_id(
        &state,
        "components./alice",
        &root_held_id_for(&state, "components./alice"),
    )
    .expect("alice root source should resolve");
    let grant_to_carol = match super::dynamic_caps::share_dynamic_capability(
        &mut state,
        "components./alice",
        &alice_root,
        "components./carol",
        None,
        &serde_json::Value::Null,
    )
    .expect("share to carol should succeed")
    {
        super::dynamic_caps::DynamicCapabilityShareOutcome::Created { grant_id, .. } => grant_id,
        other => panic!("unexpected share outcome: {other:?}"),
    };
    let grant_to_eve = match super::dynamic_caps::share_dynamic_capability(
        &mut state,
        "components./carol",
        &super::dynamic_caps::DynamicCapabilitySourceKey::Grant(grant_to_carol.clone()),
        "components./eve",
        None,
        &serde_json::Value::Null,
    )
    .expect("share to eve should succeed")
    {
        super::dynamic_caps::DynamicCapabilityShareOutcome::Created { grant_id, .. } => grant_id,
        other => panic!("unexpected re-share outcome: {other:?}"),
    };

    let carol = state
        .base_scenario
        .components
        .iter_mut()
        .find(|component| component.moniker == "/carol")
        .expect("carol component should exist");
    carol.program = None;

    super::dynamic_caps::reconcile_dynamic_capability_grants(&mut state)
        .expect("reconcile should succeed");

    assert_eq!(
        delegated_entry_for(&state, "components./carol", &grant_to_carol)
            .summary
            .state,
        HeldEntryState::Revoked
    );
    let eve_entry = delegated_entry_for(&state, "components./eve", &grant_to_eve);
    assert_eq!(eve_entry.summary.state, HeldEntryState::Revoked);
    assert_eq!(
        eve_entry.revocation_reason.as_deref(),
        Some("ancestor_revoked"),
        "descendants should be revoked in the same reconcile pass as their dead ancestor"
    );
}

#[tokio::test]
async fn dynamic_capabilities_snapshot_replay_restores_live_grants_and_rejects_old_refs() {
    let mut state = compile_dynamic_caps_binding_state().await;
    let alice_root = super::dynamic_caps::source_key_from_held_id(
        &state,
        "components./alice",
        &root_held_id_for(&state, "components./alice"),
    )
    .expect("alice root source should resolve");
    let (grant_id, old_ref) = match super::dynamic_caps::share_dynamic_capability(
        &mut state,
        "components./alice",
        &alice_root,
        "components./carol",
        None,
        &serde_json::Value::Null,
    )
    .expect("share should succeed")
    {
        super::dynamic_caps::DynamicCapabilityShareOutcome::Created { grant_id, r#ref } => {
            (grant_id, r#ref)
        }
        other => panic!("unexpected share outcome: {other:?}"),
    };

    let snapshot = snapshot(&state, state.base_scenario.root).expect("snapshot should build");
    assert!(
        snapshot.dynamic_capabilities.is_object(),
        "snapshot must include the dynamic capabilities artifact"
    );

    let replayed = compile_control_state_from_snapshot_with_run_id(&snapshot, "replay-run").await;
    let replayed_held = held_entries_for(&replayed, "components./carol");
    assert!(
        replayed_held
            .iter()
            .any(|entry| entry.entry_kind == HeldEntryKind::DelegatedGrant
                && entry.state == HeldEntryState::Live),
        "replay must rebuild holder inventory for live delegated grants"
    );

    let old_ref_error =
        super::dynamic_caps::inspect_dynamic_ref(&replayed, "components./carol", &old_ref)
            .expect_err("old-run refs must fail after replay");
    assert_eq!(old_ref_error.code, ProtocolErrorCode::MalformedRef);
    assert!(
        old_ref_error.message.contains("different run"),
        "old source-run refs should be rejected by run id"
    );

    assert_eq!(
        delegated_entry_for(&state, "components./carol", &grant_id)
            .summary
            .state,
        HeldEntryState::Live,
        "source state should remain live before replay-specific invalidation checks"
    );
}

#[tokio::test]
async fn dynamic_capabilities_snapshot_replay_restores_descendants_independent_of_order() {
    let mut state = compile_dynamic_caps_binding_state().await;
    let alice_root = super::dynamic_caps::source_key_from_held_id(
        &state,
        "components./alice",
        &root_held_id_for(&state, "components./alice"),
    )
    .expect("alice root source should resolve");
    let grant_to_carol = match super::dynamic_caps::share_dynamic_capability(
        &mut state,
        "components./alice",
        &alice_root,
        "components./carol",
        None,
        &serde_json::Value::Null,
    )
    .expect("share to carol should succeed")
    {
        super::dynamic_caps::DynamicCapabilityShareOutcome::Created { grant_id, .. } => grant_id,
        other => panic!("unexpected share outcome: {other:?}"),
    };
    match super::dynamic_caps::share_dynamic_capability(
        &mut state,
        "components./carol",
        &super::dynamic_caps::DynamicCapabilitySourceKey::Grant(grant_to_carol.clone()),
        "components./bob",
        None,
        &serde_json::Value::Null,
    )
    .expect("share to bob should succeed")
    {
        super::dynamic_caps::DynamicCapabilityShareOutcome::Created { .. } => {}
        other => panic!("unexpected re-share outcome: {other:?}"),
    };

    let snapshot = snapshot(&state, state.base_scenario.root).expect("snapshot should build");
    let replayed = compile_control_state_from_snapshot_with_run_id(&snapshot, "replay-run").await;

    let replayed_bob = held_entries_for(&replayed, "components./bob");
    assert!(
        replayed_bob
            .iter()
            .any(|entry| entry.entry_kind == HeldEntryKind::DelegatedGrant
                && entry.state == HeldEntryState::Live),
        "replay should restore descendant grants even when child holders sort before parents"
    );
    let replayed_grants = replayed
        .dynamic_capability_grants
        .values()
        .filter(|grant| grant.live)
        .collect::<Vec<_>>();
    let replayed_parent = replayed_grants
        .iter()
        .find(|grant| grant.holder_component_id == "components./carol")
        .expect("replayed parent grant should exist");
    let replayed_child = replayed_grants
        .iter()
        .find(|grant| grant.holder_component_id == "components./bob")
        .expect("replayed child grant should exist");
    assert_eq!(
        replayed_child.parent_grant_id.as_deref(),
        Some(replayed_parent.grant_id.as_str())
    );
}

#[tokio::test]
async fn dynamic_capabilities_materialization_resolution_reports_revoked_refs() {
    let mut state = compile_dynamic_caps_binding_state().await;
    let alice_root = super::dynamic_caps::source_key_from_held_id(
        &state,
        "components./alice",
        &root_held_id_for(&state, "components./alice"),
    )
    .expect("alice root source should resolve");
    let grant_id = match super::dynamic_caps::share_dynamic_capability(
        &mut state,
        "components./alice",
        &alice_root,
        "components./carol",
        None,
        &serde_json::Value::Null,
    )
    .expect("share should succeed")
    {
        super::dynamic_caps::DynamicCapabilityShareOutcome::Created { grant_id, .. } => grant_id,
        other => panic!("unexpected share outcome: {other:?}"),
    };
    super::dynamic_caps::revoke_dynamic_capability(
        &mut state,
        "components./carol",
        &super::dynamic_caps::DynamicCapabilitySourceKey::Grant(grant_id.clone()),
    )
    .expect("self revoke should succeed");

    let err = super::dynamic_caps::resolve_dynamic_materialization_source(
        &state,
        "components./carol",
        &super::dynamic_caps::DynamicCapabilitySourceKey::Grant(grant_id),
    )
    .expect_err("revoked materialization sources must fail");
    assert_eq!(err.code, ProtocolErrorCode::RevokedRef);
}

#[tokio::test]
async fn dynamic_capabilities_inspect_ref_rejects_unsupported_token_versions() {
    let mut state = compile_dynamic_caps_binding_state().await;
    let alice_root = super::dynamic_caps::source_key_from_held_id(
        &state,
        "components./alice",
        &root_held_id_for(&state, "components./alice"),
    )
    .expect("alice root source should resolve");
    let grant_id = match super::dynamic_caps::share_dynamic_capability(
        &mut state,
        "components./alice",
        &alice_root,
        "components./carol",
        None,
        &serde_json::Value::Null,
    )
    .expect("share should succeed")
    {
        super::dynamic_caps::DynamicCapabilityShareOutcome::Created { grant_id, .. } => grant_id,
        other => panic!("unexpected share outcome: {other:?}"),
    };
    let signing_key =
        mesh_dynamic_caps::signing_key_from_seed_b64(&state.dynamic_capability_signing_seed_b64)
            .expect("test signing key should decode");
    let unsupported_ref = mesh_dynamic_caps::build_dynamic_capability_ref_url(
        DynamicCapabilityRefClaims {
            version: mesh_dynamic_caps::DYNAMIC_CAPS_REF_VERSION + 1,
            run_id: state.run_id.clone(),
            grant_id,
            holder_component_id: "components./carol".to_string(),
            descriptor_hint: Some("provider.http".to_string()),
        },
        &signing_key,
        "/",
        None,
        None,
    )
    .expect("unsupported-version ref should build");

    let err =
        super::dynamic_caps::inspect_dynamic_ref(&state, "components./carol", &unsupported_ref)
            .expect_err("unsupported ref versions must be rejected");
    assert_eq!(err.code, ProtocolErrorCode::MalformedRef);
    assert!(err.message.contains("unsupported"));
}

#[test]
fn compose_site_controller_is_injected_as_a_compose_service() {
    let temp = TempDir::new().expect("tempdir should create");
    let artifact_root = temp.path().join("artifact");
    let site_state_root = temp.path().join("state").join("compose-site");
    fs::create_dir_all(&artifact_root).expect("artifact root should create");
    fs::create_dir_all(&site_state_root).expect("site state root should create");
    fs::write(
        artifact_root.join("compose.yaml"),
        r#"
services:
  amber-router:
    image: ghcr.io/rdi-foundation/amber-router:test
    volumes:
      - amber-router-control:/amber/control
  amber-router-control-init:
    image: busybox
  amber-provisioner:
    image: ghcr.io/rdi-foundation/amber-provisioner:test
networks:
  amber_mesh: {}
volumes:
  amber-router-control: {}
"#,
    )
    .expect("compose yaml should write");

    let plan = write_site_controller_plan(
        &site_controller_plan_path(&site_state_root),
        "test-run",
        "test-mesh",
        "compose-site",
        SiteKind::Compose,
        SocketAddr::from(([0, 0, 0, 0], SITE_CONTROLLER_PORT)),
        &format!("http://{SITE_CONTROLLER_SERVICE_NAME}:{SITE_CONTROLLER_PORT}"),
        "/site/compose-site/router",
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeMap::new(),
        Some("unix:///amber/control/router-control.sock"),
        Some("127.0.0.1:24000"),
        &site_state_root.join("site-controller-state.json"),
        temp.path(),
        &temp.path().join("state"),
        &site_state_root,
        &artifact_root,
        "test-auth",
        "test-verify-key",
        None,
        None,
        Some(24000),
        Some("amber_test_compose"),
        None,
        None,
        None,
        &BTreeMap::new(),
    )
    .expect("compose site controller plan should write");

    inject_compose_site_controller(
        &artifact_root,
        &plan,
        &site_controller_plan_path(&site_state_root),
        "ghcr.io/rdi-foundation/amber-site-controller:test",
    )
    .expect("compose controller should inject");

    let document: serde_yaml::Value = serde_yaml::from_str(
        &fs::read_to_string(artifact_root.join("compose.yaml")).expect("compose yaml should read"),
    )
    .expect("compose yaml should parse");
    let service = document["services"][SITE_CONTROLLER_SERVICE_NAME]
        .as_mapping()
        .expect("controller service should exist");
    assert_eq!(
        service
            .get(serde_yaml::Value::String("image".to_string()))
            .and_then(serde_yaml::Value::as_str),
        Some("ghcr.io/rdi-foundation/amber-site-controller:test")
    );
    let command = service
        .get(serde_yaml::Value::String("command".to_string()))
        .and_then(serde_yaml::Value::as_sequence)
        .expect("controller service should have a command");
    let plan_path = site_controller_plan_path(&site_state_root)
        .display()
        .to_string();
    assert_eq!(command[0].as_str(), Some("--plan"));
    assert_eq!(command[1].as_str(), Some(plan_path.as_str()));
    let volumes = service
        .get(serde_yaml::Value::String("volumes".to_string()))
        .and_then(serde_yaml::Value::as_sequence)
        .expect("controller service should mount volumes");
    let extra_hosts = service
        .get(serde_yaml::Value::String("extra_hosts".to_string()))
        .and_then(serde_yaml::Value::as_sequence)
        .expect("controller service should set extra_hosts");
    let healthcheck = service
        .get(serde_yaml::Value::String("healthcheck".to_string()))
        .and_then(serde_yaml::Value::as_mapping)
        .expect("controller service should define a healthcheck");
    assert!(volumes.iter().any(|value| {
        value.as_str()
            == Some(&format!(
                "{}:{}",
                temp.path().display(),
                temp.path().display()
            ))
    }));
    assert!(
        volumes
            .iter()
            .any(|value| value.as_str() == Some("amber-router-control:/amber/control"))
    );
    assert!(
        volumes
            .iter()
            .any(|value| value.as_str() == Some("/var/run/docker.sock:/var/run/docker.sock"))
    );
    assert!(
        extra_hosts
            .iter()
            .any(|value| value.as_str() == Some("host.docker.internal:host-gateway")),
        "compose site controller should resolve host.docker.internal inside the site network",
    );
    let healthcheck_test = healthcheck
        .get(serde_yaml::Value::String("test".to_string()))
        .and_then(serde_yaml::Value::as_sequence)
        .expect("controller healthcheck should define a test command");
    assert!(
        healthcheck_test.iter().any(|value| value
            .as_str()
            .is_some_and(|value| value.contains("/healthz"))),
        "compose site controller healthcheck should wait for the controller readiness endpoint",
    );
}

#[test]
fn kubernetes_site_controller_resources_are_injected_into_the_artifact() {
    let temp = TempDir::new().expect("tempdir should create");
    let artifact_root = temp.path().join("artifact");
    let site_state_root = temp.path().join("state").join("kube-site");
    fs::create_dir_all(artifact_root.join("05-networkpolicies"))
        .expect("network policies dir should create");
    fs::create_dir_all(site_state_root.clone()).expect("site state root should create");
    fs::write(
        artifact_root.join("kustomization.yaml"),
        "resources:\n  - 05-networkpolicies/amber-router-netpol.yaml\n",
    )
    .expect("kustomization should write");
    fs::write(
        artifact_root.join("05-networkpolicies/amber-router-netpol.yaml"),
        r#"
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: amber-router
spec:
  ingress: []
"#,
    )
    .expect("router netpol should write");
    fs::write(
        site_state_root.join("site-controller-state.json"),
        "{\"schema\":\"amber.test\",\"version\":1}",
    )
    .expect("controller state should write");
    fs::write(
        site_state_root.join("desired-links.json"),
        "{\"schema\":\"amber.test\",\"version\":1}",
    )
    .expect("desired links should write");

    let plan = write_site_controller_plan(
        &site_controller_plan_path(&site_state_root),
        "test-run",
        "test-mesh",
        "kube-site",
        SiteKind::Kubernetes,
        SocketAddr::from(([0, 0, 0, 0], SITE_CONTROLLER_PORT)),
        &format!("http://{SITE_CONTROLLER_SERVICE_NAME}:{SITE_CONTROLLER_PORT}"),
        "/site/kube-site/router",
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeMap::new(),
        Some("amber-router:24100"),
        Some("127.0.0.1:24000"),
        &site_state_root.join("site-controller-state.json"),
        temp.path(),
        &temp.path().join("state"),
        &site_state_root,
        &artifact_root,
        "test-auth",
        "test-verify-key",
        None,
        None,
        Some(24000),
        None,
        Some("amber-test-kube-site"),
        None,
        None,
        &BTreeMap::new(),
    )
    .expect("kubernetes site controller plan should write");

    inject_kubernetes_site_controller(
        &artifact_root,
        &plan,
        "ghcr.io/rdi-foundation/amber-site-controller:test",
    )
    .expect("kubernetes controller should inject");

    let kustomization = fs::read_to_string(artifact_root.join("kustomization.yaml"))
        .expect("kustomization should read");
    assert!(kustomization.contains("01-configmaps/amber-site-controller-seed.yaml"));
    assert!(kustomization.contains("03-deployments/amber-site-controller.yaml"));
    assert!(kustomization.contains("04-services/amber-site-controller.yaml"));

    let deployment =
        fs::read_to_string(artifact_root.join("03-deployments/amber-site-controller.yaml"))
            .expect("deployment should read");
    assert!(deployment.contains("amber-site-controller"));
    assert!(deployment.contains("ghcr.io/rdi-foundation/amber-site-controller:test"));
    assert!(deployment.contains("/amber/site/state/site-controller-plan.json"));

    let seed =
        fs::read_to_string(artifact_root.join("01-configmaps/amber-site-controller-seed.yaml"))
            .expect("seed configmap should read");
    assert!(seed.contains("site-controller-plan.json"));
    assert!(seed.contains("artifact.tar.b64"));
    assert!(seed.contains("http://amber-site-controller:4100"));

    let router_netpol =
        fs::read_to_string(artifact_root.join("05-networkpolicies/amber-router-netpol.yaml"))
            .expect("router netpol should read");
    assert!(router_netpol.contains("amber-site-controller"));
    assert!(router_netpol.contains("24100"));
}

#[test]
fn local_site_manager_state_uses_controller_plan_when_host_state_is_absent() {
    let temp = TempDir::new().expect("tempdir should create");
    let state_root = temp.path().join("state");
    let site_state_root = state_root.join("compose-site");
    fs::create_dir_all(&site_state_root).expect("site state root should create");
    let state = FrameworkControlState {
        schema: CONTROL_STATE_SCHEMA.to_string(),
        version: CONTROL_STATE_VERSION,
        run_id: "test-run".to_string(),
        base_scenario: ScenarioIr {
            schema: amber_scenario::SCENARIO_IR_SCHEMA.to_string(),
            version: amber_scenario::SCENARIO_IR_VERSION,
            root: 0,
            components: Vec::new(),
            bindings: Vec::new(),
            exports: Vec::new(),
            manifest_catalog: BTreeMap::new(),
        },
        run_links: Vec::new(),
        placement: FrozenPlacementState {
            offered_sites: BTreeMap::from([(
                "compose-site".to_string(),
                SiteDefinition {
                    kind: SiteKind::Compose,
                    context: None,
                },
            )]),
            defaults: PlacementDefaults::default(),
            standby_sites: Vec::new(),
            initial_active_sites: vec!["compose-site".to_string()],
            dynamic_enabled_sites: vec!["compose-site".to_string()],
            control_only_sites: Vec::new(),
            active_site_capabilities: BTreeMap::new(),
            placement_components: BTreeMap::new(),
            assignments: BTreeMap::new(),
        },
        generation: 0,
        next_child_id: 1,
        next_tx_id: 0,
        id_stride: 1,
        next_component_id: 0,
        capability_instances: BTreeMap::new(),
        journal: Vec::new(),
        dynamic_capability_signing_seed_b64: mesh_dynamic_caps::signing_seed_b64(
            &mesh_dynamic_caps::signing_key_from_seed(
                mesh_dynamic_caps::generate_dynamic_capability_signing_seed(),
            ),
        ),
        next_dynamic_capability_grant_id: 0,
        dynamic_capability_grants: BTreeMap::new(),
        dynamic_capability_grant_authority_sites: BTreeMap::new(),
        dynamic_capability_journal: Vec::new(),
        live_children: Vec::new(),
        pending_creates: Vec::new(),
        pending_destroys: Vec::new(),
    };
    let state_path = site_state_root.join("site-controller-state.json");
    write_json(&state_path, &state).expect("state should write");
    let mut app = test_control_state_app(&temp, state, state_path);
    fs::remove_file(site_state_path(&temp.path().join("state"), "compose-site"))
        .expect("host manager state should be removed for fallback test");
    let controller_plan = Arc::make_mut(&mut app.controller_plan);
    controller_plan.kind = SiteKind::Compose;
    controller_plan.compose_project = Some("amber_test_compose".to_string());
    controller_plan.local_router_control =
        Some("unix:///amber/control/router-control.sock".to_string());
    controller_plan.published_router_mesh_addr = Some("127.0.0.1:24000".to_string());
    controller_plan.authority_url =
        format!("http://{SITE_CONTROLLER_SERVICE_NAME}:{SITE_CONTROLLER_PORT}");

    let state = load_site_manager_state(&app, "compose-site")
        .expect("local controller should synthesize site metadata from its own plan");
    assert_eq!(state.status, "running");
    assert_eq!(
        state.router_control.as_deref(),
        Some("unix:///amber/control/router-control.sock")
    );
    assert_eq!(state.router_mesh_addr.as_deref(), Some("127.0.0.1:24000"));
    let authority_url = format!("http://{SITE_CONTROLLER_SERVICE_NAME}:{SITE_CONTROLLER_PORT}");
    assert_eq!(
        state.site_controller_url.as_deref(),
        Some(authority_url.as_str())
    );
}
