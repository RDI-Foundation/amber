use std::fs;

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
use reqwest::{Client, StatusCode};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use tempfile::TempDir;
use url::Url;

use super::{api::*, http::*, orchestration::*, planner::*, state::*, *};

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
            Ok((stream, _)) => return stream,
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
        components: BTreeMap::new(),
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
    let actuators = install_success_site_actuator(&app).await;

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
    for site_plan in &consumer.site_plans {
        assert_eq!(site_plan.routed_inputs.len(), 1);
        assert_eq!(site_plan.routed_inputs[0].component, "/consumer");
        assert_eq!(site_plan.routed_inputs[0].slot, "required_api");
        assert_eq!(site_plan.routed_inputs[0].provider_component, "/required");
        assert_eq!(site_plan.routed_inputs[0].protocol, "http");
        assert_eq!(site_plan.routed_inputs[0].capability_kind, "http");
        assert_eq!(
            site_plan.routed_inputs[0].target,
            DynamicInputRouteTarget::ComponentProvide {
                provide: "http".to_string()
            },
            "same-site child exports should reuse the provider component route instead of \
             inventing a synthetic dynamic-export hop",
        );
    }

    for actuator in actuators {
        actuator.abort();
    }
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
    let actuators = install_success_site_actuator(&app).await;

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
    for site_plan in &consumer.site_plans {
        assert_eq!(site_plan.routed_inputs.len(), 1);
        assert_eq!(site_plan.routed_inputs[0].component, "/consumer");
        assert_eq!(site_plan.routed_inputs[0].slot, "upstream");
        assert_eq!(site_plan.routed_inputs[0].provider_component, "/provider");
        assert_eq!(site_plan.routed_inputs[0].protocol, "http");
        assert_eq!(site_plan.routed_inputs[0].capability_kind, "http");
        assert_eq!(
            site_plan.routed_inputs[0].target,
            DynamicInputRouteTarget::ComponentProvide {
                provide: "http".to_string()
            },
            "same-site static child exports should reuse the provider component route",
        );
    }

    for actuator in actuators {
        actuator.abort();
    }
}

#[test]
fn framework_ccs_addressing_matches_site_runtime_topology() {
    assert_eq!(
        ccs_listen_addr_for_site(SiteKind::Direct, 41000),
        SocketAddr::from(([127, 0, 0, 1], 41000))
    );
    assert_eq!(
        ccs_url_for_site(SiteKind::Direct, 41000),
        "http://127.0.0.1:41000"
    );
    assert_eq!(
        ccs_listen_addr_for_site(SiteKind::Vm, 42000),
        SocketAddr::from(([127, 0, 0, 1], 42000))
    );
    assert_eq!(
        ccs_url_for_site(SiteKind::Vm, 42000),
        "http://127.0.0.1:42000"
    );
    assert_eq!(
        ccs_listen_addr_for_site(SiteKind::Compose, 43000),
        SocketAddr::from(([0, 0, 0, 0], 43000))
    );
    assert_eq!(
        ccs_url_for_site(SiteKind::Compose, 43000),
        "http://host.docker.internal:43000"
    );
    assert_eq!(
        ccs_listen_addr_for_site(SiteKind::Kubernetes, 44000),
        SocketAddr::from(([0, 0, 0, 0], 44000))
    );
    assert_eq!(
        ccs_url_for_site(SiteKind::Kubernetes, 44000),
        format!(
            "http://{}:44000",
            host_service_host_for_consumer(SiteKind::Kubernetes)
        )
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
    let state = compile_control_state(&root_path).await;
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
    let state = compile_control_state(&root_path).await;
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
                path: "/bin/echo",
                args: ["worker"],
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

    let state = compile_control_state(&root_path).await;
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
    LiveChildRecord {
        child_id,
        authority_realm_id,
        name: name.to_string(),
        state,
        template_name: Some("worker".to_string()),
        selected_manifest_catalog_key: None,
        fragment: None,
        input_bindings: Vec::new(),
        assignments: BTreeMap::new(),
        site_plans: Vec::new(),
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

fn test_control_state_app(
    dir: &TempDir,
    state: FrameworkControlState,
    state_path: PathBuf,
) -> ControlStateApp {
    let run_root = dir.path().join("run");
    let state_root = dir.path().join("state");
    fs::create_dir_all(&run_root).expect("run root should exist");
    fs::create_dir_all(&state_root).expect("state root should exist");
    ControlStateApp {
        control_state: Arc::new(Mutex::new(state)),
        client: ReqwestClient::new(),
        state_path,
        run_root,
        state_root,
        mesh_scope: Arc::<str>::from("test-mesh"),
        control_state_auth_token: Arc::<str>::from("test-control-state-auth"),
        authority_locks: Arc::new(Mutex::new(BTreeMap::new())),
        bridge_proxies: Arc::new(Mutex::new(BTreeMap::new())),
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
    let response = apply_headers(client.get(url), headers)
        .send()
        .await
        .unwrap_or_else(|err| panic!("send GET {url}: {err}"));
    let status = response.status();
    let body = response
        .text()
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
    let response = apply_headers(client.post(url), headers)
        .json(body)
        .send()
        .await
        .unwrap_or_else(|err| panic!("send POST {url}: {err}"));
    let status = response.status();
    let body = response
        .text()
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
    let response = apply_headers(client.post(url), headers)
        .send()
        .await
        .unwrap_or_else(|err| panic!("send POST {url}: {err}"));
    let status = response.status();
    let body = response
        .text()
        .await
        .unwrap_or_else(|err| panic!("read POST {url}: {err}"));
    assert_eq!(status, StatusCode::OK, "POST {url} failed: {body}");
    serde_json::from_str(&body)
        .unwrap_or_else(|err| panic!("decode POST {url} response: {err}; {body}"))
}

async fn http_delete_empty(client: &Client, url: &str, headers: &[(String, String)]) {
    let response = apply_headers(client.delete(url), headers)
        .send()
        .await
        .unwrap_or_else(|err| panic!("send DELETE {url}: {err}"));
    let status = response.status();
    let body = response
        .text()
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

struct TestMcpClient {
    client: Client,
    endpoint: String,
    session_id: String,
    headers: Vec<(String, String)>,
    next_id: u64,
}

impl TestMcpClient {
    async fn connect(base_url: &str, client_name: &str, headers: Vec<(String, String)>) -> Self {
        let client = Client::new();
        let endpoint = format!("{base_url}/mcp");
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
        let response = apply_headers(client.post(&endpoint), &headers)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .json(&initialize)
            .send()
            .await
            .expect("send initialize request");
        let status = response.status();
        let response_headers = response.headers().clone();
        let body = response.text().await.expect("read initialize response");
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

        let notification = apply_headers(client.post(&endpoint), &headers)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", &session_id)
            .json(&json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            }))
            .send()
            .await
            .expect("send initialized notification");
        assert_eq!(notification.status(), StatusCode::ACCEPTED);

        Self {
            client,
            endpoint,
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
        .send()
        .await
        .unwrap_or_else(|err| panic!("send MCP request {method}: {err}"));
        let status = response.status();
        let body = response
            .text()
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
    async fn start(with_actuators: bool) -> Self {
        let (dir, state, state_path, record) = compile_framework_binding_control_state().await;
        let app = test_control_state_app(&dir, state, state_path);
        let mut handles = if with_actuators {
            install_success_site_actuator(&app).await
        } else {
            Vec::new()
        };
        let control_router = Router::new()
            .route(CONTROL_SERVICE_PATH, get(get_control_state))
            .route("/v1/control-state/children", post(control_create_child))
            .route(
                "/v1/control-state/children/{child}/destroy",
                post(control_destroy_child),
            )
            .with_state(app.clone());
        let (control_state_url, control_handle) = spawn_test_router(control_router).await;
        handles.push(control_handle);

        let auth_token = "test-router-auth".to_string();
        let ccs_app = CcsApp {
            client: ReqwestClient::new(),
            site_state_root: app.state_root.clone(),
            control_state_url: Arc::<str>::from(control_state_url),
            router_auth_token: Arc::<str>::from(auth_token.clone()),
            control_state_auth_token: app.control_state_auth_token.clone(),
        };
        let ccs_router = Router::new()
            .nest_service("/mcp", mcp::service(ccs_app.clone()))
            .route("/v1/templates", get(ccs_list_templates))
            .route("/v1/templates/{template}", get(ccs_describe_template))
            .route(
                "/v1/templates/{template}/resolve",
                post(ccs_resolve_template),
            )
            .route(
                "/v1/children",
                get(ccs_list_children).post(ccs_create_child),
            )
            .route(
                "/v1/children/{child}",
                get(ccs_describe_child).delete(ccs_destroy_child),
            )
            .route("/v1/snapshot", post(ccs_snapshot))
            .with_state(ccs_app);
        let (base_url, ccs_handle) = spawn_test_router(ccs_router).await;
        handles.push(ccs_handle);

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
    assert!(
        help.contains("/mcp"),
        "help resource should explain the MCP endpoint path"
    );
}

#[tokio::test]
async fn framework_component_mcp_matches_http_surface() {
    let http = FrameworkMcpHarness::start(true).await;
    let mcp_harness = FrameworkMcpHarness::start(true).await;
    let mut mcp = mcp_harness.connect().await;
    let mut same_state_mcp = http.connect().await;

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
        let app = test_control_state_app(&dir, state, state_path);
        let mut handles = vec![install_dynamic_caps_origin_fixture(&app).await];
        let router = Router::new()
            .nest_service("/mcp", control_state_mcp::service(app.clone()))
            .route(
                "/v1/control-state/dynamic-caps/held",
                post(control_dynamic_held_list),
            )
            .route(
                "/v1/control-state/dynamic-caps/held/detail",
                post(control_dynamic_held_detail),
            )
            .route(
                "/v1/control-state/dynamic-caps/share",
                post(control_dynamic_share),
            )
            .route(
                "/v1/control-state/dynamic-caps/inspect-ref",
                post(control_dynamic_inspect_ref),
            )
            .route(
                "/v1/control-state/dynamic-caps/revoke",
                post(control_dynamic_revoke),
            )
            .route(
                "/v1/control-state/dynamic-caps/resolve-origin",
                post(control_dynamic_resolve_origin),
            )
            .with_state(app);
        let (base_url, handle) = spawn_test_router(router).await;
        handles.push(handle);
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
        TestMcpClient::connect(
            &self.base_url,
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
    let site_id = "direct_local";
    let site_state_root = Path::new(&app.state_root).join(site_id);
    let artifact_dir = site_state_root.join("artifact");
    let runtime_root = site_state_root.join("runtime");
    fs::create_dir_all(artifact_dir.join(".amber")).expect("artifact root should exist");
    fs::create_dir_all(&runtime_root).expect("runtime root should exist");

    let control_state_auth_token = app.control_state_auth_token.to_string();
    let publish_router = Router::new().route(
        "/v1/internal/dynamic-caps/origins/publish",
        post({
            let expected = control_state_auth_token.clone();
            move |headers: HeaderMap,
                  Json(request): Json<dynamic_caps::PublishDynamicCapabilityOriginRequest>| {
                let expected = expected.clone();
                async move {
                    assert_eq!(
                        headers
                            .get(FRAMEWORK_AUTH_HEADER)
                            .and_then(|value| value.to_str().ok()),
                        Some(expected.as_str()),
                        "origin publish should authenticate with the control-state token",
                    );
                    Json(dynamic_caps::PublishDynamicCapabilityOriginResponse {
                        route_id: request.route_id,
                        capability: "provider.http".to_string(),
                        protocol: "http".to_string(),
                    })
                }
            }
        }),
    );
    let (publish_base_url, publish_handle) = spawn_test_router(publish_router).await;
    let publish_addr = publish_base_url
        .strip_prefix("http://")
        .expect("publish base URL should be absolute HTTP")
        .parse()
        .expect("publish base URL should parse as socket address");

    write_json(
        &site_state_root.join("site-actuator-plan.json"),
        &SiteActuatorPlan {
            schema: "amber.run.site_actuator_plan".to_string(),
            version: 1,
            run_id: "test-run".to_string(),
            mesh_scope: "test-mesh".to_string(),
            run_root: app.run_root.display().to_string(),
            site_id: site_id.to_string(),
            kind: SiteKind::Direct,
            router_identity_id: "/router".to_string(),
            artifact_dir: artifact_dir.display().to_string(),
            site_state_root: site_state_root.display().to_string(),
            listen_addr: "127.0.0.1:0".parse().expect("listen addr"),
            storage_root: None,
            runtime_root: Some(runtime_root.display().to_string()),
            router_mesh_port: None,
            compose_project: None,
            kubernetes_namespace: None,
            context: None,
            observability_endpoint: None,
            launch_env: BTreeMap::new(),
        },
    )
    .expect("site actuator plan should write");
    write_json(
        &site_state_root.join("framework-ccs-plan.json"),
        &FrameworkCcsPlan {
            schema: CCS_PLAN_SCHEMA.to_string(),
            version: CCS_PLAN_VERSION,
            site_id: site_id.to_string(),
            site_state_root: site_state_root.display().to_string(),
            listen_addr: publish_addr,
            control_state_url: "http://127.0.0.1:0".to_string(),
            router_auth_token: "unused".to_string(),
            control_state_auth_token: control_state_auth_token.clone(),
        },
    )
    .expect("framework ccs plan should write");
    write_json(
        &site_state_root.join("manager-state.json"),
        &json!({
            "status": "running",
            "kind": SiteKind::Direct,
            "artifact_dir": artifact_dir.display().to_string(),
            "supervisor_pid": 1,
            "router_mesh_addr": "127.0.0.1:39001",
            "router_identity_id": "/router",
            "router_public_key_b64": "dGVzdC1yb3V0ZXIta2V5",
        }),
    )
    .expect("manager state should write");
    write_json(
        &site_state_root.join("site-actuator-state.json"),
        &json!({
            "schema": "amber.site_actuator_state",
            "version": 1,
            "run_id": "test-run",
            "site_id": site_id,
            "kind": SiteKind::Direct,
            "children": {},
        }),
    )
    .expect("site actuator state should write");
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
                "identity_id": "/router",
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
        &crate::direct_runtime::direct_runtime_state_path(&artifact_dir),
        &crate::direct_runtime::DirectRuntimeState {
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
            Vec::new(),
        )
        .mesh_config,
    )
    .expect("alice mesh config should write");
    write_json(
        &runtime_root.join("router-mesh.json"),
        &test_live_site_router(Vec::new()),
    )
    .expect("router mesh config should write");

    publish_handle
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
    assert!(
        help.contains("/v1/control-state/dynamic-caps"),
        "help resource should explain the HTTP endpoint family",
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
        .post_json("/v1/control-state/dynamic-caps/held", &held_list_request)
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
            "/v1/control-state/dynamic-caps/held/detail",
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
        .post_json("/v1/control-state/dynamic-caps/share", &share_request)
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
        .post_json("/v1/control-state/dynamic-caps/held", &carol_held_request)
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
            "/v1/control-state/dynamic-caps/inspect-ref",
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
            "/v1/control-state/dynamic-caps/resolve-origin",
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
        .post_json("/v1/control-state/dynamic-caps/revoke", &revoke_request)
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
            "/v1/control-state/dynamic-caps/held/detail",
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

async fn install_success_site_actuator(app: &ControlStateApp) -> Vec<tokio::task::JoinHandle<()>> {
    let offered_sites = {
        let state = app.control_state.lock().await;
        state
            .placement
            .offered_sites
            .iter()
            .map(|(site_id, site)| (site_id.clone(), site.kind))
            .collect::<Vec<_>>()
    };
    let mut handles = Vec::with_capacity(offered_sites.len());
    for (site_id, site_kind) in offered_sites {
        let site_state_root = Path::new(&app.state_root).join(&site_id);
        fs::create_dir_all(&site_state_root).expect("site state root should exist");
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("actuator listener");
        let listen_addr = listener.local_addr().expect("actuator addr");
        write_json(
            &site_state_root.join("site-actuator-plan.json"),
            &SiteActuatorPlan {
                schema: "amber.run.site_actuator_plan".to_string(),
                version: 1,
                run_id: "test-run".to_string(),
                mesh_scope: "test-mesh".to_string(),
                run_root: app.run_root.display().to_string(),
                site_id: site_id.clone(),
                kind: site_kind,
                router_identity_id: format!("/site/{site_id}/router"),
                artifact_dir: site_state_root.join("artifact").display().to_string(),
                site_state_root: site_state_root.display().to_string(),
                listen_addr,
                storage_root: None,
                runtime_root: None,
                router_mesh_port: None,
                compose_project: None,
                kubernetes_namespace: None,
                context: None,
                observability_endpoint: None,
                launch_env: BTreeMap::new(),
            },
        )
        .expect("site actuator plan should write");
        let app = Router::new()
            .route(
                "/v1/children/{child_id}/prepare",
                post(|| async { StatusCode::NO_CONTENT }),
            )
            .route(
                "/v1/children/{child_id}/rollback",
                post(|| async { StatusCode::NO_CONTENT }),
            )
            .route(
                "/v1/children/{child_id}/publish",
                post(|| async { StatusCode::NO_CONTENT }),
            )
            .route(
                "/v1/children/{child_id}/destroy",
                post(|| async { StatusCode::NO_CONTENT }),
            );
        handles.push(tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("site actuator should serve");
        }));
    }
    handles
}

async fn install_failing_rollback_site_actuator(
    app: &ControlStateApp,
) -> Vec<tokio::task::JoinHandle<()>> {
    let offered_sites = {
        let state = app.control_state.lock().await;
        state
            .placement
            .offered_sites
            .iter()
            .map(|(site_id, site)| (site_id.clone(), site.kind))
            .collect::<Vec<_>>()
    };
    let mut handles = Vec::with_capacity(offered_sites.len());
    for (site_id, site_kind) in offered_sites {
        let site_state_root = Path::new(&app.state_root).join(&site_id);
        fs::create_dir_all(&site_state_root).expect("site state root should exist");
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("actuator listener");
        let listen_addr = listener.local_addr().expect("actuator addr");
        write_json(
            &site_state_root.join("site-actuator-plan.json"),
            &SiteActuatorPlan {
                schema: "amber.run.site_actuator_plan".to_string(),
                version: 1,
                run_id: "test-run".to_string(),
                mesh_scope: "test-mesh".to_string(),
                run_root: app.run_root.display().to_string(),
                site_id: site_id.clone(),
                kind: site_kind,
                router_identity_id: format!("/site/{site_id}/router"),
                artifact_dir: site_state_root.join("artifact").display().to_string(),
                site_state_root: site_state_root.display().to_string(),
                listen_addr,
                storage_root: None,
                runtime_root: None,
                router_mesh_port: None,
                compose_project: None,
                kubernetes_namespace: None,
                context: None,
                observability_endpoint: None,
                launch_env: BTreeMap::new(),
            },
        )
        .expect("site actuator plan should write");
        let app = Router::new()
            .route(
                "/v1/children/{child_id}/prepare",
                post(|| async { StatusCode::NO_CONTENT }),
            )
            .route(
                "/v1/children/{child_id}/rollback",
                post(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
            )
            .route(
                "/v1/children/{child_id}/publish",
                post(|| async { StatusCode::NO_CONTENT }),
            )
            .route(
                "/v1/children/{child_id}/destroy",
                post(|| async { StatusCode::NO_CONTENT }),
            );
        handles.push(tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("site actuator should serve");
        }));
    }
    handles
}

async fn install_barrier_destroy_site_actuator(
    app: &ControlStateApp,
) -> (
    Vec<tokio::task::JoinHandle<()>>,
    tokio::sync::mpsc::UnboundedReceiver<String>,
    Arc<tokio::sync::Barrier>,
) {
    let offered_sites = {
        let state = app.control_state.lock().await;
        state
            .placement
            .offered_sites
            .iter()
            .map(|(site_id, site)| (site_id.clone(), site.kind))
            .collect::<Vec<_>>()
    };
    let barrier = Arc::new(tokio::sync::Barrier::new(offered_sites.len() + 1));
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let mut handles = Vec::with_capacity(offered_sites.len());
    for (site_id, site_kind) in offered_sites {
        let site_state_root = Path::new(&app.state_root).join(&site_id);
        fs::create_dir_all(&site_state_root).expect("site state root should exist");
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("actuator listener");
        let listen_addr = listener.local_addr().expect("actuator addr");
        write_json(
            &site_state_root.join("site-actuator-plan.json"),
            &SiteActuatorPlan {
                schema: "amber.run.site_actuator_plan".to_string(),
                version: 1,
                run_id: "test-run".to_string(),
                mesh_scope: "test-mesh".to_string(),
                run_root: app.run_root.display().to_string(),
                site_id: site_id.clone(),
                kind: site_kind,
                router_identity_id: format!("/site/{site_id}/router"),
                artifact_dir: site_state_root.join("artifact").display().to_string(),
                site_state_root: site_state_root.display().to_string(),
                listen_addr,
                storage_root: None,
                runtime_root: None,
                router_mesh_port: None,
                compose_project: None,
                kubernetes_namespace: None,
                context: None,
                observability_endpoint: None,
                launch_env: BTreeMap::new(),
            },
        )
        .expect("site actuator plan should write");
        let start_tx = tx.clone();
        let destroy_barrier = barrier.clone();
        let site_id_for_destroy = site_id.clone();
        let app = Router::new()
            .route(
                "/v1/children/{child_id}/prepare",
                post(|| async { StatusCode::NO_CONTENT }),
            )
            .route(
                "/v1/children/{child_id}/publish",
                post(|| async { StatusCode::NO_CONTENT }),
            )
            .route(
                "/v1/children/{child_id}/destroy",
                post(move || {
                    let start_tx = start_tx.clone();
                    let destroy_barrier = destroy_barrier.clone();
                    let site_id = site_id_for_destroy.clone();
                    async move {
                        start_tx
                            .send(site_id)
                            .expect("destroy start notification should send");
                        destroy_barrier.wait().await;
                        StatusCode::NO_CONTENT
                    }
                }),
            );
        handles.push(tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("site actuator should serve");
        }));
    }
    (handles, rx, barrier)
}

async fn install_barrier_publish_site_actuator(
    app: &ControlStateApp,
) -> (
    Vec<tokio::task::JoinHandle<()>>,
    tokio::sync::mpsc::UnboundedReceiver<String>,
    Arc<tokio::sync::Barrier>,
) {
    let offered_sites = {
        let state = app.control_state.lock().await;
        state
            .placement
            .offered_sites
            .iter()
            .map(|(site_id, site)| (site_id.clone(), site.kind))
            .collect::<Vec<_>>()
    };
    let barrier = Arc::new(tokio::sync::Barrier::new(offered_sites.len() + 1));
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let mut handles = Vec::with_capacity(offered_sites.len());
    for (site_id, site_kind) in offered_sites {
        let site_state_root = Path::new(&app.state_root).join(&site_id);
        fs::create_dir_all(&site_state_root).expect("site state root should exist");
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("actuator listener");
        let listen_addr = listener.local_addr().expect("actuator addr");
        write_json(
            &site_state_root.join("site-actuator-plan.json"),
            &SiteActuatorPlan {
                schema: "amber.run.site_actuator_plan".to_string(),
                version: 1,
                run_id: "test-run".to_string(),
                mesh_scope: "test-mesh".to_string(),
                run_root: app.run_root.display().to_string(),
                site_id: site_id.clone(),
                kind: site_kind,
                router_identity_id: format!("/site/{site_id}/router"),
                artifact_dir: site_state_root.join("artifact").display().to_string(),
                site_state_root: site_state_root.display().to_string(),
                listen_addr,
                storage_root: None,
                runtime_root: None,
                router_mesh_port: None,
                compose_project: None,
                kubernetes_namespace: None,
                context: None,
                observability_endpoint: None,
                launch_env: BTreeMap::new(),
            },
        )
        .expect("site actuator plan should write");
        let start_tx = tx.clone();
        let publish_barrier = barrier.clone();
        let site_id_for_publish = site_id.clone();
        let app = Router::new()
            .route(
                "/v1/children/{child_id}/prepare",
                post(|| async { StatusCode::NO_CONTENT }),
            )
            .route(
                "/v1/children/{child_id}/publish",
                post(move || {
                    let start_tx = start_tx.clone();
                    let publish_barrier = publish_barrier.clone();
                    let site_id = site_id_for_publish.clone();
                    async move {
                        start_tx
                            .send(site_id)
                            .expect("publish start notification should send");
                        publish_barrier.wait().await;
                        StatusCode::NO_CONTENT
                    }
                }),
            )
            .route(
                "/v1/children/{child_id}/destroy",
                post(|| async { StatusCode::NO_CONTENT }),
            );
        handles.push(tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("site actuator should serve");
        }));
    }
    (handles, rx, barrier)
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
        !replayed.live_children[0].site_plans.is_empty(),
        "replay should rebuild derived site plans from the restored child fragment",
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
        next_component_id: 0,
        dynamic_capability_signing_seed_b64: mesh_dynamic_caps::signing_seed_b64(
            &mesh_dynamic_caps::signing_key_from_seed(
                mesh_dynamic_caps::generate_dynamic_capability_signing_seed(),
            ),
        ),
        next_dynamic_capability_grant_id: 0,
        dynamic_capability_grants: BTreeMap::new(),
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
    let actuators = install_success_site_actuator(&app).await;
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
    for actuator in actuators {
        actuator.abort();
    }
}

#[tokio::test]
async fn destroy_retracted_tears_down_sites_concurrently() {
    let dir = TempDir::new().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    write_file(
        &root_path,
        r#"
            {
              manifest_version: "0.3.0",
              program: {
                path: "/bin/sh",
                args: ["-c", "sleep 1"]
              }
            }
            "#,
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
        ]),
        defaults: PlacementDefaults {
            path: Some("direct_local".to_string()),
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
    let (actuators, mut destroy_starts, barrier) =
        install_barrier_destroy_site_actuator(&app).await;
    {
        let mut state = app.control_state.lock().await;
        state.pending_destroys.push(pending_destroy(
            1,
            LiveChildRecord {
                child_id: 7,
                authority_realm_id: root_authority,
                name: "job-compose".to_string(),
                state: ChildState::DestroyRetracted,
                template_name: Some("fixture".to_string()),
                selected_manifest_catalog_key: None,
                fragment: None,
                input_bindings: Vec::new(),
                assignments: BTreeMap::new(),
                site_plans: vec![
                    DynamicSitePlanRecord {
                        site_id: "compose_local".to_string(),
                        kind: SiteKind::Compose,
                        router_identity_id: "/site/compose_local/router".to_string(),
                        component_ids: Vec::new(),
                        assigned_components: Vec::new(),
                        artifact_files: BTreeMap::new(),
                        desired_artifact_files: BTreeMap::new(),
                        proxy_exports: BTreeMap::new(),
                        routed_inputs: Vec::new(),
                    },
                    DynamicSitePlanRecord {
                        site_id: "direct_local".to_string(),
                        kind: SiteKind::Direct,
                        router_identity_id: "/site/direct_local/router".to_string(),
                        component_ids: Vec::new(),
                        assigned_components: Vec::new(),
                        artifact_files: BTreeMap::new(),
                        desired_artifact_files: BTreeMap::new(),
                        proxy_exports: BTreeMap::new(),
                        routed_inputs: Vec::new(),
                    },
                ],
                overlay_ids: Vec::new(),
                overlays: Vec::new(),
                outputs: BTreeMap::new(),
            },
        ));
    }

    let destroy = tokio::spawn({
        let app = app.clone();
        async move { continue_destroy_retracted(&app, 7).await }
    });

    let first = tokio::time::timeout(Duration::from_secs(5), destroy_starts.recv())
        .await
        .expect("first destroy should start in time")
        .expect("first destroy notification should arrive");
    let second = tokio::time::timeout(Duration::from_secs(5), destroy_starts.recv())
        .await
        .expect("second destroy should start in time")
        .expect("second destroy notification should arrive");
    assert_ne!(
        first, second,
        "destroy should reach both site actuators before either completes"
    );

    barrier.wait().await;
    destroy
        .await
        .expect("destroy task should join")
        .expect("destroy should succeed");

    let recovered = app.control_state.lock().await.clone();
    assert!(
        recovered.live_children.is_empty(),
        "successful destroy should remove the child after concurrent site teardown",
    );
    for actuator in actuators {
        actuator.abort();
    }
}

#[tokio::test]
async fn create_committed_hidden_publishes_independent_sites_concurrently() {
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
                  program: {{
                    path: "/bin/sh",
                    args: ["-c", "sleep 1"]
                  }},
                  slots: {{
                    realm: {{ kind: "component", optional: true }}
                  }},
                  child_templates: {{
                    fixture: {{ manifest: "{child}" }}
                  }}
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
        ]),
        defaults: PlacementDefaults {
            path: Some("direct_local".to_string()),
            image: Some("compose_local".to_string()),
            ..PlacementDefaults::default()
        },
        components: BTreeMap::new(),
        dynamic_capabilities: None,
        framework_children: None,
    };

    let mut state = compile_control_state_with_placement(&root_path, Some(&placement)).await;
    let state_path = dir.path().join("control-state.json");
    let root_authority = state.base_scenario.root;
    let mut child = prepare_child_record(
        &mut state,
        root_authority,
        &CreateChildRequest {
            template: "fixture".to_string(),
            name: "job-compose".to_string(),
            manifest: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
        },
    )
    .await
    .expect("child should plan successfully");
    let child_id = child.child_id;
    child.state = ChildState::CreateCommittedHidden;
    child.site_plans = vec![
        DynamicSitePlanRecord {
            site_id: "compose_local".to_string(),
            kind: SiteKind::Compose,
            router_identity_id: "/site/compose_local/router".to_string(),
            component_ids: Vec::new(),
            assigned_components: Vec::new(),
            artifact_files: BTreeMap::new(),
            desired_artifact_files: BTreeMap::new(),
            proxy_exports: BTreeMap::new(),
            routed_inputs: Vec::new(),
        },
        DynamicSitePlanRecord {
            site_id: "direct_local".to_string(),
            kind: SiteKind::Direct,
            router_identity_id: "/site/direct_local/router".to_string(),
            component_ids: Vec::new(),
            assigned_components: Vec::new(),
            artifact_files: BTreeMap::new(),
            desired_artifact_files: BTreeMap::new(),
            proxy_exports: BTreeMap::new(),
            routed_inputs: Vec::new(),
        },
    ];
    write_control_state(&state_path, &state).expect("state should write");
    let app = test_control_state_app(&dir, state, state_path);
    let (actuators, mut publish_starts, barrier) =
        install_barrier_publish_site_actuator(&app).await;
    {
        let mut state = app.control_state.lock().await;
        state.pending_creates.push(pending_create(1, child));
    }

    let publish = tokio::spawn({
        let app = app.clone();
        async move { continue_create_committed_hidden(&app, child_id).await }
    });

    let first = tokio::time::timeout(Duration::from_secs(5), publish_starts.recv())
        .await
        .expect("first publish should start in time")
        .expect("first publish notification should arrive");
    let second = tokio::time::timeout(Duration::from_secs(5), publish_starts.recv())
        .await
        .expect("second publish should start in time")
        .expect("second publish notification should arrive");
    assert_ne!(
        first, second,
        "create should reach both independent site actuators before either completes"
    );

    barrier.wait().await;
    publish
        .await
        .expect("publish task should join")
        .expect("publish should succeed");

    let recovered = app.control_state.lock().await.clone();
    let child = recovered
        .live_children
        .iter()
        .find(|child| child.child_id == child_id)
        .expect("child should remain present");
    assert_eq!(
        child.state,
        ChildState::Live,
        "successful concurrent site publication should promote the child to live",
    );
    for actuator in actuators {
        actuator.abort();
    }
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
    let actuators = install_success_site_actuator(&app).await;

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
    for actuator in actuators {
        actuator.abort();
    }
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
async fn prepare_child_record_preserves_cross_backend_matrix_assignments() {
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
    let child = prepare_child_record(
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
    .expect("matrix child should plan successfully");

    assert_eq!(
        child
            .assignments
            .get("/job-compose/root")
            .map(String::as_str),
        Some("compose_local"),
    );
    assert_eq!(
        child
            .assignments
            .get("/job-compose/kind_helper")
            .map(String::as_str),
        Some("kind_local"),
    );
    assert_eq!(
        child
            .assignments
            .get("/job-compose/direct_helper")
            .map(String::as_str),
        Some("direct_local"),
    );
    assert_eq!(
        child
            .assignments
            .get("/job-compose/vm_helper/root")
            .map(String::as_str),
        Some("vm_local"),
    );
    assert_eq!(
        child
            .site_plans
            .iter()
            .map(|site_plan| site_plan.site_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["compose_local", "direct_local", "kind_local", "vm_local"]),
        "cross-backend child planning should retain all expected site slices",
    );
    let proxy_exports_by_site = child
        .site_plans
        .iter()
        .map(|site_plan| {
            (
                site_plan.site_id.as_str(),
                site_plan
                    .proxy_exports
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        proxy_exports_by_site.get("compose_local"),
        Some(&BTreeSet::from(["http"])),
        "compose site should own the dynamic child root export",
    );
    for (site_id, public_export) in [
        ("kind_local", "kind_http"),
        ("direct_local", "direct_http"),
        ("vm_local", "vm_http"),
    ] {
        let exports = proxy_exports_by_site
            .get(site_id)
            .unwrap_or_else(|| panic!("missing proxy export set for {site_id}"));
        assert!(
            exports.contains(public_export),
            "{site_id} should keep its public helper export",
        );
        assert!(
            exports.iter().any(|name| name.starts_with("amber_export_")),
            "{site_id} should also publish its internal routed link export",
        );
    }
    assert!(
        child
            .site_plans
            .iter()
            .all(|site_plan| site_plan.routed_inputs.is_empty()),
        "bindings that stay inside the created fragment must remain intra-fragment wiring, not \
         site-router routed inputs",
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
    let app = test_control_state_app(&dir, state.clone(), state_path.clone());
    let actuators = install_failing_rollback_site_actuator(&app).await;
    state.pending_creates.push(pending_create(
        1,
        LiveChildRecord {
            child_id: 1,
            authority_realm_id: root_authority,
            name: "prepared".to_string(),
            state: ChildState::CreatePrepared,
            template_name: Some("worker".to_string()),
            selected_manifest_catalog_key: None,
            fragment: None,
            input_bindings: Vec::new(),
            assignments: BTreeMap::new(),
            site_plans: vec![DynamicSitePlanRecord {
                site_id: "direct_local".to_string(),
                kind: SiteKind::Direct,
                router_identity_id: "/site/direct_local/router".to_string(),
                component_ids: Vec::new(),
                assigned_components: Vec::new(),
                artifact_files: BTreeMap::new(),
                desired_artifact_files: BTreeMap::new(),
                proxy_exports: BTreeMap::new(),
                routed_inputs: Vec::new(),
            }],
            overlay_ids: Vec::new(),
            overlays: Vec::new(),
            outputs: BTreeMap::new(),
        },
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
    for actuator in actuators {
        actuator.abort();
    }
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
    child.site_plans.clear();
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
        site_plans: vec![DynamicSitePlanRecord {
            site_id: "direct_local".to_string(),
            kind: SiteKind::Direct,
            router_identity_id: "/site/direct_local/router".to_string(),
            component_ids: Vec::new(),
            assigned_components: Vec::new(),
            artifact_files: BTreeMap::new(),
            desired_artifact_files: BTreeMap::new(),
            proxy_exports: BTreeMap::new(),
            routed_inputs: Vec::new(),
        }],
        overlay_ids: Vec::new(),
        overlays: Vec::new(),
        outputs: BTreeMap::new(),
    });
    write_control_state(&state_path, &state).expect("state should write");
    let app = test_control_state_app(&dir, state, state_path);
    let (actuators, mut publish_starts, _barrier) =
        install_barrier_publish_site_actuator(&app).await;

    recover_control_state(&app)
        .await
        .expect("recovery should leave live children alone");

    assert!(
        tokio::time::timeout(Duration::from_millis(200), publish_starts.recv())
            .await
            .is_err(),
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
    for actuator in actuators {
        actuator.abort();
    }
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
