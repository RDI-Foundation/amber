use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use tempfile::tempdir;

use super::*;
use crate::framework_component::DynamicProxyExportRecord;

fn test_dynamic_proxy_export_record(
    component_id: usize,
    component: &str,
    provide: &str,
    protocol: &str,
    capability_kind: &str,
    target_port: u16,
) -> DynamicProxyExportRecord {
    DynamicProxyExportRecord {
        component_id,
        component: component.to_string(),
        provide: provide.to_string(),
        protocol: protocol.to_string(),
        capability_kind: capability_kind.to_string(),
        capability_profile: None,
        target_port,
    }
}

fn test_site_receipt(
    kind: SiteKind,
    artifact_dir: &Path,
    router_control: Option<&str>,
    router_mesh_addr: Option<&str>,
) -> SiteReceipt {
    SiteReceipt {
        kind,
        artifact_dir: artifact_dir.display().to_string(),
        supervisor_pid: 100,
        process_pid: None,
        compose_project: None,
        kubernetes_namespace: None,
        port_forward_pid: None,
        context: None,
        router_control: router_control.map(str::to_string),
        router_mesh_addr: router_mesh_addr.map(str::to_string),
        router_identity_id: None,
        router_public_key_b64: None,
    }
}

fn test_site_state(
    run_id: &str,
    site_id: &str,
    kind: SiteKind,
    artifact_dir: &Path,
    router_control: Option<&str>,
    router_mesh_addr: Option<&str>,
) -> SiteManagerState {
    SiteManagerState {
        schema: "amber.run.site-state".to_string(),
        version: 1,
        run_id: run_id.to_string(),
        site_id: site_id.to_string(),
        kind,
        status: SiteLifecycleStatus::Running,
        artifact_dir: artifact_dir.display().to_string(),
        supervisor_pid: 101,
        process_pid: None,
        compose_project: None,
        kubernetes_namespace: None,
        port_forward_pid: None,
        context: None,
        router_control: router_control.map(str::to_string),
        router_mesh_addr: router_mesh_addr.map(str::to_string),
        router_identity_id: None,
        router_public_key_b64: None,
        last_error: None,
    }
}

#[test]
fn forwarded_endpoint_ready_accepts_open_connection() {
    let listener =
        TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("listener should bind");
    let addr = listener.local_addr().expect("listener addr");
    let handle = std::thread::spawn(move || {
        let (_stream, _) = listener.accept().expect("listener should accept");
        std::thread::sleep(Duration::from_millis(500));
    });

    assert!(crate::tcp_readiness::endpoint_accepts_stable_connection(
        addr,
        Duration::from_millis(250),
        Duration::from_millis(250),
    ));
    handle.join().expect("listener thread should finish");
}

#[test]
fn forwarded_endpoint_ready_rejects_reset_connection() {
    let listener =
        TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("listener should bind");
    let addr = listener.local_addr().expect("listener addr");
    let handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("listener should accept");
        drop(stream);
    });

    assert!(!crate::tcp_readiness::endpoint_accepts_stable_connection(
        addr,
        Duration::from_millis(250),
        Duration::from_millis(250),
    ));
    handle.join().expect("listener thread should finish");
}

#[test]
fn desired_link_overlays_are_owned_per_overlay_id() {
    let temp = tempdir().expect("tempdir");
    let site_state_root = temp.path();

    super::supervisor::update_desired_overlay_for_consumer(
        site_state_root,
        "overlay-a",
        DesiredExternalSlotOverlay {
            slot_name: "api".to_string(),
            url: "http://provider".to_string(),
        },
    )
    .expect("first consumer overlay should persist");
    super::supervisor::update_desired_overlay_for_consumer(
        site_state_root,
        "overlay-b",
        DesiredExternalSlotOverlay {
            slot_name: "api".to_string(),
            url: "http://provider".to_string(),
        },
    )
    .expect("second consumer overlay should persist");
    super::supervisor::update_desired_overlay_for_provider(
        site_state_root,
        "provider-a",
        DesiredExportPeerOverlay {
            export_name: "amber_export_shared".to_string(),
            peer_id: "consumer-a".to_string(),
            peer_key_b64: "a2V5".to_string(),
            protocol: "http".to_string(),
            route_id: Some("route-a".to_string()),
        },
    )
    .expect("first provider overlay should persist");
    super::supervisor::update_desired_overlay_for_provider(
        site_state_root,
        "provider-b",
        DesiredExportPeerOverlay {
            export_name: "amber_export_shared".to_string(),
            peer_id: "consumer-b".to_string(),
            peer_key_b64: "a2V5".to_string(),
            protocol: "http".to_string(),
            route_id: Some("route-b".to_string()),
        },
    )
    .expect("second provider overlay should persist");

    let path = desired_links_path(site_state_root);
    let desired: DesiredLinkState = read_json(&path, "desired links").expect("desired links");
    assert_eq!(desired.external_slot_overlays.len(), 2);
    assert_eq!(desired.export_peer_overlays.len(), 2);

    super::supervisor::clear_desired_overlay_for_consumer(site_state_root, "overlay-a")
        .expect("consumer overlay removal should persist");
    super::supervisor::clear_desired_overlay_for_provider(site_state_root, "provider-a")
        .expect("provider overlay removal should persist");

    let desired: DesiredLinkState = read_json(&path, "desired links").expect("desired links");
    assert_eq!(desired.external_slot_overlays.len(), 1);
    assert_eq!(desired.export_peer_overlays.len(), 1);
    assert!(desired.external_slot_overlays.contains_key("overlay-b"));
    assert!(desired.export_peer_overlays.contains_key("provider-b"));
}

fn test_local_mesh_config(path: &Path, protocol: MeshProtocol, port: u16) -> Result<()> {
    write_json(
        path,
        &MeshConfigPublic {
            identity: MeshIdentityPublic {
                id: "/site/test/router".to_string(),
                public_key: [7; 32],
                mesh_scope: Some("test-scope".to_string()),
            },
            mesh_listen: SocketAddr::from(([127, 0, 0, 1], 24000)),
            control_listen: Some(SocketAddr::from(([127, 0, 0, 1], 24100))),
            control_allow: None,
            peers: Vec::new(),
            inbound: vec![InboundRoute {
                route_id: "route".to_string(),
                capability: "http".to_string(),
                capability_kind: None,
                capability_profile: None,
                protocol,
                http_plugins: Vec::new(),
                target: InboundTarget::Local { port },
                allowed_issuers: Vec::new(),
            }],
            outbound: Vec::new(),
            transport: TransportConfig::NoiseIk {},
        },
    )
}

#[test]
fn mesh_config_local_targets_ready_accepts_http_inbound_routes() {
    let temp = tempdir().expect("tempdir should be created");
    let config_path = temp.path().join("mesh-config.json");
    let listener =
        TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("listener should bind");
    let addr = listener.local_addr().expect("listener addr");
    test_local_mesh_config(&config_path, MeshProtocol::Http, addr.port())
        .expect("mesh config should be written");
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("listener should accept");
        let mut request = [0u8; 256];
        let _ = stream.read(&mut request);
        let _ = stream.write_all(
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
    });

    assert!(
        mesh_config_local_targets_ready(&config_path, Duration::from_secs(1))
            .expect("mesh config should be readable")
    );
    handle.join().expect("listener thread should finish");
}

#[test]
fn mesh_config_local_targets_ready_rejects_unreachable_http_inbound_routes() {
    let temp = tempdir().expect("tempdir should be created");
    let config_path = temp.path().join("mesh-config.json");
    let listener =
        TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("listener should bind");
    let addr = listener.local_addr().expect("listener addr");
    drop(listener);
    test_local_mesh_config(&config_path, MeshProtocol::Http, addr.port())
        .expect("mesh config should be written");

    assert!(
        !mesh_config_local_targets_ready(&config_path, Duration::from_millis(100))
            .expect("mesh config should be readable")
    );
}

#[test]
fn read_compose_launch_env_returns_saved_launch_env() {
    let temp = tempdir().expect("tempdir should be created");
    let run_root = temp.path().join("run-root");
    let state_root = run_root.join("state").join("compose_local");
    write_json(
        &site_supervisor_plan_path(&state_root),
        &SiteSupervisorPlan {
            schema: SITE_PLAN_SCHEMA.to_string(),
            version: SITE_PLAN_VERSION,
            run_id: "run-123".to_string(),
            mesh_scope: "test.scope".to_string(),
            run_root: run_root.display().to_string(),
            coordinator_pid: 1,
            site_id: "compose_local".to_string(),
            kind: SiteKind::Compose,
            artifact_dir: temp.path().join("artifact").display().to_string(),
            site_state_root: state_root.display().to_string(),
            storage_root: None,
            runtime_root: None,
            router_mesh_port: None,
            compose_project: Some("amber-test".to_string()),
            kubernetes_namespace: None,
            context: None,
            port_forward_mesh_port: None,
            port_forward_control_port: None,
            observability_endpoint: None,
            framework_ccs_plan_path: None,
            site_actuator_plan_path: None,
            launch_env: BTreeMap::from([
                ("AMBER_CONFIG_TENANT".to_string(), "acme-local".to_string()),
                (
                    "AMBER_CONFIG_CATALOG_TOKEN".to_string(),
                    "demo-token".to_string(),
                ),
            ]),
        },
    )
    .expect("site supervisor plan should be written");

    assert_eq!(
        read_compose_launch_env(&run_root, "compose_local")
            .expect("compose launch env should be readable"),
        BTreeMap::from([
            (
                "AMBER_CONFIG_CATALOG_TOKEN".to_string(),
                "demo-token".to_string()
            ),
            ("AMBER_CONFIG_TENANT".to_string(), "acme-local".to_string()),
        ])
    );
}

#[test]
fn rewrite_dynamic_proxy_metadata_updates_compose_x_amber_exports() {
    let temp = tempdir().expect("tempdir should be created");
    let artifact_root = temp.path();
    fs::write(
        artifact_root.join("compose.yaml"),
        r#"
services: {}
x-amber:
  version: "1"
  router:
    mesh_port: 24000
    control_port: 24100
  exports:
    stale:
      component: /stale
      provide: old
      protocol: http
      router_mesh_port: 24000
"#,
    )
    .expect("compose artifact should be written");

    rewrite_dynamic_proxy_metadata(
        artifact_root,
        &DynamicSitePlanRecord {
            site_id: "compose_local".to_string(),
            kind: SiteKind::Compose,
            router_identity_id: "router".to_string(),
            component_ids: Vec::new(),
            assigned_components: Vec::new(),
            artifact_files: BTreeMap::new(),
            desired_artifact_files: BTreeMap::new(),
            proxy_exports: BTreeMap::from([(
                "http".to_string(),
                test_dynamic_proxy_export_record(8, "/job/root", "http", "http", "http", 8080),
            )]),
            routed_inputs: Vec::new(),
        },
    )
    .expect("compose proxy metadata should rewrite");

    let raw = fs::read_to_string(artifact_root.join("compose.yaml"))
        .expect("compose artifact should be readable");
    let document: serde_yaml::Value =
        serde_yaml::from_str(&raw).expect("compose yaml should remain valid");
    let exports = document["x-amber"]["exports"]
        .as_mapping()
        .expect("compose x-amber exports should be a mapping");
    assert_eq!(exports.len(), 1, "stale compose exports should be replaced");
    let export = exports
        .get(serde_yaml::Value::String("http".to_string()))
        .expect("expected rewritten compose export");
    assert_eq!(export["component"].as_str(), Some("/job/root"));
    assert_eq!(export["provide"].as_str(), Some("http"));
    assert_eq!(export["protocol"].as_str(), Some("http"));
}

#[test]
fn prepare_dynamic_compose_child_artifact_keeps_only_child_owned_services() {
    let temp = tempdir().expect("tempdir should be created");
    let site_artifact = temp.path().join("site-artifact");
    let child_artifact = temp.path().join("child-artifact");
    let site_state_root = temp.path().join("state").join("compose_local");
    let mesh_plan = MeshProvisionPlan {
        version: "2".to_string(),
        identity_seed: None,
        existing_peer_identities: Vec::new(),
        targets: vec![
            amber_mesh::MeshProvisionTarget {
                kind: MeshProvisionTargetKind::Component,
                config: amber_mesh::MeshConfigTemplate {
                    identity: amber_mesh::MeshIdentityTemplate {
                        id: "/compose_admin".to_string(),
                        mesh_scope: Some("scope".to_string()),
                    },
                    mesh_listen: SocketAddr::from(([0, 0, 0, 0], 23000)),
                    control_listen: None,
                    control_allow: None,
                    peers: vec![amber_mesh::MeshPeerTemplate {
                        id: "/site/compose_local/router".to_string(),
                    }],
                    inbound: vec![InboundRoute {
                        route_id: component_route_id("/compose_admin", "http", MeshProtocol::Http),
                        capability: "http".to_string(),
                        capability_kind: Some("http".to_string()),
                        capability_profile: None,
                        protocol: MeshProtocol::Http,
                        http_plugins: Vec::new(),
                        target: InboundTarget::Local { port: 8080 },
                        allowed_issuers: vec!["/site/compose_local/router".to_string()],
                    }],
                    outbound: Vec::new(),
                    transport: TransportConfig::NoiseIk {},
                },
                output: MeshProvisionOutput::Filesystem {
                    dir: "/amber/provision/c1-compose-admin-net".to_string(),
                },
            },
            amber_mesh::MeshProvisionTarget {
                kind: MeshProvisionTargetKind::Component,
                config: amber_mesh::MeshConfigTemplate {
                    identity: amber_mesh::MeshIdentityTemplate {
                        id: "/job/root".to_string(),
                        mesh_scope: Some("scope".to_string()),
                    },
                    mesh_listen: SocketAddr::from(([0, 0, 0, 0], 23000)),
                    control_listen: None,
                    control_allow: None,
                    peers: vec![amber_mesh::MeshPeerTemplate {
                        id: "/site/compose_local/router".to_string(),
                    }],
                    inbound: vec![InboundRoute {
                        route_id: component_route_id("/job/root", "http", MeshProtocol::Http),
                        capability: "http".to_string(),
                        capability_kind: Some("http".to_string()),
                        capability_profile: None,
                        protocol: MeshProtocol::Http,
                        http_plugins: Vec::new(),
                        target: InboundTarget::Local { port: 8080 },
                        allowed_issuers: vec!["/site/compose_local/router".to_string()],
                    }],
                    outbound: Vec::new(),
                    transport: TransportConfig::NoiseIk {},
                },
                output: MeshProvisionOutput::Filesystem {
                    dir: "/amber/provision/c8-root-net".to_string(),
                },
            },
            amber_mesh::MeshProvisionTarget {
                kind: MeshProvisionTargetKind::Router,
                config: amber_mesh::MeshConfigTemplate {
                    identity: amber_mesh::MeshIdentityTemplate {
                        id: "/site/compose_local/router".to_string(),
                        mesh_scope: Some("scope".to_string()),
                    },
                    mesh_listen: SocketAddr::from(([0, 0, 0, 0], 24000)),
                    control_listen: None,
                    control_allow: None,
                    peers: vec![
                        amber_mesh::MeshPeerTemplate {
                            id: "/compose_admin".to_string(),
                        },
                        amber_mesh::MeshPeerTemplate {
                            id: "/job/root".to_string(),
                        },
                    ],
                    inbound: vec![
                        InboundRoute {
                            route_id: router_export_route_id(
                                "compose_admin_http",
                                MeshProtocol::Http,
                            ),
                            capability: "compose_admin_http".to_string(),
                            capability_kind: Some("http".to_string()),
                            capability_profile: None,
                            protocol: MeshProtocol::Http,
                            http_plugins: Vec::new(),
                            target: InboundTarget::MeshForward {
                                peer_addr: "c1-compose-admin-net:23000".to_string(),
                                peer_id: "/compose_admin".to_string(),
                                route_id: component_route_id(
                                    "/compose_admin",
                                    "http",
                                    MeshProtocol::Http,
                                ),
                                capability: "http".to_string(),
                            },
                            allowed_issuers: vec!["/site/compose_local/router".to_string()],
                        },
                        InboundRoute {
                            route_id: router_export_route_id("http", MeshProtocol::Http),
                            capability: "http".to_string(),
                            capability_kind: Some("http".to_string()),
                            capability_profile: None,
                            protocol: MeshProtocol::Http,
                            http_plugins: Vec::new(),
                            target: InboundTarget::MeshForward {
                                peer_addr: "c8-root-net:23000".to_string(),
                                peer_id: "/job/root".to_string(),
                                route_id: component_route_id(
                                    "/job/root",
                                    "http",
                                    MeshProtocol::Http,
                                ),
                                capability: "http".to_string(),
                            },
                            allowed_issuers: vec!["/site/compose_local/router".to_string()],
                        },
                        InboundRoute {
                            route_id: "cap_static_admin".to_string(),
                            capability: "component".to_string(),
                            capability_kind: Some("component".to_string()),
                            capability_profile: None,
                            protocol: MeshProtocol::Http,
                            http_plugins: Vec::new(),
                            target: InboundTarget::External {
                                url_env: "AMBER_FRAMEWORK_COMPONENT_CCS_URL".to_string(),
                                optional: false,
                            },
                            allowed_issuers: vec!["/compose_admin".to_string()],
                        },
                        InboundRoute {
                            route_id: "cap_child".to_string(),
                            capability: "component".to_string(),
                            capability_kind: Some("component".to_string()),
                            capability_profile: None,
                            protocol: MeshProtocol::Http,
                            http_plugins: Vec::new(),
                            target: InboundTarget::External {
                                url_env: "AMBER_FRAMEWORK_COMPONENT_CCS_URL".to_string(),
                                optional: false,
                            },
                            allowed_issuers: vec!["/job/root".to_string()],
                        },
                    ],
                    outbound: Vec::new(),
                    transport: TransportConfig::NoiseIk {},
                },
                output: MeshProvisionOutput::Filesystem {
                    dir: "/amber/provision/amber-router".to_string(),
                },
            },
        ],
    };

    fs::create_dir_all(&site_artifact).expect("site artifact dir should exist");
    fs::create_dir_all(&child_artifact).expect("child artifact dir should exist");
    fs::create_dir_all(&site_state_root).expect("site state dir should exist");

    fs::write(
        site_artifact.join("compose.yaml"),
        r#"
services:
  amber-router:
    image: ghcr.io/rdi-foundation/amber-router:v0.1
  amber-otelcol:
    image: otel/opentelemetry-collector-contrib:0.143.0
  amber-router-control-init:
    image: busybox:1.36.1
  c1-compose-admin:
    image: python:3.13-alpine
    depends_on:
      - c1-compose-admin-net
  c1-compose-admin-net:
    image: ghcr.io/rdi-foundation/amber-router:v0.1
    volumes:
      - c1-compose-admin-net-mesh:/amber/mesh:ro
volumes:
  c1-compose-admin-net-mesh: {}
x-amber:
  version: "1"
  router:
    mesh_port: 24000
    control_port: 24100
"#,
    )
    .expect("static compose artifact should be written");

    let mesh_plan_json = serde_json::to_string(&mesh_plan).expect("mesh plan should serialize");
    fs::write(
        child_artifact.join("compose.yaml"),
        format!(
            r#"
services:
  amber-router:
    image: ghcr.io/rdi-foundation/amber-router:v0.1
  amber-otelcol:
    image: otel/opentelemetry-collector-contrib:0.143.0
  amber-router-control-init:
    image: busybox:1.36.1
  amber-provisioner:
    image: ghcr.io/rdi-foundation/amber-provisioner:v0.1
  c1-compose-admin:
    image: python:3.13-alpine
    depends_on:
      - c1-compose-admin-net
  c1-compose-admin-net:
    image: ghcr.io/rdi-foundation/amber-router:v0.1
    volumes:
      - c1-compose-admin-net-mesh:/amber/mesh:ro
  c8-root:
    image: python:3.13-alpine
    depends_on:
      - c8-root-net
  c8-root-net:
    image: ghcr.io/rdi-foundation/amber-router:v0.1
    depends_on:
      - amber-provisioner
    environment:
      - AMBER_SCENARIO_SCOPE=scope
    volumes:
      - c8-root-net-mesh:/amber/mesh:ro
configs:
  amber-mesh-provision-plan:
    content: '{mesh_plan_json}'
volumes:
  c1-compose-admin-net-mesh: {{}}
  c8-root-net-mesh: {{}}
x-amber:
  version: "1"
  router:
    mesh_port: 24000
    control_port: 24100
"#
        ),
    )
    .expect("dynamic compose artifact should be written");

    write_json(
        &site_state_root.join("manager-state.json"),
        &SiteManagerState {
            schema: SITE_STATE_SCHEMA.to_string(),
            version: SITE_STATE_VERSION,
            run_id: "run-123".to_string(),
            site_id: "compose_local".to_string(),
            kind: SiteKind::Compose,
            status: SiteLifecycleStatus::Running,
            artifact_dir: site_artifact.display().to_string(),
            supervisor_pid: 123,
            process_pid: None,
            compose_project: Some("amber-test".to_string()),
            kubernetes_namespace: None,
            port_forward_pid: None,
            context: None,
            router_control: Some("http://127.0.0.1:24100".to_string()),
            router_mesh_addr: Some("127.0.0.1:24000".to_string()),
            router_identity_id: Some("/site/compose_local/router".to_string()),
            router_public_key_b64: Some(
                base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
            ),
            last_error: None,
        },
    )
    .expect("site manager state should be written");

    prepare_dynamic_compose_child_artifact(
        &SiteActuatorPlan {
            schema: SITE_PLAN_SCHEMA.to_string(),
            version: SITE_PLAN_VERSION,
            run_id: "run-123".to_string(),
            mesh_scope: "mesh-scope-test".to_string(),
            run_root: temp.path().display().to_string(),
            site_id: "compose_local".to_string(),
            kind: SiteKind::Compose,
            router_identity_id: "/site/compose_local/router".to_string(),
            artifact_dir: site_artifact.display().to_string(),
            site_state_root: site_state_root.display().to_string(),
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            storage_root: None,
            runtime_root: None,
            router_mesh_port: None,
            compose_project: Some("amber-test".to_string()),
            kubernetes_namespace: None,
            context: None,
            observability_endpoint: None,
            launch_env: BTreeMap::new(),
        },
        &DynamicSitePlanRecord {
            site_id: "compose_local".to_string(),
            kind: SiteKind::Compose,
            router_identity_id: "/site/compose_local/router".to_string(),
            component_ids: vec![8],
            assigned_components: vec!["/job/root".to_string()],
            artifact_files: BTreeMap::new(),
            desired_artifact_files: BTreeMap::new(),
            proxy_exports: BTreeMap::new(),
            routed_inputs: Vec::new(),
        },
        &child_artifact,
        &[],
        &BTreeMap::from([(
            "/site/compose_local/router".to_string(),
            MeshIdentityPublic {
                id: "/site/compose_local/router".to_string(),
                public_key: [7; 32],
                mesh_scope: Some("mesh-scope-test".to_string()),
            },
        )]),
    )
    .expect("dynamic compose child artifact should be prepared");

    let child_document =
        read_compose_document(&child_artifact.join("compose.yaml")).expect("compose file");
    let child_services =
        compose_services(&child_document, &child_artifact.join("compose.yaml")).expect("services");
    assert_eq!(
        child_services
            .keys()
            .filter_map(serde_yaml::Value::as_str)
            .collect::<Vec<_>>(),
        vec!["c8-root", "c8-root-net"]
    );

    let sidecar_volumes = child_services
        .get(yaml_string("c8-root-net"))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|service| service.get(yaml_string("volumes")))
        .and_then(serde_yaml::Value::as_sequence)
        .expect("child sidecar volumes should be present");
    assert_eq!(
        sidecar_volumes,
        &vec![serde_yaml::Value::String(
            "./.amber/mesh/c8-root-net:/amber/mesh:ro".to_string()
        )]
    );
    let child_compose_yaml = fs::read_to_string(child_artifact.join("compose.yaml"))
        .expect("child compose artifact should be readable");
    assert!(
        child_compose_yaml.contains("AMBER_SCENARIO_SCOPE=mesh-scope-test"),
        "dynamic compose artifact should rewrite sidecar scenario scope onto the live run scope",
    );
    assert!(
        !child_compose_yaml.contains("AMBER_SCENARIO_SCOPE=scope"),
        "dynamic compose artifact should not retain the compiled child scope",
    );

    let metadata = load_dynamic_compose_child_metadata(&child_artifact)
        .expect("dynamic compose child metadata should be readable");
    assert_eq!(
        metadata.services,
        vec!["c8-root".to_string(), "c8-root-net".to_string()]
    );
    assert_eq!(
        metadata.readiness_services,
        vec!["c8-root".to_string(), "c8-root-net".to_string()]
    );

    let filtered_plan: MeshProvisionPlan = read_json(
        &child_artifact.join("mesh-provision-plan.json"),
        "mesh provision plan",
    )
    .expect("filtered mesh provision plan should exist");
    assert_eq!(filtered_plan.targets.len(), 1);
    let component = filtered_plan
        .targets
        .iter()
        .find(|target| matches!(target.kind, MeshProvisionTargetKind::Component))
        .expect("filtered component target should exist");
    let MeshProvisionOutput::Filesystem { dir } = &component.output else {
        panic!("filtered component mesh output should be filesystem");
    };
    assert_eq!(dir, ".amber/mesh/c8-root-net");
    assert_eq!(
        component
            .config
            .inbound
            .iter()
            .map(|route| route.route_id.as_str())
            .collect::<Vec<_>>(),
        vec!["component:/job/root:http:http"]
    );
    assert_eq!(
        component.config.inbound[0].allowed_issuers,
        vec!["/site/compose_local/router".to_string()]
    );

    let mesh_config: MeshConfigPublic = read_json(
        &child_artifact
            .join(".amber/mesh/c8-root-net")
            .join("mesh-config.json"),
        "mesh config",
    )
    .expect("child sidecar mesh config should exist");
    let router_peer = mesh_config
        .peers
        .iter()
        .find(|peer| peer.id == "/site/compose_local/router")
        .expect("child sidecar should peer with the site router");
    assert_eq!(router_peer.public_key, [7u8; 32]);

    let overlay: StoredRouteOverlayPayload = read_json(
        &dynamic_route_overlay_path(&child_artifact),
        "site router overlay",
    )
    .expect("compose child router overlay should exist");
    assert_eq!(
        overlay
            .peers
            .iter()
            .map(|peer| peer.id.as_str())
            .collect::<Vec<_>>(),
        vec!["/job/root"]
    );
    assert_eq!(
        overlay
            .inbound_routes
            .iter()
            .map(|route| route.route_id.clone())
            .collect::<Vec<_>>(),
        vec![
            router_export_route_id("http", MeshProtocol::Http),
            "cap_child".to_string(),
        ]
    );
}

#[test]
fn prepare_dynamic_compose_child_artifact_rewrites_same_site_static_provider_inputs() {
    let temp = tempdir().expect("tempdir should be created");
    let site_artifact = temp.path().join("site-artifact");
    let child_artifact = temp.path().join("child-artifact");
    fs::create_dir_all(&site_artifact).expect("site artifact dir should exist");
    fs::create_dir_all(&child_artifact).expect("child artifact dir should exist");

    let mesh_plan = MeshProvisionPlan {
        version: "2".to_string(),
        identity_seed: None,
        existing_peer_identities: Vec::new(),
        targets: vec![
            amber_mesh::MeshProvisionTarget {
                kind: MeshProvisionTargetKind::Component,
                config: amber_mesh::MeshConfigTemplate {
                    identity: amber_mesh::MeshIdentityTemplate {
                        id: "/provider".to_string(),
                        mesh_scope: Some("compiled-scope".to_string()),
                    },
                    mesh_listen: SocketAddr::from(([0, 0, 0, 0], 23000)),
                    control_listen: None,
                    control_allow: None,
                    peers: vec![amber_mesh::MeshPeerTemplate {
                        id: "/site/compose_local/router".to_string(),
                    }],
                    inbound: vec![InboundRoute {
                        route_id: component_route_id("/provider", "http", MeshProtocol::Http),
                        capability: "http".to_string(),
                        capability_kind: Some("http".to_string()),
                        capability_profile: None,
                        protocol: MeshProtocol::Http,
                        http_plugins: Vec::new(),
                        target: InboundTarget::Local { port: 8080 },
                        allowed_issuers: vec!["/site/compose_local/router".to_string()],
                    }],
                    outbound: Vec::new(),
                    transport: TransportConfig::NoiseIk {},
                },
                output: MeshProvisionOutput::Filesystem {
                    dir: "/amber/provision/c4-provider-net".to_string(),
                },
            },
            amber_mesh::MeshProvisionTarget {
                kind: MeshProvisionTargetKind::Component,
                config: amber_mesh::MeshConfigTemplate {
                    identity: amber_mesh::MeshIdentityTemplate {
                        id: "/sibling".to_string(),
                        mesh_scope: Some("compiled-scope".to_string()),
                    },
                    mesh_listen: SocketAddr::from(([0, 0, 0, 0], 23000)),
                    control_listen: None,
                    control_allow: None,
                    peers: vec![amber_mesh::MeshPeerTemplate {
                        id: "/provider".to_string(),
                    }],
                    inbound: Vec::new(),
                    outbound: vec![OutboundRoute {
                        route_id: component_route_id("/provider", "http", MeshProtocol::Http),
                        slot: "upstream".to_string(),
                        capability_kind: Some("http".to_string()),
                        capability_profile: None,
                        listen_port: 20000,
                        listen_addr: None,
                        protocol: MeshProtocol::Http,
                        http_plugins: Vec::new(),
                        peer_addr: "c4-provider-net:23000".to_string(),
                        peer_id: "/provider".to_string(),
                        capability: "http".to_string(),
                    }],
                    transport: TransportConfig::NoiseIk {},
                },
                output: MeshProvisionOutput::Filesystem {
                    dir: "/amber/provision/c5-sibling-net".to_string(),
                },
            },
            amber_mesh::MeshProvisionTarget {
                kind: MeshProvisionTargetKind::Router,
                config: amber_mesh::MeshConfigTemplate {
                    identity: amber_mesh::MeshIdentityTemplate {
                        id: "/site/compose_local/router".to_string(),
                        mesh_scope: Some("compiled-scope".to_string()),
                    },
                    mesh_listen: SocketAddr::from(([0, 0, 0, 0], 24000)),
                    control_listen: None,
                    control_allow: None,
                    peers: vec![amber_mesh::MeshPeerTemplate {
                        id: "/provider".to_string(),
                    }],
                    inbound: vec![InboundRoute {
                        route_id: router_export_route_id("provider_http", MeshProtocol::Http),
                        capability: "provider_http".to_string(),
                        capability_kind: Some("http".to_string()),
                        capability_profile: None,
                        protocol: MeshProtocol::Http,
                        http_plugins: Vec::new(),
                        target: InboundTarget::MeshForward {
                            peer_addr: "c4-provider-net:23000".to_string(),
                            peer_id: "/provider".to_string(),
                            route_id: component_route_id("/provider", "http", MeshProtocol::Http),
                            capability: "http".to_string(),
                        },
                        allowed_issuers: vec!["/site/compose_local/router".to_string()],
                    }],
                    outbound: Vec::new(),
                    transport: TransportConfig::NoiseIk {},
                },
                output: MeshProvisionOutput::Filesystem {
                    dir: "/amber/provision/amber-router".to_string(),
                },
            },
        ],
    };
    let mesh_plan_json = serde_json::to_string(&mesh_plan).expect("mesh plan should serialize");
    fs::write(
        child_artifact.join("compose.yaml"),
        format!(
            r#"
services:
  amber-router:
    image: ghcr.io/rdi-foundation/amber-router:v0.1
  amber-otelcol:
    image: otel/opentelemetry-collector-contrib:0.143.0
  amber-router-control-init:
    image: busybox:1.36.1
  amber-provisioner:
    image: ghcr.io/rdi-foundation/amber-provisioner:v0.1
  c4-provider:
    image: python:3.13-alpine
    depends_on:
      - c4-provider-net
  c4-provider-net:
    image: ghcr.io/rdi-foundation/amber-router:v0.1
    volumes:
      - c4-provider-net-mesh:/amber/mesh:ro
  c5-sibling:
    image: python:3.13-alpine
    depends_on:
      - c5-sibling-net
      - c4-provider
  c5-sibling-net:
    image: ghcr.io/rdi-foundation/amber-router:v0.1
    depends_on:
      - amber-provisioner
    environment:
      - AMBER_SCENARIO_SCOPE=compiled-scope
    volumes:
      - c5-sibling-net-mesh:/amber/mesh:ro
configs:
  amber-mesh-provision-plan:
    content: '{mesh_plan_json}'
volumes:
  c4-provider-net-mesh: {{}}
  c5-sibling-net-mesh: {{}}
networks:
  amber_mesh:
    driver: bridge
  amber_boundary:
    driver: bridge
x-amber:
  version: "1"
  router:
    mesh_port: 24000
    control_port: 24100
"#
        ),
    )
    .expect("dynamic compose artifact should be written");

    fs::write(
        site_artifact.join("compose.yaml"),
        r#"
services:
  amber-router:
    image: ghcr.io/rdi-foundation/amber-router:v0.1
  amber-otelcol:
    image: otel/opentelemetry-collector-contrib:0.143.0
  amber-router-control-init:
    image: busybox:1.36.1
  c4-provider:
    image: python:3.13-alpine
    depends_on:
      - c4-provider-net
  c4-provider-net:
    image: ghcr.io/rdi-foundation/amber-router:v0.1
    volumes:
      - c4-provider-net-mesh:/amber/mesh:ro
volumes:
  c4-provider-net-mesh: {}
x-amber:
  version: "1"
  router:
    mesh_port: 24000
    control_port: 24100
"#,
    )
    .expect("site compose artifact should be written");

    prepare_dynamic_compose_child_artifact(
        &SiteActuatorPlan {
            schema: SITE_PLAN_SCHEMA.to_string(),
            version: SITE_PLAN_VERSION,
            run_id: "run-123".to_string(),
            mesh_scope: "live-scope".to_string(),
            run_root: temp.path().display().to_string(),
            site_id: "compose_local".to_string(),
            kind: SiteKind::Compose,
            router_identity_id: "/site/compose_local/router".to_string(),
            artifact_dir: site_artifact.display().to_string(),
            site_state_root: temp.path().display().to_string(),
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            storage_root: None,
            runtime_root: None,
            router_mesh_port: None,
            compose_project: Some("amber-test".to_string()),
            kubernetes_namespace: None,
            context: None,
            observability_endpoint: None,
            launch_env: BTreeMap::new(),
        },
        &DynamicSitePlanRecord {
            site_id: "compose_local".to_string(),
            kind: SiteKind::Compose,
            router_identity_id: "/site/compose_local/router".to_string(),
            component_ids: vec![5],
            assigned_components: vec!["/sibling".to_string()],
            artifact_files: BTreeMap::new(),
            desired_artifact_files: BTreeMap::new(),
            proxy_exports: BTreeMap::new(),
            routed_inputs: vec![DynamicInputRouteRecord {
                component: "/sibling".to_string(),
                slot: "upstream".to_string(),
                provider_component: "/provider".to_string(),
                protocol: "http".to_string(),
                capability_kind: "http".to_string(),
                capability_profile: None,
                target: DynamicInputRouteTarget::ComponentProvide {
                    provide: "http".to_string(),
                },
            }],
        },
        &child_artifact,
        &[],
        &BTreeMap::from([
            (
                "/site/compose_local/router".to_string(),
                MeshIdentityPublic {
                    id: "/site/compose_local/router".to_string(),
                    public_key: [7; 32],
                    mesh_scope: Some("live-scope".to_string()),
                },
            ),
            (
                "/provider".to_string(),
                MeshIdentityPublic {
                    id: "/provider".to_string(),
                    public_key: [8; 32],
                    mesh_scope: Some("live-scope".to_string()),
                },
            ),
        ]),
    )
    .expect("dynamic compose child artifact should be prepared");

    let filtered_plan: MeshProvisionPlan = read_json(
        &child_artifact.join("mesh-provision-plan.json"),
        "mesh provision plan",
    )
    .expect("filtered mesh provision plan should exist");
    assert_eq!(filtered_plan.targets.len(), 1);
    let component = filtered_plan
        .targets
        .iter()
        .find(|target| matches!(target.kind, MeshProvisionTargetKind::Component))
        .expect("filtered component target should exist");
    assert_eq!(component.config.identity.id, "/sibling");
    assert!(
        component
            .config
            .peers
            .iter()
            .any(|peer| peer.id == "/site/compose_local/router"),
        "rewritten child mesh plan should peer with the site router",
    );
    assert_eq!(component.config.outbound.len(), 1);
    let outbound = &component.config.outbound[0];
    assert_eq!(outbound.slot, "upstream");
    assert_eq!(
        outbound.route_id,
        component_route_id("/provider", "http", MeshProtocol::Http)
    );
    assert_eq!(
        outbound.peer_addr,
        format!("{COMPOSE_ROUTER_SERVICE_NAME}:24000")
    );
    assert_eq!(outbound.peer_id, "/site/compose_local/router");
    assert_eq!(outbound.capability, "http");

    let embedded_plan = read_embedded_compose_mesh_provision_plan(&child_artifact)
        .expect("embedded compose mesh plan should be readable");
    let embedded_component = embedded_plan
        .targets
        .iter()
        .find(|target| {
            matches!(target.kind, MeshProvisionTargetKind::Component)
                && target.config.identity.id == "/sibling"
        })
        .expect("embedded child component target should exist");
    assert_eq!(embedded_component.config.outbound.len(), 1);
    assert_eq!(
        embedded_component.config.outbound[0].peer_addr,
        format!("{COMPOSE_ROUTER_SERVICE_NAME}:24000")
    );
    assert_eq!(
        embedded_component.config.outbound[0].peer_id,
        "/site/compose_local/router"
    );

    let overlay: StoredRouteOverlayPayload = read_json(
        &dynamic_route_overlay_path(&child_artifact),
        "site router overlay",
    )
    .expect("compose child router overlay should exist");
    assert!(
        overlay.peers.iter().any(|peer| peer.id == "/provider"),
        "compose routed-input overlay should include the provider peer",
    );
    let routed_input_route = overlay
        .inbound_routes
        .iter()
        .find(|route| route.route_id == component_route_id("/provider", "http", MeshProtocol::Http))
        .expect("compose routed-input overlay should include the provider route");
    let InboundTarget::MeshForward {
        peer_addr,
        peer_id,
        route_id,
        capability,
    } = &routed_input_route.target
    else {
        panic!("compose routed-input overlay should forward across mesh");
    };
    assert_eq!(peer_addr, "c4-provider-net:23000");
    assert_eq!(peer_id, "/provider");
    assert_eq!(route_id, "component:/provider:http:http");
    assert_eq!(capability, "http");
}

#[test]
fn dynamic_route_issuer_grants_include_component_provide_inputs() {
    let issuers = dynamic_route_issuer_grants(&[SiteActuatorChildRecord {
        child_id: 7,
        artifact_root: "/tmp/child".to_string(),
        assigned_components: vec!["/sibling".to_string()],
        proxy_exports: BTreeMap::new(),
        routed_inputs: vec![DynamicInputRouteRecord {
            component: "/sibling".to_string(),
            slot: "upstream".to_string(),
            provider_component: "/provider".to_string(),
            protocol: "http".to_string(),
            capability_kind: "http".to_string(),
            capability_profile: None,
            target: DynamicInputRouteTarget::ComponentProvide {
                provide: "http".to_string(),
            },
        }],
        process_pid: None,
        published: true,
    }])
    .expect("component-provide routed inputs should produce issuer grants");

    assert_eq!(
        issuers.get("component:/provider:http:http"),
        Some(&BTreeSet::from(["/sibling".to_string()]))
    );
}

#[test]
fn filter_dynamic_mesh_provision_plan_keeps_only_child_owned_router_routes() {
    let temp = tempdir().expect("tempdir should be created");
    let artifact_root = temp.path();
    write_json(
        &artifact_root.join("mesh-provision-plan.json"),
        &MeshProvisionPlan {
            version: "2".to_string(),
            identity_seed: None,
            existing_peer_identities: Vec::new(),
            targets: vec![
                amber_mesh::MeshProvisionTarget {
                    kind: MeshProvisionTargetKind::Component,
                    config: amber_mesh::MeshConfigTemplate {
                        identity: amber_mesh::MeshIdentityTemplate {
                            id: "/vm_admin".to_string(),
                            mesh_scope: Some("scope".to_string()),
                        },
                        mesh_listen: SocketAddr::from(([127, 0, 0, 1], 0)),
                        control_listen: None,
                        control_allow: None,
                        peers: vec![amber_mesh::MeshPeerTemplate {
                            id: "/site/vm_local/router".to_string(),
                        }],
                        inbound: vec![InboundRoute {
                            route_id: component_route_id("/vm_admin", "http", MeshProtocol::Http),
                            capability: "http".to_string(),
                            capability_kind: Some("http".to_string()),
                            capability_profile: None,
                            protocol: MeshProtocol::Http,
                            http_plugins: Vec::new(),
                            target: InboundTarget::Local { port: 8080 },
                            allowed_issuers: vec!["/site/vm_local/router".to_string()],
                        }],
                        outbound: Vec::new(),
                        transport: TransportConfig::NoiseIk {},
                    },
                    output: MeshProvisionOutput::Filesystem {
                        dir: "mesh/components/c4-vm_admin".to_string(),
                    },
                },
                amber_mesh::MeshProvisionTarget {
                    kind: MeshProvisionTargetKind::Component,
                    config: amber_mesh::MeshConfigTemplate {
                        identity: amber_mesh::MeshIdentityTemplate {
                            id: "/job-compose/vm_helper/root".to_string(),
                            mesh_scope: Some("scope".to_string()),
                        },
                        mesh_listen: SocketAddr::from(([127, 0, 0, 1], 0)),
                        control_listen: None,
                        control_allow: None,
                        peers: vec![amber_mesh::MeshPeerTemplate {
                            id: "/site/vm_local/router".to_string(),
                        }],
                        inbound: vec![InboundRoute {
                            route_id: component_route_id(
                                "/job-compose/vm_helper/root",
                                "http",
                                MeshProtocol::Http,
                            ),
                            capability: "http".to_string(),
                            capability_kind: Some("http".to_string()),
                            capability_profile: None,
                            protocol: MeshProtocol::Http,
                            http_plugins: Vec::new(),
                            target: InboundTarget::Local { port: 8080 },
                            allowed_issuers: vec!["/site/vm_local/router".to_string()],
                        }],
                        outbound: Vec::new(),
                        transport: TransportConfig::NoiseIk {},
                    },
                    output: MeshProvisionOutput::Filesystem {
                        dir: "mesh/components/c9-root".to_string(),
                    },
                },
                amber_mesh::MeshProvisionTarget {
                    kind: MeshProvisionTargetKind::Router,
                    config: amber_mesh::MeshConfigTemplate {
                        identity: amber_mesh::MeshIdentityTemplate {
                            id: "/site/vm_local/router".to_string(),
                            mesh_scope: Some("scope".to_string()),
                        },
                        mesh_listen: SocketAddr::from(([127, 0, 0, 1], 0)),
                        control_listen: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
                        control_allow: None,
                        peers: vec![
                            amber_mesh::MeshPeerTemplate {
                                id: "/vm_admin".to_string(),
                            },
                            amber_mesh::MeshPeerTemplate {
                                id: "/job-compose/vm_helper/root".to_string(),
                            },
                        ],
                        inbound: vec![
                            InboundRoute {
                                route_id: router_export_route_id(
                                    "vm_admin_http",
                                    MeshProtocol::Http,
                                ),
                                capability: "vm_admin_http".to_string(),
                                capability_kind: Some("http".to_string()),
                                capability_profile: None,
                                protocol: MeshProtocol::Http,
                                http_plugins: Vec::new(),
                                target: InboundTarget::MeshForward {
                                    peer_addr: "127.0.0.1:23001".to_string(),
                                    peer_id: "/vm_admin".to_string(),
                                    route_id: component_route_id(
                                        "/vm_admin",
                                        "http",
                                        MeshProtocol::Http,
                                    ),
                                    capability: "http".to_string(),
                                },
                                allowed_issuers: vec!["/site/vm_local/router".to_string()],
                            },
                            InboundRoute {
                                route_id: router_export_route_id(
                                    "amber_export_916351bacd5bad90",
                                    MeshProtocol::Http,
                                ),
                                capability: "amber_export_916351bacd5bad90".to_string(),
                                capability_kind: Some("http".to_string()),
                                capability_profile: None,
                                protocol: MeshProtocol::Http,
                                http_plugins: Vec::new(),
                                target: InboundTarget::MeshForward {
                                    peer_addr: "127.0.0.1:23002".to_string(),
                                    peer_id: "/job-compose/vm_helper/root".to_string(),
                                    route_id: component_route_id(
                                        "/job-compose/vm_helper/root",
                                        "http",
                                        MeshProtocol::Http,
                                    ),
                                    capability: "http".to_string(),
                                },
                                allowed_issuers: vec!["/site/vm_local/router".to_string()],
                            },
                            InboundRoute {
                                route_id: "cap_static_admin".to_string(),
                                capability: "component".to_string(),
                                capability_kind: Some("component".to_string()),
                                capability_profile: None,
                                protocol: MeshProtocol::Http,
                                http_plugins: Vec::new(),
                                target: InboundTarget::External {
                                    url_env: "AMBER_FRAMEWORK_COMPONENT_CCS_URL".to_string(),
                                    optional: false,
                                },
                                allowed_issuers: vec!["/vm_admin".to_string()],
                            },
                            InboundRoute {
                                route_id: "cap_child".to_string(),
                                capability: "component".to_string(),
                                capability_kind: Some("component".to_string()),
                                capability_profile: None,
                                protocol: MeshProtocol::Http,
                                http_plugins: Vec::new(),
                                target: InboundTarget::External {
                                    url_env: "AMBER_FRAMEWORK_COMPONENT_CCS_URL".to_string(),
                                    optional: false,
                                },
                                allowed_issuers: vec!["/job-compose/vm_helper/root".to_string()],
                            },
                        ],
                        outbound: Vec::new(),
                        transport: TransportConfig::NoiseIk {},
                    },
                    output: MeshProvisionOutput::Filesystem {
                        dir: "mesh/router".to_string(),
                    },
                },
            ],
        },
    )
    .expect("mesh provision plan should be written");

    filter_dynamic_mesh_provision_plan(
        artifact_root,
        &BTreeSet::from(["mesh/components/c9-root".to_string()]),
    )
    .expect("dynamic mesh provision plan should be filtered");

    let filtered: MeshProvisionPlan = read_json(
        &artifact_root.join("mesh-provision-plan.json"),
        "mesh provision plan",
    )
    .expect("filtered mesh provision plan should be readable");
    assert_eq!(filtered.targets.len(), 2);

    let component = filtered
        .targets
        .iter()
        .find(|target| matches!(target.kind, MeshProvisionTargetKind::Component))
        .expect("filtered child component target should remain");
    assert_eq!(component.config.identity.id, "/job-compose/vm_helper/root");

    let router = filtered
        .targets
        .iter()
        .find(|target| matches!(target.kind, MeshProvisionTargetKind::Router))
        .expect("filtered router target should remain");
    assert_eq!(
        router
            .config
            .peers
            .iter()
            .map(|peer| peer.id.as_str())
            .collect::<Vec<_>>(),
        vec!["/job-compose/vm_helper/root"]
    );
    assert_eq!(
        router
            .config
            .inbound
            .iter()
            .map(|route| route.route_id.clone())
            .collect::<Vec<_>>(),
        vec![
            router_export_route_id("amber_export_916351bacd5bad90", MeshProtocol::Http),
            "cap_child".to_string(),
        ]
    );
}

#[test]
fn ensure_dynamic_proxy_export_component_routes_in_artifact_adds_provider_route() {
    let temp = tempdir().expect("tempdir should be created");
    let artifact_root = temp.path();
    write_json(
        &artifact_root.join("mesh-provision-plan.json"),
        &MeshProvisionPlan {
            version: "2".to_string(),
            identity_seed: None,
            existing_peer_identities: Vec::new(),
            targets: vec![amber_mesh::MeshProvisionTarget {
                kind: MeshProvisionTargetKind::Component,
                config: amber_mesh::MeshConfigTemplate {
                    identity: amber_mesh::MeshIdentityTemplate {
                        id: "/job/root".to_string(),
                        mesh_scope: Some("scope".to_string()),
                    },
                    mesh_listen: SocketAddr::from(([127, 0, 0, 1], 23000)),
                    control_listen: None,
                    control_allow: None,
                    peers: Vec::new(),
                    inbound: Vec::new(),
                    outbound: Vec::new(),
                    transport: TransportConfig::NoiseIk {},
                },
                output: MeshProvisionOutput::Filesystem {
                    dir: "mesh/components/c8-root".to_string(),
                },
            }],
        },
    )
    .expect("mesh provision plan should be written");

    ensure_dynamic_proxy_export_component_routes_in_artifact(
        artifact_root,
        &BTreeMap::from([(
            "http".to_string(),
            test_dynamic_proxy_export_record(8, "/job/root", "http", "http", "http", 8080),
        )]),
        "/site/direct_local/router",
    )
    .expect("dynamic provider routes should be projected into the child mesh plan");

    let filtered: MeshProvisionPlan = read_json(
        &artifact_root.join("mesh-provision-plan.json"),
        "mesh provision plan",
    )
    .expect("mesh provision plan should be readable");
    let component = filtered
        .targets
        .iter()
        .find(|target| matches!(target.kind, MeshProvisionTargetKind::Component))
        .expect("component target should remain");
    assert_eq!(
        component
            .config
            .peers
            .iter()
            .map(|peer| peer.id.as_str())
            .collect::<Vec<_>>(),
        vec!["/site/direct_local/router"]
    );
    assert_eq!(
        component
            .config
            .inbound
            .iter()
            .map(|route| route.route_id.as_str())
            .collect::<Vec<_>>(),
        vec!["component:/job/root:http:http"]
    );
    assert_eq!(
        component.config.inbound[0].allowed_issuers,
        vec!["/site/direct_local/router".to_string()]
    );
}

#[test]
fn add_dynamic_proxy_export_overlay_routes_rewrites_existing_export_route() {
    let mut inbound_routes = vec![InboundRoute {
        route_id: router_dynamic_export_route_id("/job/root", "http", MeshProtocol::Http),
        capability: "http".to_string(),
        capability_kind: Some("http".to_string()),
        capability_profile: None,
        protocol: MeshProtocol::Http,
        http_plugins: Vec::new(),
        target: InboundTarget::MeshForward {
            peer_addr: "stale-service:23000".to_string(),
            peer_id: "/job/root".to_string(),
            route_id: component_route_id("/job/root", "http", MeshProtocol::Http),
            capability: "http".to_string(),
        },
        allowed_issuers: vec!["/site/kind_local/router".to_string()],
    }];

    add_dynamic_proxy_export_overlay_routes(
        &mut inbound_routes,
        &BTreeMap::from([(
            "http".to_string(),
            test_dynamic_proxy_export_record(8, "/job/root", "http", "http", "http", 8080),
        )]),
        |_| Ok("current-service:23000".to_string()),
    )
    .expect("dynamic export routes should be rewritten from the current artifact state");

    assert_eq!(inbound_routes.len(), 1);
    let InboundTarget::MeshForward {
        peer_addr,
        peer_id,
        route_id,
        capability,
    } = &inbound_routes[0].target
    else {
        panic!("export route should remain a mesh forward");
    };
    assert_eq!(peer_addr, "current-service:23000");
    assert_eq!(peer_id, "/job/root");
    assert_eq!(route_id, "component:/job/root:http:http");
    assert_eq!(capability, "http");
}

#[test]
fn child_router_overlay_payload_synthesizes_dynamic_proxy_export_routes_for_direct_children() {
    let temp = tempdir().expect("tempdir should be created");
    let artifact_root = temp.path().join("artifact");
    let runtime_root = temp.path().join("runtime");
    fs::create_dir_all(&artifact_root).expect("artifact root should be created");
    fs::create_dir_all(runtime_root.join("mesh/components/c8-root"))
        .expect("runtime mesh dir should be created");

    write_json(
        &artifact_root.join("mesh-provision-plan.json"),
        &MeshProvisionPlan {
            version: "2".to_string(),
            identity_seed: None,
            existing_peer_identities: Vec::new(),
            targets: vec![
                amber_mesh::MeshProvisionTarget {
                    kind: MeshProvisionTargetKind::Component,
                    config: amber_mesh::MeshConfigTemplate {
                        identity: amber_mesh::MeshIdentityTemplate {
                            id: "/job/root".to_string(),
                            mesh_scope: Some("scope".to_string()),
                        },
                        mesh_listen: SocketAddr::from(([127, 0, 0, 1], 23000)),
                        control_listen: None,
                        control_allow: None,
                        peers: vec![amber_mesh::MeshPeerTemplate {
                            id: "/site/direct_local/router".to_string(),
                        }],
                        inbound: vec![InboundRoute {
                            route_id: "cap_child".to_string(),
                            capability: "component".to_string(),
                            capability_kind: Some("component".to_string()),
                            capability_profile: None,
                            protocol: MeshProtocol::Http,
                            http_plugins: Vec::new(),
                            target: InboundTarget::External {
                                url_env: "AMBER_FRAMEWORK_COMPONENT_CCS_URL".to_string(),
                                optional: false,
                            },
                            allowed_issuers: vec!["/job/root".to_string()],
                        }],
                        outbound: Vec::new(),
                        transport: TransportConfig::NoiseIk {},
                    },
                    output: MeshProvisionOutput::Filesystem {
                        dir: "mesh/components/c8-root".to_string(),
                    },
                },
                amber_mesh::MeshProvisionTarget {
                    kind: MeshProvisionTargetKind::Router,
                    config: amber_mesh::MeshConfigTemplate {
                        identity: amber_mesh::MeshIdentityTemplate {
                            id: "/site/direct_local/router".to_string(),
                            mesh_scope: Some("scope".to_string()),
                        },
                        mesh_listen: SocketAddr::from(([127, 0, 0, 1], 24000)),
                        control_listen: Some(SocketAddr::from(([127, 0, 0, 1], 24100))),
                        control_allow: None,
                        peers: vec![amber_mesh::MeshPeerTemplate {
                            id: "/job/root".to_string(),
                        }],
                        inbound: vec![InboundRoute {
                            route_id: "cap_child".to_string(),
                            capability: "component".to_string(),
                            capability_kind: Some("component".to_string()),
                            capability_profile: None,
                            protocol: MeshProtocol::Http,
                            http_plugins: Vec::new(),
                            target: InboundTarget::External {
                                url_env: "AMBER_FRAMEWORK_COMPONENT_CCS_URL".to_string(),
                                optional: false,
                            },
                            allowed_issuers: vec!["/job/root".to_string()],
                        }],
                        outbound: Vec::new(),
                        transport: TransportConfig::NoiseIk {},
                    },
                    output: MeshProvisionOutput::Filesystem {
                        dir: "mesh/router".to_string(),
                    },
                },
            ],
        },
    )
    .expect("mesh provision plan should be written");
    write_dynamic_proxy_exports_metadata(
        &artifact_root,
        &BTreeMap::from([(
            "http".to_string(),
            test_dynamic_proxy_export_record(8, "/job/root", "http", "http", "http", 8080),
        )]),
    )
    .expect("dynamic proxy export metadata should be written");
    let identity = MeshIdentity::generate("/job/root", Some("scope".to_string()));
    write_json(
        &runtime_root
            .join("mesh/components/c8-root")
            .join(MESH_IDENTITY_FILENAME),
        &MeshIdentitySecret::from_identity(&identity),
    )
    .expect("mesh identity should be written");
    write_json(
        &runtime_root
            .join("mesh/components/c8-root")
            .join(MESH_CONFIG_FILENAME),
        &MeshConfigPublic {
            identity: MeshIdentityPublic {
                id: "/job/root".to_string(),
                public_key: identity.public_key,
                mesh_scope: Some("scope".to_string()),
            },
            mesh_listen: SocketAddr::from(([127, 0, 0, 1], 26000)),
            control_listen: None,
            control_allow: None,
            peers: Vec::new(),
            inbound: Vec::new(),
            outbound: Vec::new(),
            transport: TransportConfig::NoiseIk {},
        },
    )
    .expect("mesh config should be written");

    let (_peers, inbound_routes) = child_router_overlay_payload(
        &SiteActuatorPlan {
            schema: SITE_ACTUATOR_PLAN_SCHEMA.to_string(),
            version: SITE_ACTUATOR_PLAN_VERSION,
            run_id: "run-123".to_string(),
            mesh_scope: "mesh-scope-test".to_string(),
            run_root: temp.path().display().to_string(),
            site_id: "direct_local".to_string(),
            kind: SiteKind::Direct,
            router_identity_id: "/site/direct_local/router".to_string(),
            artifact_dir: artifact_root.display().to_string(),
            site_state_root: temp.path().join("state").display().to_string(),
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            storage_root: Some(temp.path().join("storage").display().to_string()),
            runtime_root: Some(runtime_root.display().to_string()),
            router_mesh_port: Some(24000),
            compose_project: None,
            kubernetes_namespace: None,
            context: None,
            observability_endpoint: None,
            launch_env: BTreeMap::new(),
        },
        &artifact_root,
        &runtime_root,
    )
    .expect("child router overlay payload should be synthesized");

    let export_route = inbound_routes
        .iter()
        .find(|route| {
            route.route_id
                == router_dynamic_export_route_id("/job/root", "http", MeshProtocol::Http)
        })
        .expect("dynamic export route should be synthesized");
    let InboundTarget::MeshForward {
        peer_addr,
        peer_id,
        route_id,
        capability,
    } = &export_route.target
    else {
        panic!("dynamic export route should forward to the child provider");
    };
    assert_eq!(peer_addr, "127.0.0.1:26000");
    assert_eq!(peer_id, "/job/root");
    assert_eq!(route_id, "component:/job/root:http:http");
    assert_eq!(capability, "http");
}

#[test]
fn prepare_dynamic_kubernetes_child_artifact_keeps_router_overlay_local() {
    let temp = tempdir().expect("tempdir should be created");
    let configmaps_dir = temp.path().join("01-configmaps");
    let rbac_dir = temp.path().join("02-rbac");
    let deployments_dir = temp.path().join("03-deployments");
    let services_dir = temp.path().join("04-services");
    let netpol_dir = temp.path().join("05-networkpolicies");
    let site_state_root = temp.path().join("state").join("kind_local");
    fs::create_dir_all(&configmaps_dir).expect("configmaps dir should exist");
    fs::create_dir_all(&rbac_dir).expect("rbac dir should exist");
    fs::create_dir_all(&deployments_dir).expect("deployments dir should exist");
    fs::create_dir_all(&services_dir).expect("services dir should exist");
    fs::create_dir_all(&netpol_dir).expect("network policies dir should exist");
    fs::create_dir_all(&site_state_root).expect("site state dir should exist");

    let full_plan = MeshProvisionPlan {
        version: "2".to_string(),
        identity_seed: None,
        existing_peer_identities: Vec::new(),
        targets: vec![
            amber_mesh::MeshProvisionTarget {
                kind: MeshProvisionTargetKind::Component,
                config: amber_mesh::MeshConfigTemplate {
                    identity: amber_mesh::MeshIdentityTemplate {
                        id: "/kind_admin".to_string(),
                        mesh_scope: Some("scope".to_string()),
                    },
                    mesh_listen: SocketAddr::from(([127, 0, 0, 1], 0)),
                    control_listen: None,
                    control_allow: None,
                    peers: vec![amber_mesh::MeshPeerTemplate {
                        id: "/site/kind_local/router".to_string(),
                    }],
                    inbound: vec![InboundRoute {
                        route_id: component_route_id("/kind_admin", "http", MeshProtocol::Http),
                        capability: "http".to_string(),
                        capability_kind: Some("http".to_string()),
                        capability_profile: None,
                        protocol: MeshProtocol::Http,
                        http_plugins: Vec::new(),
                        target: InboundTarget::Local { port: 8080 },
                        allowed_issuers: vec!["/site/kind_local/router".to_string()],
                    }],
                    outbound: Vec::new(),
                    transport: TransportConfig::NoiseIk {},
                },
                output: MeshProvisionOutput::KubernetesSecret {
                    name: "c3-kind-admin-mesh".to_string(),
                    namespace: None,
                },
            },
            amber_mesh::MeshProvisionTarget {
                kind: MeshProvisionTargetKind::Component,
                config: amber_mesh::MeshConfigTemplate {
                    identity: amber_mesh::MeshIdentityTemplate {
                        id: "/job/root".to_string(),
                        mesh_scope: Some("scope".to_string()),
                    },
                    mesh_listen: SocketAddr::from(([127, 0, 0, 1], 23007)),
                    control_listen: None,
                    control_allow: None,
                    peers: vec![amber_mesh::MeshPeerTemplate {
                        id: "/site/kind_local/router".to_string(),
                    }],
                    inbound: vec![InboundRoute {
                        route_id: component_route_id("/job/root", "http", MeshProtocol::Http),
                        capability: "http".to_string(),
                        capability_kind: Some("http".to_string()),
                        capability_profile: None,
                        protocol: MeshProtocol::Http,
                        http_plugins: Vec::new(),
                        target: InboundTarget::Local { port: 8080 },
                        allowed_issuers: vec!["/site/kind_local/router".to_string()],
                    }],
                    outbound: Vec::new(),
                    transport: TransportConfig::NoiseIk {},
                },
                output: MeshProvisionOutput::KubernetesSecret {
                    name: "c7-kind-helper-mesh".to_string(),
                    namespace: None,
                },
            },
            amber_mesh::MeshProvisionTarget {
                kind: MeshProvisionTargetKind::Router,
                config: amber_mesh::MeshConfigTemplate {
                    identity: amber_mesh::MeshIdentityTemplate {
                        id: "/site/kind_local/router".to_string(),
                        mesh_scope: Some("scope".to_string()),
                    },
                    mesh_listen: SocketAddr::from(([127, 0, 0, 1], 0)),
                    control_listen: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
                    control_allow: None,
                    peers: vec![
                        amber_mesh::MeshPeerTemplate {
                            id: "/kind_admin".to_string(),
                        },
                        amber_mesh::MeshPeerTemplate {
                            id: "/job/root".to_string(),
                        },
                    ],
                    inbound: vec![
                        InboundRoute {
                            route_id: router_export_route_id("kind_http", MeshProtocol::Http),
                            capability: "kind_http".to_string(),
                            capability_kind: Some("http".to_string()),
                            capability_profile: None,
                            protocol: MeshProtocol::Http,
                            http_plugins: Vec::new(),
                            target: InboundTarget::MeshForward {
                                peer_addr: "c3-kind-admin:23000".to_string(),
                                peer_id: "/kind_admin".to_string(),
                                route_id: component_route_id(
                                    "/kind_admin",
                                    "http",
                                    MeshProtocol::Http,
                                ),
                                capability: "http".to_string(),
                            },
                            allowed_issuers: vec!["/site/kind_local/router".to_string()],
                        },
                        InboundRoute {
                            route_id: router_export_route_id(
                                "amber_export_5062ceb53a8ac5c2",
                                MeshProtocol::Http,
                            ),
                            capability: "amber_export_5062ceb53a8ac5c2".to_string(),
                            capability_kind: Some("http".to_string()),
                            capability_profile: None,
                            protocol: MeshProtocol::Http,
                            http_plugins: Vec::new(),
                            target: InboundTarget::MeshForward {
                                peer_addr: "c7-kind-helper:23000".to_string(),
                                peer_id: "/job/root".to_string(),
                                route_id: component_route_id(
                                    "/job/root",
                                    "http",
                                    MeshProtocol::Http,
                                ),
                                capability: "http".to_string(),
                            },
                            allowed_issuers: vec!["/site/kind_local/router".to_string()],
                        },
                        InboundRoute {
                            route_id: "cap_static_admin".to_string(),
                            capability: "component".to_string(),
                            capability_kind: Some("component".to_string()),
                            capability_profile: None,
                            protocol: MeshProtocol::Http,
                            http_plugins: Vec::new(),
                            target: InboundTarget::External {
                                url_env: "AMBER_FRAMEWORK_COMPONENT_CCS_URL".to_string(),
                                optional: false,
                            },
                            allowed_issuers: vec!["/kind_admin".to_string()],
                        },
                        InboundRoute {
                            route_id: "cap_child".to_string(),
                            capability: "component".to_string(),
                            capability_kind: Some("component".to_string()),
                            capability_profile: None,
                            protocol: MeshProtocol::Http,
                            http_plugins: Vec::new(),
                            target: InboundTarget::External {
                                url_env: "AMBER_FRAMEWORK_COMPONENT_CCS_URL".to_string(),
                                optional: false,
                            },
                            allowed_issuers: vec!["/job/root".to_string()],
                        },
                    ],
                    outbound: Vec::new(),
                    transport: TransportConfig::NoiseIk {},
                },
                output: MeshProvisionOutput::KubernetesSecret {
                    name: "amber-router-external".to_string(),
                    namespace: None,
                },
            },
        ],
    };

    let full_plan_json =
        serde_json::to_string_pretty(&full_plan).expect("mesh plan should serialize");
    let indented_json = full_plan_json
        .lines()
        .map(|line| format!("    {line}"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(
        configmaps_dir.join("amber-mesh-provision.yaml"),
        format!(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: amber-mesh-provision\ndata:\n  \
             mesh-plan.json: |-\n{indented_json}\n"
        ),
    )
    .expect("mesh provision configmap should be written");
    for (path, body) in
        [
            (
                temp.path().join("kustomization.yaml"),
                r#"apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- 01-configmaps/amber-mesh-provision.yaml
- 02-rbac/amber-provisioner-job.yaml
- 02-rbac/amber-provisioner-role.yaml
- 02-rbac/amber-provisioner-rolebinding.yaml
- 02-rbac/amber-provisioner-sa.yaml
- 03-deployments/amber-router.yaml
- 03-deployments/c3-kind-admin.yaml
- 03-deployments/c7-kind-helper.yaml
- 04-services/amber-router.yaml
- 04-services/c3-kind-admin.yaml
- 04-services/c7-kind-helper.yaml
- 05-networkpolicies/amber-router-netpol.yaml
- 05-networkpolicies/c3-kind-admin-netpol.yaml
- 05-networkpolicies/c7-kind-helper-netpol.yaml
secretGenerator:
- name: amber-router-external
  envs:
  - router-external.env
"#,
            ),
            (
                temp.path().join("router-external.env"),
                "AMBER_EXTERNAL_SLOT_API_URL=\n",
            ),
            (
                rbac_dir.join("amber-provisioner-job.yaml"),
                "apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: amber-provisioner-bdcf48c3\n",
            ),
            (
                rbac_dir.join("amber-provisioner-role.yaml"),
                "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: \
                 amber-provisioner\n",
            ),
            (
                rbac_dir.join("amber-provisioner-rolebinding.yaml"),
                "apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n  name: \
                 amber-provisioner\n",
            ),
            (
                rbac_dir.join("amber-provisioner-sa.yaml"),
                "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: amber-provisioner\n",
            ),
            (
                deployments_dir.join("amber-router.yaml"),
                "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: amber-router\n  \
                 labels:\n    amber.io/component-id: router\n",
            ),
            (
                deployments_dir.join("c3-kind-admin.yaml"),
                "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: c3-kind-admin\n  \
                 labels:\n    amber.io/component-id: c3\n",
            ),
            (
                deployments_dir.join("c7-kind-helper.yaml"),
                "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: c7-kind-helper\n  \
                 labels:\n    amber.io/component-id: c7\nspec:\n  template:\n    spec:\n      \
                 initContainers:\n      - name: wait-mesh-config\n        command:\n        - \
                 /amber-helper\n        - wait-mesh-config\n        - \
                 /amber/mesh/mesh-config.json\n        - scope\n        - '30'\n      \
                 containers:\n      - name: sidecar\n        env:\n        - name: \
                 AMBER_SCENARIO_SCOPE\n          value: scope\n",
            ),
            (
                services_dir.join("amber-router.yaml"),
                "apiVersion: v1\nkind: Service\nmetadata:\n  name: amber-router\n  labels:\n    \
                 amber.io/component-id: router\n",
            ),
            (
                services_dir.join("c3-kind-admin.yaml"),
                "apiVersion: v1\nkind: Service\nmetadata:\n  name: c3-kind-admin\n  labels:\n    \
                 amber.io/component-id: c3\n",
            ),
            (
                services_dir.join("c7-kind-helper.yaml"),
                "apiVersion: v1\nkind: Service\nmetadata:\n  name: c7-kind-helper\n  labels:\n    \
                 amber.io/component-id: c7\n",
            ),
            (
                netpol_dir.join("amber-router-netpol.yaml"),
                "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: \
                 amber-router-netpol\n  labels:\n    amber.io/component-id: router\n",
            ),
            (
                netpol_dir.join("c3-kind-admin-netpol.yaml"),
                "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: \
                 c3-kind-admin-netpol\n  labels:\n    amber.io/component-id: c3\n",
            ),
            (
                netpol_dir.join("c7-kind-helper-netpol.yaml"),
                "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: \
                 c7-kind-helper-netpol\n  labels:\n    amber.io/component-id: c7\nspec:\n  \
                 podSelector:\n    matchLabels:\n      amber.io/component: c7-kind-helper\n  \
                 policyTypes:\n  - Ingress\n  ingress:\n  - from:\n    - podSelector:\n        \
                 matchLabels:\n          amber.io/component: c3-kind-admin\n    ports:\n    - \
                 protocol: TCP\n      port: 23007\n",
            ),
        ]
    {
        fs::write(path, body).expect("kubernetes artifact file should be written");
    }
    write_json(
        &site_state_root.join("manager-state.json"),
        &SiteManagerState {
            schema: SITE_STATE_SCHEMA.to_string(),
            version: SITE_STATE_VERSION,
            run_id: "run-123".to_string(),
            site_id: "kind_local".to_string(),
            kind: SiteKind::Kubernetes,
            status: SiteLifecycleStatus::Running,
            artifact_dir: temp.path().display().to_string(),
            supervisor_pid: 1,
            process_pid: None,
            compose_project: None,
            kubernetes_namespace: Some("amber-run-123-kind-local".to_string()),
            port_forward_pid: None,
            context: Some("kind-test".to_string()),
            router_control: Some("127.0.0.1:24100".to_string()),
            router_mesh_addr: Some("127.0.0.1:24000".to_string()),
            router_identity_id: Some("/site/kind_local/router".to_string()),
            router_public_key_b64: Some(
                base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
            ),
            last_error: None,
        },
    )
    .expect("site manager state should be written");

    prepare_dynamic_kubernetes_child_artifact(
        &SiteActuatorPlan {
            schema: SITE_ACTUATOR_PLAN_SCHEMA.to_string(),
            version: SITE_PLAN_VERSION,
            run_id: "run-123".to_string(),
            mesh_scope: "mesh-scope-test".to_string(),
            run_root: temp.path().display().to_string(),
            site_id: "kind_local".to_string(),
            kind: SiteKind::Kubernetes,
            router_identity_id: "/site/kind_local/router".to_string(),
            artifact_dir: temp.path().display().to_string(),
            site_state_root: site_state_root.display().to_string(),
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            storage_root: None,
            runtime_root: None,
            router_mesh_port: None,
            compose_project: None,
            kubernetes_namespace: Some("amber-run-123-kind-local".to_string()),
            context: Some("kind-test".to_string()),
            observability_endpoint: None,
            launch_env: BTreeMap::new(),
        },
        &DynamicSitePlanRecord {
            site_id: "kind_local".to_string(),
            kind: SiteKind::Kubernetes,
            router_identity_id: "/site/kind_local/router".to_string(),
            component_ids: vec![7],
            assigned_components: vec!["/job/root".to_string()],
            artifact_files: BTreeMap::new(),
            desired_artifact_files: BTreeMap::new(),
            proxy_exports: BTreeMap::from([(
                "http".to_string(),
                test_dynamic_proxy_export_record(7, "/job/root", "http", "http", "http", 8080),
            )]),
            routed_inputs: Vec::new(),
        },
        temp.path(),
        &BTreeMap::from([(
            "/site/kind_local/router".to_string(),
            MeshIdentityPublic {
                id: "/site/kind_local/router".to_string(),
                public_key: [7; 32],
                mesh_scope: Some("mesh-scope-test".to_string()),
            },
        )]),
    )
    .expect("kubernetes dynamic child artifact should be prepared");

    let overlay_plan: MeshProvisionPlan = read_json(
        &temp.path().join("mesh-provision-plan.json"),
        "mesh provision plan",
    )
    .expect("overlay mesh plan should be readable");
    assert_eq!(overlay_plan.targets.len(), 2);
    let overlay_scopes = overlay_plan
        .targets
        .iter()
        .map(|target| target.config.identity.mesh_scope.clone())
        .collect::<Vec<_>>();
    assert!(
        overlay_plan
            .targets
            .iter()
            .all(|target| target.config.identity.mesh_scope.as_deref() == Some("mesh-scope-test")),
        "dynamic kubernetes overlay plan should be projected onto the live run mesh scope: \
         {overlay_scopes:?}",
    );
    let overlay_router = overlay_plan
        .targets
        .iter()
        .find(|target| matches!(target.kind, MeshProvisionTargetKind::Router))
        .expect("overlay router target should exist");
    assert_eq!(
        overlay_router
            .config
            .peers
            .iter()
            .map(|peer| peer.id.as_str())
            .collect::<Vec<_>>(),
        vec!["/job/root"]
    );
    assert_eq!(
        overlay_router
            .config
            .inbound
            .iter()
            .map(|route| route.route_id.clone())
            .collect::<Vec<_>>(),
        vec![
            router_export_route_id("amber_export_5062ceb53a8ac5c2", MeshProtocol::Http),
            "cap_child".to_string(),
        ]
    );

    let embedded_plan = read_embedded_kubernetes_mesh_provision_plan(temp.path())
        .expect("embedded kubernetes plan should be readable");
    assert_eq!(embedded_plan.targets.len(), 1);
    assert!(
        embedded_plan
            .targets
            .iter()
            .all(|target| matches!(target.kind, MeshProvisionTargetKind::Component))
    );
    assert_eq!(
        embedded_plan.targets[0].config.identity.id, "/job/root",
        "embedded provision plan should keep only child component targets"
    );
    assert!(
        embedded_plan
            .targets
            .iter()
            .all(|target| target.config.identity.mesh_scope.as_deref() == Some("mesh-scope-test")),
        "embedded provision plan should inherit the live run mesh scope",
    );
    assert_eq!(embedded_plan.existing_peer_identities.len(), 1);
    assert_eq!(
        embedded_plan.existing_peer_identities[0].id,
        "/site/kind_local/router"
    );
    assert_eq!(
        embedded_plan.existing_peer_identities[0]
            .mesh_scope
            .as_deref(),
        Some("mesh-scope-test"),
        "existing router identity should preserve the live run mesh scope",
    );
    let helper_deployment = fs::read_to_string(deployments_dir.join("c7-kind-helper.yaml"))
        .expect("kubernetes child deployment should be readable");
    assert!(
        helper_deployment.contains("- mesh-scope-test"),
        "dynamic kubernetes deployment should rewrite the wait-mesh-config expected scope",
    );
    assert!(
        helper_deployment.contains("value: mesh-scope-test"),
        "dynamic kubernetes deployment should rewrite AMBER_SCENARIO_SCOPE onto the live run scope",
    );
    assert!(
        !helper_deployment.contains("value: scope"),
        "dynamic kubernetes deployment should not retain the compiled child scope",
    );
    let helper_netpol = fs::read_to_string(netpol_dir.join("c7-kind-helper-netpol.yaml"))
        .expect("kubernetes child network policy should be readable");
    assert!(
        helper_netpol.contains("amber.io/component: amber-router"),
        "dynamic kubernetes child network policy should admit router ingress for proxy exports",
    );
    assert!(
        helper_netpol.contains("port: 23007"),
        "dynamic kubernetes child network policy should retain the child mesh port for router \
         ingress",
    );

    let kustomization = fs::read_to_string(temp.path().join("kustomization.yaml"))
        .expect("kustomization should be readable");
    assert!(kustomization.contains("03-deployments/c7-kind-helper.yaml"));
    assert!(kustomization.contains("04-services/c7-kind-helper.yaml"));
    assert!(kustomization.contains("05-networkpolicies/c7-kind-helper-netpol.yaml"));
    assert!(kustomization.contains("02-rbac/amber-provisioner-job.yaml"));
    assert!(!kustomization.contains("03-deployments/amber-router.yaml"));
    assert!(!kustomization.contains("03-deployments/c3-kind-admin.yaml"));
    assert!(!kustomization.contains("amber-router-external"));
}

#[test]
fn kubernetes_expected_workloads_reads_current_artifact_names() {
    let temp = tempdir().expect("tempdir should be created");
    let artifact_root = temp.path();
    fs::create_dir_all(artifact_root.join("03-deployments"))
        .expect("deployment dir should be created");
    fs::create_dir_all(artifact_root.join("02-rbac")).expect("rbac dir should be created");
    fs::write(
        artifact_root.join("03-deployments").join("app.yaml"),
        r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: child-helper
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: amber-router
"#,
    )
    .expect("deployment yaml should be written");
    fs::write(
        artifact_root.join("02-rbac").join("job.yaml"),
        r#"
apiVersion: batch/v1
kind: Job
metadata:
  name: amber-provisioner-1234
"#,
    )
    .expect("job yaml should be written");

    let workloads = supervisor::kubernetes_expected_workloads(artifact_root)
        .expect("artifact workloads should parse");
    assert_eq!(workloads.jobs, vec!["amber-provisioner-1234"]);
    assert_eq!(workloads.deployments, vec!["amber-router", "child-helper"]);
}

#[test]
fn cleanup_dynamic_site_children_removes_child_roots_and_clears_state() {
    let temp = tempdir().expect("tempdir should be created");
    let site_state_root = temp.path().join("state").join("direct_local");
    let child_root = site_actuator_child_root_for_site(&site_state_root, 7);
    fs::create_dir_all(child_root.join("artifact")).expect("child artifact dir should exist");
    fs::write(child_root.join("artifact").join("marker.txt"), "marker")
        .expect("child marker should be written");
    write_json(
        &site_actuator_state_path(&site_state_root),
        &SiteActuatorState {
            schema: "amber.run.site_actuator_state".to_string(),
            version: 1,
            run_id: "run-123".to_string(),
            site_id: "direct_local".to_string(),
            kind: SiteKind::Direct,
            children: BTreeMap::from([(
                7,
                SiteActuatorChildRecord {
                    child_id: 7,
                    artifact_root: child_root.join("artifact").display().to_string(),
                    assigned_components: Vec::new(),
                    proxy_exports: BTreeMap::new(),
                    routed_inputs: Vec::new(),
                    process_pid: None,
                    published: true,
                },
            )]),
        },
    )
    .expect("site actuator state should be written");

    cleanup_dynamic_site_children(&site_state_root, SiteKind::Direct)
        .expect("dynamic site children should be cleaned");

    let state: SiteActuatorState = read_json(
        &site_actuator_state_path(&site_state_root),
        "site actuator state",
    )
    .expect("site actuator state should be readable");
    assert!(state.children.is_empty());
    assert!(!child_root.exists());
}

#[test]
fn parse_process_table_reads_ps_output() {
    assert_eq!(
        parse_process_table("  42     1\n  84   42\n").expect("process table should parse"),
        HashMap::from([(42, 1), (84, 42)])
    );
}

#[cfg(unix)]
#[test]
fn parse_process_status_code_reads_ps_state() {
    assert_eq!(parse_process_status_code("S+\n"), Some('S'));
    assert_eq!(parse_process_status_code("z\n"), Some('Z'));
    assert_eq!(parse_process_status_code("\n"), None);
}

#[cfg(unix)]
#[test]
fn collect_process_tree_postorder_visits_descendants_before_parent() {
    let children_by_parent = HashMap::from([(1, vec![2, 3]), (2, vec![4]), (3, vec![5, 6])]);
    let mut ordered = Vec::new();
    collect_process_tree_postorder(1, &children_by_parent, &mut ordered);
    assert_eq!(ordered, vec![4, 2, 5, 6, 3, 1]);
}

#[test]
fn container_host_from_resolved_ip_matches_provider_and_consumer_kind() {
    assert_eq!(
        container_host_from_resolved_ip(SiteKind::Compose, SiteKind::Direct, Some("172.17.0.1"),),
        "127.0.0.1"
    );
    assert_eq!(
        container_host_from_resolved_ip(SiteKind::Compose, SiteKind::Vm, Some("172.17.0.1"),),
        "127.0.0.1"
    );
    assert_eq!(
        container_host_from_resolved_ip(SiteKind::Vm, SiteKind::Compose, Some("172.17.0.1"),),
        CONTAINER_HOST_ALIAS
    );
    assert_eq!(
        container_host_from_resolved_ip(SiteKind::Direct, SiteKind::Compose, Some("172.17.0.1"),),
        CONTAINER_HOST_ALIAS
    );
    assert_eq!(
        container_host_from_resolved_ip(
            SiteKind::Kubernetes,
            SiteKind::Compose,
            Some("172.17.0.1"),
        ),
        "172.17.0.1"
    );
    assert_eq!(
        container_host_from_resolved_ip(SiteKind::Vm, SiteKind::Kubernetes, Some("172.17.0.1"),),
        "172.17.0.1"
    );
    assert_eq!(
        container_host_from_resolved_ip(SiteKind::Vm, SiteKind::Kubernetes, None),
        CONTAINER_HOST_ALIAS
    );
}

#[test]
fn containerized_consumers_bridge_runtime_links() {
    assert!(link_needs_bridge_proxy(SiteKind::Direct, SiteKind::Compose));
    assert!(link_needs_bridge_proxy(SiteKind::Vm, SiteKind::Compose));
    assert!(!link_needs_bridge_proxy(
        SiteKind::Kubernetes,
        SiteKind::Compose
    ));
    assert!(link_needs_bridge_proxy(
        SiteKind::Direct,
        SiteKind::Kubernetes
    ));
    assert!(link_needs_bridge_proxy(SiteKind::Vm, SiteKind::Kubernetes));
    assert!(!link_needs_bridge_proxy(
        SiteKind::Kubernetes,
        SiteKind::Kubernetes
    ));
    assert!(link_needs_bridge_proxy(
        SiteKind::Compose,
        SiteKind::Compose
    ));
    assert!(!link_needs_bridge_proxy(SiteKind::Vm, SiteKind::Direct));
}

#[test]
fn bridge_proxy_bind_and_probe_addresses_match_consumer_kind() {
    let compose_listen = bridge_proxy_bind_addr(SiteKind::Compose, 41000);
    assert_eq!(compose_listen, SocketAddr::from(([0, 0, 0, 0], 41000)));
    assert_eq!(
        bridge_proxy_probe_addr(compose_listen),
        SocketAddr::from(([127, 0, 0, 1], 41000))
    );

    let kind_listen = bridge_proxy_bind_addr(SiteKind::Kubernetes, 42000);
    assert_eq!(kind_listen, SocketAddr::from(([0, 0, 0, 0], 42000)));
    assert_eq!(
        bridge_proxy_probe_addr(kind_listen),
        SocketAddr::from(([127, 0, 0, 1], 42000))
    );

    let direct_listen = bridge_proxy_bind_addr(SiteKind::Direct, 43000);
    assert_eq!(direct_listen, SocketAddr::from(([127, 0, 0, 1], 43000)));
    assert_eq!(bridge_proxy_probe_addr(direct_listen), direct_listen);
}

#[test]
fn host_service_addressing_matches_consumer_kind() {
    assert_eq!(
        host_service_bind_addr_for_consumer(SiteKind::Compose, 41000),
        SocketAddr::from(([0, 0, 0, 0], 41000))
    );
    assert_eq!(
        host_service_bind_addr_for_consumer(SiteKind::Kubernetes, 42000),
        SocketAddr::from(([0, 0, 0, 0], 42000))
    );
    assert_eq!(
        host_service_bind_addr_for_consumer(SiteKind::Direct, 43000),
        SocketAddr::from(([127, 0, 0, 1], 43000))
    );
    assert_eq!(
        host_service_bind_addr_for_consumer(SiteKind::Vm, 44000),
        SocketAddr::from(([127, 0, 0, 1], 44000))
    );
    assert_eq!(
        host_service_host_for_consumer(SiteKind::Compose),
        "host.docker.internal"
    );
    assert_eq!(
        host_service_host_for_consumer(SiteKind::Direct),
        "127.0.0.1"
    );
    assert_eq!(host_service_host_for_consumer(SiteKind::Vm), "127.0.0.1");
    assert_eq!(
        host_service_host_for_consumer(SiteKind::Kubernetes),
        container_host_for_consumer(SiteKind::Direct, SiteKind::Kubernetes)
    );
}

#[test]
fn bridge_proxy_external_url_uses_consumer_aware_host() {
    assert_eq!(
        bridge_proxy_external_url(44000, NetworkProtocol::Http, SiteKind::Compose)
            .expect("http bridge proxy url should be valid"),
        "http://host.docker.internal:44000"
    );
    assert_eq!(
        bridge_proxy_external_url(45000, NetworkProtocol::Http, SiteKind::Kubernetes)
            .expect("http bridge proxy url should be valid"),
        format!(
            "http://{}:45000",
            host_service_host_for_consumer(SiteKind::Kubernetes)
        )
    );
}

#[test]
fn outside_proxy_mesh_listener_stays_loopback_for_local_consumers() {
    let context = RunOutsideProxyContext {
        mesh_scope: "scope".to_string(),
        sites: BTreeMap::from([(
            "direct".to_string(),
            test_launched_site_with_kind(SiteKind::Direct),
        )]),
        exports: BTreeMap::new(),
        slots: BTreeMap::from([(
            "api".to_string(),
            RunOutsideSlot {
                required: true,
                kind: CapabilityKind::Http,
                url_env: "AMBER_EXTERNAL_SLOT_API_URL".to_string(),
                consumer_sites: vec!["direct".to_string()],
            },
        )]),
    };

    assert_eq!(
        outside_proxy_mesh_listen_addr(
            &context,
            &[("api".to_string(), "http://127.0.0.1:9000".to_string())],
            48000,
        )
        .expect("outside proxy bind addr"),
        SocketAddr::from(([127, 0, 0, 1], 48000))
    );
}

#[test]
fn outside_proxy_mesh_listener_expands_for_container_consumers() {
    let context = RunOutsideProxyContext {
        mesh_scope: "scope".to_string(),
        sites: BTreeMap::from([
            (
                "direct".to_string(),
                test_launched_site_with_kind(SiteKind::Direct),
            ),
            (
                "compose".to_string(),
                test_launched_site_with_kind(SiteKind::Compose),
            ),
        ]),
        exports: BTreeMap::new(),
        slots: BTreeMap::from([(
            "api".to_string(),
            RunOutsideSlot {
                required: true,
                kind: CapabilityKind::Http,
                url_env: "AMBER_EXTERNAL_SLOT_API_URL".to_string(),
                consumer_sites: vec!["direct".to_string(), "compose".to_string()],
            },
        )]),
    };

    assert_eq!(
        outside_proxy_mesh_listen_addr(
            &context,
            &[("api".to_string(), "http://127.0.0.1:9000".to_string())],
            49000,
        )
        .expect("outside proxy bind addr"),
        SocketAddr::from(([0, 0, 0, 0], 49000))
    );
}

#[test]
fn bridge_proxy_export_binding_uses_selected_listen_addr() {
    assert_eq!(
        bridge_proxy_export_binding("api", SocketAddr::from(([127, 0, 0, 1], 46000))),
        "api=127.0.0.1:46000"
    );
    assert_eq!(
        bridge_proxy_export_binding("api", SocketAddr::from(([0, 0, 0, 0], 47000))),
        "api=0.0.0.0:47000"
    );
}

fn test_launched_site_with_kind(kind: SiteKind) -> LaunchedSite {
    LaunchedSite {
        receipt: SiteReceipt {
            kind,
            artifact_dir: "/tmp/artifact".to_string(),
            supervisor_pid: 1,
            process_pid: None,
            compose_project: None,
            context: None,
            kubernetes_namespace: None,
            port_forward_pid: None,
            router_mesh_addr: None,
            router_control: None,
            router_identity_id: None,
            router_public_key_b64: None,
        },
        router_identity: MeshIdentityPublic {
            id: format!("/site/{kind:?}"),
            public_key: [0; 32],
            mesh_scope: None,
        },
        router_addr: SocketAddr::from(([127, 0, 0, 1], 24000)),
        router_control: ControlEndpoint::Tcp("127.0.0.1:24100".to_string()),
    }
}

#[test]
fn kubernetes_sites_get_startup_budget_after_workloads_are_ready() {
    assert_eq!(
        site_ready_timeout_for_kind(SiteKind::Kubernetes),
        KUBERNETES_WORKLOAD_READY_TIMEOUT + KUBERNETES_SITE_READY_BUFFER
    );
}

#[test]
fn kubernetes_namespace_name_is_run_scoped() {
    assert_eq!(
        kubernetes_namespace_name("run-1234abcd", "kind_c"),
        "amber-run-1234abcd-kind-c"
    );
    assert_ne!(
        kubernetes_namespace_name("run-1234abcd", "kind_c"),
        kubernetes_namespace_name("run-5678efgh", "kind_c")
    );
}

#[test]
fn prepare_kubernetes_artifact_namespace_rewrites_kustomization_namespace() {
    let temp = tempdir().expect("tempdir should be created");
    let kustomization = temp.path().join("kustomization.yaml");
    fs::write(
        &kustomization,
        "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nnamespace: \
         scenario-old\n",
    )
    .expect("kustomization should be written");

    let namespace = prepare_kubernetes_artifact_namespace("run-1234abcd", "kind_c", temp.path())
        .expect("artifact namespace should be prepared");

    assert_eq!(namespace, "amber-run-1234abcd-kind-c");
    assert_eq!(
        fs::read_to_string(&kustomization).expect("kustomization should be readable"),
        "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nnamespace: \
         amber-run-1234abcd-kind-c\n"
    );
}

#[test]
fn prepare_kubernetes_site_artifact_for_apply_rewrites_runtime_artifact_state() {
    let temp = tempdir().expect("tempdir should be created");
    let kustomization = temp.path().join("kustomization.yaml");
    fs::write(
        &kustomization,
        "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nnamespace: \
         scenario-old\n",
    )
    .expect("kustomization should be written");
    let env_file = temp.path().join("root-config.env");
    fs::write(&env_file, "AMBER_TEST_VALUE=stale\n").expect("env file should be written");

    let mut launch_env = BTreeMap::new();
    launch_env.insert("AMBER_TEST_VALUE".to_string(), "fresh".to_string());
    let plan = SiteActuatorPlan {
        schema: SITE_ACTUATOR_PLAN_SCHEMA.to_string(),
        version: SITE_PLAN_VERSION,
        run_id: "run-1234abcd".to_string(),
        mesh_scope: "mesh-scope-test".to_string(),
        run_root: temp.path().display().to_string(),
        site_id: "kind_c".to_string(),
        kind: SiteKind::Kubernetes,
        router_identity_id: "/site/kind_c/router".to_string(),
        artifact_dir: temp.path().display().to_string(),
        site_state_root: temp.path().join("state").display().to_string(),
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        storage_root: None,
        runtime_root: None,
        router_mesh_port: None,
        compose_project: None,
        kubernetes_namespace: None,
        context: Some("kind-test".to_string()),
        observability_endpoint: None,
        launch_env,
    };

    let supervisor_plan =
        prepare_kubernetes_site_artifact_for_apply(&plan).expect("artifact should be prepared");

    assert_eq!(
        supervisor_plan.kubernetes_namespace.as_deref(),
        Some("amber-run-1234abcd-kind-c")
    );
    assert_eq!(
        fs::read_to_string(&kustomization).expect("kustomization should be readable"),
        "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nnamespace: \
         amber-run-1234abcd-kind-c\n"
    );
    assert_eq!(
        fs::read_to_string(&env_file).expect("env file should be readable"),
        "AMBER_TEST_VALUE=fresh\n"
    );
}

#[test]
fn external_slot_name_from_env_var_restores_slot_name() {
    assert_eq!(
        external_slot_name_from_env_var("AMBER_EXTERNAL_SLOT_API_URL"),
        "api"
    );
}

#[test]
fn external_slot_env_for_site_skips_missing_weak_provider() {
    let env = external_slot_env_for_site(
        "consumer_site",
        SiteKind::Direct,
        &[RunLink {
            provider_site: "provider_site".to_string(),
            consumer_site: "consumer_site".to_string(),
            provider_component: "/provider".to_string(),
            provide: "api".to_string(),
            consumer_component: "/consumer".to_string(),
            slot: "upstream".to_string(),
            weak: true,
            protocol: NetworkProtocol::Http,
            export_name: "amber_export_provider_api_http".to_string(),
            external_slot_name: "amber_link_consumer_provider_api_http".to_string(),
        }],
        &BTreeMap::new(),
    )
    .expect("weak links should not require a launched provider");
    assert!(env.is_empty());
}

#[test]
fn maybe_resolve_proxy_run_target_resolves_run_id_and_prefers_live_state() {
    let temp = tempdir().expect("tempdir should exist");
    let storage_root = temp.path();
    let run_id = "run-123";
    let run_root = storage_root.join("runs").join(run_id);
    let artifact_dir = run_root.join("sites").join("direct_local").join("artifact");
    fs::create_dir_all(&artifact_dir).expect("artifact dir should exist");
    let state_root = run_root.join("state");
    fs::create_dir_all(state_root.join("direct_local")).expect("state dir should exist");

    let receipt = RunReceipt {
        schema: RECEIPT_SCHEMA.to_string(),
        version: RECEIPT_VERSION,
        run_id: run_id.to_string(),
        mesh_scope: "mesh.scope.test".to_string(),
        plan_path: run_plan_path(&run_root).display().to_string(),
        source_plan_path: None,
        run_root: run_root.display().to_string(),
        framework_control_state: None,
        observability: None,
        bridge_proxies: Vec::new(),
        sites: BTreeMap::from([(
            "direct_local".to_string(),
            test_site_receipt(
                SiteKind::Direct,
                &artifact_dir,
                Some("unix:///receipt.sock"),
                Some("127.0.0.1:18080"),
            ),
        )]),
    };
    write_json(&receipt_path(&run_root), &receipt).expect("receipt should serialize");
    write_json(
        &site_state_path(&state_root, "direct_local"),
        &test_site_state(
            run_id,
            "direct_local",
            SiteKind::Direct,
            &artifact_dir,
            Some("unix:///live.sock"),
            Some("127.0.0.1:18081"),
        ),
    )
    .expect("state should serialize");

    let resolved = maybe_resolve_proxy_run_target(run_id, Some("direct_local"), Some(storage_root))
        .expect("run target resolution should succeed")
        .expect("run target should resolve");

    assert_eq!(
        resolved.artifact_dir,
        artifact_dir
            .canonicalize()
            .expect("artifact dir should canonicalize")
    );
    assert_eq!(
        resolved.router_control_addr.as_deref(),
        Some("unix:///live.sock")
    );
    assert_eq!(
        resolved.router_addr,
        Some(
            "127.0.0.1:18081"
                .parse::<SocketAddr>()
                .expect("socket addr should parse")
        )
    );
}

#[test]
fn maybe_resolve_proxy_run_target_requires_site_for_multi_site_run() {
    let temp = tempdir().expect("tempdir should exist");
    let storage_root = temp.path();
    let run_id = "run-456";
    let run_root = storage_root.join("runs").join(run_id);
    let direct_artifact = run_root.join("sites").join("direct_local").join("artifact");
    let compose_artifact = run_root
        .join("sites")
        .join("compose_local")
        .join("artifact");
    fs::create_dir_all(&direct_artifact).expect("direct artifact dir should exist");
    fs::create_dir_all(&compose_artifact).expect("compose artifact dir should exist");

    let receipt = RunReceipt {
        schema: RECEIPT_SCHEMA.to_string(),
        version: RECEIPT_VERSION,
        run_id: run_id.to_string(),
        mesh_scope: "mesh.scope.test".to_string(),
        plan_path: run_plan_path(&run_root).display().to_string(),
        source_plan_path: None,
        run_root: run_root.display().to_string(),
        framework_control_state: None,
        observability: None,
        bridge_proxies: Vec::new(),
        sites: BTreeMap::from([
            (
                "compose_local".to_string(),
                test_site_receipt(
                    SiteKind::Compose,
                    &compose_artifact,
                    Some("unix:///compose.sock"),
                    Some("127.0.0.1:19090"),
                ),
            ),
            (
                "direct_local".to_string(),
                test_site_receipt(
                    SiteKind::Direct,
                    &direct_artifact,
                    Some("unix:///direct.sock"),
                    Some("127.0.0.1:19091"),
                ),
            ),
        ]),
    };
    write_json(&receipt_path(&run_root), &receipt).expect("receipt should serialize");

    let err = maybe_resolve_proxy_run_target(run_id, None, Some(storage_root))
        .expect_err("multi-site run ids should require --site");
    let message = err.to_string();
    assert!(
        message.contains("contains multiple sites"),
        "expected multi-site guidance, got: {message}"
    );
    assert!(
        message.contains("--site <site-id>"),
        "expected --site guidance, got: {message}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn stop_run_forces_supervisor_shutdown_and_cleans_up() {
    let temp = tempdir().expect("tempdir should exist");
    let storage_root = temp.path();
    let run_id = "run-stuck";
    let run_root = storage_root.join("runs").join(run_id);
    let artifact_dir = run_root.join("sites").join("direct_local").join("artifact");
    fs::create_dir_all(&artifact_dir).expect("artifact dir should exist");

    let mut stubborn_supervisor = Command::new("sh")
        .arg("-c")
        .arg("trap '' TERM; while :; do sleep 1 & wait $!; done")
        .spawn()
        .expect("stubborn supervisor should spawn");

    let receipt = RunReceipt {
        schema: RECEIPT_SCHEMA.to_string(),
        version: RECEIPT_VERSION,
        run_id: run_id.to_string(),
        mesh_scope: "mesh.scope.test".to_string(),
        plan_path: run_plan_path(&run_root).display().to_string(),
        source_plan_path: None,
        run_root: run_root.display().to_string(),
        framework_control_state: None,
        observability: None,
        bridge_proxies: Vec::new(),
        sites: BTreeMap::from([(
            "direct_local".to_string(),
            SiteReceipt {
                supervisor_pid: stubborn_supervisor.id(),
                ..test_site_receipt(
                    SiteKind::Direct,
                    &artifact_dir,
                    Some("unix:///receipt.sock"),
                    Some("127.0.0.1:18080"),
                )
            },
        )]),
    };
    write_json(&receipt_path(&run_root), &receipt).expect("receipt should serialize");

    let state_root = run_root.join("state");
    let mut state = test_site_state(
        run_id,
        "direct_local",
        SiteKind::Direct,
        &artifact_dir,
        Some("unix:///live.sock"),
        Some("127.0.0.1:18081"),
    );
    state.status = SiteLifecycleStatus::Stopped;
    state.supervisor_pid = stubborn_supervisor.id();
    write_json(&site_state_path(&state_root, "direct_local"), &state)
        .expect("state should serialize");

    let result = stop_run(run_id, Some(storage_root)).await;

    let _ = stubborn_supervisor.kill();
    let _ = stubborn_supervisor.wait();

    result.expect("stop_run should force the supervisor down and succeed");
    assert!(
        !receipt_path(&run_root).is_file(),
        "receipt should be removed after forced shutdown cleanup"
    );
    assert!(
        stop_marker_path(&run_root).is_file(),
        "stop marker should be written for supervisors"
    );

    let updated_state: SiteManagerState = read_json(
        &site_state_path(&state_root, "direct_local"),
        "site manager state",
    )
    .expect("updated state should deserialize");
    assert_eq!(updated_state.status, SiteLifecycleStatus::Stopped);
    assert!(
        updated_state.last_error.as_deref().is_some_and(|value| {
            value.contains("forcing shutdown") || value.contains("exited before confirming stop")
        }),
        "expected escalated shutdown cleanup to be recorded, got: {:?}",
        updated_state.last_error
    );
}

#[cfg(unix)]
#[tokio::test]
async fn stop_bridge_proxies_terminates_dynamic_children() {
    let temp = tempdir().expect("tempdir should exist");
    let child = Command::new("sh")
        .current_dir(temp.path())
        .arg("-c")
        .arg("sleep 30")
        .spawn()
        .expect("bridge proxy child should spawn");
    let pid = child.id();

    let mut bridge_proxies = BTreeMap::from([(
        BridgeProxyKey {
            provider_output_dir: temp.path().display().to_string(),
            export_name: "amber_export_test".to_string(),
            consumer_kind: SiteKind::Compose,
        },
        BridgeProxyHandle {
            child,
            export_name: "amber_export_test".to_string(),
            listen: SocketAddr::from(([127, 0, 0, 1], 46000)),
        },
    )]);

    stop_bridge_proxies(&mut bridge_proxies)
        .await
        .expect("bridge proxies should stop cleanly");

    assert!(
        bridge_proxies.is_empty(),
        "bridge proxy cleanup should remove all tracked proxies"
    );
    assert!(
        !pid_is_alive(pid),
        "bridge proxy cleanup should terminate the owned child process"
    );
}
