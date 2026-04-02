use std::collections::BTreeMap;

use tempfile::tempdir;

use super::*;
use crate::framework_component::DynamicProxyExportRecord;

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
                DynamicProxyExportRecord {
                    component: "/job/root".to_string(),
                    provide: "http".to_string(),
                    protocol: "http".to_string(),
                },
            )]),
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

fn write_compose_artifact_with_mesh_plan(artifact_root: &Path, plan: &MeshProvisionPlan) {
    fs::create_dir_all(artifact_root).expect("compose artifact root should exist");
    let plan_json = serde_json::to_string(plan).expect("mesh provision plan should serialize");
    fs::write(
        artifact_root.join("compose.yaml"),
        format!(
            "configs:\n  amber-mesh-provision-plan:\n    content: '{}'\n",
            plan_json
        ),
    )
    .expect("compose artifact should be written");
}

#[test]
fn patch_dynamic_compose_site_mesh_plan_projects_child_routes_into_site_artifact() {
    let temp = tempdir().expect("tempdir should be created");
    let site_artifact = temp.path().join("site");
    let child_artifact = temp.path().join("child");
    let site_plan = MeshProvisionPlan {
        version: "2".to_string(),
        identity_seed: None,
        targets: vec![
            amber_mesh::MeshProvisionTarget {
                kind: MeshProvisionTargetKind::Component,
                config: amber_mesh::MeshConfigTemplate {
                    identity: amber_mesh::MeshIdentityTemplate {
                        id: "/job".to_string(),
                        mesh_scope: Some("scope".to_string()),
                    },
                    mesh_listen: SocketAddr::from(([0, 0, 0, 0], 23000)),
                    control_listen: None,
                    control_allow: None,
                    peers: Vec::new(),
                    inbound: Vec::new(),
                    outbound: Vec::new(),
                    transport: TransportConfig::NoiseIk {},
                },
                output: MeshProvisionOutput::Filesystem {
                    dir: "/amber/provision/c2-job-net".to_string(),
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
                    peers: Vec::new(),
                    inbound: Vec::new(),
                    outbound: Vec::new(),
                    transport: TransportConfig::NoiseIk {},
                },
                output: MeshProvisionOutput::Filesystem {
                    dir: "/amber/provision/amber-router".to_string(),
                },
            },
        ],
    };
    let child_plan = MeshProvisionPlan {
        version: "2".to_string(),
        identity_seed: None,
        targets: vec![
            amber_mesh::MeshProvisionTarget {
                kind: MeshProvisionTargetKind::Component,
                config: amber_mesh::MeshConfigTemplate {
                    identity: amber_mesh::MeshIdentityTemplate {
                        id: "/job".to_string(),
                        mesh_scope: Some("scope".to_string()),
                    },
                    mesh_listen: SocketAddr::from(([0, 0, 0, 0], 23000)),
                    control_listen: None,
                    control_allow: None,
                    peers: vec![amber_mesh::MeshPeerTemplate {
                        id: "/site/compose_local/router".to_string(),
                    }],
                    inbound: vec![InboundRoute {
                        route_id: component_route_id("/job", "http", MeshProtocol::Http),
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
                    dir: "/amber/provision/c1-job-net".to_string(),
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
                    peers: vec![amber_mesh::MeshPeerTemplate {
                        id: "/job".to_string(),
                    }],
                    inbound: vec![InboundRoute {
                        route_id: router_export_route_id("http", MeshProtocol::Http),
                        capability: "http".to_string(),
                        capability_kind: Some("http".to_string()),
                        capability_profile: None,
                        protocol: MeshProtocol::Http,
                        http_plugins: Vec::new(),
                        target: InboundTarget::MeshForward {
                            peer_addr: "c1-job-net:23000".to_string(),
                            peer_id: "/job".to_string(),
                            route_id: component_route_id("/job", "http", MeshProtocol::Http),
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
    write_compose_artifact_with_mesh_plan(&site_artifact, &site_plan);
    write_compose_artifact_with_mesh_plan(&child_artifact, &child_plan);

    patch_dynamic_compose_site_mesh_plan(&site_artifact, &child_artifact)
        .expect("compose site mesh plan should be patched");

    let patched = read_embedded_compose_mesh_provision_plan(&site_artifact)
        .expect("patched mesh provision plan should be readable");
    let component = patched
        .targets
        .iter()
        .find(|target| {
            matches!(target.kind, MeshProvisionTargetKind::Component)
                && target.config.identity.id == "/job"
        })
        .expect("patched component target should exist");
    assert_eq!(component.config.peers.len(), 1);
    assert_eq!(component.config.peers[0].id, "/site/compose_local/router");
    assert_eq!(component.config.inbound.len(), 1);
    assert_eq!(
        component.config.inbound[0].route_id,
        component_route_id("/job", "http", MeshProtocol::Http)
    );

    let router = patched
        .targets
        .iter()
        .find(|target| matches!(target.kind, MeshProvisionTargetKind::Router))
        .expect("patched router target should exist");
    assert_eq!(router.config.peers.len(), 1);
    assert_eq!(router.config.peers[0].id, "/job");
    assert_eq!(router.config.inbound.len(), 1);
    let InboundTarget::MeshForward { peer_addr, .. } = &router.config.inbound[0].target else {
        panic!("patched router route should be a mesh-forward route");
    };
    assert_eq!(peer_addr, "c2-job-net:23000");
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
    assert!(link_needs_bridge_proxy(
        SiteKind::Kubernetes,
        SiteKind::Compose
    ));
    assert!(link_needs_bridge_proxy(
        SiteKind::Direct,
        SiteKind::Kubernetes
    ));
    assert!(link_needs_bridge_proxy(SiteKind::Vm, SiteKind::Kubernetes));
    assert!(link_needs_bridge_proxy(
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
            bridge_proxy_host_for_consumer(SiteKind::Kubernetes)
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
