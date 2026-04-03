use std::sync::{Mutex, OnceLock};

use super::*;

struct EnvVarRestore {
    name: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvVarRestore {
    fn set(name: &'static str, value: &str) -> Self {
        let previous = env::var_os(name);
        unsafe {
            env::set_var(name, value);
        }
        Self { name, previous }
    }

    fn set_os(name: &'static str, value: &std::ffi::OsStr) -> Self {
        let previous = env::var_os(name);
        unsafe {
            env::set_var(name, value);
        }
        Self { name, previous }
    }
}

impl Drop for EnvVarRestore {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => unsafe {
                env::set_var(self.name, value);
            },
            None => unsafe {
                env::remove_var(self.name);
            },
        }
    }
}

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn port_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn reserve_test_port() -> SocketAddr {
    let listener =
        TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("listener should bind");
    let addr = listener
        .local_addr()
        .expect("listener should report its local address");
    drop(listener);
    addr
}

#[cfg(unix)]
fn with_fake_compose_runtime<F>(script: &str, test: F)
where
    F: FnOnce(),
{
    use std::os::unix::fs::PermissionsExt as _;

    let _env_guard = env_lock().lock().expect("env lock should not be poisoned");
    let temp = tempfile::tempdir().expect("temp dir should be created");
    let docker_path = temp.path().join("docker");
    fs::write(&docker_path, script).expect("fake docker script should be written");
    let mut perms = fs::metadata(&docker_path)
        .expect("fake docker script should exist")
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&docker_path, perms).expect("fake docker script should be executable");

    let original_path = env::var_os("PATH").unwrap_or_default();
    let mut updated_path = std::ffi::OsString::from(temp.path().as_os_str());
    updated_path.push(std::ffi::OsStr::new(":"));
    updated_path.push(&original_path);
    let _path = EnvVarRestore::set_os("PATH", &updated_path);

    test();
}

#[test]
fn proxy_builder_rejects_non_loopback_slot_upstreams() {
    let mut proxy = ProxyCommand::new("/tmp/out");
    let err = proxy
        .add_slot_binding("api", "192.0.2.10:8080".parse().expect("socket address"))
        .expect_err("non-loopback upstream should be rejected");
    assert!(err.to_string().contains("loopback upstream"), "{err}");
}

#[test]
fn proxy_builder_rejects_duplicate_slot_bindings() {
    let mut proxy = ProxyCommand::new("/tmp/out");
    proxy
        .add_slot_binding("api", "127.0.0.1:8080".parse().expect("socket address"))
        .expect("first binding should succeed");
    let err = proxy
        .add_slot_binding("api", "127.0.0.1:8081".parse().expect("socket address"))
        .expect_err("duplicate binding should fail");
    assert!(
        err.to_string().contains("duplicate --slot binding"),
        "{err}"
    );
}

#[test]
fn proxy_prepare_requires_at_least_one_binding() {
    let rt = tokio::runtime::Runtime::new().expect("runtime should start");
    let err = rt
        .block_on(async { ProxyCommand::new("/tmp/out").prepare().await })
        .expect_err("missing bindings should be rejected");
    assert!(err.to_string().contains("at least one --slot"), "{err}");
}

fn test_proxy_target(kind: ProxyTargetKind) -> ProxyTarget {
    ProxyTarget {
        kind,
        metadata: ProxyMetadata {
            version: PROXY_METADATA_VERSION.to_string(),
            ..Default::default()
        },
        source: PathBuf::from("/tmp/out"),
    }
}

#[test]
fn reserve_mesh_addresses_for_compose_keeps_listener_public() {
    let target = test_proxy_target(ProxyTargetKind::DockerCompose);

    let (mesh_addr, listen, listener) =
        reserve_mesh_addresses(None, &target).expect("mesh listener should reserve");

    assert_eq!(mesh_addr, format!("host.docker.internal:{}", listen.port()));
    assert!(
        listen.ip().is_unspecified(),
        "compose proxy mesh listener must stay reachable from containers"
    );
    assert_eq!(
        listener
            .local_addr()
            .expect("reserved listener should report its address"),
        listen
    );
}

#[test]
fn reserve_mesh_addresses_for_direct_keeps_listener_loopback() {
    let target = test_proxy_target(ProxyTargetKind::Direct);

    let (mesh_addr, listen, listener) =
        reserve_mesh_addresses(None, &target).expect("mesh listener should reserve");

    assert_eq!(mesh_addr, format!("127.0.0.1:{}", listen.port()));
    assert!(
        listen.ip().is_loopback(),
        "direct proxy mesh listener should stay local to the host"
    );
    assert_eq!(
        listener
            .local_addr()
            .expect("reserved listener should report its address"),
        listen
    );
}

#[test]
fn reserve_mesh_addresses_rewrites_ephemeral_override_port() {
    let target = test_proxy_target(ProxyTargetKind::Direct);

    let (mesh_addr, listen, _listener) =
        reserve_mesh_addresses(Some("127.0.0.1:0"), &target).expect("mesh listener should reserve");

    assert_eq!(mesh_addr, format!("127.0.0.1:{}", listen.port()));
    assert_ne!(listen.port(), 0);
}

#[test]
fn reserve_export_bindings_hold_reserved_ports_until_drop() {
    let _port_guard = port_lock()
        .lock()
        .expect("port lock should not be poisoned");
    let requested_port = reserve_test_port();
    let requested = [ExportBinding {
        export: "api".to_string(),
        listen: requested_port,
    }];

    let (bindings, listeners) =
        reserve_export_bindings(&requested).expect("export listeners should reserve");
    let actual = bindings
        .first()
        .expect("reserved export should exist")
        .listen;

    assert_ne!(actual.port(), 0);
    assert!(
        TcpListener::bind(actual).is_err(),
        "reserved export port should stay occupied until the reservation is dropped"
    );

    drop(listeners);
    TcpListener::bind(actual).expect("dropping the reservation should release the port");
}

#[tokio::test]
async fn reserve_export_bindings_preserve_duplicate_export_listeners() {
    let _port_guard = port_lock()
        .lock()
        .expect("port lock should not be poisoned");
    let requested = vec![
        ExportBinding {
            export: "api".to_string(),
            listen: reserve_test_port(),
        },
        ExportBinding {
            export: "api".to_string(),
            listen: reserve_test_port(),
        },
    ];

    let (bindings, listeners) =
        reserve_export_bindings(&requested).expect("export listeners should reserve");
    let routes = vec![
        OutboundRoute {
            route_id: "duplicate-route".to_string(),
            slot: "api".to_string(),
            capability_kind: None,
            capability_profile: None,
            listen_port: bindings[0].listen.port(),
            listen_addr: Some(bindings[0].listen.ip().to_string()),
            protocol: MeshProtocol::Http,
            http_plugins: Vec::new(),
            peer_addr: "127.0.0.1:1".to_string(),
            peer_id: "/router".to_string(),
            capability: "api".to_string(),
        },
        OutboundRoute {
            route_id: "duplicate-route".to_string(),
            slot: "api".to_string(),
            capability_kind: None,
            capability_profile: None,
            listen_port: bindings[1].listen.port(),
            listen_addr: Some(bindings[1].listen.ip().to_string()),
            protocol: MeshProtocol::Http,
            http_plugins: Vec::new(),
            peer_addr: "127.0.0.1:1".to_string(),
            peer_id: "/router".to_string(),
            capability: "api".to_string(),
        },
    ];

    let listeners = listeners
        .into_router_prebound(&routes)
        .expect("duplicate export listeners should convert");

    assert!(
        TcpListener::bind(bindings[0].listen).is_err(),
        "the first duplicate listener should still be reserved after conversion"
    );
    assert!(
        TcpListener::bind(bindings[1].listen).is_err(),
        "the second duplicate listener should still be reserved after conversion"
    );

    drop(listeners);
    TcpListener::bind(bindings[0].listen)
        .expect("dropping the converted listeners should release the first port");
    TcpListener::bind(bindings[1].listen)
        .expect("dropping the converted listeners should release the second port");
}

#[test]
fn parse_matching_compose_project_names_filters_to_target_compose_file() {
    let projects = parse_matching_compose_project_names(
        "alpha\t/tmp/amber.yaml\n\nbeta\t/tmp/other.yaml\n gamma \t /tmp/amber.yaml \n",
        Path::new("/tmp/amber.yaml"),
    );
    assert_eq!(
        projects,
        BTreeSet::from(["alpha".to_string(), "gamma".to_string()])
    );
}

#[test]
fn choose_compose_project_name_prefers_single_running_stack() {
    let discovered = BTreeSet::from(["custom-stack".to_string()]);
    let selected =
        choose_compose_project_name(None, &discovered, Some("tmp"), Path::new("/tmp/amber.yaml"))
            .expect("selection should succeed");
    assert_eq!(selected.as_deref(), Some("custom-stack"));
}

#[test]
fn choose_compose_project_name_prefers_env_override() {
    let discovered = BTreeSet::from(["custom-stack".to_string()]);
    let selected = choose_compose_project_name(
        Some("from-env"),
        &discovered,
        Some("tmp"),
        Path::new("/tmp/amber.yaml"),
    )
    .expect("selection should succeed");
    assert_eq!(selected.as_deref(), Some("from-env"));
}

#[test]
fn resolve_compose_project_name_prefers_router_metadata_project() {
    let selected = resolve_compose_project_name(
        None,
        Some("dynamic-stack"),
        Path::new("/tmp/child/compose.yaml"),
    )
    .expect("selection should succeed");
    assert_eq!(selected.as_deref(), Some("dynamic-stack"));
}

#[test]
fn choose_compose_project_name_rejects_multiple_running_stacks() {
    let discovered = BTreeSet::from(["stack-a".to_string(), "stack-b".to_string()]);
    let err =
        choose_compose_project_name(None, &discovered, Some("tmp"), Path::new("/tmp/amber.yaml"))
            .expect_err("selection should fail");
    let rendered = err.to_string();
    assert!(rendered.contains("stack-a"), "{rendered}");
    assert!(rendered.contains("stack-b"), "{rendered}");
    assert!(rendered.contains("--project-name"), "{rendered}");
}

#[test]
#[cfg(unix)]
fn discover_running_compose_projects_handles_override_stacks() {
    with_fake_compose_runtime(
        r#"#!/bin/sh
if [ "$1" = "ps" ]; then
  shift
  args="$*"
  case "$args" in
    *"label=com.docker.compose.service=amber-router"*'{{.Label "com.docker.compose.project"}}'*'{{.Label "com.docker.compose.project.config_files"}}'*)
      printf '%s\t%s\n' override-stack /tmp/amber.yaml
      printf '%s\t%s\n' unrelated-stack /tmp/other.yaml
      exit 0
      ;;
  esac
  exit 0
fi
exit 1
"#,
        || {
            let projects = discover_running_compose_projects(Path::new("/tmp/amber.yaml"));
            assert_eq!(projects, BTreeSet::from(["override-stack".to_string()]));
        },
    );
}

#[test]
fn compose_project_config_files_match_accepts_multi_file_labels() {
    assert!(compose_project_config_files_match(
        "/tmp/base.yaml,/tmp/amber.yaml",
        "/tmp/amber.yaml"
    ));
    assert!(!compose_project_config_files_match(
        "/tmp/base.yaml,/tmp/other.yaml",
        "/tmp/amber.yaml"
    ));
}

#[test]
#[cfg(unix)]
fn find_running_compose_service_container_handles_override_stacks() {
    with_fake_compose_runtime(
        r#"#!/bin/sh
if [ "$1" = "ps" ]; then
  shift
  args="$*"
  case "$args" in
    *"label=com.docker.compose.project=override-stack"*\
*"label=com.docker.compose.service=amber-router"*\
*"{{.ID}}"*)
      printf '%s\n' container-123
      exit 0
      ;;
  esac
  exit 0
fi
exit 1
"#,
        || {
            let container = find_running_compose_service_container(
                Path::new("/tmp/amber.yaml"),
                "override-stack",
                COMPOSE_ROUTER_SERVICE_NAME,
            )
            .expect("container should be found");
            assert_eq!(container.runtime, "docker");
            assert_eq!(container.id, "container-123");
        },
    );
}

#[test]
fn expand_env_templates_prefers_explicit_compose_project_name() {
    let _compose_project = EnvVarRestore::set(COMPOSE_PROJECT_NAME_ENV, "from-env");
    let result = expand_env_templates(
        "${COMPOSE_PROJECT_NAME}/router/${COMPOSE_PROJECT_NAME:-fallback}",
        Some("from-flag"),
    )
    .expect("template should render");
    assert_eq!(result, "from-flag/router/from-flag");
}

#[test]
fn expand_env_templates_uses_env_for_other_names() {
    let _test_env = EnvVarRestore::set("AMBER_TEMPLATE_TEST", "from-env");
    let result = expand_env_templates(
        "${AMBER_TEMPLATE_TEST}/${AMBER_TEMPLATE_TEST:-fallback}",
        Some("from-flag"),
    )
    .expect("template should render");
    assert_eq!(result, "from-env/from-env");
}

#[test]
fn resolve_control_endpoint_uses_short_direct_control_socket_alias() {
    let source = PathBuf::from(
        "/home/runner/work/amber/amber/target/cli-test-outputs/direct-smoke-FOF9wf/out",
    );
    let target = ProxyTarget {
        kind: ProxyTargetKind::Direct,
        metadata: ProxyMetadata {
            version: PROXY_METADATA_VERSION.to_string(),
            router: Some(amber_compiler::mesh::RouterMetadata {
                mesh_port: 0,
                control_port: 0,
                compose_project: None,
                control_socket: Some(".amber/router-control.sock".to_string()),
                control_socket_volume: None,
            }),
            ..Default::default()
        },
        source: source.clone(),
    };

    let endpoint = resolve_control_endpoint(None, None, &target).expect("endpoint should resolve");

    let ControlEndpoint::Unix(path) = endpoint else {
        panic!("expected unix control endpoint");
    };
    assert_eq!(path, direct_current_control_socket_path(&source));
    assert!(
        path.as_os_str().len() < 100,
        "direct control alias should stay well below unix socket path limits: {}",
        path.display()
    );
}

#[test]
fn resolve_control_endpoint_preserves_nested_compose_volume_socket_path() {
    let target = ProxyTarget {
        kind: ProxyTargetKind::DockerCompose,
        metadata: ProxyMetadata {
            version: PROXY_METADATA_VERSION.to_string(),
            router: Some(amber_compiler::mesh::RouterMetadata {
                mesh_port: 24000,
                control_port: 24100,
                compose_project: None,
                control_socket: Some("/site/compose_local/router-control.sock".to_string()),
                control_socket_volume: Some(
                    "${COMPOSE_PROJECT_NAME:-default}_amber-router-control".to_string(),
                ),
            }),
            ..Default::default()
        },
        source: PathBuf::from("/tmp/out/compose.yaml"),
    };

    let endpoint = resolve_control_endpoint(None, Some("mixed-stack"), &target)
        .expect("endpoint should resolve");

    let ControlEndpoint::VolumeSocket {
        volume,
        socket_path,
    } = endpoint
    else {
        panic!("expected compose volume socket endpoint");
    };
    assert_eq!(volume, "mixed-stack_amber-router-control");
    assert_eq!(socket_path, "/site/compose_local/router-control.sock");
}

#[test]
fn resolve_control_endpoint_prefers_router_metadata_compose_project() {
    let target = ProxyTarget {
        kind: ProxyTargetKind::DockerCompose,
        metadata: ProxyMetadata {
            version: PROXY_METADATA_VERSION.to_string(),
            router: Some(amber_compiler::mesh::RouterMetadata {
                mesh_port: 24000,
                control_port: 24100,
                compose_project: Some("dynamic-stack".to_string()),
                control_socket: Some("/site/compose_local/router-control.sock".to_string()),
                control_socket_volume: Some(
                    "${COMPOSE_PROJECT_NAME:-default}_amber-router-control".to_string(),
                ),
            }),
            ..Default::default()
        },
        source: PathBuf::from("/tmp/out/compose.yaml"),
    };

    let endpoint = resolve_control_endpoint(None, None, &target).expect("endpoint should resolve");

    let ControlEndpoint::VolumeSocket {
        volume,
        socket_path,
    } = endpoint
    else {
        panic!("expected compose volume socket endpoint");
    };
    assert_eq!(volume, "dynamic-stack_amber-router-control");
    assert_eq!(socket_path, "/site/compose_local/router-control.sock");
}

#[test]
fn parse_compose_published_port_addrs_reads_loopback_binding() {
    let addrs = parse_compose_published_port_addrs(
        r#"[{
                "NetworkSettings": {
                    "Ports": {
                        "24000/tcp": [
                            { "HostIp": "127.0.0.1", "HostPort": "32768" }
                        ]
                    }
                }
            }]"#,
        24000,
    )
    .expect("published port should parse");
    assert_eq!(addrs, vec![SocketAddr::from(([127, 0, 0, 1], 32768))]);
}

#[test]
fn parse_compose_published_port_addrs_defaults_unspecified_host_to_loopback() {
    let addrs = parse_compose_published_port_addrs(
        r#"[{
                "NetworkSettings": {
                    "Ports": {
                        "24000/tcp": [
                            { "HostIp": "0.0.0.0", "HostPort": "32768" }
                        ]
                    }
                }
            }]"#,
        24000,
    )
    .expect("published port should parse");
    assert_eq!(addrs, vec![SocketAddr::from(([127, 0, 0, 1], 32768))]);
}

#[test]
fn validate_proxy_bindings_accepts_http_transport_slot_kinds() {
    let metadata: ProxyMetadata = serde_json::from_value(serde_json::json!({
        "version": PROXY_METADATA_VERSION,
        "external_slots": {
            "http_slot": { "required": true, "kind": "http", "url_env": "HTTP_SLOT_URL" },
            "mcp_slot": { "required": true, "kind": "mcp", "url_env": "MCP_SLOT_URL" },
            "llm_slot": { "required": true, "kind": "llm", "url_env": "LLM_SLOT_URL" },
            "a2a_slot": { "required": true, "kind": "a2a", "url_env": "A2A_SLOT_URL" }
        }
    }))
    .expect("proxy metadata should deserialize");
    let slot_bindings = vec![
        SlotBinding {
            slot: "http_slot".to_string(),
            upstream: "127.0.0.1:18080".parse().expect("socket address"),
        },
        SlotBinding {
            slot: "mcp_slot".to_string(),
            upstream: "127.0.0.1:18081".parse().expect("socket address"),
        },
        SlotBinding {
            slot: "llm_slot".to_string(),
            upstream: "127.0.0.1:18082".parse().expect("socket address"),
        },
        SlotBinding {
            slot: "a2a_slot".to_string(),
            upstream: "127.0.0.1:18083".parse().expect("socket address"),
        },
    ];
    validate_proxy_bindings(&metadata, &slot_bindings, &[])
        .expect("HTTP-transport slots should be accepted");
}

#[test]
fn validate_proxy_bindings_rejects_non_http_transport_slot_kinds() {
    let metadata: ProxyMetadata = serde_json::from_value(serde_json::json!({
        "version": PROXY_METADATA_VERSION,
        "external_slots": {
            "state": { "required": true, "kind": "storage", "url_env": "STATE_URL" }
        }
    }))
    .expect("proxy metadata should deserialize");
    let slot_bindings = vec![SlotBinding {
        slot: "state".to_string(),
        upstream: "127.0.0.1:18080".parse().expect("socket address"),
    }];
    let err = validate_proxy_bindings(&metadata, &slot_bindings, &[])
        .expect_err("non-HTTP transports should be rejected");
    assert!(err.to_string().contains("HTTP-transport slots"), "{err}");
}

#[tokio::test]
async fn try_fetch_router_identity_times_out_stalled_control_requests() {
    let listener =
        TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("listener should bind");
    let addr = listener.local_addr().expect("listener addr");
    let handle = std::thread::spawn(move || {
        let (_stream, _) = listener.accept().expect("listener should accept");
        std::thread::sleep(CONTROL_REQUEST_TIMEOUT + Duration::from_secs(1));
    });

    let started = std::time::Instant::now();
    let err = try_fetch_router_identity(&ControlEndpoint::Tcp(addr.to_string()))
        .await
        .expect_err("stalled control request should fail");
    assert!(matches!(err, ControlUpdateError::Retryable));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "stalled control request should fail quickly"
    );
    handle.join().expect("listener thread should finish");
}
