#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::{
    fs,
    net::{SocketAddr, TcpListener},
    thread,
    time::Duration,
};

use tempfile::TempDir;

use super::*;

#[test]
fn site_state_paths_are_site_scoped() {
    let root = Path::new("/tmp/amber-run/state");
    assert_eq!(
        site_state_path(root, "site-a"),
        Path::new("/tmp/amber-run/state/site-a/manager-state.json")
    );
    assert_eq!(
        desired_links_path(Path::new("/tmp/amber-run/state/site-a")),
        Path::new("/tmp/amber-run/state/site-a/desired-links.json")
    );
    assert_eq!(
        site_controller_plan_path(Path::new("/tmp/amber-run/state/site-a")),
        Path::new("/tmp/amber-run/state/site-a/site-controller-plan.json")
    );
    assert_eq!(
        site_existing_peer_ports_path(Path::new("/tmp/amber-run/state/site-a")),
        Path::new("/tmp/amber-run/state/site-a/existing-peer-ports.json")
    );
    assert_eq!(
        site_existing_peer_identities_path(Path::new("/tmp/amber-run/state/site-a")),
        Path::new("/tmp/amber-run/state/site-a/existing-peer-identities.json")
    );
}

#[test]
fn site_controller_image_override_uses_dev_tag() {
    let overrides = BTreeMap::from([(
        "site_controller".to_string(),
        "dev-site-controller".to_string(),
    )]);

    assert_eq!(
        launch_bundle::site_controller_image_reference_from_overrides(&overrides),
        format!(
            "{}/{}:{}",
            amber_images::AMBER_SITE_CONTROLLER.registry,
            amber_images::AMBER_SITE_CONTROLLER.name,
            "dev-site-controller",
        )
    );
}

#[test]
fn recorded_process_roots_include_site_supervisor() {
    let site = SiteReceipt {
        kind: SiteKind::Direct,
        artifact_dir: "/tmp/artifact".to_string(),
        supervisor_pid: 7,
        process_pid: Some(11),
        compose_project: None,
        kubernetes_namespace: None,
        port_forward_pid: Some(13),
        context: None,
        router_control: None,
        router_mesh_addr: None,
        compose_consumer_router_mesh_addr: None,
        kubernetes_consumer_router_mesh_addr: None,
        router_identity_id: None,
        router_public_key_b64: None,
        site_controller_pid: None,
        site_controller_url: None,
    };

    assert_eq!(recorded_process_roots(&site), vec![7, 11, 13]);
}

#[test]
fn site_controller_local_router_control_uses_backend_local_control_targets() {
    let artifact_dir = Path::new("/tmp/site-artifact");

    assert_eq!(
        launch_bundle::site_controller_local_router_control(SiteKind::Compose, artifact_dir),
        "unix:///amber/control/router-control.sock"
    );
    assert_eq!(
        launch_bundle::site_controller_local_router_control(SiteKind::Kubernetes, artifact_dir),
        "amber-router:24100"
    );
    assert!(
        launch_bundle::site_controller_local_router_control(SiteKind::Direct, artifact_dir)
            .starts_with("unix://"),
        "direct site controllers should know their local router control socket up front"
    );
    assert!(
        launch_bundle::site_controller_local_router_control(SiteKind::Vm, artifact_dir)
            .starts_with("unix://"),
        "vm site controllers should know their local router control socket up front"
    );
}

#[test]
fn site_controller_peer_router_urls_are_local_to_the_controller_site() {
    assert_eq!(
        amber_site_controller::site_controller_peer_router_url(SiteKind::Direct, 37046),
        "http://127.0.0.1:37046"
    );
    assert_eq!(
        amber_site_controller::site_controller_peer_router_url(SiteKind::Vm, 37046),
        "http://127.0.0.1:37046"
    );
    assert_eq!(
        amber_site_controller::site_controller_peer_router_url(SiteKind::Compose, 37046),
        "http://amber-router:37046"
    );
    assert_eq!(
        amber_site_controller::site_controller_peer_router_url(SiteKind::Kubernetes, 37046),
        "http://amber-router:37046"
    );
}

#[test]
fn compose_consumers_use_host_alias_for_kubernetes_router_mesh() {
    assert_eq!(
        supervisor::container_host_from_resolved_ip(
            SiteKind::Kubernetes,
            SiteKind::Compose,
            Some("192.168.65.254"),
        ),
        "host.docker.internal"
    );
    assert_eq!(
        amber_site_controller::router_mesh_addr_for_consumer(
            SiteKind::Kubernetes,
            SiteKind::Compose,
            "127.0.0.1:24077",
        )
        .expect("compose consumers should be able to route to kubernetes peers"),
        "host.docker.internal:24077"
    );
}

#[test]
fn site_controller_image_includes_the_amber_cli_binary() {
    let dockerfile = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../docker/amber-site-controller/Dockerfile"),
    )
    .expect("site-controller Dockerfile should read");
    assert!(
        dockerfile.contains("cargo build --locked --release -p amber-cli -p amber-site-controller")
            || dockerfile.contains("cargo build --locked -p amber-cli -p amber-site-controller"),
        "site-controller image must build the amber CLI so containerized controllers can spawn \
         amber subcommands:\n{dockerfile}"
    );
    assert!(
        dockerfile.contains("COPY --from=builder /out/amber /usr/local/bin/amber"),
        "site-controller image must ship the amber CLI binary alongside \
         amber-site-controller:\n{dockerfile}"
    );
    assert!(
        dockerfile.contains("COPY examples ./examples"),
        "site-controller image must include the examples tree so amber-cli can satisfy \
         cli/build.rs:\n{dockerfile}"
    );
    assert!(
        dockerfile.contains("COPY README.md ./"),
        "site-controller image must include the workspace README because amber-cli embeds \
         it:\n{dockerfile}"
    );
}

#[test]
fn provisioner_image_supports_debug_builds() {
    let dockerfile = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../docker/amber-provisioner/Dockerfile"),
    )
    .expect("provisioner Dockerfile should read");
    assert!(
        dockerfile.contains("ARG BUILD_MODE=release"),
        "provisioner image should accept the shared BUILD_MODE argument so mixed-run tests can \
         use debug builds:\n{dockerfile}"
    );
    assert!(
        dockerfile.contains("if [ \"$BUILD_MODE\" = \"release\" ]; then")
            && dockerfile.contains("cargo build -p amber-provisioner --release --locked")
            && dockerfile.contains("cargo build -p amber-provisioner --locked")
            && dockerfile.contains("\"${build_dir}\"/amber-provisioner"),
        "provisioner image should support both release and debug output paths:\n{dockerfile}"
    );
}

#[test]
fn site_controller_command_prefers_fresh_amber_binary_under_cargo_tests() {
    let temp = TempDir::new().expect("temp dir");
    let debug_dir = temp.path().join("target").join("debug");
    let deps_dir = debug_dir.join("deps");
    fs::create_dir_all(&deps_dir).expect("deps dir should exist");
    let current = deps_dir.join(format!("mixed_run-test{}", std::env::consts::EXE_SUFFIX));
    let amber = debug_dir.join(format!("amber{}", std::env::consts::EXE_SUFFIX));
    let site_controller = debug_dir.join(format!(
        "amber-site-controller{}",
        std::env::consts::EXE_SUFFIX
    ));
    fs::write(&current, "").expect("current test binary should exist");
    fs::write(&amber, "").expect("amber binary should exist");
    fs::write(&site_controller, "").expect("stale site controller binary should exist");

    let command = site_controller_command_from(&current).expect("site controller command");
    assert_eq!(
        command.executable, amber,
        "cargo test binaries should launch the freshly built amber binary instead of a stale \
         sibling amber-site-controller executable"
    );
    assert_eq!(command.prefix_args, vec!["run-site-controller"]);
}

#[test]
fn local_site_controller_addr_requires_loopback_http() {
    let mut plan = SiteSupervisorPlan {
        schema: "amber.run.site_supervisor_plan".to_string(),
        version: 2,
        run_id: "run".to_string(),
        mesh_scope: "scope".to_string(),
        run_root: "/tmp/run".to_string(),
        coordinator_pid: 1,
        site_id: "site-a".to_string(),
        kind: SiteKind::Direct,
        artifact_dir: "/tmp/artifact".to_string(),
        site_state_root: "/tmp/state".to_string(),
        storage_root: None,
        runtime_root: None,
        router_mesh_port: None,
        compose_project: None,
        kubernetes_namespace: None,
        context: None,
        port_forward_mesh_port: None,
        port_forward_control_port: None,
        observability_endpoint: None,
        site_controller_plan_path: None,
        site_controller_url: Some("http://127.0.0.1:24200".to_string()),
        launch_env: BTreeMap::new(),
    };

    assert_eq!(
        supervisor::local_site_controller_addr(&plan).expect("loopback controller address"),
        Some(SocketAddr::from(([127, 0, 0, 1], 24200)))
    );

    plan.site_controller_url = Some("http://192.168.1.10:24200".to_string());
    assert_eq!(
        supervisor::local_site_controller_addr(&plan)
            .expect("non-loopback controller address should be ignored"),
        None
    );
}

#[test]
fn host_service_bind_addr_matches_component_reachability() {
    assert_eq!(
        supervisor::host_service_bind_addr_for_consumer(SiteKind::Compose, 24200),
        SocketAddr::from(([0, 0, 0, 0], 24200))
    );
    assert_eq!(
        supervisor::host_service_bind_addr_for_consumer(SiteKind::Kubernetes, 24201),
        SocketAddr::from(([0, 0, 0, 0], 24201))
    );
    assert_eq!(
        supervisor::host_service_bind_addr_for_consumer(SiteKind::Vm, 24202),
        SocketAddr::from(([0, 0, 0, 0], 24202))
    );

    let direct = supervisor::host_service_bind_addr_for_consumer(SiteKind::Direct, 24203);
    if cfg!(target_os = "linux") {
        assert_eq!(direct, SocketAddr::from(([0, 0, 0, 0], 24203)));
    } else {
        assert_eq!(direct, SocketAddr::from(([127, 0, 0, 1], 24203)));
    }
}

#[test]
fn local_site_controller_ready_waits_for_http_listener() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener should bind");
    let addr = listener.local_addr().expect("listener addr");
    let handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut request = [0u8; 256];
            let _ = stream.read(&mut request);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}",
            );
        }
    });
    let plan = SiteSupervisorPlan {
        schema: "amber.run.site_supervisor_plan".to_string(),
        version: 2,
        run_id: "run".to_string(),
        mesh_scope: "scope".to_string(),
        run_root: "/tmp/run".to_string(),
        coordinator_pid: 1,
        site_id: "site-a".to_string(),
        kind: SiteKind::Direct,
        artifact_dir: "/tmp/artifact".to_string(),
        site_state_root: "/tmp/state".to_string(),
        storage_root: None,
        runtime_root: None,
        router_mesh_port: None,
        compose_project: None,
        kubernetes_namespace: None,
        context: None,
        port_forward_mesh_port: None,
        port_forward_control_port: None,
        observability_endpoint: None,
        site_controller_plan_path: None,
        site_controller_url: Some(format!("http://127.0.0.1:{}", addr.port())),
        launch_env: BTreeMap::new(),
    };

    assert!(
        supervisor::local_site_controller_ready(&plan, Duration::from_secs(1))
            .expect("controller readiness should succeed"),
        "local site readiness should wait for the controller HTTP listener"
    );
    handle.join().expect("listener thread should exit");
}

#[test]
fn compose_site_controller_status_parsing_handles_health_and_plain_running() {
    assert_eq!(
        supervisor::parse_container_runtime_status("running healthy\n"),
        Some(("running", Some("healthy")))
    );
    assert_eq!(
        supervisor::parse_container_runtime_status("running\n"),
        Some(("running", None))
    );
    assert_eq!(supervisor::parse_container_runtime_status(""), None);
}

#[test]
fn compose_site_controller_container_name_uses_compose_project() {
    let plan = SiteSupervisorPlan {
        schema: "amber.run.site_supervisor_plan".to_string(),
        version: 2,
        run_id: "run".to_string(),
        mesh_scope: "scope".to_string(),
        run_root: "/tmp/run".to_string(),
        coordinator_pid: 1,
        site_id: "compose-site".to_string(),
        kind: SiteKind::Compose,
        artifact_dir: "/tmp/artifact".to_string(),
        site_state_root: "/tmp/state".to_string(),
        storage_root: None,
        runtime_root: None,
        router_mesh_port: None,
        compose_project: Some("amber_run_compose-site".to_string()),
        kubernetes_namespace: None,
        context: None,
        port_forward_mesh_port: None,
        port_forward_control_port: None,
        observability_endpoint: None,
        site_controller_plan_path: None,
        site_controller_url: Some("http://amber-site-controller:4100".to_string()),
        launch_env: BTreeMap::new(),
    };

    assert_eq!(
        supervisor::compose_site_controller_container_name(&plan).as_deref(),
        Some("amber_run_compose-site-amber-site-controller-1")
    );
}

#[test]
fn reserve_loopback_port_keeps_allocations_unique_within_one_process() {
    let mut ports = BTreeSet::new();
    for _ in 0..64 {
        let port = reserve_loopback_port().expect("loopback port reservation should succeed");
        assert!(
            ports.insert(port),
            "loopback port allocator reused {port} within one process"
        );
    }
}

#[test]
fn reserve_loopback_port_shares_allocator_with_site_controller_runtime() {
    let mixed_run_port =
        reserve_loopback_port().expect("mixed-run loopback port reservation should succeed");
    for _ in 0..32 {
        let runtime_port = amber_site_controller::reserve_loopback_port()
            .expect("site-controller loopback port reservation should succeed");
        assert_ne!(
            runtime_port, mixed_run_port,
            "mixed-run and site-controller loopback reservations must use the same shared pool",
        );
    }
}

#[cfg(unix)]
#[test]
fn stop_kubernetes_namespace_force_deletes_stuck_pods_before_retrying() {
    let temp = TempDir::new().expect("temp dir");
    let kubectl = temp.path().join("kubectl");
    let log_path = temp.path().join("kubectl.log");
    let state_path = temp.path().join("namespace-state");
    fs::write(
        &kubectl,
        format!(
            "#!/bin/sh\nset -eu\nlog_path='{}'\nstate_path='{}'\nprintf '%s\\n' \"$*\" >> \
             \"$log_path\"\nif [ \"${{1:-}}\" = \"--context\" ]; then\n  shift \
             2\nfi\nstate=alive\nif [ -f \"$state_path\" ]; then\n  state=$(cat \
             \"$state_path\")\nfi\nif [ \"${{1:-}}\" = \"delete\" ] && [ \"${{2:-}}\" = \
             \"namespace\" ]; then\n  exit 0\nfi\nif [ \"${{1:-}}\" = \"get\" ] && [ \"${{2:-}}\" \
             = \"namespace\" ]; then\n  if [ \"$state\" = \"gone\" ]; then\n    echo 'Error from \
             server (NotFound): namespaces \"'\"${{3:-}}\"'\" not found' >&2\n    exit 1\n  fi\n  \
             printf '{{\"metadata\":{{\"name\":\"%s\",\"deletionTimestamp\":\"2026-04-16T02:33:\
             55Z\"}}}}\\n' \"${{3:-}}\"\n  exit 0\nfi\nif [ \"${{1:-}}\" = \"-n\" ] && [ \
             \"${{2:-}}\" = \"test-ns\" ] && [ \"${{3:-}}\" = \"delete\" ] && [ \"${{4:-}}\" = \
             \"pods\" ]; then\n  printf 'gone' > \"$state_path\"\n  exit 0\nfi\necho \"unexpected \
             kubectl invocation: $*\" >&2\nexit 1\n",
            log_path.display(),
            state_path.display(),
        ),
    )
    .expect("kubectl stub");
    let mut permissions = fs::metadata(&kubectl)
        .expect("kubectl metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&kubectl, permissions).expect("kubectl chmod");

    stop_kubernetes_namespace_with_kubectl(
        &kubectl,
        Some("test-context"),
        "test-ns",
        Duration::from_millis(20),
    )
    .expect("namespace stop should force-delete remaining pods and retry");

    let log = fs::read_to_string(&log_path).expect("kubectl log");
    let delete_namespace_calls = log
        .lines()
        .filter(|line| line.contains("delete namespace test-ns --ignore-not-found --wait=false"))
        .count();
    assert_eq!(
        delete_namespace_calls, 2,
        "namespace deletion should be retried after forced pod cleanup:\n{log}"
    );
    assert!(
        log.lines().any(|line| {
            line.contains(
                "-n test-ns delete pods --all --ignore-not-found --force --grace-period=0",
            )
        }),
        "forced pod cleanup should run before the retry:\n{log}"
    );
}
