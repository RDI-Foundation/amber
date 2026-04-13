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
        controller_route_ports: Vec::new(),
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
        controller_route_ports: Vec::new(),
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
        controller_route_ports: vec![60066],
        launch_env: BTreeMap::new(),
    };

    assert_eq!(
        supervisor::compose_site_controller_container_name(&plan).as_deref(),
        Some("amber_run_compose-site-amber-site-controller-1")
    );
}
