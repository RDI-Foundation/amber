use clap::CommandFactory as _;

use super::*;

#[derive(Default)]
struct RecordingStatusIndicator {
    shown_frames: Vec<usize>,
    cleared: bool,
}

impl StatusIndicator for RecordingStatusIndicator {
    fn show(&mut self, frame_index: usize) -> Result<()> {
        self.shown_frames.push(frame_index);
        Ok(())
    }

    fn clear(&mut self) -> Result<()> {
        self.cleared = true;
        Ok(())
    }
}

fn encode_json_b64(value: &serde_json::Value) -> String {
    base64::engine::general_purpose::STANDARD
        .encode(serde_json::to_vec(value).expect("json should serialize"))
}

fn encode_mount_specs_b64(mounts: &[MountSpec]) -> String {
    base64::engine::general_purpose::STANDARD
        .encode(serde_json::to_vec(mounts).expect("mount specs should serialize"))
}

fn root_runtime_config_payload(schema: serde_json::Value) -> DirectRuntimeConfigPayload {
    DirectRuntimeConfigPayload {
        root_schema_b64: encode_json_b64(&schema),
        component_cfg_template_b64: encode_json_b64(&ConfigTemplatePayload::Root.to_value()),
        component_schema_b64: encode_json_b64(&schema),
        allowed_root_leaf_paths: Vec::new(),
    }
}

#[test]
fn verbosity_levels_follow_v_flag_ladder() {
    assert_eq!(verbosity_level(0), "error");
    assert_eq!(verbosity_level(1), "warn");
    assert_eq!(verbosity_level(2), "info");
    assert_eq!(verbosity_level(3), "debug");
    assert_eq!(verbosity_level(4), "trace");
    assert_eq!(verbosity_level(9), "trace");
}

#[test]
fn cli_version_comes_from_build_metadata() {
    let cli = Cli::command();
    assert_eq!(cli.get_version(), Some(CLI_VERSION));
}

#[test]
fn proxy_console_is_quiet_by_default() {
    assert_eq!(
        console_filter_spec(0),
        "error,amber=error,amber_=error,amber_router=error,amber.binding=error,amber.proxy=error"
    );
}

#[test]
fn ensure_absolute_direct_program_path_rejects_relative_paths() {
    let err = ensure_absolute_direct_program_path("./bin/server", "app")
        .expect_err("relative program path should fail");
    let rendered = err.to_string();
    assert!(rendered.contains("non-absolute program path"), "{rendered}");
    assert!(rendered.contains("amber compile --direct"), "{rendered}");
}

#[test]
fn proxy_telemetry_keeps_router_info_without_verbose_output() {
    assert_eq!(
        proxy_telemetry_filter_spec(0),
        "error,amber=error,amber_=error,amber_router=info,amber.proxy=error"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn component_program_read_only_mounts_resolve_parent_escape_paths() {
    let component = DirectComponentPlan {
        id: 3,
        moniker: "app".to_string(),
        log_name: "app".to_string(),
        source_dir: Some("/workspace/scenarios/app".to_string()),
        depends_on: Vec::new(),
        sidecar: amber_compiler::reporter::direct::DirectSidecarPlan {
            log_name: "app-sidecar".to_string(),
            mesh_port: 0,
            mesh_config_path: "mesh/components/app/mesh-config.json".to_string(),
            mesh_identity_path: "mesh/components/app/mesh-identity.json".to_string(),
            env_passthrough: Vec::new(),
        },
        program: amber_compiler::reporter::direct::DirectProgramPlan {
            log_name: "app-program".to_string(),
            work_dir: "work/components/app".to_string(),
            storage_mounts: Vec::new(),
            execution: DirectProgramExecutionPlan::Direct {
                entrypoint: vec!["/workspace/scenarios/app/../bin/tool".to_string()],
                env: BTreeMap::new(),
            },
        },
    };

    let mounts =
        component_program_read_only_mounts(&component, Some(Path::new("/workspace/scenarios/app")))
            .expect("mounts should resolve");

    assert!(
        mounts
            .iter()
            .any(|mount| mount.source == Path::new("/workspace/scenarios/app"))
    );
    assert!(
        mounts
            .iter()
            .any(|mount| mount.source == Path::new("/workspace/scenarios/app/../bin"))
    );
}

#[test]
fn build_runtime_template_context_uses_runtime_slot_ports() {
    let runtime_addresses = DirectRuntimeAddressPlan {
        slots_by_scope: BTreeMap::from([(
            3,
            BTreeMap::from([(
                "api".to_string(),
                DirectRuntimeUrlSource::Slot {
                    component_id: 7,
                    slot: "api".to_string(),
                    scheme: "http".to_string(),
                },
            )]),
        )]),
        slot_items_by_scope: BTreeMap::from([(
            5,
            BTreeMap::from([(
                "upstream".to_string(),
                vec![
                    DirectRuntimeUrlSource::SlotItem {
                        component_id: 8,
                        slot: "upstream".to_string(),
                        item_index: 0,
                        scheme: "http".to_string(),
                    },
                    DirectRuntimeUrlSource::SlotItem {
                        component_id: 8,
                        slot: "upstream".to_string(),
                        item_index: 1,
                        scheme: "http".to_string(),
                    },
                ],
            )]),
        )]),
    };
    let runtime_state = DirectRuntimeState {
        slot_ports_by_component: BTreeMap::from([(
            7,
            BTreeMap::from([("api".to_string(), 31001)]),
        )]),
        slot_route_ports_by_component: BTreeMap::from([(
            8,
            BTreeMap::from([("upstream".to_string(), vec![32001, 32002])]),
        )]),
        dynamic_caps_port_by_component: BTreeMap::new(),
        component_mesh_port_by_id: BTreeMap::new(),
        router_mesh_port: None,
    };

    let context =
        build_runtime_template_context(&runtime_addresses, &runtime_state).expect("context");

    assert_eq!(
        context
            .slots_by_scope
            .get(&3)
            .and_then(|values| values.get("api")),
        Some(&r#"{"url":"http://127.0.0.1:31001"}"#.to_string())
    );
    assert_eq!(
        context
            .slots_by_scope
            .get(&3)
            .and_then(|values| values.get("api.url")),
        Some(&"http://127.0.0.1:31001".to_string())
    );
    assert_eq!(
        context
            .slot_items_by_scope
            .get(&5)
            .and_then(|values| values.get("upstream"))
            .map(|items| items
                .iter()
                .map(|item| item.url.as_str())
                .collect::<Vec<_>>()),
        Some(vec!["http://127.0.0.1:32001", "http://127.0.0.1:32002"])
    );
}

#[tokio::test]
async fn await_with_status_indicator_is_silent_for_fast_future() {
    let mut indicator = RecordingStatusIndicator::default();

    let (result, shown) = await_with_status_indicator(
        async { 7usize },
        Some(Duration::from_millis(50)),
        Duration::from_millis(5),
        &mut indicator,
    )
    .await
    .expect("helper should succeed");

    assert_eq!(result, 7);
    assert!(!shown);
    assert!(indicator.shown_frames.is_empty());
    assert!(!indicator.cleared);
}

#[tokio::test]
async fn await_with_status_indicator_renders_and_clears_for_slow_future() {
    let mut indicator = RecordingStatusIndicator::default();

    let (result, shown) = await_with_status_indicator(
        async {
            sleep(Duration::from_millis(30)).await;
            11usize
        },
        Some(Duration::from_millis(1)),
        Duration::from_millis(5),
        &mut indicator,
    )
    .await
    .expect("helper should succeed");

    assert_eq!(result, 11);
    assert!(shown);
    assert_eq!(indicator.shown_frames.first().copied(), Some(0));
    assert!(indicator.cleared);
}

#[tokio::test]
async fn await_with_status_indicator_can_start_immediately() {
    let mut indicator = RecordingStatusIndicator::default();

    let (result, shown) = await_with_status_indicator(
        async {
            sleep(Duration::from_millis(20)).await;
            5usize
        },
        None,
        Duration::from_millis(5),
        &mut indicator,
    )
    .await
    .expect("helper should succeed");

    assert_eq!(result, 5);
    assert!(shown);
    assert_eq!(indicator.shown_frames.first().copied(), Some(0));
    assert!(indicator.cleared);
}

#[test]
fn decode_mount_parent_dirs_supports_literal_template_mount_paths() {
    let mounts = vec![MountSpec::Template(amber_template::MountTemplateSpec {
        when: None,
        each: None,
        path: vec![TemplatePart::lit("/run/app.txt")],
        source: vec![TemplatePart::lit("config.app")],
    })];
    let runtime_config = root_runtime_config_payload(serde_json::json!({
        "type": "object",
        "properties": {
            "app": { "type": "string" }
        },
        "required": ["app"]
    }));

    let parents = decode_mount_parent_dirs_with_env(
        &encode_mount_specs_b64(&mounts),
        Some(&runtime_config),
        &RuntimeTemplateContext::default(),
        &BTreeMap::from([("AMBER_CONFIG_APP".to_string(), "hello".to_string())]),
    )
    .expect("literal template mount path should resolve");

    assert_eq!(parents, vec![PathBuf::from("/run")]);
}

#[test]
fn decode_mount_parent_dirs_renders_config_template_mount_paths() {
    let mounts = vec![MountSpec::Template(amber_template::MountTemplateSpec {
        when: None,
        each: None,
        path: vec![
            TemplatePart::lit("/etc/"),
            TemplatePart::config("mount_dir"),
            TemplatePart::lit("/app.txt"),
        ],
        source: vec![TemplatePart::lit("config.app")],
    })];
    let runtime_config = root_runtime_config_payload(serde_json::json!({
        "type": "object",
        "properties": {
            "app": { "type": "string" },
            "mount_dir": { "type": "string" }
        },
        "required": ["app", "mount_dir"]
    }));

    let parents = decode_mount_parent_dirs_with_env(
        &encode_mount_specs_b64(&mounts),
        Some(&runtime_config),
        &RuntimeTemplateContext::default(),
        &BTreeMap::from([
            ("AMBER_CONFIG_APP".to_string(), "hello".to_string()),
            ("AMBER_CONFIG_MOUNT_DIR".to_string(), "service".to_string()),
        ]),
    )
    .expect("config template mount path should resolve");

    assert_eq!(parents, vec![PathBuf::from("/etc/service")]);
}

#[test]
fn assign_direct_runtime_ports_preserves_repeated_slot_item_order() {
    let temp = tempfile::tempdir().expect("temp dir should be created");
    let mesh_config_rel = PathBuf::from("mesh/components/app/mesh-config.json");
    let mesh_config_path = temp.path().join(&mesh_config_rel);
    fs::create_dir_all(
        mesh_config_path
            .parent()
            .expect("mesh config should have a parent"),
    )
    .expect("mesh config dir should be created");

    let config = MeshConfigPublic {
        identity: MeshIdentityPublic {
            id: "/app".to_string(),
            public_key: [7; 32],
            mesh_scope: None,
        },
        mesh_listen: "127.0.0.1:19000".parse().expect("mesh listen"),
        control_listen: None,
        dynamic_caps_listen: None,
        control_allow: None,
        peers: Vec::new(),
        inbound: Vec::new(),
        outbound: vec![
            OutboundRoute {
                route_id: "route-b".to_string(),
                slot: "upstream".to_string(),
                capability_kind: Some("http".to_string()),
                capability_profile: None,
                listen_port: 20001,
                listen_addr: None,
                protocol: MeshProtocol::Http,
                http_plugins: Vec::new(),
                peer_addr: "127.0.0.1:18081".to_string(),
                peer_id: "/app".to_string(),
                capability: "api".to_string(),
            },
            OutboundRoute {
                route_id: "route-a".to_string(),
                slot: "upstream".to_string(),
                capability_kind: Some("http".to_string()),
                capability_profile: None,
                listen_port: 20000,
                listen_addr: None,
                protocol: MeshProtocol::Http,
                http_plugins: Vec::new(),
                peer_addr: "127.0.0.1:18080".to_string(),
                peer_id: "/app".to_string(),
                capability: "api".to_string(),
            },
        ],
        transport: TransportConfig::NoiseIk {},
    };
    write_mesh_config_public(&mesh_config_path, &config).expect("mesh config should be written");

    let direct_plan = DirectPlan {
        version: DIRECT_PLAN_VERSION.to_string(),
        mesh_provision_plan: "{}".to_string(),
        startup_order: vec![7],
        components: vec![DirectComponentPlan {
            id: 7,
            moniker: "/app".to_string(),
            log_name: "app".to_string(),
            source_dir: None,
            depends_on: Vec::new(),
            sidecar: amber_compiler::reporter::direct::DirectSidecarPlan {
                log_name: "app-sidecar".to_string(),
                mesh_port: 0,
                mesh_config_path: mesh_config_rel.display().to_string(),
                mesh_identity_path: "mesh/components/app/mesh-identity.json".to_string(),
                env_passthrough: Vec::new(),
            },
            program: amber_compiler::reporter::direct::DirectProgramPlan {
                log_name: "app-program".to_string(),
                work_dir: "work/components/app".to_string(),
                storage_mounts: Vec::new(),
                execution: DirectProgramExecutionPlan::Direct {
                    entrypoint: vec!["/bin/echo".to_string()],
                    env: BTreeMap::new(),
                },
            },
        }],
        runtime_addresses: DirectRuntimeAddressPlan {
            slots_by_scope: BTreeMap::new(),
            slot_items_by_scope: BTreeMap::from([(
                7,
                BTreeMap::from([(
                    "upstream".to_string(),
                    vec![
                        DirectRuntimeUrlSource::SlotItem {
                            component_id: 7,
                            slot: "upstream".to_string(),
                            item_index: 0,
                            scheme: "http".to_string(),
                        },
                        DirectRuntimeUrlSource::SlotItem {
                            component_id: 7,
                            slot: "upstream".to_string(),
                            item_index: 1,
                            scheme: "http".to_string(),
                        },
                    ],
                )]),
            )]),
        },
        router: None,
    };

    let runtime_state =
        assign_direct_runtime_ports(temp.path(), &direct_plan, None).expect("ports should assign");
    let rewritten =
        read_mesh_config_public(&mesh_config_path).expect("mesh config should be rewritten");
    let runtime_ports = runtime_state
        .slot_route_ports_by_component
        .get(&7)
        .and_then(|slots| slots.get("upstream"))
        .expect("runtime slot ports should exist");
    let route_ports: Vec<u16> = rewritten
        .outbound
        .iter()
        .map(|route| route.listen_port)
        .collect();

    assert_eq!(runtime_ports.len(), 2);
    assert_eq!(route_ports.len(), 2);
    assert_eq!(runtime_ports[0], route_ports[1]);
    assert_eq!(runtime_ports[1], route_ports[0]);

    let context = build_runtime_template_context(&direct_plan.runtime_addresses, &runtime_state)
        .expect("context should build");
    let item_urls = context
        .slot_items_by_scope
        .get(&7)
        .and_then(|slots| slots.get("upstream"))
        .expect("runtime item urls should exist");
    assert_eq!(item_urls.len(), 2);
    assert_eq!(
        item_urls[0].url,
        format!("http://127.0.0.1:{}", runtime_ports[0])
    );
    assert_eq!(
        item_urls[1].url,
        format!("http://127.0.0.1:{}", runtime_ports[1])
    );
}

#[test]
fn direct_runtime_control_socket_path_is_unique_per_run() {
    let first = tempfile::tempdir().expect("temp dir should be created");
    let second = tempfile::tempdir().expect("temp dir should be created");

    assert_ne!(
        direct_runtime_control_socket_path(first.path()),
        direct_runtime_control_socket_path(second.path())
    );
}

#[test]
fn direct_storage_root_defaults_next_to_output() {
    let root = direct_storage_root(Path::new("/tmp/out"), None).expect("storage root");
    assert_eq!(root, Path::new("/tmp/.out.amber-state"));
}

#[test]
fn direct_storage_root_uses_explicit_override() {
    let root = direct_storage_root(
        Path::new("/tmp/out"),
        Some(Path::new("custom-storage-root")),
    )
    .expect("storage root");
    assert!(
        root.ends_with("custom-storage-root"),
        "override should be used verbatim: {}",
        root.display()
    );
}

#[test]
fn attached_run_storage_defaults_to_temporary_root() {
    let storage = AttachedRunStorage::new(None).expect("attached storage should build");
    let path = storage.storage_root();
    assert!(path.exists(), "temporary storage root should exist");
    assert!(
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("amber-run-")),
        "unexpected temporary storage root: {}",
        path.display()
    );
}

#[test]
fn attached_run_storage_uses_explicit_override() {
    let storage = AttachedRunStorage::new(Some(Path::new("custom-storage-root")))
        .expect("attached storage should build");
    assert!(
        storage.storage_root().ends_with("custom-storage-root"),
        "override should be used verbatim: {}",
        storage.storage_root().display()
    );
}

#[test]
fn framework_component_example_control_calls_use_extended_timeout_budget() {
    let admin_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("examples")
        .join("framework-component")
        .join("admin.py");
    let python = ["python3", "python"].into_iter().find(|candidate| {
        std::process::Command::new(candidate)
            .arg("--version")
            .output()
            .is_ok()
    });
    let Some(python) = python else {
        return;
    };

    let script = r#"
import os
import sys

source = open(sys.argv[1], "r", encoding="utf-8").read()
source = source.rsplit("\nThreadingHTTPServer", 1)[0]
module_globals = {"__name__": "amber_example_admin", "__file__": sys.argv[1]}
exec(compile(source, sys.argv[1], "exec"), module_globals)

class Module:
    pass

module = Module()
for key, value in module_globals.items():
    setattr(module, key, value)

assert module.FRAMEWORK_COMPONENT_TIMEOUT_SECS >= 120, module.FRAMEWORK_COMPONENT_TIMEOUT_SECS

seen = {}

class FakeResponse:
    status = 204
    headers = {}
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc, tb):
        return False
    def read(self):
        return b""

def fake_urlopen(request, timeout):
    seen["timeout"] = timeout
    return FakeResponse()

module.urlopen = fake_urlopen
module_globals["urlopen"] = fake_urlopen
status, _, _ = module.call("POST", "/v1/children", {"name": "child"})
assert status == 204, status
assert seen["timeout"] == module.FRAMEWORK_COMPONENT_TIMEOUT_SECS, seen
"#;

    let output = std::process::Command::new(python)
        .arg("-c")
        .arg(script)
        .arg(&admin_path)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("NAME", "admin")
        .env("PORT", "18080")
        .env("CTL_URL", "http://127.0.0.1:9")
        .output()
        .expect("python should execute");
    assert!(
        output.status.success(),
        "python regression check failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[cfg(unix)]
#[test]
fn remove_direct_control_socket_link_preserves_newer_run_symlink() {
    let plan_root = tempfile::tempdir().expect("temp dir should be created");
    let runtime_one = tempfile::tempdir().expect("temp dir should be created");
    let runtime_two = tempfile::tempdir().expect("temp dir should be created");
    let paths_one = DirectControlSocketPaths {
        artifact_link: plan_root.path().join(".amber/router-control.sock"),
        current_link: direct_current_control_socket_path(plan_root.path()),
        runtime: direct_runtime_control_socket_path(runtime_one.path()),
    };
    let runtime_two_socket = direct_runtime_control_socket_path(runtime_two.path());
    fs::create_dir_all(paths_one.current_link.parent().expect("link parent"))
        .expect("link parent should be created");
    std::os::unix::fs::symlink(&runtime_two_socket, &paths_one.current_link)
        .expect("symlink should be created");

    remove_direct_control_socket_link(&paths_one);

    assert_eq!(
        fs::read_link(&paths_one.current_link).expect("newer run symlink should remain"),
        runtime_two_socket
    );
}

#[cfg(unix)]
#[tokio::test]
async fn cleanup_direct_runtime_removes_partial_startup_artifacts() {
    let plan_root = tempfile::tempdir().expect("temp dir should be created");
    let runtime_dir = tempfile::Builder::new()
        .prefix("amber-direct-test-")
        .tempdir()
        .expect("runtime dir should be created");
    let runtime_root = runtime_dir.path().to_path_buf();
    let runtime_state_path = direct_runtime_state_path(plan_root.path());
    fs::create_dir_all(runtime_state_path.parent().expect("state parent"))
        .expect("state parent should be created");
    fs::write(&runtime_state_path, "{}").expect("state file should be written");

    let control_socket_paths = DirectControlSocketPaths {
        artifact_link: plan_root.path().join(".amber/router-control.sock"),
        current_link: direct_current_control_socket_path(plan_root.path()),
        runtime: direct_runtime_control_socket_path(&runtime_root),
    };
    fs::create_dir_all(
        control_socket_paths
            .artifact_link
            .parent()
            .expect("link parent"),
    )
    .expect("link parent should be created");
    fs::create_dir_all(
        control_socket_paths
            .current_link
            .parent()
            .expect("current link parent"),
    )
    .expect("current link parent should be created");
    fs::create_dir_all(
        control_socket_paths
            .runtime
            .parent()
            .expect("runtime parent"),
    )
    .expect("runtime parent should be created");
    fs::write(&control_socket_paths.runtime, "").expect("runtime socket placeholder");
    std::os::unix::fs::symlink(
        &control_socket_paths.current_link,
        &control_socket_paths.artifact_link,
    )
    .expect("artifact symlink should be created");
    std::os::unix::fs::symlink(
        &control_socket_paths.runtime,
        &control_socket_paths.current_link,
    )
    .expect("symlink should be created");

    let child = TokioCommand::new("sh")
        .arg("-c")
        .arg("sleep 30")
        .spawn()
        .expect("child should spawn");
    let mut children = vec![ManagedChild {
        name: "partial-startup-child".to_string(),
        wrapper: Some(child),
        #[cfg(target_os = "linux")]
        wrapper_pid: 0,
        #[cfg(target_os = "linux")]
        managed_pid: 0,
    }];
    #[cfg(target_os = "linux")]
    {
        let pid = children[0]
            .wrapper
            .as_ref()
            .and_then(tokio::process::Child::id)
            .expect("child pid should be available");
        children[0].wrapper_pid = pid;
        children[0].managed_pid = pid;
    }

    cleanup_direct_runtime(
        &mut children,
        Vec::new(),
        &runtime_state_path,
        Some(&control_socket_paths),
        Some(runtime_dir),
    )
    .await;

    assert!(
        fs::symlink_metadata(&control_socket_paths.artifact_link).is_ok(),
        "artifact control socket link should remain available for future runs"
    );
    assert_eq!(
        fs::read_link(&control_socket_paths.artifact_link)
            .expect("artifact link should still point at current alias"),
        control_socket_paths.current_link
    );
    assert!(
        fs::symlink_metadata(&control_socket_paths.current_link).is_err(),
        "current control socket link should be removed"
    );
    assert!(
        fs::metadata(&control_socket_paths.runtime).is_err(),
        "runtime control socket should be removed"
    );
    assert!(
        fs::metadata(&runtime_state_path).is_err(),
        "runtime state should be removed"
    );
    assert!(
        fs::metadata(&runtime_root).is_err(),
        "runtime workspace should be removed"
    );

    assert!(
        children[0].wrapper.is_none(),
        "cleanup should reap partial-startup child"
    );
}

#[test]
fn write_direct_runtime_state_preserves_projected_router_mesh_port() {
    let plan_root = tempfile::tempdir().expect("temp dir should be created");
    let existing = DirectRuntimeState {
        router_mesh_port: Some(24000),
        component_mesh_port_by_id: BTreeMap::from([(1, 20001)]),
        ..Default::default()
    };
    write_direct_runtime_state(plan_root.path(), &existing)
        .expect("existing runtime state should be written");

    let replacement = DirectRuntimeState {
        component_mesh_port_by_id: BTreeMap::from([(2, 20002)]),
        ..Default::default()
    };
    write_direct_runtime_state(plan_root.path(), &replacement)
        .expect("replacement runtime state should be written");

    let persisted = read_direct_runtime_state(&direct_runtime_state_path(plan_root.path()))
        .expect("persisted runtime state should be readable");
    assert_eq!(persisted.router_mesh_port, Some(24000));
    assert_eq!(
        persisted.component_mesh_port_by_id,
        replacement.component_mesh_port_by_id
    );
}

#[cfg(unix)]
#[tokio::test]
async fn supervise_children_treats_zero_exit_as_success() {
    let child = TokioCommand::new("sh")
        .arg("-c")
        .arg("exit 0")
        .spawn()
        .expect("child should spawn");
    let mut children = vec![ManagedChild {
        name: "ok-child".to_string(),
        wrapper: Some(child),
        #[cfg(target_os = "linux")]
        wrapper_pid: 0,
        #[cfg(target_os = "linux")]
        managed_pid: 0,
    }];
    #[cfg(target_os = "linux")]
    {
        let pid = children[0]
            .wrapper
            .as_ref()
            .and_then(tokio::process::Child::id)
            .expect("child pid should be available");
        children[0].wrapper_pid = pid;
        children[0].managed_pid = pid;
    }

    let (reason, exit_code) = supervise_children(&mut children)
        .await
        .expect("supervision should succeed");
    assert_eq!(exit_code, 0);
    match reason {
        RuntimeExitReason::ChildExited { name, status } => {
            assert_eq!(name, "ok-child");
            assert!(status.success());
        }
        RuntimeExitReason::CtrlC => panic!("unexpected Ctrl+C reason"),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn supervise_children_propagates_non_zero_exit() {
    let child = TokioCommand::new("sh")
        .arg("-c")
        .arg("exit 7")
        .spawn()
        .expect("child should spawn");
    let mut children = vec![ManagedChild {
        name: "fail-child".to_string(),
        wrapper: Some(child),
        #[cfg(target_os = "linux")]
        wrapper_pid: 0,
        #[cfg(target_os = "linux")]
        managed_pid: 0,
    }];
    #[cfg(target_os = "linux")]
    {
        let pid = children[0]
            .wrapper
            .as_ref()
            .and_then(tokio::process::Child::id)
            .expect("child pid should be available");
        children[0].wrapper_pid = pid;
        children[0].managed_pid = pid;
    }

    let (reason, exit_code) = supervise_children(&mut children)
        .await
        .expect("supervision should succeed");
    assert_eq!(exit_code, 7);
    match reason {
        RuntimeExitReason::ChildExited { name, status } => {
            assert_eq!(name, "fail-child");
            assert_eq!(status.code(), Some(7));
        }
        RuntimeExitReason::CtrlC => panic!("unexpected Ctrl+C reason"),
    }
}

#[cfg(target_os = "linux")]
#[test]
fn normalize_linux_writable_dir_resolves_symlink_prefix() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("temp dir should be created");
    let real_root = temp.path().join("real");
    fs::create_dir_all(&real_root).expect("real root should be created");
    let symlink_root = temp.path().join("symlink");
    symlink(&real_root, &symlink_root).expect("symlink should be created");

    let normalized = normalize_linux_writable_dir(&symlink_root.join("nested/dir"));
    assert_eq!(normalized, real_root.join("nested/dir"));
}

#[cfg(target_os = "linux")]
fn linux_test_process_spec() -> ProcessSpec {
    ProcessSpec {
        name: "component".to_string(),
        program: "/bin/echo".to_string(),
        args: vec!["ok".to_string()],
        env: BTreeMap::new(),
        work_dir: PathBuf::from("/tmp/amber-work"),
        sandbox: ProcessSandbox::Sandboxed,
        drop_all_caps: false,
        #[cfg(target_os = "linux")]
        read_only_mounts: Vec::new(),
        writable_dirs: Vec::new(),
        bind_dirs: Vec::new(),
        bind_mounts: Vec::new(),
        hidden_paths: Vec::new(),
        network: ProcessNetwork::Host,
    }
}

#[cfg(target_os = "linux")]
#[test]
fn rewrite_mesh_listen_for_slirp_guest_rewrites_loopback_only() {
    assert_eq!(
        rewrite_mesh_listen_for_slirp_guest("127.0.0.1:23000".parse().expect("addr")),
        "0.0.0.0:23000".parse().expect("addr")
    );
    assert_eq!(
        rewrite_mesh_listen_for_slirp_guest("192.168.1.10:23000".parse().expect("addr")),
        "192.168.1.10:23000".parse().expect("addr")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn rewrite_peer_addr_for_slirp_gateway_rewrites_loopback_only() {
    assert_eq!(
        rewrite_peer_addr_for_slirp_gateway("127.0.0.1:23000"),
        "10.0.2.2:23000"
    );
    assert_eq!(
        rewrite_peer_addr_for_slirp_gateway("[::1]:24000"),
        "10.0.2.2:24000"
    );
    assert_eq!(
        rewrite_peer_addr_for_slirp_gateway("192.168.1.10:25000"),
        "192.168.1.10:25000"
    );
    assert_eq!(
        rewrite_peer_addr_for_slirp_gateway("not-a-socket"),
        "not-a-socket"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn rewrite_loopback_url_for_slirp_gateway_rewrites_loopback_only() {
    assert_eq!(
        rewrite_loopback_url_for_slirp_gateway("http://127.0.0.1:23000/base?x=1"),
        "http://10.0.2.2:23000/base?x=1"
    );
    assert_eq!(
        rewrite_loopback_url_for_slirp_gateway("http://localhost:24000"),
        "http://10.0.2.2:24000/"
    );
    assert_eq!(
        rewrite_loopback_url_for_slirp_gateway("http://192.168.1.10:25000/path"),
        "http://192.168.1.10:25000/path"
    );
    assert_eq!(
        rewrite_loopback_url_for_slirp_gateway("not-a-url"),
        "not-a-url"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn rewrite_sidecar_env_passthrough_for_slirp_rewrites_only_dynamic_caps_control_url() {
    assert_eq!(
        rewrite_sidecar_env_passthrough_for_slirp(
            amber_mesh::DYNAMIC_CAPS_CONTROL_URL_ENV,
            "http://127.0.0.1:25000/v1/control-state"
        ),
        "http://10.0.2.2:25000/v1/control-state"
    );
    assert_eq!(
        rewrite_sidecar_env_passthrough_for_slirp("UNRELATED_ENV", "http://127.0.0.1:25000"),
        "http://127.0.0.1:25000"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn slirp4netns_add_hostfwd_payload_uses_guest_default_address() {
    let payload = slirp4netns_add_hostfwd_payload(23000);
    assert_eq!(payload["execute"], "add_hostfwd");
    assert_eq!(payload["arguments"]["proto"], "tcp");
    assert_eq!(payload["arguments"]["host_addr"], "127.0.0.1");
    assert_eq!(payload["arguments"]["host_port"], 23000);
    assert_eq!(payload["arguments"]["guest_port"], 23000);
    assert!(
        payload["arguments"].get("guest_addr").is_none(),
        "guest_addr should be omitted so slirp targets its configured guest address"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn bubblewrap_does_not_emit_tmpfs_for_var_run_symlink_path() {
    let mut sandbox = DirectSandbox::Bubblewrap {
        binary: PathBuf::from("/usr/bin/bwrap"),
    };
    let spec = ProcessSpec {
        writable_dirs: vec![PathBuf::from("/var/run"), PathBuf::from("/run")],
        ..linux_test_process_spec()
    };

    let (_, args) = sandbox
        .wrap_command(&spec)
        .expect("command should be wrapped");
    assert!(
        !args
            .windows(2)
            .any(|pair| pair[0] == "--tmpfs" && pair[1] == "/var/run"),
        "bubblewrap args unexpectedly include --tmpfs /var/run: {args:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn bubblewrap_creates_missing_tmpfs_mountpoints() {
    let mut sandbox = DirectSandbox::Bubblewrap {
        binary: PathBuf::from("/usr/bin/bwrap"),
    };
    let spec = ProcessSpec {
        writable_dirs: vec![PathBuf::from("/__amber_bwrap_test__/nested")],
        ..linux_test_process_spec()
    };

    let (_, args) = sandbox
        .wrap_command(&spec)
        .expect("command should be wrapped");

    let parent_pos = args
        .windows(2)
        .position(|pair| pair[0] == "--dir" && pair[1] == "/__amber_bwrap_test__")
        .expect("expected --dir for parent tmpfs mountpoint");
    let nested_pos = args
        .windows(2)
        .position(|pair| pair[0] == "--dir" && pair[1] == "/__amber_bwrap_test__/nested")
        .expect("expected --dir for tmpfs mountpoint");
    let tmpfs_pos = args
        .windows(2)
        .position(|pair| pair[0] == "--tmpfs" && pair[1] == "/__amber_bwrap_test__/nested")
        .expect("expected --tmpfs for mountpoint");

    assert!(
        parent_pos < nested_pos,
        "--dir parent should precede nested: {args:?}"
    );
    assert!(
        nested_pos < tmpfs_pos,
        "--dir should precede --tmpfs for the same mountpoint: {args:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn bubblewrap_isolated_network_adds_unshare_net() {
    let mut sandbox = DirectSandbox::Bubblewrap {
        binary: PathBuf::from("/usr/bin/bwrap"),
    };
    let spec = ProcessSpec {
        network: ProcessNetwork::Isolated,
        ..linux_test_process_spec()
    };

    let (_, args) = sandbox
        .wrap_command(&spec)
        .expect("command should be wrapped");
    assert!(
        args.contains(&"--unshare-net".to_string()),
        "bubblewrap args missing --unshare-net: {args:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn bubblewrap_can_drop_all_caps_for_internal_processes() {
    let mut sandbox = DirectSandbox::Bubblewrap {
        binary: PathBuf::from("/usr/bin/bwrap"),
    };
    let spec = ProcessSpec {
        drop_all_caps: true,
        ..linux_test_process_spec()
    };

    let (_, args) = sandbox
        .wrap_command(&spec)
        .expect("command should be wrapped");
    assert!(
        args.windows(2)
            .any(|window| window[0] == "--cap-drop" && window[1] == "ALL"),
        "bubblewrap args should drop all caps when requested: {args:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn bubblewrap_uses_curated_linux_mounts() {
    let mut sandbox = DirectSandbox::Bubblewrap {
        binary: PathBuf::from("/usr/bin/bwrap"),
    };
    let spec = linux_test_process_spec();

    let (_, args) = sandbox
        .wrap_command(&spec)
        .expect("command should be wrapped");
    assert!(
        !args.contains(&"--dev".to_string()),
        "bubblewrap args unexpectedly include --dev: {args:?}"
    );
    assert!(
        !args
            .windows(3)
            .any(|window| { window[0] == "--ro-bind" && window[1] == "/" && window[2] == "/" }),
        "bubblewrap args unexpectedly include a full host root bind: {args:?}"
    );
    assert!(
        args.windows(3)
            .any(|window| { window[0] == "--ro-bind" && window[2] == "/usr" }),
        "bubblewrap args should include the standard /usr mount: {args:?}"
    );
    assert!(
        args.windows(3).any(|window| {
            window[0] == "--dev-bind" && window[1] == "/dev/null" && window[2] == "/dev/null"
        }),
        "bubblewrap args should bind /dev/null explicitly: {args:?}"
    );
    assert!(
        !args.windows(3).any(|window| {
            window[0] == "--dev-bind" && window[1] == "/dev" && window[2] == "/dev"
        }),
        "bubblewrap args unexpectedly include the full host /dev tree: {args:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn insert_bubblewrap_info_fd_places_flag_before_command_separator() {
    let mut args = vec![
        "--die-with-parent".to_string(),
        "--tmpfs".to_string(),
        "/tmp".to_string(),
        "--".to_string(),
        "/bin/echo".to_string(),
        "ok".to_string(),
    ];

    insert_bubblewrap_info_fd(&mut args, 3).expect("info fd should be inserted");

    assert_eq!(
        args,
        vec![
            "--die-with-parent".to_string(),
            "--tmpfs".to_string(),
            "/tmp".to_string(),
            "--info-fd".to_string(),
            "3".to_string(),
            "--".to_string(),
            "/bin/echo".to_string(),
            "ok".to_string(),
        ]
    );
}

#[cfg(target_os = "linux")]
#[test]
fn parse_bubblewrap_child_pid_reads_payload() {
    let raw = r#"{
            "child-pid": 4242,
            "child-pidns": "pid:[4026532834]"
        }"#;

    let pid = parse_bubblewrap_child_pid(raw).expect("bubblewrap info payload should parse");
    assert_eq!(pid, 4242);
}

#[cfg(target_os = "linux")]
#[test]
fn bubblewrap_join_network_reuses_existing_namespace() {
    let mut sandbox = DirectSandbox::Bubblewrap {
        binary: PathBuf::from("/usr/bin/bwrap"),
    };
    let spec = ProcessSpec {
        network: ProcessNetwork::Join(12345),
        ..linux_test_process_spec()
    };

    let (program, args) = sandbox
        .wrap_command(&spec)
        .expect("command should be wrapped");
    assert_eq!(program, "/usr/bin/bwrap");
    assert!(
        !args.contains(&"--unshare-net".to_string()),
        "join mode should not unshare net: {args:?}"
    );
}
