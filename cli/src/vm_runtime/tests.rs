use amber_compiler::reporter::vm::{MESH_PROVISION_PLAN_FILENAME, VmStorageMount};
use amber_mesh::{MeshProtocol, OutboundRoute, TransportConfig};

use super::*;

#[test]
fn vm_storage_root_defaults_next_to_output() {
    let root = vm_storage_root(Path::new("/tmp/out"), None).expect("storage root");
    assert_eq!(root, Path::new("/tmp/.out.amber-state"));
}

#[test]
fn vm_runtime_control_socket_path_is_unique_per_run() {
    let first = tempfile::tempdir().expect("temp dir");
    let second = tempfile::tempdir().expect("temp dir");
    assert_ne!(
        vm_runtime_control_socket_path(first.path()),
        vm_runtime_control_socket_path(second.path())
    );
}

#[test]
fn build_vm_runtime_template_context_uses_guest_slot_host() {
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
    let runtime_state = VmRuntimeState {
        slot_ports_by_component: BTreeMap::from([(
            7,
            BTreeMap::from([("api".to_string(), 31001)]),
        )]),
        slot_route_ports_by_component: BTreeMap::from([(
            8,
            BTreeMap::from([("upstream".to_string(), vec![32001, 32002])]),
        )]),
        route_host_ports_by_component: BTreeMap::new(),
        endpoint_forwards_by_component: BTreeMap::new(),
        component_mesh_port_by_id: BTreeMap::new(),
        router_mesh_port: None,
    };

    let context =
        build_vm_runtime_template_context(&runtime_addresses, &runtime_state).expect("context");

    assert_eq!(
        context
            .slots_by_scope
            .get(&3)
            .and_then(|values| values.get("api")),
        Some(&r#"{"url":"http://10.0.2.100:31001"}"#.to_string())
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
        Some(vec!["http://10.0.2.100:32001", "http://10.0.2.100:32002"])
    );
}

#[test]
fn assign_vm_runtime_ports_preserves_guest_slot_order() {
    let temp = tempfile::tempdir().expect("temp dir");
    let mesh_config_rel = PathBuf::from("mesh/components/app/mesh-config.json");
    let mesh_config_path = temp.path().join(&mesh_config_rel);
    fs::create_dir_all(mesh_config_path.parent().expect("parent")).expect("mkdir");

    let config = MeshConfigPublic {
        identity: MeshIdentityPublic {
            id: "/app".to_string(),
            public_key: [7; 32],
            mesh_scope: None,
        },
        mesh_listen: "127.0.0.1:19000".parse().expect("mesh"),
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
    write_mesh_config_public(&mesh_config_path, &config).expect("write");

    let vm_plan = VmPlan {
        version: VM_PLAN_VERSION.to_string(),
        mesh_provision_plan: MESH_PROVISION_PLAN_FILENAME.to_string(),
        startup_order: vec![7],
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
        components: vec![VmComponentPlan {
            id: 7,
            moniker: "/app".to_string(),
            log_name: "app".to_string(),
            depends_on: Vec::new(),
            mesh_config_path: mesh_config_rel.display().to_string(),
            mesh_identity_path: "mesh/components/app/mesh-identity.json".to_string(),
            cpus: VmScalarPlanU32::Literal { value: 1 },
            memory_mib: VmScalarPlanU32::Literal { value: 512 },
            base_image: VmHostPathPlan::Static {
                path: "/tmp/base.img".to_string(),
            },
            cloud_init_user_data: None,
            cloud_init_vendor_data: None,
            egress: VmEgressPlan::None,
            storage_mounts: vec![VmStorageMount {
                mount_path: "/data".to_string(),
                state_subdir: "app/data-1234".to_string(),
                serial: "amber-1234".to_string(),
                size: "1G".to_string(),
            }],
            runtime_config: None,
            mount_spec_b64: None,
        }],
        router: None,
    };

    let assignments = assign_vm_runtime_ports(temp.path(), &vm_plan, None).expect("ports");
    let runtime_ports = assignments
        .state
        .slot_route_ports_by_component
        .get(&7)
        .and_then(|slots| slots.get("upstream"))
        .expect("runtime ports");
    assert_eq!(runtime_ports, &vec![20000, 20001]);
}

#[test]
fn build_qemu_user_netdev_arg_uses_guestfwd_bridge_command() {
    let component = VmComponentPlan {
        id: 7,
        moniker: "/bound".to_string(),
        log_name: "bound".to_string(),
        depends_on: Vec::new(),
        mesh_config_path: "mesh/components/bound/mesh-config.json".to_string(),
        mesh_identity_path: "mesh/components/bound/mesh-identity.json".to_string(),
        cpus: VmScalarPlanU32::Literal { value: 1 },
        memory_mib: VmScalarPlanU32::Literal { value: 512 },
        base_image: VmHostPathPlan::Static {
            path: "/tmp/base.img".to_string(),
        },
        cloud_init_user_data: None,
        cloud_init_vendor_data: None,
        egress: VmEgressPlan::None,
        storage_mounts: Vec::new(),
        runtime_config: None,
        mount_spec_b64: None,
    };
    let assignments = VmPortAssignments {
        state: VmRuntimeState {
            slot_ports_by_component: BTreeMap::new(),
            slot_route_ports_by_component: BTreeMap::from([(
                7,
                BTreeMap::from([("api".to_string(), vec![20_000])]),
            )]),
            route_host_ports_by_component: BTreeMap::from([(
                7,
                BTreeMap::from([("api".to_string(), vec![43_071])]),
            )]),
            endpoint_forwards_by_component: BTreeMap::from([(7, BTreeMap::from([(8080, 33_655)]))]),
            component_mesh_port_by_id: BTreeMap::new(),
            router_mesh_port: None,
        },
        route_host_ports_by_component: BTreeMap::from([(
            7,
            BTreeMap::from([("api".to_string(), vec![43_071])]),
        )]),
    };

    let netdev =
        build_qemu_user_netdev_arg("/tmp/amber cli", &component, &assignments).expect("netdev");

    assert!(netdev.contains("guestfwd=tcp:10.0.2.100:20000-cmd:'"));
    assert!(netdev.contains("/tmp/amber cli"));
    assert!(netdev.contains("run-vm-guestfwd-bridge 127.0.0.1:43071"));
    assert!(netdev.contains("hostfwd=tcp:127.0.0.1:33655-:8080"));
}

#[test]
fn build_vm_launch_preview_exposes_qemu_command_and_disk_paths() {
    let temp = tempfile::tempdir().expect("temp dir");
    let runtime_root = temp.path().join("runtime");
    fs::create_dir_all(&runtime_root).expect("runtime dir");
    let storage_root = temp.path().join("storage");
    let base_image = temp.path().join("base.img");
    fs::write(&base_image, []).expect("base image");

    let component = VmComponentPlan {
        id: 7,
        moniker: "/bound".to_string(),
        log_name: "bound".to_string(),
        depends_on: Vec::new(),
        mesh_config_path: "mesh/components/bound/mesh-config.json".to_string(),
        mesh_identity_path: "mesh/components/bound/mesh-identity.json".to_string(),
        cpus: VmScalarPlanU32::Literal { value: 1 },
        memory_mib: VmScalarPlanU32::Literal { value: 512 },
        base_image: VmHostPathPlan::Static {
            path: base_image.display().to_string(),
        },
        cloud_init_user_data: None,
        cloud_init_vendor_data: None,
        egress: VmEgressPlan::None,
        storage_mounts: vec![VmStorageMount {
            mount_path: "/data".to_string(),
            state_subdir: "bound/data-1234".to_string(),
            serial: "amber-1234".to_string(),
            size: "1G".to_string(),
        }],
        runtime_config: None,
        mount_spec_b64: Some(base64::engine::general_purpose::STANDARD.encode(b"[]")),
    };
    let assignments = VmPortAssignments {
        state: VmRuntimeState {
            slot_ports_by_component: BTreeMap::new(),
            slot_route_ports_by_component: BTreeMap::from([(
                7,
                BTreeMap::from([("api".to_string(), vec![20_000])]),
            )]),
            route_host_ports_by_component: BTreeMap::from([(
                7,
                BTreeMap::from([("api".to_string(), vec![43_071])]),
            )]),
            endpoint_forwards_by_component: BTreeMap::from([(7, BTreeMap::from([(8080, 33_655)]))]),
            component_mesh_port_by_id: BTreeMap::new(),
            router_mesh_port: None,
        },
        route_host_ports_by_component: BTreeMap::from([(
            7,
            BTreeMap::from([("api".to_string(), vec![43_071])]),
        )]),
    };

    let preview = build_vm_launch_preview(
        VmHostContext {
            runtime_root: &runtime_root,
            storage_root: &storage_root,
            qemu_img: Path::new("/tmp/qemu-img"),
            qemu_system: Path::new("/tmp/qemu-system-x86_64"),
            amber_cli: "/tmp/amber",
            arch: VmArch::X86_64,
            accel: QemuAccel::Tcg,
        },
        &component,
        &assignments,
        &RuntimeTemplateContext::default(),
        &VmPreviewComponentConfig::default(),
    );

    assert_eq!(preview.name, "bound");
    assert_eq!(preview.command[0], "/tmp/qemu-system-x86_64");
    let rendered = preview.command.join(" ");
    assert!(rendered.contains(
        "guestfwd=tcp:10.0.2.100:20000-cmd:/tmp/amber run-vm-guestfwd-bridge 127.0.0.1:43071"
    ));
    assert!(rendered.contains("hostfwd=tcp:127.0.0.1:33655-:8080"));
    assert!(
        preview
            .overlay_path
            .ends_with("vms/bound/root-overlay.qcow2")
    );
    assert!(
        preview
            .runtime_disk_path
            .as_deref()
            .is_some_and(|path| path.ends_with("vms/bound/runtime.img"))
    );
    assert!(preview.seed_disk_path.ends_with("vms/bound/seed.iso"));
    assert_eq!(preview.cpus, Some(1));
    assert_eq!(preview.memory_mib, Some(512));
    assert_eq!(
        preview.base_image.as_deref(),
        Some(base_image.to_string_lossy().as_ref())
    );
    assert_eq!(preview.persistent_disks.len(), 1);
    assert_eq!(
        preview.persistent_disks[0].host_path,
        storage_root
            .join("bound/data-1234")
            .with_extension("qcow2")
            .display()
            .to_string()
    );
    assert!(preview.unresolved_fields.is_empty());
}

#[test]
fn build_vm_launch_preview_keeps_command_when_base_image_is_unresolved() {
    let temp = tempfile::tempdir().expect("temp dir");
    let runtime_root = temp.path().join("runtime");
    fs::create_dir_all(&runtime_root).expect("runtime dir");
    let storage_root = temp.path().join("storage");

    let component = VmComponentPlan {
        id: 7,
        moniker: "/bound".to_string(),
        log_name: "bound".to_string(),
        depends_on: Vec::new(),
        mesh_config_path: "mesh/components/bound/mesh-config.json".to_string(),
        mesh_identity_path: "mesh/components/bound/mesh-identity.json".to_string(),
        cpus: VmScalarPlanU32::Literal { value: 1 },
        memory_mib: VmScalarPlanU32::Literal { value: 512 },
        base_image: VmHostPathPlan::RuntimeConfig {
            query: "base_image".to_string(),
            source_dir: None,
        },
        cloud_init_user_data: None,
        cloud_init_vendor_data: None,
        egress: VmEgressPlan::None,
        storage_mounts: Vec::new(),
        runtime_config: None,
        mount_spec_b64: None,
    };
    let assignments = VmPortAssignments {
        state: VmRuntimeState {
            slot_ports_by_component: BTreeMap::new(),
            slot_route_ports_by_component: BTreeMap::from([(
                7,
                BTreeMap::from([("api".to_string(), vec![20_000])]),
            )]),
            route_host_ports_by_component: BTreeMap::from([(
                7,
                BTreeMap::from([("api".to_string(), vec![43_071])]),
            )]),
            endpoint_forwards_by_component: BTreeMap::from([(7, BTreeMap::from([(8080, 33_655)]))]),
            component_mesh_port_by_id: BTreeMap::new(),
            router_mesh_port: None,
        },
        route_host_ports_by_component: BTreeMap::from([(
            7,
            BTreeMap::from([("api".to_string(), vec![43_071])]),
        )]),
    };

    let preview = build_vm_launch_preview(
        VmHostContext {
            runtime_root: &runtime_root,
            storage_root: &storage_root,
            qemu_img: Path::new("/tmp/qemu-img"),
            qemu_system: Path::new("/tmp/qemu-system-x86_64"),
            amber_cli: "/tmp/amber",
            arch: VmArch::X86_64,
            accel: QemuAccel::Tcg,
        },
        &component,
        &assignments,
        &RuntimeTemplateContext::default(),
        &VmPreviewComponentConfig {
            error: Some(
                "failed to resolve runtime component config: \"base_image\" is a required property"
                    .to_string(),
            ),
            ..Default::default()
        },
    );

    assert!(!preview.command.is_empty());
    assert_eq!(preview.cpus, Some(1));
    assert_eq!(preview.memory_mib, Some(512));
    assert_eq!(preview.base_image, None);
    assert!(preview.unresolved_fields.iter().any(|issue| {
        issue.field == "base_image"
            && issue
                .detail
                .contains("\"base_image\" is a required property")
    }));
}

#[test]
fn render_cloud_init_multipart_keeps_generated_and_user_parts() {
    let rendered = render_cloud_init_multipart(
        "#cloud-boothook\n#!/bin/sh\necho generated\n",
        "#!/bin/sh\necho hi\n",
    );
    assert!(rendered.contains("multipart/mixed"));
    assert!(rendered.contains("text/cloud-boothook"));
    assert!(rendered.contains("text/x-shellscript"));
}

#[test]
fn bootstrap_script_skips_runtime_helper_disk_when_component_has_no_file_mounts() {
    let component = VmComponentPlan {
        id: 1,
        moniker: "/app".to_string(),
        log_name: "app".to_string(),
        depends_on: Vec::new(),
        mesh_config_path: "mesh/components/app/mesh-config.json".to_string(),
        mesh_identity_path: "mesh/components/app/mesh-identity.json".to_string(),
        cpus: VmScalarPlanU32::Literal { value: 1 },
        memory_mib: VmScalarPlanU32::Literal { value: 512 },
        base_image: VmHostPathPlan::Static {
            path: "/tmp/base.img".to_string(),
        },
        cloud_init_user_data: None,
        cloud_init_vendor_data: None,
        egress: VmEgressPlan::None,
        storage_mounts: vec![VmStorageMount {
            mount_path: "/data".to_string(),
            state_subdir: "app/data-1234".to_string(),
            serial: "amber-1234".to_string(),
            size: "1G".to_string(),
        }],
        runtime_config: None,
        mount_spec_b64: None,
    };

    let script = render_bootstrap_script(&component);
    assert!(!script.contains("/amber/runtime"));
    assert!(script.contains("/dev/vdc"));
}

#[test]
fn bootstrap_script_uses_runtime_disk_before_storage_when_file_mounts_exist() {
    let component = VmComponentPlan {
        id: 1,
        moniker: "/app".to_string(),
        log_name: "app".to_string(),
        depends_on: Vec::new(),
        mesh_config_path: "mesh/components/app/mesh-config.json".to_string(),
        mesh_identity_path: "mesh/components/app/mesh-identity.json".to_string(),
        cpus: VmScalarPlanU32::Literal { value: 1 },
        memory_mib: VmScalarPlanU32::Literal { value: 512 },
        base_image: VmHostPathPlan::Static {
            path: "/tmp/base.img".to_string(),
        },
        cloud_init_user_data: None,
        cloud_init_vendor_data: None,
        egress: VmEgressPlan::None,
        storage_mounts: vec![VmStorageMount {
            mount_path: "/data".to_string(),
            state_subdir: "app/data-1234".to_string(),
            serial: "amber-1234".to_string(),
            size: "1G".to_string(),
        }],
        runtime_config: None,
        mount_spec_b64: Some("ignored".to_string()),
    };

    let script = render_bootstrap_script(&component);
    assert!(script.contains("mount -t vfat -o ro,exec /dev/vdc /amber/runtime"));
    assert!(script.contains("/dev/vdd"));
}

#[test]
fn resolve_vm_base_image_uses_source_dir_for_runtime_config_paths() {
    let temp = tempfile::tempdir().expect("temp dir");
    let image_dir = temp.path().join("images");
    fs::create_dir_all(&image_dir).expect("image dir");
    let image_path = image_dir.join("base.qcow2");
    fs::write(&image_path, []).expect("image file");

    let component_config = serde_json::json!({
        "vm_image": "images/base.qcow2"
    });
    let resolved = resolve_vm_base_image(
        &VmHostPathPlan::RuntimeConfig {
            query: "vm_image".to_string(),
            source_dir: Some(temp.path().display().to_string()),
        },
        Some(&component_config),
    )
    .expect("base image");

    assert_eq!(resolved, image_path);
}
