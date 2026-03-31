use super::*;

pub(crate) fn build_vm_launch_preview(
    host: VmHostContext<'_>,
    component: &VmComponentPlan,
    port_assignments: &VmPortAssignments,
    runtime_context: &RuntimeTemplateContext,
    component_config: &VmPreviewComponentConfig,
) -> VmLaunchPreview {
    let artifacts = build_vm_launch_artifacts(host, component);
    let component_config_value = component_config.config.as_ref();
    let component_schema = component_config.schema.as_ref();
    let component_config_error = component_config.error.as_deref();
    let mut unresolved_fields = Vec::new();

    let base_image = match preview_vm_base_image(
        &component.base_image,
        component_config_value,
        component_config_error,
    ) {
        Ok(path) => Some(path.display().to_string()),
        Err(detail) => {
            unresolved_fields.push(vm_launch_preview_issue("base_image", detail));
            None
        }
    };
    let cpus = match preview_vm_scalar(
        &component.cpus,
        "program.vm.cpus",
        component_config_value,
        component_config_error,
    ) {
        Ok(value) => Some(value),
        Err(detail) => {
            unresolved_fields.push(vm_launch_preview_issue("cpus", detail));
            None
        }
    };
    let memory_mib = match preview_vm_scalar(
        &component.memory_mib,
        "program.vm.memory_mib",
        component_config_value,
        component_config_error,
    ) {
        Ok(value) => Some(value),
        Err(detail) => {
            unresolved_fields.push(vm_launch_preview_issue("memory_mib", detail));
            None
        }
    };
    if let Err(detail) = preview_vm_mounts(
        component.mount_spec_b64.as_deref(),
        component_config_value,
        component_schema,
        runtime_context,
    ) {
        unresolved_fields.push(vm_launch_preview_issue("runtime_mounts", detail));
    }
    if let Err(detail) = preview_vm_template_string(
        component.cloud_init_user_data.as_ref(),
        "cloud_init_user_data",
        component_config_value,
        component_config_error,
        runtime_context,
    ) {
        unresolved_fields.push(vm_launch_preview_issue("cloud_init_user_data", detail));
    }
    if let Err(detail) = preview_vm_template_string(
        component.cloud_init_vendor_data.as_ref(),
        "cloud_init_vendor_data",
        component_config_value,
        component_config_error,
        runtime_context,
    ) {
        unresolved_fields.push(vm_launch_preview_issue("cloud_init_vendor_data", detail));
    }

    let command = match (cpus, memory_mib) {
        (Some(cpus), Some(memory_mib)) => match build_vm_qemu_command(
            host,
            component,
            port_assignments,
            cpus,
            memory_mib,
            &artifacts,
        ) {
            Ok(command) => command,
            Err(err) => {
                unresolved_fields.push(vm_launch_preview_issue(
                    "command",
                    format!("failed to build QEMU launch command: {err}"),
                ));
                Vec::new()
            }
        },
        _ => Vec::new(),
    };

    let persistent_disks = artifacts
        .persistent_disks
        .iter()
        .map(|disk| VmPersistentDiskPreview {
            serial: disk.serial.clone(),
            mount_path: disk.mount_path.clone(),
            host_path: disk.host_path.display().to_string(),
        })
        .collect::<Vec<_>>();

    VmLaunchPreview {
        name: component.log_name.clone(),
        command,
        base_image,
        overlay_path: artifacts.overlay_path.display().to_string(),
        runtime_disk_path: artifacts
            .runtime_disk_path
            .as_ref()
            .map(|path| path.display().to_string()),
        seed_disk_path: artifacts.seed_disk_path.display().to_string(),
        qmp_socket: artifacts.qmp_socket.display().to_string(),
        serial_log: artifacts.serial_log.display().to_string(),
        cpus,
        memory_mib,
        persistent_disks,
        unresolved_fields,
    }
}

pub(crate) fn build_vm_site_launch_preview(
    plan_path: &Path,
    storage_root: &Path,
    runtime_root: &Path,
    router_mesh_port: Option<u16>,
) -> Result<VmSiteLaunchPreview> {
    let plan_path = canonicalize_path(plan_path, "vm plan")?;
    let VmRuntimeInputs {
        plan_root,
        vm_plan,
        mesh_plan,
    } = load_vm_runtime_inputs(&plan_path)?;

    let port_assignments = materialize_vm_runtime(
        &plan_root,
        runtime_root,
        &vm_plan,
        &mesh_plan,
        router_mesh_port,
        true,
    )?;
    let arch = host_arch()?;
    let (qemu_system, qemu_warning) = preview_qemu_system_binary(arch);
    let (amber_cli, amber_warning) = preview_amber_binary();
    let accel = detect_qemu_accel();
    let components_by_id = vm_plan
        .components
        .iter()
        .map(|component| (component.id, component))
        .collect::<HashMap<_, _>>();
    let runtime_context =
        build_vm_runtime_template_context(&vm_plan.runtime_addresses, &port_assignments.state)?;

    let router_public_key_b64 = vm_plan
        .router
        .as_ref()
        .map(|router| {
            read_mesh_config_public(&runtime_root.join(&router.mesh_config_path)).map(|config| {
                base64::engine::general_purpose::STANDARD.encode(config.identity.public_key)
            })
        })
        .transpose()?;

    let mut virtual_machines = Vec::new();
    let mut inspectability_warnings = Vec::new();
    inspectability_warnings.extend(qemu_warning);
    inspectability_warnings.extend(amber_warning);
    for component_id in &vm_plan.startup_order {
        let component = components_by_id.get(component_id).copied().ok_or_else(|| {
            miette::miette!(
                "vm plan startup order references unknown component id {}",
                component_id
            )
        })?;
        let component_config =
            build_vm_preview_component_config(component.runtime_config.as_ref(), &runtime_context);
        virtual_machines.push(build_vm_launch_preview(
            VmHostContext {
                runtime_root,
                storage_root,
                qemu_img: Path::new("/dev/null"),
                qemu_system: &qemu_system,
                amber_cli: &amber_cli,
                arch,
                accel,
            },
            component,
            &port_assignments,
            &runtime_context,
            &component_config,
        ));
    }

    Ok(VmSiteLaunchPreview {
        router_public_key_b64,
        virtual_machines,
        inspectability_warnings,
    })
}

pub(crate) fn build_vm_launch_artifacts(
    host: VmHostContext<'_>,
    component: &VmComponentPlan,
) -> VmLaunchArtifacts {
    let vm_root = host.runtime_root.join("vms").join(&component.log_name);
    let qmp_socket = hashed_temp_socket_path(
        "amber-vm-qmp",
        &format!("component-{}", component.id),
        &vm_root,
    );
    VmLaunchArtifacts {
        overlay_path: vm_root.join("root-overlay.qcow2"),
        runtime_disk_path: component
            .mount_spec_b64
            .as_ref()
            .map(|_| vm_root.join("runtime.img")),
        seed_disk_path: vm_root.join("seed.iso"),
        qmp_socket,
        serial_log: vm_root.join("serial.log"),
        persistent_disks: component
            .storage_mounts
            .iter()
            .map(|mount| VmPersistentDiskArtifact {
                serial: mount.serial.clone(),
                mount_path: mount.mount_path.clone(),
                host_path: storage_image_path(host.storage_root, mount),
            })
            .collect(),
        vm_root,
    }
}

pub(crate) fn build_vm_qemu_command(
    host: VmHostContext<'_>,
    component: &VmComponentPlan,
    port_assignments: &VmPortAssignments,
    cpus: u32,
    memory_mib: u32,
    artifacts: &VmLaunchArtifacts,
) -> Result<Vec<String>> {
    let netdev_arg = build_qemu_user_netdev_arg(host.amber_cli, component, port_assignments)?;
    let mut command = vec![
        host.qemu_system.display().to_string(),
        "-name".to_string(),
        format!("amber-{}", component.log_name),
        "-display".to_string(),
        "none".to_string(),
        "-monitor".to_string(),
        "none".to_string(),
        "-serial".to_string(),
        format!("file:{}", artifacts.serial_log.display()),
        "-qmp".to_string(),
        format!("unix:{},server=on,wait=off", artifacts.qmp_socket.display()),
        "-no-reboot".to_string(),
        "-smp".to_string(),
        cpus.to_string(),
        "-m".to_string(),
        memory_mib.to_string(),
    ];
    command.extend(qemu_machine_args(host.arch, host.accel)?);
    command.extend([
        "-device".to_string(),
        "virtio-rng-pci,rombar=0".to_string(),
        "-netdev".to_string(),
        netdev_arg,
        "-device".to_string(),
        QEMU_VIRTIO_NET_DEVICE.to_string(),
    ]);
    push_qemu_block_device(
        &mut command,
        "root",
        "qcow2",
        &artifacts.overlay_path,
        false,
        None,
        Some(1),
    );
    push_qemu_block_device(
        &mut command,
        "seed",
        "raw",
        &artifacts.seed_disk_path,
        true,
        None,
        None,
    );
    if let Some(runtime_disk_path) = artifacts.runtime_disk_path.as_ref() {
        push_qemu_block_device(
            &mut command,
            "runtime",
            "raw",
            runtime_disk_path,
            true,
            Some("amber-runtime"),
            None,
        );
    }
    for disk in &artifacts.persistent_disks {
        push_qemu_block_device(
            &mut command,
            &disk.serial,
            "qcow2",
            &disk.host_path,
            false,
            Some(disk.serial.as_str()),
            None,
        );
    }
    Ok(command)
}

pub(crate) fn build_vm_preview_component_config(
    payload: Option<&DirectRuntimeConfigPayload>,
    runtime_context: &RuntimeTemplateContext,
) -> VmPreviewComponentConfig {
    match build_component_config(payload, runtime_context) {
        Ok(Some((config, schema))) => VmPreviewComponentConfig {
            config: Some(config),
            schema: Some(schema),
            error: None,
        },
        Ok(None) => VmPreviewComponentConfig::default(),
        Err(err) => VmPreviewComponentConfig {
            config: None,
            schema: None,
            error: Some(err.to_string()),
        },
    }
}

pub(crate) fn preview_vm_scalar(
    plan: &VmScalarPlanU32,
    field_name: &str,
    component_config: Option<&Value>,
    component_config_error: Option<&str>,
) -> std::result::Result<u32, String> {
    match plan {
        VmScalarPlanU32::Literal { .. } => {
            resolve_vm_scalar(plan, field_name, component_config).map_err(|err| err.to_string())
        }
        VmScalarPlanU32::RuntimeConfig { .. } => {
            if component_config.is_none() {
                return Err(preview_vm_config_dependency_error(
                    field_name,
                    component_config_error,
                ));
            }
            resolve_vm_scalar(plan, field_name, component_config).map_err(|err| err.to_string())
        }
    }
}

pub(crate) fn preview_vm_base_image(
    plan: &VmHostPathPlan,
    component_config: Option<&Value>,
    component_config_error: Option<&str>,
) -> std::result::Result<PathBuf, String> {
    match plan {
        VmHostPathPlan::Static { path } => {
            resolve_vm_runtime_host_path(path, None).map_err(|err| err.to_string())
        }
        VmHostPathPlan::RuntimeConfig { query, source_dir } => {
            let path = preview_vm_runtime_config(
                query,
                "program.vm.image",
                component_config,
                component_config_error,
            )?;
            resolve_vm_runtime_host_path(&path, source_dir.as_deref())
                .map_err(|err| err.to_string())
        }
        VmHostPathPlan::RuntimeTemplate { parts, source_dir } => {
            let rendered = preview_vm_host_path_template(
                parts,
                component_config,
                component_config_error,
                "program.vm.image",
            )?;
            resolve_vm_runtime_host_path(&rendered, source_dir.as_deref())
                .map_err(|err| err.to_string())
        }
    }
}

pub(crate) fn preview_vm_mounts(
    mount_spec_b64: Option<&str>,
    component_config: Option<&Value>,
    component_schema: Option<&Value>,
    runtime_context: &RuntimeTemplateContext,
) -> std::result::Result<(), String> {
    render_mount_files(
        mount_spec_b64,
        component_config,
        component_schema,
        runtime_context,
    )
    .map(|_| ())
    .map_err(|err| err.to_string())
}

pub(crate) fn preview_vm_template_string(
    plan: Option<&VmTemplateStringPlan>,
    field_name: &str,
    component_config: Option<&Value>,
    component_config_error: Option<&str>,
    runtime_context: &RuntimeTemplateContext,
) -> std::result::Result<(), String> {
    let Some(plan) = plan else {
        return Ok(());
    };
    match plan {
        VmTemplateStringPlan::Static { .. } => Ok(()),
        VmTemplateStringPlan::RuntimeTemplate { parts } => {
            let requires_config = parts
                .iter()
                .any(|part| matches!(part, TemplatePart::Config { .. }));
            if requires_config && component_config.is_none() {
                return Err(preview_vm_config_dependency_error(
                    field_name,
                    component_config_error,
                ));
            }
            let empty = Value::Object(Default::default());
            let component_config = component_config.unwrap_or(&empty);
            render_template_string_with_context(parts, component_config, runtime_context)
                .map(|_| ())
                .map_err(|err| format!("failed to render {field_name}: {err}"))
        }
    }
}

pub(crate) fn preview_vm_host_path_template(
    parts: &[VmHostPathPart],
    component_config: Option<&Value>,
    component_config_error: Option<&str>,
    field_name: &str,
) -> std::result::Result<String, String> {
    let mut rendered = String::new();
    for part in parts {
        match part {
            VmHostPathPart::Literal { value } => rendered.push_str(value),
            VmHostPathPart::RuntimeConfig { query } => {
                rendered.push_str(&preview_vm_runtime_config(
                    query,
                    field_name,
                    component_config,
                    component_config_error,
                )?)
            }
        }
    }
    Ok(rendered)
}

pub(crate) fn preview_vm_runtime_config(
    query: &str,
    field_name: &str,
    component_config: Option<&Value>,
    component_config_error: Option<&str>,
) -> std::result::Result<String, String> {
    if component_config.is_none() {
        return Err(preview_vm_config_dependency_error(
            field_name,
            component_config_error,
        ));
    }
    resolve_vm_runtime_config(component_config, query, field_name).map_err(|err| err.to_string())
}

pub(crate) fn preview_vm_config_dependency_error(
    field_name: &str,
    component_config_error: Option<&str>,
) -> String {
    match component_config_error {
        Some(err) => {
            format!("failed to resolve runtime component config needed by {field_name}: {err}")
        }
        None => {
            format!(
                "{field_name} requires runtime config, but no runtime component config was \
                 provided"
            )
        }
    }
}

pub(crate) fn vm_launch_preview_issue(
    field: &str,
    detail: impl Into<String>,
) -> VmLaunchPreviewIssue {
    VmLaunchPreviewIssue {
        field: field.to_string(),
        detail: detail.into(),
    }
}

pub(crate) fn preview_qemu_system_binary(arch: VmArch) -> (PathBuf, Option<String>) {
    match resolve_qemu_system_binary() {
        Ok(path) => (path, None),
        Err(err) => {
            let guessed = PathBuf::from(match arch {
                VmArch::Aarch64 => "qemu-system-aarch64",
                VmArch::X86_64 => "qemu-system-x86_64",
            });
            (
                guessed.clone(),
                Some(format!(
                    "failed to resolve the host QEMU binary exactly: {err}; preview uses {}",
                    guessed.display()
                )),
            )
        }
    }
}

pub(crate) fn preview_amber_binary() -> (String, Option<String>) {
    match resolve_host_binary("amber") {
        Ok(path) => (path, None),
        Err(err) => (
            "amber".to_string(),
            Some(format!(
                "failed to resolve the host amber binary exactly: {err}; preview uses `amber`"
            )),
        ),
    }
}
