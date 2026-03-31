use super::*;

pub(crate) fn create_overlay_image(
    qemu_img: &Path,
    base_image: &Path,
    overlay_path: &Path,
) -> Result<()> {
    let base_info = qemu_img_info(qemu_img, base_image)?;
    if overlay_path.exists() {
        fs::remove_file(overlay_path)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!("failed to remove stale overlay {}", overlay_path.display())
            })?;
    }
    run_checked_command(
        ProcessCommand::new(qemu_img)
            .arg("create")
            .arg("-f")
            .arg("qcow2")
            .arg("-F")
            .arg(&base_info.format)
            .arg("-b")
            .arg(base_image)
            .arg(overlay_path),
        "create vm overlay image",
    )
}

pub(crate) fn ensure_persistent_image(qemu_img: &Path, path: &Path, size: &str) -> Result<()> {
    if path.is_file() {
        return Ok(());
    }
    let size = normalize_qemu_image_size(size)?;
    let parent = path
        .parent()
        .ok_or_else(|| miette::miette!("invalid persistent storage path {}", path.display()))?;
    fs::create_dir_all(parent)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create storage directory {}", parent.display()))?;
    run_checked_command(
        ProcessCommand::new(qemu_img)
            .arg("create")
            .arg("-f")
            .arg("qcow2")
            .arg(path)
            .arg(&size),
        "create vm persistent storage image",
    )
}

pub(crate) fn normalize_qemu_image_size(size: &str) -> Result<String> {
    let trimmed = size.trim();
    if trimmed.is_empty() {
        return Err(miette::miette!("vm storage size must not be empty"));
    }
    for (suffix, qemu_suffix) in [
        ("KiB", "K"),
        ("Ki", "K"),
        ("MiB", "M"),
        ("Mi", "M"),
        ("GiB", "G"),
        ("Gi", "G"),
        ("TiB", "T"),
        ("Ti", "T"),
        ("PiB", "P"),
        ("Pi", "P"),
        ("EiB", "E"),
        ("Ei", "E"),
    ] {
        if let Some(number) = trimmed.strip_suffix(suffix) {
            let number = number.trim();
            if number.is_empty() {
                return Err(miette::miette!("vm storage size must not be empty"));
            }
            return Ok(format!("{number}{qemu_suffix}"));
        }
    }
    Ok(trimmed.to_string())
}

pub(crate) fn storage_image_path(
    storage_root: &Path,
    mount: &amber_compiler::reporter::vm::VmStorageMount,
) -> PathBuf {
    storage_root
        .join(&mount.state_subdir)
        .with_extension("qcow2")
}

pub(crate) fn qemu_img_info(qemu_img: &Path, image: &Path) -> Result<QemuImgInfo> {
    let output = ProcessCommand::new(qemu_img)
        .arg("info")
        .arg("--output=json")
        .arg(image)
        .output()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to inspect vm image {}", image.display()))?;
    if !output.status.success() {
        return Err(miette::miette!(
            "failed to inspect vm image {}: {}",
            image.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|err| {
        miette::miette!(
            "invalid qemu-img info output for {}: {err}",
            image.display()
        )
    })
}

pub(crate) fn run_checked_command(command: &mut ProcessCommand, description: &str) -> Result<()> {
    let rendered = render_process_command(command);
    let output = command
        .output()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to {description}: {rendered}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(miette::miette!(
        "failed to {description}: {}\nstdout:\n{}\nstderr:\n{}",
        rendered,
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

pub(crate) fn render_process_command(command: &ProcessCommand) -> String {
    let program = command.get_program().to_string_lossy();
    let args = command
        .get_args()
        .map(|arg| shell_quote(&arg.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(" ");
    if args.is_empty() {
        program.into_owned()
    } else {
        format!("{program} {args}")
    }
}

pub(crate) fn write_fat_image(
    path: &Path,
    size: u64,
    volume_label: [u8; 11],
    files: &[RuntimeDiskFile],
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create image directory {}", parent.display()))?;
    }
    let file = File::options()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create image {}", path.display()))?;
    file.set_len(size)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to size image {}", path.display()))?;
    let mut file = file;
    format_volume(
        &mut file,
        FormatVolumeOptions::new().volume_label(volume_label),
    )
    .into_diagnostic()
    .wrap_err_with(|| format!("failed to format FAT image {}", path.display()))?;
    file.seek(SeekFrom::Start(0))
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to rewind FAT image {}", path.display()))?;
    let fs = FileSystem::new(file, FsOptions::new())
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to open FAT image {}", path.display()))?;
    let root = fs.root_dir();
    for item in files {
        let path = Path::new(&item.path);
        if path.is_absolute() {
            return Err(miette::miette!(
                "FAT image path {} must be relative",
                path.display()
            ));
        }
        let mut parent = root.clone();
        let components = path
            .components()
            .map(|component| component.as_os_str().to_string_lossy().to_string())
            .collect::<Vec<_>>();
        for component in components.iter().take(components.len().saturating_sub(1)) {
            parent = match parent.open_dir(component) {
                Ok(dir) => dir,
                Err(_) => parent
                    .create_dir(component)
                    .into_diagnostic()
                    .wrap_err_with(|| {
                        format!(
                            "failed to create FAT directory {} in {}",
                            component,
                            path.display()
                        )
                    })?,
            };
        }
        let file_name = components
            .last()
            .ok_or_else(|| miette::miette!("FAT image entry path must not be empty"))?;
        let mut file = parent
            .create_file(file_name)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "failed to create FAT image file {} in {}",
                    file_name,
                    path.display()
                )
            })?;
        file.write_all(&item.contents)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to write FAT image file {}", path.display()))?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum CloudInitSeedTool {
    #[cfg(target_os = "macos")]
    Hdiutil,
    #[cfg(target_os = "linux")]
    Genisoimage,
    #[cfg(target_os = "linux")]
    Mkisofs,
    #[cfg(target_os = "linux")]
    Xorriso,
    #[cfg(target_os = "linux")]
    CloudLocalds,
}

pub(crate) fn write_cloud_init_seed_image(
    path: &Path,
    user_data: &str,
    meta_data: &str,
    vendor_data: Option<&str>,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!("failed to create seed image directory {}", parent.display())
            })?;
    }
    if path.exists() {
        fs::remove_file(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to remove stale seed image {}", path.display()))?;
    }

    let staging = tempfile::Builder::new()
        .prefix("amber-vm-seed-")
        .tempdir()
        .into_diagnostic()
        .wrap_err("failed to create cloud-init seed staging directory")?;
    fs::write(staging.path().join("user-data"), user_data)
        .into_diagnostic()
        .wrap_err("failed to write cloud-init user-data")?;
    fs::write(staging.path().join("meta-data"), meta_data)
        .into_diagnostic()
        .wrap_err("failed to write cloud-init meta-data")?;
    if let Some(vendor_data) = vendor_data {
        fs::write(staging.path().join("vendor-data"), vendor_data)
            .into_diagnostic()
            .wrap_err("failed to write cloud-init vendor-data")?;
    }

    match detect_cloud_init_seed_tool(vendor_data.is_some())? {
        #[cfg(target_os = "macos")]
        CloudInitSeedTool::Hdiutil => run_checked_command(
            ProcessCommand::new("/usr/bin/hdiutil")
                .arg("makehybrid")
                .arg("-quiet")
                .arg("-iso")
                .arg("-joliet")
                .arg("-default-volume-name")
                .arg("CIDATA")
                .arg("-o")
                .arg(path)
                .arg(staging.path()),
            "create vm cloud-init seed image",
        ),
        #[cfg(target_os = "linux")]
        CloudInitSeedTool::Genisoimage => run_checked_command(
            ProcessCommand::new("genisoimage")
                .current_dir(staging.path())
                .arg("-quiet")
                .arg("-volid")
                .arg("CIDATA")
                .arg("-joliet")
                .arg("-rock")
                .arg("-output")
                .arg(path)
                .arg("user-data")
                .arg("meta-data")
                .args(vendor_data.map(|_| "vendor-data")),
            "create vm cloud-init seed image",
        ),
        #[cfg(target_os = "linux")]
        CloudInitSeedTool::Mkisofs => run_checked_command(
            ProcessCommand::new("mkisofs")
                .current_dir(staging.path())
                .arg("-quiet")
                .arg("-volid")
                .arg("CIDATA")
                .arg("-joliet")
                .arg("-rock")
                .arg("-output")
                .arg(path)
                .arg("user-data")
                .arg("meta-data")
                .args(vendor_data.map(|_| "vendor-data")),
            "create vm cloud-init seed image",
        ),
        #[cfg(target_os = "linux")]
        CloudInitSeedTool::Xorriso => run_checked_command(
            ProcessCommand::new("xorriso")
                .current_dir(staging.path())
                .arg("-as")
                .arg("mkisofs")
                .arg("-quiet")
                .arg("-volid")
                .arg("CIDATA")
                .arg("-joliet")
                .arg("-rock")
                .arg("-output")
                .arg(path)
                .arg("user-data")
                .arg("meta-data")
                .args(vendor_data.map(|_| "vendor-data")),
            "create vm cloud-init seed image",
        ),
        #[cfg(target_os = "linux")]
        CloudInitSeedTool::CloudLocalds => run_checked_command(
            ProcessCommand::new("cloud-localds")
                .arg("--filesystem")
                .arg("iso")
                .arg(path)
                .arg(staging.path().join("user-data"))
                .arg(staging.path().join("meta-data")),
            "create vm cloud-init seed image",
        ),
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn detect_cloud_init_seed_tool(needs_vendor_data: bool) -> Result<CloudInitSeedTool> {
    let _ = needs_vendor_data;
    Ok(CloudInitSeedTool::Hdiutil)
}

#[cfg(target_os = "linux")]
pub(crate) fn detect_cloud_init_seed_tool(needs_vendor_data: bool) -> Result<CloudInitSeedTool> {
    if find_executable_in_path("genisoimage").is_some() {
        return Ok(CloudInitSeedTool::Genisoimage);
    }
    if find_executable_in_path("mkisofs").is_some() {
        return Ok(CloudInitSeedTool::Mkisofs);
    }
    if find_executable_in_path("xorriso").is_some() {
        return Ok(CloudInitSeedTool::Xorriso);
    }
    if !needs_vendor_data && find_executable_in_path("cloud-localds").is_some() {
        return Ok(CloudInitSeedTool::CloudLocalds);
    }
    if needs_vendor_data {
        return Err(miette::miette!(
            "building a VM cloud-init seed with vendor-data requires one of `genisoimage`, \
             `mkisofs`, or `xorriso` on PATH"
        ));
    }
    Err(miette::miette!(
        "building a VM cloud-init seed requires one of `genisoimage`, `mkisofs`, `xorriso`, or \
         `cloud-localds` on PATH"
    ))
}

#[cfg(target_os = "linux")]
pub(crate) fn find_executable_in_path(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

pub(crate) fn build_runtime_disk_files(
    mount_files: &[RenderedMountFile],
) -> Result<Vec<RuntimeDiskFile>> {
    let mut files = Vec::new();
    files.push(RuntimeDiskFile {
        path: "apply-mounts.sh".to_string(),
        contents: render_mount_apply_script(mount_files).into_bytes(),
    });
    for (index, mount) in mount_files.iter().enumerate() {
        files.push(RuntimeDiskFile {
            path: format!("mounts/file-{index:04}"),
            contents: mount.contents.as_bytes().to_vec(),
        });
    }
    Ok(files)
}

pub(crate) fn render_mount_apply_script(mount_files: &[RenderedMountFile]) -> String {
    let mut script = String::from("#!/bin/sh\nset -eu\n");
    for (index, mount) in mount_files.iter().enumerate() {
        let source = format!("/amber/runtime/mounts/file-{index:04}");
        let target = mount.guest_path.as_str();
        let parent = Path::new(target)
            .parent()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "/".to_string());
        let _ = writeln!(script, "mkdir -p {}", shell_quote(&parent));
        let _ = writeln!(
            script,
            "cp {} {}",
            shell_quote(&source),
            shell_quote(target)
        );
    }
    script
}

pub(crate) fn render_user_data(
    component: &VmComponentPlan,
    component_config: Option<&Value>,
    runtime_context: &RuntimeTemplateContext,
) -> Result<String> {
    let generated = format!("#cloud-boothook\n{}", render_bootstrap_script(component));
    let extra = render_vm_template_string(
        component.cloud_init_user_data.as_ref(),
        component_config,
        runtime_context,
    )?;
    Ok(match extra.as_deref() {
        None => generated,
        Some(extra) => render_cloud_init_multipart(&generated, extra),
    })
}

pub(crate) fn render_vm_template_string(
    plan: Option<&VmTemplateStringPlan>,
    component_config: Option<&Value>,
    runtime_context: &RuntimeTemplateContext,
) -> Result<Option<String>> {
    let Some(plan) = plan else {
        return Ok(None);
    };
    match plan {
        VmTemplateStringPlan::Static { value } => Ok(Some(value.clone())),
        VmTemplateStringPlan::RuntimeTemplate { parts } => {
            let requires_config = parts
                .iter()
                .any(|part| matches!(part, TemplatePart::Config { .. }));
            let empty = Value::Object(Default::default());
            let component_config = match (requires_config, component_config) {
                (true, None) => {
                    return Err(miette::miette!(
                        "vm template requires runtime config, but no runtime config payload was \
                         provided"
                    ));
                }
                (true, Some(config)) => config,
                (false, Some(config)) => config,
                (false, None) => &empty,
            };
            render_template_string_with_context(parts, component_config, runtime_context)
                .map(Some)
                .map_err(|err| miette::miette!("failed to render vm template: {err}"))
        }
    }
}

pub(crate) fn render_bootstrap_script(component: &VmComponentPlan) -> String {
    let mut script = String::from("#!/bin/sh\nexec >/dev/console 2>&1\nset -eux\n");
    let mut next_data_disk_index = 2usize;
    if component.mount_spec_b64.is_some() {
        script.push_str("mkdir -p /amber/runtime\n");
        script.push_str("for _ in $(seq 1 60); do [ -b /dev/vdc ] && break; sleep 1; done\n");
        script.push_str("[ -b /dev/vdc ] || { echo missing runtime helper disk >&2; exit 1; }\n");
        script.push_str("mount -t vfat -o ro,exec /dev/vdc /amber/runtime\n");
        script.push_str(
            "if [ -f /amber/runtime/apply-mounts.sh ]; then /bin/sh \
             /amber/runtime/apply-mounts.sh; fi\n",
        );
        next_data_disk_index += 1;
    }
    for (index, mount) in component.storage_mounts.iter().enumerate() {
        let dev = format!(
            "/dev/vd{}",
            (b'a' + (next_data_disk_index + index) as u8) as char
        );
        let mount_path = shell_quote(&mount.mount_path);
        let dev_quoted = shell_quote(&dev);
        let _ = writeln!(script, "mkdir -p {mount_path}");
        let _ = writeln!(
            script,
            "for _ in $(seq 1 60); do [ -b {dev_quoted} ] && break; sleep 1; done"
        );
        let _ = writeln!(
            script,
            "[ -b {dev_quoted} ] || {{ echo missing storage device {dev_quoted} >&2; exit 1; }}"
        );
        let _ = writeln!(
            script,
            "if ! blkid {dev_quoted} >/dev/null 2>&1; then mkfs.ext4 -F {dev_quoted}; fi"
        );
        let _ = writeln!(
            script,
            "mount {dev_quoted} {mount_path} || mount -o rw {dev_quoted} {mount_path}"
        );
    }
    script.push_str("sync || true\n");
    script.push_str("exit 0\n");
    script
}

pub(crate) fn render_cloud_init_multipart(generated: &str, extra: &str) -> String {
    const BOUNDARY: &str = "===============amber-vm-boundary==";
    let generated_type = cloud_init_content_type(generated);
    let extra_type = cloud_init_content_type(extra);
    format!(
        "MIME-Version: 1.0\nContent-Type: multipart/mixed; \
         boundary=\"{BOUNDARY}\"\n\n--{BOUNDARY}\nContent-Type: {generated_type}; \
         charset=\"us-ascii\"\n\n{generated}\n--{BOUNDARY}\nContent-Type: {extra_type}; \
         charset=\"us-ascii\"\n\n{extra}\n--{BOUNDARY}--\n"
    )
}

pub(crate) fn cloud_init_content_type(raw: &str) -> &'static str {
    let trimmed = raw.trim_start();
    if trimmed.starts_with("#cloud-config") {
        "text/cloud-config"
    } else if trimmed.starts_with("#cloud-boothook") {
        "text/cloud-boothook"
    } else if trimmed.starts_with("#!") {
        "text/x-shellscript"
    } else {
        "text/plain"
    }
}

pub(crate) fn build_qemu_user_netdev_arg(
    amber_cli: &str,
    component: &VmComponentPlan,
    port_assignments: &VmPortAssignments,
) -> Result<String> {
    let mut netdev = format!(
        "user,id=net0,hostname={},restrict={}",
        component.log_name,
        match component.egress {
            VmEgressPlan::None => "on",
            VmEgressPlan::Optional => "off",
        }
    );
    if let Some(slot_ports) = port_assignments
        .state
        .slot_route_ports_by_component
        .get(&component.id)
    {
        let slot_host_ports = port_assignments
            .route_host_ports_by_component
            .get(&component.id)
            .ok_or_else(|| {
                miette::miette!(
                    "missing host slot ports for component {}",
                    component.moniker
                )
            })?;
        for (slot, guest_ports) in slot_ports {
            let host_ports = slot_host_ports.get(slot.as_str()).ok_or_else(|| {
                miette::miette!(
                    "missing guestfwd host ports for component {} slot {}",
                    component.moniker,
                    slot
                )
            })?;
            if guest_ports.len() != host_ports.len() {
                return Err(miette::miette!(
                    "slot {} for component {} has mismatched guest/host port counts",
                    slot,
                    component.moniker
                ));
            }
            for (guest_port, host_port) in guest_ports.iter().zip(host_ports) {
                let bridge_command = guestfwd_bridge_command(amber_cli, *host_port);
                let _ = write!(
                    netdev,
                    ",guestfwd=tcp:{VM_HOST_GUESTFWD_IP}:{guest_port}-cmd:{bridge_command}"
                );
            }
        }
    }
    if let Some(endpoint_ports) = port_assignments
        .state
        .endpoint_forwards_by_component
        .get(&component.id)
    {
        for (guest_port, host_port) in endpoint_ports {
            let _ = write!(netdev, ",hostfwd=tcp:127.0.0.1:{host_port}-:{guest_port}");
        }
    }
    Ok(netdev)
}

pub(crate) fn guestfwd_bridge_command(amber_cli: &str, host_port: u16) -> String {
    format!(
        "{} run-vm-guestfwd-bridge {}",
        shell_quote_posix(amber_cli),
        shell_quote_posix(&SocketAddr::from(([127, 0, 0, 1], host_port)).to_string())
    )
}

pub(crate) fn shell_quote_posix(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    if value
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'/' | b'.' | b'_' | b'-' | b':' | b'@' | b'%'))
    {
        return value.to_string();
    }

    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

pub(crate) fn qemu_machine_args(arch: VmArch, accel: QemuAccel) -> Result<Vec<String>> {
    let mut args = match arch {
        VmArch::Aarch64 => vec![
            "-machine".to_string(),
            "virt,highmem=off".to_string(),
            "-cpu".to_string(),
            match accel {
                #[cfg(target_os = "macos")]
                QemuAccel::Hvf => "host".to_string(),
                #[cfg(target_os = "linux")]
                QemuAccel::Kvm => "host".to_string(),
                QemuAccel::Tcg => "max".to_string(),
            },
        ],
        VmArch::X86_64 => vec![
            "-machine".to_string(),
            "q35".to_string(),
            "-cpu".to_string(),
            match accel {
                #[cfg(target_os = "macos")]
                QemuAccel::Hvf => "host".to_string(),
                #[cfg(target_os = "linux")]
                QemuAccel::Kvm => "host".to_string(),
                QemuAccel::Tcg => "max".to_string(),
            },
        ],
    };
    args.extend(match accel {
        #[cfg(target_os = "macos")]
        QemuAccel::Hvf => vec!["-accel".to_string(), "hvf".to_string()],
        #[cfg(target_os = "linux")]
        QemuAccel::Kvm => vec!["-accel".to_string(), "kvm".to_string()],
        QemuAccel::Tcg => vec!["-accel".to_string(), "tcg".to_string()],
    });
    if arch == VmArch::Aarch64 {
        let firmware = resolve_aarch64_firmware()?;
        args.extend(["-bios".to_string(), firmware.display().to_string()]);
    }
    Ok(args)
}

pub(crate) fn resolve_qemu_system_binary() -> Result<PathBuf> {
    if let Ok(value) = env::var("AMBER_VM_QEMU_SYSTEM") {
        let path = PathBuf::from(value);
        if path.is_file() {
            return Ok(path);
        }
        return Err(miette::miette!(
            "AMBER_VM_QEMU_SYSTEM points to a missing file: {}",
            path.display()
        ));
    }
    let name = match host_arch()? {
        VmArch::Aarch64 => "qemu-system-aarch64",
        VmArch::X86_64 => "qemu-system-x86_64",
    };
    find_in_path(name).ok_or_else(|| {
        miette::miette!(
            "could not locate runtime binary `{name}`; set AMBER_VM_QEMU_SYSTEM or add it to PATH"
        )
    })
}

pub(crate) fn resolve_qemu_img_binary() -> Result<PathBuf> {
    if let Ok(value) = env::var("AMBER_VM_QEMU_IMG") {
        let path = PathBuf::from(value);
        if path.is_file() {
            return Ok(path);
        }
        return Err(miette::miette!(
            "AMBER_VM_QEMU_IMG points to a missing file: {}",
            path.display()
        ));
    }
    find_in_path("qemu-img").ok_or_else(|| {
        miette::miette!(
            "could not locate runtime binary `qemu-img`; set AMBER_VM_QEMU_IMG or add it to PATH"
        )
    })
}

pub(crate) fn resolve_host_binary(name: &str) -> Result<String> {
    if let Ok(dir) = env::var("AMBER_RUNTIME_BIN_DIR") {
        let candidate = Path::new(&dir).join(name);
        if candidate.is_file() {
            return Ok(candidate.display().to_string());
        }
        return Err(miette::miette!(
            "runtime binary `{name}` was not found in AMBER_RUNTIME_BIN_DIR ({})",
            Path::new(&dir).display()
        ));
    }

    if let Ok(current_exe) = env::current_exe()
        && let Some(bin_dir) = current_exe.parent()
    {
        for dir in [Some(bin_dir), bin_dir.parent()].into_iter().flatten() {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Ok(candidate.display().to_string());
            }
        }
    }

    if let Some(candidate) = find_in_path(name) {
        return Ok(candidate.display().to_string());
    }

    Err(miette::miette!(
        "could not locate runtime binary `{name}`; set AMBER_RUNTIME_BIN_DIR, place it next to \
         the `amber` binary, or add it to PATH"
    ))
}

pub(crate) fn resolve_aarch64_firmware() -> Result<PathBuf> {
    if let Ok(path) = env::var("AMBER_VM_AARCH64_FIRMWARE") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        return Err(miette::miette!(
            "AMBER_VM_AARCH64_FIRMWARE points to a missing file: {}",
            path.display()
        ));
    }

    let candidates = [
        "/opt/homebrew/share/qemu/edk2-aarch64-code.fd",
        "/usr/local/share/qemu/edk2-aarch64-code.fd",
        "/usr/share/AAVMF/AAVMF_CODE.fd",
        "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
        "/usr/share/edk2/aarch64/QEMU_EFI.fd",
        "/usr/share/edk2/ovmf/AAVMF_CODE.fd",
    ];
    candidates
        .iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            miette::miette!("could not locate AArch64 UEFI firmware; set AMBER_VM_AARCH64_FIRMWARE")
        })
}

pub(crate) fn host_arch() -> Result<VmArch> {
    match env::consts::ARCH {
        "aarch64" => Ok(VmArch::Aarch64),
        "x86_64" => Ok(VmArch::X86_64),
        other => Err(miette::miette!(
            "vm runtime supports only aarch64 and x86_64 hosts, found {}",
            other
        )),
    }
}
