#![cfg(target_os = "macos")]

#[path = "test_support/cloud_image.rs"]
mod cloud_image_support;
#[path = "test_support/macos_vm.rs"]
mod macos_vm_support;
#[path = "test_support/outputs_root.rs"]
mod outputs_root_support;
#[path = "test_support/workspace_root.rs"]
mod workspace_root_support;

use std::{
    env, fs,
    hash::{Hash as _, Hasher as _},
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use cloud_image_support::default_host_arch_cloud_image_filename;
use macos_vm_support::resolve_aarch64_firmware;
use outputs_root_support::cli_test_outputs_root;
use tempfile::TempDir;
use workspace_root_support::workspace_root;

const GUEST_USER: &str = "amber";
const DEFAULT_ROOT_OVERLAY_SIZE: &str = "40G";
const QEMU_VIRTIO_NET_DEVICE: &str = "virtio-net-pci,netdev=net0,rombar=0";
const LINUX_VM_KIND_VERSION: &str = "v0.26.0";
const LINUX_VM_KIND_NODE_IMAGE: &str =
    "kindest/node:v1.32.0@sha256:c48c62eac5da28cdadcf560d1d8616cfa6783b58f0d94cf63ad1bf49600cb027";
const LINUX_VM_KIND_PULL_TIMEOUT: &str = "180s";

struct GuestArch {
    cloud_image_filename: &'static str,
    cloud_image_url: &'static str,
    kind_arch: &'static str,
    kubectl_arch: &'static str,
    qemu_packages: &'static str,
    qemu_system: &'static str,
}

struct ProvisioningSpec {
    guest_packages: &'static str,
    profile_setup: String,
    profile_checks: String,
}

#[derive(Clone, Copy)]
enum ProvisionProfile {
    VmSmoke,
    MixedRun,
}

impl ProvisionProfile {
    fn name(self) -> &'static str {
        match self {
            Self::VmSmoke => "vm-smoke",
            Self::MixedRun => "mixed-run",
        }
    }

    fn provisioning_spec(self, arch: &GuestArch) -> ProvisioningSpec {
        match self {
            Self::VmSmoke => ProvisioningSpec {
                guest_packages: "build-essential ca-certificates curl git jq pkg-config libssl-dev",
                profile_setup: String::new(),
                profile_checks: String::new(),
            },
            Self::MixedRun => ProvisioningSpec {
                guest_packages: "build-essential ca-certificates curl git jq pkg-config libssl-dev bubblewrap \
                                 slirp4netns docker.io",
                profile_setup: format!(
                    "if ! docker compose version >/dev/null 2>&1; then\n\
                       sudo apt-get install -y --no-install-recommends docker-compose-v2 || sudo apt-get install -y --no-install-recommends docker-compose-plugin\n\
                     fi\n\
                     if ! docker buildx version >/dev/null 2>&1; then\n\
                       sudo apt-get install -y --no-install-recommends docker-buildx-plugin || \\\n\
                       sudo apt-get install -y --no-install-recommends docker-buildx || \\\n\
                       sudo apt-get install -y --no-install-recommends moby-buildx\n\
                     fi\n\
                     if sysctl kernel.apparmor_restrict_unprivileged_unconfined >/dev/null 2>&1; then\n\
                       sudo sysctl -w kernel.apparmor_restrict_unprivileged_unconfined=0\n\
                     fi\n\
                     if sysctl kernel.apparmor_restrict_unprivileged_userns >/dev/null 2>&1; then\n\
                       sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0\n\
                     fi\n\
                     sudo systemctl enable --now docker\n\
                     sudo usermod -aG docker {user}\n\
                     if ! command -v kind >/dev/null 2>&1 || ! kind --version | grep -q '{kind_version}'; then\n\
                       curl -fsSL -o /tmp/kind https://kind.sigs.k8s.io/dl/{kind_version}/kind-linux-{kind_arch}\n\
                       chmod +x /tmp/kind\n\
                       sudo mv /tmp/kind /usr/local/bin/kind\n\
                     fi\n\
                     if ! sudo docker image inspect '{kind_node_image}' >/dev/null 2>&1; then\n\
                       timeout {kind_pull_timeout} sudo docker pull '{kind_node_image}'\n\
                     fi\n\
                     if ! command -v kubectl >/dev/null 2>&1; then\n\
                       stable=\"$(curl -fsSL https://dl.k8s.io/release/stable.txt)\"\n\
                       curl -fsSL -o /tmp/kubectl \"https://dl.k8s.io/release/${{stable}}/bin/linux/{kubectl_arch}/kubectl\"\n\
                       chmod +x /tmp/kubectl\n\
                       sudo mv /tmp/kubectl /usr/local/bin/kubectl\n\
                     fi\n",
                    user = GUEST_USER,
                    kind_arch = arch.kind_arch,
                    kind_version = LINUX_VM_KIND_VERSION,
                    kind_node_image = LINUX_VM_KIND_NODE_IMAGE,
                    kind_pull_timeout = LINUX_VM_KIND_PULL_TIMEOUT,
                    kubectl_arch = arch.kubectl_arch,
                ),
                profile_checks: "docker compose version\ndocker buildx version\nkind \
                                 --version\nkubectl version --client=true\n"
                    .to_string(),
            },
        }
    }

    fn cache_key(self) -> String {
        let spec = self.provisioning_spec(&guest_arch());
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        spec.guest_packages.hash(&mut hasher);
        spec.profile_setup.hash(&mut hasher);
        spec.profile_checks.hash(&mut hasher);
        format!("{}-{:016x}", self.name(), hasher.finish())
    }
}

struct OutputDir {
    path: PathBuf,
    guard: Option<TempDir>,
}

impl OutputDir {
    fn new(prefix: &str) -> Result<Self, String> {
        let workspace_root = workspace_root();
        let outputs_root = cli_test_outputs_root(&workspace_root);
        fs::create_dir_all(&outputs_root)
            .map_err(|err| format!("failed to create {}: {err}", outputs_root.display()))?;
        let temp = tempfile::Builder::new()
            .prefix(prefix)
            .tempdir_in(&outputs_root)
            .map_err(|err| {
                format!(
                    "failed to create output directory in {}: {err}",
                    outputs_root.display()
                )
            })?;
        Ok(Self {
            path: temp.path().to_path_buf(),
            guard: Some(temp),
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn preserve(&mut self) {
        if let Some(temp) = self.guard.take() {
            self.path = temp.keep();
        }
    }
}

struct LinuxVmHarness {
    output_dir: PathBuf,
    root_overlay_path: PathBuf,
    ssh_port: u16,
    ssh_private_key: PathBuf,
    serial_log: PathBuf,
    qemu_log: PathBuf,
    guest_workspace: String,
    qemu_child: Child,
}

impl Drop for LinuxVmHarness {
    fn drop(&mut self) {
        let _ = self.qemu_child.kill();
        let _ = self.qemu_child.wait();
    }
}

fn guest_arch() -> GuestArch {
    match env::consts::ARCH {
        "aarch64" => GuestArch {
            cloud_image_filename: "ubuntu-24.04-minimal-cloudimg-arm64.img",
            cloud_image_url: "https://cloud-images.ubuntu.com/minimal/releases/noble/release-20240709/ubuntu-24.04-minimal-cloudimg-arm64.img",
            kind_arch: "arm64",
            kubectl_arch: "arm64",
            qemu_packages: "qemu-system-arm qemu-utils qemu-efi-aarch64 xorriso",
            qemu_system: "qemu-system-aarch64",
        },
        "x86_64" => GuestArch {
            cloud_image_filename: "ubuntu-24.04-minimal-cloudimg-amd64.img",
            cloud_image_url: "https://cloud-images.ubuntu.com/minimal/releases/noble/release-20240709/ubuntu-24.04-minimal-cloudimg-amd64.img",
            kind_arch: "amd64",
            kubectl_arch: "amd64",
            qemu_packages: "qemu-system-x86 qemu-utils xorriso",
            qemu_system: "qemu-system-x86_64",
        },
        other => panic!("linux-vm test supports only aarch64 and x86_64 hosts, found {other}"),
    }
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
    for path in env::split_paths(&path_var) {
        let candidate = path.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn qemu_img_binary() -> PathBuf {
    env::var_os("AMBER_VM_QEMU_IMG")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .or_else(|| find_in_path("qemu-img"))
        .unwrap_or_else(|| {
            panic!(
                "could not locate runtime binary `qemu-img`; set AMBER_VM_QEMU_IMG or add it to \
                 PATH"
            )
        })
}

fn qemu_system_binary(arch: &GuestArch) -> PathBuf {
    env::var_os("AMBER_VM_QEMU_SYSTEM")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .or_else(|| find_in_path(arch.qemu_system))
        .unwrap_or_else(|| {
            panic!(
                "could not locate runtime binary `{}`; set AMBER_VM_QEMU_SYSTEM or add it to PATH",
                arch.qemu_system
            )
        })
}

fn pick_free_port() -> u16 {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    listener.local_addr().unwrap().port()
}

fn shell_escape(text: &str) -> String {
    if text
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"-_./:=,@".contains(&byte))
    {
        return text.to_string();
    }
    format!("'{}'", text.replace('\'', "'\"'\"'"))
}

fn render_command(command: &Command) -> String {
    let program = command.get_program().to_string_lossy();
    let args = command
        .get_args()
        .map(|arg| shell_escape(arg.to_string_lossy().as_ref()))
        .collect::<Vec<_>>()
        .join(" ");
    if args.is_empty() {
        program.into_owned()
    } else {
        format!("{program} {args}")
    }
}

fn run_checked(command: &mut Command, description: &str) -> Result<(), String> {
    let rendered = render_command(command);
    let output = command
        .output()
        .map_err(|err| format!("failed to {description}: {rendered}: {err}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "failed to {description}: {rendered}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim(),
    ))
}

fn qemu_image_format(image: &Path) -> Result<String, String> {
    let output = Command::new(qemu_img_binary())
        .arg("info")
        .arg("--output=json")
        .arg(image)
        .output()
        .map_err(|err| format!("failed to inspect vm image {}: {err}", image.display()))?;
    if !output.status.success() {
        return Err(format!(
            "failed to inspect vm image {}: {}",
            image.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|err| {
        format!(
            "invalid qemu-img info output for {}: {err}",
            image.display()
        )
    })?;
    json["format"].as_str().map(str::to_string).ok_or_else(|| {
        format!(
            "qemu-img info output for {} did not contain format",
            image.display()
        )
    })
}

fn host_cloud_image_path() -> PathBuf {
    workspace_root().join(default_host_arch_cloud_image_filename())
}

fn ensure_host_cloud_image_exists(path: &Path) -> Result<(), String> {
    if path.is_file() {
        Ok(())
    } else {
        Err(format!(
            "missing Linux VM base image {}; place {} at the workspace root",
            path.display(),
            default_host_arch_cloud_image_filename()
        ))
    }
}

fn provisioned_cache_dir() -> PathBuf {
    cli_test_outputs_root(&workspace_root()).join("linux-vm-cache")
}

fn provisioned_cache_path(profile: ProvisionProfile) -> PathBuf {
    provisioned_cache_dir().join(format!(
        "{}-{}.qcow2",
        profile.cache_key(),
        env::consts::ARCH
    ))
}

fn linux_vm_instance_id(output_dir: &Path) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    output_dir.hash(&mut hasher);
    format!("amber-linux-vm-{:016x}", hasher.finish())
}

fn write_cloud_init_seed_image(
    path: &Path,
    user_data: &str,
    meta_data: &str,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create seed image directory {}: {err}",
                parent.display()
            )
        })?;
    }
    if path.exists() {
        fs::remove_file(path).map_err(|err| {
            format!(
                "failed to remove stale seed image {}: {err}",
                path.display()
            )
        })?;
    }

    let staging = tempfile::Builder::new()
        .prefix("amber-linux-vm-seed-")
        .tempdir()
        .map_err(|err| format!("failed to create cloud-init seed staging directory: {err}"))?;
    fs::write(staging.path().join("user-data"), user_data)
        .map_err(|err| format!("failed to write cloud-init user-data: {err}"))?;
    fs::write(staging.path().join("meta-data"), meta_data)
        .map_err(|err| format!("failed to write cloud-init meta-data: {err}"))?;

    run_checked(
        Command::new("/usr/bin/hdiutil")
            .arg("makehybrid")
            .arg("-quiet")
            .arg("-iso")
            .arg("-joliet")
            .arg("-default-volume-name")
            .arg("CIDATA")
            .arg("-o")
            .arg(path)
            .arg(staging.path()),
        "create linux-vm cloud-init seed image",
    )
}

fn write_ssh_keypair(private_key: &Path) -> Result<String, String> {
    run_checked(
        Command::new("/usr/bin/ssh-keygen")
            .arg("-q")
            .arg("-t")
            .arg("ed25519")
            .arg("-N")
            .arg("")
            .arg("-f")
            .arg(private_key),
        "generate linux-vm ssh key",
    )?;
    fs::read_to_string(private_key.with_extension("pub")).map_err(|err| {
        format!(
            "failed to read {}: {err}",
            private_key.with_extension("pub").display()
        )
    })
}

impl LinuxVmHarness {
    fn start(output_dir: &Path, base_image: &Path) -> Result<Self, String> {
        let arch = guest_arch();
        ensure_host_cloud_image_exists(base_image)?;

        let overlay_path = output_dir.join("root-overlay.qcow2");
        let base_format = qemu_image_format(base_image)?;
        run_checked(
            Command::new(qemu_img_binary())
                .arg("create")
                .arg("-f")
                .arg("qcow2")
                .arg("-F")
                .arg(&base_format)
                .arg("-b")
                .arg(base_image)
                .arg(&overlay_path)
                .arg(
                    env::var("AMBER_LINUX_VM_ROOT_DISK_SIZE")
                        .unwrap_or_else(|_| DEFAULT_ROOT_OVERLAY_SIZE.to_string()),
                ),
            "create linux-vm overlay image",
        )?;

        let ssh_private_key = output_dir.join("guest-key");
        let ssh_public_key = write_ssh_keypair(&ssh_private_key)?;
        let seed_path = output_dir.join("seed.iso");
        let serial_log = output_dir.join("serial.log");
        let qemu_log = output_dir.join("qemu.log");
        let ssh_port = pick_free_port();
        let user_data = format!(
            "#cloud-config\nusers:\n  - default\n  - name: {GUEST_USER}\n    sudo: ALL=(ALL) \
             NOPASSWD:ALL\n    groups: [adm, sudo]\n    shell: /bin/bash\n    \
             ssh_authorized_keys:\n      - {}\nssh_pwauth: false\n",
            ssh_public_key.trim()
        );
        write_cloud_init_seed_image(
            &seed_path,
            &user_data,
            &format!(
                "instance-id: {}\nlocal-hostname: amber-linux-vm\n",
                linux_vm_instance_id(output_dir)
            ),
        )?;

        let qemu_stdout = fs::File::create(&qemu_log)
            .map_err(|err| format!("failed to create {}: {err}", qemu_log.display()))?;
        let qemu_stderr = qemu_stdout
            .try_clone()
            .map_err(|err| format!("failed to clone {}: {err}", qemu_log.display()))?;
        let mut command = Command::new(qemu_system_binary(&arch));
        let default_memory_mib = match env::consts::ARCH {
            "aarch64" => "6144",
            "x86_64" => "8192",
            other => return Err(format!("unsupported macOS host architecture {other}")),
        };

        command
            .arg("-name")
            .arg("amber-linux-vm-tests")
            .arg("-display")
            .arg("none")
            .arg("-monitor")
            .arg("none")
            .arg("-serial")
            .arg(format!("file:{}", serial_log.display()))
            .arg("-no-reboot")
            .arg("-smp")
            .arg(env::var("AMBER_LINUX_VM_CPUS").unwrap_or_else(|_| "4".to_string()))
            .arg("-m")
            .arg(
                env::var("AMBER_LINUX_VM_MEMORY_MIB")
                    .unwrap_or_else(|_| default_memory_mib.to_string()),
            );

        match env::consts::ARCH {
            "aarch64" => {
                command
                    .arg("-machine")
                    .arg("virt")
                    .arg("-cpu")
                    .arg("host")
                    .arg("-accel")
                    .arg("hvf")
                    .arg("-bios")
                    .arg(resolve_aarch64_firmware());
            }
            "x86_64" => {
                command
                    .arg("-machine")
                    .arg("q35")
                    .arg("-cpu")
                    .arg("host")
                    .arg("-accel")
                    .arg("hvf");
            }
            other => return Err(format!("unsupported macOS host architecture {other}")),
        }

        command
            .arg("-netdev")
            .arg(format!("user,id=net0,hostfwd=tcp:127.0.0.1:{ssh_port}-:22"))
            .arg("-device")
            .arg(QEMU_VIRTIO_NET_DEVICE)
            .arg("-drive")
            .arg(format!(
                "if=none,id=root,format=qcow2,file={},readonly=off",
                overlay_path.display()
            ))
            .arg("-device")
            .arg("virtio-blk-pci,drive=root,bootindex=1")
            .arg("-drive")
            .arg(format!(
                "if=none,id=seed,format=raw,file={},readonly=on",
                seed_path.display()
            ))
            .arg("-device")
            .arg("virtio-blk-pci,drive=seed")
            .stdout(Stdio::from(qemu_stdout))
            .stderr(Stdio::from(qemu_stderr));
        let qemu_child = command
            .spawn()
            .map_err(|err| format!("failed to start qemu: {err}"))?;

        let mut harness = Self {
            output_dir: output_dir.to_path_buf(),
            root_overlay_path: overlay_path,
            ssh_port,
            ssh_private_key,
            serial_log,
            qemu_log,
            guest_workspace: format!("/home/{GUEST_USER}/amber"),
            qemu_child,
        };
        harness.wait_for_ssh()?;
        Ok(harness)
    }

    fn ssh_base_command(&self) -> Command {
        let mut command = Command::new("/usr/bin/ssh");
        command
            .arg("-i")
            .arg(&self.ssh_private_key)
            .arg("-p")
            .arg(self.ssh_port.to_string())
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg("-o")
            .arg("UserKnownHostsFile=/dev/null")
            .arg("-o")
            .arg("LogLevel=ERROR")
            .arg(format!("{GUEST_USER}@127.0.0.1"));
        command
    }

    fn ssh_output(&self, script: &str) -> Result<Output, String> {
        self.ssh_base_command()
            .arg("--")
            .arg("bash")
            .arg("-lc")
            .arg(script)
            .output()
            .map_err(|err| format!("failed to run ssh command: {err}"))
    }

    fn wait_for_ssh(&mut self) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(300);
        while Instant::now() < deadline {
            if let Some(status) = self
                .qemu_child
                .try_wait()
                .map_err(|err| format!("failed to poll qemu process: {err}"))?
            {
                return Err(self.failure_context(
                    &format!("linux guest qemu exited before ssh became ready: {status}"),
                    None,
                ));
            }
            if let Ok(output) = self.ssh_output("true")
                && output.status.success()
            {
                return Ok(());
            }
            thread::sleep(Duration::from_secs(2));
        }
        Err(self.failure_context(
            "linux guest did not become reachable over ssh within 300s",
            None,
        ))
    }

    fn run_guest_checked(&self, label: &str, script: &str) -> Result<(), String> {
        let output = self.ssh_output(script)?;
        if output.status.success() {
            return Ok(());
        }
        Err(self.failure_context(label, Some(&output)))
    }

    fn scp_to_guest(&self, sources: &[&Path], description: &str) -> Result<(), String> {
        let mut command = Command::new("/usr/bin/scp");
        command
            .arg("-i")
            .arg(&self.ssh_private_key)
            .arg("-P")
            .arg(self.ssh_port.to_string())
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg("-o")
            .arg("UserKnownHostsFile=/dev/null")
            .arg("-o")
            .arg("LogLevel=ERROR");
        for source in sources {
            command.arg(source);
        }
        let scp_output = command
            .arg(format!("{GUEST_USER}@127.0.0.1:/home/{GUEST_USER}/"))
            .output()
            .map_err(|err| format!("failed to {description}: {err}"))?;
        if scp_output.status.success() {
            Ok(())
        } else {
            Err(self.failure_context(description, Some(&scp_output)))
        }
    }

    fn copy_host_cloud_image(&self) -> Result<(), String> {
        let base_image = host_cloud_image_path();
        ensure_host_cloud_image_exists(&base_image)?;
        self.scp_to_guest(
            &[base_image.as_path()],
            "copy Linux VM base image into guest",
        )
    }

    fn copy_workspace(&self) -> Result<(), String> {
        let archive = self.output_dir.join("workspace.tgz");
        let workspace_root = workspace_root();
        let base_image = host_cloud_image_path();
        ensure_host_cloud_image_exists(&base_image)?;
        run_checked(
            Command::new("/usr/bin/tar")
                .current_dir(&workspace_root)
                .env("COPYFILE_DISABLE", "1")
                .arg("-czf")
                .arg(&archive)
                .arg("--exclude=./target")
                .arg("--exclude=./.git")
                .arg("--exclude=._*")
                .arg("--exclude=*/._*")
                .arg("."),
            "archive workspace for linux guest",
        )?;
        self.scp_to_guest(
            &[archive.as_path(), base_image.as_path()],
            "copy guest assets into linux guest",
        )?;

        self.run_guest_checked(
            "unpack workspace in linux guest",
            &format!(
                "set -euo pipefail\nrm -rf {guest}\nmkdir -p {guest}\ntar -xzf \
                 /home/{user}/workspace.tgz -C {guest}\nrm /home/{user}/workspace.tgz",
                guest = shell_escape(&self.guest_workspace),
                user = GUEST_USER,
            ),
        )
    }

    fn prepare_for_snapshot(&self) -> Result<(), String> {
        self.run_guest_checked(
            "prepare linux guest snapshot",
            "set -euxo pipefail\n. \"$HOME/.cargo/env\" || true\nsudo cloud-init clean --logs \
             --machine-id\nsudo rm -rf \"$HOME/amber\" \"$HOME/amber-target\"\nsudo sync\n",
        )
    }

    fn shutdown_for_snapshot(&mut self) -> Result<(), String> {
        let _ = self.ssh_output("sudo systemctl poweroff --no-block || sudo shutdown -h now");
        let deadline = Instant::now() + Duration::from_secs(180);
        while Instant::now() < deadline {
            if self
                .qemu_child
                .try_wait()
                .map_err(|err| format!("failed to poll qemu process: {err}"))?
                .is_some()
            {
                return Ok(());
            }
            thread::sleep(Duration::from_secs(2));
        }
        Err(self.failure_context(
            "linux guest did not power off after snapshot preparation",
            None,
        ))
    }

    fn provision_guest(&self, profile: ProvisionProfile) -> Result<(), String> {
        let arch = guest_arch();
        let spec = profile.provisioning_spec(&arch);
        self.run_guest_checked(
            "provision linux guest",
            &format!(
                "set -euxo pipefail\n\
                 export DEBIAN_FRONTEND=noninteractive\n\
                 sudo apt-get update\n\
                 sudo apt-get install -y --no-install-recommends {guest_packages} {qemu_packages}\n\
                 sudo apt-get clean\n\
                 if ! command -v rustup >/dev/null 2>&1; then\n\
                   curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal\n\
                 fi\n\
                 . \"$HOME/.cargo/env\"\n\
                 {profile_setup}\
                 if [ ! -f \"$HOME/{image_filename}\" ]; then\n\
                   curl --fail --show-error --silent --location --retry 5 --retry-all-errors \\\n\
                     --output \"$HOME/{image_filename}\" \\\n\
                     {image_url}\n\
                 fi\n\
                 qemu-img info \"$HOME/{image_filename}\" >/dev/null\n\
                 {profile_checks}",
                guest_packages = spec.guest_packages,
                qemu_packages = arch.qemu_packages,
                profile_setup = spec.profile_setup,
                image_filename = arch.cloud_image_filename,
                image_url = shell_escape(arch.cloud_image_url),
                profile_checks = spec.profile_checks,
            ),
        )
    }

    fn run_test_command(&self, label: &str, command: &str) -> Result<(), String> {
        let arch = guest_arch();
        self.run_guest_checked(
            label,
            &format!(
                "set -euxo pipefail\n. \"$HOME/.cargo/env\"\ncd {guest}\nexport \
                 AMBER_TEST_KEEP_OUTPUTS=1\nexport \
                 AMBER_VM_SMOKE_BASE_IMAGE=\"$HOME/{image_filename}\"\nexport \
                 AMBER_MIXED_RUN_BASE_IMAGE=\"$HOME/{image_filename}\"\nexport \
                 CARGO_TARGET_DIR=\"$HOME/amber-target\"\n{command}\n",
                guest = shell_escape(&self.guest_workspace),
                image_filename = arch.cloud_image_filename,
                command = command,
            ),
        )
    }

    fn guest_failure_diagnostics(&self) -> String {
        let guest_workspace = shell_escape(&self.guest_workspace);
        let script = format!(
            "set -euo pipefail\noutputs={guest_workspace}/target/cli-test-outputs\nif [ ! -d \
             \"$outputs\" ]; then\nexit 0\nfi\nlatest=\"$(find \"$outputs\" -maxdepth 1 -type d \
             -name 'mixed-run-*' | sort | tail -n 1)\"\nif [ -z \"$latest\" ]; \
             then\nlatest=\"$(find \"$outputs\" -maxdepth 1 -type d | sort | tail -n 1)\"\nfi\nif \
             [ -z \"$latest\" ]; then\nexit 0\nfi\necho \"latest guest test output: \
             $latest\"\nfind \"$latest\" -maxdepth 3 -type f | sort\nwhile IFS= read -r path; \
             do\necho \"----- $path -----\"\nsed -n '1,220p' \"$path\"\ndone < <(find \
             \"$latest/state\" -maxdepth 2 -type f \\( -name 'manager-state.json' -o -name \
             'supervisor.log' -o -name 'port-forward.log' -o -name 'site.log' \\) 2>/dev/null | \
             sort)\n"
        );
        self.ssh_output(&script)
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
            .unwrap_or_default()
    }

    fn failure_context(&self, label: &str, output: Option<&Output>) -> String {
        let mut message = format!(
            "linux guest step failed: {label}\noutput dir: {}",
            self.output_dir.display()
        );
        if let Some(output) = output {
            message.push_str(&format!(
                "\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ));
        }
        message.push_str(&format!(
            "\nqemu log ({}):\n{}",
            self.qemu_log.display(),
            fs::read_to_string(&self.qemu_log).unwrap_or_default()
        ));
        message.push_str(&format!(
            "\nserial log ({}):\n{}",
            self.serial_log.display(),
            fs::read_to_string(&self.serial_log).unwrap_or_default()
        ));
        let guest_diagnostics = self.guest_failure_diagnostics();
        if !guest_diagnostics.trim().is_empty() {
            message.push_str(&format!("\nguest diagnostics:\n{guest_diagnostics}"));
        }
        message
    }
}

fn run_linux_guest_test(
    prefix: impl AsRef<str>,
    profile: ProvisionProfile,
    command: &str,
) -> Result<(), String> {
    let prefix = prefix.as_ref();
    let mut output_dir = OutputDir::new(prefix)?;
    let result = (|| {
        let provisioned_image = ensure_provisioned_image(profile)?;
        let harness = LinuxVmHarness::start(output_dir.path(), &provisioned_image)?;
        harness.copy_workspace()?;
        harness.run_test_command(prefix, command)
    })();
    if result.is_err() || env::var_os("AMBER_TEST_KEEP_OUTPUTS").is_some() {
        output_dir.preserve();
        eprintln!(
            "preserving linux-vm outputs in {}",
            output_dir.path.display()
        );
    }
    result
}

fn ensure_provisioned_image(profile: ProvisionProfile) -> Result<PathBuf, String> {
    let cache_path = provisioned_cache_path(profile);
    if cache_path.is_file() && env::var_os("AMBER_LINUX_VM_REFRESH_CACHE").is_none() {
        return Ok(cache_path);
    }

    let cache_prefix = format!("linux-vm-cache-{}-", profile.cache_key());
    let mut output_dir = OutputDir::new(&cache_prefix)?;
    let result = (|| {
        let base_image = host_cloud_image_path();
        ensure_host_cloud_image_exists(&base_image)?;
        let mut harness = LinuxVmHarness::start(output_dir.path(), &base_image)?;
        harness.copy_host_cloud_image()?;
        harness.provision_guest(profile)?;
        harness.prepare_for_snapshot()?;
        harness.shutdown_for_snapshot()?;

        let cache_dir = provisioned_cache_dir();
        fs::create_dir_all(&cache_dir)
            .map_err(|err| format!("failed to create {}: {err}", cache_dir.display()))?;
        let temp_cache_path = cache_path.with_extension("qcow2.tmp");
        if temp_cache_path.exists() {
            fs::remove_file(&temp_cache_path).map_err(|err| {
                format!(
                    "failed to remove stale temporary provisioned image {}: {err}",
                    temp_cache_path.display()
                )
            })?;
        }
        fs::copy(&harness.root_overlay_path, &temp_cache_path).map_err(|err| {
            format!(
                "failed to copy provisioned linux VM image {} to {}: {err}",
                harness.root_overlay_path.display(),
                temp_cache_path.display()
            )
        })?;
        fs::rename(&temp_cache_path, &cache_path).map_err(|err| {
            format!(
                "failed to publish provisioned linux VM image {}: {err}",
                cache_path.display()
            )
        })?;
        Ok(())
    })();
    if result.is_err() || env::var_os("AMBER_TEST_KEEP_OUTPUTS").is_some() {
        output_dir.preserve();
        eprintln!(
            "preserving linux-vm cache-build outputs in {}",
            output_dir.path.display()
        );
    }
    result.map(|()| cache_path)
}

fn run_linux_guest_mixed_run_test(test_name: &str) -> Result<(), String> {
    run_linux_guest_test(
        format!("linux-vm-{test_name}-"),
        ProvisionProfile::MixedRun,
        &format!(
            "cargo test -p amber-cli --test mixed_run {test_name} -- --ignored --nocapture \
             --test-threads=1"
        ),
    )
}

#[test]
#[ignore = "requires qemu on macOS; boots Ubuntu and runs the real Linux vm_smoke test inside the \
            guest"]
fn linux_vm_runs_vm_smoke_test() {
    run_linux_guest_test(
        "linux-vm-vm-smoke-",
        ProvisionProfile::VmSmoke,
        "cargo test -p amber-cli --test vm_smoke -- --ignored --nocapture --test-threads=1",
    )
    .unwrap_or_else(|err| panic!("{err}"));
}

#[test]
#[ignore = "requires qemu on macOS; boots Ubuntu and runs the real Linux mixed_run tests inside \
            the guest"]
fn linux_vm_runs_mixed_run_tests() {
    run_linux_guest_test(
        "linux-vm-mixed-run-",
        ProvisionProfile::MixedRun,
        "cargo test -p amber-cli --test mixed_run mixed_run_ -- --ignored --nocapture \
         --test-threads=1",
    )
    .unwrap_or_else(|err| panic!("{err}"));
}

#[test]
#[ignore = "requires qemu on macOS; boots Ubuntu and runs the real Linux mixed_run cleanup test \
            inside the guest"]
fn linux_vm_runs_mixed_run_cleanup_after_coordinator_dies_during_setup() {
    run_linux_guest_mixed_run_test("mixed_run_cleanup_after_coordinator_dies_during_setup")
        .unwrap_or_else(|err| panic!("{err}"));
}

#[test]
#[ignore = "requires qemu on macOS; boots Ubuntu and runs the real Linux mixed_run direct/compose \
            proxy smoke test inside the guest"]
fn linux_vm_runs_mixed_run_direct_compose_proxy_smoke() {
    run_linux_guest_mixed_run_test("mixed_run_direct_compose_proxy_smoke")
        .unwrap_or_else(|err| panic!("{err}"));
}

#[test]
#[ignore = "requires qemu on macOS; boots Ubuntu and runs the real Linux mixed_run detached stop \
            smoke test inside the guest"]
fn linux_vm_runs_mixed_run_detached_stop_smoke() {
    run_linux_guest_mixed_run_test("mixed_run_detached_stop_smoke")
        .unwrap_or_else(|err| panic!("{err}"));
}

#[test]
#[ignore = "requires qemu on macOS; boots Ubuntu and runs the real Linux mixed_run five-site \
            startup test inside the guest"]
fn linux_vm_runs_mixed_run_five_site_startup_state_and_teardown() {
    run_linux_guest_mixed_run_test("mixed_run_five_site_startup_state_and_teardown")
        .unwrap_or_else(|err| panic!("{err}"));
}

#[test]
#[ignore = "requires qemu on macOS; boots Ubuntu and runs the real Linux mixed_run local \
            observability smoke test inside the guest"]
fn linux_vm_runs_mixed_run_local_observability_scenario_smoke() {
    run_linux_guest_mixed_run_test("mixed_run_local_observability_scenario_smoke")
        .unwrap_or_else(|err| panic!("{err}"));
}

#[test]
#[ignore = "requires qemu on macOS; boots Ubuntu and runs the real Linux mixed_run recovery test \
            inside the guest"]
fn linux_vm_runs_mixed_run_recovers_direct_component_failure_after_setup() {
    run_linux_guest_mixed_run_test("mixed_run_recovers_direct_component_failure_after_setup")
        .unwrap_or_else(|err| panic!("{err}"));
}

#[test]
fn provisioned_cache_keys_track_guest_setup() {
    let vm_smoke_cache_key = ProvisionProfile::VmSmoke.cache_key();
    let mixed_run_cache_key = ProvisionProfile::MixedRun.cache_key();

    assert!(vm_smoke_cache_key.starts_with("vm-smoke-"));
    assert!(mixed_run_cache_key.starts_with("mixed-run-"));
    assert_ne!(vm_smoke_cache_key, mixed_run_cache_key);
}
