use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use amber_manifest::ManifestRef;
use amber_mesh::{
    MeshConfig, MeshConfigPublic, MeshIdentity, MeshIdentityPublic, MeshIdentitySecret, MeshPeer,
    MeshProtocol, OutboundRoute, TransportConfig, router_export_route_id,
};
use amber_resolver::Resolver;
use amber_router as router;
use amber_scenario::ComponentId;
use base64::Engine as _;
use serde_json::json;
use tempfile::tempdir;
use url::Url;

use super::KubernetesReporter;
use crate::{
    CompileOptions, Compiler, DigestStore, OptimizeOptions, reporter::Reporter as _,
    storage_plan::StorageIdentity, targets::mesh::internal_images::resolve_internal_images,
};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("compiler crate should live under the workspace root")
        .to_path_buf()
}

fn ensure_amber_cli_binary() -> PathBuf {
    let root = workspace_root();
    let status = Command::new("cargo")
        .current_dir(&root)
        .args(["build", "-q", "-p", "amber-cli"])
        .status()
        .expect("run cargo build -p amber-cli");
    assert!(status.success(), "cargo build -p amber-cli failed");
    root.join("target").join("debug").join("amber")
}

fn internal_images() -> crate::targets::mesh::internal_images::InternalImages {
    resolve_internal_images().expect("internal images should resolve for tests")
}

fn compiled_scenario(output: &crate::CompileOutput) -> crate::reporter::CompiledScenario {
    crate::reporter::CompiledScenario::from_compile_output(output)
        .expect("test compiler output should convert to compiled Scenario")
}

fn render_artifact(output: &crate::CompileOutput) -> super::KubernetesArtifact {
    KubernetesReporter
        .emit(&compiled_scenario(output))
        .expect("render kubernetes output")
}

fn storage_claim_name_for_prefix(
    artifact: &super::KubernetesArtifact,
    prefix: &str,
) -> Option<String> {
    artifact.files.keys().find_map(|path| {
        let path = path.to_str()?;
        let name = path
            .strip_prefix("03-persistentvolumeclaims/")?
            .strip_suffix(".yaml")?;
        name.starts_with(prefix).then(|| name.to_string())
    })
}

fn use_prebuilt_images() -> bool {
    std::env::var("AMBER_TEST_USE_PREBUILT_IMAGES").is_ok()
}

fn docker_platform() -> String {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    format!("linux/{arch}")
}

fn image_platform_opt(tag: &str) -> Option<String> {
    let output = Command::new("docker")
        .arg("image")
        .arg("inspect")
        .arg("-f")
        .arg("{{.Architecture}}")
        .arg(tag)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let arch = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if arch.is_empty() {
        return None;
    }
    Some(format!("linux/{arch}"))
}

fn ensure_image_platform(tag: &str, platform: &str) {
    let needs_pull = match image_platform_opt(tag) {
        Some(existing) => existing != platform,
        None => true,
    };

    if needs_pull {
        let mut cmd = Command::new("docker");
        cmd.arg("pull").arg("--platform").arg(platform).arg(tag);
        checked_status(&mut cmd, &format!("docker pull {tag} ({platform})"));
    }
}

fn build_docker_image(tag: &str, dockerfile: &Path, context: &Path) {
    if use_prebuilt_images() {
        image_platform_opt(tag).unwrap_or_else(|| {
            panic!(
                "AMBER_TEST_USE_PREBUILT_IMAGES is set but {tag} is not available locally. Ensure \
                 images are pulled and retagged before running tests."
            )
        });
        return;
    }

    let mut cmd = Command::new("docker");
    cmd.arg("build")
        .env("DOCKER_BUILDKIT", "1")
        .arg("-t")
        .arg(tag)
        .arg("-f")
        .arg(dockerfile)
        .arg(context);
    checked_status(&mut cmd, &format!("docker build {tag} image"));
}

fn build_router_image() {
    let root = workspace_root();
    let images = internal_images();
    build_docker_image(
        &images.router,
        &root.join("docker/amber-router/Dockerfile"),
        &root,
    );
}

fn build_provisioner_image() {
    let root = workspace_root();
    let images = internal_images();
    build_docker_image(
        &images.provisioner,
        &root.join("docker/amber-provisioner/Dockerfile"),
        &root,
    );
}

fn file_url(path: &Path) -> Url {
    Url::from_file_path(path).expect("path should be valid file URL")
}

fn write_kubernetes_smoke_fixture(root: &Path) -> PathBuf {
    let scenario_dir = root.join("kubernetes-basic");
    fs::create_dir_all(&scenario_dir).expect("create kubernetes smoke fixture directory");

    fs::write(
        scenario_dir.join("client.json5"),
        r##"{
  manifest_version: "0.1.0",
  program: {
    image: "busybox:1.36",
    entrypoint: [
      "sh",
      "-eu",
      "-c",
      "\
        mkdir content\n\
        cd content\n\
        wget '${slots.server.url}/runtime_secret.txt'\n\
        wget '${slots.server.url}/runtime_config.txt'\n\
        wget '${slots.server.url}/static_secret.txt'\n\
        wget '${slots.server.url}/static_config.txt'\n\
        httpd -f -p 8080\n\
      ",
    ],
    network: {
      endpoints: [{ name: "http", port: 8080 }],
    },
  },
  slots: {
    server: { kind: "http" },
  },
  provides: {
    http: { kind: "http", endpoint: "http" },
  },
  exports: {
    http: "http",
  },
}
"##,
    )
    .expect("write kubernetes smoke client manifest");

    fs::write(
        scenario_dir.join("server.json5"),
        r##"{
  manifest_version: "0.1.0",
  config_schema: {
    type: "object",
    properties: {
      runtime_secret: { type: "string", secret: true },
      runtime_config: { type: "string", },
      static_secret: { type: "string", secret: true },
      static_config: { type: "string", },
    },
    required: [
      "runtime_secret",
      "runtime_config",
      "static_secret",
      "static_config",
    ],
  },
  program: {
    image: "busybox:1.36",
    entrypoint: [
      "sh",
      "-eu",
      "-c",
      "\
        mkdir content\n\
        cd content\n\
        printf '%s\n' \"$RUNTIME_SECRET\" >runtime_secret.txt\n\
        printf '%s\n' '${config.runtime_config}' >runtime_config.txt\n\
        printf '%s\n' \"$STATIC_SECRET\" >static_secret.txt\n\
        printf '%s\n' '${config.static_config}' >static_config.txt\n\
        httpd -f -p 8080\n\
      ",
    ],
    env: {
      RUNTIME_SECRET: "${config.runtime_secret}",
      STATIC_SECRET: "${config.static_secret}",
    },
    network: {
      endpoints: [{ name: "http", port: 8080 }],
    },
  },
  provides: {
    http: { kind: "http", endpoint: "http" },
  },
  exports: {
    http: "http",
  },
}
"##,
    )
    .expect("write kubernetes smoke server manifest");

    let scenario_path = scenario_dir.join("scenario.json5");
    fs::write(
        &scenario_path,
        r##"{
  manifest_version: "0.1.0",
  config_schema: {
    type: "object",
    properties: {
      server_runtime_secret: { type: "string", secret: true },
      server_runtime_config: { type: "string" },
    },
    required: ["server_runtime_secret", "server_runtime_config"],
  },
  components: {
    server: {
      manifest: "./server.json5",
      config: {
        runtime_secret: "${config.server_runtime_secret}",
        runtime_config: "${config.server_runtime_config}",
        static_secret: "hardcode-this-secret",
        static_config: "hardcode-this-config",
      },
    },
    client: "./client.json5",
  },
  bindings: [
    { to: "#client.server", from: "#server.http" },
  ],
  exports: {
    server_http: "#server.http",
    client_http: "#client.http",
  },
}
"##,
    )
    .expect("write kubernetes smoke root scenario");

    scenario_path
}

fn write_kubernetes_counter_storage_fixture(root: &Path, version: &str) -> PathBuf {
    let scenario_dir = root.join("kubernetes-storage");
    fs::create_dir_all(&scenario_dir).expect("create kubernetes storage fixture directory");

    let scenario_path = scenario_dir.join("scenario.json5");
    fs::write(
        &scenario_path,
        format!(
            r#"{{
  manifest_version: "0.1.0",
  resources: {{
    state: {{ kind: "storage" }},
  }},
  program: {{
    image: "busybox:1.36.1",
    entrypoint: [
      "sh",
      "-eu",
      "-c",
      "mkdir -p /var/lib/app /www; count=0; if [ -f /var/lib/app/count ]; then count=$(cat /var/lib/app/count); fi; count=$((count+1)); printf '%s' \"$count\" >/var/lib/app/count; printf '{version}:%s\n' \"$count\" >/www/index.html; exec httpd -f -p 8080 -h /www"
    ],
    mounts: [
      {{ path: "/var/lib/app", from: "resources.state" }},
    ],
    network: {{
      endpoints: [
        {{ name: "http", port: 8080, protocol: "http" }},
      ],
    }},
  }},
  provides: {{
    http: {{ kind: "http", endpoint: "http" }},
  }},
  exports: {{
    http: "http",
  }},
}}
"#
        ),
    )
    .expect("write kubernetes storage root scenario");

    scenario_path
}

fn write_kubernetes_storage_fixture(root: &Path, version: &str, initial_state: &str) -> PathBuf {
    let scenario_dir = root.join("kubernetes-storage");
    fs::create_dir_all(&scenario_dir).expect("create kubernetes storage fixture directory");

    let scenario_path = scenario_dir.join("scenario.json5");
    fs::write(
        &scenario_path,
        format!(
            r##"{{
  manifest_version: "0.1.0",
  resources: {{
    state: {{ kind: "storage" }},
  }},
  program: {{
    image: "busybox:1.36.1",
    entrypoint: [
      "sh",
      "-eu",
      "-c",
      "\
        mkdir -p /var/lib/app /tmp/www\n\
        if [ ! -f /var/lib/app/state.txt ]; then printf '%s\n' '{initial_state}' >/var/lib/app/state.txt; fi\n\
        printf '%s\n' '{version}' >/tmp/www/version.txt\n\
        cp /var/lib/app/state.txt /tmp/www/state.txt\n\
        exec httpd -f -p 8080 -h /tmp/www\n\
      ",
    ],
    mounts: [
      {{ path: "/var/lib/app", from: "resources.state" }},
    ],
    network: {{
      endpoints: [{{ name: "http", port: 8080, protocol: "http" }}],
    }},
  }},
  provides: {{
    http: {{ kind: "http", endpoint: "http" }},
  }},
}}
"##,
        ),
    )
    .expect("write kubernetes storage root scenario");

    scenario_path
}

fn write_kubernetes_output(root: &Path, artifact: &super::KubernetesArtifact) {
    if root.exists() {
        fs::remove_dir_all(root).expect("remove kubernetes output directory");
    }
    fs::create_dir_all(root).expect("create kubernetes output directory");

    for (rel_path, content) in &artifact.files {
        let full_path = root.join(rel_path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).expect("create kubernetes output subdir");
        }
        fs::write(&full_path, content).expect("write kubernetes output file");
    }
}

fn set_env_value(path: &Path, key: &str, value: &str) {
    let contents = fs::read_to_string(path).expect("read config env file");
    let mut found = false;
    let mut lines = Vec::new();
    for line in contents.lines() {
        if line.starts_with(&format!("{key}=")) {
            lines.push(format!("{key}={value}"));
            found = true;
        } else {
            lines.push(line.to_string());
        }
    }
    assert!(found, "expected {key} in {}", path.display());
    let mut output = lines.join("\n");
    output.push('\n');
    fs::write(path, output).expect("write updated config env file");
}

fn checked_output(cmd: &mut Command, context: &str) -> std::process::Output {
    let output = cmd.output().unwrap_or_else(|err| {
        panic!("failed to run {context}: {err}");
    });
    if !output.status.success() {
        panic!(
            "{context} failed (status: {})\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    output
}

fn checked_status(cmd: &mut Command, context: &str) {
    cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    let status = cmd.status().unwrap_or_else(|err| {
        panic!("failed to run {context}: {err}");
    });
    if !status.success() {
        panic!("{context} failed (status: {status})");
    }
}

fn best_effort_output(cmd: &mut Command) -> String {
    match cmd.output() {
        Ok(output) => format!(
            "status: {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        Err(err) => format!("failed to run command: {err}"),
    }
}

fn kubernetes_failure_diagnostics(namespace: &str, kubeconfig: &Path) -> String {
    let pods = best_effort_output(
        kubectl_cmd(kubeconfig)
            .arg("get")
            .arg("pods")
            .arg("-n")
            .arg(namespace)
            .arg("-o")
            .arg("wide"),
    );
    let jobs = best_effort_output(
        kubectl_cmd(kubeconfig)
            .arg("get")
            .arg("jobs")
            .arg("-n")
            .arg(namespace),
    );
    let pvc = best_effort_output(
        kubectl_cmd(kubeconfig)
            .arg("get")
            .arg("pvc")
            .arg("-n")
            .arg(namespace),
    );
    let describe_job = best_effort_output(
        kubectl_cmd(kubeconfig)
            .arg("describe")
            .arg("job")
            .arg("-l")
            .arg("amber.io/type=provisioner")
            .arg("-n")
            .arg(namespace),
    );
    let logs_job = best_effort_output(
        kubectl_cmd(kubeconfig)
            .arg("logs")
            .arg("-n")
            .arg(namespace)
            .arg("-l")
            .arg("amber.io/type=provisioner")
            .arg("--all-containers=true"),
    );
    let events = best_effort_output(
        kubectl_cmd(kubeconfig)
            .arg("get")
            .arg("events")
            .arg("-n")
            .arg(namespace)
            .arg("--sort-by=.lastTimestamp"),
    );
    format!(
        "pods:\n{pods}\n\njobs:\n{jobs}\n\npvc:\n{pvc}\n\ndescribe \
         provisioner:\n{describe_job}\n\nprovisioner logs:\n{logs_job}\n\nevents:\n{events}"
    )
}

fn kustomization_namespace(path: &Path) -> String {
    let kustomization = fs::read_to_string(path).expect("read kustomization");
    let kust_doc: serde_yaml::Value =
        serde_yaml::from_str(&kustomization).expect("parse kustomization");
    kust_doc["namespace"]
        .as_str()
        .expect("kustomization namespace")
        .to_string()
}

fn provisioner_job_name(path: &Path) -> String {
    let raw = fs::read_to_string(path).expect("read provisioner job yaml");
    let doc: serde_yaml::Value = serde_yaml::from_str(&raw).expect("parse provisioner job yaml");
    doc["metadata"]["name"]
        .as_str()
        .expect("provisioner job metadata.name")
        .to_string()
}

fn set_kustomization_namespace(path: &Path, namespace: &str) {
    let kustomization = fs::read_to_string(path).expect("read kustomization");
    let mut kust_doc: serde_yaml::Value =
        serde_yaml::from_str(&kustomization).expect("parse kustomization");
    kust_doc["namespace"] = serde_yaml::Value::String(namespace.to_string());
    fs::write(
        path,
        serde_yaml::to_string(&kust_doc).expect("serialize kustomization"),
    )
    .expect("write kustomization");
}

fn ensure_namespace_exists(namespace: &str, kubeconfig: &Path) {
    let exists = kubectl_cmd(kubeconfig)
        .arg("get")
        .arg("namespace")
        .arg(namespace)
        .output()
        .expect("run kubectl get namespace")
        .status
        .success();
    if exists {
        return;
    }

    let mut cmd = kubectl_cmd(kubeconfig);
    cmd.arg("create").arg("namespace").arg(namespace);
    checked_status(&mut cmd, &format!("kubectl create namespace {namespace}"));
}

fn build_helper_image() {
    let root = workspace_root();
    let images = internal_images();
    build_docker_image(
        &images.helper,
        &root.join("docker/amber-helper/Dockerfile"),
        &root,
    );
}

struct KindClusterGuard {
    name: String,
    kubeconfig: PathBuf,
}

impl KindClusterGuard {
    fn new(name: String, kubeconfig: &Path) -> Self {
        let _ = kind_cmd(kubeconfig)
            .arg("delete")
            .arg("cluster")
            .arg("--name")
            .arg(&name)
            .status();
        let mut cmd = kind_cmd(kubeconfig);
        cmd.arg("create")
            .arg("cluster")
            .arg("--name")
            .arg(&name)
            .arg("--wait")
            .arg("120s");
        cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
        let status = cmd.status().unwrap_or_else(|err| {
            panic!("failed to run kind create cluster: {err}");
        });
        if !status.success() {
            let _ = kind_cmd(kubeconfig)
                .arg("delete")
                .arg("cluster")
                .arg("--name")
                .arg(&name)
                .status();
            panic!("kind create cluster failed (status: {status})");
        }
        Self {
            name,
            kubeconfig: kubeconfig.to_path_buf(),
        }
    }
}

impl Drop for KindClusterGuard {
    fn drop(&mut self) {
        let _ = kind_cmd(&self.kubeconfig)
            .arg("delete")
            .arg("cluster")
            .arg("--name")
            .arg(&self.name)
            .status();
    }
}

struct KindCluster {
    name: String,
    kubeconfig: PathBuf,
    _guard: Option<KindClusterGuard>,
}

impl KindCluster {
    fn from_env_or_create(default_kubeconfig: &Path) -> Self {
        match (
            std::env::var("AMBER_TEST_KIND_CLUSTER_NAME").ok(),
            std::env::var("AMBER_TEST_KIND_KUBECONFIG").ok(),
        ) {
            (Some(name), Some(kubeconfig)) => {
                if name.is_empty() || kubeconfig.is_empty() {
                    panic!(
                        "AMBER_TEST_KIND_CLUSTER_NAME and AMBER_TEST_KIND_KUBECONFIG must be \
                         non-empty when set"
                    );
                }
                Self {
                    name,
                    kubeconfig: PathBuf::from(kubeconfig),
                    _guard: None,
                }
            }
            (None, None) => {
                let nonce = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("system time")
                    .as_nanos();
                let name = format!("amber-test-{}-{nonce}", std::process::id());
                let guard = KindClusterGuard::new(name.clone(), default_kubeconfig);
                Self {
                    name,
                    kubeconfig: default_kubeconfig.to_path_buf(),
                    _guard: Some(guard),
                }
            }
            _ => {
                panic!(
                    "set both AMBER_TEST_KIND_CLUSTER_NAME and AMBER_TEST_KIND_KUBECONFIG together"
                );
            }
        }
    }
}

struct PortForwardGuard {
    child: std::process::Child,
    log_path: PathBuf,
    local_port: u16,
    remote_port: u16,
}

impl PortForwardGuard {
    fn new(namespace: &str, pod: &str, log_path: &Path, kubeconfig: &Path) -> Self {
        Self::new_with_ports(namespace, pod, 8080, 8080, log_path, kubeconfig)
    }

    fn new_with_ports(
        namespace: &str,
        pod: &str,
        local_port: u16,
        remote_port: u16,
        log_path: &Path,
        kubeconfig: &Path,
    ) -> Self {
        let log = fs::File::create(log_path).expect("create port-forward log");
        let log_err = log.try_clone().expect("clone port-forward log");
        let child = kubectl_cmd(kubeconfig)
            .arg("port-forward")
            .arg("-n")
            .arg(namespace)
            .arg(format!("pod/{pod}"))
            .arg(format!("{local_port}:{remote_port}"))
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .spawn()
            .expect("spawn kubectl port-forward");
        Self {
            child,
            log_path: log_path.to_path_buf(),
            local_port,
            remote_port,
        }
    }

    fn is_running(&mut self) -> bool {
        match self.child.try_wait() {
            Ok(None) => true,
            Ok(Some(_)) => false,
            Err(_) => false,
        }
    }

    fn logs(&self) -> String {
        fs::read_to_string(&self.log_path).unwrap_or_default()
    }

    fn wait_until_ready(&mut self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            if !self.is_running() {
                let logs = self.logs();
                panic!("port-forward exited before becoming ready\nport-forward logs:\n{logs}");
            }

            let logs = self.logs();
            let local_marker = format!(":{}", self.local_port);
            let remote_marker = format!("-> {}", self.remote_port);
            if logs.contains("Forwarding from")
                && logs.contains(&local_marker)
                && logs.contains(&remote_marker)
            {
                return;
            }

            if Instant::now() >= deadline {
                panic!("timed out waiting for port-forward readiness\nport-forward logs:\n{logs}");
            }

            thread::sleep(Duration::from_millis(200));
        }
    }
}

fn kind_cmd(kubeconfig: &Path) -> Command {
    let mut cmd = Command::new("kind");
    cmd.env("KUBECONFIG", kubeconfig);
    cmd
}

fn kubectl_cmd(kubeconfig: &Path) -> Command {
    let mut cmd = Command::new("kubectl");
    cmd.env("KUBECONFIG", kubeconfig);
    cmd
}

fn compile_fixture(manifest_path: &Path) -> super::KubernetesArtifact {
    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let opts = CompileOptions::default();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let output = rt
        .block_on(compiler.compile(ManifestRef::from_url(file_url(manifest_path)), opts))
        .expect("compile scenario");

    render_artifact(&output)
}

impl Drop for PortForwardGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn kubectl_logs(namespace: &str, pod: &str, kubeconfig: &Path) -> String {
    let output = kubectl_cmd(kubeconfig)
        .arg("logs")
        .arg("-n")
        .arg(namespace)
        .arg(pod)
        .output();
    match output {
        Ok(output) => String::from_utf8_lossy(&output.stdout).to_string(),
        Err(err) => format!("failed to run kubectl logs: {err}"),
    }
}

fn fetch(
    url: &str,
    port_forward: &mut PortForwardGuard,
    namespace: &str,
    pod: &str,
    kubeconfig: &Path,
) -> String {
    if !port_forward.is_running() {
        let logs = port_forward.logs();
        let pod_logs = kubectl_logs(namespace, pod, kubeconfig);
        panic!(
            "port-forward exited before fetching {url}\nport-forward logs:\n{logs}\npod \
             logs:\n{pod_logs}"
        );
    }

    let output = Command::new("curl")
        .arg("-fsS")
        .arg(url)
        .output()
        .unwrap_or_else(|err| panic!("failed to run curl for {url}: {err}"));
    if output.status.success() {
        return String::from_utf8_lossy(&output.stdout).trim().to_string();
    }

    let logs = port_forward.logs();
    let pod_logs = kubectl_logs(namespace, pod, kubeconfig);
    panic!(
        "curl failed for {url} (status: {})\nstdout:\n{}\nstderr:\n{}\nport-forward \
         logs:\n{logs}\npod logs:\n{pod_logs}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn kubernetes_namespace_and_metadata_digest_follow_scenario_ir() {
    let dir = tempdir().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");
    fs::write(
        &root_path,
        r#"
        {
          manifest_version: "0.1.0",
          components: { child: "./child.json5" }
        }
        "#,
    )
    .expect("write root manifest");

    let compile_namespace_and_digest = |child_contents: &str| {
        fs::write(&child_path, child_contents).expect("write child manifest");
        let compiler = Compiler::new(Resolver::new(), DigestStore::default());
        let opts = CompileOptions {
            optimize: OptimizeOptions { dce: false },
            ..Default::default()
        };
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let output = rt
            .block_on(compiler.compile(ManifestRef::from_url(file_url(&root_path)), opts))
            .expect("compile scenario");

        let artifact = render_artifact(&output);

        let kustomization = artifact
            .files
            .get(&PathBuf::from("kustomization.yaml"))
            .expect("kustomization");
        let kust_doc: serde_yaml::Value =
            serde_yaml::from_str(kustomization).expect("parse kustomization");
        let namespace = kust_doc["namespace"]
            .as_str()
            .expect("kustomization namespace")
            .to_string();

        let metadata_yaml = artifact
            .files
            .get(&PathBuf::from("01-configmaps/amber-metadata.yaml"))
            .expect("metadata configmap");
        let meta_doc: serde_yaml::Value =
            serde_yaml::from_str(metadata_yaml).expect("parse metadata yaml");
        let scenario_json = meta_doc["data"]["scenario.json"]
            .as_str()
            .expect("scenario.json in metadata");
        let scenario_json: serde_json::Value =
            serde_json::from_str(scenario_json).expect("parse scenario.json");
        let digest = scenario_json["digest"]
            .as_str()
            .expect("scenario digest")
            .to_string();

        (namespace, digest)
    };

    let child_a = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "sleep 3600"]
          }
        }
        "#;
    let child_b = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "sleep 1200"]
          }
        }
        "#;

    let (namespace_a, digest_a) = compile_namespace_and_digest(child_a);
    let (namespace_b, digest_b) = compile_namespace_and_digest(child_b);

    assert_ne!(
        namespace_a, namespace_b,
        "namespace should change when scenario IR changes"
    );
    assert_ne!(
        digest_a, digest_b,
        "metadata digest should change when scenario IR changes"
    );
}

#[test]
fn kubernetes_emits_router_for_external_slots() {
    let dir = tempdir().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let client_path = dir.path().join("client.json5");

    fs::write(
        &root_path,
        r##"
        {
          manifest_version: "0.1.0",
          slots: { api: { kind: "http" } },
          components: { client: "./client.json5" },
          bindings: [
            { to: "#client.api", from: "self.api", weak: true }
          ]
        }
        "##,
    )
    .expect("write root manifest");

    fs::write(
        &client_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "client",
            entrypoint: ["client"],
            env: { API_URL: "${slots.api.url}" }
          },
          slots: { api: { kind: "http" } }
        }
        "#,
    )
    .expect("write client manifest");

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let opts = CompileOptions {
        optimize: OptimizeOptions { dce: false },
        ..Default::default()
    };
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let output = rt
        .block_on(compiler.compile(ManifestRef::from_url(file_url(&root_path)), opts))
        .expect("compile scenario");

    let artifact = render_artifact(&output);

    let router_deploy = artifact
        .files
        .get(&PathBuf::from("03-deployments/amber-router.yaml"))
        .expect("router deployment");
    assert!(
        router_deploy.contains("AMBER_ROUTER_CONFIG_PATH"),
        "{router_deploy}"
    );
    assert!(
        router_deploy.contains("AMBER_ROUTER_IDENTITY_PATH"),
        "{router_deploy}"
    );
    assert!(
        router_deploy.contains("amber-router-external"),
        "{router_deploy}"
    );

    let router_service = artifact
        .files
        .get(&PathBuf::from("04-services/amber-router.yaml"))
        .expect("router service");
    assert!(router_service.contains("port: 24000"), "{router_service}");

    let router_env = artifact
        .files
        .get(&PathBuf::from(super::DEFAULT_EXTERNAL_ENV_FILE))
        .expect("router env template");
    assert!(
        router_env.contains("AMBER_EXTERNAL_SLOT_API_URL="),
        "{router_env}"
    );

    let kustomization = artifact
        .files
        .get(&PathBuf::from("kustomization.yaml"))
        .expect("kustomization");
    let kust_doc: serde_yaml::Value =
        serde_yaml::from_str(kustomization).expect("parse kustomization");
    let resources = kust_doc["resources"]
        .as_sequence()
        .expect("kustomization resources list");
    let contains_env = resources
        .iter()
        .any(|item| item.as_str() == Some(super::DEFAULT_EXTERNAL_ENV_FILE));
    assert!(!contains_env, "{kustomization}");
    let contains_proxy = resources
        .iter()
        .any(|item| item.as_str() == Some(super::PROXY_METADATA_FILENAME));
    assert!(!contains_proxy, "{kustomization}");
    let contains_readme = resources
        .iter()
        .any(|item| item.as_str() == Some("README.md"));
    assert!(!contains_readme, "{kustomization}");

    let proxy_json = artifact
        .files
        .get(&PathBuf::from(super::PROXY_METADATA_FILENAME))
        .expect("proxy metadata file");
    let proxy_meta: serde_json::Value =
        serde_json::from_str(proxy_json).expect("parse proxy metadata json");
    assert_eq!(proxy_meta["version"], super::PROXY_METADATA_VERSION);
    assert_eq!(proxy_meta["router"]["mesh_port"], 24000);
    assert_eq!(proxy_meta["router"]["control_port"], 24100);
    assert_eq!(proxy_meta["external_slots"]["api"]["kind"], "http");
    let readme = artifact
        .files
        .get(&PathBuf::from("README.md"))
        .expect("generated readme");
    assert!(readme.contains("kubectl apply -k ."), "{readme}");
    assert!(readme.contains("amber proxy ."), "{readme}");

    let role_yaml = artifact
        .files
        .get(&PathBuf::from("02-rbac/amber-provisioner-role.yaml"))
        .expect("provisioner role");
    let role_doc: serde_yaml::Value = serde_yaml::from_str(role_yaml).expect("parse role yaml");
    let rules = role_doc["rules"].as_sequence().expect("role rules");
    let has_create_rule = rules.iter().any(|rule| {
        let verbs = rule["verbs"].as_sequence().expect("rule verbs");
        verbs.iter().any(|v| v.as_str() == Some("create"))
            && rule["resourceNames"].is_null()
            && rule["resources"]
                .as_sequence()
                .expect("rule resources")
                .iter()
                .any(|r| r.as_str() == Some("secrets"))
    });
    assert!(has_create_rule, "{role_yaml}");
    let has_named_get_update_rule = rules.iter().any(|rule| {
        let verbs = rule["verbs"].as_sequence().expect("rule verbs");
        let has_get = verbs.iter().any(|v| v.as_str() == Some("get"));
        let has_update = verbs.iter().any(|v| v.as_str() == Some("update"));
        has_get
            && has_update
            && !rule["resourceNames"].is_null()
            && rule["resources"]
                .as_sequence()
                .expect("rule resources")
                .iter()
                .any(|r| r.as_str() == Some("secrets"))
    });
    assert!(has_named_get_update_rule, "{role_yaml}");

    let metadata_yaml = artifact
        .files
        .get(&PathBuf::from("01-configmaps/amber-metadata.yaml"))
        .expect("metadata configmap");
    let meta_doc: serde_yaml::Value =
        serde_yaml::from_str(metadata_yaml).expect("parse metadata yaml");
    let scenario_json = meta_doc["data"]["scenario.json"]
        .as_str()
        .expect("scenario.json in metadata");
    let scenario_json: serde_json::Value =
        serde_json::from_str(scenario_json).expect("parse scenario.json");
    assert_eq!(
        scenario_json["external_slots"]["api"]["required"],
        serde_json::Value::Bool(true)
    );
    assert_eq!(
        scenario_json["external_slots"]["api"]["kind"],
        serde_json::Value::String("http".to_string())
    );
}

#[test]
fn kubernetes_storage_mounts_emit_pvc_and_recreate_deployment() {
    let fixture_dir = tempdir().expect("fixture dir");
    let scenario_path = write_kubernetes_counter_storage_fixture(fixture_dir.path(), "v1");
    let artifact = compile_fixture(&scenario_path);

    assert!(
        !artifact
            .files
            .contains_key(&PathBuf::from("00-namespace.yaml")),
        "runtime artifact should not embed a Namespace object"
    );

    let claim_name = storage_claim_name_for_prefix(&artifact, "storage-component-state-")
        .expect("storage pvc claim name");

    let pvc_yaml = artifact
        .files
        .get(&PathBuf::from(format!(
            "03-persistentvolumeclaims/{claim_name}.yaml"
        )))
        .expect("pvc yaml");
    assert!(
        pvc_yaml.contains("kind: PersistentVolumeClaim"),
        "{pvc_yaml}"
    );
    assert!(pvc_yaml.contains("ReadWriteOnce"), "{pvc_yaml}");
    assert!(pvc_yaml.contains("storage: 1Gi"), "{pvc_yaml}");

    let deployment_yaml = artifact
        .files
        .get(&PathBuf::from("03-deployments/c0-component.yaml"))
        .expect("deployment yaml");
    assert!(
        deployment_yaml.contains("kind: Deployment"),
        "{deployment_yaml}"
    );
    assert!(
        deployment_yaml.contains("type: Recreate"),
        "{deployment_yaml}"
    );
    assert!(
        deployment_yaml.contains(&format!("claimName: {claim_name}")),
        "{deployment_yaml}"
    );
    assert!(
        deployment_yaml.contains("mountPath: /var/lib/app"),
        "{deployment_yaml}"
    );
    assert!(
        !deployment_yaml.contains("\n  namespace:"),
        "{deployment_yaml}"
    );

    let provision_plan_yaml = artifact
        .files
        .get(&PathBuf::from("01-configmaps/amber-mesh-provision.yaml"))
        .expect("mesh provision configmap");
    let provision_plan_doc: serde_yaml::Value =
        serde_yaml::from_str(provision_plan_yaml).expect("parse mesh provision yaml");
    let plan_json = provision_plan_doc["data"]["mesh-plan.json"]
        .as_str()
        .expect("mesh plan json");
    let plan_doc: serde_json::Value =
        serde_json::from_str(plan_json).expect("parse mesh plan json");
    assert_eq!(
        plan_doc["targets"][0]["output"]["namespace"],
        serde_json::Value::Null
    );
    assert_eq!(
        plan_doc["targets"][1]["output"]["namespace"],
        serde_json::Value::Null
    );
    assert_eq!(
        plan_doc["targets"][1]["config"]["inbound"][0]["target"]["peer_addr"],
        serde_json::Value::String("c0-component:23000".to_string())
    );

    let readme = artifact
        .files
        .get(&PathBuf::from("README.md"))
        .expect("generated readme");
    assert!(
        readme.contains("Open `kustomization.yaml` and choose the namespace"),
        "{readme}"
    );
    assert!(
        readme.contains("If you want this scenario's storage to persist across redeploys"),
        "{readme}"
    );
    assert!(
        readme.contains("kubectl -n YOUR_NAMESPACE delete pvc --all"),
        "{readme}"
    );
}

#[test]
fn kubernetes_storage_claim_names_include_identity_hash() {
    let upper = StorageIdentity {
        owner: ComponentId(0),
        owner_moniker: "/Component".to_string(),
        resource: "state".to_string(),
    };
    let lower = StorageIdentity {
        owner: ComponentId(1),
        owner_moniker: "/component".to_string(),
        resource: "state".to_string(),
    };

    let upper_name = super::storage_claim_name(&upper);
    let lower_name = super::storage_claim_name(&lower);

    assert_ne!(upper_name, lower_name);
    assert!(upper_name.starts_with("storage-component-state-"));
    assert!(lower_name.starts_with("storage-component-state-"));
    assert!(upper_name.len() <= 63);
    assert!(lower_name.len() <= 63);
}

#[test]
fn kubernetes_emits_deployment_and_pvc_for_storage_mounts() {
    let fixture_dir = tempdir().expect("create fixture temp dir");
    let scenario_path =
        write_kubernetes_storage_fixture(fixture_dir.path(), "version-v1", "persisted-v1");

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let opts = CompileOptions {
        optimize: OptimizeOptions { dce: false },
        ..Default::default()
    };
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let output = rt
        .block_on(compiler.compile(ManifestRef::from_url(file_url(&scenario_path)), opts))
        .expect("compile kubernetes storage scenario");

    let artifact = render_artifact(&output);

    assert!(
        !artifact
            .files
            .contains_key(&PathBuf::from("00-namespace.yaml")),
        "runtime output should not include a Namespace resource"
    );

    let claim_name = storage_claim_name_for_prefix(&artifact, "storage-component-state-")
        .expect("storage pvc claim name");

    let pvc = artifact
        .files
        .get(&PathBuf::from(format!(
            "03-persistentvolumeclaims/{claim_name}.yaml"
        )))
        .expect("persistentvolumeclaim manifest");
    assert!(pvc.contains("kind: PersistentVolumeClaim"), "{pvc}");
    assert!(pvc.contains("ReadWriteOnce"), "{pvc}");
    assert!(pvc.contains("storage: 1Gi"), "{pvc}");

    let deployment = artifact
        .files
        .get(&PathBuf::from("03-deployments/c0-component.yaml"))
        .expect("deployment manifest");
    assert!(deployment.contains("kind: Deployment"), "{deployment}");
    assert!(deployment.contains("type: Recreate"), "{deployment}");
    assert!(
        deployment.contains(&format!("claimName: {claim_name}")),
        "{deployment}"
    );
    assert!(
        deployment.contains("mountPath: /var/lib/app"),
        "{deployment}"
    );
    assert!(
        artifact
            .files
            .contains_key(&PathBuf::from("03-deployments/c0-component.yaml")),
        "storage-backed components should still render as deployments"
    );
}

#[test]
fn kubernetes_mesh_workloads_wait_for_fresh_mesh_config() {
    let fixture_dir = tempdir().expect("fixture dir");
    let scenario_path = write_kubernetes_counter_storage_fixture(fixture_dir.path(), "v1");
    let artifact = compile_fixture(&scenario_path);

    let component_deployment = artifact
        .files
        .get(&PathBuf::from("03-deployments/c0-component.yaml"))
        .expect("component deployment yaml");
    assert!(
        component_deployment.contains("name: wait-mesh-config"),
        "{component_deployment}"
    );
    assert!(
        component_deployment.contains("/amber/mesh/mesh-config.json"),
        "{component_deployment}"
    );

    let router_deployment = artifact
        .files
        .get(&PathBuf::from("03-deployments/amber-router.yaml"))
        .expect("router deployment yaml");
    assert!(
        router_deployment.contains("name: wait-mesh-config"),
        "{router_deployment}"
    );
    assert!(
        router_deployment.contains("/amber/mesh/mesh-config.json"),
        "{router_deployment}"
    );
}

#[test]
fn kubernetes_emits_otelcol_and_wires_otel_env() {
    let dir = tempdir().expect("temp dir");
    let root_path = dir.path().join("root.json5");
    let worker_path = dir.path().join("worker.json5");

    fs::write(
        &root_path,
        r##"
        {
          manifest_version: "0.1.0",
          components: { worker: "./worker.json5" }
        }
        "##,
    )
    .expect("write root manifest");

    fs::write(
        &worker_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "echo hello && sleep 3600"]
          }
        }
        "#,
    )
    .expect("write worker manifest");

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let opts = CompileOptions {
        optimize: OptimizeOptions { dce: false },
        ..Default::default()
    };
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let output = rt
        .block_on(compiler.compile(ManifestRef::from_url(file_url(&root_path)), opts))
        .expect("compile scenario");

    let artifact = render_artifact(&output);

    let otelcol_config = artifact
        .files
        .get(&PathBuf::from("01-configmaps/amber-otelcol-config.yaml"))
        .expect("otelcol config");
    assert!(
        otelcol_config.contains("endpoint: 0.0.0.0:4317"),
        "{otelcol_config}"
    );
    assert!(
        otelcol_config.contains("endpoint: 0.0.0.0:4318"),
        "{otelcol_config}"
    );
    assert!(otelcol_config.contains("service:"), "{otelcol_config}");
    assert!(otelcol_config.contains("traces:"), "{otelcol_config}");
    assert!(otelcol_config.contains("logs/otlp:"), "{otelcol_config}");
    assert!(otelcol_config.contains("logs/program:"), "{otelcol_config}");
    assert!(otelcol_config.contains("metrics:"), "{otelcol_config}");
    assert!(
        otelcol_config.contains("resource/amber"),
        "{otelcol_config}"
    );
    assert!(
        otelcol_config.contains("${env:AMBER_SCENARIO_RUN_ID}"),
        "{otelcol_config}"
    );
    assert!(
        otelcol_config.contains("filelog/kubernetes"),
        "{otelcol_config}"
    );
    assert!(
        otelcol_config.contains("/var/log/containers"),
        "{otelcol_config}"
    );
    assert!(
        otelcol_config.contains("transform/program_logs"),
        "{otelcol_config}"
    );
    assert!(
        otelcol_config.contains("set(scope.name, \"amber.program\")"),
        "{otelcol_config}"
    );
    assert!(
        otelcol_config
            .contains("set(log.attributes[\"amber_stream\"], log.attributes[\"log.iostream\"])"),
        "{otelcol_config}"
    );
    assert!(
        otelcol_config.contains(
            "set(log.severity_number, SEVERITY_NUMBER_INFO) where log.severity_number == 0"
        ),
        "{otelcol_config}"
    );

    let otelcol_daemonset = artifact
        .files
        .get(&PathBuf::from("03-daemonsets/amber-otelcol.yaml"))
        .expect("otelcol daemonset");
    assert!(
        otelcol_daemonset.contains("AMBER_SCENARIO_RUN_ID"),
        "{otelcol_daemonset}"
    );
    assert!(
        otelcol_daemonset.contains("AMBER_OTEL_UPSTREAM_OTLP_HTTP_ENDPOINT"),
        "{otelcol_daemonset}"
    );
    assert!(
        otelcol_daemonset.contains("serviceAccountName: amber-otelcol"),
        "{otelcol_daemonset}"
    );
    assert!(
        otelcol_daemonset.contains("/var/log/containers"),
        "{otelcol_daemonset}"
    );
    assert!(
        otelcol_daemonset.contains("/var/log/pods"),
        "{otelcol_daemonset}"
    );

    let otelcol_service = artifact
        .files
        .get(&PathBuf::from("04-services/amber-otelcol.yaml"))
        .expect("otelcol service");
    assert!(otelcol_service.contains("port: 4317"), "{otelcol_service}");
    assert!(otelcol_service.contains("port: 4318"), "{otelcol_service}");

    let component_deploy = artifact
        .files
        .iter()
        .find_map(|(path, content)| {
            let path = path.to_string_lossy();
            (path.starts_with("03-deployments/") && path.ends_with("worker.yaml"))
                .then_some(content)
        })
        .expect("worker deployment");
    assert!(
        component_deploy.contains("OTEL_EXPORTER_OTLP_ENDPOINT"),
        "{component_deploy}"
    );
    assert!(
        component_deploy.contains("http://amber-otelcol:4318"),
        "{component_deploy}"
    );
    assert!(
        component_deploy.contains("AMBER_COMPONENT_MONIKER"),
        "{component_deploy}"
    );
    assert!(
        !component_deploy.contains("AMBER_LOG_FORMAT"),
        "{component_deploy}"
    );
    assert!(
        component_deploy.contains("resource.opentelemetry.io/service.name"),
        "{component_deploy}"
    );
    assert!(
        component_deploy.contains("amber.io/component-moniker"),
        "{component_deploy}"
    );
}

#[test]
#[ignore = "requires docker + kind + kubectl + curl; run manually"]
fn kubernetes_smoke_storage_upgrade_reuses_pvc() {
    use std::{io::Read, net::TcpListener};

    let fixture_dir = tempdir().expect("create fixture temp dir");
    let scenario_path = write_kubernetes_counter_storage_fixture(fixture_dir.path(), "v1");

    let dir = tempdir().expect("create temp dir");
    let kubeconfig = dir.path().join("kubeconfig");
    let output_dir = dir.path().join("kubernetes");
    let amber_bin = ensure_amber_cli_binary();

    let platform = docker_platform();
    build_helper_image();
    build_router_image();
    build_provisioner_image();
    ensure_image_platform("busybox:1.36.1", &platform);
    let images = internal_images();

    let cluster = KindCluster::from_env_or_create(&kubeconfig);
    let cluster_name = cluster.name.clone();
    let kubeconfig = cluster.kubeconfig.clone();

    struct ProxyGuard {
        child: std::process::Child,
    }

    impl Drop for ProxyGuard {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn pick_free_port() -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind local port");
        let port = listener
            .local_addr()
            .expect("local listener address")
            .port();
        drop(listener);
        port
    }

    fn drain_pipes(child: &mut std::process::Child) -> (String, String) {
        let mut stdout = String::new();
        if let Some(mut pipe) = child.stdout.take() {
            let _ = pipe.read_to_string(&mut stdout);
        }

        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }

        (stdout, stderr)
    }

    for image in [
        images.helper.as_str(),
        images.router.as_str(),
        images.provisioner.as_str(),
        "busybox:1.36.1",
    ] {
        let mut cmd = kind_cmd(&kubeconfig);
        cmd.arg("load")
            .arg("docker-image")
            .arg(image)
            .arg("--name")
            .arg(&cluster_name);
        checked_status(&mut cmd, &format!("kind load {image} image"));
    }

    let namespace = format!("amber-storage-{}", std::process::id());
    let cleanup_namespace = |ns: &str| {
        let _ = kubectl_cmd(&kubeconfig)
            .arg("delete")
            .arg("namespace")
            .arg(ns)
            .arg("--ignore-not-found=true")
            .arg("--wait=false")
            .status();
    };
    cleanup_namespace(&namespace);

    let mut create_namespace = kubectl_cmd(&kubeconfig);
    create_namespace
        .arg("create")
        .arg("namespace")
        .arg(&namespace);
    checked_status(&mut create_namespace, "kubectl create namespace");

    let wait_for_body = |expected: &str, namespace: &str| {
        let mut get_router_pod = kubectl_cmd(&kubeconfig);
        get_router_pod
            .arg("get")
            .arg("pod")
            .arg("-n")
            .arg(namespace)
            .arg("-l")
            .arg("amber.io/component=amber-router")
            .arg("-o")
            .arg("jsonpath={.items[0].metadata.name}");
        let router_pod = String::from_utf8_lossy(
            &checked_output(&mut get_router_pod, "kubectl get router pod").stdout,
        )
        .trim()
        .to_string();
        assert!(
            !router_pod.is_empty(),
            "expected router pod in namespace {namespace}"
        );

        let mesh_port = pick_free_port();
        let control_port = pick_free_port();
        let export_port = pick_free_port();

        let mesh_log_path = dir.path().join(format!("router-mesh-{expected}.log"));
        let mut mesh_forward = PortForwardGuard::new_with_ports(
            namespace,
            &router_pod,
            mesh_port,
            24000,
            &mesh_log_path,
            &kubeconfig,
        );
        mesh_forward.wait_until_ready(Duration::from_secs(30));

        let control_log_path = dir.path().join(format!("router-control-{expected}.log"));
        let mut control_forward = PortForwardGuard::new_with_ports(
            namespace,
            &router_pod,
            control_port,
            24100,
            &control_log_path,
            &kubeconfig,
        );
        control_forward.wait_until_ready(Duration::from_secs(30));

        let mut proxy = ProxyGuard {
            child: Command::new(&amber_bin)
                .arg("proxy")
                .arg(&output_dir)
                .arg("--export")
                .arg(format!("http=127.0.0.1:{export_port}"))
                .arg("--router-addr")
                .arg(format!("127.0.0.1:{mesh_port}"))
                .arg("--router-control-addr")
                .arg(format!("127.0.0.1:{control_port}"))
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("start amber proxy"),
        };

        let deadline = Instant::now() + Duration::from_secs(60);
        let url = format!("http://127.0.0.1:{export_port}/");
        let mut last_err: Option<String> = None;
        loop {
            let output = Command::new("curl")
                .arg("-fsS")
                .arg("--max-time")
                .arg("2")
                .arg(&url)
                .output();
            match output {
                Ok(output) if output.status.success() => {
                    let body = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if body == expected {
                        return;
                    }
                    last_err = Some(format!("unexpected response body: {body:?}"));
                }
                Ok(output) => {
                    last_err = Some(format!(
                        "curl failed (status: {})\nstdout:\n{}\nstderr:\n{}",
                        output.status,
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    ));
                }
                Err(err) => last_err = Some(format!("failed to run curl: {err}")),
            }

            if let Ok(Some(status)) = proxy.child.try_wait() {
                let (proxy_stdout, proxy_stderr) = drain_pipes(&mut proxy.child);
                let mesh_logs = mesh_forward.logs();
                let control_logs = control_forward.logs();
                let router_logs = kubectl_logs(namespace, &router_pod, &kubeconfig);
                panic!(
                    "amber proxy exited before export served {expected} (status: {status})\nproxy \
                     stdout:\n{proxy_stdout}\nproxy stderr:\n{proxy_stderr}\nmesh port-forward \
                     logs:\n{mesh_logs}\ncontrol port-forward logs:\n{control_logs}\nrouter \
                     logs:\n{router_logs}"
                );
            }
            if Instant::now() >= deadline {
                let (proxy_stdout, proxy_stderr) = drain_pipes(&mut proxy.child);
                let mesh_logs = mesh_forward.logs();
                let control_logs = control_forward.logs();
                let router_logs = kubectl_logs(namespace, &router_pod, &kubeconfig);
                panic!(
                    "export did not serve {expected} via amber proxy at {url}\n{}\n\nproxy \
                     stdout:\n{proxy_stdout}\nproxy stderr:\n{proxy_stderr}\nmesh port-forward \
                     logs:\n{mesh_logs}\ncontrol port-forward logs:\n{control_logs}\nrouter \
                     logs:\n{router_logs}",
                    last_err.unwrap_or_else(|| "no curl output captured".to_string())
                );
            }
            thread::sleep(Duration::from_millis(500));
        }
    };

    let apply_version = |version: &str| {
        write_kubernetes_output(&output_dir, &compile_fixture(&scenario_path));
        set_kustomization_namespace(&output_dir.join("kustomization.yaml"), &namespace);
        let provisioner_job =
            provisioner_job_name(&output_dir.join("02-rbac/amber-provisioner-job.yaml"));
        let mut apply = kubectl_cmd(&kubeconfig);
        apply.arg("apply").arg("-k").arg(&output_dir);
        checked_status(&mut apply, &format!("kubectl apply {version}"));

        let mut wait_job = kubectl_cmd(&kubeconfig);
        wait_job
            .arg("wait")
            .arg("--for=condition=complete")
            .arg("--timeout=180s")
            .arg("job")
            .arg(&provisioner_job)
            .arg("-n")
            .arg(&namespace);
        let wait_status = wait_job.status().unwrap_or_else(|err| {
            panic!("failed to run kubectl wait provisioner {version}: {err}");
        });
        if !wait_status.success() {
            let diagnostics = kubernetes_failure_diagnostics(&namespace, &kubeconfig);
            panic!(
                "kubectl wait provisioner {version} failed (status: {wait_status})\n{diagnostics}"
            );
        }

        let mut rollout = kubectl_cmd(&kubeconfig);
        rollout
            .arg("rollout")
            .arg("status")
            .arg("deployment/c0-component")
            .arg("--timeout=180s")
            .arg("-n")
            .arg(&namespace);
        let rollout_status = rollout.status().unwrap_or_else(|err| {
            panic!("failed to run kubectl rollout deployment {version}: {err}");
        });
        if !rollout_status.success() {
            let diagnostics = kubernetes_failure_diagnostics(&namespace, &kubeconfig);
            panic!(
                "kubectl rollout deployment {version} failed (status: \
                 {rollout_status})\n{diagnostics}"
            );
        }
    };

    apply_version("v1");
    wait_for_body("v1:1", &namespace);

    write_kubernetes_counter_storage_fixture(fixture_dir.path(), "v2");
    apply_version("v2");
    wait_for_body("v2:2", &namespace);

    cleanup_namespace(&namespace);
}

#[test]
#[ignore = "requires docker + kind + kubectl + curl; run manually"]
fn kubernetes_smoke_config_roundtrip() {
    let fixture_dir = tempdir().expect("create fixture temp dir");
    let scenario_path = write_kubernetes_smoke_fixture(fixture_dir.path());

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let opts = CompileOptions::default();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let output = rt
        .block_on(compiler.compile(ManifestRef::from_url(file_url(&scenario_path)), opts))
        .expect("compile kubernetes scenario");

    let artifact = render_artifact(&output);

    let dir = tempdir().expect("create temp dir");
    let kubeconfig = dir.path().join("kubeconfig");
    let output_dir = dir.path().join("kubernetes");
    write_kubernetes_output(&output_dir, &artifact);

    set_env_value(
        &output_dir.join("root-config-secret.env"),
        "AMBER_CONFIG_SERVER_RUNTIME_SECRET",
        "test-secret-value",
    );
    set_env_value(
        &output_dir.join("root-config.env"),
        "AMBER_CONFIG_SERVER_RUNTIME_CONFIG",
        "test-config-value",
    );

    let platform = docker_platform();
    build_helper_image();
    build_router_image();
    build_provisioner_image();
    ensure_image_platform("busybox:1.36", &platform);
    let images = internal_images();

    let cluster = KindCluster::from_env_or_create(&kubeconfig);
    let cluster_name = cluster.name.clone();
    let kubeconfig = cluster.kubeconfig.clone();

    for image in [
        images.helper.as_str(),
        images.router.as_str(),
        images.provisioner.as_str(),
        "busybox:1.36",
    ] {
        let mut cmd = kind_cmd(&kubeconfig);
        cmd.arg("load")
            .arg("docker-image")
            .arg(image)
            .arg("--name")
            .arg(&cluster_name);
        checked_status(&mut cmd, &format!("kind load {image} image"));
    }

    let namespace = kustomization_namespace(&output_dir.join("kustomization.yaml"));
    ensure_namespace_exists(&namespace, &kubeconfig);

    let mut cmd = kubectl_cmd(&kubeconfig);
    cmd.arg("apply").arg("-k").arg(&output_dir);
    checked_status(&mut cmd, "kubectl apply");

    let mut cmd = kubectl_cmd(&kubeconfig);
    cmd.arg("wait")
        .arg("--for=condition=available")
        .arg("--timeout=120s")
        .arg("deployment")
        .arg("--all")
        .arg("-n")
        .arg(&namespace);
    checked_status(&mut cmd, "kubectl wait for deployments");

    let client_pod = {
        let mut cmd = kubectl_cmd(&kubeconfig);
        cmd.arg("get")
            .arg("pod")
            .arg("-n")
            .arg(&namespace)
            .arg("-l")
            .arg("amber.io/component=c1-client")
            .arg("-o")
            .arg("jsonpath={.items[0].metadata.name}");
        let output = checked_output(&mut cmd, "kubectl get client pod");
        let pod = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert!(!pod.is_empty(), "no client pod found");
        pod
    };

    let mut cmd = kubectl_cmd(&kubeconfig);
    cmd.arg("wait")
        .arg("--for=condition=ready")
        .arg("--timeout=120s")
        .arg("pod")
        .arg("-n")
        .arg(&namespace)
        .arg(&client_pod);
    checked_status(&mut cmd, "kubectl wait for client pod");

    let port_forward_log = dir.path().join("port-forward.log");
    let mut port_forward =
        PortForwardGuard::new(&namespace, &client_pod, &port_forward_log, &kubeconfig);
    port_forward.wait_until_ready(Duration::from_secs(30));

    let runtime_secret = fetch(
        "http://localhost:8080/runtime_secret.txt",
        &mut port_forward,
        &namespace,
        &client_pod,
        &kubeconfig,
    );
    let runtime_config = fetch(
        "http://localhost:8080/runtime_config.txt",
        &mut port_forward,
        &namespace,
        &client_pod,
        &kubeconfig,
    );
    let static_secret = fetch(
        "http://localhost:8080/static_secret.txt",
        &mut port_forward,
        &namespace,
        &client_pod,
        &kubeconfig,
    );
    let static_config = fetch(
        "http://localhost:8080/static_config.txt",
        &mut port_forward,
        &namespace,
        &client_pod,
        &kubeconfig,
    );

    assert_eq!(runtime_secret, "test-secret-value");
    assert_eq!(runtime_config, "test-config-value");
    assert_eq!(static_secret, "hardcode-this-secret");
    assert_eq!(static_config, "hardcode-this-config");
}

#[test]
#[ignore = "requires docker + kind + kubectl; run manually"]
fn kubernetes_smoke_external_slot_routes_to_outside_service() {
    let dir = tempdir().expect("temp dir");
    let kubeconfig = dir.path().join("kubeconfig");
    let root_path = dir.path().join("root.json5");
    let client_path = dir.path().join("client.json5");

    fs::write(
        &root_path,
        r##"
        {
          manifest_version: "0.1.0",
          slots: { api: { kind: "http" } },
          components: { client: "./client.json5" },
          bindings: [
            { to: "#client.api", from: "self.api", weak: true }
          ]
        }
        "##,
    )
    .expect("write root manifest");

    fs::write(
        &client_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "sleep 3600"],
            env: { API_URL: "${slots.api.url}" }
          },
          slots: { api: { kind: "http" } }
        }
        "#,
    )
    .expect("write client manifest");

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let opts = CompileOptions {
        optimize: OptimizeOptions { dce: false },
        ..Default::default()
    };
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let output = rt
        .block_on(compiler.compile(ManifestRef::from_url(file_url(&root_path)), opts))
        .expect("compile scenario");

    let artifact = render_artifact(&output);

    let output_dir = dir.path().join("kubernetes");
    write_kubernetes_output(&output_dir, &artifact);

    let kustomization =
        fs::read_to_string(output_dir.join("kustomization.yaml")).expect("read kustomization");
    let kust_doc: serde_yaml::Value =
        serde_yaml::from_str(&kustomization).expect("parse kustomization");
    let namespace = kust_doc["namespace"]
        .as_str()
        .expect("kustomization namespace");

    set_env_value(
        &output_dir.join(super::DEFAULT_EXTERNAL_ENV_FILE),
        "AMBER_EXTERNAL_SLOT_API_URL",
        "http://external-echo:8080",
    );

    let platform = docker_platform();
    build_router_image();
    build_provisioner_image();
    ensure_image_platform("busybox:1.36.1", &platform);
    let images = internal_images();

    let cluster = KindCluster::from_env_or_create(&kubeconfig);
    let cluster_name = cluster.name.clone();
    let kubeconfig = cluster.kubeconfig.clone();

    for image in [
        images.router.as_str(),
        images.provisioner.as_str(),
        "busybox:1.36.1",
    ] {
        let mut cmd = kind_cmd(&kubeconfig);
        cmd.arg("load")
            .arg("docker-image")
            .arg(image)
            .arg("--name")
            .arg(&cluster_name);
        checked_status(&mut cmd, &format!("kind load {image} image"));
    }

    ensure_namespace_exists(namespace, &kubeconfig);

    let mut cmd = kubectl_cmd(&kubeconfig);
    cmd.arg("apply").arg("-k").arg(&output_dir);
    checked_status(&mut cmd, "kubectl apply amber");

    let external_path = dir.path().join("external-echo.yaml");
    fs::write(
        &external_path,
        format!(
            r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: external-echo
  namespace: {namespace}
  labels:
    app: external-echo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: external-echo
  template:
    metadata:
      labels:
        app: external-echo
    spec:
      containers:
        - name: external-echo
          image: busybox:1.36.1
          command: ["sh", "-lc", "mkdir -p /www && echo external-ok > /www/index.html && httpd -f -p 8080 -h /www"]
          ports:
            - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: external-echo
  namespace: {namespace}
spec:
  selector:
    app: external-echo
  ports:
    - port: 8080
      targetPort: 8080
      protocol: TCP
"#
        ),
    )
    .expect("write external service manifest");

    let mut cmd = kubectl_cmd(&kubeconfig);
    cmd.arg("apply").arg("-f").arg(&external_path);
    checked_status(&mut cmd, "kubectl apply external service");

    let mut cmd = kubectl_cmd(&kubeconfig);
    cmd.arg("wait")
        .arg("--for=condition=available")
        .arg("--timeout=120s")
        .arg("deployment")
        .arg("--all")
        .arg("-n")
        .arg(namespace);
    checked_status(&mut cmd, "kubectl wait for deployments");

    let client_pod = {
        let mut cmd = kubectl_cmd(&kubeconfig);
        cmd.arg("get")
            .arg("pod")
            .arg("-n")
            .arg(namespace)
            .arg("-l")
            .arg("amber.io/component=c1-client")
            .arg("-o")
            .arg("jsonpath={.items[0].metadata.name}");
        let output = checked_output(&mut cmd, "kubectl get client pod");
        let pod = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert!(!pod.is_empty(), "no client pod found");
        pod
    };

    let mut cmd = kubectl_cmd(&kubeconfig);
    cmd.arg("wait")
        .arg("--for=condition=ready")
        .arg("--timeout=120s")
        .arg("pod")
        .arg("-n")
        .arg(namespace)
        .arg(&client_pod);
    checked_status(&mut cmd, "kubectl wait for client pod");

    let mut ok = false;
    for _ in 0..30 {
        let output = kubectl_cmd(&kubeconfig)
            .arg("exec")
            .arg("-n")
            .arg(namespace)
            .arg(&client_pod)
            .arg("-c")
            .arg("main")
            .arg("--")
            .arg("sh")
            .arg("-lc")
            .arg(r#"wget -qO- --timeout=2 --tries=1 "$API_URL" | grep -q external-ok"#)
            .output()
            .unwrap();
        if output.status.success() {
            ok = true;
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }

    if !ok {
        let client_logs = {
            let mut cmd = kubectl_cmd(&kubeconfig);
            cmd.arg("logs")
                .arg("-n")
                .arg(namespace)
                .arg(&client_pod)
                .arg("-c")
                .arg("main");
            cmd.output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_else(|err| format!("failed to capture client logs: {err}"))
        };
        let router_logs = {
            let mut cmd = kubectl_cmd(&kubeconfig);
            cmd.arg("logs")
                .arg("-n")
                .arg(namespace)
                .arg("-l")
                .arg("amber.io/component=amber-router");
            cmd.output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_else(|err| format!("failed to capture router logs: {err}"))
        };
        let external_logs = {
            let mut cmd = kubectl_cmd(&kubeconfig);
            cmd.arg("logs")
                .arg("-n")
                .arg(namespace)
                .arg("-l")
                .arg("app=external-echo");
            cmd.output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_else(|err| format!("failed to capture external logs: {err}"))
        };
        panic!(
            "client could not reach external slot via router\nclient logs:\n{}\nrouter \
             logs:\n{}\nexternal logs:\n{}",
            client_logs, router_logs, external_logs
        );
    }
}

#[test]
#[ignore = "requires docker + kind + kubectl; run manually"]
fn kubernetes_smoke_a2a_three_party_url_rewrite_routes_follow_up_call() {
    let dir = tempdir().expect("temp dir");
    let kubeconfig = dir.path().join("kubeconfig");
    let root_path = dir.path().join("root.json");
    let agent_a_path = dir.path().join("agent-a.json");
    let agent_b_path = dir.path().join("agent-b.json");
    let client_c_path = dir.path().join("client-c.json");

    let agent_a_entrypoint = r#"
set -eu
mkdir -p /www/.well-known /www/cgi-bin
cat >/www/.well-known/agent-card.json <<'JSON'
{"name":"agent","description":"test agent","supportedInterfaces":[{"url":"http://127.0.0.1:8080/cgi-bin/a2a","protocolBinding":"JSONRPC","protocolVersion":"1.0"}],"capabilities":{},"defaultInputModes":["text/plain"],"defaultOutputModes":["text/plain"],"skills":[]}
JSON
cat >/www/cgi-bin/a2a <<'SH'
#!/bin/sh
touch /tmp/a-invoked
echo 'Status: 200 OK'
echo 'Content-Type: text/plain'
echo
echo 'a-ok'
SH
chmod +x /www/cgi-bin/a2a
httpd -f -p 8080 -h /www
"#;
    let agent_b_entrypoint = r#"
set -eu
mkdir -p /www/cgi-bin
cat >/www/cgi-bin/inbox <<'SH'
#!/bin/sh
set -eu
body="$(cat)"
url="$(printf '%s' "$body" | sed -n 's/.*"url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
printf '%s' "$url" >/tmp/received-url
expected_a_base="$(printf '%s' "$A_URL" | sed 's:/*$::')"
expected_a_url="$expected_a_base/cgi-bin/a2a"
if [ -n "$A_URL" ] && [ "$url" = "$expected_a_url" ]; then
  touch /tmp/url-matched-a-slot
fi
if [ -n "$url" ] && wget -qO- --timeout=2 --tries=1 "$url" >/tmp/a-follow-up-response 2>/dev/null; then
  touch /tmp/follow-up-success
fi
echo 'Status: 200 OK'
echo 'Content-Type: text/plain'
echo
echo 'b-ok'
SH
chmod +x /www/cgi-bin/inbox
httpd -f -p 8080 -h /www
"#;
    let client_c_entrypoint = r#"
set -eu
i=0
while [ "$i" -lt 60 ]; do
  card="$(wget -qO- --timeout=2 --tries=1 "$A_URL/.well-known/agent-card.json" 2>/dev/null || true)"
  target="$(printf '%s' "$card" | sed -n 's/.*"url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  if [ -n "$target" ]; then
    payload="{\"url\":\"$target\"}"
    if wget -qO- --timeout=2 --tries=1 --header='Content-Type: application/json' --post-data "$payload" "$B_URL/cgi-bin/inbox" >/tmp/c-send-response 2>/dev/null; then
      touch /tmp/c-send-success
      sleep infinity
    fi
  fi
  i=$((i+1))
  sleep 1
done
touch /tmp/c-send-failed
sleep infinity
"#;

    let root_manifest = json!({
        "manifest_version": "0.1.0",
        "components": {
            "agent-a": "./agent-a.json",
            "agent-b": "./agent-b.json",
            "client-c": "./client-c.json"
        },
        "bindings": [
            {
                "to": "#agent-b.agent_a",
                "from": "#agent-a.agent"
            },
            {
                "to": "#client-c.z_agent_a",
                "from": "#agent-a.agent"
            },
            {
                "to": "#client-c.agent_b",
                "from": "#agent-b.agent"
            }
        ]
    });
    fs::write(
        &root_path,
        serde_json::to_string_pretty(&root_manifest).expect("serialize root manifest"),
    )
    .expect("write root manifest");

    let agent_a_manifest = json!({
        "manifest_version": "0.1.0",
        "program": {
            "image": "busybox:1.36.1",
            "entrypoint": ["sh", "-lc", agent_a_entrypoint],
            "network": {
                "endpoints": [{ "name": "agent", "port": 8080, "protocol": "http" }]
            }
        },
        "provides": {
            "agent": { "kind": "a2a", "endpoint": "agent" }
        },
        "exports": {
            "agent": "agent"
        }
    });
    fs::write(
        &agent_a_path,
        serde_json::to_string_pretty(&agent_a_manifest).expect("serialize agent manifest"),
    )
    .expect("write agent manifest");

    let agent_b_manifest = json!({
        "manifest_version": "0.1.0",
        "program": {
            "image": "busybox:1.36.1",
            "entrypoint": ["sh", "-lc", agent_b_entrypoint],
            "env": {
                "A_URL": "${slots.agent_a.url}"
            },
            "network": {
                "endpoints": [{ "name": "agent", "port": 8080, "protocol": "http" }]
            }
        },
        "slots": {
            "agent_a": { "kind": "a2a" }
        },
        "provides": {
            "agent": { "kind": "a2a", "endpoint": "agent" }
        },
        "exports": {
            "agent": "agent"
        }
    });
    fs::write(
        &agent_b_path,
        serde_json::to_string_pretty(&agent_b_manifest).expect("serialize agent manifest"),
    )
    .expect("write agent manifest");

    let client_c_manifest = json!({
        "manifest_version": "0.1.0",
        "program": {
            "image": "busybox:1.36.1",
            "entrypoint": ["sh", "-lc", client_c_entrypoint],
            "env": {
                "A_URL": "${slots.z_agent_a.url}",
                "B_URL": "${slots.agent_b.url}"
            }
        },
        "slots": {
            "agent_b": { "kind": "a2a" },
            "z_agent_a": { "kind": "a2a" }
        }
    });
    fs::write(
        &client_c_path,
        serde_json::to_string_pretty(&client_c_manifest).expect("serialize client manifest"),
    )
    .expect("write client manifest");

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let opts = CompileOptions {
        optimize: OptimizeOptions { dce: false },
        ..Default::default()
    };
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let output = rt
        .block_on(compiler.compile(ManifestRef::from_url(file_url(&root_path)), opts))
        .expect("compile scenario");

    let artifact = render_artifact(&output);

    let output_dir = dir.path().join("kubernetes");
    write_kubernetes_output(&output_dir, &artifact);
    let provisioner_job =
        provisioner_job_name(&output_dir.join("02-rbac/amber-provisioner-job.yaml"));

    let kustomization =
        fs::read_to_string(output_dir.join("kustomization.yaml")).expect("read kustomization");
    let kust_doc: serde_yaml::Value =
        serde_yaml::from_str(&kustomization).expect("parse kustomization");
    let namespace = kust_doc["namespace"]
        .as_str()
        .expect("kustomization namespace");

    let platform = docker_platform();
    build_router_image();
    build_provisioner_image();
    ensure_image_platform("busybox:1.36.1", &platform);
    let images = internal_images();

    let cluster = KindCluster::from_env_or_create(&kubeconfig);
    let cluster_name = cluster.name.clone();
    let kubeconfig = cluster.kubeconfig.clone();

    for image in [
        images.router.as_str(),
        images.provisioner.as_str(),
        "busybox:1.36.1",
    ] {
        let mut cmd = kind_cmd(&kubeconfig);
        cmd.arg("load")
            .arg("docker-image")
            .arg(image)
            .arg("--name")
            .arg(&cluster_name);
        checked_status(&mut cmd, &format!("kind load {image} image"));
    }

    ensure_namespace_exists(namespace, &kubeconfig);

    let mut cmd = kubectl_cmd(&kubeconfig);
    cmd.arg("apply").arg("-k").arg(&output_dir);
    checked_status(&mut cmd, "kubectl apply amber");

    let mut cmd = kubectl_cmd(&kubeconfig);
    cmd.arg("wait")
        .arg("--for=condition=complete")
        .arg("--timeout=120s")
        .arg("job")
        .arg(&provisioner_job)
        .arg("-n")
        .arg(namespace);
    checked_status(&mut cmd, "kubectl wait for provisioner job");

    let mut cmd = kubectl_cmd(&kubeconfig);
    cmd.arg("wait")
        .arg("--for=condition=available")
        .arg("--timeout=120s")
        .arg("deployment")
        .arg("--all")
        .arg("-n")
        .arg(namespace);
    checked_status(&mut cmd, "kubectl wait for deployments");

    let client_pod = {
        let mut cmd = kubectl_cmd(&kubeconfig);
        cmd.arg("get")
            .arg("pod")
            .arg("-n")
            .arg(namespace)
            .arg("-l")
            .arg("amber.io/component=c3-client-c")
            .arg("-o")
            .arg("jsonpath={.items[0].metadata.name}");
        let output = checked_output(&mut cmd, "kubectl get client pod");
        let pod = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert!(!pod.is_empty(), "no client pod found");
        pod
    };
    let agent_a_pod = {
        let mut cmd = kubectl_cmd(&kubeconfig);
        cmd.arg("get")
            .arg("pod")
            .arg("-n")
            .arg(namespace)
            .arg("-l")
            .arg("amber.io/component=c1-agent-a")
            .arg("-o")
            .arg("jsonpath={.items[0].metadata.name}");
        let output = checked_output(&mut cmd, "kubectl get agent-a pod");
        let pod = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert!(!pod.is_empty(), "no agent-a pod found");
        pod
    };
    let agent_b_pod = {
        let mut cmd = kubectl_cmd(&kubeconfig);
        cmd.arg("get")
            .arg("pod")
            .arg("-n")
            .arg(namespace)
            .arg("-l")
            .arg("amber.io/component=c2-agent-b")
            .arg("-o")
            .arg("jsonpath={.items[0].metadata.name}");
        let output = checked_output(&mut cmd, "kubectl get agent-b pod");
        let pod = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert!(!pod.is_empty(), "no agent-b pod found");
        pod
    };

    for pod in [&client_pod, &agent_a_pod, &agent_b_pod] {
        let mut cmd = kubectl_cmd(&kubeconfig);
        cmd.arg("wait")
            .arg("--for=condition=ready")
            .arg("--timeout=120s")
            .arg("pod")
            .arg("-n")
            .arg(namespace)
            .arg(pod);
        checked_status(&mut cmd, &format!("kubectl wait for pod {pod}"));
    }

    let pod_logs = |pod: &str, container: &str| -> String {
        let output = kubectl_cmd(&kubeconfig)
            .arg("logs")
            .arg("-n")
            .arg(namespace)
            .arg(pod)
            .arg("-c")
            .arg(container)
            .output();
        match output {
            Ok(output) => String::from_utf8_lossy(&output.stdout).to_string(),
            Err(err) => format!("failed to capture logs for {pod}/{container}: {err}"),
        }
    };

    let mut client_ok = false;
    for _ in 0..60 {
        let output = kubectl_cmd(&kubeconfig)
            .arg("exec")
            .arg("-n")
            .arg(namespace)
            .arg(&client_pod)
            .arg("-c")
            .arg("main")
            .arg("--")
            .arg("sh")
            .arg("-lc")
            .arg("test -f /tmp/c-send-success")
            .output()
            .unwrap();
        if output.status.success() {
            client_ok = true;
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }
    if !client_ok {
        panic!(
            "client C never completed card discovery + relay call\nclient main logs:\n{}\nclient \
             net logs:\n{}\nagent-a main logs:\n{}\nagent-a net logs:\n{}\nagent-b main \
             logs:\n{}\nagent-b net logs:\n{}",
            pod_logs(&client_pod, "main"),
            pod_logs(&client_pod, "net"),
            pod_logs(&agent_a_pod, "main"),
            pod_logs(&agent_a_pod, "net"),
            pod_logs(&agent_b_pod, "main"),
            pod_logs(&agent_b_pod, "net"),
        );
    }

    let follow_up = kubectl_cmd(&kubeconfig)
        .arg("exec")
        .arg("-n")
        .arg(namespace)
        .arg(&agent_b_pod)
        .arg("-c")
        .arg("main")
        .arg("--")
        .arg("sh")
        .arg("-lc")
        .arg("test -f /tmp/follow-up-success && test -f /tmp/url-matched-a-slot")
        .output()
        .unwrap();
    assert!(
        follow_up.status.success(),
        "agent B did not receive an A URL rewritten to B's local slot view\nagent-b main \
         logs:\n{}\nagent-b net logs:\n{}",
        pod_logs(&agent_b_pod, "main"),
        pod_logs(&agent_b_pod, "net"),
    );

    let invoked = kubectl_cmd(&kubeconfig)
        .arg("exec")
        .arg("-n")
        .arg(namespace)
        .arg(&agent_a_pod)
        .arg("-c")
        .arg("main")
        .arg("--")
        .arg("sh")
        .arg("-lc")
        .arg("test -f /tmp/a-invoked")
        .output()
        .unwrap();
    assert!(
        invoked.status.success(),
        "agent A endpoint was not invoked by agent B follow-up call\nagent-a main \
         logs:\n{}\nagent-a net logs:\n{}",
        pod_logs(&agent_a_pod, "main"),
        pod_logs(&agent_a_pod, "net"),
    );
}

#[test]
#[ignore = "requires docker + kind + kubectl; run manually"]
fn kubernetes_smoke_export_routes_to_host() {
    let dir = tempdir().expect("temp dir");
    let kubeconfig = dir.path().join("kubeconfig");
    let root_path = dir.path().join("root.json5");
    let server_path = dir.path().join("server.json5");

    fs::write(
        &root_path,
        r##"
        {
          manifest_version: "0.1.0",
          components: { server: "./server.json5" },
          exports: { public: "#server.api" }
        }
        "##,
    )
    .expect("write root manifest");

    fs::write(
        &server_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "busybox:1.36.1",
            entrypoint: ["sh", "-lc", "mkdir -p /www && echo export-ok > /www/index.html && httpd -f -p 8080 -h /www"],
            network: { endpoints: [ { name: "api", port: 8080, protocol: "http" } ] }
          },
          provides: { api: { kind: "http", endpoint: "api" } },
          exports: { api: "api" }
        }
        "#,
    )
    .expect("write server manifest");

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let opts = CompileOptions {
        optimize: OptimizeOptions { dce: false },
        ..Default::default()
    };
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let output = rt
        .block_on(compiler.compile(ManifestRef::from_url(file_url(&root_path)), opts))
        .expect("compile scenario");

    let artifact = render_artifact(&output);

    let output_dir = dir.path().join("kubernetes");
    write_kubernetes_output(&output_dir, &artifact);
    let provisioner_job =
        provisioner_job_name(&output_dir.join("02-rbac/amber-provisioner-job.yaml"));

    let kustomization =
        fs::read_to_string(output_dir.join("kustomization.yaml")).expect("read kustomization");
    let kust_doc: serde_yaml::Value =
        serde_yaml::from_str(&kustomization).expect("parse kustomization");
    let namespace = kust_doc["namespace"]
        .as_str()
        .expect("kustomization namespace");

    let platform = docker_platform();
    build_router_image();
    build_provisioner_image();
    ensure_image_platform("busybox:1.36.1", &platform);
    let images = internal_images();

    let cluster = KindCluster::from_env_or_create(&kubeconfig);
    let cluster_name = cluster.name.clone();
    let kubeconfig = cluster.kubeconfig.clone();

    for image in [
        images.router.as_str(),
        images.provisioner.as_str(),
        "busybox:1.36.1",
    ] {
        let mut cmd = kind_cmd(&kubeconfig);
        cmd.arg("load")
            .arg("docker-image")
            .arg(image)
            .arg("--name")
            .arg(&cluster_name);
        checked_status(&mut cmd, &format!("kind load {image} image"));
    }

    ensure_namespace_exists(namespace, &kubeconfig);

    let mut cmd = kubectl_cmd(&kubeconfig);
    cmd.arg("apply").arg("-k").arg(&output_dir);
    checked_status(&mut cmd, "kubectl apply amber");

    let mut cmd = kubectl_cmd(&kubeconfig);
    cmd.arg("wait")
        .arg("--for=condition=complete")
        .arg("--timeout=120s")
        .arg("job")
        .arg(&provisioner_job)
        .arg("-n")
        .arg(namespace);
    checked_status(&mut cmd, "kubectl wait for provisioner job");

    let mut cmd = kubectl_cmd(&kubeconfig);
    cmd.arg("wait")
        .arg("--for=condition=available")
        .arg("--timeout=120s")
        .arg("deployment")
        .arg("--all")
        .arg("-n")
        .arg(namespace);
    checked_status(&mut cmd, "kubectl wait for deployments");

    let mut cmd = kubectl_cmd(&kubeconfig);
    cmd.arg("get")
        .arg("secret")
        .arg("amber-router-mesh")
        .arg("-n")
        .arg(namespace)
        .arg("-o")
        .arg("json");
    let secret_output = checked_output(&mut cmd, "kubectl get router mesh secret (json)");
    let secret_doc: serde_json::Value =
        serde_json::from_slice(&secret_output.stdout).expect("parse router mesh secret json");
    let data = secret_doc["data"]
        .as_object()
        .expect("router mesh secret data should be an object");
    let config_b64 = data
        .get("mesh-config.json")
        .and_then(|v| v.as_str())
        .expect("router mesh secret missing mesh-config.json");
    let identity_b64 = data
        .get("mesh-identity.json")
        .and_then(|v| v.as_str())
        .expect("router mesh secret missing mesh-identity.json");
    let config_raw = base64::engine::general_purpose::STANDARD
        .decode(config_b64.as_bytes())
        .expect("decode mesh-config.json");
    let identity_raw = base64::engine::general_purpose::STANDARD
        .decode(identity_b64.as_bytes())
        .expect("decode mesh-identity.json");
    let config_public: MeshConfigPublic =
        serde_json::from_slice(&config_raw).expect("parse mesh-config.json");
    let identity_secret: MeshIdentitySecret =
        serde_json::from_slice(&identity_raw).expect("parse mesh-identity.json");
    let router_config = config_public
        .with_identity_secret(identity_secret)
        .expect("combine router config with identity secret");
    let router_mesh_port = router_config.mesh_listen.port();

    let router_pod = {
        let mut cmd = kubectl_cmd(&kubeconfig);
        cmd.arg("get")
            .arg("pod")
            .arg("-n")
            .arg(namespace)
            .arg("-l")
            .arg("amber.io/component=amber-router")
            .arg("-o")
            .arg("jsonpath={.items[0].metadata.name}");
        let output = checked_output(&mut cmd, "kubectl get router pod");
        let pod = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert!(!pod.is_empty(), "no router pod found");
        pod
    };

    // Port-forward router mesh port so we can connect from the host.
    let router_mesh_forward_log = dir.path().join("port-forward-router-mesh.log");
    let mut router_mesh_forward = PortForwardGuard::new_with_ports(
        namespace,
        &router_pod,
        19000,
        router_mesh_port,
        &router_mesh_forward_log,
        &kubeconfig,
    );
    router_mesh_forward.wait_until_ready(Duration::from_secs(30));

    let router_control_port = router_config
        .control_listen
        .expect("router control listen")
        .port();
    let router_control_forward_log = dir.path().join("port-forward-router-control.log");
    let mut router_control_forward = PortForwardGuard::new_with_ports(
        namespace,
        &router_pod,
        19100,
        router_control_port,
        &router_control_forward_log,
        &kubeconfig,
    );
    router_control_forward.wait_until_ready(Duration::from_secs(30));

    let control_addr = SocketAddr::from(([127, 0, 0, 1], 19100));
    let identity_url = format!("http://{}/identity", control_addr);
    let identity_output = Command::new("curl")
        .arg("-fsS")
        .arg(&identity_url)
        .output()
        .expect("fetch router identity via control");
    assert!(
        identity_output.status.success(),
        "control identity fetch failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&identity_output.stdout),
        String::from_utf8_lossy(&identity_output.stderr)
    );
    let router_identity: MeshIdentityPublic =
        serde_json::from_slice(&identity_output.stdout).expect("parse router identity");
    assert_eq!(router_identity.id, router_config.identity.id);
    assert_eq!(
        router_identity.public_key,
        router_config.identity.public_key
    );

    // Start a local proxy registered as an export peer and tunnel HTTP over the mesh connection.
    let export_name = "public";
    let proxy_listen = SocketAddr::from(([127, 0, 0, 1], 18080));
    let router_addr = SocketAddr::from(([127, 0, 0, 1], 19000));
    let router_id = router_identity.id.clone();
    let router_peer = MeshPeer {
        id: router_id.clone(),
        public_key: router_identity.public_key,
    };
    let proxy_identity =
        MeshIdentity::generate("/proxy/export/public", router_identity.mesh_scope.clone());
    let peer_key = base64::engine::general_purpose::STANDARD.encode(proxy_identity.public_key);
    let register_payload = serde_json::json!({
        "peer_id": proxy_identity.id.clone(),
        "peer_key": peer_key,
        "protocol": "http",
    })
    .to_string();
    let register_url = format!("http://{}/exports/{}", control_addr, export_name);
    let mut registered = false;
    for _ in 0..60 {
        let output = Command::new("curl")
            .arg("-fsS")
            .arg("-X")
            .arg("PUT")
            .arg("-H")
            .arg("Content-Type: application/json")
            .arg("--data")
            .arg(&register_payload)
            .arg(&register_url)
            .output();
        match output {
            Ok(output) if output.status.success() => {
                registered = true;
                break;
            }
            _ => thread::sleep(Duration::from_millis(250)),
        }
    }
    if !registered {
        let forward_logs = router_control_forward.logs();
        let router_logs = kubectl_logs(namespace, &router_pod, &kubeconfig);
        panic!(
            "failed to register export via router control at {register_url}\ncontrol port-forward \
             logs:\n{}\nrouter logs:\n{}",
            forward_logs, router_logs
        );
    }
    let proxy_config = MeshConfig {
        identity: proxy_identity.clone(),
        mesh_listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        control_listen: None,
        control_allow: None,
        peers: vec![router_peer],
        inbound: Vec::new(),
        outbound: vec![OutboundRoute {
            route_id: router_export_route_id(export_name, MeshProtocol::Http),
            slot: export_name.to_string(),
            capability_kind: None,
            capability_profile: None,
            listen_port: proxy_listen.port(),
            listen_addr: Some(proxy_listen.ip().to_string()),
            protocol: MeshProtocol::Http,
            http_plugins: Vec::new(),
            peer_addr: router_addr.to_string(),
            peer_id: router_id.clone(),
            capability: export_name.to_string(),
        }],
        transport: TransportConfig::NoiseIk {},
    };
    let proxy_handle = rt.spawn(async move { router::run(proxy_config).await });

    let url = format!("http://{}", proxy_listen);
    let mut last_err: Option<String> = None;
    let mut ok = false;
    for _ in 0..60 {
        let output = Command::new("curl")
            .arg("-fsS")
            .arg("--max-time")
            .arg("2")
            .arg(&url)
            .output();
        match output {
            Ok(output) if output.status.success() => {
                let body = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if body == "export-ok" {
                    ok = true;
                    break;
                }
                last_err = Some(format!("unexpected response body: {body:?}"));
            }
            Ok(output) => {
                last_err = Some(format!(
                    "curl failed (status: {})\nstdout:\n{}\nstderr:\n{}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Err(err) => last_err = Some(format!("failed to run curl: {err}")),
        }
        thread::sleep(Duration::from_millis(500));
    }

    proxy_handle.abort();

    if !ok {
        let forward_logs = router_mesh_forward.logs();
        let router_logs = kubectl_logs(namespace, &router_pod, &kubeconfig);
        panic!(
            "export was not reachable via local proxy at {url}\n{}\n\nport-forward \
             logs:\n{}\nrouter logs:\n{}",
            last_err.unwrap_or_else(|| "no curl output captured".to_string()),
            forward_logs,
            router_logs
        );
    }
}
