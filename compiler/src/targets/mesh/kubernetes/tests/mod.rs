use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use amber_config as rc;
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

use super::{KubernetesReporter, *};
use crate::{
    CompileOptions, Compiler, DigestStore, OptimizeOptions,
    targets::{mesh::internal_images::resolve_internal_images, storage::StorageIdentity},
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

fn parse_rendered_env(content: &str) -> std::collections::BTreeMap<String, String> {
    content
        .lines()
        .filter_map(|line| {
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line
                .split_once('=')
                .expect("rendered env lines should contain '='");
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

fn assert_default_container_security_context(doc: &str) {
    assert!(doc.contains("securityContext:"), "{doc}");
    assert!(doc.contains("allowPrivilegeEscalation: false"), "{doc}");
    assert!(doc.contains("drop:"), "{doc}");
    assert!(doc.contains("- ALL"), "{doc}");
    assert!(doc.contains("seccompProfile:"), "{doc}");
    assert!(doc.contains("type: RuntimeDefault"), "{doc}");
}

fn assert_internal_container_runtime_hardening(doc: &str) {
    assert!(doc.contains("readOnlyRootFilesystem: true"), "{doc}");
    assert!(doc.contains("runAsNonRoot: true"), "{doc}");
    assert!(doc.contains("runAsUser: 65532"), "{doc}");
}

#[test]
fn render_root_config_env_content_materializes_defaults() {
    let leaves = [
        (
            "base_image".to_string(),
            crate::runtime_interface::RootInputDescriptor {
                env_var: "AMBER_CONFIG_BASE_IMAGE".to_string(),
                required: true,
                secret: false,
                default_value: Some(json!("line one\nline two")),
                runtime_used: true,
            },
        ),
        (
            "replicas".to_string(),
            crate::runtime_interface::RootInputDescriptor {
                env_var: "AMBER_CONFIG_REPLICAS".to_string(),
                required: false,
                secret: false,
                default_value: Some(json!(2)),
                runtime_used: true,
            },
        ),
    ];
    let refs: Vec<_> = leaves.iter().map(|(path, input)| (path, input)).collect();

    let rendered = super::render_root_config_env_content(
        &refs,
        "# Root config values - fill in values before deploying",
    )
    .expect("root env content should render");

    assert!(rendered.contains("AMBER_CONFIG_BASE_IMAGE=\"line one\\nline two\""));
    assert!(rendered.contains("AMBER_CONFIG_REPLICAS=2"));
}

#[test]
fn render_root_config_env_content_round_trips_union_defaults() {
    let schema = json!({
        "type": "object",
        "properties": {
            "flag": {
                "type": ["boolean", "string"],
                "default": true,
            },
            "count": {
                "type": ["integer", "string"],
                "default": 2,
            },
        },
    });
    let inputs = crate::runtime_interface::collect_root_inputs(
        &crate::targets::program_config::ConfigPlan {
            root_leaves: rc::collect_leaf_paths(&schema).expect("collect leaf paths"),
            program_plans: std::collections::HashMap::new(),
            mount_specs: std::collections::HashMap::new(),
            needs_helper: false,
            needs_runtime_config: false,
            runtime_views: std::collections::HashMap::new(),
        },
    )
    .expect("collect root inputs");
    let refs: Vec<_> = inputs.iter().collect();

    let rendered = super::render_root_config_env_content(
        &refs,
        "# Root config values - fill in values before deploying",
    )
    .expect("root env content should render");

    assert!(rendered.contains("AMBER_CONFIG_FLAG=true"));
    assert!(rendered.contains("AMBER_CONFIG_COUNT=2"));

    let rebuilt =
        rc::build_root_config(&schema, &parse_rendered_env(&rendered)).expect("build root config");
    assert_eq!(
        rebuilt,
        json!({
            "flag": true,
            "count": 2,
        })
    );
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

mod networking;
mod rendering;
mod storage;
