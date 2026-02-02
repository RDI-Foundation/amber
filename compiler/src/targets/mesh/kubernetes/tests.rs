use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use amber_manifest::ManifestRef;
use amber_resolver::Resolver;
use tempfile::tempdir;
use url::Url;

use super::{HELPER_IMAGE, KubernetesReporter, KubernetesReporterConfig, ROUTER_IMAGE};
use crate::{CompileOptions, Compiler, DigestStore, OptimizeOptions, reporter::Reporter as _};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("compiler crate should live under the workspace root")
        .to_path_buf()
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

fn build_router_image() {
    let root = workspace_root();
    let dockerfile = root.join("docker/amber-router/Dockerfile");
    let mut cmd = Command::new("docker");
    cmd.arg("build")
        .env("DOCKER_BUILDKIT", "1")
        .arg("-t")
        .arg(ROUTER_IMAGE)
        .arg("-f")
        .arg(&dockerfile)
        .arg(&root);
    checked_status(&mut cmd, "docker build amber-router image");
}

fn file_url(path: &Path) -> Url {
    Url::from_file_path(path).expect("path should be valid file URL")
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

fn build_helper_image() {
    let root = workspace_root();
    let dockerfile = root.join("docker/amber-helper/Dockerfile");
    let mut cmd = Command::new("docker");
    cmd.arg("build")
        .arg("-t")
        .arg(HELPER_IMAGE)
        .arg("-f")
        .arg(&dockerfile)
        .arg(&root);
    checked_status(&mut cmd, "docker build amber-helper image");
}

struct KindClusterGuard {
    name: String,
}

impl KindClusterGuard {
    fn new(name: String) -> Self {
        let mut cmd = Command::new("kind");
        cmd.arg("create")
            .arg("cluster")
            .arg("--name")
            .arg(&name)
            .arg("--wait")
            .arg("120s");
        checked_status(&mut cmd, "kind create cluster");
        Self { name }
    }
}

impl Drop for KindClusterGuard {
    fn drop(&mut self) {
        let _ = Command::new("kind")
            .arg("delete")
            .arg("cluster")
            .arg("--name")
            .arg(&self.name)
            .status();
    }
}

struct PortForwardGuard {
    child: std::process::Child,
    log_path: PathBuf,
}

impl PortForwardGuard {
    fn new(namespace: &str, pod: &str, log_path: &Path) -> Self {
        let log = fs::File::create(log_path).expect("create port-forward log");
        let log_err = log.try_clone().expect("clone port-forward log");
        let child = Command::new("kubectl")
            .arg("port-forward")
            .arg("-n")
            .arg(namespace)
            .arg(format!("pod/{pod}"))
            .arg("8080:8080")
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .spawn()
            .expect("spawn kubectl port-forward");
        Self {
            child,
            log_path: log_path.to_path_buf(),
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
            if logs.contains("Forwarding from") && logs.contains(":8080") {
                return;
            }

            if Instant::now() >= deadline {
                panic!("timed out waiting for port-forward readiness\nport-forward logs:\n{logs}");
            }

            thread::sleep(Duration::from_millis(200));
        }
    }
}

impl Drop for PortForwardGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn kubectl_logs(namespace: &str, pod: &str) -> String {
    let output = Command::new("kubectl")
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

fn fetch(url: &str, port_forward: &mut PortForwardGuard, namespace: &str, pod: &str) -> String {
    if !port_forward.is_running() {
        let logs = port_forward.logs();
        let pod_logs = kubectl_logs(namespace, pod);
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
    let pod_logs = kubectl_logs(namespace, pod);
    panic!(
        "curl failed for {url} (status: {})\nstdout:\n{}\nstderr:\n{}\nport-forward \
         logs:\n{logs}\npod logs:\n{pod_logs}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
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
    let mut opts = CompileOptions::default();
    opts.optimize = OptimizeOptions { dce: false };
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let output = rt
        .block_on(compiler.compile(ManifestRef::from_url(file_url(&root_path)), opts))
        .expect("compile scenario");

    let reporter = KubernetesReporter {
        config: KubernetesReporterConfig {
            // kind's default CNI doesn't enforce NetworkPolicy, so the netpol
            // check would keep pods in init forever in this test.
            disable_networkpolicy_check: true,
        },
    };
    let artifact = reporter.emit(&output).expect("render kubernetes output");

    let router_deploy = artifact
        .files
        .get(&PathBuf::from("03-deployments/amber-router.yaml"))
        .expect("router deployment");
    assert!(
        router_deploy.contains("AMBER_ROUTER_CONFIG_B64"),
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
    assert!(router_service.contains("port: 21000"), "{router_service}");

    let router_env = artifact
        .files
        .get(&PathBuf::from("router-external.env"))
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
        .any(|item| item.as_str() == Some("router-external.env"));
    assert!(!contains_env, "{kustomization}");

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
#[ignore = "requires docker + kind + kubectl + curl; run manually"]
fn kubernetes_smoke_config_roundtrip() {
    let workspace = workspace_root();
    let scenario_path = workspace.join("test-scenarios/kubernetes-basic/scenario.json5");

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let opts = CompileOptions::default();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let output = rt
        .block_on(compiler.compile(ManifestRef::from_url(file_url(&scenario_path)), opts))
        .expect("compile kubernetes scenario");

    let reporter = KubernetesReporter {
        config: KubernetesReporterConfig {
            // kind's default CNI doesn't enforce NetworkPolicy, so the netpol
            // check would keep pods in init forever in this test.
            disable_networkpolicy_check: true,
        },
    };
    let artifact = reporter.emit(&output).expect("render kubernetes output");

    let dir = tempdir().expect("create temp dir");
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
    ensure_image_platform("busybox:1.36", &platform);

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs();
    let cluster_name = format!("amber-test-{}-{nonce}", std::process::id());
    let _cluster_guard = KindClusterGuard::new(cluster_name.clone());

    for image in [HELPER_IMAGE, ROUTER_IMAGE, "busybox:1.36"] {
        let mut cmd = Command::new("kind");
        cmd.arg("load")
            .arg("docker-image")
            .arg(image)
            .arg("--name")
            .arg(&cluster_name);
        checked_status(&mut cmd, &format!("kind load {image} image"));
    }

    let mut cmd = Command::new("kubectl");
    cmd.arg("apply").arg("-k").arg(&output_dir);
    checked_status(&mut cmd, "kubectl apply");

    let namespace = {
        let mut cmd = Command::new("kubectl");
        cmd.arg("get")
            .arg("namespaces")
            .arg("-l")
            .arg("app.kubernetes.io/managed-by=amber")
            .arg("-o")
            .arg("jsonpath={.items[0].metadata.name}");
        let output = checked_output(&mut cmd, "kubectl get namespace");
        let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert!(!name.is_empty(), "no namespace found for amber");
        name
    };

    let mut cmd = Command::new("kubectl");
    cmd.arg("wait")
        .arg("--for=condition=available")
        .arg("--timeout=120s")
        .arg("deployment")
        .arg("--all")
        .arg("-n")
        .arg(&namespace);
    checked_status(&mut cmd, "kubectl wait for deployments");

    let client_pod = {
        let mut cmd = Command::new("kubectl");
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

    let mut cmd = Command::new("kubectl");
    cmd.arg("wait")
        .arg("--for=condition=ready")
        .arg("--timeout=120s")
        .arg("pod")
        .arg("-n")
        .arg(&namespace)
        .arg(&client_pod);
    checked_status(&mut cmd, "kubectl wait for client pod");

    let port_forward_log = dir.path().join("port-forward.log");
    let mut port_forward = PortForwardGuard::new(&namespace, &client_pod, &port_forward_log);
    port_forward.wait_until_ready(Duration::from_secs(30));

    let runtime_secret = fetch(
        "http://localhost:8080/runtime_secret.txt",
        &mut port_forward,
        &namespace,
        &client_pod,
    );
    let runtime_config = fetch(
        "http://localhost:8080/runtime_config.txt",
        &mut port_forward,
        &namespace,
        &client_pod,
    );
    let static_secret = fetch(
        "http://localhost:8080/static_secret.txt",
        &mut port_forward,
        &namespace,
        &client_pod,
    );
    let static_config = fetch(
        "http://localhost:8080/static_config.txt",
        &mut port_forward,
        &namespace,
        &client_pod,
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
            args: ["sh", "-lc", "sleep 3600"],
            env: { API_URL: "${slots.api.url}" }
          },
          slots: { api: { kind: "http" } }
        }
        "#,
    )
    .expect("write client manifest");

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let mut opts = CompileOptions::default();
    opts.optimize = OptimizeOptions { dce: false };
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let output = rt
        .block_on(compiler.compile(ManifestRef::from_url(file_url(&root_path)), opts))
        .expect("compile scenario");

    let reporter = KubernetesReporter {
        config: KubernetesReporterConfig {
            // kind's default CNI doesn't enforce NetworkPolicy, so the netpol
            // check would keep pods in init forever in this test.
            disable_networkpolicy_check: true,
        },
    };
    let artifact = reporter.emit(&output).expect("render kubernetes output");

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
        &output_dir.join("router-external.env"),
        "AMBER_EXTERNAL_SLOT_API_URL",
        "http://external-echo:8080",
    );

    let platform = docker_platform();
    build_router_image();
    ensure_image_platform("busybox:1.36.1", &platform);

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs();
    let cluster_name = format!("amber-test-{}-{nonce}", std::process::id());
    let _cluster_guard = KindClusterGuard::new(cluster_name.clone());

    for image in [ROUTER_IMAGE, "busybox:1.36.1"] {
        let mut cmd = Command::new("kind");
        cmd.arg("load")
            .arg("docker-image")
            .arg(image)
            .arg("--name")
            .arg(&cluster_name);
        checked_status(&mut cmd, &format!("kind load {image} image"));
    }

    let mut cmd = Command::new("kubectl");
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

    let mut cmd = Command::new("kubectl");
    cmd.arg("apply").arg("-f").arg(&external_path);
    checked_status(&mut cmd, "kubectl apply external service");

    let mut cmd = Command::new("kubectl");
    cmd.arg("wait")
        .arg("--for=condition=available")
        .arg("--timeout=120s")
        .arg("deployment")
        .arg("--all")
        .arg("-n")
        .arg(namespace);
    checked_status(&mut cmd, "kubectl wait for deployments");

    let client_pod = {
        let mut cmd = Command::new("kubectl");
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

    let mut cmd = Command::new("kubectl");
    cmd.arg("wait")
        .arg("--for=condition=ready")
        .arg("--timeout=120s")
        .arg("pod")
        .arg("-n")
        .arg(namespace)
        .arg(&client_pod);
    checked_status(&mut cmd, "kubectl wait for client pod");

    let bypass = Command::new("kubectl")
        .arg("exec")
        .arg("-n")
        .arg(namespace)
        .arg(&client_pod)
        .arg("-c")
        .arg("main")
        .arg("--")
        .arg("sh")
        .arg("-lc")
        .arg(r#"wget -qO- --timeout=2 --tries=1 "http://external-echo:8080" 2>/dev/null"#)
        .output()
        .unwrap();
    if bypass.status.success() {
        eprintln!(
            "NetworkPolicy not enforced: client can reach external-echo directly; skipping bypass \
             assertion"
        );
    }

    let mut ok = false;
    for _ in 0..30 {
        let output = Command::new("kubectl")
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
            let mut cmd = Command::new("kubectl");
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
            let mut cmd = Command::new("kubectl");
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
            let mut cmd = Command::new("kubectl");
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
