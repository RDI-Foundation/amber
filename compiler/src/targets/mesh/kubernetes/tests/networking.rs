use super::*;

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
    let proxy_handle = rt.spawn(async move { router::control::run(proxy_config).await });

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
