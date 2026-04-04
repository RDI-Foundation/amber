use super::*;

const FRAMEWORK_MUTATION_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

const FRAMEWORK_ADMIN_APP: &str = r#"import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

NAME = os.environ["NAME"]
PORT = int(os.environ["PORT"])
CTL_URL = os.environ["CTL_URL"].rstrip("/")
CONTROL_TIMEOUT = 300.0

def send(handler, status, body, content_type="text/plain; charset=utf-8"):
    payload = body.encode("utf-8")
    handler.send_response(status)
    handler.send_header("content-type", content_type)
    handler.send_header("content-length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)

def call(method, path, payload=None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Connection": "close"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = Request(f"{CTL_URL}{path}", data=data, headers=headers, method=method)
    with urlopen(request, timeout=CONTROL_TIMEOUT) as response:
        return response.read().decode("utf-8")

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            if self.path == "/create":
                length = int(self.headers.get("content-length", "0") or "0")
                payload = self.rfile.read(length).decode("utf-8") if length else "{}"
                request = json.loads(payload)
                send(
                    self,
                    200,
                    call("POST", "/v1/children", request),
                    "application/json",
                )
                return
            if self.path == "/snapshot":
                send(self, 200, call("POST", "/v1/snapshot", {}), "application/json")
                return
            send(self, 404, "missing")
        except HTTPError as err:
            body = err.read().decode("utf-8", errors="replace").strip()
            detail = f"{err.__class__.__name__}: HTTP {err.code}: {body or err.reason}"
            send(self, 502, detail)
        except Exception as err:
            send(self, 502, f"{err.__class__.__name__}: {err}")

    def do_GET(self):
        try:
            if self.path == "/id":
                send(self, 200, NAME)
                return
            if self.path == "/children":
                send(self, 200, call("GET", "/v1/children"), "application/json")
                return
            if self.path == "/snapshot":
                send(self, 200, call("POST", "/v1/snapshot", {}), "application/json")
                return
            if self.path.startswith("/create/"):
                suffix = self.path.removeprefix("/create/")
                template, sep, name = suffix.partition("/")
                if not sep:
                    name = template
                    template = "worker"
                send(
                    self,
                    200,
                    call("POST", "/v1/children", {"template": template, "name": name}),
                    "application/json",
                )
                return
            if self.path.startswith("/destroy/"):
                name = self.path.removeprefix("/destroy/")
                call("DELETE", f"/v1/children/{name}")
                send(self, 200, "destroyed")
                return
            send(self, 404, "missing")
        except HTTPError as err:
            body = err.read().decode("utf-8", errors="replace").strip()
            detail = f"{err.__class__.__name__}: HTTP {err.code}: {body or err.reason}"
            send(self, 502, detail)
        except Exception as err:
            send(self, 502, f"{err.__class__.__name__}: {err}")

    def do_DELETE(self):
        try:
            if self.path.startswith("/destroy/"):
                name = self.path.removeprefix("/destroy/")
                call("DELETE", f"/v1/children/{name}")
                send(self, 200, "destroyed")
                return
            send(self, 404, "missing")
        except HTTPError as err:
            body = err.read().decode("utf-8", errors="replace").strip()
            detail = f"{err.__class__.__name__}: HTTP {err.code}: {body or err.reason}"
            send(self, 502, detail)
        except Exception as err:
            send(self, 502, f"{err.__class__.__name__}: {err}")

    def log_message(self, fmt, *args):
        print(f"[admin] {fmt % args}", flush=True)

ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
"#;

const FRAMEWORK_WORKER_APP: &str = r#"import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NAME = os.environ["NAME"]
PORT = int(os.environ["PORT"])

def send(handler, status, body):
    payload = body.encode("utf-8")
    handler.send_response(status)
    handler.send_header("content-type", "text/plain; charset=utf-8")
    handler.send_header("content-length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/id":
            send(self, 200, NAME)
            return
        send(self, 200, "ok")

    def log_message(self, fmt, *args):
        print(f"[worker] {fmt % args}", flush=True)

ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
"#;

const FRAMEWORK_MATRIX_APP: &str = r#"import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen

NAME = os.environ["NAME"]
PORT = int(os.environ["PORT"])
UPSTREAMS = {
    key.removeprefix("UPSTREAM_").lower(): value.rstrip("/")
    for key, value in os.environ.items()
    if key.startswith("UPSTREAM_") and value
}

def fetch_text(url: str, timeout: float = 30.0) -> str:
    request = Request(url, headers={"Connection": "close"})
    with urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8")

def send(handler, status, body):
    payload = body.encode("utf-8")
    handler.send_response(status)
    handler.send_header("content-type", "text/plain; charset=utf-8")
    handler.send_header("content-length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/id":
            send(self, 200, NAME)
            return
        if self.path.startswith("/call/"):
            alias = self.path.removeprefix("/call/")
            upstream = UPSTREAMS.get(alias)
            if not upstream:
                send(self, 404, f"missing upstream {alias}")
                return
            send(self, 200, fetch_text(f"{upstream}/id"))
            return
        send(self, 200, "ok")

    def log_message(self, fmt, *args):
        print(f"[matrix] {fmt % args}", flush=True)

ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
"#;

const FRAMEWORK_EXTERNAL_BIND_APP: &str = r#"import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen

NAME = os.environ["NAME"]
PORT = int(os.environ["PORT"])
UPSTREAM_URL = os.environ["UPSTREAM_URL"].rstrip("/")

def fetch_text(url: str, timeout: float = 10.0) -> str:
    request = Request(url, headers={"Connection": "close"})
    with urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8")

def send(handler, status, body):
    payload = body.encode("utf-8")
    handler.send_response(status)
    handler.send_header("content-type", "text/plain; charset=utf-8")
    handler.send_header("content-length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/id":
            send(self, 200, NAME)
            return
        if self.path == "/probe":
            send(self, 200, fetch_text(f"{UPSTREAM_URL}/item/amber-mug"))
            return
        send(self, 200, "ok")

    def log_message(self, fmt, *args):
        print(f"[external-bind] {fmt % args}", flush=True)

ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
"#;

const FRAMEWORK_BARRIER_PROBE_APP: &str = r#"import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen

NAME = os.environ["NAME"]
PORT = int(os.environ["PORT"])
REQUIRED_URL = os.environ["REQUIRED_URL"].rstrip("/")
WEAK_URL = os.environ["WEAK_URL"].rstrip("/")

def fetch_id(url: str, timeout: float = 2.0):
    request = Request(f"{url}/id", headers={"Connection": "close"})
    with urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8")

def probe(url: str):
    try:
        return {"ok": True, "body": fetch_id(url)}
    except Exception as err:
        return {"ok": False, "error": err.__class__.__name__}

STARTUP = json.dumps(
    {
        "required": probe(REQUIRED_URL),
        "weak": probe(WEAK_URL),
    },
    sort_keys=True,
)

def send(handler, status, body, content_type="text/plain; charset=utf-8"):
    payload = body.encode("utf-8")
    handler.send_response(status)
    handler.send_header("content-type", content_type)
    handler.send_header("content-length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/id":
            send(self, 200, NAME)
            return
        if self.path == "/startup":
            send(self, 200, STARTUP, "application/json")
            return
        send(self, 200, "ok")

    def log_message(self, fmt, *args):
        print(f"[barrier] {fmt % args}", flush=True)

ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
"#;

fn write_framework_admin_component(root: &Path, file_name: &str, image: bool, port: u16) {
    let program = if image {
        json!({
            "image": TEST_APP_IMAGE,
            "entrypoint": ["python3", "-u", "-c", { "file": "./admin.py" }],
            "env": {
                "NAME": "admin",
                "PORT": port.to_string(),
                "CTL_URL": "${slots.ctl.url}"
            },
            "network": {
                "endpoints": [
                    { "name": "http", "port": port, "protocol": "http" }
                ]
            }
        })
    } else {
        json!({
            "path": "/usr/bin/env",
            "args": ["python3", "-u", "-c", { "file": "./admin.py" }],
            "env": {
                "NAME": "admin",
                "PORT": port.to_string(),
                "CTL_URL": "${slots.ctl.url}"
            },
            "network": {
                "endpoints": [
                    { "name": "http", "port": port, "protocol": "http" }
                ]
            }
        })
    };
    write_json(
        &root.join(file_name),
        &json!({
            "manifest_version": "0.3.0",
            "slots": {
                "ctl": { "kind": "component" }
            },
            "program": program,
            "provides": {
                "http": { "kind": "http", "endpoint": "http" }
            },
            "exports": {
                "http": "http"
            }
        }),
    );
}

fn write_framework_worker_component(
    root: &Path,
    file_name: &str,
    image: bool,
    name: &str,
    port: u16,
) {
    let program = if image {
        json!({
            "image": TEST_APP_IMAGE,
            "entrypoint": ["python3", "-u", "-c", { "file": "./worker.py" }],
            "env": {
                "NAME": name,
                "PORT": port.to_string()
            },
            "network": {
                "endpoints": [
                    { "name": "http", "port": port, "protocol": "http" }
                ]
            }
        })
    } else {
        json!({
            "path": "/usr/bin/env",
            "args": ["python3", "-u", "-c", { "file": "./worker.py" }],
            "env": {
                "NAME": name,
                "PORT": port.to_string()
            },
            "network": {
                "endpoints": [
                    { "name": "http", "port": port, "protocol": "http" }
                ]
            }
        })
    };
    write_json(
        &root.join(file_name),
        &json!({
            "manifest_version": "0.3.0",
            "program": program,
            "provides": {
                "http": { "kind": "http", "endpoint": "http" }
            },
            "exports": {
                "http": "http"
            }
        }),
    );
}

fn framework_control_state_path(run: &RunHandle) -> PathBuf {
    run.run_root
        .join("state")
        .join("framework-component")
        .join("control-state.json")
}

fn wait_for_live_child(control_state_path: &Path, name: &str) -> u64 {
    wait_for_condition(
        Duration::from_secs(60),
        || {
            read_json(control_state_path)["live_children"]
                .as_array()
                .is_some_and(|children| {
                    children
                        .iter()
                        .any(|child| child["name"] == name && child["state"] == "live")
                })
        },
        &format!("dynamic child `{name}` live in control state"),
    );
    let control_state = read_json(control_state_path);
    control_state["live_children"]
        .as_array()
        .expect("live children should be an array")
        .iter()
        .find(|child| child["name"] == name)
        .and_then(|child| child["child_id"].as_u64())
        .unwrap_or_else(|| panic!("dynamic child `{name}` should have an id"))
}

fn framework_child_artifact(run: &RunHandle, site_id: &str, child_id: u64) -> PathBuf {
    run.run_root
        .join("state")
        .join(site_id)
        .join("framework-component")
        .join("children")
        .join(child_id.to_string())
        .join("artifact")
}

fn framework_manifest_catalog_key(path: &Path) -> String {
    let canonical = path
        .canonicalize()
        .unwrap_or_else(|err| panic!("failed to canonicalize {}: {err}", path.display()));
    url::Url::from_file_path(&canonical)
        .unwrap_or_else(|_| panic!("failed to build file URL for {}", canonical.display()))
        .to_string()
}

fn framework_proxy_args_for_site_state(site_state: &Value) -> Vec<String> {
    if !matches!(
        site_state["kind"].as_str(),
        Some("direct" | "vm" | "kubernetes")
    ) {
        return Vec::new();
    }
    vec![
        "--router-addr".to_string(),
        site_state["router_mesh_addr"]
            .as_str()
            .expect("kubernetes site should publish router mesh addr")
            .to_string(),
        "--router-control-addr".to_string(),
        site_state["router_control"]
            .as_str()
            .expect("kubernetes site should publish router control")
            .to_string(),
    ]
}

fn spawn_framework_proxy_for_site(
    output_dir: &Path,
    export: &str,
    local_port: u16,
    site_state: &Value,
) -> SpawnedProxy {
    let args = framework_proxy_args_for_site_state(site_state);
    spawn_proxy(output_dir, export, local_port, &args)
}

fn wait_for_framework_child_absent(
    control_state_path: &Path,
    child_name: &str,
    child_roots: &[PathBuf],
    timeout: Duration,
) {
    wait_for_condition(
        timeout,
        || {
            let no_live_child = read_json(control_state_path)["live_children"]
                .as_array()
                .is_some_and(|children| children.iter().all(|child| child["name"] != child_name));
            no_live_child && child_roots.iter().all(|root| !root.exists())
        },
        &format!("dynamic child `{child_name}` removed from control state and site artifacts"),
    );
}

fn indent_block(contents: &str, spaces: usize) -> String {
    let prefix = " ".repeat(spaces);
    contents
        .lines()
        .map(|line| format!("{prefix}{line}\n"))
        .collect()
}

fn render_framework_admin_vm_cloud_init(port: u16) -> String {
    format!(
        r#"#cloud-config
write_files:
  - path: /usr/local/bin/framework-admin.py
    permissions: '0755'
    content: |
{script}
  - path: /etc/systemd/system/framework-admin.service
    permissions: '0644'
    content: |
      [Unit]
      Description=Amber framework admin VM app

      [Service]
      Environment=NAME=admin
      Environment=PORT={port}
      Environment=CTL_URL=${{slots.ctl.url}}
      ExecStart=/usr/bin/python3 /usr/local/bin/framework-admin.py
      Restart=always

      [Install]
      WantedBy=multi-user.target
runcmd:
  - [systemctl, daemon-reload]
  - [systemctl, enable, --now, framework-admin.service]
"#,
        script = indent_block(FRAMEWORK_ADMIN_APP, 6),
    )
}

fn write_framework_vm_admin_component(
    root: &Path,
    file_name: &str,
    cloud_init_name: &str,
    base_image: &Path,
) {
    fs::write(
        root.join(cloud_init_name),
        render_framework_admin_vm_cloud_init(8080),
    )
    .unwrap_or_else(|err| {
        panic!(
            "failed to write {}: {err}",
            root.join(cloud_init_name).display()
        )
    });
    write_json(
        &root.join(file_name),
        &json!({
            "manifest_version": "0.3.0",
            "slots": {
                "ctl": { "kind": "component" }
            },
            "program": {
                "vm": {
                    "image": base_image.display().to_string(),
                    "cpus": 2,
                    "memory_mib": 768,
                    "cloud_init": {
                        "user_data": { "file": format!("./{cloud_init_name}") }
                    },
                    "network": {
                        "endpoints": [
                            { "name": "http", "port": 8080, "protocol": "http" }
                        ]
                    }
                }
            },
            "provides": {
                "http": { "kind": "http", "endpoint": "http" }
            },
            "exports": {
                "http": "http"
            }
        }),
    );
}

fn write_framework_dynamic_child_manifest(
    root: &Path,
    file_name: &str,
    root_component_file: &str,
    helper_components: &[(&str, &str)],
) {
    let mut components = helper_components
        .iter()
        .map(|(alias, file_name)| (format!("{alias}_helper"), json!(format!("./{file_name}"))))
        .collect::<serde_json::Map<_, _>>();
    components.insert(
        "root".to_string(),
        json!(format!("./{root_component_file}")),
    );
    let bindings = helper_components
        .iter()
        .map(|(alias, _)| {
            json!({
                "to": format!("#root.{alias}"),
                "from": format!("#{alias}_helper.http")
            })
        })
        .collect::<Vec<_>>();
    let mut exports = serde_json::Map::from_iter([("http".to_string(), json!("#root.http"))]);
    for (alias, _) in helper_components {
        exports.insert(
            format!("{alias}_http"),
            json!(format!("#{alias}_helper.http")),
        );
    }
    write_json(
        &root.join(file_name),
        &json!({
            "manifest_version": "0.3.0",
            "components": components,
            "bindings": bindings,
            "exports": exports
        }),
    );
}

fn write_framework_matrix_fixture(root: &Path, kind_cluster: &KindCluster) -> ScenarioFixture {
    fs::write(root.join("admin.py"), FRAMEWORK_ADMIN_APP).expect("failed to write admin.py");
    fs::write(root.join("app.py"), FRAMEWORK_MATRIX_APP).expect("failed to write app.py");

    let base_image = mixed_run_base_image();
    assert!(
        base_image.is_file(),
        "framework matrix test requires {}\nset AMBER_MIXED_RUN_BASE_IMAGE to override",
        base_image.display()
    );

    let direct_admin_port = pick_free_port();
    let direct_root_port = pick_free_port();
    let direct_helper_port = pick_free_port();

    write_framework_admin_component(root, "compose-admin.json5", true, 8080);
    write_framework_admin_component(root, "kind-admin.json5", true, 8080);
    write_framework_admin_component(root, "direct-admin.json5", false, direct_admin_port);
    write_framework_vm_admin_component(
        root,
        "vm-admin.json5",
        "vm-admin.cloud-init.yaml",
        &base_image,
    );

    write_image_component(
        root,
        "compose-helper.json5",
        "child-compose-helper",
        8080,
        &[],
        &[],
    );
    write_image_component(
        root,
        "kind-helper.json5",
        "child-kind-helper",
        8080,
        &[],
        &[],
    );
    write_path_component(
        root,
        "direct-helper.json5",
        "child-direct-helper",
        direct_helper_port,
        &[],
        &[],
    );
    write_json(
        &root.join("vm-helper.json5"),
        &json!({
            "manifest_version": "0.3.0",
            "components": {
                "root": "./vm-helper-root.json5"
            },
            "exports": {
                "http": "#root.http"
            }
        }),
    );
    write_vm_component(
        root,
        VmComponentSpec {
            file_name: "vm-helper-root.json5",
            cloud_init_name: "vm-helper.cloud-init.yaml",
            name: "child-vm-helper",
            listen_port: 8080,
            base_image: &base_image,
            upstreams: &[],
            adversarial_host_url: None,
        },
    );

    write_path_component(
        root,
        "child-direct-root.json5",
        "child-direct-root",
        direct_root_port,
        &[
            ("compose", "${slots.compose.url}"),
            ("kind", "${slots.kind.url}"),
            ("vm", "${slots.vm.url}"),
        ],
        &[],
    );
    write_image_component(
        root,
        "child-compose-root.json5",
        "child-compose-root",
        8080,
        &[
            ("kind", "${slots.kind.url}"),
            ("direct", "${slots.direct.url}"),
            ("vm", "${slots.vm.url}"),
        ],
        &[],
    );
    write_image_component(
        root,
        "child-kind-root.json5",
        "child-kind-root",
        8080,
        &[
            ("compose", "${slots.compose.url}"),
            ("direct", "${slots.direct.url}"),
            ("vm", "${slots.vm.url}"),
        ],
        &[],
    );
    write_vm_component(
        root,
        VmComponentSpec {
            file_name: "child-vm-root.json5",
            cloud_init_name: "child-vm.cloud-init.yaml",
            name: "child-vm-root",
            listen_port: 8080,
            base_image: &base_image,
            upstreams: &[
                ("compose", "${slots.compose.url}"),
                ("kind", "${slots.kind.url}"),
                ("direct", "${slots.direct.url}"),
            ],
            adversarial_host_url: None,
        },
    );

    write_framework_dynamic_child_manifest(
        root,
        "child-direct.json5",
        "child-direct-root.json5",
        &[
            ("compose", "compose-helper.json5"),
            ("kind", "kind-helper.json5"),
            ("vm", "vm-helper.json5"),
        ],
    );
    write_framework_dynamic_child_manifest(
        root,
        "child-compose.json5",
        "child-compose-root.json5",
        &[
            ("kind", "kind-helper.json5"),
            ("direct", "direct-helper.json5"),
            ("vm", "vm-helper.json5"),
        ],
    );
    write_framework_dynamic_child_manifest(
        root,
        "child-kind.json5",
        "child-kind-root.json5",
        &[
            ("compose", "compose-helper.json5"),
            ("direct", "direct-helper.json5"),
            ("vm", "vm-helper.json5"),
        ],
    );
    write_framework_dynamic_child_manifest(
        root,
        "child-vm.json5",
        "child-vm-root.json5",
        &[
            ("compose", "compose-helper.json5"),
            ("kind", "kind-helper.json5"),
            ("direct", "direct-helper.json5"),
        ],
    );

    let manifest = root.join("root.json5");
    write_json(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "slots": {
                "realm": { "kind": "component", "optional": true }
            },
            "components": {
                "compose_admin": "./compose-admin.json5",
                "kind_admin": "./kind-admin.json5",
                "direct_admin": "./direct-admin.json5",
                "vm_admin": "./vm-admin.json5"
            },
            "child_templates": {
                "child_compose": { "manifest": "./child-compose.json5" },
                "child_kind": { "manifest": "./child-kind.json5" },
                "child_direct": { "manifest": "./child-direct.json5" },
                "child_vm": { "manifest": "./child-vm.json5" }
            },
            "bindings": [
                { "to": "#compose_admin.ctl", "from": "framework.component" },
                { "to": "#kind_admin.ctl", "from": "framework.component" },
                { "to": "#direct_admin.ctl", "from": "framework.component" },
                { "to": "#vm_admin.ctl", "from": "framework.component" }
            ],
            "exports": {
                "compose_admin_http": "#compose_admin.http",
                "kind_admin_http": "#kind_admin.http",
                "direct_admin_http": "#direct_admin.http",
                "vm_admin_http": "#vm_admin.http"
            }
        }),
    );

    let mut components = serde_json::Map::new();
    components.insert("/compose_admin".to_string(), json!("compose_local"));
    components.insert("/kind_admin".to_string(), json!("kind_local"));
    components.insert("/direct_admin".to_string(), json!("direct_local"));
    components.insert("/vm_admin".to_string(), json!("vm_local"));
    for (moniker, site_id) in [
        ("/job-compose/root", "compose_local"),
        ("/job-compose/kind_helper", "kind_local"),
        ("/job-compose/direct_helper", "direct_local"),
        ("/job-compose/vm_helper/root", "vm_local"),
        ("/job-kind/root", "kind_local"),
        ("/job-kind/compose_helper", "compose_local"),
        ("/job-kind/direct_helper", "direct_local"),
        ("/job-kind/vm_helper/root", "vm_local"),
        ("/job-direct/root", "direct_local"),
        ("/job-direct/compose_helper", "compose_local"),
        ("/job-direct/kind_helper", "kind_local"),
        ("/job-direct/vm_helper/root", "vm_local"),
        ("/job-vm/root", "vm_local"),
        ("/job-vm/compose_helper", "compose_local"),
        ("/job-vm/kind_helper", "kind_local"),
        ("/job-vm/direct_helper", "direct_local"),
    ] {
        components.insert(moniker.to_string(), json!(site_id));
    }

    let placement = root.join("placement.json5");
    write_json(
        &placement,
        &json!({
            "schema": "amber.run.placement",
            "version": 1,
            "sites": {
                "compose_local": { "kind": "compose" },
                "kind_local": {
                    "kind": "kubernetes",
                    "context": kind_cluster.context_name()
                },
                "direct_local": { "kind": "direct" },
                "vm_local": { "kind": "vm" }
            },
            "defaults": {
                "image": "compose_local",
                "path": "direct_local",
                "vm": "vm_local"
            },
            "components": components
        }),
    );

    ScenarioFixture {
        manifest,
        placement,
    }
}

#[derive(Clone, Copy)]
struct FrameworkMatrixTemplateCase {
    template: &'static str,
    child_name: &'static str,
    exports: &'static [(&'static str, &'static str, &'static str)],
    root_calls: &'static [(&'static str, &'static str)],
}

const FRAMEWORK_MATRIX_CREATORS: [(&str, &str); 4] = [
    ("compose_local", "compose_admin_http"),
    ("kind_local", "kind_admin_http"),
    ("direct_local", "direct_admin_http"),
    ("vm_local", "vm_admin_http"),
];

const FRAMEWORK_MATRIX_COMPOSE_EXPORTS: [(&str, &str, &str); 4] = [
    ("compose_local", "http", "child-compose-root"),
    ("kind_local", "kind_http", "child-kind-helper"),
    ("direct_local", "direct_http", "child-direct-helper"),
    ("vm_local", "vm_http", "child-vm-helper"),
];
const FRAMEWORK_MATRIX_COMPOSE_CALLS: [(&str, &str); 3] = [
    ("kind", "child-kind-helper"),
    ("direct", "child-direct-helper"),
    ("vm", "child-vm-helper"),
];

const FRAMEWORK_MATRIX_KIND_EXPORTS: [(&str, &str, &str); 4] = [
    ("kind_local", "http", "child-kind-root"),
    ("compose_local", "compose_http", "child-compose-helper"),
    ("direct_local", "direct_http", "child-direct-helper"),
    ("vm_local", "vm_http", "child-vm-helper"),
];
const FRAMEWORK_MATRIX_KIND_CALLS: [(&str, &str); 3] = [
    ("compose", "child-compose-helper"),
    ("direct", "child-direct-helper"),
    ("vm", "child-vm-helper"),
];

const FRAMEWORK_MATRIX_DIRECT_EXPORTS: [(&str, &str, &str); 4] = [
    ("direct_local", "http", "child-direct-root"),
    ("compose_local", "compose_http", "child-compose-helper"),
    ("kind_local", "kind_http", "child-kind-helper"),
    ("vm_local", "vm_http", "child-vm-helper"),
];
const FRAMEWORK_MATRIX_DIRECT_CALLS: [(&str, &str); 3] = [
    ("compose", "child-compose-helper"),
    ("kind", "child-kind-helper"),
    ("vm", "child-vm-helper"),
];

const FRAMEWORK_MATRIX_VM_EXPORTS: [(&str, &str, &str); 4] = [
    ("vm_local", "http", "child-vm-root"),
    ("compose_local", "compose_http", "child-compose-helper"),
    ("kind_local", "kind_http", "child-kind-helper"),
    ("direct_local", "direct_http", "child-direct-helper"),
];
const FRAMEWORK_MATRIX_VM_CALLS: [(&str, &str); 3] = [
    ("compose", "child-compose-helper"),
    ("kind", "child-kind-helper"),
    ("direct", "child-direct-helper"),
];

const FRAMEWORK_MATRIX_TEMPLATES: [FrameworkMatrixTemplateCase; 4] = [
    FrameworkMatrixTemplateCase {
        template: "child_compose",
        child_name: "job-compose",
        exports: &FRAMEWORK_MATRIX_COMPOSE_EXPORTS,
        root_calls: &FRAMEWORK_MATRIX_COMPOSE_CALLS,
    },
    FrameworkMatrixTemplateCase {
        template: "child_kind",
        child_name: "job-kind",
        exports: &FRAMEWORK_MATRIX_KIND_EXPORTS,
        root_calls: &FRAMEWORK_MATRIX_KIND_CALLS,
    },
    FrameworkMatrixTemplateCase {
        template: "child_direct",
        child_name: "job-direct",
        exports: &FRAMEWORK_MATRIX_DIRECT_EXPORTS,
        root_calls: &FRAMEWORK_MATRIX_DIRECT_CALLS,
    },
    FrameworkMatrixTemplateCase {
        template: "child_vm",
        child_name: "job-vm",
        exports: &FRAMEWORK_MATRIX_VM_EXPORTS,
        root_calls: &FRAMEWORK_MATRIX_VM_CALLS,
    },
];

fn assert_string_array_members(value: &Value, expected: &[&str], message: &str) {
    let actual = value
        .as_array()
        .expect("expected a JSON array")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("expected array entries to be strings")
                .to_owned()
        })
        .collect::<std::collections::BTreeSet<_>>();
    let expected = expected
        .iter()
        .map(|entry| (*entry).to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(actual, expected, "{message}");
}

fn framework_create_child_with_request(port: u16, request: &Value) -> (u16, String) {
    let body = serde_json::to_string(request).expect("create request should serialize");
    http_request_with_timeout(
        "POST",
        port,
        "/create",
        Some(&body),
        FRAMEWORK_MUTATION_REQUEST_TIMEOUT,
    )
    .expect("create request should return an HTTP response")
}

fn framework_destroy_child_via_admin(port: u16, name: &str) -> (u16, String) {
    http_request_with_timeout(
        "DELETE",
        port,
        &format!("/destroy/{name}"),
        None,
        FRAMEWORK_MUTATION_REQUEST_TIMEOUT,
    )
    .expect("destroy request should return an HTTP response")
}

fn framework_snapshot_via_admin(port: u16) -> Value {
    let (status, body) = http_request_with_timeout(
        "POST",
        port,
        "/snapshot",
        Some("{}"),
        FRAMEWORK_MUTATION_REQUEST_TIMEOUT,
    )
    .expect("snapshot request should return an HTTP response");
    assert_eq!(status, 200, "snapshot request should succeed: {body}");
    serde_json::from_str(&body).expect("snapshot response should be valid json")
}

fn write_snapshot_run_inputs(root: &Path, snapshot: &Value) -> (PathBuf, PathBuf) {
    let scenario_path = root.join("snapshot-scenario.json");
    let placement_path = root.join("snapshot-placement.json5");
    write_json(&scenario_path, &snapshot["scenario"]);
    write_json(
        &placement_path,
        &json!({
            "schema": "amber.run.placement",
            "version": 1,
            "sites": snapshot["placement"]["offered_sites"],
            "defaults": snapshot["placement"]["defaults"],
            "components": snapshot["placement"]
                .get("assignments")
                .cloned()
                .unwrap_or_else(|| json!({}))
        }),
    );
    (scenario_path, placement_path)
}

#[test]
#[ignore = "requires a working direct runtime sandbox; run manually or in CI"]
fn framework_component_direct_create_destroy_live() {
    let temp = temp_output_dir("framework-component-direct-");
    let admin_port = pick_free_port();
    let worker_port = pick_free_port();

    fs::write(temp.path().join("admin.py"), FRAMEWORK_ADMIN_APP).expect("failed to write admin.py");
    fs::write(temp.path().join("worker.py"), FRAMEWORK_WORKER_APP)
        .expect("failed to write worker.py");
    write_framework_admin_component(temp.path(), "admin.json5", false, admin_port);
    write_json(
        &temp.path().join("worker.json5"),
        &json!({
            "manifest_version": "0.3.0",
            "config_schema": {
                "type": "object",
                "properties": {
                    "name": { "type": "string" }
                },
                "required": ["name"]
            },
            "program": {
                "path": "/usr/bin/env",
                "args": ["python3", "-u", "-c", { "file": "./worker.py" }],
                "env": {
                    "NAME": "${config.name}",
                    "PORT": worker_port.to_string()
                },
                "network": {
                    "endpoints": [
                        { "name": "http", "port": worker_port, "protocol": "http" }
                    ]
                }
            },
            "provides": {
                "http": { "kind": "http", "endpoint": "http" }
            },
            "exports": {
                "http": "http"
            }
        }),
    );
    let manifest = temp.path().join("root.json5");
    write_json(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "slots": {
                "realm": { "kind": "component", "optional": true }
            },
            "components": {
                "admin": "./admin.json5"
            },
            "child_templates": {
                "worker": {
                    "manifest": "./worker.json5"
                }
            },
            "bindings": [
                { "to": "#admin.ctl", "from": "framework.component" }
            ],
            "exports": {
                "admin_http": "#admin.http"
            }
        }),
    );
    let placement = temp.path().join("placement.json5");
    write_json(
        &placement,
        &json!({
            "schema": "amber.run.placement",
            "version": 1,
            "sites": {
                "direct_local": { "kind": "direct" }
            },
            "defaults": {
                "path": "direct_local"
            }
        }),
    );

    let storage_root = temp.path().join("state");
    let mut run = run_manifest(&manifest, &placement, &storage_root);

    let admin_port = pick_free_port();
    let mut admin_proxy = spawn_proxy(
        &run.site_artifact_dir("direct_local"),
        "admin_http",
        admin_port,
        &[],
    );
    wait_for_path(&mut admin_proxy, admin_port, "/id", Duration::from_secs(60));
    assert_eq!(
        wait_for_body(&mut admin_proxy, admin_port, "/id", Duration::from_secs(60)),
        "admin"
    );

    let (create_status, create_response) = framework_create_child_with_request(
        admin_port,
        &json!({
            "template": "worker",
            "name": "job-1",
            "config": {
                "name": "worker-one"
            }
        }),
    );
    assert_eq!(create_status, 200, "create request should succeed");
    let create_json: Value =
        serde_json::from_str(&create_response).expect("create response should be valid json");
    assert_eq!(create_json["child"]["name"], "job-1");

    let control_state_path = framework_control_state_path(&run);
    let child_id = wait_for_live_child(&control_state_path, "job-1");

    let child_artifact = framework_child_artifact(&run, "direct_local", child_id);
    wait_for_file(
        &child_artifact.join(".amber").join("direct-runtime.json"),
        Duration::from_secs(60),
    );

    let child_proxy_port = pick_free_port();
    let mut child_proxy = spawn_proxy(&child_artifact, "http", child_proxy_port, &[]);
    wait_for_path(
        &mut child_proxy,
        child_proxy_port,
        "/id",
        Duration::from_secs(60),
    );
    assert_eq!(
        wait_for_body(
            &mut child_proxy,
            child_proxy_port,
            "/id",
            Duration::from_secs(60)
        ),
        "worker-one"
    );

    stop_proxy(&mut child_proxy);

    let (destroy_status, destroy_response) = framework_destroy_child_via_admin(admin_port, "job-1");
    assert_eq!(
        destroy_status, 200,
        "destroy request should succeed; response: {destroy_response}"
    );
    let child_root = child_artifact
        .parent()
        .expect("child artifact should have a parent")
        .to_path_buf();
    wait_for_condition(
        Duration::from_secs(60),
        || {
            !child_root.exists()
                && read_json(&control_state_path)["live_children"]
                    .as_array()
                    .is_some_and(|children| children.iter().all(|child| child["name"] != "job-1"))
        },
        "dynamic child teardown",
    );

    let (recreate_status, recreate_response) = framework_create_child_with_request(
        admin_port,
        &json!({
            "template": "worker",
            "name": "job-1",
            "config": {
                "name": "worker-two"
            }
        }),
    );
    assert_eq!(
        recreate_status, 200,
        "recreate request should succeed; response: {recreate_response}"
    );
    let recreate_json: Value =
        serde_json::from_str(&recreate_response).expect("recreate response should be valid json");
    assert_eq!(recreate_json["child"]["name"], "job-1");

    let recreated_child_id = wait_for_live_child(&control_state_path, "job-1");
    assert_ne!(
        recreated_child_id, child_id,
        "recreate should allocate a fresh dynamic child id"
    );

    let recreated_artifact = framework_child_artifact(&run, "direct_local", recreated_child_id);
    wait_for_file(
        &recreated_artifact
            .join(".amber")
            .join("direct-runtime.json"),
        Duration::from_secs(60),
    );

    let recreated_proxy_port = pick_free_port();
    let mut recreated_proxy = spawn_proxy(&recreated_artifact, "http", recreated_proxy_port, &[]);
    wait_for_path(
        &mut recreated_proxy,
        recreated_proxy_port,
        "/id",
        Duration::from_secs(60),
    );
    assert_eq!(
        wait_for_body(
            &mut recreated_proxy,
            recreated_proxy_port,
            "/id",
            Duration::from_secs(60)
        ),
        "worker-two",
        "recreated child must serve the new config, not a leaked stale workload"
    );

    stop_proxy(&mut recreated_proxy);
    stop_proxy(&mut admin_proxy);
    run.stop();
}

#[test]
#[ignore = "requires a working direct runtime sandbox; run manually or in CI"]
fn framework_component_open_template_frozen_source_replay_live() {
    let temp = temp_output_dir("framework-component-frozen-open-template-");
    let admin_port = pick_free_port();
    let alpha_port = pick_free_port();
    let beta_port = pick_free_port();

    fs::write(temp.path().join("admin.py"), FRAMEWORK_ADMIN_APP).expect("failed to write admin.py");
    fs::write(temp.path().join("worker.py"), FRAMEWORK_WORKER_APP)
        .expect("failed to write worker.py");
    write_framework_admin_component(temp.path(), "admin.json5", false, admin_port);
    write_framework_worker_component(
        temp.path(),
        "alpha.json5",
        false,
        "alpha-original",
        alpha_port,
    );
    write_framework_worker_component(temp.path(), "beta.json5", false, "beta-original", beta_port);
    let alpha_path = temp.path().join("alpha.json5");
    let beta_path = temp.path().join("beta.json5");
    let alpha_key = framework_manifest_catalog_key(&alpha_path);
    let beta_key = framework_manifest_catalog_key(&beta_path);

    let manifest = temp.path().join("root.json5");
    write_json(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "slots": {
                "realm": { "kind": "component", "optional": true }
            },
            "components": {
                "admin": "./admin.json5"
            },
            "child_templates": {
                "worker": {
                    "allowed_manifests": [alpha_key.clone(), beta_key.clone()]
                }
            },
            "bindings": [
                { "to": "#admin.ctl", "from": "framework.component" }
            ],
            "exports": {
                "admin_http": "#admin.http"
            }
        }),
    );
    let placement = temp.path().join("placement.json5");
    write_json(
        &placement,
        &json!({
            "schema": "amber.run.placement",
            "version": 1,
            "sites": {
                "direct_local": { "kind": "direct" }
            },
            "defaults": {
                "path": "direct_local"
            }
        }),
    );

    let storage_root = temp.path().join("state");
    let mut run = run_manifest(&manifest, &placement, &storage_root);

    let admin_proxy_port = pick_free_port();
    let mut admin_proxy = spawn_proxy(
        &run.site_artifact_dir("direct_local"),
        "admin_http",
        admin_proxy_port,
        &[],
    );
    wait_for_path(
        &mut admin_proxy,
        admin_proxy_port,
        "/id",
        Duration::from_secs(60),
    );

    write_framework_worker_component(
        temp.path(),
        "beta.json5",
        false,
        "beta-mutated-on-disk",
        beta_port,
    );
    fs::remove_file(&alpha_path).expect("alpha manifest should be removable after run start");

    let (create_status, create_response) = framework_create_child_with_request(
        admin_proxy_port,
        &json!({
            "template": "worker",
            "name": "job-beta",
            "manifest": {
                "catalog_key": beta_key
            }
        }),
    );
    assert_eq!(
        create_status, 200,
        "open-template create should use the frozen catalog; response: {create_response}"
    );

    let control_state_path = framework_control_state_path(&run);
    let beta_child_id = wait_for_live_child(&control_state_path, "job-beta");
    let beta_artifact = framework_child_artifact(&run, "direct_local", beta_child_id);
    let beta_proxy_port = pick_free_port();
    let mut beta_proxy = spawn_proxy(&beta_artifact, "http", beta_proxy_port, &[]);
    wait_for_path(
        &mut beta_proxy,
        beta_proxy_port,
        "/id",
        Duration::from_secs(60),
    );
    assert_eq!(
        wait_for_body(
            &mut beta_proxy,
            beta_proxy_port,
            "/id",
            Duration::from_secs(60)
        ),
        "beta-original",
        "live create should use the frozen manifest contents, not the mutated disk source"
    );

    let snapshot = framework_snapshot_via_admin(admin_proxy_port);
    stop_proxy(&mut beta_proxy);
    stop_proxy(&mut admin_proxy);
    run.stop();

    fs::remove_file(&beta_path).expect("beta manifest should be removable before replay");
    let replay_root = temp.path().join("replay");
    fs::create_dir_all(&replay_root).expect("failed to create replay dir");
    let (snapshot_scenario, snapshot_placement) =
        write_snapshot_run_inputs(&replay_root, &snapshot);

    let replay_storage_root = temp.path().join("replay-state");
    let mut replay_run = run_manifest(
        &snapshot_scenario,
        &snapshot_placement,
        &replay_storage_root,
    );
    let replay_admin_port = pick_free_port();
    let mut replay_admin_proxy = spawn_proxy(
        &replay_run.site_artifact_dir("direct_local"),
        "admin_http",
        replay_admin_port,
        &[],
    );
    wait_for_path(
        &mut replay_admin_proxy,
        replay_admin_port,
        "/id",
        Duration::from_secs(60),
    );

    let (replay_status, replay_response) = framework_create_child_with_request(
        replay_admin_port,
        &json!({
            "template": "worker",
            "name": "job-alpha",
            "manifest": {
                "catalog_key": alpha_key
            }
        }),
    );
    assert_eq!(
        replay_status, 200,
        "replay should preserve future dynamic create affordances; response: {replay_response}"
    );

    let replay_control_state = framework_control_state_path(&replay_run);
    let alpha_child_id = wait_for_live_child(&replay_control_state, "job-alpha");
    let alpha_artifact = framework_child_artifact(&replay_run, "direct_local", alpha_child_id);
    let alpha_proxy_port = pick_free_port();
    let mut alpha_proxy = spawn_proxy(&alpha_artifact, "http", alpha_proxy_port, &[]);
    wait_for_path(
        &mut alpha_proxy,
        alpha_proxy_port,
        "/id",
        Duration::from_secs(60),
    );
    assert_eq!(
        wait_for_body(
            &mut alpha_proxy,
            alpha_proxy_port,
            "/id",
            Duration::from_secs(60)
        ),
        "alpha-original",
        "replay should still use the frozen manifest content after the source files are gone"
    );

    stop_proxy(&mut alpha_proxy);
    stop_proxy(&mut replay_admin_proxy);
    replay_run.stop();
}

#[test]
#[ignore = "requires docker; run manually or in CI"]
fn framework_component_concurrent_create_serialization_live() {
    ensure_internal_images();
    let temp = temp_output_dir("framework-component-concurrency-");
    let admin_port = pick_free_port();
    let worker_port = pick_free_port();

    fs::write(temp.path().join("admin.py"), FRAMEWORK_ADMIN_APP).expect("failed to write admin.py");
    fs::write(temp.path().join("worker.py"), FRAMEWORK_WORKER_APP)
        .expect("failed to write worker.py");
    write_framework_admin_component(temp.path(), "admin.json5", true, admin_port);
    write_json(
        &temp.path().join("worker.json5"),
        &json!({
            "manifest_version": "0.3.0",
            "config_schema": {
                "type": "object",
                "properties": {
                    "name": { "type": "string" }
                },
                "required": ["name"]
            },
            "program": {
                "image": TEST_APP_IMAGE,
                "entrypoint": ["python3", "-u", "-c", { "file": "./worker.py" }],
                "env": {
                    "NAME": "${config.name}",
                    "PORT": worker_port.to_string()
                },
                "network": {
                    "endpoints": [
                        { "name": "http", "port": worker_port, "protocol": "http" }
                    ]
                }
            },
            "provides": {
                "http": { "kind": "http", "endpoint": "http" }
            },
            "exports": {
                "http": "http"
            }
        }),
    );
    let manifest = temp.path().join("root.json5");
    write_json(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "slots": {
                "realm": { "kind": "component", "optional": true }
            },
            "components": {
                "admin": "./admin.json5"
            },
            "child_templates": {
                "worker": {
                    "manifest": "./worker.json5"
                }
            },
            "bindings": [
                { "to": "#admin.ctl", "from": "framework.component" }
            ],
            "exports": {
                "admin_http": "#admin.http"
            }
        }),
    );
    let placement = temp.path().join("placement.json5");
    write_json(
        &placement,
        &json!({
            "schema": "amber.run.placement",
            "version": 1,
            "sites": {
                "compose_local": { "kind": "compose" }
            },
            "defaults": {
                "image": "compose_local"
            }
        }),
    );

    let storage_root = temp.path().join("state");
    let mut run = run_manifest(&manifest, &placement, &storage_root);
    let admin_proxy_port = pick_free_port();
    let mut admin_proxy = spawn_proxy(
        &run.site_artifact_dir("compose_local"),
        "admin_http",
        admin_proxy_port,
        &[],
    );
    wait_for_path(
        &mut admin_proxy,
        admin_proxy_port,
        "/id",
        Duration::from_secs(60),
    );

    let race_barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let race_request = json!({
        "template": "worker",
        "name": "job-race",
        "config": {
            "name": "race-winner"
        }
    });
    let left_barrier = race_barrier.clone();
    let left_request = race_request.clone();
    let left = std::thread::spawn(move || {
        left_barrier.wait();
        framework_create_child_with_request(admin_proxy_port, &left_request)
    });
    let right_barrier = race_barrier.clone();
    let right_request = race_request.clone();
    let right = std::thread::spawn(move || {
        right_barrier.wait();
        framework_create_child_with_request(admin_proxy_port, &right_request)
    });
    race_barrier.wait();
    let race_results = [
        left.join().expect("left race request should return"),
        right.join().expect("right race request should return"),
    ];
    assert_eq!(
        race_results
            .iter()
            .filter(|(status, _)| *status == 200)
            .count(),
        1,
        "exactly one same-name create should succeed: {race_results:?}"
    );
    let failure_body = race_results
        .iter()
        .find_map(|(status, body)| (*status == 502).then_some(body))
        .expect("one same-name create should fail");
    assert!(
        failure_body.contains("name_conflict"),
        "same-name race should report name_conflict, got: {failure_body}"
    );

    let control_state_path = framework_control_state_path(&run);
    let race_child_id = wait_for_live_child(&control_state_path, "job-race");
    let race_snapshot = framework_snapshot_via_admin(admin_proxy_port);
    let race_component_count = race_snapshot["scenario"]["components"]
        .as_array()
        .expect("snapshot components should be an array")
        .iter()
        .filter(|component| component["moniker"].as_str() == Some("/job-race"))
        .count();
    assert_eq!(
        race_component_count, 1,
        "snapshot should contain exactly one child after the same-name race"
    );

    let distinct_barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let left_distinct_barrier = distinct_barrier.clone();
    let distinct_left = std::thread::spawn(move || {
        left_distinct_barrier.wait();
        framework_create_child_with_request(
            admin_proxy_port,
            &json!({
                "template": "worker",
                "name": "job-a",
                "config": {
                    "name": "worker-a"
                }
            }),
        )
    });
    let right_distinct_barrier = distinct_barrier.clone();
    let distinct_right = std::thread::spawn(move || {
        right_distinct_barrier.wait();
        framework_create_child_with_request(
            admin_proxy_port,
            &json!({
                "template": "worker",
                "name": "job-b",
                "config": {
                    "name": "worker-b"
                }
            }),
        )
    });
    distinct_barrier.wait();
    let distinct_results = [
        distinct_left
            .join()
            .expect("left distinct request should return"),
        distinct_right
            .join()
            .expect("right distinct request should return"),
    ];
    assert!(
        distinct_results.iter().all(|(status, _)| *status == 200),
        "distinct-name creates should both succeed: {distinct_results:?}"
    );

    let job_a_id = wait_for_live_child(&control_state_path, "job-a");
    let job_b_id = wait_for_live_child(&control_state_path, "job-b");
    assert_ne!(race_child_id, job_a_id);
    assert_ne!(race_child_id, job_b_id);
    assert_ne!(job_a_id, job_b_id);

    let job_a_artifact = framework_child_artifact(&run, "compose_local", job_a_id);
    let job_b_artifact = framework_child_artifact(&run, "compose_local", job_b_id);
    let job_a_proxy_port = pick_free_port();
    let job_b_proxy_port = pick_free_port();
    let mut job_a_proxy = spawn_proxy(&job_a_artifact, "http", job_a_proxy_port, &[]);
    let mut job_b_proxy = spawn_proxy(&job_b_artifact, "http", job_b_proxy_port, &[]);
    wait_for_path(
        &mut job_a_proxy,
        job_a_proxy_port,
        "/id",
        Duration::from_secs(60),
    );
    wait_for_path(
        &mut job_b_proxy,
        job_b_proxy_port,
        "/id",
        Duration::from_secs(60),
    );
    assert_eq!(
        wait_for_body(
            &mut job_a_proxy,
            job_a_proxy_port,
            "/id",
            Duration::from_secs(60)
        ),
        "worker-a"
    );
    assert_eq!(
        wait_for_body(
            &mut job_b_proxy,
            job_b_proxy_port,
            "/id",
            Duration::from_secs(60)
        ),
        "worker-b"
    );

    stop_proxy(&mut job_b_proxy);
    stop_proxy(&mut job_a_proxy);
    stop_proxy(&mut admin_proxy);
    run.stop();
}

#[test]
#[ignore = "run manually or in CI"]
fn framework_component_create_to_unoffered_site_fails_deterministically_live() {
    let temp = temp_output_dir("framework-component-placement-unsatisfied-");
    let direct_worker_port = pick_free_port();

    fs::write(temp.path().join("admin.py"), FRAMEWORK_ADMIN_APP).expect("failed to write admin.py");
    fs::write(temp.path().join("worker.py"), FRAMEWORK_WORKER_APP)
        .expect("failed to write worker.py");
    write_framework_admin_component(temp.path(), "admin.json5", true, 8080);
    write_framework_worker_component(
        temp.path(),
        "compose-worker.json5",
        true,
        "compose-worker",
        8080,
    );
    write_framework_worker_component(
        temp.path(),
        "direct-worker.json5",
        false,
        "direct-worker",
        direct_worker_port,
    );

    let compose_manifest =
        framework_manifest_catalog_key(&temp.path().join("compose-worker.json5"));
    let direct_manifest = framework_manifest_catalog_key(&temp.path().join("direct-worker.json5"));

    let manifest = temp.path().join("root.json5");
    write_json(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "slots": {
                "realm": { "kind": "component", "optional": true }
            },
            "components": {
                "admin": "./admin.json5"
            },
            "child_templates": {
                "worker": {
                    "allowed_manifests": [
                        compose_manifest,
                        direct_manifest
                    ]
                }
            },
            "bindings": [
                { "to": "#admin.ctl", "from": "framework.component" }
            ],
            "exports": {
                "admin_http": "#admin.http"
            }
        }),
    );
    let placement = temp.path().join("placement.json5");
    write_json(
        &placement,
        &json!({
            "schema": "amber.run.placement",
            "version": 1,
            "sites": {
                "compose_local": { "kind": "compose" }
            },
            "defaults": {
                "image": "compose_local"
            }
        }),
    );

    let storage_root = temp.path().join("state");
    let output = amber_command()
        .arg("run")
        .arg(&manifest)
        .arg("--placement")
        .arg(&placement)
        .arg("--storage-root")
        .arg(&storage_root)
        .output()
        .expect("failed to run amber");
    assert!(
        !output.status.success(),
        "run should fail deterministically when an open template allows a manifest that requires \
         an unoffered site\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("program.path")
            || stderr.contains("placement_unsatisfied")
            || stderr.contains("direct_local"),
        "failure should be operator-actionable, got stderr:\n{stderr}"
    );

    let runs_dir = storage_root.join("runs");
    assert!(
        !runs_dir.exists()
            || fs::read_dir(&runs_dir)
                .expect("runs dir should be readable")
                .next()
                .is_none(),
        "deterministic placement failure must not leave partial run artifacts under {}",
        runs_dir.display()
    );
}

#[test]
#[ignore = "requires docker; run manually or in CI"]
fn framework_component_root_external_binding_live() {
    ensure_internal_images();
    let temp = temp_output_dir("framework-component-root-external-");
    let catalog = HostHttpServer::start();
    let catalog_url = docker_host_http_url(catalog.port())
        .trim_end_matches('/')
        .to_string();
    let admin_port = pick_free_port();
    let worker_port = pick_free_port();
    let nested_admin_port = pick_free_port();

    fs::write(temp.path().join("admin.py"), FRAMEWORK_ADMIN_APP).expect("failed to write admin.py");
    fs::write(
        temp.path().join("external_bind.py"),
        FRAMEWORK_EXTERNAL_BIND_APP,
    )
    .expect("failed to write external_bind.py");
    write_framework_admin_component(temp.path(), "root-admin.json5", true, admin_port);
    write_framework_admin_component(temp.path(), "nested-admin.json5", true, nested_admin_port);
    write_json(
        &temp.path().join("external-worker.json5"),
        &json!({
            "manifest_version": "0.3.0",
            "slots": {
                "catalog_api": { "kind": "http" }
            },
            "program": {
                "image": TEST_APP_IMAGE,
                "entrypoint": ["python3", "-u", "-c", { "file": "./external_bind.py" }],
                "env": {
                    "NAME": "external-worker",
                    "PORT": worker_port.to_string(),
                    "UPSTREAM_URL": "${slots.catalog_api.url}"
                },
                "network": {
                    "endpoints": [
                        { "name": "http", "port": worker_port, "protocol": "http" }
                    ]
                }
            },
            "provides": {
                "http": { "kind": "http", "endpoint": "http" }
            },
            "exports": {
                "http": "http"
            }
        }),
    );
    write_json(
        &temp.path().join("parent.json5"),
        &json!({
            "manifest_version": "0.3.0",
            "slots": {
                "realm": { "kind": "component", "optional": true }
            },
            "components": {
                "admin": "./nested-admin.json5"
            },
            "child_templates": {
                "worker": {
                    "manifest": "./external-worker.json5"
                }
            },
            "bindings": [
                { "to": "#admin.ctl", "from": "framework.component" }
            ],
            "exports": {
                "http": "#admin.http"
            }
        }),
    );

    let manifest = temp.path().join("root.json5");
    write_json(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "slots": {
                "realm": { "kind": "component", "optional": true },
                "catalog_api": { "kind": "http" }
            },
            "program": {
                "image": TEST_APP_IMAGE,
                "entrypoint": ["sleep", "3600"]
            },
            "components": {
                "admin": "./root-admin.json5",
                "parent": "./parent.json5"
            },
            "child_templates": {
                "worker": {
                    "manifest": "./external-worker.json5"
                }
            },
            "bindings": [
                { "to": "#admin.ctl", "from": "framework.component" }
            ],
            "exports": {
                "admin_http": "#admin.http",
                "parent_http": "#parent.http"
            }
        }),
    );
    let placement = temp.path().join("placement.json5");
    write_json(
        &placement,
        &json!({
            "schema": "amber.run.placement",
            "version": 1,
            "sites": {
                "compose_local": { "kind": "compose" }
            },
            "defaults": {
                "image": "compose_local"
            }
        }),
    );

    let storage_root = temp.path().join("state");
    let mut run = run_manifest_with_env(
        &manifest,
        &placement,
        &storage_root,
        &[("AMBER_EXTERNAL_SLOT_CATALOG_API_URL", catalog_url.as_str())],
    );

    wait_for_state_status(
        &run.run_root,
        "compose_local",
        "running",
        Duration::from_secs(60),
    );

    let root_proxy_port = pick_free_port();
    let mut root_proxy = spawn_proxy(
        &run.site_artifact_dir("compose_local"),
        "admin_http",
        root_proxy_port,
        &[],
    );
    wait_for_path(
        &mut root_proxy,
        root_proxy_port,
        "/id",
        Duration::from_secs(60),
    );
    assert_eq!(
        wait_for_body(
            &mut root_proxy,
            root_proxy_port,
            "/id",
            Duration::from_secs(60)
        ),
        "admin"
    );

    let (create_status, create_response) = framework_create_child_with_request(
        root_proxy_port,
        &json!({
            "template": "worker",
            "name": "job-root-external",
            "bindings": {
                "catalog_api": {
                    "selector": "external.catalog_api"
                }
            }
        }),
    );
    assert_eq!(
        create_status, 200,
        "root realm should be able to bind from external.catalog_api; response: {create_response}"
    );
    let child_id = wait_for_live_child(&framework_control_state_path(&run), "job-root-external");
    let child_artifact = framework_child_artifact(&run, "compose_local", child_id);
    let child_proxy_port = pick_free_port();
    let mut child_proxy = spawn_proxy(&child_artifact, "http", child_proxy_port, &[]);
    wait_for_path(
        &mut child_proxy,
        child_proxy_port,
        "/id",
        Duration::from_secs(60),
    );
    assert_eq!(
        wait_for_body(
            &mut child_proxy,
            child_proxy_port,
            "/probe",
            Duration::from_secs(60)
        ),
        r#"{"source":"external","item":"amber mug"}"#,
        "dynamic child should consume the real external capability from the root realm"
    );

    let parent_proxy_port = pick_free_port();
    let mut parent_proxy = spawn_proxy(
        &run.site_artifact_dir("compose_local"),
        "parent_http",
        parent_proxy_port,
        &[],
    );
    wait_for_path(
        &mut parent_proxy,
        parent_proxy_port,
        "/id",
        Duration::from_secs(60),
    );
    assert_eq!(
        wait_for_body(
            &mut parent_proxy,
            parent_proxy_port,
            "/id",
            Duration::from_secs(60)
        ),
        "admin"
    );

    let (forbidden_status, forbidden_response) = framework_create_child_with_request(
        parent_proxy_port,
        &json!({
            "template": "worker",
            "name": "job-parent-external",
            "bindings": {
                "catalog_api": {
                    "selector": "external.catalog_api"
                }
            }
        }),
    );
    assert_eq!(
        forbidden_status, 502,
        "non-root realms should not bind external.catalog_api directly"
    );
    assert!(
        forbidden_response.contains("external.catalog_api")
            && forbidden_response.contains("not present in the authority realm"),
        "non-root external bind failure should explain the realm boundary, got: \
         {forbidden_response}"
    );

    stop_proxy(&mut parent_proxy);
    stop_proxy(&mut child_proxy);
    stop_proxy(&mut root_proxy);
    run.stop();
}

#[test]
#[ignore = "requires docker; run manually or in CI"]
fn framework_component_nonweak_publication_barrier_live() {
    ensure_internal_images();
    let temp = temp_output_dir("framework-component-publication-barrier-");
    let admin_port = pick_free_port();
    let required_port = pick_free_port();
    let consumer_port = pick_free_port();
    let delayed_port = pick_free_port();
    let delayed_url = docker_host_http_url(delayed_port)
        .trim_end_matches('/')
        .to_string();

    fs::write(temp.path().join("admin.py"), FRAMEWORK_ADMIN_APP).expect("failed to write admin.py");
    fs::write(temp.path().join("worker.py"), FRAMEWORK_WORKER_APP)
        .expect("failed to write worker.py");
    fs::write(
        temp.path().join("barrier_probe.py"),
        FRAMEWORK_BARRIER_PROBE_APP,
    )
    .expect("failed to write barrier_probe.py");
    write_framework_admin_component(temp.path(), "admin.json5", true, admin_port);
    write_framework_worker_component(
        temp.path(),
        "required-worker.json5",
        true,
        "required-upstream",
        required_port,
    );
    write_json(
        &temp.path().join("consumer.json5"),
        &json!({
            "manifest_version": "0.3.0",
            "slots": {
                "required_api": { "kind": "http" },
                "weak_api": { "kind": "http" }
            },
            "program": {
                "image": TEST_APP_IMAGE,
                "entrypoint": ["python3", "-u", "-c", { "file": "./barrier_probe.py" }],
                "env": {
                    "NAME": "consumer",
                    "PORT": consumer_port.to_string(),
                    "REQUIRED_URL": "${slots.required_api.url}",
                    "WEAK_URL": "${slots.weak_api.url}"
                },
                "network": {
                    "endpoints": [
                        { "name": "http", "port": consumer_port, "protocol": "http" }
                    ]
                }
            },
            "provides": {
                "http": { "kind": "http", "endpoint": "http" }
            },
            "exports": {
                "http": "http"
            }
        }),
    );
    let manifest = temp.path().join("root.json5");
    write_json(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "slots": {
                "realm": { "kind": "component", "optional": true },
                "delayed_api": { "kind": "http" }
            },
            "program": {
                "image": TEST_APP_IMAGE,
                "entrypoint": ["sleep", "3600"]
            },
            "components": {
                "admin": "./admin.json5"
            },
            "child_templates": {
                "required": {
                    "manifest": "./required-worker.json5"
                },
                "consumer": {
                    "manifest": "./consumer.json5"
                }
            },
            "bindings": [
                { "to": "#admin.ctl", "from": "framework.component" }
            ],
            "exports": {
                "admin_http": "#admin.http"
            }
        }),
    );
    let placement = temp.path().join("placement.json5");
    write_json(
        &placement,
        &json!({
            "schema": "amber.run.placement",
            "version": 1,
            "sites": {
                "compose_local": { "kind": "compose" }
            },
            "defaults": {
                "image": "compose_local"
            }
        }),
    );

    let storage_root = temp.path().join("state");
    let mut run = run_manifest_with_env(
        &manifest,
        &placement,
        &storage_root,
        &[("AMBER_EXTERNAL_SLOT_DELAYED_API_URL", delayed_url.as_str())],
    );
    wait_for_state_status(
        &run.run_root,
        "compose_local",
        "running",
        Duration::from_secs(60),
    );

    let admin_proxy_port = pick_free_port();
    let mut admin_proxy = spawn_proxy(
        &run.site_artifact_dir("compose_local"),
        "admin_http",
        admin_proxy_port,
        &[],
    );
    wait_for_path(
        &mut admin_proxy,
        admin_proxy_port,
        "/id",
        Duration::from_secs(60),
    );

    let (required_status, required_response) = framework_create_child_with_request(
        admin_proxy_port,
        &json!({
            "template": "required",
            "name": "required"
        }),
    );
    assert_eq!(
        required_status, 200,
        "required provider create should succeed; response: {required_response}"
    );

    let control_state_path = framework_control_state_path(&run);
    wait_for_live_child(&control_state_path, "required");

    let (consumer_status, consumer_response) = framework_create_child_with_request(
        admin_proxy_port,
        &json!({
            "template": "consumer",
            "name": "consumer",
            "bindings": {
                "required_api": {
                    "selector": "children.required.exports.http"
                },
                "weak_api": {
                    "selector": "external.delayed_api"
                }
            }
        }),
    );
    assert_eq!(
        consumer_status, 200,
        "consumer create should succeed without waiting on the weak binding; response: \
         {consumer_response}"
    );

    let consumer_id = wait_for_live_child(&control_state_path, "consumer");
    let consumer_artifact = framework_child_artifact(&run, "compose_local", consumer_id);
    let consumer_proxy_port = pick_free_port();
    let mut consumer_proxy = spawn_proxy(&consumer_artifact, "http", consumer_proxy_port, &[]);
    wait_for_path(
        &mut consumer_proxy,
        consumer_proxy_port,
        "/startup",
        Duration::from_secs(60),
    );
    let startup: Value = serde_json::from_str(&wait_for_body(
        &mut consumer_proxy,
        consumer_proxy_port,
        "/startup",
        Duration::from_secs(60),
    ))
    .expect("startup payload should be valid json");
    assert_eq!(
        startup["required"]["ok"],
        json!(true),
        "required nonweak binding must be usable when the child first becomes live: {startup}"
    );
    assert_eq!(
        startup["required"]["body"],
        json!("required-upstream"),
        "required startup probe should hit the required upstream: {startup}"
    );
    assert_eq!(
        startup["weak"]["ok"],
        json!(false),
        "weak binding may still be absent during startup, but it must not block child liveness: \
         {startup}"
    );
    assert!(
        startup["weak"]["error"]
            .as_str()
            .is_some_and(|error| !error.is_empty()),
        "weak startup probe should record its failure mode: {startup}"
    );

    stop_proxy(&mut consumer_proxy);
    stop_proxy(&mut admin_proxy);
    run.stop();
}

#[test]
#[ignore = "requires docker + a working direct runtime sandbox; run manually or in CI"]
fn framework_component_delegated_realm_cross_site_live() {
    ensure_internal_images();
    let temp = temp_output_dir("framework-component-delegated-realm-");
    let delegate_port = pick_free_port();
    let intruder_port = pick_free_port();

    fs::write(temp.path().join("admin.py"), FRAMEWORK_ADMIN_APP).expect("failed to write admin.py");
    fs::write(temp.path().join("app.py"), FRAMEWORK_MATRIX_APP).expect("failed to write app.py");
    write_framework_admin_component(temp.path(), "delegate-admin.json5", false, delegate_port);
    write_framework_admin_component(temp.path(), "intruder-admin.json5", false, intruder_port);
    write_image_component(temp.path(), "provider.json5", "provider", 8080, &[], &[]);
    write_image_component(
        temp.path(),
        "root-worker.json5",
        "root-worker",
        8080,
        &[("upstream", "${slots.upstream.url}")],
        &[],
    );
    write_image_component(
        temp.path(),
        "local-worker.json5",
        "local-worker",
        8080,
        &[("upstream", "${slots.upstream.url}")],
        &[],
    );
    write_json(
        &temp.path().join("parent.json5"),
        &json!({
            "manifest_version": "0.3.0",
            "slots": {
                "realm": { "kind": "component", "optional": true }
            },
            "components": {
                "delegate": "./delegate-admin.json5",
                "intruder": "./intruder-admin.json5"
            },
            "child_templates": {
                "worker": {
                    "manifest": "./local-worker.json5"
                }
            },
            "bindings": [
                { "to": "#delegate.ctl", "from": "slots.realm" },
                { "to": "#intruder.ctl", "from": "framework.component" }
            ],
            "exports": {
                "delegate_http": "#delegate.http",
                "intruder_http": "#intruder.http"
            }
        }),
    );

    let manifest = temp.path().join("root.json5");
    write_json(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "slots": {
                "realm": { "kind": "component", "optional": true }
            },
            "components": {
                "parent": "./parent.json5",
                "provider": "./provider.json5"
            },
            "child_templates": {
                "root_worker": {
                    "manifest": "./root-worker.json5"
                }
            },
            "bindings": [
                { "to": "#parent.realm", "from": "framework.component" }
            ],
            "exports": {
                "delegate_http": "#parent.delegate_http",
                "intruder_http": "#parent.intruder_http",
                "provider_http": "#provider.http"
            }
        }),
    );
    let placement = temp.path().join("placement.json5");
    write_json(
        &placement,
        &json!({
            "schema": "amber.run.placement",
            "version": 1,
            "sites": {
                "compose_local": { "kind": "compose" },
                "direct_local": { "kind": "direct" }
            },
            "defaults": {
                "image": "compose_local",
                "path": "direct_local"
            },
            "components": {
                "/parent": "compose_local",
                "/parent/delegate": "direct_local",
                "/parent/intruder": "direct_local",
                "/provider": "compose_local"
            }
        }),
    );

    let storage_root = temp.path().join("state");
    let mut run = run_manifest(&manifest, &placement, &storage_root);

    wait_for_state_status(
        &run.run_root,
        "compose_local",
        "running",
        Duration::from_secs(60),
    );
    wait_for_state_status(
        &run.run_root,
        "direct_local",
        "running",
        Duration::from_secs(60),
    );

    let delegate_proxy_port = pick_free_port();
    let mut delegate_proxy = spawn_proxy(
        &run.site_artifact_dir("direct_local"),
        "delegate_http",
        delegate_proxy_port,
        &[],
    );
    wait_for_path(
        &mut delegate_proxy,
        delegate_proxy_port,
        "/id",
        Duration::from_secs(60),
    );

    let intruder_proxy_port = pick_free_port();
    let mut intruder_proxy = spawn_proxy(
        &run.site_artifact_dir("direct_local"),
        "intruder_http",
        intruder_proxy_port,
        &[],
    );
    wait_for_path(
        &mut intruder_proxy,
        intruder_proxy_port,
        "/id",
        Duration::from_secs(60),
    );

    let (delegate_status, delegate_response) = framework_create_child_with_request(
        delegate_proxy_port,
        &json!({
            "template": "root_worker",
            "name": "sibling",
            "bindings": {
                "upstream": {
                    "selector": "children.provider.exports.http"
                }
            }
        }),
    );
    assert_eq!(
        delegate_status, 200,
        "delegated authority should create in the forwarded realm; response: {delegate_response}"
    );
    let delegate_json: Value =
        serde_json::from_str(&delegate_response).expect("delegate create response should be valid");
    assert_eq!(
        delegate_json["child"]["selector"].as_str(),
        Some("children.sibling"),
        "child selector should reflect the authority realm, not the transport caller"
    );

    let control_state_path = framework_control_state_path(&run);
    let sibling_id = wait_for_live_child(&control_state_path, "sibling");
    let sibling_artifact = framework_child_artifact(&run, "compose_local", sibling_id);
    let sibling_proxy_port = pick_free_port();
    let mut sibling_proxy = spawn_proxy(&sibling_artifact, "http", sibling_proxy_port, &[]);
    wait_for_path(
        &mut sibling_proxy,
        sibling_proxy_port,
        "/id",
        Duration::from_secs(60),
    );
    assert_eq!(
        wait_for_body(
            &mut sibling_proxy,
            sibling_proxy_port,
            "/call/upstream",
            Duration::from_secs(60)
        ),
        "provider",
        "selector resolution should happen in the authority realm visible to the delegated \
         capability instance"
    );

    let (intruder_status, intruder_response) = framework_create_child_with_request(
        intruder_proxy_port,
        &json!({
            "template": "worker",
            "name": "blocked",
            "bindings": {
                "upstream": {
                    "selector": "children.provider.exports.http"
                }
            }
        }),
    );
    assert_eq!(
        intruder_status, 502,
        "an unrelated child on the same site must not act in the delegated realm"
    );
    assert!(
        intruder_response.contains("children.provider.exports.http")
            && intruder_response.contains("not present in the authority realm"),
        "intruder failure should explain that selector resolution stayed in its own realm, got: \
         {intruder_response}"
    );

    let (destroy_status, destroy_response) =
        framework_destroy_child_via_admin(delegate_proxy_port, "sibling");
    assert_eq!(
        destroy_status, 200,
        "delegated destroy should succeed; response: {destroy_response}"
    );
    wait_for_framework_child_absent(
        &control_state_path,
        "sibling",
        &[sibling_artifact
            .parent()
            .expect("sibling artifact should have a parent")
            .to_path_buf()],
        Duration::from_secs(60),
    );

    stop_proxy(&mut sibling_proxy);
    stop_proxy(&mut intruder_proxy);
    stop_proxy(&mut delegate_proxy);
    run.stop();
}

#[test]
#[ignore = "requires docker and a working direct runtime sandbox; run manually or in CI"]
fn framework_component_compose_parent_standby_direct_live() {
    ensure_internal_images();
    let temp = temp_output_dir("framework-component-standby-direct-");
    let admin_port = pick_free_port();
    let worker_port = pick_free_port();

    fs::write(temp.path().join("admin.py"), FRAMEWORK_ADMIN_APP).expect("failed to write admin.py");
    fs::write(temp.path().join("worker.py"), FRAMEWORK_WORKER_APP)
        .expect("failed to write worker.py");
    write_framework_admin_component(temp.path(), "admin.json5", true, admin_port);
    write_framework_worker_component(temp.path(), "worker.json5", false, "worker", worker_port);

    let manifest = temp.path().join("root.json5");
    write_json(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "slots": {
                "realm": { "kind": "component", "optional": true }
            },
            "components": {
                "admin": "./admin.json5"
            },
            "child_templates": {
                "worker": {
                    "manifest": "./worker.json5"
                }
            },
            "bindings": [
                { "to": "#admin.ctl", "from": "framework.component" }
            ],
            "exports": {
                "admin_http": "#admin.http"
            }
        }),
    );
    let placement = temp.path().join("placement.json5");
    write_json(
        &placement,
        &json!({
            "schema": "amber.run.placement",
            "version": 1,
            "sites": {
                "direct_local": { "kind": "direct" },
                "compose_local": { "kind": "compose" }
            },
            "defaults": {
                "path": "direct_local",
                "image": "compose_local"
            },
            "components": {
                "/admin": "compose_local"
            }
        }),
    );

    let storage_root = temp.path().join("state");
    let mut run = run_manifest(&manifest, &placement, &storage_root);

    let run_plan: Value = serde_json::from_slice(
        &fs::read(run.run_root.join("run-plan.json")).expect("failed to read run-plan.json"),
    )
    .expect("run-plan.json should be valid JSON");
    assert_eq!(
        run_plan["standby_sites"],
        json!(["direct_local"]),
        "direct should be activated as a standby site for the dynamic path template"
    );
    assert_string_array_members(
        &run_plan["initial_active_sites"],
        &["compose_local", "direct_local"],
        "the standby direct site should be active from run start",
    );
    let _compose_state = wait_for_state_status(
        &run.run_root,
        "compose_local",
        "running",
        Duration::from_secs(60),
    );
    let _direct_state = wait_for_state_status(
        &run.run_root,
        "direct_local",
        "running",
        Duration::from_secs(60),
    );

    let proxy_port = pick_free_port();
    let mut admin_proxy = spawn_proxy(
        &run.site_artifact_dir("compose_local"),
        "admin_http",
        proxy_port,
        &[],
    );
    wait_for_path(&mut admin_proxy, proxy_port, "/id", Duration::from_secs(60));
    assert_eq!(
        wait_for_body(&mut admin_proxy, proxy_port, "/id", Duration::from_secs(60)),
        "admin"
    );

    let (create_status, create_response) = http_get_with_timeout(
        proxy_port,
        "/create/worker/job-1",
        FRAMEWORK_MUTATION_REQUEST_TIMEOUT,
    )
    .expect("create request should return an HTTP response");
    assert_eq!(create_status, 200, "create request should succeed");
    let create_json: Value =
        serde_json::from_str(&create_response).expect("create response should be valid json");
    assert_eq!(create_json["child"]["name"], "job-1");

    let control_state_path = framework_control_state_path(&run);
    let child_id = wait_for_live_child(&control_state_path, "job-1");
    let child_artifact = framework_child_artifact(&run, "direct_local", child_id);
    wait_for_file(
        &child_artifact.join(".amber").join("direct-runtime.json"),
        Duration::from_secs(60),
    );

    let child_proxy_port = pick_free_port();
    let mut child_proxy = spawn_proxy(&child_artifact, "http", child_proxy_port, &[]);
    wait_for_path(
        &mut child_proxy,
        child_proxy_port,
        "/id",
        Duration::from_secs(60),
    );
    assert_eq!(
        wait_for_body(
            &mut child_proxy,
            child_proxy_port,
            "/id",
            Duration::from_secs(60)
        ),
        "worker"
    );

    stop_proxy(&mut child_proxy);
    stop_proxy(&mut admin_proxy);
    run.stop();
}

#[test]
#[ignore = "requires docker + a working direct runtime sandbox; run manually or in CI"]
fn framework_component_direct_parent_compose_child_live() {
    ensure_internal_images();
    let temp = temp_output_dir("framework-component-direct-compose-");
    let admin_port = pick_free_port();

    fs::write(temp.path().join("admin.py"), FRAMEWORK_ADMIN_APP).expect("failed to write admin.py");
    fs::write(temp.path().join("worker.py"), FRAMEWORK_WORKER_APP)
        .expect("failed to write worker.py");
    write_framework_admin_component(temp.path(), "admin.json5", false, admin_port);
    write_framework_worker_component(temp.path(), "worker.json5", true, "worker", 8080);

    let manifest = temp.path().join("root.json5");
    write_json(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "slots": {
                "realm": { "kind": "component", "optional": true }
            },
            "components": {
                "admin": "./admin.json5"
            },
            "child_templates": {
                "worker": {
                    "manifest": "./worker.json5"
                }
            },
            "bindings": [
                { "to": "#admin.ctl", "from": "framework.component" }
            ],
            "exports": {
                "admin_http": "#admin.http"
            }
        }),
    );
    let placement = temp.path().join("placement.json5");
    write_json(
        &placement,
        &json!({
            "schema": "amber.run.placement",
            "version": 1,
            "sites": {
                "direct_local": { "kind": "direct" },
                "compose_local": { "kind": "compose" }
            },
            "defaults": {
                "path": "direct_local",
                "image": "compose_local"
            }
        }),
    );

    let storage_root = temp.path().join("state");
    let mut run = run_manifest(&manifest, &placement, &storage_root);

    let run_plan: Value = serde_json::from_slice(
        &fs::read(run.run_root.join("run-plan.json")).expect("failed to read run-plan.json"),
    )
    .expect("run-plan.json should be valid JSON");
    assert_eq!(
        run_plan["standby_sites"],
        json!(["compose_local"]),
        "compose should stay active as a standby site for the dynamic image template"
    );
    assert_string_array_members(
        &run_plan["initial_active_sites"],
        &["direct_local", "compose_local"],
        "the compose standby site should be active from run start",
    );
    let _direct_state = wait_for_state_status(
        &run.run_root,
        "direct_local",
        "running",
        Duration::from_secs(60),
    );
    let _compose_state = wait_for_state_status(
        &run.run_root,
        "compose_local",
        "running",
        Duration::from_secs(60),
    );

    let proxy_port = pick_free_port();
    let mut admin_proxy = spawn_proxy(
        &run.site_artifact_dir("direct_local"),
        "admin_http",
        proxy_port,
        &[],
    );
    wait_for_path(&mut admin_proxy, proxy_port, "/id", Duration::from_secs(60));
    assert_eq!(
        wait_for_body(&mut admin_proxy, proxy_port, "/id", Duration::from_secs(60)),
        "admin"
    );

    let (create_status, create_response) = http_get_with_timeout(
        proxy_port,
        "/create/job-1",
        FRAMEWORK_MUTATION_REQUEST_TIMEOUT,
    )
    .expect("create request should return an HTTP response");
    assert_eq!(create_status, 200, "create request should succeed");
    let create_json: Value =
        serde_json::from_str(&create_response).expect("create response should be valid json");
    assert_eq!(create_json["child"]["name"], "job-1");

    let control_state_path = framework_control_state_path(&run);
    let child_id = wait_for_live_child(&control_state_path, "job-1");
    let child_artifact = framework_child_artifact(&run, "compose_local", child_id);

    let child_proxy_port = pick_free_port();
    let mut child_proxy = spawn_proxy(&child_artifact, "http", child_proxy_port, &[]);
    wait_for_path(
        &mut child_proxy,
        child_proxy_port,
        "/id",
        Duration::from_secs(60),
    );
    assert_eq!(
        wait_for_body(
            &mut child_proxy,
            child_proxy_port,
            "/id",
            Duration::from_secs(60)
        ),
        "worker"
    );

    stop_proxy(&mut child_proxy);
    stop_proxy(&mut admin_proxy);
    run.stop();
}

#[test]
#[ignore = "requires docker + a working direct runtime sandbox; run manually or in CI"]
fn framework_component_dynamic_children_teardown_with_run_live() {
    ensure_internal_images();
    let temp = temp_output_dir("framework-component-run-stop-");
    let admin_port = pick_free_port();
    let direct_worker_port = pick_free_port();

    fs::write(temp.path().join("admin.py"), FRAMEWORK_ADMIN_APP).expect("failed to write admin.py");
    fs::write(temp.path().join("worker.py"), FRAMEWORK_WORKER_APP)
        .expect("failed to write worker.py");
    write_framework_admin_component(temp.path(), "admin.json5", false, admin_port);
    write_framework_worker_component(
        temp.path(),
        "worker-direct.json5",
        false,
        "worker-direct",
        direct_worker_port,
    );
    write_framework_worker_component(
        temp.path(),
        "worker-compose.json5",
        true,
        "worker-compose",
        8080,
    );

    let manifest = temp.path().join("root.json5");
    write_json(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "slots": {
                "realm": { "kind": "component", "optional": true }
            },
            "components": {
                "admin": "./admin.json5"
            },
            "child_templates": {
                "worker_direct": {
                    "manifest": "./worker-direct.json5"
                },
                "worker_compose": {
                    "manifest": "./worker-compose.json5"
                }
            },
            "bindings": [
                { "to": "#admin.ctl", "from": "framework.component" }
            ],
            "exports": {
                "admin_http": "#admin.http"
            }
        }),
    );
    let placement = temp.path().join("placement.json5");
    write_json(
        &placement,
        &json!({
            "schema": "amber.run.placement",
            "version": 1,
            "sites": {
                "direct_local": { "kind": "direct" },
                "compose_local": { "kind": "compose" }
            },
            "defaults": {
                "path": "direct_local",
                "image": "compose_local"
            }
        }),
    );

    let storage_root = temp.path().join("state");
    let mut run = run_manifest(&manifest, &placement, &storage_root);

    let direct_state = wait_for_state_status(
        &run.run_root,
        "direct_local",
        "running",
        Duration::from_secs(60),
    );
    let compose_state = wait_for_state_status(
        &run.run_root,
        "compose_local",
        "running",
        Duration::from_secs(60),
    );

    let proxy_port = pick_free_port();
    let mut admin_proxy = spawn_proxy(
        &run.site_artifact_dir("direct_local"),
        "admin_http",
        proxy_port,
        &[],
    );
    wait_for_path(&mut admin_proxy, proxy_port, "/id", Duration::from_secs(60));

    let (create_direct_status, create_direct_response) = http_get_with_timeout(
        proxy_port,
        "/create/worker_direct/job-direct",
        FRAMEWORK_MUTATION_REQUEST_TIMEOUT,
    )
    .expect("direct create request should return an HTTP response");
    assert_eq!(
        create_direct_status, 200,
        "direct child create request should succeed"
    );
    let create_direct_json: Value = serde_json::from_str(&create_direct_response)
        .expect("direct child create response should be valid json");
    assert_eq!(create_direct_json["child"]["name"], "job-direct");

    let (create_compose_status, create_compose_response) = http_get_with_timeout(
        proxy_port,
        "/create/worker_compose/job-compose",
        FRAMEWORK_MUTATION_REQUEST_TIMEOUT,
    )
    .expect("compose create request should return an HTTP response");
    assert_eq!(
        create_compose_status, 200,
        "compose child create request should succeed"
    );
    let create_compose_json: Value = serde_json::from_str(&create_compose_response)
        .expect("compose child create response should be valid json");
    assert_eq!(create_compose_json["child"]["name"], "job-compose");

    let control_state_path = framework_control_state_path(&run);
    let direct_child_id = wait_for_live_child(&control_state_path, "job-direct");
    let compose_child_id = wait_for_live_child(&control_state_path, "job-compose");

    let direct_child_artifact = framework_child_artifact(&run, "direct_local", direct_child_id);
    let compose_child_artifact = framework_child_artifact(&run, "compose_local", compose_child_id);
    let direct_child_root = direct_child_artifact
        .parent()
        .expect("direct child artifact should have a parent")
        .to_path_buf();
    let compose_child_root = compose_child_artifact
        .parent()
        .expect("compose child artifact should have a parent")
        .to_path_buf();

    let direct_child_proxy_port = pick_free_port();
    let mut direct_child_proxy =
        spawn_proxy(&direct_child_artifact, "http", direct_child_proxy_port, &[]);
    wait_for_path(
        &mut direct_child_proxy,
        direct_child_proxy_port,
        "/id",
        Duration::from_secs(60),
    );
    assert_eq!(
        wait_for_body(
            &mut direct_child_proxy,
            direct_child_proxy_port,
            "/id",
            Duration::from_secs(60)
        ),
        "worker-direct"
    );

    let compose_child_proxy_port = pick_free_port();
    let mut compose_child_proxy = spawn_proxy(
        &compose_child_artifact,
        "http",
        compose_child_proxy_port,
        &[],
    );
    wait_for_path(
        &mut compose_child_proxy,
        compose_child_proxy_port,
        "/id",
        Duration::from_secs(60),
    );
    assert_eq!(
        wait_for_body(
            &mut compose_child_proxy,
            compose_child_proxy_port,
            "/id",
            Duration::from_secs(60)
        ),
        "worker-compose"
    );

    stop_proxy(&mut compose_child_proxy);
    stop_proxy(&mut direct_child_proxy);
    stop_proxy(&mut admin_proxy);

    let direct_pid = direct_state["process_pid"]
        .as_u64()
        .expect("direct site pid should exist") as u32;
    let compose_project = compose_state["compose_project"]
        .as_str()
        .expect("compose project should exist")
        .to_string();

    run.stop();
    wait_for_state_status(
        &run.run_root,
        "direct_local",
        "stopped",
        Duration::from_secs(60),
    );
    wait_for_state_status(
        &run.run_root,
        "compose_local",
        "stopped",
        Duration::from_secs(60),
    );
    wait_for_condition(
        Duration::from_secs(60),
        || {
            !run.run_root.join("receipt.json").exists()
                && compose_ps_ids(&compose_project, &run.site_artifact_dir("compose_local"))
                    .is_empty()
                && !pid_is_alive(direct_pid)
                && !direct_child_root.exists()
                && !compose_child_root.exists()
        },
        "dynamic child teardown when the whole scenario stops",
    );
}

#[test]
#[ignore = "requires a working direct runtime sandbox; run manually or in CI"]
fn framework_component_destroy_of_provider_keeps_consumer_live() {
    let temp = temp_output_dir("framework-component-destroy-provider-");
    let admin_port = pick_free_port();
    let provider_port = pick_free_port();
    let consumer_port = pick_free_port();

    fs::write(temp.path().join("admin.py"), FRAMEWORK_ADMIN_APP).expect("failed to write admin.py");
    fs::write(temp.path().join("app.py"), FRAMEWORK_MATRIX_APP).expect("failed to write app.py");
    fs::write(temp.path().join("worker.py"), FRAMEWORK_WORKER_APP)
        .expect("failed to write worker.py");
    write_framework_admin_component(temp.path(), "admin.json5", false, admin_port);
    write_framework_worker_component(
        temp.path(),
        "producer.json5",
        false,
        "provider",
        provider_port,
    );
    write_path_component(
        temp.path(),
        "consumer.json5",
        "consumer",
        consumer_port,
        &[("upstream", "${slots.upstream.url}")],
        &[],
    );

    let manifest = temp.path().join("root.json5");
    write_json(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "slots": {
                "realm": { "kind": "component", "optional": true }
            },
            "components": {
                "admin": "./admin.json5"
            },
            "child_templates": {
                "producer": { "manifest": "./producer.json5" },
                "consumer": { "manifest": "./consumer.json5" }
            },
            "bindings": [
                { "to": "#admin.ctl", "from": "framework.component" }
            ],
            "exports": {
                "admin_http": "#admin.http"
            }
        }),
    );
    let placement = temp.path().join("placement.json5");
    write_json(
        &placement,
        &json!({
            "schema": "amber.run.placement",
            "version": 1,
            "sites": {
                "direct_local": { "kind": "direct" }
            },
            "defaults": {
                "path": "direct_local"
            }
        }),
    );

    let storage_root = temp.path().join("state");
    let mut run = run_manifest(&manifest, &placement, &storage_root);

    let proxy_port = pick_free_port();
    let mut admin_proxy = spawn_proxy(
        &run.site_artifact_dir("direct_local"),
        "admin_http",
        proxy_port,
        &[],
    );
    wait_for_path(&mut admin_proxy, proxy_port, "/id", Duration::from_secs(60));

    let (create_provider_status, create_provider_response) = http_get_with_timeout(
        proxy_port,
        "/create/producer/source",
        FRAMEWORK_MUTATION_REQUEST_TIMEOUT,
    )
    .expect("producer create request should return an HTTP response");
    assert_eq!(
        create_provider_status, 200,
        "producer create request should succeed"
    );
    let create_provider_json: Value = serde_json::from_str(&create_provider_response)
        .expect("producer create response should be valid json");
    assert_eq!(create_provider_json["child"]["name"], "source");

    let control_state_path = framework_control_state_path(&run);
    let source_id = wait_for_live_child(&control_state_path, "source");
    let source_root = framework_child_artifact(&run, "direct_local", source_id)
        .parent()
        .expect("source artifact should have a parent")
        .to_path_buf();

    let (create_consumer_status, create_consumer_response) = framework_create_child_with_request(
        proxy_port,
        &json!({
            "template": "consumer",
            "name": "sink",
            "bindings": {
                "upstream": {
                    "selector": "children.source.exports.http"
                }
            }
        }),
    );
    assert_eq!(
        create_consumer_status, 200,
        "consumer create request should succeed; response: {create_consumer_response}"
    );
    let create_consumer_json: Value = serde_json::from_str(&create_consumer_response)
        .expect("consumer create response should be valid json");
    assert_eq!(create_consumer_json["child"]["name"], "sink");

    let sink_id = wait_for_live_child(&control_state_path, "sink");
    let sink_artifact = framework_child_artifact(&run, "direct_local", sink_id);

    let sink_proxy_port = pick_free_port();
    let mut sink_proxy = spawn_proxy(&sink_artifact, "http", sink_proxy_port, &[]);
    wait_for_path(
        &mut sink_proxy,
        sink_proxy_port,
        "/id",
        Duration::from_secs(60),
    );
    assert_eq!(
        wait_for_body(
            &mut sink_proxy,
            sink_proxy_port,
            "/id",
            Duration::from_secs(60)
        ),
        "consumer"
    );
    assert_eq!(
        wait_for_body(
            &mut sink_proxy,
            sink_proxy_port,
            "/call/upstream",
            Duration::from_secs(60)
        ),
        "provider",
        "consumer should initially resolve the provider binding"
    );

    let (destroy_status, destroy_response) =
        framework_destroy_child_via_admin(proxy_port, "source");
    assert_eq!(
        destroy_status, 200,
        "provider destroy request should succeed; response: {destroy_response}"
    );

    wait_for_condition(
        Duration::from_secs(60),
        || {
            !source_root.exists()
                && read_json(&control_state_path)["live_children"]
                    .as_array()
                    .is_some_and(|children| children.iter().all(|child| child["name"] != "source"))
        },
        "provider child removal after destroy",
    );

    assert_eq!(
        wait_for_body(
            &mut sink_proxy,
            sink_proxy_port,
            "/id",
            Duration::from_secs(60)
        ),
        "consumer",
        "consumer should remain alive after destroying the provider"
    );
    wait_for_condition(
        Duration::from_secs(60),
        || match http_get_with_timeout(sink_proxy_port, "/call/upstream", Duration::from_secs(5)) {
            Some((status, body)) => status != 200 || body != "provider",
            None => true,
        },
        "consumer upstream route removal after provider destroy",
    );

    stop_proxy(&mut sink_proxy);
    stop_proxy(&mut admin_proxy);
    run.stop();
}

#[test]
#[ignore = "requires docker + kind + kubectl + qemu + an Ubuntu 24.04 cloud image matching the \
            host architecture; run manually or in CI"]
fn framework_component_kind_root_export_live() {
    ensure_internal_images();
    let temp = temp_output_dir("framework-component-kind-root-");
    let kubeconfig = temp.path().join("kubeconfig");
    let kind_cluster = KindCluster::from_env_or_create(&kubeconfig);
    ensure_kind_internal_images(&kind_cluster);
    let kubeconfig_env = kind_cluster.kubeconfig.display().to_string();

    let fixture = write_framework_matrix_fixture(temp.path(), &kind_cluster);
    let storage_root = temp.path().join("state");
    let mut run = run_manifest_with_env(
        &fixture.manifest,
        &fixture.placement,
        &storage_root,
        &[("KUBECONFIG", &kubeconfig_env)],
    );

    let compose_state = wait_for_state_status(
        &run.run_root,
        "compose_local",
        "running",
        Duration::from_secs(60),
    );
    let kind_state = wait_for_state_status(
        &run.run_root,
        "kind_local",
        "running",
        Duration::from_secs(120),
    );
    let direct_state = wait_for_state_status(
        &run.run_root,
        "direct_local",
        "running",
        Duration::from_secs(60),
    );
    let vm_state = wait_for_state_status(
        &run.run_root,
        "vm_local",
        "running",
        Duration::from_secs(240),
    );
    let site_state = |site_id: &str| match site_id {
        "compose_local" => &compose_state,
        "kind_local" => &kind_state,
        "direct_local" => &direct_state,
        "vm_local" => &vm_state,
        _ => panic!("unknown site {site_id}"),
    };

    let control_state_path = framework_control_state_path(&run);
    let creator_port = pick_free_port();
    let mut creator_proxy = spawn_framework_proxy_for_site(
        &run.site_artifact_dir("compose_local"),
        "compose_admin_http",
        creator_port,
        site_state("compose_local"),
    );
    wait_for_path(
        &mut creator_proxy,
        creator_port,
        "/id",
        Duration::from_secs(240),
    );
    assert_eq!(
        wait_for_body(
            &mut creator_proxy,
            creator_port,
            "/id",
            Duration::from_secs(30),
        ),
        "admin",
    );

    let (create_status, create_response) = http_get_with_timeout(
        creator_port,
        "/create/child_kind/job-kind",
        FRAMEWORK_MUTATION_REQUEST_TIMEOUT,
    )
    .expect("create request should return an HTTP response");
    assert_eq!(
        create_status, 200,
        "create request should succeed; response: {create_response}"
    );
    let child_id = wait_for_live_child(&control_state_path, "job-kind");

    let root_artifact = framework_child_artifact(&run, "kind_local", child_id);
    let root_port = pick_free_port();
    let mut root_proxy =
        spawn_framework_proxy_for_site(&root_artifact, "http", root_port, site_state("kind_local"));
    wait_for_path(&mut root_proxy, root_port, "/id", Duration::from_secs(300));
    assert_eq!(
        wait_for_body(&mut root_proxy, root_port, "/id", Duration::from_secs(30)),
        "child-kind-root"
    );

    stop_proxy(&mut root_proxy);
    stop_proxy(&mut creator_proxy);
    run.stop();
}

#[test]
#[ignore = "requires docker + kind + kubectl + qemu + an Ubuntu 24.04 cloud image matching the \
            host architecture; run manually or in CI"]
fn framework_component_kind_creator_compose_child_live() {
    ensure_internal_images();
    let temp = temp_output_dir("framework-component-kind-creator-compose-child-");
    let kubeconfig = temp.path().join("kubeconfig");
    let kind_cluster = KindCluster::from_env_or_create(&kubeconfig);
    ensure_kind_internal_images(&kind_cluster);
    let kubeconfig_env = kind_cluster.kubeconfig.display().to_string();

    let fixture = write_framework_matrix_fixture(temp.path(), &kind_cluster);
    let storage_root = temp.path().join("state");
    let mut run = run_manifest_with_env(
        &fixture.manifest,
        &fixture.placement,
        &storage_root,
        &[("KUBECONFIG", &kubeconfig_env)],
    );

    let compose_state = wait_for_state_status(
        &run.run_root,
        "compose_local",
        "running",
        Duration::from_secs(60),
    );
    let kind_state = wait_for_state_status(
        &run.run_root,
        "kind_local",
        "running",
        Duration::from_secs(120),
    );
    let direct_state = wait_for_state_status(
        &run.run_root,
        "direct_local",
        "running",
        Duration::from_secs(60),
    );
    let vm_state = wait_for_state_status(
        &run.run_root,
        "vm_local",
        "running",
        Duration::from_secs(240),
    );
    let site_state = |site_id: &str| match site_id {
        "compose_local" => &compose_state,
        "kind_local" => &kind_state,
        "direct_local" => &direct_state,
        "vm_local" => &vm_state,
        _ => panic!("unknown site {site_id}"),
    };

    let control_state_path = framework_control_state_path(&run);
    let creator_port = pick_free_port();
    let mut creator_proxy = spawn_framework_proxy_for_site(
        &run.site_artifact_dir("kind_local"),
        "kind_admin_http",
        creator_port,
        site_state("kind_local"),
    );
    wait_for_path(
        &mut creator_proxy,
        creator_port,
        "/id",
        Duration::from_secs(240),
    );
    assert_eq!(
        wait_for_body(
            &mut creator_proxy,
            creator_port,
            "/id",
            Duration::from_secs(30),
        ),
        "admin",
        "kind creator should expose the framework admin app"
    );

    let (create_status, create_response) = http_get_with_timeout(
        creator_port,
        "/create/child_compose/job-compose",
        FRAMEWORK_MUTATION_REQUEST_TIMEOUT,
    )
    .expect("create request should return an HTTP response");
    assert_eq!(
        create_status, 200,
        "create request should succeed; response: {create_response}"
    );
    let child_id = wait_for_live_child(&control_state_path, "job-compose");

    let root_artifact = framework_child_artifact(&run, "compose_local", child_id);
    let root_port = pick_free_port();
    let mut root_proxy = spawn_framework_proxy_for_site(
        &root_artifact,
        "http",
        root_port,
        site_state("compose_local"),
    );
    wait_for_path(&mut root_proxy, root_port, "/id", Duration::from_secs(300));
    assert_eq!(
        wait_for_body(&mut root_proxy, root_port, "/id", Duration::from_secs(30)),
        "child-compose-root"
    );

    stop_proxy(&mut root_proxy);
    stop_proxy(&mut creator_proxy);
    run.stop();
}

#[test]
#[ignore = "requires docker + kind + kubectl + qemu + an Ubuntu 24.04 cloud image matching the \
            host architecture; run manually or in CI"]
fn framework_component_kind_creator_after_compose_churn_live() {
    ensure_internal_images();
    let temp = temp_output_dir("framework-component-kind-after-compose-churn-");
    let kubeconfig = temp.path().join("kubeconfig");
    let kind_cluster = KindCluster::from_env_or_create(&kubeconfig);
    ensure_kind_internal_images(&kind_cluster);
    let kubeconfig_env = kind_cluster.kubeconfig.display().to_string();

    let fixture = write_framework_matrix_fixture(temp.path(), &kind_cluster);
    let storage_root = temp.path().join("state");
    let mut run = run_manifest_with_env(
        &fixture.manifest,
        &fixture.placement,
        &storage_root,
        &[("KUBECONFIG", &kubeconfig_env)],
    );

    let compose_state = wait_for_state_status(
        &run.run_root,
        "compose_local",
        "running",
        Duration::from_secs(60),
    );
    let kind_state = wait_for_state_status(
        &run.run_root,
        "kind_local",
        "running",
        Duration::from_secs(120),
    );
    let direct_state = wait_for_state_status(
        &run.run_root,
        "direct_local",
        "running",
        Duration::from_secs(60),
    );
    let vm_state = wait_for_state_status(
        &run.run_root,
        "vm_local",
        "running",
        Duration::from_secs(240),
    );
    let site_state = |site_id: &str| match site_id {
        "compose_local" => &compose_state,
        "kind_local" => &kind_state,
        "direct_local" => &direct_state,
        "vm_local" => &vm_state,
        _ => panic!("unknown site {site_id}"),
    };

    let control_state_path = framework_control_state_path(&run);

    let compose_creator_port = pick_free_port();
    let mut compose_creator_proxy = spawn_framework_proxy_for_site(
        &run.site_artifact_dir("compose_local"),
        "compose_admin_http",
        compose_creator_port,
        site_state("compose_local"),
    );
    wait_for_path(
        &mut compose_creator_proxy,
        compose_creator_port,
        "/id",
        Duration::from_secs(240),
    );
    assert_eq!(
        wait_for_body(
            &mut compose_creator_proxy,
            compose_creator_port,
            "/id",
            Duration::from_secs(30),
        ),
        "admin",
        "compose creator should expose the framework admin app"
    );

    for template_case in FRAMEWORK_MATRIX_TEMPLATES {
        let create_path = format!(
            "/create/{}/{}",
            template_case.template, template_case.child_name
        );
        let (create_status, create_response) = http_get_with_timeout(
            compose_creator_port,
            &create_path,
            FRAMEWORK_MUTATION_REQUEST_TIMEOUT,
        )
        .expect("compose churn create request should return an HTTP response");
        assert_eq!(
            create_status, 200,
            "compose churn create request {create_path} should succeed; response: \
             {create_response}"
        );
        let child_id = wait_for_live_child(&control_state_path, template_case.child_name);
        let child_roots = template_case
            .exports
            .iter()
            .map(|(site_id, _, _)| {
                framework_child_artifact(&run, site_id, child_id)
                    .parent()
                    .expect("dynamic child artifact should have a parent")
                    .to_path_buf()
            })
            .collect::<Vec<_>>();
        let (destroy_status, destroy_response) =
            framework_destroy_child_via_admin(compose_creator_port, template_case.child_name);
        assert_eq!(
            destroy_status, 200,
            "compose churn destroy should succeed for {}; response: {destroy_response}",
            template_case.child_name,
        );
        wait_for_framework_child_absent(
            &control_state_path,
            template_case.child_name,
            &child_roots,
            Duration::from_secs(300),
        );
    }
    stop_proxy(&mut compose_creator_proxy);

    let kind_creator_port = pick_free_port();
    let mut kind_creator_proxy = spawn_framework_proxy_for_site(
        &run.site_artifact_dir("kind_local"),
        "kind_admin_http",
        kind_creator_port,
        site_state("kind_local"),
    );
    wait_for_path(
        &mut kind_creator_proxy,
        kind_creator_port,
        "/id",
        Duration::from_secs(240),
    );
    assert_eq!(
        wait_for_body(
            &mut kind_creator_proxy,
            kind_creator_port,
            "/id",
            Duration::from_secs(30),
        ),
        "admin",
        "kind creator should expose the framework admin app after compose churn"
    );
    let children_body = wait_for_body(
        &mut kind_creator_proxy,
        kind_creator_port,
        "/children",
        Duration::from_secs(30),
    );
    let children: Value =
        serde_json::from_str(&children_body).expect("children response should be valid JSON");
    assert_eq!(
        children["children"],
        Value::Array(Vec::new()),
        "kind creator control path should be healthy after compose churn"
    );

    let (create_status, create_response) = http_get_with_timeout(
        kind_creator_port,
        "/create/child_compose/job-compose",
        FRAMEWORK_MUTATION_REQUEST_TIMEOUT,
    )
    .expect("kind create request should return an HTTP response");
    assert_eq!(
        create_status, 200,
        "kind creator create after compose churn should succeed; response: {create_response}"
    );

    stop_proxy(&mut kind_creator_proxy);
    run.stop();
}

#[test]
#[ignore = "requires docker + kind + kubectl + qemu + an Ubuntu 24.04 cloud image matching the \
            host architecture; run manually or in CI"]
fn framework_component_cross_backend_matrix_live() {
    ensure_internal_images();
    let temp = temp_output_dir("framework-component-matrix-");
    let kubeconfig = temp.path().join("kubeconfig");
    let kind_cluster = KindCluster::from_env_or_create(&kubeconfig);
    ensure_kind_internal_images(&kind_cluster);
    let kubeconfig_env = kind_cluster.kubeconfig.display().to_string();

    let fixture = write_framework_matrix_fixture(temp.path(), &kind_cluster);
    let storage_root = temp.path().join("state");
    let mut run = run_manifest_with_env(
        &fixture.manifest,
        &fixture.placement,
        &storage_root,
        &[("KUBECONFIG", &kubeconfig_env)],
    );

    let compose_state = wait_for_state_status(
        &run.run_root,
        "compose_local",
        "running",
        Duration::from_secs(60),
    );
    let kind_state = wait_for_state_status(
        &run.run_root,
        "kind_local",
        "running",
        Duration::from_secs(120),
    );
    let direct_state = wait_for_state_status(
        &run.run_root,
        "direct_local",
        "running",
        Duration::from_secs(60),
    );
    let vm_state = wait_for_state_status(
        &run.run_root,
        "vm_local",
        "running",
        Duration::from_secs(240),
    );
    let site_state = |site_id: &str| match site_id {
        "compose_local" => &compose_state,
        "kind_local" => &kind_state,
        "direct_local" => &direct_state,
        "vm_local" => &vm_state,
        _ => panic!("unknown site {site_id}"),
    };

    let control_state_path = framework_control_state_path(&run);

    for (creator_site, creator_export) in FRAMEWORK_MATRIX_CREATORS {
        let creator_port = pick_free_port();
        let mut creator_proxy = spawn_framework_proxy_for_site(
            &run.site_artifact_dir(creator_site),
            creator_export,
            creator_port,
            site_state(creator_site),
        );
        wait_for_path(
            &mut creator_proxy,
            creator_port,
            "/id",
            Duration::from_secs(240),
        );
        assert_eq!(
            wait_for_body(
                &mut creator_proxy,
                creator_port,
                "/id",
                Duration::from_secs(30)
            ),
            "admin",
            "creator {creator_site} should expose the framework admin app"
        );

        for template_case in FRAMEWORK_MATRIX_TEMPLATES {
            let create_path = format!(
                "/create/{}/{}",
                template_case.template, template_case.child_name
            );
            let (create_status, create_response) = http_get_with_timeout(
                creator_port,
                &create_path,
                FRAMEWORK_MUTATION_REQUEST_TIMEOUT,
            )
            .expect("create request should return an HTTP response");
            assert_eq!(
                create_status, 200,
                "create request {create_path} from {creator_site} should succeed; response: \
                 {create_response}"
            );
            let create_json: Value =
                serde_json::from_str(&create_response).expect("create response should be valid");
            assert_eq!(create_json["child"]["name"], template_case.child_name);

            let child_id = wait_for_live_child(&control_state_path, template_case.child_name);
            let child_roots = template_case
                .exports
                .iter()
                .map(|(site_id, _, _)| {
                    framework_child_artifact(&run, site_id, child_id)
                        .parent()
                        .expect("dynamic child artifact should have a parent")
                        .to_path_buf()
                })
                .collect::<Vec<_>>();

            let root_site_id = template_case.exports[0].0;
            let root_artifact = framework_child_artifact(&run, root_site_id, child_id);
            let root_port = pick_free_port();
            let mut root_proxy = spawn_framework_proxy_for_site(
                &root_artifact,
                template_case.exports[0].1,
                root_port,
                site_state(root_site_id),
            );
            wait_for_path(&mut root_proxy, root_port, "/id", Duration::from_secs(300));
            assert_eq!(
                wait_for_body(&mut root_proxy, root_port, "/id", Duration::from_secs(30)),
                template_case.exports[0].2
            );

            for (site_id, export_name, expected_id) in &template_case.exports[1..] {
                let artifact = framework_child_artifact(&run, site_id, child_id);
                let port = pick_free_port();
                let mut proxy = spawn_framework_proxy_for_site(
                    &artifact,
                    export_name,
                    port,
                    site_state(site_id),
                );
                wait_for_path(&mut proxy, port, "/id", Duration::from_secs(300));
                assert_eq!(
                    wait_for_body(&mut proxy, port, "/id", Duration::from_secs(30)),
                    *expected_id,
                    "dynamic child export {export_name} on {site_id} should be reachable"
                );
                stop_proxy(&mut proxy);
            }

            for (alias, expected_id) in template_case.root_calls {
                let path = format!("/call/{alias}");
                assert_eq!(
                    wait_for_body(&mut root_proxy, root_port, &path, Duration::from_secs(120)),
                    *expected_id,
                    "dynamic child root should reach its {alias} helper"
                );
            }
            stop_proxy(&mut root_proxy);

            let (destroy_status, destroy_response) =
                framework_destroy_child_via_admin(creator_port, template_case.child_name);
            assert_eq!(
                destroy_status, 200,
                "destroy request for {} from {creator_site} should succeed; response: \
                 {destroy_response}",
                template_case.child_name,
            );
            wait_for_framework_child_absent(
                &control_state_path,
                template_case.child_name,
                &child_roots,
                Duration::from_secs(300),
            );
        }

        stop_proxy(&mut creator_proxy);
    }

    run.stop();
}

#[test]
#[ignore = "requires docker; run manually or in CI"]
fn mixed_run_proxy_attaches_by_run_id_smoke() {
    ensure_internal_images();
    let temp = temp_output_dir("mixed-run-proxy-run-id-");
    let fixture = write_two_site_fixture(temp.path());

    let storage_root = temp.path().join("state");
    let mut run = run_manifest(&fixture.manifest, &fixture.placement, &storage_root);

    let proxy_port = pick_free_port();
    let proxy_args = vec![
        "--storage-root".to_string(),
        storage_root.display().to_string(),
    ];
    let mut proxy = spawn_proxy_target(&run.run_id, "a_http", proxy_port, &proxy_args);
    wait_for_path(&mut proxy, proxy_port, "/id", Duration::from_secs(60));
    assert_eq!(
        wait_for_body(&mut proxy, proxy_port, "/call/b", Duration::from_secs(60)),
        "B"
    );
    stop_proxy(&mut proxy);

    run.stop();
    assert!(
        !run.run_root.join("receipt.json").exists(),
        "receipt should be removed after amber stop"
    );
}

#[test]
#[ignore = "requires docker; run manually or in CI"]
fn mixed_run_direct_compose_proxy_smoke() {
    ensure_internal_images();
    let temp = temp_output_dir("mixed-run-two-site-");
    let fixture = write_two_site_fixture(temp.path());

    let storage_root = temp.path().join("state");
    let mut run = run_manifest(&fixture.manifest, &fixture.placement, &storage_root);

    let run_plan: Value = serde_json::from_slice(
        &fs::read(run.run_root.join("run-plan.json")).expect("failed to read run-plan.json"),
    )
    .expect("run-plan.json should be valid JSON");
    assert_eq!(
        run_plan["startup_waves"],
        json!([["compose_local"], ["direct_local"]])
    );
    assert_eq!(
        run.receipt["sites"]
            .as_object()
            .expect("receipt sites should be an object")
            .len(),
        2
    );

    let direct_artifact = run.site_artifact_dir("direct_local");
    let proxy_port = pick_free_port();
    let mut proxy = spawn_proxy(&direct_artifact, "a_http", proxy_port, &[]);
    wait_for_path(&mut proxy, proxy_port, "/id", Duration::from_secs(60));
    let body = wait_for_body(&mut proxy, proxy_port, "/call/b", Duration::from_secs(60));
    assert_eq!(body, "B");
    stop_proxy(&mut proxy);

    run.stop();
    assert!(
        !run.run_root.join("receipt.json").exists(),
        "receipt should be removed after amber stop"
    );
}

#[test]
#[ignore = "requires docker; run manually or in CI"]
fn mixed_run_detached_stop_smoke() {
    ensure_internal_images();
    let temp = temp_output_dir("mixed-run-detach-");
    let fixture = write_two_site_fixture(temp.path());
    let storage_root = temp.path().join("state");
    let mut run = run_manifest_detached(&fixture.manifest, &fixture.placement, &storage_root);

    let direct_artifact = run.site_artifact_dir("direct_local");
    let proxy_port = pick_free_port();
    let mut proxy = spawn_proxy(&direct_artifact, "a_http", proxy_port, &[]);
    wait_for_path(&mut proxy, proxy_port, "/id", Duration::from_secs(60));
    assert_eq!(
        wait_for_body(&mut proxy, proxy_port, "/call/b", Duration::from_secs(60)),
        "B"
    );
    stop_proxy(&mut proxy);

    run.stop();
    wait_for_condition(
        Duration::from_secs(30),
        || !run.run_root.join("receipt.json").exists(),
        "detached run receipt removal",
    );
}

#[test]
#[ignore = "requires docker; run manually or in CI"]
fn mixed_run_documented_example_detached_stop_smoke() {
    ensure_internal_images();
    let temp = temp_output_dir("mixed-run-doc-example-detach-");
    let fixture = copy_documented_mixed_site_fixture(temp.path());
    let storage_root = temp.path().join("state");
    let catalog = HostHttpServer::start();
    let catalog_url = docker_host_http_url(catalog.port())
        .trim_end_matches('/')
        .to_string();
    let runtime_env = [
        ("AMBER_CONFIG_TENANT", "acme-local"),
        ("AMBER_CONFIG_CATALOG_TOKEN", "demo-token"),
        ("AMBER_EXTERNAL_SLOT_CATALOG_API_URL", catalog_url.as_str()),
    ];
    let mut run = run_manifest_with_args_and_env(
        &fixture.manifest,
        &fixture.placement,
        &storage_root,
        &["--detach"],
        &runtime_env,
    );

    let direct_state = wait_for_state_status(
        &run.run_root,
        "direct_local",
        "running",
        Duration::from_secs(30),
    );
    let compose_state = wait_for_state_status(
        &run.run_root,
        "compose_local",
        "running",
        Duration::from_secs(30),
    );
    let direct_pid = direct_state["process_pid"]
        .as_u64()
        .expect("direct process pid should be present") as u32;
    let compose_project = compose_state["compose_project"]
        .as_str()
        .expect("compose project should be present")
        .to_string();

    let proxy_port = pick_free_port();
    let proxy_args = vec![
        "--storage-root".to_string(),
        storage_root.display().to_string(),
    ];
    let mut proxy = spawn_proxy_target(&run.run_id, "app", proxy_port, &proxy_args);
    wait_for_path(&mut proxy, proxy_port, "/chain", Duration::from_secs(60));
    let body = wait_for_body(&mut proxy, proxy_port, "/chain", Duration::from_secs(60));
    assert!(
        body.contains("\"site\": \"direct\""),
        "documented example should return the direct web response, got:\n{body}"
    );
    assert!(
        body.contains("\"item\": \"amber mug\""),
        "documented example should reach the outside catalog service, got:\n{body}"
    );
    stop_proxy(&mut proxy);

    run.stop();
    wait_for_condition(
        Duration::from_secs(30),
        || !run.run_root.join("receipt.json").exists(),
        "documented example detached run receipt removal",
    );
    wait_for_condition(
        Duration::from_secs(30),
        || !pid_is_alive(direct_pid),
        "documented example direct process exit",
    );
    wait_for_condition(
        Duration::from_secs(30),
        || {
            compose_ps_ids_with_env(
                &compose_project,
                &run.site_artifact_dir("compose_local"),
                &runtime_env,
            )
            .is_empty()
        },
        "documented example compose teardown",
    );
}

#[test]
#[ignore = "requires docker; run manually or in CI"]
fn mixed_run_local_observability_scenario_smoke() {
    ensure_internal_images();
    let temp = temp_output_dir("mixed-run-obsv-scenario-");
    let fixture = write_two_site_fixture(temp.path());
    let storage_root = temp.path().join("state");
    let mut run = run_manifest_with_args(
        &fixture.manifest,
        &fixture.placement,
        &storage_root,
        &["--observability", "local"],
    );

    let requests_log = PathBuf::from(
        run.receipt["observability"]["requests_log"]
            .as_str()
            .expect("run receipt should contain observability log"),
    );
    wait_for_text(&requests_log, "/v1/logs", Duration::from_secs(60));
    let before_lines = fs::read_to_string(&requests_log)
        .unwrap_or_default()
        .lines()
        .count();
    let direct_artifact = run.site_artifact_dir("direct_local");
    let proxy_port = pick_free_port();
    let mut proxy = spawn_proxy(&direct_artifact, "a_http", proxy_port, &[]);
    wait_for_path(&mut proxy, proxy_port, "/id", Duration::from_secs(60));
    assert_eq!(
        wait_for_body(&mut proxy, proxy_port, "/call/b", Duration::from_secs(60)),
        "B"
    );
    wait_for_condition(
        Duration::from_secs(60),
        || {
            fs::read_to_string(&requests_log)
                .map(|contents| contents.lines().count() > before_lines)
                .unwrap_or(false)
        },
        "scenario telemetry after routed traffic",
    );
    stop_proxy(&mut proxy);
    run.stop();
}

#[test]
#[ignore = "requires docker; run manually or in CI"]
fn mixed_run_local_observability_manager_smoke() {
    let temp = temp_output_dir("mixed-run-obsv-manager-");
    let fixture = write_single_site_direct_fixture(temp.path());
    let storage_root = temp.path().join("state");
    let mut run = run_manifest_with_args(
        &fixture.manifest,
        &fixture.placement,
        &storage_root,
        &["--observability", "local"],
    );

    let requests_log = PathBuf::from(
        run.receipt["observability"]["requests_log"]
            .as_str()
            .expect("run receipt should contain observability log"),
    );
    wait_for_text(&requests_log, "/v1/logs", Duration::from_secs(60));
    let before = fs::read_to_string(&requests_log).unwrap_or_default();
    let before_lines = before.lines().count();
    run.stop();
    wait_for_condition(
        Duration::from_secs(30),
        || {
            fs::read_to_string(&requests_log)
                .map(|contents| contents.lines().count() > before_lines)
                .unwrap_or(false)
        },
        "site-manager stop logs",
    );
}
