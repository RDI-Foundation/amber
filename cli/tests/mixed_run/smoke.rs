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

const DYNAMIC_CAPS_APP: &str = r#"import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlsplit
from urllib.request import Request, urlopen

NAME = os.environ["NAME"]
PORT = int(os.environ["PORT"])
DYNAMIC_CAPS_API_URL = os.environ.get("AMBER_DYNAMIC_CAPS_API_URL", "").rstrip("/")
UPSTREAMS = {
    key.removeprefix("UPSTREAM_").lower(): value.rstrip("/")
    for key, value in os.environ.items()
    if key.startswith("UPSTREAM_") and value
}
LAST_MESSAGE = ""
LAST_MESSAGE_CONTENT_TYPE = "text/plain; charset=utf-8"

def send(handler, status, body, content_type="text/plain; charset=utf-8"):
    payload = body.encode("utf-8")
    handler.send_response(status)
    handler.send_header("content-type", content_type)
    handler.send_header("content-length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)

def send_json(handler, status, payload):
    send(
        handler,
        status,
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        "application/json; charset=utf-8",
    )

def request_target(target):
    parsed = urlsplit(target)
    query = {
        key: values[-1]
        for key, values in parse_qs(parsed.query, keep_blank_values=True).items()
    }
    return parsed.path, query

def read_body(handler):
    length = int(handler.headers.get("content-length", "0") or "0")
    return handler.rfile.read(length).decode("utf-8") if length else ""

def parse_json_body(handler):
    raw = read_body(handler)
    if not raw:
        return {}, raw
    return json.loads(raw), raw

def http_call(base_url, method, path, payload=None, content_type="application/json"):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Connection": "close"}
    if data is not None:
        headers["Content-Type"] = content_type
    request = Request(f"{base_url.rstrip('/')}{path}", data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=30) as response:
            return (
                response.status,
                response.headers.get("content-type", "application/json; charset=utf-8"),
                response.read().decode("utf-8"),
            )
    except HTTPError as err:
        return (
            err.code,
            err.headers.get("content-type", "application/json; charset=utf-8"),
            err.read().decode("utf-8"),
        )
    except URLError as err:
        return (
            502,
            "application/json; charset=utf-8",
            json.dumps({"error": f"{err.__class__.__name__}: {err.reason}"}),
        )

def api_call(method, path, payload=None):
    if not DYNAMIC_CAPS_API_URL:
        return (
            503,
            "application/json; charset=utf-8",
            json.dumps({"error": "AMBER_DYNAMIC_CAPS_API_URL is not set"}),
        )
    return http_call(DYNAMIC_CAPS_API_URL, method, path, payload)

def proxy_response(handler, status, content_type, body):
    send(handler, status, body or "", content_type)

def join_url(base, suffix):
    if not suffix:
        return base
    return f"{base.rstrip('/')}/{suffix.lstrip('/')}"

def fetch_text(url, timeout=30.0):
    request = Request(url, headers={"Connection": "close"})
    with urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8")

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        global LAST_MESSAGE, LAST_MESSAGE_CONTENT_TYPE

        path, query = request_target(self.path)
        try:
            if path == "/id":
                send(self, 200, NAME)
                return
            if path == "/held":
                proxy_response(self, *api_call("GET", "/v1/held"))
                return
            if path.startswith("/held/"):
                held_id = quote(path.removeprefix("/held/"), safe="")
                proxy_response(self, *api_call("GET", f"/v1/held/{held_id}"))
                return
            if path == "/last-message":
                send(self, 200, LAST_MESSAGE, LAST_MESSAGE_CONTENT_TYPE)
                return
            if path == "/call-upstream":
                alias = query.get("alias", "upstream")
                upstream = UPSTREAMS.get(alias)
                if not upstream:
                    send_json(self, 404, {"error": f"missing upstream {alias}"})
                    return
                send(self, 200, fetch_text(join_url(upstream, query.get("suffix", "/id"))))
                return
            if path == "/call-url":
                url = query.get("url")
                if not url:
                    send_json(self, 400, {"error": "missing url"})
                    return
                send(self, 200, fetch_text(join_url(url, query.get("suffix", ""))))
                return
            if path == "/call-last-message-field":
                field = query.get("field", "url")
                suffix = query.get("suffix", "")
                payload = json.loads(LAST_MESSAGE or "{}")
                url = payload.get(field)
                if not url:
                    send_json(self, 404, {"error": f"missing field {field}"})
                    return
                send(self, 200, fetch_text(join_url(url, suffix)))
                return
            send(self, 404, "missing")
        except HTTPError as err:
            send(self, err.code, err.read().decode("utf-8", errors="replace"))
        except Exception as err:
            send_json(self, 502, {"error": f"{err.__class__.__name__}: {err}"})

    def do_POST(self):
        global LAST_MESSAGE, LAST_MESSAGE_CONTENT_TYPE

        path, query = request_target(self.path)
        try:
            if path == "/message":
                raw = read_body(self)
                LAST_MESSAGE = raw
                LAST_MESSAGE_CONTENT_TYPE = self.headers.get(
                    "content-type", "text/plain; charset=utf-8"
                )
                send(
                    self,
                    200,
                    raw or "{}",
                    LAST_MESSAGE_CONTENT_TYPE,
                )
                return

            payload, _ = parse_json_body(self)
            if path == "/share":
                status, content_type, body = api_call(
                    "POST",
                    "/v1/share",
                    {
                        "source": {
                            "kind": payload["source_kind"],
                            "value": payload["value"],
                        },
                        "recipient": payload["recipient"],
                        "idempotency_key": payload.get("idempotency_key"),
                        "options": payload.get("options", {}),
                    },
                )
                proxy_response(self, status, content_type, body)
                return
            if path == "/forward-share":
                alias = payload.get("alias", "peer")
                peer_url = UPSTREAMS.get(alias)
                if not peer_url:
                    send_json(self, 404, {"error": f"missing upstream {alias}"})
                    return
                status, content_type, body = api_call(
                    "POST",
                    "/v1/share",
                    {
                        "source": {
                            "kind": payload["source_kind"],
                            "value": payload["value"],
                        },
                        "recipient": payload["recipient"],
                        "idempotency_key": payload.get("idempotency_key"),
                        "options": payload.get("options", {}),
                    },
                )
                share_json = json.loads(body or "{}")
                if status != 200 or not share_json.get("ref"):
                    proxy_response(self, status, content_type, body)
                    return
                delivery_payload = payload.get("delivery_payload", {"ref": share_json["ref"]})
                delivery = http_call(
                    peer_url,
                    "POST",
                    payload.get("path", "/message"),
                    delivery_payload,
                )
                send_json(
                    self,
                    200,
                    {
                        "share": share_json,
                        "delivery": {
                            "status": delivery[0],
                            "content_type": delivery[1],
                            "body": delivery[2],
                        },
                    },
                )
                return
            if path == "/inspect-ref":
                proxy_response(self, *api_call("POST", "/v1/inspect-ref", payload))
                return
            if path == "/inspect-last-message-ref":
                field = query.get("field", "ref")
                message = json.loads(LAST_MESSAGE or "{}")
                proxy_response(
                    self,
                    *api_call("POST", "/v1/inspect-ref", {"ref": message.get(field)}),
                )
                return
            if path == "/materialize":
                proxy_response(self, *api_call("POST", "/v1/materialize", payload))
                return
            if path == "/materialize-last-message-ref":
                field = query.get("field", "ref")
                message = json.loads(LAST_MESSAGE or "{}")
                proxy_response(
                    self,
                    *api_call("POST", "/v1/materialize", {"ref": message.get(field)}),
                )
                return
            if path == "/revoke":
                proxy_response(self, *api_call("POST", "/v1/revoke", payload))
                return
            if path == "/inspect-handle":
                proxy_response(self, *api_call("POST", "/v1/inspect-handle", payload))
                return
            if path == "/inspect-last-message-handle":
                field = query.get("field", "url")
                message = json.loads(LAST_MESSAGE or "{}")
                proxy_response(
                    self,
                    *api_call(
                        "POST",
                        "/v1/inspect-handle",
                        {"handle": message.get(field)},
                    ),
                )
                return
            if path == "/call-url":
                url = payload.get("url")
                if not url:
                    send_json(self, 400, {"error": "missing url"})
                    return
                send(self, 200, fetch_text(join_url(url, payload.get("suffix", ""))))
                return
            send(self, 404, "missing")
        except HTTPError as err:
            send(self, err.code, err.read().decode("utf-8", errors="replace"))
        except Exception as err:
            send_json(self, 502, {"error": f"{err.__class__.__name__}: {err}"})

    def log_message(self, fmt, *args):
        print(f"[dynamic-caps:{NAME}] {fmt % args}", flush=True)

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

#[allow(clippy::too_many_arguments)]
fn write_dynamic_caps_component(
    root: &Path,
    file_name: &str,
    image: bool,
    name: &str,
    port: u16,
    provide_kind: &str,
    slots: &[(&str, &str)],
    extra_env: &[(&str, &str)],
) {
    let env = slots
        .iter()
        .map(|(slot_name, _)| {
            (
                format!("UPSTREAM_{}", slot_name.to_ascii_uppercase()),
                json!(format!("${{slots.{slot_name}.url}}")),
            )
        })
        .chain(
            extra_env
                .iter()
                .map(|(key, value)| ((*key).to_string(), json!(value))),
        )
        .chain(std::iter::once(("NAME".to_string(), json!(name))))
        .chain(std::iter::once((
            "PORT".to_string(),
            json!(port.to_string()),
        )))
        .collect::<serde_json::Map<_, _>>();
    let slots = slots
        .iter()
        .map(|(slot_name, kind)| ((*slot_name).to_string(), json!({ "kind": kind })))
        .collect::<serde_json::Map<_, _>>();
    let program = if image {
        json!({
            "image": TEST_APP_IMAGE,
            "entrypoint": ["python3", "-u", "-c", { "file": "./dynamic_caps_app.py" }],
            "env": env,
            "network": {
                "endpoints": [
                    { "name": "http", "port": port, "protocol": "http" }
                ]
            }
        })
    } else {
        json!({
            "path": "/usr/bin/env",
            "args": ["python3", "-u", "-c", { "file": "./dynamic_caps_app.py" }],
            "env": env,
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
            "slots": slots,
            "program": program,
            "provides": {
                "api": { "kind": provide_kind, "endpoint": "http" }
            },
            "exports": {
                "api": "api"
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

fn framework_control_state_plan_path(run: &RunHandle) -> PathBuf {
    run.run_root
        .join("state")
        .join("framework-component")
        .join("control-state-plan.json")
}

fn framework_control_state_post(run: &RunHandle, path: &str, payload: &Value) -> (u16, String) {
    let plan = read_json(&framework_control_state_plan_path(run));
    let listen_addr = plan["listen_addr"]
        .as_str()
        .expect("framework control-state plan should publish listen_addr");
    let auth_token = plan["auth_token"]
        .as_str()
        .expect("framework control-state plan should publish auth token");
    let body = serde_json::to_string(payload).expect("request body should serialize");
    let output = std::process::Command::new("curl")
        .arg("-sS")
        .arg("--max-time")
        .arg("30.000")
        .arg("-X")
        .arg("POST")
        .arg("-H")
        .arg("content-type: application/json")
        .arg("-H")
        .arg(format!("x-amber-framework-auth: {auth_token}"))
        .arg("--data")
        .arg(body)
        .arg("-o")
        .arg("-")
        .arg("-w")
        .arg("\n%{http_code}")
        .arg(format!("http://{listen_addr}{path}"))
        .output()
        .expect("framework control-state request should complete");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let (body, status) = stdout
        .rsplit_once('\n')
        .expect("framework control-state response should include HTTP status");
    (
        status
            .trim()
            .parse()
            .expect("framework control-state status should parse"),
        body.trim().to_string(),
    )
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

fn framework_manifest_url(path: &Path) -> String {
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
                .unwrap_or_else(|| json!({})),
            "dynamic_capabilities": snapshot["dynamic_capabilities"],
            "framework_children": snapshot["placement"]
                .get("framework_children")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        }),
    );
    (scenario_path, placement_path)
}

fn app_post_json(port: u16, path: &str, payload: &Value) -> (u16, String) {
    let body = serde_json::to_string(payload).expect("request body should serialize");
    http_request_with_timeout("POST", port, path, Some(&body), Duration::from_secs(30))
        .expect("app request should return an HTTP response")
}

fn app_get_json(port: u16, path: &str) -> Value {
    let (status, body) = http_get_with_timeout(port, path, Duration::from_secs(30))
        .expect("app request should return an HTTP response");
    assert_eq!(status, 200, "GET {path} should succeed: {body}");
    serde_json::from_str(&body).expect("response should be valid json")
}

fn held_id_with_kind(held: &Value, entry_kind: &str) -> String {
    held["held"]
        .as_array()
        .expect("held response should contain an array")
        .iter()
        .find(|entry| entry["entry_kind"] == entry_kind && entry["state"] == "live")
        .and_then(|entry| entry["held_id"].as_str())
        .unwrap_or_else(|| panic!("missing live held entry of kind {entry_kind}: {held}"))
        .to_string()
}

fn delegated_held_id_from_component(held: &Value, from_component: &str) -> String {
    held["held"]
        .as_array()
        .expect("held response should contain an array")
        .iter()
        .find(|entry| {
            entry["entry_kind"] == "delegated_grant"
                && entry["state"] == "live"
                && entry["from_component"] == from_component
        })
        .and_then(|entry| entry["held_id"].as_str())
        .unwrap_or_else(|| panic!("missing delegated grant from {from_component}: {held}"))
        .to_string()
}

fn response_json(status: u16, body: &str, context: &str) -> Value {
    assert_eq!(status, 200, "{context} should succeed: {body}");
    serde_json::from_str(body).expect("response should be valid json")
}

fn response_json_from(response: (u16, String), context: &str) -> Value {
    response_json(response.0, &response.1, context)
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
fn framework_component_bounded_template_frozen_source_replay_live() {
    let temp = temp_output_dir("framework-component-frozen-bounded-template-");
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
    let alpha_manifest = framework_manifest_url(&alpha_path);
    let beta_manifest = framework_manifest_url(&beta_path);

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
                    "manifest": [alpha_manifest.clone(), beta_manifest.clone()]
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
            "manifest": beta_manifest
        }),
    );
    assert_eq!(
        create_status, 200,
        "bounded-template create should use the frozen catalog; response: {create_response}"
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
            "manifest": alpha_manifest
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

    let compose_manifest = framework_manifest_url(&temp.path().join("compose-worker.json5"));
    let direct_manifest = framework_manifest_url(&temp.path().join("direct-worker.json5"));

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
                    "manifest": [
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
        "run should fail deterministically when a bounded template allows a manifest that \
         requires an unoffered site\nstdout:\n{}\nstderr:\n{}",
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
#[ignore = "requires a working direct runtime sandbox; run manually or in CI"]
fn dynamic_capabilities_manual_materialization_live() {
    let temp = temp_output_dir("dynamic-caps-manual-");
    let provider_port = pick_free_port();
    let sender_port = pick_free_port();
    let receiver_port = pick_free_port();

    fs::write(temp.path().join("dynamic_caps_app.py"), DYNAMIC_CAPS_APP)
        .expect("failed to write dynamic_caps_app.py");
    write_dynamic_caps_component(
        temp.path(),
        "provider.json5",
        false,
        "provider",
        provider_port,
        "http",
        &[],
        &[],
    );
    write_dynamic_caps_component(
        temp.path(),
        "sender.json5",
        false,
        "sender",
        sender_port,
        "http",
        &[("upstream", "http"), ("peer", "http")],
        &[],
    );
    write_dynamic_caps_component(
        temp.path(),
        "receiver.json5",
        false,
        "receiver",
        receiver_port,
        "http",
        &[],
        &[],
    );

    let manifest = temp.path().join("root.json5");
    write_json(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "components": {
                "provider": "./provider.json5",
                "sender": "./sender.json5",
                "receiver": "./receiver.json5"
            },
            "bindings": [
                { "to": "#sender.upstream", "from": "#provider.api" },
                { "to": "#sender.peer", "from": "#receiver.api" }
            ],
            "exports": {
                "sender_api": "#sender.api",
                "receiver_api": "#receiver.api"
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
                "direct_a": { "kind": "direct" },
                "direct_b": { "kind": "direct" }
            },
            "defaults": {
                "path": "direct_a"
            },
            "components": {
                "/provider": "direct_a",
                "/sender": "direct_a",
                "/receiver": "direct_b"
            }
        }),
    );

    let storage_root = temp.path().join("state");
    let mut run = run_manifest(&manifest, &placement, &storage_root);
    wait_for_state_status(
        &run.run_root,
        "direct_a",
        "running",
        Duration::from_secs(60),
    );
    wait_for_state_status(
        &run.run_root,
        "direct_b",
        "running",
        Duration::from_secs(60),
    );

    let sender_proxy_port = pick_free_port();
    let mut sender_proxy = spawn_proxy(
        &run.site_artifact_dir("direct_a"),
        "sender_api",
        sender_proxy_port,
        &[],
    );
    wait_for_path(
        &mut sender_proxy,
        sender_proxy_port,
        "/id",
        Duration::from_secs(60),
    );
    let receiver_proxy_port = pick_free_port();
    let mut receiver_proxy = spawn_proxy(
        &run.site_artifact_dir("direct_b"),
        "receiver_api",
        receiver_proxy_port,
        &[],
    );
    wait_for_path(
        &mut receiver_proxy,
        receiver_proxy_port,
        "/id",
        Duration::from_secs(60),
    );

    let sender_root =
        held_id_with_kind(&app_get_json(sender_proxy_port, "/held"), "root_authority");
    let (forward_status, forward_body) = app_post_json(
        sender_proxy_port,
        "/forward-share",
        &json!({
            "source_kind": "held_id",
            "value": sender_root,
            "recipient": "components./receiver"
        }),
    );
    let forward_json = response_json(forward_status, &forward_body, "manual forward share");
    assert_eq!(forward_json["share"]["outcome"], "created");
    assert_eq!(forward_json["delivery"]["status"], 200);

    let last_message = app_get_json(receiver_proxy_port, "/last-message");
    let raw_ref = last_message["ref"]
        .as_str()
        .expect("receiver should record the shared ref");
    assert!(
        raw_ref.starts_with("amber://ref/"),
        "plain http delivery must preserve the raw ref, got {raw_ref}"
    );

    let (inspect_status, inspect_body) = app_post_json(
        receiver_proxy_port,
        "/inspect-ref",
        &json!({ "ref": raw_ref }),
    );
    let inspect = response_json(inspect_status, &inspect_body, "inspect ref");
    assert_eq!(inspect["state"], "live");
    assert_eq!(inspect["holder_component_id"], "components./receiver");

    let (materialize_status, materialize_body) = app_post_json(
        receiver_proxy_port,
        "/materialize",
        &json!({ "ref": raw_ref }),
    );
    let materialized = response_json(materialize_status, &materialize_body, "materialize ref");
    let handle = materialized["url"]
        .as_str()
        .expect("materialize should return a url");

    let (call_status, call_body) = app_post_json(
        receiver_proxy_port,
        "/call-url",
        &json!({ "url": handle, "suffix": "/id" }),
    );
    assert_eq!(
        call_status, 200,
        "materialized handle should be usable: {call_body}"
    );
    assert_eq!(call_body, "provider");

    stop_proxy(&mut receiver_proxy);
    stop_proxy(&mut sender_proxy);
    run.stop();
}

#[test]
#[ignore = "requires a working direct runtime sandbox; run manually or in CI"]
fn dynamic_capabilities_a2a_auto_materialization_live() {
    let temp = temp_output_dir("dynamic-caps-a2a-");
    let provider_port = pick_free_port();
    let sender_port = pick_free_port();
    let receiver_port = pick_free_port();

    fs::write(temp.path().join("dynamic_caps_app.py"), DYNAMIC_CAPS_APP)
        .expect("failed to write dynamic_caps_app.py");
    write_dynamic_caps_component(
        temp.path(),
        "provider.json5",
        false,
        "provider",
        provider_port,
        "a2a",
        &[],
        &[],
    );
    write_dynamic_caps_component(
        temp.path(),
        "sender.json5",
        false,
        "sender",
        sender_port,
        "http",
        &[("upstream", "a2a"), ("peer", "a2a")],
        &[],
    );
    write_dynamic_caps_component(
        temp.path(),
        "receiver.json5",
        false,
        "receiver",
        receiver_port,
        "a2a",
        &[],
        &[],
    );

    let manifest = temp.path().join("root.json5");
    write_json(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "components": {
                "provider": "./provider.json5",
                "sender": "./sender.json5",
                "receiver": "./receiver.json5"
            },
            "bindings": [
                { "to": "#sender.upstream", "from": "#provider.api" },
                { "to": "#sender.peer", "from": "#receiver.api" }
            ],
            "exports": {
                "sender_api": "#sender.api",
                "receiver_api": "#receiver.api"
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
                "direct_a": { "kind": "direct" },
                "direct_b": { "kind": "direct" }
            },
            "defaults": {
                "path": "direct_a"
            },
            "components": {
                "/provider": "direct_a",
                "/sender": "direct_a",
                "/receiver": "direct_b"
            }
        }),
    );

    let storage_root = temp.path().join("state");
    let mut run = run_manifest(&manifest, &placement, &storage_root);
    wait_for_state_status(
        &run.run_root,
        "direct_a",
        "running",
        Duration::from_secs(60),
    );
    wait_for_state_status(
        &run.run_root,
        "direct_b",
        "running",
        Duration::from_secs(60),
    );

    let sender_proxy_port = pick_free_port();
    let mut sender_proxy = spawn_proxy(
        &run.site_artifact_dir("direct_a"),
        "sender_api",
        sender_proxy_port,
        &[],
    );
    wait_for_path(
        &mut sender_proxy,
        sender_proxy_port,
        "/id",
        Duration::from_secs(60),
    );
    let receiver_proxy_port = pick_free_port();
    let mut receiver_proxy = spawn_proxy(
        &run.site_artifact_dir("direct_b"),
        "receiver_api",
        receiver_proxy_port,
        &[],
    );
    wait_for_path(
        &mut receiver_proxy,
        receiver_proxy_port,
        "/id",
        Duration::from_secs(60),
    );

    let sender_root =
        held_id_with_kind(&app_get_json(sender_proxy_port, "/held"), "root_authority");
    let (forward_status, forward_body) = app_post_json(
        sender_proxy_port,
        "/forward-share",
        &json!({
            "source_kind": "held_id",
            "value": sender_root,
            "recipient": "components./receiver"
        }),
    );
    let forward_json = response_json(forward_status, &forward_body, "a2a forward share");
    assert_eq!(forward_json["share"]["outcome"], "created");
    assert_eq!(forward_json["delivery"]["status"], 200);

    let last_message = app_get_json(receiver_proxy_port, "/last-message");
    let auto_handle = last_message["ref"]
        .as_str()
        .expect("receiver should record the auto-materialized handle");
    assert!(
        !auto_handle.starts_with("amber://ref/"),
        "a2a delivery should auto-materialize the ref, got {auto_handle}"
    );
    assert!(
        auto_handle.starts_with("http://127.0.0.1:"),
        "auto-materialization should yield a local loopback handle, got {auto_handle}"
    );

    let receiver_held = app_get_json(receiver_proxy_port, "/held");
    assert!(
        receiver_held["held"]
            .as_array()
            .is_some_and(|entries| entries.iter().any(|entry| {
                entry["entry_kind"] == "delegated_grant"
                    && entry["state"] == "live"
                    && entry["materializations"]
                        .as_array()
                        .is_some_and(|materializations| !materializations.is_empty())
            })),
        "auto-materialization should register a local handle in held inventory: {receiver_held}"
    );

    let (inspect_status, inspect_body) = app_post_json(
        receiver_proxy_port,
        "/inspect-handle",
        &json!({ "handle": auto_handle }),
    );
    let inspect = response_json(inspect_status, &inspect_body, "inspect handle");
    assert_eq!(inspect["state"], "live");

    let (call_status, call_body) = http_get_with_timeout(
        receiver_proxy_port,
        "/call-last-message-field?field=ref&suffix=/id",
        Duration::from_secs(30),
    )
    .expect("receiver should answer call-last-message-field");
    assert_eq!(
        call_status, 200,
        "auto-materialized handle should work: {call_body}"
    );
    assert_eq!(call_body, "provider");

    let (note_share_status, note_share_body) = app_post_json(
        sender_proxy_port,
        "/share",
        &json!({
            "source_kind": "held_id",
            "value": sender_root,
            "recipient": "components./receiver"
        }),
    );
    let note_share = response_json(note_share_status, &note_share_body, "note-only share");
    let note_ref = note_share["ref"]
        .as_str()
        .expect("note-only share should return a ref");
    let note_grant_id = note_share["grant_id"]
        .as_str()
        .expect("note-only share should return a grant id");

    let (message_status, message_body) = app_post_json(
        receiver_proxy_port,
        "/message",
        &json!({ "note": note_ref }),
    );
    assert_eq!(
        message_status, 200,
        "receiver should accept note-only a2a payloads: {message_body}"
    );
    let last_message = app_get_json(receiver_proxy_port, "/last-message");
    assert_eq!(last_message["note"], note_ref);

    let receiver_held = app_get_json(receiver_proxy_port, "/held");
    let note_entry = receiver_held["held"]
        .as_array()
        .and_then(|entries| {
            entries
                .iter()
                .find(|entry| entry["grant_id"] == note_grant_id)
                .cloned()
        })
        .expect("receiver should list the note-only grant");
    assert!(
        note_entry["materializations"]
            .as_array()
            .is_some_and(|materializations| materializations.is_empty()),
        "non-capability-bearing fields must not auto-materialize refs: {note_entry}"
    );

    let (note_materialize_status, note_materialize_body) = app_post_json(
        receiver_proxy_port,
        "/materialize-last-message-ref?field=note",
        &json!({}),
    );
    let note_materialized = response_json(
        note_materialize_status,
        &note_materialize_body,
        "explicit materialization from non-ref field",
    );
    let note_handle = note_materialized["url"]
        .as_str()
        .expect("explicit materialization should return a url");
    let (note_call_status, note_call_body) = http_get_with_timeout(
        receiver_proxy_port,
        "/call-last-message-field?field=note&suffix=/id",
        Duration::from_secs(30),
    )
    .expect("receiver should answer call-last-message-field for note");
    assert_eq!(
        note_call_status, 502,
        "non-ref fields should remain raw refs until explicitly materialized: {note_call_body}"
    );
    let (explicit_call_status, explicit_call_body) = app_post_json(
        receiver_proxy_port,
        "/call-url",
        &json!({ "url": note_handle, "suffix": "/id" }),
    );
    assert_eq!(
        explicit_call_status, 200,
        "explicitly materialized handle should work: {explicit_call_body}"
    );
    assert_eq!(explicit_call_body, "provider");

    stop_proxy(&mut receiver_proxy);
    stop_proxy(&mut sender_proxy);
    run.stop();
}

#[test]
#[ignore = "requires a working direct runtime sandbox; run manually or in CI"]
fn dynamic_capabilities_three_site_transit_live() {
    let temp = temp_output_dir("dynamic-caps-transit-");
    let a_port = pick_free_port();
    let b_port = pick_free_port();
    let c_port = pick_free_port();

    fs::write(temp.path().join("dynamic_caps_app.py"), DYNAMIC_CAPS_APP)
        .expect("failed to write dynamic_caps_app.py");
    write_dynamic_caps_component(temp.path(), "a.json5", false, "a", a_port, "http", &[], &[]);
    write_dynamic_caps_component(temp.path(), "b.json5", false, "b", b_port, "http", &[], &[]);
    write_dynamic_caps_component(temp.path(), "c.json5", false, "c", c_port, "http", &[], &[]);

    let manifest = temp.path().join("root.json5");
    write_json(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "components": {
                "a": "./a.json5",
                "b": "./b.json5",
                "c": "./c.json5"
            },
            "exports": {
                "a_api": "#a.api",
                "b_api": "#b.api",
                "c_api": "#c.api"
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
                "direct_a": { "kind": "direct" },
                "direct_b": { "kind": "direct" },
                "direct_c": { "kind": "direct" }
            },
            "defaults": {
                "path": "direct_a"
            },
            "components": {
                "/a": "direct_a",
                "/b": "direct_b",
                "/c": "direct_c"
            }
        }),
    );

    let storage_root = temp.path().join("state");
    let mut run = run_manifest(&manifest, &placement, &storage_root);
    wait_for_state_status(
        &run.run_root,
        "direct_a",
        "running",
        Duration::from_secs(60),
    );
    wait_for_state_status(
        &run.run_root,
        "direct_b",
        "running",
        Duration::from_secs(60),
    );
    wait_for_state_status(
        &run.run_root,
        "direct_c",
        "running",
        Duration::from_secs(60),
    );

    let a_proxy_port = pick_free_port();
    let mut a_proxy = spawn_proxy(
        &run.site_artifact_dir("direct_a"),
        "a_api",
        a_proxy_port,
        &[],
    );
    wait_for_path(&mut a_proxy, a_proxy_port, "/id", Duration::from_secs(60));
    let b_proxy_port = pick_free_port();
    let mut b_proxy = spawn_proxy(
        &run.site_artifact_dir("direct_b"),
        "b_api",
        b_proxy_port,
        &[],
    );
    wait_for_path(&mut b_proxy, b_proxy_port, "/id", Duration::from_secs(60));
    let c_proxy_port = pick_free_port();
    let mut c_proxy = spawn_proxy(
        &run.site_artifact_dir("direct_c"),
        "c_api",
        c_proxy_port,
        &[],
    );
    wait_for_path(&mut c_proxy, c_proxy_port, "/id", Duration::from_secs(60));

    let a_root = held_id_with_kind(&app_get_json(a_proxy_port, "/held"), "root_authority");
    let (share_b_status, share_b_body) = app_post_json(
        a_proxy_port,
        "/share",
        &json!({
            "source_kind": "held_id",
            "value": a_root,
            "recipient": "components./b"
        }),
    );
    let _share_b = response_json(share_b_status, &share_b_body, "share a->b");

    let b_held = app_get_json(b_proxy_port, "/held");
    let b_grant = delegated_held_id_from_component(&b_held, "components./a");
    let (share_c_status, share_c_body) = app_post_json(
        b_proxy_port,
        "/share",
        &json!({
            "source_kind": "held_id",
            "value": b_grant,
            "recipient": "components./c"
        }),
    );
    let share_c = response_json(share_c_status, &share_c_body, "share b->c");
    let c_ref = share_c["ref"].as_str().expect("share should return a ref");

    let (materialize_status, materialize_body) =
        app_post_json(c_proxy_port, "/materialize", &json!({ "ref": c_ref }));
    let materialized = response_json(materialize_status, &materialize_body, "materialize c ref");
    let c_handle = materialized["url"]
        .as_str()
        .expect("materialize should return a url");

    let (call_status, call_body) = app_post_json(
        c_proxy_port,
        "/call-url",
        &json!({ "url": c_handle, "suffix": "/id" }),
    );
    assert_eq!(
        call_status, 200,
        "c should use the transit capability: {call_body}"
    );
    assert_eq!(call_body, "a");

    let (revoke_status, revoke_body) =
        app_post_json(b_proxy_port, "/revoke", &json!({ "held_id": b_grant }));
    let revoke = response_json(revoke_status, &revoke_body, "revoke b grant");
    assert_eq!(revoke["outcome"], "revoked");

    let (revoked_call_status, revoked_call_body) = app_post_json(
        c_proxy_port,
        "/call-url",
        &json!({ "url": c_handle, "suffix": "/id" }),
    );
    assert_ne!(
        revoked_call_status, 200,
        "revoking the middle hop should remove c's access, got: {revoked_call_body}"
    );

    stop_proxy(&mut c_proxy);
    stop_proxy(&mut b_proxy);
    stop_proxy(&mut a_proxy);
    run.stop();
}

#[test]
#[ignore = "requires a working direct runtime sandbox; run manually or in CI"]
fn dynamic_capabilities_diamond_revocation_live() {
    let temp = temp_output_dir("dynamic-caps-diamond-");
    let a_port = pick_free_port();
    let b_port = pick_free_port();
    let c_port = pick_free_port();
    let d_port = pick_free_port();

    fs::write(temp.path().join("dynamic_caps_app.py"), DYNAMIC_CAPS_APP)
        .expect("failed to write dynamic_caps_app.py");
    write_dynamic_caps_component(temp.path(), "a.json5", false, "a", a_port, "http", &[], &[]);
    write_dynamic_caps_component(temp.path(), "b.json5", false, "b", b_port, "http", &[], &[]);
    write_dynamic_caps_component(temp.path(), "c.json5", false, "c", c_port, "http", &[], &[]);
    write_dynamic_caps_component(temp.path(), "d.json5", false, "d", d_port, "http", &[], &[]);

    let manifest = temp.path().join("root.json5");
    write_json(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "components": {
                "a": "./a.json5",
                "b": "./b.json5",
                "c": "./c.json5",
                "d": "./d.json5"
            },
            "exports": {
                "a_api": "#a.api",
                "b_api": "#b.api",
                "c_api": "#c.api",
                "d_api": "#d.api"
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
                "direct_a": { "kind": "direct" },
                "direct_b": { "kind": "direct" },
                "direct_c": { "kind": "direct" },
                "direct_d": { "kind": "direct" }
            },
            "defaults": {
                "path": "direct_a"
            },
            "components": {
                "/a": "direct_a",
                "/b": "direct_b",
                "/c": "direct_c",
                "/d": "direct_d"
            }
        }),
    );

    let storage_root = temp.path().join("state");
    let mut run = run_manifest(&manifest, &placement, &storage_root);
    for site in ["direct_a", "direct_b", "direct_c", "direct_d"] {
        wait_for_state_status(&run.run_root, site, "running", Duration::from_secs(60));
    }

    let a_proxy_port = pick_free_port();
    let mut a_proxy = spawn_proxy(
        &run.site_artifact_dir("direct_a"),
        "a_api",
        a_proxy_port,
        &[],
    );
    wait_for_path(&mut a_proxy, a_proxy_port, "/id", Duration::from_secs(60));
    let b_proxy_port = pick_free_port();
    let mut b_proxy = spawn_proxy(
        &run.site_artifact_dir("direct_b"),
        "b_api",
        b_proxy_port,
        &[],
    );
    wait_for_path(&mut b_proxy, b_proxy_port, "/id", Duration::from_secs(60));
    let c_proxy_port = pick_free_port();
    let mut c_proxy = spawn_proxy(
        &run.site_artifact_dir("direct_c"),
        "c_api",
        c_proxy_port,
        &[],
    );
    wait_for_path(&mut c_proxy, c_proxy_port, "/id", Duration::from_secs(60));
    let d_proxy_port = pick_free_port();
    let mut d_proxy = spawn_proxy(
        &run.site_artifact_dir("direct_d"),
        "d_api",
        d_proxy_port,
        &[],
    );
    wait_for_path(&mut d_proxy, d_proxy_port, "/id", Duration::from_secs(60));

    let a_root = held_id_with_kind(&app_get_json(a_proxy_port, "/held"), "root_authority");
    let share_b = response_json_from(
        app_post_json(
            a_proxy_port,
            "/share",
            &json!({
                "source_kind": "held_id",
                "value": a_root,
                "recipient": "components./b"
            }),
        ),
        "share a->b",
    );
    let share_c = response_json_from(
        app_post_json(
            a_proxy_port,
            "/share",
            &json!({
                "source_kind": "held_id",
                "value": a_root,
                "recipient": "components./c"
            }),
        ),
        "share a->c",
    );
    let _ = share_b;
    let _ = share_c;

    let b_grant =
        delegated_held_id_from_component(&app_get_json(b_proxy_port, "/held"), "components./a");
    let c_grant =
        delegated_held_id_from_component(&app_get_json(c_proxy_port, "/held"), "components./a");
    let share_bd = response_json_from(
        app_post_json(
            b_proxy_port,
            "/share",
            &json!({
                "source_kind": "held_id",
                "value": b_grant,
                "recipient": "components./d"
            }),
        ),
        "share b->d",
    );
    let share_cd = response_json_from(
        app_post_json(
            c_proxy_port,
            "/share",
            &json!({
                "source_kind": "held_id",
                "value": c_grant,
                "recipient": "components./d"
            }),
        ),
        "share c->d",
    );
    let ref_bd = share_bd["ref"]
        .as_str()
        .expect("b->d share should return a ref");
    let ref_cd = share_cd["ref"]
        .as_str()
        .expect("c->d share should return a ref");

    let handle_bd = response_json_from(
        app_post_json(d_proxy_port, "/materialize", &json!({ "ref": ref_bd })),
        "materialize b->d ref",
    )["url"]
        .as_str()
        .expect("materialize should return a url")
        .to_string();
    let handle_cd = response_json_from(
        app_post_json(d_proxy_port, "/materialize", &json!({ "ref": ref_cd })),
        "materialize c->d ref",
    )["url"]
        .as_str()
        .expect("materialize should return a url")
        .to_string();

    let (call_bd_status, call_bd_body) = app_post_json(
        d_proxy_port,
        "/call-url",
        &json!({ "url": handle_bd, "suffix": "/id" }),
    );
    let (call_cd_status, call_cd_body) = app_post_json(
        d_proxy_port,
        "/call-url",
        &json!({ "url": handle_cd, "suffix": "/id" }),
    );
    assert_eq!(call_bd_status, 200, "b path should work: {call_bd_body}");
    assert_eq!(call_cd_status, 200, "c path should work: {call_cd_body}");
    assert_eq!(call_bd_body, "a");
    assert_eq!(call_cd_body, "a");

    let _ = response_json_from(
        app_post_json(c_proxy_port, "/revoke", &json!({ "held_id": c_grant })),
        "revoke c grant",
    );
    let (post_c_revoke_b_status, post_c_revoke_b_body) = app_post_json(
        d_proxy_port,
        "/call-url",
        &json!({ "url": handle_bd, "suffix": "/id" }),
    );
    let (post_c_revoke_c_status, post_c_revoke_c_body) = app_post_json(
        d_proxy_port,
        "/call-url",
        &json!({ "url": handle_cd, "suffix": "/id" }),
    );
    assert_eq!(
        post_c_revoke_b_status, 200,
        "d should retain access through b after c revokes: {post_c_revoke_b_body}"
    );
    assert_ne!(
        post_c_revoke_c_status, 200,
        "d should lose the c-derived path after c revokes: {post_c_revoke_c_body}"
    );

    let _ = response_json_from(
        app_post_json(b_proxy_port, "/revoke", &json!({ "held_id": b_grant })),
        "revoke b grant",
    );
    let (post_b_revoke_status, post_b_revoke_body) = app_post_json(
        d_proxy_port,
        "/call-url",
        &json!({ "url": handle_bd, "suffix": "/id" }),
    );
    assert_ne!(
        post_b_revoke_status, 200,
        "d should lose all access once b also revokes: {post_b_revoke_body}"
    );

    stop_proxy(&mut d_proxy);
    stop_proxy(&mut c_proxy);
    stop_proxy(&mut b_proxy);
    stop_proxy(&mut a_proxy);
    run.stop();
}

#[test]
#[ignore = "requires a working direct runtime sandbox; run manually or in CI"]
fn dynamic_capabilities_external_slot_root_share_live() {
    let temp = temp_output_dir("dynamic-caps-external-root-");
    let catalog = HostHttpServer::start();
    let catalog_url = format!("http://127.0.0.1:{}", catalog.port());
    let root_port = pick_free_port();
    let receiver_port = pick_free_port();

    fs::write(temp.path().join("dynamic_caps_app.py"), DYNAMIC_CAPS_APP)
        .expect("failed to write dynamic_caps_app.py");
    write_dynamic_caps_component(
        temp.path(),
        "receiver.json5",
        false,
        "receiver",
        receiver_port,
        "http",
        &[],
        &[],
    );
    write_json(
        &temp.path().join("root.json5"),
        &json!({
            "manifest_version": "0.3.0",
            "slots": {
                "catalog_api": { "kind": "http" }
            },
            "program": {
                "path": "/usr/bin/env",
                "args": ["python3", "-u", "-c", { "file": "./dynamic_caps_app.py" }],
                "env": {
                    "NAME": "root",
                    "PORT": root_port.to_string(),
                    "UPSTREAM_CATALOG_API": "${slots.catalog_api.url}"
                },
                "network": {
                    "endpoints": [
                        { "name": "http", "port": root_port, "protocol": "http" }
                    ]
                }
            },
            "provides": {
                "api": { "kind": "http", "endpoint": "http" }
            },
            "components": {
                "receiver": "./receiver.json5"
            },
            "exports": {
                "root_api": "api",
                "receiver_api": "#receiver.api"
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
    let mut run = run_manifest_with_env(
        &temp.path().join("root.json5"),
        &placement,
        &storage_root,
        &[("AMBER_EXTERNAL_SLOT_CATALOG_API_URL", catalog_url.as_str())],
    );
    wait_for_state_status(
        &run.run_root,
        "direct_local",
        "running",
        Duration::from_secs(60),
    );

    let root_proxy_port = pick_free_port();
    let mut root_proxy = spawn_proxy(
        &run.site_artifact_dir("direct_local"),
        "root_api",
        root_proxy_port,
        &[],
    );
    wait_for_path(
        &mut root_proxy,
        root_proxy_port,
        "/id",
        Duration::from_secs(60),
    );
    let receiver_proxy_port = pick_free_port();
    let mut receiver_proxy = spawn_proxy(
        &run.site_artifact_dir("direct_local"),
        "receiver_api",
        receiver_proxy_port,
        &[],
    );
    wait_for_path(
        &mut receiver_proxy,
        receiver_proxy_port,
        "/id",
        Duration::from_secs(60),
    );

    let root_held = app_get_json(root_proxy_port, "/held");
    let root_authority = held_id_with_kind(&root_held, "root_authority");
    let (root_materialize_status, root_materialize_body) = app_post_json(
        root_proxy_port,
        "/materialize",
        &json!({ "held_id": root_authority }),
    );
    let root_materialized = response_json(
        root_materialize_status,
        &root_materialize_body,
        "materialize root authority",
    );
    let root_handle = root_materialized["url"]
        .as_str()
        .expect("root materialization should return a url");
    let (root_call_status, root_call_body) = app_post_json(
        root_proxy_port,
        "/call-url",
        &json!({ "url": root_handle, "suffix": "/item/amber-mug" }),
    );
    assert_eq!(
        root_call_status, 200,
        "root should use the external slot directly: {root_call_body}"
    );
    assert_eq!(
        root_call_body,
        r#"{"source":"external","item":"amber mug"}"#
    );

    let (share_status, share_body) = app_post_json(
        root_proxy_port,
        "/share",
        &json!({
            "source_kind": "held_id",
            "value": root_authority,
            "recipient": "components./receiver"
        }),
    );
    let share = response_json(share_status, &share_body, "share external root");
    let shared_ref = share["ref"].as_str().expect("share should return a ref");

    let (receiver_materialize_status, receiver_materialize_body) = app_post_json(
        receiver_proxy_port,
        "/materialize",
        &json!({ "ref": shared_ref }),
    );
    let receiver_materialized = response_json(
        receiver_materialize_status,
        &receiver_materialize_body,
        "materialize receiver ref",
    );
    let receiver_handle = receiver_materialized["url"]
        .as_str()
        .expect("receiver materialization should return a url");
    let (receiver_call_status, receiver_call_body) = app_post_json(
        receiver_proxy_port,
        "/call-url",
        &json!({ "url": receiver_handle, "suffix": "/item/amber-mug" }),
    );
    assert_eq!(
        receiver_call_status, 200,
        "shared external-root grant should be usable: {receiver_call_body}"
    );
    assert_eq!(
        receiver_call_body,
        r#"{"source":"external","item":"amber mug"}"#
    );

    let receiver_grant = delegated_held_id_from_component(
        &app_get_json(receiver_proxy_port, "/held"),
        "components./",
    );
    let _ = response_json_from(
        app_post_json(
            receiver_proxy_port,
            "/revoke",
            &json!({ "held_id": receiver_grant }),
        ),
        "revoke receiver grant",
    );

    let (revoked_status, revoked_body) = app_post_json(
        receiver_proxy_port,
        "/call-url",
        &json!({ "url": receiver_handle, "suffix": "/item/amber-mug" }),
    );
    assert_ne!(
        revoked_status, 200,
        "revoked external-root grant should stop working: {revoked_body}"
    );
    assert_eq!(
        held_id_with_kind(&app_get_json(root_proxy_port, "/held"), "root_authority"),
        root_authority,
        "root holder must retain its directly held external authority"
    );

    stop_proxy(&mut receiver_proxy);
    stop_proxy(&mut root_proxy);
    run.stop();
}

#[test]
#[ignore = "requires a working direct runtime sandbox; run manually or in CI"]
fn dynamic_capabilities_dynamic_child_post_create_share_live() {
    let temp = temp_output_dir("dynamic-caps-dynamic-child-");
    let admin_port = pick_free_port();
    let provider_port = pick_free_port();
    let consumer_port = pick_free_port();
    let child_port = pick_free_port();

    fs::write(temp.path().join("admin.py"), FRAMEWORK_ADMIN_APP).expect("failed to write admin.py");
    fs::write(temp.path().join("dynamic_caps_app.py"), DYNAMIC_CAPS_APP)
        .expect("failed to write dynamic_caps_app.py");
    write_framework_admin_component(temp.path(), "admin.json5", false, admin_port);
    write_dynamic_caps_component(
        temp.path(),
        "provider.json5",
        false,
        "provider",
        provider_port,
        "http",
        &[],
        &[],
    );
    write_dynamic_caps_component(
        temp.path(),
        "consumer.json5",
        false,
        "consumer",
        consumer_port,
        "http",
        &[],
        &[],
    );
    write_dynamic_caps_component(
        temp.path(),
        "child.json5",
        false,
        "child",
        child_port,
        "http",
        &[],
        &[],
    );
    let child_manifest_url = framework_manifest_url(&temp.path().join("child.json5"));

    let manifest = temp.path().join("root.json5");
    write_json(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "slots": {
                "realm": { "kind": "component", "optional": true }
            },
            "components": {
                "admin": "./admin.json5",
                "provider": "./provider.json5",
                "consumer": "./consumer.json5"
            },
            "child_templates": {
                "open_worker": {}
            },
            "bindings": [
                { "to": "#admin.ctl", "from": "framework.component" }
            ],
            "exports": {
                "admin_http": "#admin.http",
                "provider_api": "#provider.api",
                "consumer_api": "#consumer.api"
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
    wait_for_state_status(
        &run.run_root,
        "direct_local",
        "running",
        Duration::from_secs(60),
    );

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
    let provider_proxy_port = pick_free_port();
    let mut provider_proxy = spawn_proxy(
        &run.site_artifact_dir("direct_local"),
        "provider_api",
        provider_proxy_port,
        &[],
    );
    wait_for_path(
        &mut provider_proxy,
        provider_proxy_port,
        "/id",
        Duration::from_secs(60),
    );
    let consumer_proxy_port = pick_free_port();
    let mut consumer_proxy = spawn_proxy(
        &run.site_artifact_dir("direct_local"),
        "consumer_api",
        consumer_proxy_port,
        &[],
    );
    wait_for_path(
        &mut consumer_proxy,
        consumer_proxy_port,
        "/id",
        Duration::from_secs(60),
    );

    let (create_status, create_body) = framework_create_child_with_request(
        admin_proxy_port,
        &json!({
            "template": "open_worker",
            "name": "job-dynamic",
            "manifest": child_manifest_url
        }),
    );
    assert_eq!(
        create_status, 200,
        "dynamic child create should succeed: {create_body}"
    );
    let control_state_path = framework_control_state_path(&run);
    let child_id = wait_for_live_child(&control_state_path, "job-dynamic");
    let child_artifact = framework_child_artifact(&run, "direct_local", child_id);
    let child_proxy_port = pick_free_port();
    let mut child_proxy = spawn_proxy(&child_artifact, "api", child_proxy_port, &[]);
    wait_for_path(
        &mut child_proxy,
        child_proxy_port,
        "/id",
        Duration::from_secs(60),
    );

    let provider_root = held_id_with_kind(
        &app_get_json(provider_proxy_port, "/held"),
        "root_authority",
    );
    let (share_status, share_body) = app_post_json(
        provider_proxy_port,
        "/share",
        &json!({
            "source_kind": "held_id",
            "value": provider_root,
            "recipient": "components./job-dynamic"
        }),
    );
    let share = response_json(share_status, &share_body, "share to dynamic child");
    let _shared_ref = share["ref"].as_str().expect("share should return a ref");

    let child_grant = delegated_held_id_from_component(
        &app_get_json(child_proxy_port, "/held"),
        "components./provider",
    );
    let (child_materialize_status, child_materialize_body) = app_post_json(
        child_proxy_port,
        "/materialize",
        &json!({ "held_id": child_grant }),
    );
    let child_materialized = response_json(
        child_materialize_status,
        &child_materialize_body,
        "child materialization",
    );
    let child_handle = child_materialized["url"]
        .as_str()
        .expect("child materialization should return a url");
    let (child_call_status, child_call_body) = app_post_json(
        child_proxy_port,
        "/call-url",
        &json!({ "url": child_handle, "suffix": "/id" }),
    );
    assert_eq!(
        child_call_status, 200,
        "child should use the shared capability: {child_call_body}"
    );
    assert_eq!(child_call_body, "provider");

    let (reshare_status, reshare_body) = app_post_json(
        child_proxy_port,
        "/share",
        &json!({
            "source_kind": "held_id",
            "value": child_grant,
            "recipient": "components./consumer"
        }),
    );
    let _reshare = response_json(reshare_status, &reshare_body, "child reshare");
    let consumer_grant = delegated_held_id_from_component(
        &app_get_json(consumer_proxy_port, "/held"),
        "components./job-dynamic",
    );
    let (consumer_materialize_status, consumer_materialize_body) = app_post_json(
        consumer_proxy_port,
        "/materialize",
        &json!({ "held_id": consumer_grant }),
    );
    let consumer_materialized = response_json(
        consumer_materialize_status,
        &consumer_materialize_body,
        "consumer materialization",
    );
    let consumer_handle = consumer_materialized["url"]
        .as_str()
        .expect("consumer materialization should return a url");
    let (consumer_call_status, consumer_call_body) = app_post_json(
        consumer_proxy_port,
        "/call-url",
        &json!({ "url": consumer_handle, "suffix": "/id" }),
    );
    assert_eq!(
        consumer_call_status, 200,
        "consumer should use the dynamic child's reshared capability: {consumer_call_body}"
    );
    assert_eq!(consumer_call_body, "provider");

    stop_proxy(&mut child_proxy);
    stop_proxy(&mut consumer_proxy);
    stop_proxy(&mut provider_proxy);
    stop_proxy(&mut admin_proxy);
    run.stop();
}

#[test]
#[ignore = "requires a working direct runtime sandbox; run manually or in CI"]
fn dynamic_capabilities_snapshot_replay_dynamic_child_live() {
    let temp = temp_output_dir("dynamic-caps-replay-child-");
    let admin_port = pick_free_port();
    let provider_port = pick_free_port();
    let child_port = pick_free_port();

    fs::write(temp.path().join("admin.py"), FRAMEWORK_ADMIN_APP).expect("failed to write admin.py");
    fs::write(temp.path().join("dynamic_caps_app.py"), DYNAMIC_CAPS_APP)
        .expect("failed to write dynamic_caps_app.py");
    write_framework_admin_component(temp.path(), "admin.json5", false, admin_port);
    write_dynamic_caps_component(
        temp.path(),
        "provider.json5",
        false,
        "provider",
        provider_port,
        "http",
        &[],
        &[],
    );
    write_dynamic_caps_component(
        temp.path(),
        "child.json5",
        false,
        "child",
        child_port,
        "http",
        &[],
        &[],
    );
    let child_manifest_url = framework_manifest_url(&temp.path().join("child.json5"));

    let manifest = temp.path().join("root.json5");
    write_json(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "slots": {
                "realm": { "kind": "component", "optional": true }
            },
            "components": {
                "admin": "./admin.json5",
                "provider": "./provider.json5"
            },
            "child_templates": {
                "open_worker": {}
            },
            "bindings": [
                { "to": "#admin.ctl", "from": "framework.component" }
            ],
            "exports": {
                "admin_http": "#admin.http",
                "provider_api": "#provider.api"
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
    wait_for_state_status(
        &run.run_root,
        "direct_local",
        "running",
        Duration::from_secs(60),
    );

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
    let provider_proxy_port = pick_free_port();
    let mut provider_proxy = spawn_proxy(
        &run.site_artifact_dir("direct_local"),
        "provider_api",
        provider_proxy_port,
        &[],
    );
    wait_for_path(
        &mut provider_proxy,
        provider_proxy_port,
        "/id",
        Duration::from_secs(60),
    );

    let (create_status, create_body) = framework_create_child_with_request(
        admin_proxy_port,
        &json!({
            "template": "open_worker",
            "name": "job-replay",
            "manifest": child_manifest_url
        }),
    );
    assert_eq!(
        create_status, 200,
        "dynamic child create should succeed: {create_body}"
    );
    let control_state_path = framework_control_state_path(&run);
    let child_id = wait_for_live_child(&control_state_path, "job-replay");
    let child_artifact = framework_child_artifact(&run, "direct_local", child_id);
    let child_proxy_port = pick_free_port();
    let mut child_proxy = spawn_proxy(&child_artifact, "api", child_proxy_port, &[]);
    wait_for_path(
        &mut child_proxy,
        child_proxy_port,
        "/id",
        Duration::from_secs(60),
    );

    let provider_root = held_id_with_kind(
        &app_get_json(provider_proxy_port, "/held"),
        "root_authority",
    );
    let (share_status, share_body) = app_post_json(
        provider_proxy_port,
        "/share",
        &json!({
            "source_kind": "held_id",
            "value": provider_root,
            "recipient": "components./job-replay"
        }),
    );
    let share = response_json(share_status, &share_body, "share to replay child");
    let old_ref = share["ref"]
        .as_str()
        .expect("share should return a ref")
        .to_string();

    let snapshot = framework_snapshot_via_admin(admin_proxy_port);

    stop_proxy(&mut child_proxy);
    stop_proxy(&mut provider_proxy);
    stop_proxy(&mut admin_proxy);
    run.stop();

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
    wait_for_state_status(
        &replay_run.run_root,
        "direct_local",
        "running",
        Duration::from_secs(60),
    );

    let replay_provider_proxy_port = pick_free_port();
    let mut replay_provider_proxy = spawn_proxy(
        &replay_run.site_artifact_dir("direct_local"),
        "provider_api",
        replay_provider_proxy_port,
        &[],
    );
    wait_for_path(
        &mut replay_provider_proxy,
        replay_provider_proxy_port,
        "/id",
        Duration::from_secs(60),
    );
    let replay_control_state = framework_control_state_path(&replay_run);
    wait_for_condition(
        Duration::from_secs(60),
        || {
            read_json(&replay_control_state)["base_scenario"]["components"]
                .as_array()
                .is_some_and(|components| {
                    components
                        .iter()
                        .any(|component| component["moniker"] == "/job-replay")
                })
        },
        "replayed child `job-replay` in the replayed scenario graph",
    );
    wait_for_live_child(&replay_control_state, "job-replay");
    let replay_held = response_json_from(
        framework_control_state_post(
            &replay_run,
            "/v1/control-state/dynamic-caps/held",
            &json!({
                "holder_component_id": "components./job-replay"
            }),
        ),
        "replay child held list",
    );
    let replay_grant = delegated_held_id_from_component(&replay_held, "components./provider");

    let replay_provider_root = held_id_with_kind(
        &app_get_json(replay_provider_proxy_port, "/held"),
        "root_authority",
    );
    let replay_share = response_json_from(
        app_post_json(
            replay_provider_proxy_port,
            "/share",
            &json!({
                "source_kind": "held_id",
                "value": replay_provider_root,
                "recipient": "components./job-replay"
            }),
        ),
        "share to replayed child",
    );
    assert!(
        matches!(
            replay_share["outcome"].as_str(),
            Some("created" | "deduplicated")
        ),
        "replay share should create or deduplicate a live grant: {replay_share}"
    );
    let replay_ref = replay_share["ref"]
        .as_str()
        .expect("replay share should return a ref");
    let replay_grant_id = replay_share["grant_id"]
        .as_str()
        .expect("replay share should return a grant id");

    let replay_ref_detail = response_json_from(
        framework_control_state_post(
            &replay_run,
            "/v1/control-state/dynamic-caps/inspect-ref",
            &json!({
                "holder_component_id": "components./job-replay",
                "ref": replay_ref
            }),
        ),
        "replay child ref inspection",
    );
    assert_eq!(replay_ref_detail["state"], "live");
    assert_eq!(
        replay_ref_detail["holder_component_id"],
        "components./job-replay"
    );
    assert_eq!(replay_ref_detail["grant_id"], replay_grant_id);
    let replay_shared_held_id = replay_ref_detail["held_id"]
        .as_str()
        .expect("replay ref inspection should return a held id")
        .to_string();

    let replay_held_detail = response_json_from(
        framework_control_state_post(
            &replay_run,
            "/v1/control-state/dynamic-caps/held/detail",
            &json!({
                "holder_component_id": "components./job-replay",
                "held_id": replay_shared_held_id
            }),
        ),
        "replay child held detail",
    );
    assert_eq!(replay_held_detail["held_id"], replay_shared_held_id);
    assert_eq!(replay_held_detail["state"], "live");
    assert_eq!(
        replay_held_detail["sharer_component_id"],
        "components./provider"
    );
    assert_eq!(
        replay_held_detail["holder_component_id"],
        "components./job-replay"
    );
    assert!(
        replay_shared_held_id == replay_grant || replay_share["outcome"] == "created",
        "replay should either reuse the restored grant or create a new live one"
    );

    let (old_ref_status, old_ref_body) = framework_control_state_post(
        &replay_run,
        "/v1/control-state/dynamic-caps/inspect-ref",
        &json!({
            "holder_component_id": "components./job-replay",
            "ref": old_ref
        }),
    );
    assert_eq!(
        old_ref_status, 400,
        "old run refs should be rejected after replay"
    );
    assert!(
        old_ref_body.contains("different run"),
        "old ref failure should explain the run mismatch, got: {old_ref_body}"
    );

    stop_proxy(&mut replay_provider_proxy);
    replay_run.stop();
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
