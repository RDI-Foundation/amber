import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

NAME = os.environ["NAME"]
PORT = int(os.environ["PORT"])
CTL_URL = os.environ["CTL_URL"].rstrip("/")
DYNAMIC_CAPS_API_URL = os.environ.get("AMBER_DYNAMIC_CAPS_API_URL", "").rstrip("/")
FRAMEWORK_COMPONENT_TIMEOUT_SECS = 180


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


def call(method, path, payload=None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Connection": "close"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = Request(f"{CTL_URL}{path}", data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=FRAMEWORK_COMPONENT_TIMEOUT_SECS) as response:
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
            json.dumps(
                {"error": f"failed to reach framework.component service: {err.reason}"}
            ),
        )


def proxy(handler, method, path, payload=None):
    status, content_type, body = call(method, path, payload)
    send(handler, status, body or "", content_type)


def dynamic_caps_call(method, path, payload=None):
    if not DYNAMIC_CAPS_API_URL:
        return (
            503,
            "application/json; charset=utf-8",
            json.dumps({"error": "AMBER_DYNAMIC_CAPS_API_URL is not set"}),
        )
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Connection": "close"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = Request(
        f"{DYNAMIC_CAPS_API_URL}{path}",
        data=data,
        headers=headers,
        method=method,
    )
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
            json.dumps(
                {"error": f"failed to reach dynamic capabilities service: {err.reason}"}
            ),
        )


def admin_http_held_id():
    status, _, body = dynamic_caps_call("GET", "/v1/held")
    if status != 200:
        raise RuntimeError(f"GET /v1/held failed: {body}")
    held = json.loads(body)
    for entry in held.get("held", []):
        selector = entry.get("root_authority_selector", {})
        if (
            entry.get("entry_kind") == "root_authority"
            and entry.get("state") == "live"
            and selector.get("kind") == "self_provide"
            and selector.get("provide_name") == "http"
        ):
            return entry["held_id"]
    raise RuntimeError("missing live self-provided admin.http root authority")


def provision_child_capability(child_name):
    status, _, body = dynamic_caps_call(
        "POST",
        "/v1/share",
        {
            "source": {"kind": "held_id", "value": admin_http_held_id()},
            "recipient": f"components./{child_name}",
        },
    )
    if status != 200:
        raise RuntimeError(body)
    return json.loads(body)


def guide():
    return {
        "service": NAME,
        "routes": {
            "templates": "/templates",
            "template": "/templates/<name>",
            "resolve": "/resolve/<template>?manifest=<absolute-url>",
            "children": "/children",
            "child": "/children/<name>",
            "create": "/create/<child-name>?template=<template>&label=<label>&manifest=<absolute-url>",
            "destroy": "/destroy/<child-name>",
            "snapshot": "/snapshot",
        },
        "provisioning": {
            "create": "new children automatically receive the admin.http capability as a live delegated grant",
            "rediscover": "workers expose /held and /materialize so they can rediscover and use that grant",
        },
        "templates": {
            "exact_worker": "fixed manifest, runtime label required",
            "bounded_worker": "choose one manifest from /templates/bounded_worker",
            "open_worker": "supply any absolute manifest URL at create or resolve time",
        },
    }


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path, query = request_target(self.path)

        if path == "/":
            send_json(self, 200, guide())
            return
        if path == "/id":
            send(self, 200, NAME)
            return
        if path == "/templates":
            proxy(self, "GET", "/v1/templates")
            return
        if path.startswith("/templates/"):
            proxy(self, "GET", f"/v1/templates/{path.removeprefix('/templates/')}")
            return
        if path.startswith("/resolve/"):
            payload = {}
            if query.get("manifest"):
                payload["manifest"] = query["manifest"]
            proxy(
                self,
                "POST",
                f"/v1/templates/{path.removeprefix('/resolve/')}/resolve",
                payload,
            )
            return
        if path == "/children":
            proxy(self, "GET", "/v1/children")
            return
        if path.startswith("/children/"):
            proxy(self, "GET", f"/v1/children/{path.removeprefix('/children/')}")
            return
        if path.startswith("/create/"):
            template = query.get("template")
            if not template:
                send_json(self, 400, {"error": "missing `template` query parameter"})
                return
            payload = {
                "template": template,
                "name": path.removeprefix("/create/"),
            }
            if query.get("manifest"):
                payload["manifest"] = query["manifest"]
            if query.get("label"):
                payload["config"] = {"label": query["label"]}
            create_status, _, create_body = call("POST", "/v1/children", payload)
            if create_status != 200:
                send(self, create_status, create_body or "", "application/json; charset=utf-8")
                return
            child = json.loads(create_body or "{}")
            try:
                provisioning = provision_child_capability(payload["name"])
            except Exception as err:
                send_json(
                    self,
                    502,
                    {
                        "error": f"child created but capability provisioning failed: {err}",
                        "child": child,
                    },
                )
                return
            send_json(
                self,
                200,
                {
                    "child": child,
                    "provisioned_capability": {
                        "source": "admin.http",
                        "recipient": f"components./{payload['name']}",
                        "share": provisioning,
                    },
                },
            )
            return
        if path.startswith("/destroy/"):
            proxy(self, "DELETE", f"/v1/children/{path.removeprefix('/destroy/')}")
            return
        if path == "/snapshot":
            proxy(self, "POST", "/v1/snapshot", {})
            return
        send(self, 404, "missing")

    def log_message(self, fmt, *args):
        print(f"[admin] {fmt % args}", flush=True)


ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
