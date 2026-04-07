import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

NAME = os.environ["NAME"]
PORT = int(os.environ["PORT"])
CTL_URL = os.environ["CTL_URL"].rstrip("/")


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
                {"error": f"failed to reach framework.component service: {err.reason}"}
            ),
        )


def proxy(handler, method, path, payload=None):
    status, content_type, body = call(method, path, payload)
    send(handler, status, body or "", content_type)


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
            proxy(self, "POST", "/v1/children", payload)
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
