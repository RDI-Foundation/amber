import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

NAME = os.environ["NAME"]
LABEL = os.environ["LABEL"]
PORT = int(os.environ["PORT"])
DYNAMIC_CAPS_API_URL = os.environ.get("AMBER_DYNAMIC_CAPS_API_URL", "").rstrip("/")


def send(handler, status, body):
    payload = body.encode("utf-8")
    handler.send_response(status)
    handler.send_header("content-type", "text/plain; charset=utf-8")
    handler.send_header("content-length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


def send_json(handler, status, payload):
    body = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    encoded = body.encode("utf-8")
    handler.send_response(status)
    handler.send_header("content-type", "application/json; charset=utf-8")
    handler.send_header("content-length", str(len(encoded)))
    handler.end_headers()
    handler.wfile.write(encoded)


def read_body(handler):
    length = int(handler.headers.get("content-length", "0") or "0")
    return handler.rfile.read(length).decode("utf-8") if length else ""


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
            json.dumps({"error": f"{err.__class__.__name__}: {err.reason}"}),
        )


def proxy(handler, method, path, payload=None):
    status, content_type, body = dynamic_caps_call(method, path, payload)
    encoded = (body or "").encode("utf-8")
    handler.send_response(status)
    handler.send_header("content-type", content_type)
    handler.send_header("content-length", str(len(encoded)))
    handler.end_headers()
    handler.wfile.write(encoded)


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
        if self.path in ("/", "/id"):
            send(self, 200, f"{NAME}:{LABEL}")
            return
        if self.path == "/held":
            proxy(self, "GET", "/v1/held")
            return
        send(self, 200, "ok")

    def do_POST(self):
        if self.path == "/materialize":
            proxy(self, "POST", "/v1/materialize", json.loads(read_body(self) or "{}"))
            return
        if self.path == "/call-url":
            payload = json.loads(read_body(self) or "{}")
            url = payload.get("url")
            if not url:
                send_json(self, 400, {"error": "missing url"})
                return
            try:
                send(self, 200, fetch_text(join_url(url, payload.get("suffix", ""))))
            except HTTPError as err:
                send(self, err.code, err.read().decode("utf-8", errors="replace"))
            except Exception as err:
                send_json(self, 502, {"error": f"{err.__class__.__name__}: {err}"})
            return
        send_json(self, 404, {"error": "missing"})

    def log_message(self, fmt, *args):
        print(f"[worker] {fmt % args}", flush=True)


ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
