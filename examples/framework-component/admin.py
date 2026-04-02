import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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


def call(method, path, payload=None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Connection": "close"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = Request(f"{CTL_URL}{path}", data=data, headers=headers, method=method)
    with urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
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
            name = self.path.removeprefix("/create/")
            send(
                self,
                200,
                call("POST", "/v1/children", {"template": "worker", "name": name}),
                "application/json",
            )
            return
        if self.path.startswith("/destroy/"):
            name = self.path.removeprefix("/destroy/")
            call("DELETE", f"/v1/children/{name}")
            send(self, 200, "destroyed")
            return
        send(self, 404, "missing")

    def log_message(self, fmt, *args):
        print(f"[admin] {fmt % args}", flush=True)


ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
