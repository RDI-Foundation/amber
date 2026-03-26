import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen

API_URL = os.environ["API_URL"].rstrip("/")
PORT = int(os.environ.get("PORT", "8080"))
TENANT = os.environ["TENANT"]


def fetch_json(path: str, timeout: float = 10.0) -> object:
    request = Request(f"{API_URL}{path}", headers={"Connection": "close"})
    with urlopen(request, timeout=timeout) as response:
        return json.load(response)


def send_json(handler: BaseHTTPRequestHandler, status: int, payload: object) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("content-type", "application/json; charset=utf-8")
    handler.send_header("content-length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/":
            send_json(
                self,
                200,
                {
                    "site": "direct",
                    "tenant": TENANT,
                    "api": f"{API_URL}/debug",
                },
            )
            return
        if self.path == "/chain":
            send_json(
                self,
                200,
                {
                    "site": "direct",
                    "api": fetch_json("/debug"),
                },
            )
            return
        send_json(self, 404, {"error": "not found"})

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[web] {fmt % args}", flush=True)


ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
