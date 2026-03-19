import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen

PORT = int(os.environ.get("PORT", "8080"))
VAULT_URL = os.environ["VAULT_URL"].rstrip("/")


def fetch_text(url: str) -> str:
    request = Request(url, headers={"Connection": "close"})
    with urlopen(request, timeout=10) as response:
        return response.read().decode("utf-8").strip()


def send_json(handler: BaseHTTPRequestHandler, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(200)
    handler.send_header("content-type", "application/json; charset=utf-8")
    handler.send_header("content-length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/id":
            send_json(self, {"site": "compose", "name": "queue"})
            return
        if self.path == "/next":
            send_json(self, {"site": "compose", "vault": fetch_text(f"{VAULT_URL}/id")})
            return
        self.send_error(404)

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[queue] {fmt % args}", flush=True)


ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
