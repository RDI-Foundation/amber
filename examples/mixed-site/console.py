import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen

PORT = int(os.environ.get("PORT", "8080"))
QUEUE_URL = os.environ["QUEUE_URL"].rstrip("/")


def fetch_json(url: str) -> dict:
    request = Request(url, headers={"Connection": "close"})
    with urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


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
            send_json(self, {"site": "direct", "name": "console"})
            return
        if self.path == "/chain":
            send_json(self, {"site": "direct", "queue": fetch_json(f"{QUEUE_URL}/next")})
            return
        self.send_error(404)

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[console] {fmt % args}", flush=True)


ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
