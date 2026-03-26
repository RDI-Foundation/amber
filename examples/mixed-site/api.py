import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen

CATALOG_API_URL = os.environ.get("CATALOG_API_URL", "").rstrip("/")
CATALOG_TOKEN = os.environ.get("CATALOG_TOKEN", "")
PORT = int(os.environ.get("PORT", "8080"))
TENANT = os.environ["TENANT"]


def fetch_catalog(timeout: float = 5.0) -> object:
    if not CATALOG_API_URL:
        return {
            "source": "external",
            "available": False,
            "error": "missing catalog_api",
        }
    request = Request(
        f"{CATALOG_API_URL}/item/amber-mug",
        headers={
            "Authorization": f"Bearer {CATALOG_TOKEN}",
            "Connection": "close",
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except Exception as err:
        return {
            "source": "external",
            "available": False,
            "error": err.__class__.__name__,
        }


def send_json(handler: BaseHTTPRequestHandler, status: int, payload: object) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("content-type", "application/json; charset=utf-8")
    handler.send_header("content-length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path in {"/", "/debug"}:
            send_json(
                self,
                200,
                {
                    "site": "compose",
                    "tenant": TENANT,
                    "catalog_token_configured": bool(CATALOG_TOKEN),
                    "catalog": fetch_catalog(),
                },
            )
            return
        send_json(self, 404, {"error": "not found"})

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[api] {fmt % args}", flush=True)


ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
