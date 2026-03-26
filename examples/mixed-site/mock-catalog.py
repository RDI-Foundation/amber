import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 9100


def send_json(handler: BaseHTTPRequestHandler, status: int, payload: object) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("content-type", "application/json; charset=utf-8")
    handler.send_header("content-length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/item/amber-mug":
            send_json(
                self,
                200,
                {
                    "source": "external",
                    "item": "amber mug",
                },
            )
            return
        if self.path == "/health":
            send_json(self, 200, {"ok": True})
            return
        send_json(self, 404, {"error": "not found"})

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[catalog] {fmt % args}", flush=True)


print(f"mock catalog listening on http://127.0.0.1:{PORT}", flush=True)
ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
