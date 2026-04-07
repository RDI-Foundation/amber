import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NAME = os.environ["NAME"]
LABEL = os.environ["LABEL"]
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
        if self.path in ("/", "/id"):
            send(self, 200, f"{NAME}:{LABEL}")
            return
        send(self, 200, "ok")

    def log_message(self, fmt, *args):
        print(f"[worker] {fmt % args}", flush=True)


ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
