#!/usr/bin/env python3

import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        print(f"[upstream] {self.address_string()} - {fmt % args}")

    def do_POST(self) -> None:
        if self.path != "/rpc":
            self.send_error(404)
            return

        raw = self._read_body()
        payload = self._parse_json(raw)
        method = payload.get("method") if isinstance(payload, dict) else None
        request_id = payload.get("id") if isinstance(payload, dict) else None

        print(
            f"[upstream] rpc method={method!r} id={request_id!r} "
            f"x-amber-tutorial={self.headers.get('x-amber-tutorial')!r}"
        )

        response = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "result": {
                "source": "external-upstream",
                "method": method,
            },
        }
        body = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json({"ok": True})
            return

        if self.path != "/stream":
            self.send_error(404)
            return

        print(
            f"[upstream] sse stream requested "
            f"x-amber-tutorial={self.headers.get('x-amber-tutorial')!r}"
        )
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.send_header("connection", "close")
        self.end_headers()

        frames = [
            (
                "event: message\n"
                "id: sse-1\n"
                "data: {\"jsonrpc\":\"2.0\",\"id\":\"sse-1\",\"method\":\"notifications/tools\"}\n\n"
            ),
            (
                "event: message\n"
                "id: sse-2\n"
                "data: {\"jsonrpc\":\"2.0\",\"id\":\"sse-2\",\"method\":\"notifications/progress\"}\n\n"
            ),
        ]
        for frame in frames:
            self.wfile.write(frame.encode("utf-8"))
            self.wfile.flush()
            time.sleep(0.2)
        self.close_connection = True

    def _read_body(self) -> bytes:
        length = self.headers.get("content-length")
        if length is None:
            return b""
        try:
            size = int(length)
        except ValueError:
            return b""
        if size <= 0:
            return b""
        return self.rfile.read(size)

    @staticmethod
    def _parse_json(raw: bytes):
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None

    def _send_json(self, value: object, status: int = 200) -> None:
        body = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser(description="Amber observability tutorial upstream service.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=38081)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"[upstream] listening on http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
