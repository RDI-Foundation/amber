import http.server
import json
import os
import socketserver

PORT = int(os.environ["PORT"])
REDACTION_TERMS = json.loads(os.environ["REDACTION_TERMS"])
REDACTOR_RUNTIME = r"""
import json
import os
import socketserver
import urllib.request
from http.server import BaseHTTPRequestHandler

PORT = int(os.environ["PORT"])
UPSTREAM_URL = os.environ["UPSTREAM_URL"]
REDACTION_TERMS = json.loads(os.environ.get("REDACTION_TERMS", "[]"))


def redact(payload):
    text = payload.decode("utf-8")
    for term in REDACTION_TERMS:
        text = text.replace(term, "[REDACTED]")
    return text.encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    def _proxy(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length) if length else b""
        upstream_body = redact(raw_body)

        request = urllib.request.Request(
            UPSTREAM_URL,
            data=upstream_body,
            method=self.command,
            headers={"Content-Type": self.headers.get("Content-Type", "application/json")},
        )

        with urllib.request.urlopen(request) as response:
            response_body = redact(response.read())
            content_type = response.headers.get("Content-Type", "application/json")
            self.send_response(response.status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)

    def do_POST(self):
        self._proxy()

    def do_GET(self):
        self._proxy()

    def log_message(self, fmt, *args):
        return


socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
    httpd.serve_forever()
"""


def interposition_for(target_id):
    upstream_url_template = "$" + "{slots.upstream.url}"
    return {
        "interposer": {
            "program": {
                "path": "/usr/bin/env",
                "args": ["python3", "-u", "-c", REDACTOR_RUNTIME],
                "env": {
                    "PORT": "8130",
                    "UPSTREAM_URL": upstream_url_template,
                    "REDACTION_TERMS": json.dumps(REDACTION_TERMS), # TODO: leaks the secret
                },
                "network": {
                    "endpoints": [
                        {"name": "endpoint", "port": 8130 },
                    ],
                },
            },
            "slots": {
                "upstream": {"kind": "a2a"},
            },
            "provides": {
                "downstream": {"kind": "a2a", "endpoint": "endpoint"},
            },
            "metadata": {
                "generated_by": "governance-redaction",
                "policy": "redact-all-a2a",
            },
        },
        "attachments": [
            {
                "target": target_id,
                "interposer_slot": "upstream",
                "interposer_provide": "downstream",
            }
        ],
    }


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        scope = json.loads(raw.decode("utf-8"))

        interpositions = []
        for section in ("imports", "bindings", "exports"):
            for edge in scope.get(section, []):
                capability = edge.get("capability", {})
                if capability.get("kind") == "a2a":
                    interpositions.append(interposition_for(edge["id"]))

        body = json.dumps({"interpositions": interpositions}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
    httpd.serve_forever()
