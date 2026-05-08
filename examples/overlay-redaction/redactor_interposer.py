#!/usr/bin/env python3

import json

from overlay_lib import InterposerComponentJson, InterpositionJson, attachment, interposition

REDACTOR_PROGRAM = r"""
import json
import os
import socketserver
import urllib.request
from http.server import BaseHTTPRequestHandler

PORT = int(os.environ["PORT"])
UPSTREAM_URL = os.environ["UPSTREAM_URL"]
REDACTION_TERMS = json.loads(os.environ["REDACTION_TERMS"])


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


def parse_redaction_terms(raw):
    parsed = json.loads(raw)
    if not isinstance(parsed, list) or any(not isinstance(item, str) for item in parsed):
        raise ValueError("REDACTION_TERMS must be a JSON array of strings")
    return parsed


def build_redaction_interposition(
    target_id: int, redaction_terms: list[str]
) -> InterpositionJson:
    # Build `${...}` from fragments here so the embedded Python source stays plain text.
    upstream_url_template = "$" + "{slots.upstream.url}"
    redaction_terms_template = "$" + "{config.redaction_terms}"
    interposer: InterposerComponentJson = {
        "config": {
            "redaction_terms": redaction_terms,
        },
        "config_schema": {
            "type": "object",
            "properties": {
                "redaction_terms": {
                    "type": "array",
                    "items": {"type": "string"},
                }
            },
            "required": ["redaction_terms"],
        },
        "program": {
            "path": "/usr/bin/env",
            "args": ["python3", "-u", "-c", REDACTOR_PROGRAM],
            "env": {
                "PORT": "8130",
                "UPSTREAM_URL": upstream_url_template,
                "REDACTION_TERMS": redaction_terms_template,
            },
            "network": {
                "endpoints": [
                    {"name": "endpoint", "port": 8130},
                ],
            },
        },
        "slots": {
            "upstream": {"kind": "a2a"},
        },
        "provides": {
            "downstream": {"kind": "a2a", "endpoint": "endpoint"},
        },
    }
    return interposition(
        interposer=interposer,
        attachments=[attachment(target_id, "upstream", "downstream")],
    )
