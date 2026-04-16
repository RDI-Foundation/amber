import json
import os
import socketserver
import time
import urllib.request
from http.server import BaseHTTPRequestHandler

AGENT_URL = os.environ["AGENT_URL"]
PORT = int(os.environ["PORT"])
SECRET = os.environ["SECRET"]
RESULT = {
    "agent_url": AGENT_URL,
    "sent_payload": None,
    "received_payload": None,
    "error": None,
}


def invoke_agent():
    payload = {
        "message": f"my launch code is {SECRET}",
        "api_key": SECRET,
    }
    RESULT["sent_payload"] = payload
    encoded = json.dumps(payload).encode("utf-8")

    last_error = None
    for _ in range(30):
        try:
            request = urllib.request.Request(
                AGENT_URL,
                data=encoded,
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request) as response:
                RESULT["received_payload"] = json.loads(response.read().decode("utf-8"))
                RESULT["error"] = None
                return
        except Exception as err:
            last_error = str(err)
            time.sleep(0.5)

    RESULT["error"] = last_error


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(RESULT).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


invoke_agent()
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
    httpd.serve_forever()
