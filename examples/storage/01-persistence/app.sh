python3 - <<'PY'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import os

STATE_PATH = Path('/var/lib/app/state.txt')
STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
if not STATE_PATH.exists():
    STATE_PATH.write_text(os.environ['APP_INITIAL_STATE'], encoding='utf-8')
VERSION = os.environ['APP_VERSION']

def read_state() -> str:
    return STATE_PATH.read_text(encoding='utf-8')

def send(handler: BaseHTTPRequestHandler, status: int, body: str) -> None:
    payload = body.encode('utf-8')
    handler.send_response(status)
    handler.send_header('content-type', 'text/plain; charset=utf-8')
    handler.send_header('content-length', str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == '/version':
            send(self, 200, VERSION)
        elif self.path == '/state':
            send(self, 200, read_state())
        elif self.path == '/':
            send(self, 200, 'GET /version\nGET /state\nPUT /state\n')
        else:
            send(self, 404, 'not found\n')

    def do_PUT(self) -> None:
        if self.path != '/state':
            send(self, 404, 'not found\n')
            return
        length = int(self.headers.get('content-length', '0'))
        state = self.rfile.read(length).decode('utf-8')
        STATE_PATH.write_text(state, encoding='utf-8')
        send(self, 200, read_state())

    def log_message(self, _format: str, *_args: object) -> None:
        pass

ThreadingHTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
PY
