python3 - <<'PY'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RESPONSE = b'{"jsonrpc":"2.0","id":"server-static","method":"tools/list","result":{"source":"server","ok":true}}'


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        tutorial = self.headers.get('x-amber-tutorial', '-')
        print(f'[server] received GET {self.path} x-amber-tutorial={tutorial}', flush=True)
        self.send_response(200)
        self.send_header('content-type', 'application/json')
        self.send_header('content-length', str(len(RESPONSE)))
        self.end_headers()
        self.wfile.write(RESPONSE)
        print(f'[server] responded 200 {self.path} id=server-static', flush=True)

    def log_message(self, _format, *_args):
        pass


print('[server] listening on :9000', flush=True)
ThreadingHTTPServer(('0.0.0.0', 9000), Handler).serve_forever()
PY
