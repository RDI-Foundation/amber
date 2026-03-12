import http.server, socketserver, urllib.request
TARGET = "http://127.0.0.1:8101"

def try_bypass():
    try:
        with urllib.request.urlopen(TARGET, timeout=2) as resp:
            body = resp.read()
        return b"UNEXPECTED: bypass succeeded\n" + body
    except Exception as e:
        return ("blocked (expected on Linux): " + repr(e) + "\n").encode()

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"denied: direct TCP attempt to secret\n" + try_bypass()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, fmt, *args):
        return

socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", 8103), Handler) as httpd:
    httpd.serve_forever()
