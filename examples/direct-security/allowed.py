import http.server, os, socketserver, urllib.request
SECRET_URL = os.environ["SECRET_URL"]

def fetch_secret():
    try:
        with urllib.request.urlopen(SECRET_URL, timeout=2) as resp:
            return resp.read()
    except Exception as e:
        return ("ERROR fetching secret via slot: " + repr(e) + "\n").encode()

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        secret = fetch_secret()
        body = b"allowed: secret via slot\n" + secret
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, fmt, *args):
        return

socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", 8102), Handler) as httpd:
    httpd.serve_forever()
