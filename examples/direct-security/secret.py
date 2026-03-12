import http.server, socketserver
SECRET = b"amber secret: swordfish\n"

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(SECRET)))
        self.end_headers()
        self.wfile.write(SECRET)
    def log_message(self, fmt, *args):
        return

socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", 8101), Handler) as httpd:
    httpd.serve_forever()
