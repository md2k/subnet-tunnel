# Test service reached through the tunnel.
#   GET /           -> "subtun-dev web ok"
#   GET /bytes/N    -> N zero bytes (download throughput)
#   PUT|POST any    -> reads and discards the body, returns its length (upload throughput)
import http.server

CHUNK = bytes(1 << 20)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def reply(self, body):
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.path.startswith("/bytes/"):
            return self.reply(b"subtun-dev web ok\n")
        left = int(self.path[len("/bytes/"):])
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(left))
        self.end_headers()
        while left > 0:
            n = min(left, len(CHUNK))
            self.wfile.write(CHUNK[:n])
            left -= n

    def do_PUT(self):
        size = int(self.headers.get("Content-Length", "0"))
        left = size
        while left > 0:
            data = self.rfile.read(min(left, 1 << 20))
            if not data:
                break
            left -= len(data)
        self.reply(f"{size - left}\n".encode())

    do_POST = do_PUT

    def log_message(self, *args):
        pass


http.server.ThreadingHTTPServer(("", 8080), Handler).serve_forever()
