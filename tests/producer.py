"""Synthetic stdout producer; the distribution must read actual CRI files."""
import http.server
import json


class Producer(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        print(json.dumps({"level": "error", "message": "SYNTHETIC_PRIVATE_DO_NOT_EXPORT"}), flush=True)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("0.0.0.0", 8080), Producer).serve_forever()
