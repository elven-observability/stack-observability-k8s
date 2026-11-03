"""Synthetic HTTPS OTLP sink for an isolated Kind cluster. No third-party deps."""
import base64
import gzip
import http.server
import json
import os
import ssl
import threading

LOCK = threading.Lock()
STATE = {"status": 200, "attempts": {}, "accepted": [], "rejections": 0}
TOKEN = os.environ.get("SYNTHETIC_TOKEN", "synthetic-test-token")


class Sink(http.server.BaseHTTPRequestHandler):
    def authorized(self):
        return self.headers.get("Authorization") == "Bearer " + TOKEN

    def reply(self, status, payload=b""):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if not self.authorized():
            return self.reply(401)
        with LOCK:
            payload = json.dumps(STATE).encode()
        self.reply(200, payload)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if not self.authorized():
            with LOCK:
                STATE["rejections"] += 1
            return self.reply(401)
        if self.path == "/control":
            control = json.loads(body)
            with LOCK:
                STATE["status"] = int(control["status"])
            return self.reply(200, b"{}")
        if self.headers.get("Content-Encoding") == "gzip":
            body = gzip.decompress(body)
        with LOCK:
            STATE["attempts"][self.path] = STATE["attempts"].get(self.path, 0) + 1
            status = STATE["status"]
            if status == 200:
                STATE["accepted"].append({"path": self.path,
                    "tenant": self.headers.get("X-Scope-OrgID"),
                    "authorization_valid": self.authorized(),
                    "body": base64.b64encode(body).decode()})
        self.reply(status, b"{}" if status == 200 else b"")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), Sink)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
