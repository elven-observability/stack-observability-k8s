"""Test-only OTLP HTTPS sink requiring a verified mTLS client certificate.

Exports deliberately do not require backend Bearer credentials: real language
SDKs authenticate using their injected client identity. GET /state does require
a separate synthetic Bearer token, never a backend production credential.
"""
import base64
import gzip
import http.server
import io
import json
import os
from pathlib import Path
import re
import ssl
import threading
import time
import zlib


LOCK = threading.Lock()
STATE = {"accepted": [], "attempts": {}, "rejections": 0}
TOKEN = os.environ.get("SYNTHETIC_TOKEN", "synthetic-test-token")
MAX_BODY = 8 * 1024 * 1024
MAX_CHUNK_LINE = 1024
MAX_CHUNK_FRAMING = 64 * 1024
MAX_CHUNKS = 65536
MAX_TRAILER_LINES = 32
MAX_TRAILER_BYTES = 16 * 1024
BODY_TIMEOUT = 10


class BodyError(Exception):
    def __init__(self, status):
        self.status = status


class Sink(http.server.BaseHTTPRequestHandler):
    def reply(self, status, payload=b"{}", content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path != "/state":
            return self.reply(404)
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            return self.reply(401)
        with LOCK:
            payload = json.dumps(STATE).encode()
        return self.reply(200, payload)

    def _read_piece(self, maximum):
        remaining = self._body_deadline - time.monotonic()
        if remaining <= 0:
            raise BodyError(400)
        self.connection.settimeout(remaining)
        value = self.rfile.read1(maximum)
        if not value:
            raise BodyError(400)
        return value

    def _read_exact(self, length):
        value = bytearray()
        while len(value) < length:
            value.extend(self._read_piece(min(length - len(value), 65536)))
        return bytes(value)

    def _read_chunk_line(self):
        value = bytearray()
        while len(value) <= MAX_CHUNK_LINE:
            value.extend(self._read_piece(1))
            if len(value) > MAX_CHUNK_LINE:
                raise BodyError(400)
            if value.endswith(b"\r\n"):
                return bytes(value)
            if value.endswith(b"\n"):
                raise BodyError(400)
        raise BodyError(400)

    def _read_chunked(self):
        body = bytearray()
        framing = 0
        for _ in range(MAX_CHUNKS):
            line = self._read_chunk_line()
            framing += len(line) + 2
            if framing > MAX_CHUNK_FRAMING:
                raise BodyError(413)
            size_text, _, extension = line[:-2].partition(b";")
            if not re.fullmatch(rb"[0-9A-Fa-f]+", size_text):
                raise BodyError(400)
            if any(byte < 32 or byte > 126 for byte in extension):
                raise BodyError(400)
            size = int(size_text, 16)
            if size > MAX_BODY - len(body):
                raise BodyError(413)
            if size == 0:
                trailer_bytes = 0
                for number in range(MAX_TRAILER_LINES + 1):
                    trailer = self._read_chunk_line()
                    trailer_bytes += len(trailer)
                    if trailer_bytes > MAX_TRAILER_BYTES:
                        raise BodyError(413)
                    if trailer == b"\r\n":
                        return bytes(body)
                    if number == MAX_TRAILER_LINES:
                        raise BodyError(413)
                    name, separator, value = trailer[:-2].partition(b":")
                    if (not separator or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                            or name.lower() in (b"content-length", b"transfer-encoding")
                            or any(byte < 32 and byte != 9 or byte == 127 for byte in value)):
                        raise BodyError(400)
            body.extend(self._read_exact(size))
            if self._read_exact(2) != b"\r\n":
                raise BodyError(400)
        raise BodyError(413)

    def _read_body(self):
        lengths = self.headers.get_all("Content-Length", [])
        transfers = self.headers.get_all("Transfer-Encoding", [])
        if len(lengths) > 1 or len(transfers) > 1 or lengths and transfers:
            raise BodyError(400)
        self._body_deadline = time.monotonic() + BODY_TIMEOUT
        if transfers:
            if transfers[0].strip().lower() != "chunked":
                raise BodyError(400)
            return self._read_chunked()
        if not lengths:
            return b""
        length = lengths[0].strip()
        if not re.fullmatch(r"[0-9]+", length):
            raise BodyError(400)
        if len(length) > 20 or int(length) > MAX_BODY:
            raise BodyError(413)
        return self._read_exact(int(length))

    def do_POST(self):
        if self.path not in ("/v1/traces", "/v1/logs", "/v1/metrics"):
            return self.reply(404)
        try:
            body = self._read_body()
            encoding = self.headers.get("Content-Encoding", "").strip().lower()
            if encoding not in ("", "identity", "gzip"):
                raise BodyError(415)
            if encoding == "gzip":
                with gzip.GzipFile(fileobj=io.BytesIO(body)) as compressed:
                    body = compressed.read(MAX_BODY + 1)
                if len(body) > MAX_BODY:
                    raise BodyError(413)
        except BodyError as error:
            self.close_connection = True
            return self.reply(error.status)
        except (ValueError, OSError, EOFError, zlib.error):
            self.close_connection = True
            return self.reply(400)
        certificate = self.connection.getpeercert()
        if not certificate:
            with LOCK:
                STATE["rejections"] += 1
            return self.reply(401)
        content_type = self.headers.get("Content-Type", "")
        with LOCK:
            STATE["attempts"][self.path] = STATE["attempts"].get(self.path, 0) + 1
            STATE["accepted"].append({
                "path": self.path,
                "body": base64.b64encode(body).decode(),
                "content_type": content_type,
                "content_length": self.headers.get("Content-Length"),
                "transfer_encoding": "chunked" if self.headers.get("Transfer-Encoding") else None,
                "content_encoding": encoding or None,
                "client_certificate_verified": True,
                "client_certificate_subject": certificate.get("subject", ()),
                "authorization_present": "Authorization" in self.headers,
            })
        # Empty protobuf is a valid Export*ServiceResponse. JSON clients receive
        # an empty JSON response object instead.
        if "protobuf" in content_type:
            return self.reply(200, b"", "application/x-protobuf")
        return self.reply(200)

    def log_message(self, *args):
        pass


def create_server(address=("0.0.0.0", 8443), tls_directory="/tls"):
    directory = Path(tls_directory)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(directory / "tls.crt", directory / "tls.key")
    context.load_verify_locations(cafile=directory / "ca.crt")
    context.verify_mode = ssl.CERT_REQUIRED
    server = http.server.ThreadingHTTPServer(address, Sink)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


if __name__ == "__main__":
    create_server().serve_forever()
