"""Fixture contracts and real loopback mTLS sink checks; not an SDK proof."""
import base64
import gzip
import http.client
import importlib.util
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("instrumentation_fixture_sink", SOURCE / "sink.py")
SINK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SINK)
# Serialized ExportTraceServiceRequest containing one synthetic service/span.
# Kept as bytes so fixture checks need only the Python standard library.
OTLP_PROTOBUF = bytes.fromhex(
    "0a690a250a230a0c736572766963652e6e616d6512130a1173796e7468657469632d66697874757265"
    "1240123e0a1011111111111111111111111111111111120822222222222222222a0c666978747572"
    "652d6874747030023900002a36fe9c97174140423936fe9c9717")


class FixtureContracts(unittest.TestCase):
    def test_dockerfiles_match_the_verified_runtime_pins(self):
        lock = json.loads((SOURCE / "fixtures.json").read_text())
        self.assertEqual(set(lock["images"]), {"java17", "java21", "node22", "node20"})
        for name, image in lock["images"].items():
            self.assertRegex(image, r"^docker.io/library/.+@sha256:[a-f0-9]{64}$")
            self.assertIn("FROM " + image + "\n", (SOURCE / ("Dockerfile." + name)).read_text())
        self.assertRegex(lock["h2"]["sha256"], r"^[a-f0-9]{64}$")
        self.assertTrue(lock["h2"]["url"].startswith("https://repo.maven.apache.org/"))

    def test_applications_have_no_sdk_or_tracing_dependency(self):
        java = (SOURCE / "JavaFixture.java").read_text()
        javascript = (SOURCE / "main.js").read_text()
        self.assertNotIn("io.opentelemetry", java)
        self.assertNotIn("require('@opentelemetry", javascript)
        self.assertIn("statement.executeQuery(QUERY)", java)
        self.assertIn("HttpURLConnection", java)
        self.assertIn("http.get(endpoint", javascript)


class SinkMutualTLS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="elven-sdk-sink-test-")
        cls.directory = Path(cls.temporary.name)

        def openssl(*arguments):
            subprocess.run(["openssl", *map(str, arguments)], check=True,
                           capture_output=True, timeout=30)

        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=synthetic-sdk-test-ca", "-keyout", cls.directory / "ca.key",
                "-out", cls.directory / "ca.crt", "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        for name, purpose in (("tls", "serverAuth"), ("client", "clientAuth")):
            openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=synthetic-sdk-" + name,
                    "-keyout", cls.directory / (name + ".key"), "-out", cls.directory / (name + ".csr"),
                    "-addext", "basicConstraints=critical,CA:FALSE",
                    "-addext", "extendedKeyUsage=" + purpose,
                    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1")
            openssl("x509", "-req", "-in", cls.directory / (name + ".csr"),
                    "-CA", cls.directory / "ca.crt", "-CAkey", cls.directory / "ca.key",
                    "-CAcreateserial", "-out", cls.directory / (name + ".crt"), "-days", "1",
                    "-copy_extensions", "copy")
        cls.server = SINK.create_server(("127.0.0.1", 0), cls.directory)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.client = ssl.create_default_context(cafile=str(cls.directory / "ca.crt"))
        cls.client.load_cert_chain(cls.directory / "client.crt", cls.directory / "client.key")
        cls.no_certificate = ssl.create_default_context(cafile=str(cls.directory / "ca.crt"))
        # TLS1.2 exposes the missing-client-certificate rejection during the
        # handshake itself. TLS1.3 can surface it as a later BrokenPipe instead.
        cls.no_certificate.maximum_version = ssl.TLSVersion.TLSv1_2

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.temporary.cleanup()

    def setUp(self):
        with SINK.LOCK:
            SINK.STATE["accepted"].clear()
            SINK.STATE["attempts"].clear()
            SINK.STATE["rejections"] = 0

    def request(self, method, path, body=None, headers=None, context=None, encode_chunked=False):
        connection = http.client.HTTPSConnection("127.0.0.1", self.server.server_port,
                                                 context=context or self.client, timeout=5)
        try:
            connection.request(method, path, body=body, headers=headers or {}, encode_chunked=encode_chunked)
            result = connection.getresponse()
            return result.status, result.read()
        finally:
            connection.close()

    def raw_post(self, body, headers=b"Transfer-Encoding: chunked\r\n"):
        connection = http.client.HTTPSConnection("127.0.0.1", self.server.server_port,
                                                 context=self.client, timeout=5)
        try:
            connection.connect()
            connection.sock.sendall(b"POST /v1/traces HTTP/1.1\r\nHost: localhost\r\n"
                                    b"Connection: close\r\nContent-Type: application/x-protobuf\r\n"
                                    + headers + b"\r\n" + body)
            response = http.client.HTTPResponse(connection.sock)
            response.begin()
            return response.status, response.read(), response.getheader("Connection")
        finally:
            connection.close()

    def captured(self):
        status, response = self.request("GET", "/state", headers={"Authorization": "Bearer " + SINK.TOKEN})
        self.assertEqual(status, 200)
        return json.loads(response)["accepted"]

    def assert_body_rejected(self, body, status=400, headers=b"Transfer-Encoding: chunked\r\n"):
        actual, _, connection = self.raw_post(body, headers)
        self.assertEqual(actual, status)
        self.assertEqual(connection, "close")
        self.assertEqual(self.captured(), [])

    def test_real_mtls_export_needs_no_backend_bearer_and_preserves_protobuf(self):
        original = OTLP_PROTOBUF
        status, response = self.request("POST", "/v1/traces", gzip.compress(original),
                                        {"Content-Type": "application/x-protobuf", "Content-Encoding": "gzip"})
        self.assertEqual((status, response), (200, b""))
        status, response = self.request("GET", "/state", headers={"Authorization": "Bearer " + SINK.TOKEN})
        self.assertEqual(status, 200)
        record = json.loads(response)["accepted"][0]
        self.assertEqual(base64.b64decode(record["body"]), original)
        self.assertTrue(record["client_certificate_verified"])
        self.assertFalse(record["authorization_present"])
        self.assertEqual(record["content_encoding"], "gzip")
        self.assertEqual(record["content_length"], str(len(gzip.compress(original))))
        self.assertIsNone(record["transfer_encoding"])

    def test_real_mtls_chunked_bytes_generator_preserves_otlp_protobuf(self):
        original = OTLP_PROTOBUF
        status, response = self.request("POST", "/v1/traces", (bytes([byte]) for byte in original),
                                        {"Content-Type": "application/x-protobuf"}, encode_chunked=True)
        self.assertEqual((status, response), (200, b""))
        record = self.captured()[0]
        self.assertEqual(base64.b64decode(record["body"]), original)
        self.assertTrue(record["client_certificate_verified"])
        self.assertFalse(record["authorization_present"])
        self.assertIsNone(record["content_length"])
        self.assertEqual(record["transfer_encoding"], "chunked")
        self.assertIsNone(record["content_encoding"])

    def test_chunked_gzip_is_dechunked_before_bounded_decompression(self):
        original = OTLP_PROTOBUF
        compressed = gzip.compress(original)
        chunks = (compressed[start:start + 3] for start in range(0, len(compressed), 3))
        status, _ = self.request("POST", "/v1/traces", chunks,
                                 {"Content-Type": "application/x-protobuf", "Content-Encoding": "gzip"},
                                 encode_chunked=True)
        self.assertEqual(status, 200)
        record = self.captured()[0]
        self.assertEqual(base64.b64decode(record["body"]), original)
        self.assertEqual(record["transfer_encoding"], "chunked")
        self.assertEqual(record["content_encoding"], "gzip")

    def test_chunk_extensions_and_bounded_trailers_are_accepted(self):
        status, _, _ = self.raw_post(b"2;fixture=yes\r\n\x0a\x00\r\n0\r\nX-Fixture: ok\r\n\r\n")
        self.assertEqual(status, 200)
        self.assertEqual(base64.b64decode(self.captured()[0]["body"]), b"\x0a\x00")

    def test_chunked_and_content_length_together_are_rejected(self):
        self.assert_body_rejected(b"2\r\n\x0a\x00\r\n0\r\n\r\n",
                                  headers=b"Transfer-Encoding: chunked\r\nContent-Length: 2\r\n")

    def test_duplicate_framing_headers_are_rejected(self):
        for headers in (b"Content-Length: 0\r\nContent-Length: 0\r\n",
                        b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n"):
            with self.subTest(headers=headers):
                self.assert_body_rejected(b"", headers=headers)

    def test_invalid_chunk_hex_or_crlf_is_rejected(self):
        for body in (b"GG\r\n", b"0x2\r\n", b"+2\r\n", b"2\n", b"1\r\nxZZ"):
            with self.subTest(body=body):
                self.assert_body_rejected(body)

    def test_unterminated_or_truncated_bodies_fail_closed(self):
        with mock.patch.object(SINK, "BODY_TIMEOUT", 0.1):
            for body in (b"2", b"4\r\nxy", b"2\r\nxy\r\n", b"0\r\nX-Fixture: missing-end\r\n"):
                with self.subTest(body=body):
                    self.assert_body_rejected(body)
            self.assert_body_rejected(b"x", headers=b"Content-Length: 2\r\n")

    def test_declared_and_aggregate_chunk_body_budgets_are_enforced(self):
        self.assert_body_rejected(f"{SINK.MAX_BODY + 1:x}\r\n".encode(), status=413)
        with mock.patch.object(SINK, "MAX_BODY", 4):
            self.assert_body_rejected(b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n", status=413)

    def test_chunk_line_and_trailer_budgets_are_enforced(self):
        self.assert_body_rejected(b"0" * (SINK.MAX_CHUNK_LINE + 1) + b"\r\n")
        self.assert_body_rejected(b"0\r\n" + b"X-Fixture: x\r\n" * (SINK.MAX_TRAILER_LINES + 1) + b"\r\n", status=413)
        with mock.patch.object(SINK, "MAX_TRAILER_BYTES", 8):
            self.assert_body_rejected(b"0\r\nX-Fixture: too-long\r\n\r\n", status=413)

    def test_malformed_or_oversized_gzip_is_not_captured(self):
        with mock.patch.object(SINK, "MAX_BODY", 64):
            compressed = gzip.compress(b"x" * 128)
            status, _ = self.request("POST", "/v1/traces", iter([compressed]),
                                     {"Content-Encoding": "gzip"}, encode_chunked=True)
        self.assertEqual(status, 413)
        self.assertEqual(self.captured(), [])
        for malformed in (b"not-gzip", b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x06" + b"\x00" * 8):
            with self.subTest(malformed=malformed):
                status, _ = self.request("POST", "/v1/traces", iter([malformed]),
                                         {"Content-Encoding": "gzip"}, encode_chunked=True)
                self.assertEqual(status, 400)
                self.assertEqual(self.captured(), [])

    def test_missing_client_certificate_is_rejected_during_tls(self):
        with self.assertRaises(ssl.SSLError):
            self.request("POST", "/v1/traces", b"", context=self.no_certificate)

    def test_untrusted_server_certificate_is_rejected(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.request("GET", "/state", context=ssl.create_default_context())

    def test_state_endpoint_requires_its_synthetic_bearer(self):
        status, _ = self.request("GET", "/state")
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)
