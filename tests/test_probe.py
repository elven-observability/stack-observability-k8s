"""Real loopback mTLS for the synthetic operator probe; no tenant access."""
import http.server
import importlib.util
import json
from pathlib import Path
import ssl
import tempfile
import threading
import unittest

from test_cli import arguments, cli

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("elven_probe", ROOT / "scripts/probe.py")
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="elven-probe-test-")
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        config = {"cluster": {"domain": "cluster.local"}}
        material = cli.generate_pki(arguments(), config, self.folder)
        for key, value in material.items():
            file = self.folder / key
            file.write_text(value)
            file.chmod(0o600)
        self.received = []
        self.status = 200
        owner = self

        class Sink(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                owner.received.append((self.path, json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
                self.send_response(owner.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Sink)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.folder / "tls.crt"), str(self.folder / "tls.key"))
        context.load_verify_locations(cafile=str(self.folder / "ca.crt"))
        context.verify_mode = ssl.CERT_REQUIRED
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.endpoint = "https://elven-synthetic-gateway.elven-synthetic.svc.cluster.local:4318"
        self.route = f"127.0.0.1:{self.server.server_port}"

    def call(self, endpoint=None):
        return probe.probe(endpoint or self.endpoint, self.folder / "ca.crt", self.folder / "client.crt",
                           self.folder / "client.key", self.route)

    def test_real_mtls_three_correlated_signals_and_honest_acceptance_boundary(self):
        result = self.call()
        self.assertEqual(result["gateway_accepted"], ["logs", "metrics", "traces"])
        self.assertEqual(result["backend_delivery"], "NOT_VERIFIED")
        self.assertEqual([path for path, _ in self.received], ["/v1/logs", "/v1/metrics", "/v1/traces"])
        log = self.received[0][1]["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
        span = self.received[2][1]["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
        self.assertEqual(log["traceId"], span["traceId"])
        self.assertEqual(span["traceId"], result["trace_id"])

    def test_wrong_san_is_rejected_even_over_loopback_forward(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.call("https://wrong-identity.example:4318")

    def test_plaintext_and_credential_urls_are_rejected_before_io(self):
        for url in ("http://example.invalid", "https://token@example.invalid", "https://example.invalid?token=fake"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                self.call(url)

    def test_world_readable_private_key_is_rejected(self):
        (self.folder / "client.key").chmod(0o644)
        with self.assertRaisesRegex(ValueError, "private key"):
            self.call()

    def test_permanent_response_does_not_claim_acceptance(self):
        self.status = 401
        with self.assertRaisesRegex(ValueError, "HTTP 401"):
            self.call()


if __name__ == "__main__":
    unittest.main(verbosity=2)
