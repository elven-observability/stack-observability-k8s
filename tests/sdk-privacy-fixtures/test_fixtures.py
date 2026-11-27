"""Lightweight source/dependency contracts; NOT app, SDK or Collector acceptance."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("sdk_privacy_prepare", ROOT / "prepare.py")
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


class RealSDKFixtureContracts(unittest.TestCase):
    def test_base_images_and_h2_reuse_existing_fixture_pins(self):
        existing = json.loads((ROOT.parent / "instrumentation-fixtures/fixtures.json").read_text())
        pins = json.loads((ROOT / "fixtures.json").read_text())
        for case in ("java17", "java21", "node22"):
            self.assertEqual(pins["images"][case], existing["images"][case])
            self.assertIn("FROM " + existing["images"][case], (ROOT / ("Dockerfile." + case)).read_text())
        self.assertEqual(pins["javaDependencies"]["h2"], existing["h2"])
        for image in pins["dbImages"].values():
            self.assertRegex(image, r"^docker.io/library/(redis|postgres):[^@]+@sha256:[0-9a-f]{64}$")

    def test_npm_closure_is_complete_api_only_and_integrity_pinned(self):
        self.assertRegex(P.node_lock(ROOT), r"^[0-9a-f]{64}$")
        lock = json.loads((ROOT / "package-lock.json").read_text())
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder).resolve()
            (path / "package.json").write_bytes((ROOT / "package.json").read_bytes())
            for edit in (lambda value: value["packages"]["node_modules/pg"].update(integrity="sha1-weak"),
                         lambda value: value["packages"].pop("node_modules/pg-types"),
                         lambda value: value["packages"].update({"node_modules/@opentelemetry/sdk-node": value["packages"]["node_modules/pg"]})):
                altered = copy.deepcopy(lock)
                edit(altered)
                (path / "package-lock.json").write_text(json.dumps(altered))
                with self.assertRaises(ValueError):
                    P.node_lock(path)

    def test_applications_use_real_clients_and_exception_api_not_exporters(self):
        java, node = ((ROOT / name).read_text() for name in ("PrivacyFixture.java", "main.js"))
        for source in (java, node):
            for value in ("/exercise", "retry=false", "checkout failed", "elven.privacy.exception", "recordException", "502"):
                self.assertIn(value, source)
            for forbidden in ("ExportTraceServiceRequest", "OTLPTraceExporter", "SdkTracerProvider", "NodeSDK", "createSpanId"):
                self.assertNotIn(forbidden, source)
        self.assertIn("DriverManager.getConnection", java)
        self.assertIn("new Jedis", java)
        self.assertIn("client.set(", java)
        self.assertIn("client.get(", java)
        self.assertIn("new Client", node)
        self.assertIn("createClient", node)
        self.assertIn("await client.query", node)
        self.assertIn("spanContext().traceId", node)
        self.assertIn("getSpanContext().getTraceId()", java)

    def test_prepare_rejects_changed_bytes_without_writing_them(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder).resolve()
            (path / "package.json").write_bytes((ROOT / "package.json").read_bytes())
            (path / "package-lock.json").write_bytes((ROOT / "package-lock.json").read_bytes())
            artifact = {"file": "synthetic.jar", "url": "https://repo.maven.apache.org/maven2/synthetic.jar", "sha256": hashlib.sha256(b"expected").hexdigest()}
            (path / "fixtures.json").write_text(json.dumps({"javaDependencies": {"synthetic": artifact}}))
            response = mock.MagicMock()
            response.__enter__.return_value.read.return_value = b"different"
            with mock.patch.object(P, "SOURCE", path), mock.patch.object(P.urllib.request, "urlopen", return_value=response):
                with self.assertRaisesRegex(ValueError, "SHA-256"):
                    P.prepare(path)
            self.assertFalse((path / "synthetic.jar").exists())

    def test_transient_retries_are_bounded_and_never_skip_integrity(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b"pinned"
        throttled = P.urllib.error.HTTPError("https://repo.maven.apache.org/test", 429, "rate limit", {}, None)
        with mock.patch.object(P.urllib.request, "urlopen", side_effect=[throttled, response]) as fetch, mock.patch.object(P.time, "sleep"):
            self.assertEqual(P.fetch_jar("https://repo.maven.apache.org/test"), b"pinned")
            self.assertEqual(fetch.call_count, 2)
        with mock.patch.object(P.urllib.request, "urlopen", side_effect=throttled) as fetch, mock.patch.object(P.time, "sleep"):
            with self.assertRaisesRegex(ValueError, "three bounded"):
                P.fetch_jar("https://repo.maven.apache.org/test")
            self.assertEqual(fetch.call_count, 3)
        denied = P.urllib.error.HTTPError("https://repo.maven.apache.org/test", 403, "denied", {}, None)
        with mock.patch.object(P.urllib.request, "urlopen", side_effect=denied) as fetch:
            with self.assertRaises(P.urllib.error.HTTPError):
                P.fetch_jar("https://repo.maven.apache.org/test")
            self.assertEqual(fetch.call_count, 1)


if __name__ == "__main__":
    unittest.main()
