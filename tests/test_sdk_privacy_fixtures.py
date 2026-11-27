"""Offline fixture source/lock regressions, never actual SDK runtime evidence."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/sdk-privacy-fixtures"
SPEC = importlib.util.spec_from_file_location("python_sdk_fixture_prepare", FIXTURES / "prepare.py")
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


class PythonSDKFixtureContracts(unittest.TestCase):
    def test_complete_linux314_closure_has_two_arch_wheels_and_no_sdk(self):
        pins = json.loads((FIXTURES / "fixtures.json").read_text())
        self.assertEqual(len(pins["pythonDependencies"]), 8)
        self.assertEqual(P.python_lock(FIXTURES, pins), hashlib.sha256((FIXTURES / "requirements-python.lock").read_bytes()).hexdigest())
        self.assertEqual(pins["pythonRuntime"]["version"], "3.14.10")
        self.assertEqual(pins["pythonRuntime"]["libc"], "glibc")
        self.assertEqual(pins["pythonRuntime"]["stability"], "beta")
        self.assertEqual(len(pins["pythonDependencies"]["markupsafe"]["wheels"]), 2)
        for name in pins["pythonDependencies"]:
            self.assertNotIn("opentelemetry", name)

    def test_omission_provider_non_official_hash_or_wrong_abi_fails_closed(self):
        good = json.loads((FIXTURES / "fixtures.json").read_text())
        for change in (
            lambda p: p["pythonDependencies"].pop("redis"),
            lambda p: p["pythonDependencies"].update({"opentelemetry-sdk": {}}),
            lambda p: p["pythonDependencies"]["jinja2"].update(dependsOn={}),
            lambda p: p["pythonDependencies"]["markupsafe"]["wheels"].pop(),
            lambda p: p["pythonDependencies"]["redis"]["wheels"][0].update(url="https://mirror.invalid/redis.whl"),
            lambda p: p["pythonDependencies"]["redis"]["wheels"][0].update(sha256="weak"),
            lambda p: p["pythonRuntime"].update(version="3.13.0"),
        ):
            with self.subTest(change=change):
                altered = copy.deepcopy(good)
                change(altered)
                with self.assertRaises(ValueError):
                    P.python_lock(FIXTURES, altered)
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            lock = (FIXTURES / "requirements-python.lock").read_text()
            (directory / "requirements-python.lock").write_text(lock.replace("--hash=sha256:", "--hash=sha1:", 1))
            with self.assertRaisesRegex(ValueError, "requirements"):
                P.python_lock(directory, good)

    def test_python_docker_build_is_isolated_hash_only_nonroot_and_api_external(self):
        recipe = (FIXTURES / "Dockerfile.python314").read_text()
        pins = json.loads((FIXTURES / "fixtures.json").read_text())
        self.assertIn("FROM " + pins["images"]["python314"], recipe)
        for option in ("--isolated", "--no-cache-dir", "--only-binary=:all:", "--require-hashes", "--index-url https://pypi.org/simple"):
            self.assertIn(option, recipe)
        self.assertIn("USER 10001:10001", recipe)
        self.assertIn('ENTRYPOINT ["python", "/fixture/main.py"]', recipe)
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", recipe)
        self.assertNotIn("--extra-index", recipe)
        self.assertNotIn("--trusted-host", recipe)

    def test_python_app_has_real_clients_exceptions_http_parent_not_fabricated_otlp(self):
        source = (FIXTURES / "main.py").read_text()
        tree = ast.parse(source)
        functions = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
        self.assertTrue({"ready", "exercise", "fetchPrice", "database", "redis_work"} <= functions)
        imports = [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        self.assertIn("opentelemetry", imports)
        self.assertFalse(any(name.startswith(("opentelemetry.sdk", "opentelemetry.exporter", "opentelemetry.proto", "opentelemetry.instrumentation")) for name in imports))
        for expected in ("sqlite3.connect", "cursor.execute", "SELECT ELVEN_MISSING_FUNCTION()", "SELECT ? AS bound_email",
                         "customer_email", "AS answer", "client.set(", "client.get(", "client.hget(", "except ResponseError",
                         "raise ValueError(MESSAGE)", "span.record_exception(expected)", "StatusCode.ERROR",
                         'trace.get_current_span()', 'trace.get_tracer("elven.sdk.privacy.fixture")',
                         '"elven.privacy.exception"', '@app.get("/exercise")', '@app.get("/ready")',
                         'runtime=CASE), 502', 'socket_timeout=3', 'Retry(NoBackoff(), 0)'):
            self.assertIn(expected, source)
        for forbidden in ("ExportTraceServiceRequest", "TracerProvider(", "OTLPSpanExporter", "set_tracer_provider", "generate_trace_id"):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("pip", source)


if __name__ == "__main__":
    unittest.main()
