"""Read-only release failures must be actionable without exposing output."""
import importlib.util
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("elven_registry_diagnostics", ROOT / "scripts/images-release.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RegistryDiagnosticsTests(unittest.TestCase):
    def test_only_finite_classifications_are_exposed_not_raw_headers_or_payloads(self):
        private = "synthetic-private-value-never-print"
        result = SimpleNamespace(returncode=1, stdout=private,
            stderr="Authorization: Bearer " + private + "\nHTTP/1.1 429 Too Many Requests\n" + private)
        with mock.patch.object(MODULE.subprocess, "run", return_value=result):
            with self.assertRaises(RuntimeError) as caught:
                MODULE.run(["crane", "digest", "docker.io/elvenobservability/elven-collector:v1.0.0"], capture=True)
        self.assertIn("registry_rate_limit,http_429", str(caught.exception))
        self.assertNotIn(private, str(caught.exception))
        self.assertNotIn("Bearer", str(caught.exception))

    def test_unknown_output_is_suppressed_and_nonzero_is_never_success(self):
        result = SimpleNamespace(returncode=1, stdout="synthetic private", stderr="unknown sensitive diagnostic")
        with mock.patch.object(MODULE.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "details_suppressed"):
                MODULE.run(["cosign", "verify-attestation", "synthetic"], capture=True)

    def test_readonly_operations_are_bounded_but_build_and_sign_defaults_are_preserved(self):
        with mock.patch.object(MODULE.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=" public ")) as execute:
            self.assertEqual(MODULE.run(["cosign", "verify", "synthetic"], capture=True), "public")
            self.assertEqual(execute.call_args.kwargs["timeout"], 180)
            MODULE.run(["docker", "buildx", "build"])
            self.assertNotIn("timeout", execute.call_args.kwargs)
            MODULE.run(["cosign", "sign", "synthetic"])
            self.assertNotIn("timeout", execute.call_args.kwargs)
            MODULE.run(["crane", "digest", "synthetic"], capture=True, timeout=7)
            self.assertEqual(execute.call_args.kwargs["timeout"], 7)

    def test_timeout_suppresses_partial_output_and_keeps_unknown_for_writes(self):
        error = subprocess.TimeoutExpired("synthetic", 180, output="private", stderr="private")
        with mock.patch.object(MODULE.subprocess, "run", side_effect=error):
            with self.assertRaisesRegex(RuntimeError, "read-only verification") as caught:
                MODULE.run(["cosign", "verify", "synthetic"], capture=True)
            self.assertNotIn("private", str(caught.exception))
            with self.assertRaisesRegex(RuntimeError, "completion UNKNOWN"):
                MODULE.run(["cosign", "sign", "synthetic"], timeout=7)

    def test_published_ci_verifies_all_eight_independently_without_write_or_credentials(self):
        source = (ROOT / ".github/workflows/verify-published.yaml").read_text()
        workflow = yaml.safe_load(source)
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        job = workflow["jobs"]["verify"]
        self.assertEqual(job["if"], "needs.publication.outputs.ready == 'true'")
        selected = {(item["family"], item["component"]) for item in job["strategy"]["matrix"]["include"]}
        self.assertEqual(selected, {("core", name) for name in ("collector", "beyla", "alloy")}
                         | {("sdk", name) for name in ("operator", "java", "nodejs", "nodejs20", "python")})
        self.assertNotIn("secrets.", source)
        self.assertNotIn("id-token:", source)
        self.assertNotIn("--development-images", source)
        self.assertNotIn("--insecure", source)
        self.assertNotIn("cosign sign", source)
        self.assertNotIn("continue-on-error", source)
        self.assertIn("scripts/images-instrumentation.py verify", source)
        self.assertIn("scripts/images-release.py verify", source)


if __name__ == "__main__":
    unittest.main()
