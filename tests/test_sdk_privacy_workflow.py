"""Offline guards for OCI reuse/rescan ordering; no Docker or cluster execution."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/sdk-privacy-candidate.yaml"


class SDKPrivacyWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text()
        cls.doc = yaml.safe_load(cls.text)
        cls.job = cls.doc["jobs"]["lab"]
        cls.steps = cls.job["steps"]
        cls.initial = next(step["run"] for step in cls.steps if "def admit_family(" in step.get("run", ""))
        cls.guard = {"__name__": "offline_candidate_guard_test"}
        code = cls.initial.split("python - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        exec(compile(code, "sdk-privacy-workflow-guard", "exec"), cls.guard)

    def test_manual_hosted_readonly_without_release_or_shared_context(self):
        events = self.doc.get("on", self.doc.get(True))
        self.assertEqual(set(events), {"workflow_dispatch"})
        self.assertEqual(set(events["workflow_dispatch"]["inputs"]), {"core_run", "sdk_run"})
        self.assertTrue(all(v["required"] is True and v["type"] == "string" for v in events["workflow_dispatch"]["inputs"].values()))
        self.assertEqual(self.doc["permissions"], {"contents": "read", "actions": "read"})
        self.assertEqual(self.doc["env"]["KUBECONFIG"], "/dev/null")
        self.assertEqual(self.doc["env"]["PYTHONDONTWRITEBYTECODE"], "1")
        self.assertEqual(self.job["runs-on"], "ubuntu-24.04")
        self.assertEqual(self.job["timeout-minutes"], 40)
        for forbidden in ("setup-buildx", "docker build", "buildx", "images-release.py publish", "images-release.py promote",
                          "images-instrumentation.py publish", "images-instrumentation.py promote", "id-token", "environment:",
                          "--privileged", "SYS_ADMIN", "insecure-skip-tls", "eo-production", "secrets."):
            self.assertNotIn(forbidden, self.text)
        for step in self.steps:
            self.assertNotIn("continue-on-error", step)
            if "uses" in step:
                self.assertRegex(step["uses"], r"^[a-zA-Z0-9_/-]+@[0-9a-f]{40}$")
            self.assertNotIn("${{ inputs.", step.get("run", ""))

    def test_exact_artifact_downloads_and_oci_index_storage(self):
        docker = next(s for s in self.steps if s.get("uses", "").startswith("docker/setup-docker-action@"))
        self.assertEqual(docker["with"]["version"], "v29.9.2")
        self.assertTrue(json.loads(docker["with"]["daemon-config"])["features"]["containerd-snapshotter"])
        downloads = [s["with"] for s in self.steps if s.get("uses", "").startswith("actions/download-artifact@")]
        self.assertEqual([(s["name"], s["path"], s["run-id"]) for s in downloads], [
            ("elven-oci-release", "artifacts/images", "${{ inputs.core_run }}"),
            ("elven-instrumentation-oci", "artifacts/instrumentation", "${{ inputs.sdk_run }}")])
        self.assertTrue(all(s["github-token"] == "${{ github.token }}" for s in downloads))

    def test_runtime_waits_for_rescan_load_govuln_and_unchanged_normal_freshness_gate(self):
        def position(fragment):
            return next(i for i, s in enumerate(self.steps) if fragment in s.get("run", ""))
        initial = position("def admit_family(")
        scanner = position("scripts/images-install-trivy.py --lock versions.lock.json")
        rescan = position("scripts/images-release.py scan --evidence-dir artifacts/images")
        load = position('["docker", "load", "--input", str(archive)]')
        audit = position("scripts/images-release.py govulncheck --evidence-dir artifacts/images")
        fresh = next(i for i, s in enumerate(self.steps) if s.get("run", "").startswith("python scripts/qualify-candidate-artifacts.py"))
        runtime = position("scripts/test-sdk-privacy-kind.py")
        self.assertEqual(sorted((initial, scanner, rescan, load, audit, fresh, runtime)),
                         [initial, scanner, rescan, load, audit, fresh, runtime])
        self.assertIn("scripts/images-instrumentation.py scan --evidence-dir artifacts/instrumentation", self.steps[rescan]["run"])
        self.assertIn("python -m pip install --requirement requirements-test.txt", self.steps[scanner]["run"])
        self.assertIn("bash scripts/images-install-ci-tools.sh", self.steps[scanner]["run"])
        self.assertIn('image["archiveSha256"]', self.steps[load]["run"])
        self.assertIn('guard.regular(folder, image["archive"])', self.steps[load]["run"])
        self.assertNotIn("--platform", self.steps[load]["run"])
        self.assertIn("--development-images", self.steps[runtime]["run"])
        self.assertIn("--core-manifest artifacts/images/release.json", self.steps[runtime]["run"])
        self.assertIn("--sdk-manifest artifacts/instrumentation/instrumentation-release.json", self.steps[runtime]["run"])
        for index in (initial, scanner, rescan, load, audit, fresh, runtime):
            self.assertNotIn("if", self.steps[index])

    def test_security_refresh_admission_allows_stale_scan_dates_but_not_changed_inputs(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            image = {"tag": "docker.io/elvenobservability/elven-collector:1.0.1-dev", "digest": "sha256:" + "a" * 64,
                     "platforms": ["linux/amd64", "linux/arm64"], "inputsSha256": {"source.go": "b" * 64},
                     "archive": "collector.oci.tar", "metadata": "collector.metadata.json",
                     "scans": {"old": {"status": "failed", "scannedAt": "2000-01-01T00:00:00Z"}}}
            for field in ("archive", "metadata"):
                raw = ("synthetic-" + field).encode()
                (root / image[field]).write_bytes(raw)
                image[field + "Sha256"] = hashlib.sha256(raw).hexdigest()
            manifest = {"revision": "c" * 40, "dirtySource": False, "images": {"collector": image}}
            lock = {"images": {"collector": {"distribution": {"repository": "docker.io/elvenobservability/elven-collector"}}}}
            inputs = lambda name, item: {"source.go": "b" * 64}
            admit = self.guard["admit_family"]
            admit(root, manifest, lock, inputs)
            edits = (lambda m: m.update(dirtySource=True), lambda m: m.update(revision="short"),
                     lambda m: m["images"]["collector"].update(inputsSha256={"changed.go": "b" * 64}),
                     lambda m: m["images"]["collector"].update(platforms=["linux/amd64"]),
                     lambda m: m["images"]["collector"].update(tag="docker.io/customer/collector:1.0.1-dev"),
                     lambda m: m["images"]["collector"].update(archive="../collector.oci.tar"))
            for edit in edits:
                changed = copy.deepcopy(manifest); edit(changed)
                with self.assertRaises(ValueError):
                    admit(root, changed, lock, inputs)
            blocked = {**lock, "runtimeBlocks": {image["digest"]: "synthetic revoked digest"}}
            with self.assertRaises(ValueError):
                admit(root, manifest, blocked, inputs)
            (root / image["archive"]).write_bytes(b"changed bytes")
            with self.assertRaises(ValueError):
                admit(root, manifest, lock, inputs)

    def test_evidence_filenames_are_regular_and_confined(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "original").write_text("synthetic")
            (root / "alias").symlink_to(root / "original")
            for unsafe in ("alias", "../original", "sub/original", "/tmp/original", ".", "..", ""):
                with self.assertRaises(ValueError):
                    self.guard["regular"](root, unsafe)
            self.assertEqual(self.guard["regular"](root, "original"), root / "original")

    def test_only_sanitized_reports_and_small_security_metadata_are_uploaded(self):
        uploads = [s for s in self.steps if s.get("uses", "").startswith("actions/upload-artifact@")]
        self.assertEqual(len(uploads), 2)
        runtime, security = uploads
        self.assertEqual(runtime["if"], "always()")
        self.assertEqual(runtime["with"]["path"], ".artifacts/sdk-privacy-*/report.json")
        self.assertTrue(runtime["with"]["include-hidden-files"])
        self.assertEqual(runtime["with"]["if-no-files-found"], "error")
        self.assertEqual(security["if"], "always()")
        self.assertIn("artifacts/images/*.govulncheck.json", security["with"]["path"])
        self.assertIn("artifacts/instrumentation/instrumentation-release.json", security["with"]["path"])
        for step in uploads:
            for forbidden in ("*.tar", "*.oci", "kubeconfig", "*.key", "*.pem", "**/*", "diagnostics"):
                self.assertNotIn(forbidden, step["with"]["path"])


if __name__ == "__main__":
    unittest.main()
