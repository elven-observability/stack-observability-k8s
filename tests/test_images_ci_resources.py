"""Keep disposable CI cache cleanup scoped and separate from release payloads."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]


class ImageCIResourcesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workflow = yaml.safe_load((ROOT / ".github/workflows/images.yaml").read_text())
        cls.job = workflow["jobs"]["build-and-scan"]
        cls.steps = cls.job["steps"]

    def test_job_and_build_have_distinct_bounded_timeouts(self):
        self.assertEqual(self.job["timeout-minutes"], 60)
        build = next(step for step in self.steps if "images-release.py build" in step.get("run", ""))
        self.assertEqual(build["timeout-minutes"], 30)

    def test_cleanup_targets_only_the_action_created_builder(self):
        builder = next(step for step in self.steps if step.get("id") == "builder")
        self.assertTrue(builder["uses"].startswith("docker/setup-buildx-action@"))
        cleanups = [step for step in self.steps if "buildx prune" in step.get("run", "")]
        self.assertEqual(len(cleanups), 1)
        cleanup = cleanups[0]
        self.assertEqual(cleanup["if"], "success()")
        self.assertEqual(cleanup["env"]["ELVEN_CI_BUILDER"], "${{ steps.builder.outputs.name }}")
        command = cleanup["run"]
        self.assertIn('test -n "$ELVEN_CI_BUILDER"', command)
        self.assertIn('docker buildx prune --builder "$ELVEN_CI_BUILDER" --all --force', command)
        for forbidden in ("docker system prune", "docker image prune", "docker volume prune", "rm -rf"):
            self.assertNotIn(forbidden, command)

    def test_cleanup_preserves_and_checks_all_exported_payloads(self):
        build_index = next(i for i, step in enumerate(self.steps) if "images-release.py build" in step.get("run", ""))
        cleanup_index = next(i for i, step in enumerate(self.steps) if "buildx prune" in step.get("run", ""))
        scan_index = next(i for i, step in enumerate(self.steps) if "images-release.py scan" in step.get("run", ""))
        self.assertLess(build_index, cleanup_index)
        self.assertLess(cleanup_index, scan_index)
        command = self.steps[cleanup_index]["run"]
        self.assertIn('test -s artifacts/images/release.json', command)
        self.assertIn('{"collector", "beyla", "alloy"}', command)
        self.assertIn('hashlib.file_digest(source, "sha256")', command)
        self.assertIn('image["archiveSha256"]', command)
        self.assertGreater(command.index('image["archiveSha256"]'), command.index("buildx prune"))

    def test_storage_is_measured_before_build_and_after_cleanup(self):
        build_index = next(i for i, step in enumerate(self.steps) if "images-release.py build" in step.get("run", ""))
        before = self.steps[build_index - 1]["run"]
        after = next(step["run"] for step in self.steps if "buildx prune" in step.get("run", ""))
        for command in (before, after):
            self.assertIn('df -h "$GITHUB_WORKSPACE" "$RUNNER_TEMP"', command)
            self.assertIn("docker system df", command)
        self.assertGreater(after.index("docker system df"), after.index("buildx prune"))

    def test_actual_payload_guard_accepts_unchanged_and_rejects_modified_archive(self):
        command = next(step["run"] for step in self.steps if "buildx prune" in step.get("run", ""))
        guard = command.split("python3 - <<'PY'\n", 1)[1].split("\nPY", 1)[0]
        with tempfile.TemporaryDirectory(prefix="elven-ci-payload-test-") as folder:
            directory = Path(folder) / "artifacts/images"
            directory.mkdir(parents=True)
            images = {}
            for name in ("collector", "beyla", "alloy"):
                payload = (name + "-synthetic-export").encode()
                archive = directory / (name + ".oci.tar")
                archive.write_bytes(payload)
                images[name] = {"archive": archive.name, "archiveSha256": hashlib.sha256(payload).hexdigest()}
            (directory / "release.json").write_text(json.dumps({"images": images}))
            accepted = subprocess.run([sys.executable, "-c", guard], cwd=folder, text=True, capture_output=True)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            (directory / "collector.oci.tar").write_bytes(b"modified-export")
            rejected = subprocess.run([sys.executable, "-c", guard], cwd=folder, text=True, capture_output=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("OCI archive changed during cache cleanup", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
