"""Production must never silently consume unpromoted or substituted images."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from test_cli import cli


def approved_lock():
    return {"distribution": {"publicationStatus": "verified"}, "images": {
        name: {"distribution": {"status": "verified", "repository": f"docker.io/elvenobservability/{name}",
                                "digest": "sha256:" + digit * 64}}
        for name, digit in (("collector", "a"), ("beyla", "b"), ("alloy", "c"))}}


def selected_values():
    return {"modules": {}, "images": {name: dict(value["distribution"])
            for name, value in approved_lock()["images"].items()}}


class ProductionGateTests(unittest.TestCase):
    def check_with_lock(self, value, settings=None):
        with tempfile.TemporaryDirectory(prefix="elven-image-policy-") as folder:
            root = Path(folder)
            (root / "versions.lock.json").write_text(json.dumps(value))
            with mock.patch.object(cli, "ROOT", root):
                cli.require_promoted_images(settings or selected_values())

    def test_unpublished_release_and_missing_lock_are_rejected(self):
        with self.assertRaisesRegex(cli.Failure, "blocked"):
            self.check_with_lock({"distribution": {"publicationStatus": "not-published"}})
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(cli, "ROOT", Path(folder)):
            with self.assertRaisesRegex(cli.Failure, "missing"):
                cli.require_promoted_images(selected_values())

    def test_approved_exact_repository_and_digest_are_accepted(self):
        self.check_with_lock(approved_lock())
        selected = selected_values()
        selected["images"]["collector"]["repository"] = "elvenobservability/collector"
        self.check_with_lock(approved_lock(), selected)

    def test_changed_digest_or_registry_is_never_adopted(self):
        for field, value in (("digest", "sha256:" + "d" * 64), ("repository", "untrusted.example/collector")):
            settings = selected_values()
            settings["images"]["collector"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(cli.Failure, "does not match"):
                self.check_with_lock(approved_lock(), settings)

    def test_individual_image_must_be_verified_even_if_release_is_verified(self):
        value = approved_lock()
        value["images"]["collector"]["distribution"]["status"] = "not-published"
        with self.assertRaisesRegex(cli.Failure, "does not match"):
            self.check_with_lock(value)

    def test_optional_modules_require_their_own_promoted_image(self):
        for module, image in (("ebpf", "beyla"), ("profiles", "alloy")):
            settings, value = selected_values(), approved_lock()
            settings["modules"][module] = {"enabled": True}
            value["images"][image]["distribution"]["digest"] = None
            with self.subTest(module=module), self.assertRaisesRegex(cli.Failure, f"images.{image}"):
                self.check_with_lock(value, settings)

    def test_development_opt_in_is_explicit_and_warns(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output), mock.patch.object(cli.Path, "read_text", side_effect=AssertionError("not needed")):
            cli.require_promoted_images({}, development=True)
        self.assertIn("not a production release", output.getvalue())


class LegacyIsolationTests(unittest.TestCase):
    def test_every_legacy_shell_entrypoint_refuses_execution_by_default(self):
        root = Path(__file__).resolve().parents[1]
        scripts = sorted((root / "legacy/v0").rglob("*.sh"))
        self.assertTrue(scripts)
        # Even a broken guard cannot find kubectl/Helm or a user's kubeconfig.
        with tempfile.TemporaryDirectory(prefix="elven-legacy-guard-") as empty:
            for script in scripts:
                with self.subTest(script=script.name):
                    result = subprocess.run(["/bin/bash", str(script)], cwd=empty,
                        env={"PATH": empty, "KUBECONFIG": "/dev/null"}, text=True, capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 78, result.stderr)
                    self.assertIn("ELVEN_ALLOW_UNSUPPORTED_LEGACY", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
