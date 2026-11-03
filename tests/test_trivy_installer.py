"""CI tool supply chain tests; no downloads, installs or executable runs."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("elven_pinned_trivy", ROOT / "scripts/images-install-trivy.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class TrivyInstallerTests(unittest.TestCase):
    def test_both_locks_pin_the_official_binary_for_their_exact_version(self):
        for name in ("versions.lock.json", "instrumentation.lock.json"):
            version, pin = MODULE.read_pin(ROOT / name)
            self.assertEqual(version, "0.76.1")
            self.assertEqual(pin["sha256"], "c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0")

    def test_url_version_or_checksum_mismatch_is_rejected(self):
        valid = json.loads((ROOT / "versions.lock.json").read_text())
        for field, value in (("url", "https://unapproved.invalid/trivy"), ("sha256", ""),
                             ("url", "https://github.com/aquasecurity/trivy/releases/download/v0.76.0/trivy_0.76.0_Linux-64bit.tar.gz")):
            with tempfile.TemporaryDirectory() as temporary:
                changed = json.loads(json.dumps(valid))
                changed["tools"]["trivyLinuxAmd64"][field] = value
                path = Path(temporary) / "lock.json"
                path.write_text(json.dumps(changed))
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    MODULE.read_pin(path)

    def archive(self, root, *, symlink=False):
        path = root / "binary.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            member = tarfile.TarInfo("trivy")
            if symlink:
                member.type = tarfile.SYMTYPE
                member.linkname = "/synthetic/unrelated"
                archive.addfile(member)
            else:
                payload = b"synthetic never-executed tool fixture"
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
            other = tarfile.TarInfo("../must-not-be-extracted")
            other.size = 4
            archive.addfile(other, io.BytesIO(b"test"))
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def test_verified_extract_reads_only_the_regular_binary_and_never_other_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive, digest = self.archive(root)
            directory = root / "owned"
            directory.mkdir()
            binary = MODULE.extract_verified(archive, directory, digest)
            self.assertEqual(binary.read_bytes(), b"synthetic never-executed tool fixture")
            self.assertEqual(binary.stat().st_mode & 0o777, 0o755)
            self.assertEqual(set(directory.iterdir()), {binary})

    def test_bad_checksum_or_symlink_never_installs_an_executable(self):
        for symlink in (False, True):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive, digest = self.archive(root, symlink=symlink)
                with self.assertRaises(ValueError):
                    MODULE.extract_verified(archive, root, digest if symlink else "0" * 64)
                self.assertFalse((root / "trivy").exists())

    def test_local_or_self_hosted_execution_is_refused_before_io(self):
        for environment in ({}, {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"}):
            with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(MODULE, "read_pin") as read:
                with self.assertRaisesRegex(ValueError, "disposable"):
                    MODULE.install(ROOT / "versions.lock.json")
                read.assert_not_called()

    def test_workflows_do_not_checkout_or_execute_an_upstream_main_installer(self):
        for filename, lock in (("images.yaml", "versions.lock.json"), ("instrumentation.yaml", "instrumentation.lock.json")):
            source = (ROOT / ".github/workflows" / filename).read_text()
            workflow = yaml.safe_load(source)
            self.assertNotIn("aquasecurity/setup-trivy@", source)
            self.assertIn("python3 scripts/images-install-trivy.py --lock " + lock, source)
            self.assertNotIn("contrib/install.sh", source)
            self.assertTrue(workflow["jobs"])


if __name__ == "__main__":
    unittest.main()
