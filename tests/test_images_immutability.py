"""Release tags must be checked as a complete set before any image upload."""
import contextlib
import datetime as dt
import importlib.util
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("images_release_immutability", ROOT / "scripts/images-release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)

COMPONENTS = ("collector", "beyla", "alloy")
CHECKSUM = "f" * 64


def release_fixture():
    timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
    platforms = ["linux/amd64", "linux/arm64"]
    lock = {"distribution": {"platforms": platforms},
            "tools": {"trivy": "1.0.0", "govulncheck": "1.0.0"}, "images": {}}
    manifest = {"version": "v1.0.0", "revision": "test-revision", "dirtySource": False, "images": {}}
    for name, digit in zip(COMPONENTS, "abc"):
        repository = release.APPROVED_REPOSITORIES[name]
        lock["images"][name] = {"distribution": {"repository": repository}}
        image = {"tag": repository + ":v1.0.0", "digest": "sha256:" + digit * 64,
                 "archive": name + ".oci.tar", "archiveSha256": CHECKSUM,
                 "metadata": name + ".metadata.json", "metadataSha256": CHECKSUM,
                 "platforms": platforms, "scans": {}}
        for platform in platforms:
            image["scans"][platform] = {"status": "passed", "highCriticalCount": 0,
                "scanner": "trivy/1.0.0", "scannedAt": timestamp, "database": {"UpdatedAt": timestamp},
                "report": name + ".scan.json", "reportSha256": CHECKSUM,
                "sbom": name + ".sbom.json", "sbomSha256": CHECKSUM}
        if name == "collector":
            reference = image["tag"] + "@" + image["digest"]
            image["licenseBundles"] = {platform: {"status": "passed", "image": reference,
                "verifiedNoticeCount": 10, "report": "licenses.json", "reportSha256": CHECKSUM}
                for platform in platforms}
            image["govulncheck"] = {platform: {"status": "passed", "tool": "govulncheck/1.0.0",
                "image": reference, "scannedAt": timestamp, "report": "go.json", "reportSha256": CHECKSUM}
                for platform in platforms}
        manifest["images"][name] = image
    return manifest, lock


def completed(tag, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(["crane", "digest", tag], returncode, stdout, stderr)


def missing(tag):
    return completed(tag, 1, stderr="Error: fetching manifest: MANIFEST_UNKNOWN: manifest unknown")


class RemoteTagStateTests(unittest.TestCase):
    def setUp(self):
        self.tag = "docker.io/elvenobservability/elven-collector:v1.0.0"
        self.digest = "sha256:" + "a" * 64

    def test_only_explicit_manifest_absence_is_allowed(self):
        manifest_url = "https://registry-1.docker.io/v2/elvenobservability/elven-collector/manifests/v1.0.0"
        for diagnostic in ("MANIFEST_UNKNOWN: manifest unknown",
                           f"GET {manifest_url}: unexpected status code 404 Not Found"):
            with self.subTest(diagnostic=diagnostic):
                result = completed(self.tag, 1, stderr=diagnostic)
                self.assertEqual(release.remote_tag_state(self.tag, self.digest, result), "missing")

    def test_ambiguous_not_found_authentication_and_transport_errors_fail_closed(self):
        for diagnostic in ("404 Not Found", "file not found", "UNAUTHORIZED: authentication required",
                           "GET https://auth.docker.io/token: unexpected status code 404 Not Found",
                           "context deadline exceeded", "connection reset by peer",
                           "MANIFEST_UNKNOWN: upstream returned 503 Service Unavailable",
                           "MANIFEST_UNKNOWN: UNAUTHORIZED"):
            with self.subTest(diagnostic=diagnostic), self.assertRaises(RuntimeError):
                release.remote_tag_state(self.tag, self.digest, completed(self.tag, 1, stderr=diagnostic))

    def test_empty_or_malformed_success_is_not_an_existing_tag(self):
        for digest in ("", "sha256:invalid", self.digest + "\n" + self.digest):
            with self.subTest(digest=digest), self.assertRaises(RuntimeError):
                release.remote_tag_state(self.tag, self.digest, completed(self.tag, stdout=digest))


class PublicationImmutabilityTests(unittest.TestCase):
    def publish_with_results(self, outcomes):
        manifest, lock = release_fixture()
        self.events = []
        by_tag = {image["tag"]: image for image in manifest["images"].values()}

        def query(command, **kwargs):
            self.assertEqual(command[:2], ["crane", "digest"])
            self.assertTrue(kwargs["capture_output"])
            self.events.append(("lookup", command[-1]))
            outcome = outcomes[len([event for event in self.events if event[0] == "lookup"]) - 1]
            if isinstance(outcome, Exception):
                raise outcome
            return outcome(command[-1], by_tag[command[-1]]["digest"])

        def run(command, **kwargs):
            self.events.append((command[1], command[-1]))
            if command[:2] == ["crane", "digest"]:
                return by_tag[command[-1]]["digest"]
            return None

        with tempfile.TemporaryDirectory(prefix="elven-immutable-tags-test-") as folder:
            with contextlib.ExitStack() as stack:
                for name, replacement in {
                    "evidence": lambda args: Path(folder), "load_manifest": lambda directory: manifest,
                    "assert_release_environment": lambda version: None,
                    "git_state": lambda: (manifest["revision"], "0", False),
                    "sha256": lambda path: CHECKSUM, "unpack_layout": lambda *args: None,
                    "write_json": lambda *args: None, "verify_image": lambda *args: None,
                    "anonymous_registry": lambda: contextlib.nullcontext({}), "run": run,
                }.items():
                    stack.enter_context(mock.patch.object(release, name, replacement))
                stack.enter_context(mock.patch.object(release.ATTESTATIONS, "evidence_policy", return_value={"fixture": True}))
                stack.enter_context(mock.patch.object(release.subprocess, "run", side_effect=query))
                stack.enter_context(mock.patch("builtins.print"))
                release.publish(SimpleNamespace(), lock)
        return manifest

    def assert_no_push(self):
        self.assertFalse(any(event[0] == "push" for event in self.events), self.events)

    def test_conflict_in_last_component_blocks_every_push(self):
        same = lambda tag, digest: completed(tag, stdout=digest)
        conflict = lambda tag, digest: completed(tag, stdout="sha256:" + "d" * 64)
        with self.assertRaisesRegex(ValueError, "different digest"):
            self.publish_with_results([same, same, conflict])
        self.assertEqual(len(self.events), 3)
        self.assert_no_push()

    def test_all_missing_tags_are_checked_before_first_push(self):
        absent = lambda tag, digest: missing(tag)
        manifest = self.publish_with_results([absent] * 3)
        self.assertEqual([event[0] for event in self.events[:3]], ["lookup"] * 3)
        self.assertEqual(len([event for event in self.events if event[0] == "push"]), 3)
        self.assertEqual(manifest["publicationStatus"], "verified")

    def test_same_digests_are_idempotent_without_reupload(self):
        same = lambda tag, digest: completed(tag, stdout=digest)
        manifest = self.publish_with_results([same] * 3)
        self.assert_no_push()
        self.assertEqual(manifest["publicationStatus"], "verified")

    def test_foreign_repository_or_tag_is_rejected_before_every_external_write(self):
        for target in ("docker.io/untrusted/elven-collector:v1.0.0",
                       "docker.io/elvenobservability/elven-collector:v1.0.1"):
            manifest, lock = release_fixture()
            manifest["images"]["alloy"]["tag"] = target  # last component must still block the whole release
            with self.subTest(target=target), contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(release, "evidence", return_value=ROOT))
                stack.enter_context(mock.patch.object(release, "load_manifest", return_value=manifest))
                stack.enter_context(mock.patch.object(release, "assert_release_environment"))
                stack.enter_context(mock.patch.object(release, "git_state", return_value=(manifest["revision"], "0", False)))
                stack.enter_context(mock.patch.object(release, "sha256", return_value=CHECKSUM))
                preflight = stack.enter_context(mock.patch.object(release, "preflight_remote_tags"))
                command = stack.enter_context(mock.patch.object(release, "run"))
                with self.assertRaisesRegex(ValueError, "publication repository or release tag"):
                    release.publish(SimpleNamespace(), lock)
                preflight.assert_not_called()
                command.assert_not_called()

    def test_network_authentication_and_execution_failures_block_every_push(self):
        absent = lambda tag, digest: missing(tag)
        for error in ("UNAUTHORIZED: authentication required", "context deadline exceeded",
                      "GET https://registry.example/v2/x/manifests/v1.0.0: 503 Service Unavailable"):
            failure = lambda tag, digest: completed(tag, 1, stderr=error)
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, "preflight failed"):
                self.publish_with_results([absent, absent, failure])
            self.assertEqual(len(self.events), 3)
            self.assert_no_push()
        with self.assertRaisesRegex(ValueError, "preflight failed"):
            self.publish_with_results([OSError("crane unavailable"), absent, absent])
        self.assertEqual(len(self.events), 3)
        self.assert_no_push()


if __name__ == "__main__":
    unittest.main(verbosity=2)
