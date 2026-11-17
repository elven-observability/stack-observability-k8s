"""An immutable client bundle must bind promoted bytes and exclude legacy kits."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("elven_distribution_package", ROOT / "scripts/package-distribution.py")
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


def locks():
    result = []
    for names in (("collector", "beyla", "alloy"), ("operator", "java", "nodejs", "nodejs20", "python")):
        result.append({"distribution": {"publicationStatus": "verified", "version": "1.0.1"}, "images": {
            name: {"distribution": {"status": "verified", "tag": "v1.0.1", "sourceRevision": "a" * 40,
                   "digest": "sha256:" + hashlib.sha256(name.encode()).hexdigest(),
                   "repository": "docker.io/elvenobservability/synthetic-" + name}} for name in names}})
    return result


class DistributionPackagingTests(unittest.TestCase):
    def test_both_complete_locks_and_one_stable_source_are_required(self):
        core, sdk = locks()
        identity = P.release_identity(core, sdk)
        self.assertEqual(len(identity["images"]), 8)
        self.assertEqual(identity["imageBuildTag"], "v1.0.1")
        self.assertEqual(identity["imageSourceRevision"], "a" * 40)
        for edit in (lambda c, s: c["distribution"].update(publicationStatus="not-published"),
                     lambda c, s: s["distribution"].update(version="1.0.2"),
                     lambda c, s: s["images"].pop("java"),
                     lambda c, s: c["images"]["beyla"]["distribution"].update(sourceRevision="b" * 40),
                     lambda c, s: c["images"]["beyla"]["distribution"].update(digest=None)):
            c, s = copy.deepcopy(core), copy.deepcopy(sdk)
            edit(c, s)
            with self.assertRaises(ValueError):
                P.release_identity(c, s)

    def test_current_block_policy_overrides_signature_history(self):
        core, sdk = locks()
        core["runtimeBlocks"] = {core["images"]["beyla"]["distribution"]["digest"]: {"reason": "synthetic CVE"}}
        with self.assertRaisesRegex(ValueError, "blocked runtime"):
            P.release_identity(core, sdk)

    def source(self, extra=()):
        output = io.BytesIO()
        names = ("elven", "versions.lock.json", "instrumentation.lock.json", "charts/elven-observability/Chart.yaml",
                 "charts/elven-instrumentation/Chart.yaml", "scripts/instrumentation.py")
        with tarfile.open(fileobj=output, mode="w") as archive:
            for name in (*names, *extra):
                entry = tarfile.TarInfo("elven-observability-v1.0.1/" + name)
                entry.mode, entry.size = 0o755 if name == "elven" else 0o644, 9
                archive.addfile(entry, io.BytesIO(b"synthetic"))
        return output.getvalue()

    def test_package_is_deterministic_and_carries_the_exact_install_manifest(self):
        manifest = P.release_identity(*locks())
        first = P.archive(self.source(), manifest)
        self.assertEqual(first, P.archive(self.source(), manifest))
        with tarfile.open(fileobj=io.BytesIO(first), mode="r:gz") as archive:
            self.assertEqual(archive.getmember("elven-observability-v1.0.1/elven").mode, 0o755)
            value = json.load(archive.extractfile("elven-observability-v1.0.1/INSTALL-MANIFEST.json"))
            self.assertEqual(value, manifest)

    def test_private_legacy_recursive_and_duplicate_content_is_rejected(self):
        for name in ("kit/instalar", "legacy/v0/apply.sh", ".artifacts/credential", "../escape", "elven", "INSTALL-MANIFEST.json"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                P.archive(self.source((name,)), P.release_identity(*locks()))

    def test_allowlist_never_archives_the_whole_repository_implicitly(self):
        self.assertNotIn(".", P.PATHS)
        self.assertNotIn("kit", P.PATHS)
        self.assertNotIn("legacy", P.PATHS)
        self.assertNotIn("helmfile.yaml", P.PATHS)
        self.assertIn("versions.lock.json", P.PATHS)


if __name__ == "__main__":
    unittest.main()
