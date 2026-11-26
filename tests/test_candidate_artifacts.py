"""Fresh artifact admission; no Docker, downloads or application execution."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("candidate_artifact_guard", ROOT / "scripts/qualify-candidate-artifacts.py")
C = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(C)
NOW = datetime(2026, 11, 26, 12, tzinfo=timezone.utc)


class CandidateArtifacts(unittest.TestCase):
    def test_manifest_mutations_and_disk_tamper_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in ("collector.oci.tar", "scan.json", "sbom.json", "go.json"):
                (root / name).write_bytes(b"synthetic " + name.encode())
            scan = {"status": "passed", "highCriticalCount": 0, "scanner": "trivy/test",
                    "scannedAt": NOW.isoformat(), "database": {"UpdatedAt": NOW.isoformat()},
                    "report": "scan.json", "reportSha256": C.digest(root / "scan.json"),
                    "sbom": "sbom.json", "sbomSha256": C.digest(root / "sbom.json")}
            image = {"tag": "docker.io/elvenobservability/elven-collector:1.0.1-dev", "digest": "sha256:" + "1"*64,
                     "archive": "collector.oci.tar", "archiveSha256": C.digest(root / "collector.oci.tar"),
                     "inputsSha256": {"processor.go": "2"*64},
                     "scans": {"linux/amd64": copy.deepcopy(scan), "linux/arm64": copy.deepcopy(scan)}}
            audit = {"status": "passed", "exitCode": 0, "tool": "govulncheck/test", "image": image["tag"]+"@"+image["digest"],
                     "scannedAt": NOW.isoformat(), "report": "go.json", "reportSha256": C.digest(root / "go.json")}
            image["govulncheck"] = {p: copy.deepcopy(audit) for p in image["scans"]}
            manifest = {"dirtySource": False, "revision": "3"*40, "images": {"collector": image}}
            lock = {"images": {"collector": {"distribution": {"repository": "docker.io/elvenobservability/elven-collector"}}},
                    "tools": {"trivy": "test", "govulncheck": "test"}, "runtimeBlocks": {}}
            expected = lambda n, i: {"processor.go": "2"*64}
            self.assertIn("collector", C.qualify(root, manifest, lock, expected, now=NOW))
            for mutate in (
                lambda m: m.update(dirtySource=True),
                lambda m: m["images"].update(other=image),
                lambda m: m["images"]["collector"].update(inputsSha256={}),
                lambda m: m["images"]["collector"].update(archive="../collector.oci.tar"),
                lambda m: m["images"]["collector"].update(govulncheck={}),
                lambda m: m["images"]["collector"]["scans"]["linux/amd64"].update(highCriticalCount=1),
                lambda m: m["images"]["collector"]["scans"]["linux/amd64"].update(highCriticalCount=False),
                lambda m: m["images"]["collector"]["scans"]["linux/amd64"].update(scannedAt=(NOW-timedelta(hours=25)).isoformat()),
                lambda m: m["images"]["collector"]["scans"]["linux/amd64"].update(scannedAt=(NOW+timedelta(hours=1)).isoformat()),
            ):
                bad = copy.deepcopy(manifest); mutate(bad)
                with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                    C.qualify(root, bad, lock, expected, now=NOW)
            (root / "scan.json").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "checksum"):
                C.qualify(root, manifest, lock, expected, now=NOW)
