"""Runtime evidence follows the isolated Kubernetes server, not the host CPU."""
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("kind_lab_metadata_under_test", ROOT / "scripts/test-kind.py")
LAB_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAB_MODULE)


class KindMetadataTests(unittest.TestCase):
    def setUp(self):
        self.lab = LAB_MODULE.Lab.__new__(LAB_MODULE.Lab)
        self.lab.report = {"not_proven": ["unrelated scope limit", *LAB_MODULE.RUNTIME_LIMITS.values()]}

    def assert_architecture(self, version, tested, reported):
        self.lab.record_server_runtime(version)
        self.assertEqual(self.lab.report["runtime_platform"], {
            "source": "kubectl version.serverVersion.platform", "reported": reported, "tested": tested,
        })
        self.assertIn("unrelated scope limit", self.lab.report["not_proven"])
        for platform, limit in LAB_MODULE.RUNTIME_LIMITS.items():
            self.assertEqual(limit in self.lab.report["not_proven"], platform != tested)

    def test_amd64_server_does_not_claim_arm64_runtime(self):
        self.assert_architecture({"serverVersion": {"platform": "linux/amd64"}}, "linux/amd64", "linux/amd64")

    def test_arm64_server_does_not_claim_amd64_runtime(self):
        self.assert_architecture({"serverVersion": {"platform": "linux/arm64"}}, "linux/arm64", "linux/arm64")

    def test_unknown_platform_proves_neither_supported_architecture(self):
        for platform in ("linux/riscv64", "darwin/amd64", "", "LINUX/AMD64", "linux/amd64/extra"):
            with self.subTest(platform=platform):
                self.assert_architecture({"serverVersion": {"platform": platform}}, None, platform)

    def test_missing_or_malformed_server_platform_proves_neither_architecture(self):
        for version in ({}, {"serverVersion": {}}, {"serverVersion": None},
                        {"serverVersion": {"platform": None}}, {"serverVersion": {"platform": ["linux/amd64"]}}):
            with self.subTest(version=version):
                self.assert_architecture(version, None, None)

    def test_unknown_followup_does_not_keep_stale_architecture_evidence(self):
        self.lab.record_server_runtime({"serverVersion": {"platform": "linux/amd64"}})
        self.assert_architecture({"serverVersion": {}}, None, None)

    def test_initial_report_claims_neither_architecture_before_boot(self):
        with tempfile.TemporaryDirectory(prefix="elven-kind-metadata-test-") as temporary, \
             mock.patch.object(LAB_MODULE, "ROOT", Path(temporary)):
            lab = LAB_MODULE.Lab(LAB_MODULE.KIND_NODE)
        self.assertNotIn("runtime_platform", lab.report)
        for limit in LAB_MODULE.RUNTIME_LIMITS.values():
            self.assertIn(limit, lab.report["not_proven"])

    def test_boot_records_actual_server_platform_not_the_client_platform(self):
        version = {"clientVersion": {"platform": "darwin/arm64"},
                   "serverVersion": {"gitVersion": "v1.37.0", "platform": "linux/amd64"}}
        with tempfile.TemporaryDirectory(prefix="elven-kind-metadata-test-") as temporary, \
             mock.patch.object(LAB_MODULE, "ROOT", Path(temporary)):
            lab = LAB_MODULE.Lab(LAB_MODULE.KIND_NODE)

            def fake_execute(args, **kwargs):
                if args[:3] == ["docker", "context", "inspect"]:
                    return SimpleNamespace(stdout="unix:///synthetic-only/docker.sock\n")
                self.assertEqual(args[:3], ["kind", "create", "cluster"])
                lab.kubeconfig.write_text("synthetic isolated kubeconfig\n")
                return SimpleNamespace(stdout="")

            lab.kube = mock.Mock(return_value=SimpleNamespace(stdout=json.dumps(version)))
            lab.apply = mock.Mock()
            lab.check = mock.Mock()
            with mock.patch.dict(os.environ, {"DOCKER_HOST": ""}), \
                 mock.patch.object(LAB_MODULE, "execute", side_effect=fake_execute):
                lab.boot()
        self.assertEqual(lab.report["versions"], version)
        self.assertEqual(lab.report["runtime_platform"]["tested"], "linux/amd64")
        self.assertNotIn("native amd64 runtime", lab.report["not_proven"])
        self.assertIn("native arm64 runtime", lab.report["not_proven"])
        lab.kube.assert_called_once_with("version", "-o", "json")


if __name__ == "__main__":
    unittest.main(verbosity=2)
