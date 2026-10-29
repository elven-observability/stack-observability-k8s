"""Kind teardown must never fall back to the caller's kubeconfig.

No Docker/Kubernetes calls: the fake Kind models its kubeconfig lock/write and
reproduces the unprivileged CI failure when KUBECONFIG points to /dev/null.
"""
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("kind_lab_cleanup_under_test", ROOT / "scripts/test-kind.py")
LAB_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAB_MODULE)


class KindCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="elven-kind-cleanup-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.lab = LAB_MODULE.Lab.__new__(LAB_MODULE.Lab)
        self.lab.name = "elven-dist-cleanup-synthetic"
        self.lab.namespace = "elven-cleanup-synthetic"
        self.lab.directory = self.directory
        self.lab.kubeconfig = self.directory / "kubeconfig"
        self.lab.kubeconfig.write_text("synthetic isolated kubeconfig\n")
        self.lab.kubeconfig.chmod(0o600)
        self.lab.created = True
        self.lab.keep = False
        self.lab.processes = []
        self.lab.report = {"completed": True, "checks": [{"name": "synthetic functional check", "result": "passed"}]}
        self.lab.kube = mock.Mock(return_value=SimpleNamespace(stdout="synthetic diagnostics\n"))

    def fake_kind_delete(self, args, **kwargs):
        self.assertEqual(args[:3], ["kind", "delete", "cluster"])
        self.assertEqual(args[args.index("--name") + 1], self.lab.name)
        # Model actual Kind precedence. Removing --kubeconfig from cleanup
        # reproduces the /dev/null.lock failure or corrupts the user fixture.
        destination = Path(args[args.index("--kubeconfig") + 1]) if "--kubeconfig" in args else Path(os.environ["KUBECONFIG"])
        if destination == Path("/dev/null"):
            raise PermissionError("/dev/null.lock: permission denied")
        lock = destination.with_name(destination.name + ".lock")
        lock.write_text("synthetic lock\n")
        destination.write_text("synthetic isolated context removed\n")
        lock.unlink()
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def report(self):
        return json.loads((self.directory / "report.json").read_text())

    def test_delete_uses_isolated_writable_kubeconfig_when_ci_default_is_dev_null(self):
        with mock.patch.dict(os.environ, {"KUBECONFIG": "/dev/null"}), \
             mock.patch.object(LAB_MODULE, "execute", side_effect=self.fake_kind_delete) as execute:
            self.lab.cleanup()
            self.assertEqual(os.environ["KUBECONFIG"], "/dev/null")
        execute.assert_called_once()
        self.assertIn(self.lab.kubeconfig, execute.call_args.args[0])
        self.assertEqual(self.lab.kubeconfig.read_text(), "synthetic isolated context removed\n")
        self.assertFalse(self.report()["cluster_retained"])
        self.assertTrue(self.report()["completed"])

    def test_delete_preserves_the_users_kubeconfig_and_current_context(self):
        user_config = self.directory / "user-kubeconfig"
        original = "current-context: synthetic-user-context\ncontexts: []\n"
        user_config.write_text(original)
        with mock.patch.dict(os.environ, {"KUBECONFIG": str(user_config)}), \
             mock.patch.object(LAB_MODULE, "execute", side_effect=self.fake_kind_delete):
            self.lab.cleanup()
            self.assertEqual(os.environ["KUBECONFIG"], str(user_config))
        self.assertEqual(user_config.read_text(), original)
        self.assertFalse((self.directory / "user-kubeconfig.lock").exists())

    def test_partial_creation_without_a_kubeconfig_still_passes_the_isolated_path(self):
        self.lab.kubeconfig.unlink()
        with mock.patch.dict(os.environ, {"KUBECONFIG": "/dev/null"}), \
             mock.patch.object(LAB_MODULE, "execute", side_effect=self.fake_kind_delete):
            self.lab.cleanup()
        self.lab.kube.assert_not_called()
        self.assertFalse(self.report()["cluster_retained"])

    def test_keep_does_not_delete_the_cluster(self):
        self.lab.keep = True
        with mock.patch.object(LAB_MODULE, "execute") as execute:
            self.lab.cleanup()
        execute.assert_not_called()
        self.assertTrue(self.report()["cluster_retained"])

    def test_no_created_cluster_never_invokes_kind_delete(self):
        self.lab.created = False
        with mock.patch.object(LAB_MODULE, "execute") as execute:
            self.lab.cleanup()
        execute.assert_not_called()
        self.lab.kube.assert_not_called()
        self.assertFalse(self.report()["cluster_retained"])

    def test_delete_failure_preserves_results_and_still_fails_the_caller(self):
        with mock.patch.object(LAB_MODULE, "execute", side_effect=RuntimeError("synthetic teardown failure")), \
             self.assertRaisesRegex(RuntimeError, "synthetic teardown failure"):
            self.lab.cleanup()
        report = self.report()
        self.assertTrue(report["completed"])
        self.assertTrue(report["cluster_retained"])
        self.assertEqual(report["checks"], self.lab.report["checks"])
        self.assertEqual(report["cleanup_error"], "synthetic teardown failure")


if __name__ == "__main__":
    unittest.main(verbosity=2)
