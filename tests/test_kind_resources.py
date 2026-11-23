"""Kind admission must stop before pulling or creating on a constrained engine."""
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("elven_kind_resource_gate", ROOT / "scripts/test-kind.py")
LAB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAB)


class ResourceGateTests(unittest.TestCase):
    def test_low_disk_stops_before_container_or_kind_operations(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(LAB, "ROOT", Path(folder)):
            lab = LAB.Lab(LAB.KIND_NODE)
            with mock.patch.dict(os.environ, {"DOCKER_HOST": ""}), \
                 mock.patch.object(LAB.shutil, "disk_usage", return_value=SimpleNamespace(free=3 * 1024**3)), \
                 mock.patch.object(LAB, "execute", return_value=SimpleNamespace(stdout="unix:///synthetic-only.sock")) as run:
                with self.assertRaisesRegex(ValueError, "insufficient host disk"):
                    lab.boot()
            self.assertFalse(lab.created)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0][:3], ["docker", "context", "inspect"])
            self.assertEqual(lab.report["resource_preflight"]["host_free_bytes"], 3 * 1024**3)

    def test_running_workload_stops_before_kind_create_and_never_deletes(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(LAB, "ROOT", Path(folder)):
            lab = LAB.Lab(LAB.KIND_NODE)
            with mock.patch.dict(os.environ, {"DOCKER_HOST": ""}), \
                 mock.patch.object(LAB.shutil, "disk_usage", return_value=SimpleNamespace(free=32 * 1024**3)), \
                 mock.patch.object(LAB, "execute", side_effect=[SimpleNamespace(stdout="unix:///synthetic-only.sock"), SimpleNamespace(stdout="synthetic-existing-container")]) as run:
                with self.assertRaisesRegex(ValueError, "running workloads"):
                    lab.boot()
            self.assertFalse(lab.created)
            self.assertEqual(run.call_args.args[0], ["docker", "ps", "--quiet"])
            self.assertEqual(run.call_count, 2)


if __name__ == "__main__":
    unittest.main()
