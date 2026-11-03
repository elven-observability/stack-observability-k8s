"""Bounded subprocesses with sanitized timeouts; no real process or cluster IO."""
import argparse
import importlib.machinery
import importlib.util
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
LOADER = importlib.machinery.SourceFileLoader("elven_timeouts_under_test", str(ROOT / "elven"))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
cli = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(cli)
PRIVATE = "SYNTHETIC_SECRET_NOT_FOR_ERRORS"


class CommandTimeoutTests(unittest.TestCase):
    def setUp(self):
        self.args = argparse.Namespace(context="synthetic-only", kubeconfig="/synthetic/never-read",
            release="elven-synthetic", namespace="elven-synthetic", timeout="600s")

    def test_default_process_deadline_is_120_seconds(self):
        result = SimpleNamespace(returncode=0, stdout="synthetic-result", stderr="")
        with mock.patch.object(cli.subprocess, "run", return_value=result) as run:
            self.assertEqual(cli.run(["synthetic-command", "read"]), "synthetic-result")
        self.assertEqual(run.call_args.kwargs["timeout"], 120)

    def test_helm_wait_timeout_includes_explicit_duration_plus_grace(self):
        for duration, expected in (("600s", 690), ("15m", 990), ("2h", 7290), ("1s", 91)):
            for operation in ("install", "upgrade", "rollback", "uninstall", "test"):
                with self.subTest(duration=duration, operation=operation), \
                     mock.patch.object(cli, "run", return_value="synthetic") as run:
                    cli.helm(self.args, operation, "--wait", "--timeout", duration, online=True)
                self.assertEqual(run.call_args.kwargs["timeout"], expected)

    def test_helm_deadline_does_not_depend_on_binary_filename(self):
        with mock.patch.dict(cli.os.environ, {"ELVEN_HELM_BINARY": "/synthetic/opaque-executable"}), \
             mock.patch.object(cli.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="", stderr="")) as run:
            cli.helm(self.args, "upgrade", "--wait", "--timeout", "600s", online=True)
        self.assertEqual(run.call_args.kwargs["timeout"], 690)

    def test_long_real_rollout_is_not_killed_at_default_command_deadline(self):
        with mock.patch.object(cli.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="", stderr="")) as run:
            cli.helm(self.args, "rollback", "elven-synthetic", "1", "--wait", "--timeout", "600s", online=True)
        self.assertGreater(run.call_args.kwargs["timeout"], 600)

    def test_wait_without_timeout_gets_helm_default_plus_grace(self):
        self.assertEqual(cli.helm_command_timeout(("upgrade", "--wait")), 390)
        self.assertEqual(cli.helm_command_timeout(("list",)), 120)
        self.assertEqual(cli.helm_command_timeout(("template", "--timeout", "600s")), 120)

    def test_last_timeout_flag_wins_even_with_similarly_named_values_file(self):
        self.assertEqual(cli.helm_command_timeout(("upgrade", "--values", "--timeout", "--wait",
                                                   "--timeout", "600s")), 690)
        self.assertEqual(cli.helm_command_timeout(("upgrade", "--timeout=600s")), 690)

    def test_invalid_wait_timeout_fails_before_process_creation(self):
        for duration in ("0s", "-1s", "unbounded", "1.5h", "999999h"):
            with self.subTest(duration=duration), mock.patch.object(cli, "run") as run, \
                 self.assertRaisesRegex(cli.Failure, "bounded positive"):
                cli.helm(self.args, "upgrade", "--wait", "--timeout", duration)
            run.assert_not_called()

    def test_timeout_error_never_echoes_arguments_payload_or_partial_output(self):
        error = subprocess.TimeoutExpired([PRIVATE, "Authorization: Bearer " + PRIVATE], 120,
                                          output=PRIVATE, stderr=PRIVATE)
        with mock.patch.object(cli.subprocess, "run", side_effect=error) as run, \
             self.assertRaises(cli.Failure) as caught:
            cli.run([PRIVATE, "Authorization: Bearer " + PRIVATE], data=PRIVATE)
        message = str(caught.exception)
        self.assertNotIn(PRIVATE, message)
        self.assertNotIn("Authorization", message)
        self.assertIn("UNKNOWN", message)
        self.assertIn("no cleanup", message)
        run.assert_called_once()
        self.assertTrue(caught.exception.__suppress_context__)

    def test_permission_probe_is_bounded_and_timeout_is_not_authorization(self):
        error = subprocess.TimeoutExpired([PRIVATE], 120, output=PRIVATE, stderr=PRIVATE)
        with mock.patch.object(cli.subprocess, "run", side_effect=error) as run, \
             self.assertRaises(cli.Failure) as caught:
            cli.can_i(self.args, "get", "pods", True)
        self.assertEqual(run.call_args.kwargs["timeout"], 120)
        self.assertIn("authorization is UNKNOWN", str(caught.exception))
        self.assertNotIn(PRIVATE, str(caught.exception))

    def test_install_timeout_preserves_reservation_and_does_not_commit_or_clean_up(self):
        settings = {"credentials": {"existingSecret": "elven-ingest"},
                    "tls": {"existingSecret": "elven-tls"}, "gateway": {"persistence": {"enabled": True}}}
        error = subprocess.TimeoutExpired([PRIVATE], 690, output=PRIVATE, stderr=PRIVATE)
        with tempfile.TemporaryDirectory(prefix="elven-timeout-test-") as folder, \
             mock.patch.object(cli, "get_secret", return_value={"metadata": {"uid": "synthetic-existing"}}), \
             mock.patch.object(cli, "reserve_storage") as reserve, \
             mock.patch.object(cli, "write_storage_identity") as commit, mock.patch.object(cli, "kube") as kube, \
             mock.patch.object(cli.subprocess, "run", side_effect=error) as run, \
             self.assertRaisesRegex(cli.Failure, "completion is UNKNOWN"):
            cli.install(self.args, {"metadata": {"name": self.args.namespace}}, settings, [], Path(folder), 4)
        reserve.assert_called_once()
        commit.assert_not_called()
        kube.assert_not_called()
        self.assertEqual(run.call_args.kwargs["timeout"], 690)


if __name__ == "__main__":
    unittest.main(verbosity=2)
