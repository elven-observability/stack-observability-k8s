"""Privacy teardown regression: no Docker calls, no real credentials or cluster."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("privacy_cleanup_under_test", ROOT / "tests/privacy-runtime.py")
PRIVACY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PRIVACY)


class PrivacyCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="elven-privacy-runtime-")
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        self.runtime = self.folder / "runtime"
        self.runtime.mkdir()
        (self.runtime / "privacy-runtime.py").write_text("# synthetic fixture\n")
        self.queues = self.folder / "queues"
        self.queues.mkdir()
        for mode in ("selective", "strict"):
            (self.queues / mode).mkdir()
        self.identity = "elven-privacy-test-0123456789ab"
        self.report = self.folder / "evidence/report.json"

    def exports(self):
        for mode in ("selective", "strict"):
            directory = self.queues / mode / "exports"
            directory.mkdir(mode=0o700)
            payload = directory / "synthetic-wal"
            payload.write_bytes(b"synthetic sanitized queue")
            payload.chmod(0o600)

    def remove_exports(self):
        for mode in ("selective", "strict"):
            for path in (self.queues / mode).iterdir():
                shutil.rmtree(path) if path.is_dir() else path.unlink()

    def clean(self):
        PRIVACY.cleanup_fixture_queues(self.folder, self.runtime, self.queues, self.identity)

    def test_helper_forwards_stdin_and_mounts_only_owned_queues_and_readonly_script(self):
        self.exports()

        def docker(*args, **options):
            self.assertEqual(args[:2], ("docker", "run"))
            self.assertIn("--interactive", args)  # Removing this reproduces EOF in CI.
            self.assertEqual(json.loads(options["data"]), {"op": "cleanup"})
            self.assertTrue(options.get("check", True))
            self.remove_exports()
            return '{"cleaned": true}'

        with mock.patch.object(PRIVACY, "run", side_effect=docker) as execute:
            self.clean()
        args = execute.call_args.args
        self.assertEqual(args[args.index("--user") + 1], "10001:10001")
        self.assertEqual(args[args.index("--network") + 1], "none")
        self.assertEqual(args[args.index("--cap-drop") + 1], "ALL")
        self.assertIn("--read-only", args)
        self.assertIn("no-new-privileges", args)
        self.assertIn(PRIVACY.PYTHON_FIXTURE, args)
        mounts = [args[index + 1] for index, value in enumerate(args) if value == "--mount"]
        self.assertEqual(mounts, [
            f"type=bind,source={self.runtime / 'privacy-runtime.py'},target=/fixture/privacy-runtime.py,readonly",
            f"type=bind,source={self.queues},target=/cleanup",
        ])
        self.assertTrue(all(not any((self.queues / mode).iterdir()) for mode in ("selective", "strict")))

    def test_nonzero_helper_or_eof_is_not_ignored_and_owned_helper_is_removed(self):
        with mock.patch.object(PRIVACY, "run", side_effect=[RuntimeError("synthetic EOFError"), ""]) as execute:
            with self.assertRaisesRegex(RuntimeError, "EOFError"):
                self.clean()
        self.assertEqual(execute.call_args_list[-1].args,
                         ("docker", "rm", "--force", self.identity + "-cleanup"))

    def test_invalid_or_false_acknowledgement_is_not_success(self):
        for response in ('{"cleaned": false}', '{}', 'not-json'):
            with self.subTest(response=response), \
                 mock.patch.object(PRIVACY, "run", side_effect=[response, ""]):
                with self.assertRaises((RuntimeError, ValueError)):
                    self.clean()

    def test_claimed_success_with_queue_contents_still_present_is_failure(self):
        self.exports()
        with mock.patch.object(PRIVACY, "run", side_effect=['{"cleaned": true}', ""]):
            with self.assertRaisesRegex(RuntimeError, "left owned queue contents"):
                self.clean()

    def test_scope_and_symlinks_are_rejected_before_docker_or_deletion(self):
        outside = self.folder / "unrelated"
        outside.mkdir()
        sentinel = outside / "must-remain"
        sentinel.write_text("synthetic unrelated data")
        (self.queues / "selective").rmdir()
        (self.queues / "selective").symlink_to(outside, target_is_directory=True)
        with mock.patch.object(PRIVACY, "run") as execute:
            with self.assertRaises(ValueError):
                self.clean()
        execute.assert_not_called()
        self.assertEqual(sentinel.read_text(), "synthetic unrelated data")

    def test_unexpected_top_level_queue_file_and_wrong_mount_are_rejected(self):
        extra = self.queues / "unexpected"
        extra.write_text("must remain")
        with mock.patch.object(PRIVACY, "run") as execute:
            with self.assertRaises(ValueError):
                self.clean()
            with self.assertRaises(ValueError):
                PRIVACY.cleanup_fixture_queues(self.folder, self.runtime, self.folder, self.identity)
        execute.assert_not_called()
        self.assertEqual(extra.read_text(), "must remain")

    def test_foreign_docker_resource_name_is_rejected_before_removal(self):
        with mock.patch.object(PRIVACY, "run") as execute:
            with self.assertRaises(ValueError):
                PRIVACY.finish_cleanup(mock.Mock(), self.folder, self.runtime, self.queues,
                                       self.identity, ["synthetic-unrelated-app"], True, {}, self.report)
        execute.assert_not_called()

    def test_cleanup_error_still_attempts_other_teardown_and_report_is_fail(self):
        evidence = {"result": "FAIL", "checks_passed": True, "checks": [{"result": "PASS"}]}
        temporary = mock.Mock()
        stdout = io.StringIO()
        with mock.patch.object(PRIVACY, "run", return_value="") as execute, \
             mock.patch.object(PRIVACY, "cleanup_fixture_queues", side_effect=RuntimeError("synthetic helper failure")), \
             contextlib.redirect_stdout(stdout), self.assertRaisesRegex(RuntimeError, "cleanup failed"):
            PRIVACY.finish_cleanup(temporary, self.folder, self.runtime, self.queues,
                                   self.identity, [self.identity + "-fixture"], True, evidence, self.report)
        self.assertIn(mock.call("docker", "network", "rm", self.identity, timeout=30), execute.call_args_list)
        temporary.cleanup.assert_called_once()
        report = json.loads(self.report.read_text())
        self.assertEqual(report["result"], "FAIL")
        self.assertFalse(report["cleanup"]["completed"])
        self.assertEqual(report["checks"], [{"result": "PASS"}])
        self.assertNotIn('"result": "PASS"', stdout.getvalue())

    def test_host_permission_error_cannot_leave_a_passing_report(self):
        evidence = {"result": "FAIL", "checks_passed": True}
        temporary = mock.Mock()
        temporary.cleanup.side_effect = PermissionError("synthetic UID10001 exports")
        with mock.patch.object(PRIVACY, "cleanup_fixture_queues"), \
             self.assertRaisesRegex(RuntimeError, "temporary directory removal"):
            PRIVACY.finish_cleanup(temporary, self.folder, self.runtime, self.queues,
                                   self.identity, [], False, evidence, self.report)
        self.assertEqual(json.loads(self.report.read_text())["result"], "FAIL")

    def test_success_is_not_printed_until_cleanup_and_host_removal_finish(self):
        evidence = {"result": "FAIL", "checks_passed": True}
        temporary = mock.Mock()
        stdout = io.StringIO()
        with mock.patch.object(PRIVACY, "cleanup_fixture_queues"), contextlib.redirect_stdout(stdout):
            PRIVACY.finish_cleanup(temporary, self.folder, self.runtime, self.queues,
                                   self.identity, [], False, evidence, self.report)
            temporary.cleanup.assert_called_once()
            self.assertEqual(stdout.getvalue(), "")
            self.assertFalse(self.report.exists())
            PRIVACY.complete_lab(evidence, self.report)
        self.assertEqual(json.loads(self.report.read_text())["result"], "PASS")
        self.assertEqual(json.loads(stdout.getvalue())["result"], "PASS")

    def test_functional_failure_remains_failed_even_after_successful_cleanup(self):
        evidence = {"result": "FAIL"}
        with mock.patch.object(PRIVACY, "cleanup_fixture_queues"):
            PRIVACY.finish_cleanup(mock.Mock(), self.folder, self.runtime, self.queues,
                                   self.identity, [], False, evidence, self.report)
        self.assertEqual(json.loads(self.report.read_text())["result"], "FAIL")
        with self.assertRaisesRegex(RuntimeError, "not completed"):
            PRIVACY.complete_lab(evidence, self.report)


if __name__ == "__main__":
    unittest.main(verbosity=2)
