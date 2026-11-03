"""The CI resource guard must never clean a local/shared or protected path."""
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ci_space_guard", ROOT / "scripts/images-ci-space.py")
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)
GIB = 1024**3


class HostedRunnerTests(unittest.TestCase):
    def test_docker_inspection_has_a_bounded_sanitized_timeout(self):
        with mock.patch.object(GUARD.subprocess, "run", side_effect=GUARD.subprocess.TimeoutExpired("docker", 30)) as run:
            with self.assertRaisesRegex(GUARD.Failure, "inspection timed out"):
                GUARD.docker_root()
        run.assert_called_once_with(["docker", "info", "--format", "{{.DockerRootDir}}"],
                                    text=True, capture_output=True, check=False, timeout=30)

    def test_local_self_hosted_windows_and_wrong_arch_fail_before_any_command(self):
        valid = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                 "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64"}
        for changes in ({}, {"GITHUB_ACTIONS": "false"}, {"RUNNER_ENVIRONMENT": "self-hosted"},
                        {"RUNNER_OS": "Windows"}, {"RUNNER_ARCH": "ARM64"}):
            env = {} if not changes else {**valid, **changes}
            with self.subTest(environment=changes), mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch.object(GUARD.subprocess, "run") as run:
                with self.assertRaises(GUARD.Failure):
                    GUARD.prepare(mutate=True)
                run.assert_not_called()

    def test_root_or_non_runner_user_is_not_a_hosted_cleanup_identity(self):
        env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
               "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64"}
        for uid, name in ((0, "runner"), (1001, "developer")):
            with self.subTest(uid=uid, name=name), mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch.object(GUARD.platform, "system", return_value="Linux"), \
                 mock.patch.object(GUARD.os, "getuid", return_value=uid), \
                 mock.patch.object(GUARD.pwd, "getpwuid", return_value=SimpleNamespace(pw_name=name)), \
                 mock.patch.object(GUARD.subprocess, "run") as run:
                with self.assertRaises(GUARD.Failure):
                    GUARD.prepare(mutate=True)
                run.assert_not_called()

    def test_non_ubuntu_or_unpinned_version_is_refused(self):
        env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
               "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64"}
        for release in ("ID=debian\nVERSION_ID=13\n", "ID=ubuntu\nVERSION_ID=22.04\n"):
            with self.subTest(release=release), mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch.object(GUARD.platform, "system", return_value="Linux"), \
                 mock.patch.object(GUARD.os, "getuid", return_value=1001), \
                 mock.patch.object(GUARD.pwd, "getpwuid", return_value=SimpleNamespace(pw_name="runner")), \
                 mock.patch.object(Path, "read_text", return_value=release), \
                 mock.patch.object(GUARD.subprocess, "run") as run:
                with self.assertRaises(GUARD.Failure):
                    GUARD.prepare(mutate=True)
                run.assert_not_called()


class SpacePreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="elven-ci-space-guard-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.sdk = self.base / "sdk"
        self.sdk.mkdir()
        self.other = self.base / "other-sdk"
        self.other.mkdir()
        self.workspace = self.base / "workspace"
        self.home = self.base / "home"
        self.runner_temp = self.base / "runner-temp"
        self.docker_data = self.base / "docker-data"
        for path in (self.workspace, self.home, self.runner_temp, self.docker_data):
            path.mkdir()
        self.high = {"filesystem": {"available_bytes": 40 * GIB, "total_bytes": 100 * GIB}}
        self.low = {"filesystem": {"available_bytes": 20 * GIB, "total_bytes": 100 * GIB}}
        patches = (
            mock.patch.object(GUARD, "require_hosted_runner", return_value=([self.workspace, self.runner_temp], self.home)),
            mock.patch.object(GUARD, "docker_root", return_value=self.docker_data),
            mock.patch.object(GUARD, "mount_points", return_value=[Path("/")]),
            mock.patch.object(GUARD, "SDK_PATHS", (self.sdk, self.other)),
            mock.patch.object(GUARD.subprocess, "run", return_value=SimpleNamespace(returncode=0)),
        )
        self.commands = None
        for patch in patches:
            value = patch.start()
            self.addCleanup(patch.stop)
            if patch.attribute == "run":
                self.commands = value

    def test_sufficient_margin_never_validates_or_removes_sdks(self):
        for mutate in (False, True):
            with self.subTest(mutate=mutate), mock.patch.object(GUARD, "disk_report", return_value=self.high), \
                 mock.patch.object(GUARD, "validate_targets") as validate:
                result = GUARD.prepare(mutate=mutate)
                self.assertEqual(result["removed_sdk_paths"], [])
                validate.assert_not_called()
        self.commands.assert_not_called()

    def test_check_only_low_space_never_calls_sudo_or_removes_anything(self):
        with mock.patch.object(GUARD, "disk_report", return_value=self.low):
            with self.assertRaisesRegex(GUARD.Failure, "check-only"):
                GUARD.prepare()
        self.commands.assert_not_called()
        self.assertTrue(self.sdk.exists())

    def test_only_needed_validated_literal_sdk_is_removed(self):
        with mock.patch.object(GUARD, "disk_report", side_effect=[self.low, self.high]):
            result = GUARD.prepare(mutate=True)
        self.assertEqual(result["removed_sdk_paths"], [str(self.sdk)])
        self.commands.assert_called_once_with(
            ["/usr/bin/sudo", "--non-interactive", "--", "/usr/bin/rm", "--recursive", "--one-file-system",
             "--preserve-root=all", "--", str(self.sdk)], text=True, capture_output=True, check=False, timeout=300)
        self.assertTrue(self.sdk.exists())  # no real cleanup is ever executed by this test

    def test_all_targets_are_prevalidated_before_first_removal(self):
        self.other.rmdir()
        self.other.symlink_to(self.home, target_is_directory=True)
        with mock.patch.object(GUARD, "disk_report", return_value=self.low):
            with self.assertRaisesRegex(GUARD.Failure, "physical directory"):
                GUARD.prepare(mutate=True)
        self.commands.assert_not_called()

    def test_symlink_in_any_ancestor_is_rejected(self):
        alias = self.base / "alias"
        alias.symlink_to(self.base / "workspace", target_is_directory=True)
        with mock.patch.object(GUARD, "SDK_PATHS", (alias / "nested-sdk",)), \
             mock.patch.object(GUARD, "disk_report", return_value=self.low):
            with self.assertRaisesRegex(GUARD.Failure, "physical directory"):
                GUARD.prepare(mutate=True)
        self.commands.assert_not_called()

    def test_home_workspace_temp_and_actual_docker_root_overlap_are_rejected(self):
        for location in (self.home, self.workspace, self.runner_temp, self.docker_data):
            for target in (location, location / "nested", location.parent):
                with self.subTest(target=target), mock.patch.object(GUARD, "SDK_PATHS", (target,)), \
                     mock.patch.object(GUARD, "disk_report", return_value=self.low):
                    with self.assertRaisesRegex(GUARD.Failure, "protected"):
                        GUARD.prepare(mutate=True)
        self.commands.assert_not_called()

    def test_nested_mount_boundary_is_rejected(self):
        with mock.patch.object(GUARD, "mount_points", return_value=[self.sdk / "mounted-data"]), \
             mock.patch.object(GUARD, "disk_report", return_value=self.low):
            with self.assertRaisesRegex(GUARD.Failure, "mount boundary"):
                GUARD.prepare(mutate=True)
        self.commands.assert_not_called()

    def test_cleanup_command_error_or_remaining_low_margin_still_fails(self):
        with mock.patch.object(GUARD, "disk_report", return_value=self.low), \
             mock.patch.object(GUARD.subprocess, "run", return_value=SimpleNamespace(returncode=1)):
            with self.assertRaisesRegex(GUARD.Failure, "cleanup failed"):
                GUARD.prepare(mutate=True)
        with mock.patch.object(GUARD, "disk_report", return_value=self.low):
            with self.assertRaisesRegex(GUARD.Failure, "still lacks"):
                GUARD.prepare(mutate=True)

    def test_cleanup_timeout_is_bounded_and_still_fails_without_starting_build(self):
        with mock.patch.object(GUARD, "disk_report", return_value=self.low), \
             mock.patch.object(GUARD.subprocess, "run", side_effect=GUARD.subprocess.TimeoutExpired("sudo", 300)) as run:
            with self.assertRaisesRegex(GUARD.Failure, "cleanup timed out"):
                GUARD.prepare(mutate=True)
        run.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
