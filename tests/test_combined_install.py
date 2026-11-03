"""One-command core/Operator contracts; all cluster/process calls are mocked."""
from __future__ import annotations

import contextlib
import copy
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from test_cli import PRIVATE, UID, arguments, cli, settings as core_settings
from test_instrumentation_cli import cli as operator_cli, settings as operator_settings

REAL_MODULE_LOADER = cli.instrumentation_module


def combined_arguments(**changes):
    defaults = dict(release="elven", namespace="elven-observability", development_images=False,
        instrumentation_values=["/synthetic/operator-base.yaml", "/synthetic/operator-site.yaml"],
        instrumentation_release="elven-operator")
    return arguments(**{**defaults, **changes})


def gateway_settings():
    current = core_settings()
    current["ports"] = {"otlpHttp": 4318}
    current["collection"] = {"namespaces": ["elven-synthetic-app"]}
    return current


class CombinedInstallTests(unittest.TestCase):
    def setUp(self):
        self.block_process = mock.patch.object(cli.subprocess, "run", side_effect=AssertionError(
            "Combined unit tests must never execute a real process or cluster command"))
        self.block_process.start()
        self.addCleanup(self.block_process.stop)
        self.private = tempfile.TemporaryDirectory(prefix="elven-combined-unit-")
        self.addCleanup(self.private.cleanup)
        self.folder = Path(self.private.name)
        self.operator_settings = operator_settings()

        def render(args, folder):
            operator_cli.validate_settings(self.operator_settings, args.namespace)
            return "synthetic manifest", copy.deepcopy(self.operator_settings), []

        self.module = SimpleNamespace(Failure=operator_cli.Failure,
            duration_seconds=operator_cli.duration_seconds, render=mock.Mock(side_effect=render),
            require_images=mock.Mock(), main=mock.Mock(return_value=None))
        self.module_patch = mock.patch.object(cli, "instrumentation_module", return_value=self.module)
        self.module_patch.start()
        self.addCleanup(self.module_patch.stop)

    def prepare(self, args=None, gateway=None):
        return cli.prepare_instrumentation(args or combined_arguments(), gateway or gateway_settings(), self.folder)

    def invocation(self, command="install", **extra):
        argv = [command, "--context", "synthetic-context", "--expect-cluster-uid", UID,
                "--cluster-name", "synthetic-cluster", "--values", "/synthetic/core.yaml",
                "--instrumentation-values", "/synthetic/operator-base.yaml",
                "--instrumentation-values", "/synthetic/operator-site.yaml",
                "--tenant-file", "/synthetic/private-tenant", "--token-file", "/synthetic/private-token",
                "--kubeconfig", "/synthetic/private-kubeconfig", "--timeout", "7m"]
        for flag, value in extra.items():
            argv += ["--" + flag.replace("_", "-"), value]
        return argv

    @contextlib.contextmanager
    def main_mocks(self, settings=None):
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(cli.os, "umask"))
            stack.enter_context(mock.patch.object(cli, "required_programs", return_value=4))
            render = stack.enter_context(mock.patch.object(cli, "render", return_value=(
                "synthetic core manifest", settings or gateway_settings(), [])))
            preflight = stack.enter_context(mock.patch.object(cli, "preflight", return_value=None))
            policy = stack.enter_context(mock.patch.object(cli, "require_promoted_images"))
            install = stack.enter_context(mock.patch.object(cli, "install"))
            kube = stack.enter_context(mock.patch.object(cli, "kube"))
            helm = stack.enter_context(mock.patch.object(cli, "helm"))
            output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            yield SimpleNamespace(render=render, preflight=preflight, policy=policy, install=install,
                                  kube=kube, helm=helm, output=output)

    def test_core_only_does_not_load_or_reconcile_instrumentation(self):
        args = arguments()
        self.assertIsNone(cli.prepare_instrumentation(args, {}, self.folder))
        cli.reconcile_instrumentation(args, None)
        with mock.patch.object(cli, "instrumentation_module") as load:
            self.assertIsNone(cli.prepare_instrumentation(args, {}, self.folder))
        load.assert_not_called()
        self.module.main.assert_not_called()

    def test_actual_stdlib_module_loads_and_missing_checkout_fails_locally(self):
        module = REAL_MODULE_LOADER()
        self.assertTrue(callable(module.main))
        self.assertTrue(callable(module.require_images))
        with mock.patch.object(cli, "ROOT", self.folder):
            with self.assertRaisesRegex(cli.Failure, "complete verified distribution"):
                REAL_MODULE_LOADER()

    def test_minimal_review_profile_preserves_selective_privacy(self):
        source = (cli.ROOT / "examples/minimal.yaml").read_text()
        self.assertIn("logBodyMode: selective", source)
        self.assertNotIn("logBodyMode: strict", source)

    def test_profile_is_frozen_private_and_exact_context_uid_and_options_are_forwarded(self):
        args = combined_arguments(tenant_file=PRIVATE, token_file=PRIVATE)
        plan = self.prepare(args)
        self.module.require_images.assert_called_once_with(self.operator_settings, False)
        selected = self.module.render.call_args.args[0]
        self.assertEqual(selected.values, args.instrumentation_values)
        command = plan["command"]
        self.assertEqual(command[0], "install")
        for name, value in (("--release", args.instrumentation_release), ("--namespace", args.namespace),
                            ("--context", args.context), ("--expect-cluster-uid", args.expect_cluster_uid),
                            ("--kubeconfig", args.kubeconfig), ("--timeout", args.timeout),
                            ("--render-kube-version", args.render_kube_version)):
            self.assertEqual(command[command.index(name) + 1], value)
        self.assertNotIn("--development-images", command)
        self.assertNotIn("--tenant-file", command)
        self.assertNotIn("--token-file", command)
        self.assertNotIn(PRIVATE, " ".join(command))
        frozen = Path(command[command.index("--values") + 1])
        self.assertEqual(frozen.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(frozen.read_text()), self.operator_settings)
        self.operator_settings["namespaces"] = ["a-different-namespace"]
        self.assertEqual(json.loads(frozen.read_text())["namespaces"], ["elven-synthetic-app"])
        cli.reconcile_instrumentation(args, plan)
        self.module.main.assert_called_once_with(command)

    def test_explicit_development_choice_is_forwarded_but_never_added_implicitly(self):
        args = combined_arguments(development_images=True)
        plan = self.prepare(args)
        self.module.require_images.assert_called_once_with(self.operator_settings, True)
        self.assertIn("--development-images", plan["command"])

    def test_invalid_profile_and_unpromoted_lock_fail_before_core_preflight_or_mutation(self):
        self.module.require_images.side_effect = operator_cli.Failure(PRIVATE)
        with self.main_mocks() as calls:
            with self.assertRaisesRegex(cli.Failure, "before core installation") as caught:
                cli.main(self.invocation())
        self.assertNotIn(PRIVATE, str(caught.exception))
        for operation in (calls.preflight, calls.policy, calls.install, calls.kube, calls.helm, self.module.main):
            operation.assert_not_called()

    def test_real_unpublished_image_lock_is_not_bypassed_in_production(self):
        lock = self.folder / "unpublished-lock.json"
        lock.write_text(json.dumps({"schemaVersion": 1, "distribution": {"publicationStatus": "not-published"}}))
        self.module.require_images.side_effect = operator_cli.require_images
        with mock.patch.object(operator_cli, "LOCK", lock), self.main_mocks() as calls:
            with self.assertRaisesRegex(cli.Failure, "promoted image verification"):
                cli.main(self.invocation())
        calls.install.assert_not_called()
        calls.preflight.assert_not_called()
        self.module.main.assert_not_called()

    def test_unpromoted_core_lock_cannot_start_either_install_phase(self):
        with self.main_mocks() as calls:
            calls.policy.side_effect = cli.Failure("Production installation blocked")
            with self.assertRaisesRegex(cli.Failure, "Production installation blocked"):
                cli.main(self.invocation())
        calls.install.assert_not_called()
        self.module.main.assert_not_called()

    def test_disabled_missing_scope_and_eol_runtime_approval_are_rejected_locally(self):
        cases = [{"enabled": False}, {"namespaces": []}, {"namespaces": ["kube-system"]},
                 {"runtimes": {**self.operator_settings["runtimes"], "nodejs20": True}}]
        original = copy.deepcopy(self.operator_settings)
        for changes in cases:
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as temporary:
                self.operator_settings = {**copy.deepcopy(original), **changes}
                with self.assertRaises(cli.Failure):
                    cli.prepare_instrumentation(combined_arguments(), gateway_settings(), Path(temporary))
        self.module.main.assert_not_called()

    def test_gateway_release_namespace_domain_endpoint_and_port_must_match_before_writes(self):
        original = copy.deepcopy(self.operator_settings)
        for key, value in (("sourceRelease", "elven-other"), ("sourceNamespace", "elven-other"),
                           ("endpoint", "https://elven-gateway.elven-observability.svc.cluster.local:4443")):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                self.operator_settings = copy.deepcopy(original)
                self.operator_settings["gateway"][key] = value
                with self.assertRaisesRegex(cli.Failure, "gateway identity"):
                    cli.prepare_instrumentation(combined_arguments(), gateway_settings(), Path(temporary))
        self.operator_settings = copy.deepcopy(original)
        self.operator_settings["clusterDomain"] = "another.invalid"
        with self.assertRaisesRegex(cli.Failure, "gateway identity"):
            self.prepare()
        self.module.main.assert_not_called()

    def test_all_application_namespaces_need_explicit_core_authorization_even_without_policy(self):
        for policy in (True, False):
            with self.subTest(network_policy=policy), tempfile.TemporaryDirectory() as temporary:
                gateway = gateway_settings()
                gateway["collection"]["namespaces"] = []
                gateway["networkPolicy"]["enabled"] = policy
                with self.assertRaisesRegex(cli.Failure, "explicitly authorize"):
                    cli.prepare_instrumentation(combined_arguments(), gateway, Path(temporary))
        self.module.main.assert_not_called()

    def test_only_install_upgrade_accept_combined_flags_and_releases_must_differ(self):
        with mock.patch.object(cli, "required_programs") as programs:
            for command in ("version", "render", "preflight", "status", "rollback", "uninstall"):
                with self.subTest(command=command), self.assertRaisesRegex(cli.Failure, "only by install and upgrade"):
                    cli.main(self.invocation(command))
            with self.assertRaisesRegex(cli.Failure, "different names"):
                cli.main(self.invocation(instrumentation_release="elven"))
            with self.assertRaisesRegex(cli.Failure, "requires --instrumentation-values"):
                cli.main(["install", "--instrumentation-release", "elven-another-operator"])
        programs.assert_not_called()

    def test_cluster_confirmation_and_operator_timeout_are_checked_before_core_writes(self):
        for changes in ({"context": None}, {"expect_cluster_uid": None}, {"timeout": "2h"}):
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as temporary:
                with self.assertRaises(cli.Failure):
                    cli.prepare_instrumentation(combined_arguments(**changes), gateway_settings(), Path(temporary))
        self.module.main.assert_not_called()

    def test_core_failure_cannot_start_the_operator_phase(self):
        with self.main_mocks() as calls:
            calls.install.side_effect = cli.Failure("synthetic core failure")
            with self.assertRaisesRegex(cli.Failure, "core failure"):
                cli.main(self.invocation())
        self.module.main.assert_not_called()

    def test_production_install_and_upgrade_reconcile_core_before_the_existing_operator_cli(self):
        for command in ("install", "upgrade"):
            with self.subTest(command=command), self.main_mocks() as calls:
                order = []
                calls.install.side_effect = lambda *args: order.append("core")
                self.module.main.side_effect = lambda argv: order.append("operator")
                cli.main(self.invocation(command))
                self.assertEqual(order, ["core", "operator"])
                self.assertFalse(calls.policy.call_args.args[1])
                operator_args = self.module.main.call_args.args[0]
                self.assertNotIn("--development-images", operator_args)
                self.assertNotIn("--token-file", operator_args)
                self.assertEqual(operator_args[operator_args.index("--timeout") + 1], "7m")

    def test_operator_failure_is_partial_retained_sanitized_and_retry_does_not_destroy_core(self):
        self.module.main.side_effect = [operator_cli.Failure(PRIVATE), None]
        with self.main_mocks() as calls:
            with self.assertRaisesRegex(cli.Failure, "retained") as caught:
                cli.main(self.invocation())
            self.assertNotIn(PRIVATE, str(caught.exception))
            self.assertIn("UNKNOWN", str(caught.exception))
            self.assertNotIn("Combined Elven installation reconciled", calls.output.getvalue())
            cli.main(self.invocation())
            self.assertEqual(calls.install.call_count, 2)
            self.assertEqual(self.module.main.call_count, 2)
            calls.kube.assert_not_called()
            calls.helm.assert_not_called()
            self.assertIn("Combined Elven installation reconciled", calls.output.getvalue())

    def test_unexpected_nonzero_or_exit_from_operator_is_never_reported_as_success(self):
        for result in (1, SystemExit(1), OSError(PRIVATE)):
            with self.subTest(result=type(result).__name__), tempfile.TemporaryDirectory() as temporary:
                plan = cli.prepare_instrumentation(combined_arguments(), gateway_settings(), Path(temporary))
                self.module.main.side_effect = result if isinstance(result, BaseException) else None
                self.module.main.return_value = result
                with self.assertRaisesRegex(cli.Failure, "instrumentation phase failed") as caught:
                    cli.reconcile_instrumentation(combined_arguments(), plan)
                self.assertNotIn(PRIVATE, str(caught.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
