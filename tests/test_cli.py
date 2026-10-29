"""Synthetic, process-mocked contracts for the stdlib-only Elven installer.

No test reads kubeconfig, invokes kubectl/Helm, or accesses a real Secret.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
LOADER = importlib.machinery.SourceFileLoader("elven_cli_under_test", str(ROOT / "elven"))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
cli = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(cli)

PRIVATE = "SYNTHETIC_SECRET_MUST_NOT_APPEAR_IN_ARGV_OR_ERRORS"
UID = "00000000-0000-4000-8000-000000000001"


def arguments(**changes):
    defaults = {
        "command": "install", "release": "elven-synthetic", "namespace": "elven-synthetic",
        "context": "synthetic-test-only", "kubeconfig": "/synthetic/never-read.kubeconfig",
        "expect_cluster_uid": UID, "cluster_name": "synthetic-cluster", "values": [],
        "render_kube_version": "1.37.0", "credentials_secret": None, "tls_secret": None,
        "use_existing_secrets": False, "allow_unrestricted_network": False,
        "allow_overlapping_collection": False,
        "tenant_file": None, "token_file": None, "timeout": "3m", "revision": None,
        "helm_major": 4,
    }
    return argparse.Namespace(**{**defaults, **changes})


def settings():
    return {
        "cluster": {"name": "synthetic-cluster", "domain": "cluster.local"},
        "credentials": {"existingSecret": "synthetic-ingest"},
        "tls": {"existingSecret": "synthetic-tls"},
        "modules": {}, "networkPolicy": {"enabled": True, "exportCIDRs": ["192.0.2.8/32"]},
        "gateway": {"persistence": {"enabled": True, "storageClass": ""}},
    }


def synthetic_secret(args, required, owned=True):
    return {
        "metadata": {"labels": cli.labels(args) if owned else {"app.kubernetes.io/managed-by": "client-gitops"}},
        "data": {key: base64.b64encode(("synthetic-" + key).encode()).decode() for key in required},
    }


def kube_reply(args, *, namespace_exists=True, version="v1.37.0", uid=UID,
               namespace_labels=None, storage_available=True, foreign_secret=False):
    """Fail on unlisted command shapes instead of allowing accidental real IO."""
    def reply(_args, *command, **kwargs):
        if command == ("version", "-o", "json"):
            return json.dumps({"serverVersion": {"gitVersion": version}})
        if command == ("get", "namespace", "kube-system", "-o", "json"):
            return json.dumps({"metadata": {"uid": uid}})
        if command == ("get", "namespace", args.namespace, "--ignore-not-found", "-o", "json"):
            return json.dumps({"metadata": {"name": args.namespace, "labels": namespace_labels or {}}}) if namespace_exists else ""
        if command == ("get", "storageclasses", "-o", "json"):
            items = [{"metadata": {"name": "synthetic-storage", "annotations": {
                "storageclass.kubernetes.io/is-default-class": "true"}}}] if storage_available else []
            return json.dumps({"items": items})
        if command[:2] == ("get", "secret"):
            required = ("tenant-id", "api-token") if command[2] == "synthetic-ingest" else (
                "tls.crt", "tls.key", "ca.crt", "client.crt", "client.key")
            return json.dumps(synthetic_secret(args, required, owned=not foreign_secret))
        raise AssertionError(f"Unexpected mocked kubectl command: {command!r}")
    return reply


class ProcessMockedTestCase(unittest.TestCase):
    def setUp(self):
        # Unexpected command shapes fail inside Python, never by invoking even
        # a synthetic kubectl path. Individual boundary tests override the mock.
        self.block_process = mock.patch.object(cli.subprocess, "run", side_effect=AssertionError(
            "Unexpected external process in a process-mocked CLI unit test"))
        self.block_process.start()
        self.addCleanup(self.block_process.stop)


class CommandBoundaryTests(ProcessMockedTestCase):
    def test_kube_refuses_implicit_active_context_before_spawning_process(self):
        with mock.patch.object(cli, "run") as run:
            with self.assertRaisesRegex(cli.Failure, "context"):
                cli.kube(arguments(context=None), "get", "pods")
        run.assert_not_called()

    def test_kube_pins_context_and_kubeconfig_and_keeps_secrets_in_stdin(self):
        args = arguments()
        with mock.patch.object(cli, "run", return_value="created") as run:
            self.assertEqual(cli.kube(args, "create", "-f", "-", data=PRIVATE), "created")
        argv = run.call_args.args[0]
        self.assertEqual(argv[:5], ["kubectl", "--kubeconfig", args.kubeconfig, "--context", args.context])
        self.assertEqual(argv[-3:], ["create", "-f", "-"])
        self.assertNotIn(PRIVATE, " ".join(argv))
        self.assertEqual(run.call_args.kwargs["data"], PRIVATE)
        self.assertTrue(run.call_args.kwargs["quiet_error"])

    def test_helm_honors_explicit_binary_without_changing_global_install(self):
        args = arguments()
        with mock.patch.dict(os.environ, {"ELVEN_HELM_BINARY": "/synthetic/helm-4.3.1"}), mock.patch.object(cli, "run", return_value="ok") as run:
            cli.helm(args, "list", online=True)
        argv = run.call_args.args[0]
        self.assertEqual(argv[0], "/synthetic/helm-4.3.1")
        self.assertIn("--kube-context", argv)
        self.assertIn(args.context, argv)
        self.assertIn("--kubeconfig", argv)

    def test_online_helm_requires_context_before_execution(self):
        with mock.patch.object(cli, "run") as run:
            with self.assertRaisesRegex(cli.Failure, "context"):
                cli.helm(arguments(context=None), "list", online=True)
        run.assert_not_called()

    def test_failed_subprocess_never_echoes_secret_stdout_stderr(self):
        completed = subprocess.CompletedProcess(["kubectl", "create"], 1, PRIVATE, PRIVATE)
        with mock.patch.object(cli.subprocess, "run", return_value=completed):
            with self.assertRaises(cli.Failure) as caught:
                cli.run(["kubectl", "create", "-f", "-"], data=PRIVATE, quiet_error=True)
        self.assertNotIn(PRIVATE, str(caught.exception))
        self.assertIn("exit 1", str(caught.exception))

    def test_can_i_denial_is_not_a_success_or_secret_error(self):
        completed = subprocess.CompletedProcess(["kubectl"], 1, "no\n", PRIVATE)
        with mock.patch.object(cli.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(cli.Failure, "Installation permission missing") as caught:
                cli.can_i(arguments(), "create", "statefulsets.apps", True)
        self.assertNotIn(PRIVATE, str(caught.exception))


class LocalConfigurationTests(ProcessMockedTestCase):
    def test_placeholder_and_unsafe_cluster_names_are_rejected(self):
        for name in (None, "CHANGE_ME", "example-cluster", "your-cluster", "https://cluster.invalid", "../../cluster", "cluster name"):
            with self.subTest(name=name), self.assertRaises(cli.Failure):
                cli.base_values(arguments(cluster_name=name))
        self.assertEqual(cli.base_values(arguments())["cluster"]["name"], "synthetic-cluster")

    def test_release_and_secret_identifiers_are_dns_labels(self):
        for value in ("UPPER", "-prefix", "suffix-", "a/b", "a.b", "a" * 64):
            with self.subTest(value=value), self.assertRaises(cli.Failure):
                cli.identifier(value, "synthetic", 63)
        self.assertEqual(cli.identifier("elven-synthetic", "synthetic"), "elven-synthetic")

    def test_only_private_regular_credential_files_are_read(self):
        with tempfile.TemporaryDirectory(prefix="elven-cli-test-") as folder:
            path = Path(folder) / "credential"
            path.write_text(PRIVATE)
            path.chmod(0o600)
            self.assertEqual(cli.private_input(path, "synthetic token"), PRIVATE)
            path.chmod(0o644)
            with self.assertRaisesRegex(cli.Failure, "permissions"):
                cli.private_input(path, "synthetic token")
            with self.assertRaises(cli.Failure):
                cli.private_input(folder, "synthetic token")

    def test_empty_multiline_and_oversized_credentials_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix="elven-cli-test-") as folder:
            path = Path(folder) / "credential"
            for contents in ("", "first\nsecond", "first\rsecond", "x" * 16385):
                path.write_text(contents)
                path.chmod(0o600)
                with self.subTest(length=len(contents)), self.assertRaises(cli.Failure):
                    cli.private_input(path, "synthetic token")

    def test_supported_helm_versions_are_explicit(self):
        for version, major in (("v3.22.1+gsynthetic", 3), ("v4.3.1+gsynthetic", 4), ("v4.4.0", 4)):
            with self.subTest(version=version), mock.patch.object(cli.shutil, "which", return_value="/synthetic/tool"), mock.patch.object(cli, "helm", return_value=version):
                self.assertEqual(cli.required_programs(arguments(), online=True), major)
        for version in ("v3.22.0", "v4.3.0", "v5.0.0", "unknown"):
            with self.subTest(version=version), mock.patch.object(cli.shutil, "which", return_value="/synthetic/tool"), mock.patch.object(cli, "helm", return_value=version), self.assertRaises(cli.Failure):
                cli.required_programs(arguments(), online=True)

    def test_prerelease_helm_does_not_satisfy_stable_support_contract(self):
        for version in ("v4.3.1-rc.1", "v3.22.1-beta.1"):
            with self.subTest(version=version), mock.patch.object(cli.shutil, "which", return_value="/synthetic/tool"), mock.patch.object(cli, "helm", return_value=version), self.assertRaises(cli.Failure):
                cli.required_programs(arguments(), online=True)

    def test_render_uses_only_helm_template_and_private_nonsecret_overrides(self):
        args = arguments()
        effective = settings()
        encoded = json.dumps(json.dumps(effective))
        contract = "data:\n  settings.json: " + encoded + "\n"
        with tempfile.TemporaryDirectory(prefix="elven-cli-test-") as folder:
            directory = Path(folder)
            with mock.patch.object(cli, "helm", side_effect=[contract, "kind: ConfigMap\n"]) as helm, mock.patch.object(cli, "kube") as kube:
                manifest, actual, flags = cli.render(args, directory)
            self.assertEqual(manifest, "kind: ConfigMap\n")
            self.assertEqual(actual, effective)
            self.assertTrue(all(call.args[1] == "template" for call in helm.call_args_list))
            self.assertNotIn("--kube-context", flags)
            self.assertNotIn("--kube-version", flags, "Render-only flags must never reach helm upgrade")
            self.assertTrue(all("--kube-version" in call.args for call in helm.call_args_list))
            kube.assert_not_called()
            overrides = directory / "values.json"
            self.assertEqual(overrides.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(PRIVATE, overrides.read_text())
            self.assertNotIn("api-token", overrides.read_text())

    def test_invalid_and_unrestricted_cidrs_are_rejected_in_every_network_field(self):
        fields = ("exportCIDRs", "apiServerCIDRs", "kubeletCIDRs", "profileCIDRs", "dnsCIDRs")
        invalid = ("999.2.3.4/32", "2001:db8::g/64", "192.0.2.1/24", "2001:db8::1/64", "0.0.0.0/0", "::/0")
        for field in fields:
            for cidr in invalid:
                effective = settings()
                effective["networkPolicy"][field] = [cidr]
                contract = "data:\n  settings.json: " + json.dumps(json.dumps(effective)) + "\n"
                with self.subTest(field=field, cidr=cidr), tempfile.TemporaryDirectory(prefix="elven-cli-test-") as folder:
                    with mock.patch.object(cli, "helm", return_value=contract) as helm, self.assertRaisesRegex(cli.Failure, "networkPolicy"):
                        cli.render(arguments(), Path(folder))
                    self.assertEqual(helm.call_count, 1, "Invalid CIDRs must fail before rendering the deployment")

    def test_canonical_ipv4_and_ipv6_cidrs_are_accepted(self):
        effective = settings()
        for field in ("exportCIDRs", "apiServerCIDRs", "kubeletCIDRs", "profileCIDRs", "dnsCIDRs"):
            effective["networkPolicy"][field] = ["192.0.2.0/24", "2001:db8::/64"]
        contract = "data:\n  settings.json: " + json.dumps(json.dumps(effective)) + "\n"
        with tempfile.TemporaryDirectory(prefix="elven-cli-test-") as folder, mock.patch.object(cli, "helm", side_effect=[contract, "kind: ConfigMap\n"]):
            _, actual, _ = cli.render(arguments(), Path(folder))
        self.assertEqual(actual, effective)

    def test_install_and_upgrade_receive_no_render_only_flags(self):
        for operation in ("install", "upgrade"):
            for major, failure_flag in ((3, "--atomic"), (4, "--rollback-on-failure")):
                args = arguments(command=operation)
                effective = settings()
                contract = "data:\n  settings.json: " + json.dumps(json.dumps(effective)) + "\n"
                with self.subTest(operation=operation, major=major), tempfile.TemporaryDirectory(prefix="elven-cli-test-") as folder:
                    with mock.patch.object(cli, "helm", side_effect=[contract, "kind: ConfigMap\n"]):
                        _, actual, flags = cli.render(args, Path(folder))
                    with mock.patch.object(cli, "get_secret", return_value={"metadata": {"name": "synthetic-existing"}}), mock.patch.object(cli, "helm") as helm, mock.patch.object(cli, "kube") as kube, contextlib.redirect_stdout(io.StringIO()):
                        cli.install(args, {"metadata": {"name": args.namespace}}, actual, flags, Path(folder), major)
                    argv = helm.call_args.args[1:]
                    self.assertEqual(argv[0], "upgrade")
                    self.assertIn("--install", argv)
                    self.assertIn(failure_flag, argv)
                    self.assertNotIn("--kube-version", argv)
                    self.assertNotIn("--show-only", argv)
                    self.assertNotIn("--output-dir", argv)
                    self.assertNotIn(PRIVATE, " ".join(str(value) for value in argv))
                    kube.assert_not_called()

    def test_render_refuses_missing_contract_or_unsupported_fullname_override(self):
        with tempfile.TemporaryDirectory(prefix="elven-cli-test-") as folder:
            directory = Path(folder)
            with mock.patch.object(cli, "helm", return_value="kind: ConfigMap\n"), self.assertRaisesRegex(cli.Failure, "contract missing"):
                cli.render(arguments(), directory)
            effective = settings()
            effective["fullnameOverride"] = "unreviewed-identity"
            contract = "data:\n  settings.json: " + json.dumps(json.dumps(effective)) + "\n"
            with mock.patch.object(cli, "helm", return_value=contract), self.assertRaisesRegex(cli.Failure, "fullnameOverride"):
                cli.render(arguments(), directory)

    def test_main_render_never_accesses_kubernetes(self):
        argv = ["elven", "render", "--cluster-name", "synthetic-cluster"]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(cli.os, "umask"), mock.patch.object(cli, "required_programs", return_value=4) as required, mock.patch.object(cli, "render", return_value=("kind: ConfigMap\n", settings(), [])), mock.patch.object(cli, "kube") as kube, mock.patch.object(cli, "preflight") as preflight, contextlib.redirect_stdout(io.StringIO()):
            cli.main()
        required.assert_called_once()
        self.assertEqual(required.call_args.args[1], False)
        kube.assert_not_called()
        preflight.assert_not_called()

    def test_render_output_does_not_overwrite_existing_review(self):
        with tempfile.TemporaryDirectory(prefix="elven-cli-test-") as folder:
            output = Path(folder) / "review.yaml"
            output.write_text("keep-this-review")
            argv = ["elven", "render", "--cluster-name", "synthetic-cluster", "--output", str(output)]
            with mock.patch.object(sys, "argv", argv), mock.patch.object(cli.os, "umask"), mock.patch.object(cli, "required_programs", return_value=4), mock.patch.object(cli, "render", return_value=("replacement", settings(), [])), self.assertRaisesRegex(cli.Failure, "already exists"):
                cli.main()
            self.assertEqual(output.read_text(), "keep-this-review")


class PreflightSafetyTests(ProcessMockedTestCase):
    def test_release_listing_uses_all_status_flag_only_for_helm3(self):
        for major in (3, 4):
            args = arguments(command="uninstall", helm_major=major)
            releases = json.dumps([{"name": args.release, "chart": "elven-observability-1.0.0-rc.1"}])
            with self.subTest(major=major), mock.patch.object(cli, "kube", side_effect=kube_reply(args)), mock.patch.object(cli, "helm", return_value=releases) as helm, contextlib.redirect_stdout(io.StringIO()):
                cli.preflight(args, "", settings(), changing=True)
            argv = helm.call_args.args[1:]
            self.assertEqual(argv[0], "list")
            self.assertEqual("--all" in argv, major == 3)
            self.assertIn("--namespace", argv)
            self.assertIn("--output", argv)

    def test_mutation_requires_matching_cluster_uid_before_other_checks(self):
        for expected in (None, "another-cluster"):
            args = arguments(expect_cluster_uid=expected)
            with self.subTest(expected=expected), mock.patch.object(cli, "kube", side_effect=kube_reply(args)) as kube, mock.patch.object(cli, "can_i") as can_i, self.assertRaises(cli.Failure):
                cli.preflight(args, "", settings(), changing=True)
            self.assertEqual(kube.call_count, 2)
            can_i.assert_not_called()

    def test_readonly_uid_check_still_rejects_wrong_cluster(self):
        args = arguments(command="status", expect_cluster_uid="another-cluster")
        with mock.patch.object(cli, "kube", side_effect=kube_reply(args)), self.assertRaisesRegex(cli.Failure, "UID does not match"):
            cli.preflight(args, "", settings(), changing=False)

    def test_unsupported_kubernetes_fails_before_identity_or_mutations(self):
        for version in ("v1.34.9", "v1.38.0", "not-a-version"):
            args = arguments()
            with self.subTest(version=version), mock.patch.object(cli, "kube", side_effect=kube_reply(args, version=version)) as kube, self.assertRaisesRegex(cli.Failure, "Unsupported Kubernetes"):
                cli.preflight(args, "", settings(), changing=True)
            self.assertEqual(kube.call_count, 1)

    def test_network_policy_is_required_unless_explicitly_acknowledged(self):
        args = arguments()
        for policy in ({"enabled": False}, {"enabled": True, "exportCIDRs": []}):
            effective = settings()
            effective["networkPolicy"] = policy
            with self.subTest(policy=policy), mock.patch.object(cli, "kube", side_effect=kube_reply(args)), mock.patch.object(cli, "can_i") as can_i, self.assertRaises(cli.Failure):
                cli.preflight(args, "", effective, changing=True)
            can_i.assert_not_called()

    def test_host_modules_do_not_relax_namespace_pod_security(self):
        args = arguments()
        effective = settings()
        effective["modules"] = {"logs": {"enabled": True}}
        with mock.patch.object(cli, "kube", side_effect=kube_reply(args, namespace_labels={"pod-security.kubernetes.io/enforce": "restricted"})), mock.patch.object(cli, "can_i") as can_i, self.assertRaisesRegex(cli.Failure, "never relaxes namespace policy"):
            cli.preflight(args, "", effective, changing=True)
        can_i.assert_not_called()

    def test_missing_storage_fails_instead_of_falling_back_to_emptydir(self):
        args = arguments()
        with mock.patch.object(cli, "kube", side_effect=kube_reply(args, storage_available=False)), mock.patch.object(cli, "can_i"), mock.patch.object(cli, "helm") as helm, self.assertRaisesRegex(cli.Failure, "StorageClass"):
            cli.preflight(args, "", settings(), changing=True)
        helm.assert_not_called()

    def test_foreign_secret_requires_explicit_reference_not_adoption(self):
        args = arguments(command="preflight")
        with mock.patch.object(cli, "kube", side_effect=kube_reply(args, foreign_secret=True)), mock.patch.object(cli, "can_i"), self.assertRaisesRegex(cli.Failure, "another owner"):
            cli.preflight(args, "", settings(), changing=False)

    def test_existing_secret_mode_does_not_require_elven_ownership(self):
        args = arguments(command="preflight", use_existing_secrets=True)
        with mock.patch.object(cli, "kube", side_effect=kube_reply(args, foreign_secret=True)), mock.patch.object(cli, "can_i"), mock.patch.object(cli, "validate_tls") as tls, contextlib.redirect_stdout(io.StringIO()):
            namespace = cli.preflight(args, "", settings(), changing=False)
        self.assertEqual(namespace["metadata"]["name"], args.namespace)
        tls.assert_called_once()

    def test_secret_scope_includes_namespace_not_just_release(self):
        args = arguments()
        existing = synthetic_secret(args, ("tenant-id", "api-token"))
        self.assertTrue(cli.secret_owned(args, existing))
        existing["metadata"]["labels"]["elven.observability/namespace"] = "another-namespace"
        self.assertFalse(cli.secret_owned(args, existing))

    def test_invalid_or_empty_secret_material_fails_without_printing_values(self):
        for secret in ({"data": {"api-token": "not-valid-base64_"}}, {"data": {"api-token": ""}}, {"data": {}}):
            with self.subTest(secret=secret), self.assertRaises(cli.Failure) as caught:
                cli.secret_keys(secret, ("api-token",), "synthetic-ingest")
            self.assertNotIn(PRIVATE, str(caught.exception))

    def test_create_secret_uses_create_not_apply_and_secret_only_on_stdin(self):
        args = arguments()
        with mock.patch.object(cli, "kube") as kube:
            cli.create_secret(args, "synthetic-ingest", {"api-token": PRIVATE})
        self.assertEqual(kube.call_args.args[1:], ("create", "-f", "-"))
        self.assertNotIn(PRIVATE, " ".join(str(value) for value in kube.call_args.args))
        obj = json.loads(kube.call_args.kwargs["data"])
        self.assertEqual(obj["stringData"]["api-token"], PRIVATE)
        self.assertEqual(obj["metadata"]["labels"]["elven.observability/namespace"], args.namespace)

    def test_invalid_local_credentials_fail_before_namespace_or_secret_creation(self):
        args = arguments()
        with tempfile.TemporaryDirectory(prefix="elven-cli-test-") as folder, mock.patch.object(cli, "kube") as kube, mock.patch.object(cli, "generate_pki") as pki, mock.patch.object(cli, "helm") as helm:
            with self.assertRaises(cli.Failure):
                cli.install(args, None, settings(), [], Path(folder), 4)
        kube.assert_not_called()
        pki.assert_not_called()
        helm.assert_not_called()


class RecoverySafetyTests(ProcessMockedTestCase):
    def invoke(self, command, *, uid=UID, settings_owner=True, release_chart="elven-observability-1.0.0-rc.1", revision=1):
        args = arguments(command=command)
        installed = {"metadata": {"annotations": {
            "meta.helm.sh/release-name": args.release if settings_owner else "someone-else",
            "meta.helm.sh/release-namespace": args.namespace}},
            "data": {"settings.json": json.dumps(settings())}}
        reply = kube_reply(args, version="v1.38.0", uid=uid)
        def kube_call(_args, *parts, **kwargs):
            if parts[:3] == ("get", "configmap", f"{args.release}-settings"):
                return json.dumps(installed)
            if parts[:2] == ("get", "pods,pvc"):
                return "synthetic healthy pod and retained PVC\n"
            return reply(_args, *parts, **kwargs)
        def helm_call(_args, *parts, **kwargs):
            if parts[0] == "list":
                return json.dumps([{"name": args.release, "chart": release_chart}])
            return ""
        argv = ["elven", command, "--release", args.release, "--namespace", args.namespace,
                "--context", args.context, "--kubeconfig", args.kubeconfig, "--expect-cluster-uid", UID]
        if command == "rollback" and revision is not None:
            argv += ["--revision", str(revision)]
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(sys, "argv", argv))
            stack.enter_context(mock.patch.object(cli.os, "umask"))
            stack.enter_context(mock.patch.object(cli, "required_programs", return_value=4))
            kube = stack.enter_context(mock.patch.object(cli, "kube", side_effect=kube_call))
            helm = stack.enter_context(mock.patch.object(cli, "helm", side_effect=helm_call))
            render = stack.enter_context(mock.patch.object(cli, "render", side_effect=AssertionError("Recovery must not render current chart")))
            stack.enter_context(mock.patch.object(cli, "can_i", side_effect=AssertionError("Recovery must not request installation permissions")))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            try:
                cli.main()
            except Exception as error:
                return error, kube, helm, render
        return None, kube, helm, render

    def test_status_uses_installed_owned_settings_without_secret_or_current_chart(self):
        error, kube, helm, render = self.invoke("status")
        self.assertIsNone(error)
        render.assert_not_called()
        self.assertFalse(any(call.args[1:3] == ("get", "secret") for call in kube.call_args_list))
        self.assertTrue(any(call.args[1:3] == ("get", "pods,pvc") for call in kube.call_args_list))
        helm.assert_not_called()

    def test_recovery_is_available_on_newer_kubernetes_with_uid_and_ownership_confirmed(self):
        for command in ("rollback", "uninstall"):
            with self.subTest(command=command):
                error, kube, helm, render = self.invoke(command)
                self.assertIsNone(error)
                render.assert_not_called()
                self.assertFalse(any(call.args[1:3] == ("get", "secret") for call in kube.call_args_list))
                self.assertTrue(any(call.args[1] == command for call in helm.call_args_list))

    def test_recovery_refuses_unowned_settings_before_any_reconcile(self):
        error, _, helm, _ = self.invoke("uninstall", settings_owner=False)
        self.assertIsInstance(error, cli.Failure)
        self.assertIn("do not belong", str(error))
        helm.assert_not_called()

    def test_recovery_rejects_wrong_uid_before_helm_mutation(self):
        error, _, helm, _ = self.invoke("uninstall", uid="another-cluster")
        self.assertIsInstance(error, cli.Failure)
        self.assertIn("identity not confirmed", str(error))
        helm.assert_not_called()

    def test_recovery_never_removes_a_release_owned_by_another_chart(self):
        error, _, helm, _ = self.invoke("uninstall", release_chart="client-prometheus-99.0")
        self.assertIsInstance(error, cli.Failure)
        self.assertIn("adoption or removal", str(error))
        self.assertTrue(all(call.args[1] == "list" for call in helm.call_args_list))


class CollectionClaimTests(ProcessMockedTestCase):
    @staticmethod
    def desired(module="logs", namespaces=("synthetic-app",)):
        effective = settings()
        effective["modules"] = {module: {"enabled": True}}
        effective["collection"] = {"namespaces": list(namespaces)}
        return effective

    @staticmethod
    def workload(*, namespace="another-elven-ns", release="another-elven-release", signals="logs", sources="synthetic-app", component="node", annotated=True):
        metadata = {"name": "synthetic-agent", "namespace": namespace,
                    "labels": {"app.kubernetes.io/instance": release, "app.kubernetes.io/component": component}}
        if annotated:
            metadata["annotations"] = {"elven.observability/source-signals": signals,
                                       "elven.observability/collection-namespaces": sources}
        return {"metadata": metadata}

    def claim_reply(self, workloads):
        return mock.patch.object(cli, "kube", return_value=json.dumps({"items": workloads}))

    def test_disabled_sources_and_explicit_overlap_review_do_not_read_cluster(self):
        with mock.patch.object(cli, "kube") as kube:
            cli.check_source_claims(arguments(), settings())
            cli.check_source_claims(arguments(allow_overlapping_collection=True), self.desired())
        kube.assert_not_called()

    def test_overlapping_namespace_and_signal_are_blocked_across_release_namespaces(self):
        with self.claim_reply([self.workload()]) as kube, self.assertRaisesRegex(cli.Failure, "Collection overlaps"):
            cli.check_source_claims(arguments(), self.desired())
        self.assertEqual(kube.call_args.args[1:4], ("get", "daemonsets,deployments", "--all-namespaces"))
        self.assertIn("app.kubernetes.io/part-of=elven-observability", kube.call_args.args)

    def test_disjoint_collection_namespaces_are_allowed(self):
        with self.claim_reply([self.workload(sources="another-app")]):
            cli.check_source_claims(arguments(), self.desired())

    def test_disjoint_signals_are_allowed_for_shared_application_namespace(self):
        with self.claim_reply([self.workload(signals="traces")]):
            cli.check_source_claims(arguments(), self.desired(module="logs"))

    def test_upgrading_same_release_in_same_namespace_skips_its_existing_claims(self):
        args = arguments()
        with self.claim_reply([self.workload(namespace=args.namespace, release=args.release)]):
            cli.check_source_claims(args, self.desired())

    def test_same_release_name_in_another_namespace_is_not_self(self):
        args = arguments()
        with self.claim_reply([self.workload(namespace="another-elven-ns", release=args.release)]), self.assertRaisesRegex(cli.Failure, "Collection overlaps"):
            cli.check_source_claims(args, self.desired())

    def test_empty_namespace_claim_means_all_not_no_sources(self):
        for wanted, existing in (((), "synthetic-app"), (("synthetic-app",), "")):
            with self.subTest(wanted=wanted, existing=existing), self.claim_reply([self.workload(sources=existing)]), self.assertRaisesRegex(cli.Failure, "Collection overlaps"):
                cli.check_source_claims(arguments(), self.desired(namespaces=wanted))

    def test_legacy_labeled_agents_without_scope_metadata_are_treated_conservatively(self):
        with self.claim_reply([self.workload(annotated=False)]), self.assertRaisesRegex(cli.Failure, "Collection overlaps"):
            cli.check_source_claims(arguments(), self.desired())

    def test_api_permission_denial_or_malformed_response_does_not_assume_no_conflict(self):
        for response in (cli.Failure("synthetic API list denied"), "not-json", "{}"):
            kwargs = {"side_effect": response} if isinstance(response, Exception) else {"return_value": response}
            with self.subTest(response=type(response).__name__), mock.patch.object(cli, "kube", **kwargs), self.assertRaisesRegex(cli.Failure, "Cannot inspect existing Elven collection claims"):
                cli.check_source_claims(arguments(), self.desired())

    def test_empty_existing_claim_list_allows_new_collector(self):
        with self.claim_reply([]):
            cli.check_source_claims(arguments(), self.desired())

    def test_readonly_preflight_runs_conflict_check_before_installation_permissions(self):
        args = arguments(command="preflight")
        with mock.patch.object(cli, "kube", side_effect=kube_reply(args)), mock.patch.object(cli, "check_source_claims", side_effect=cli.Failure("synthetic overlap")) as check, mock.patch.object(cli, "can_i") as can_i, self.assertRaisesRegex(cli.Failure, "synthetic overlap"):
            cli.preflight(args, "", self.desired(), changing=False)
        check.assert_called_once()
        can_i.assert_not_called()


class RealHelmArgumentCompatibilityTests(unittest.TestCase):
    def test_generated_list_flags_exist_in_real_helm_help(self):
        binary = os.environ.get("ELVEN_HELM_BINARY", "helm")
        if not cli.shutil.which(binary):
            raise unittest.SkipTest("Helm unavailable; real list argument compatibility was not executed")
        completed = subprocess.run([binary, "list", "--help"], text=True, capture_output=True, check=True)
        supported = set(re.findall(r"(?<![A-Za-z0-9_-])--[a-z][a-z0-9-]*", completed.stdout))
        version = subprocess.check_output([binary, "version", "--short"], text=True)
        major = int(re.search(r"v(\d+)\.", version).group(1))
        args = arguments(command="uninstall", helm_major=major)
        releases = json.dumps([{"name": args.release, "chart": "elven-observability-1.0.0-rc.1"}])
        with mock.patch.object(cli, "kube", side_effect=kube_reply(args)), mock.patch.object(cli, "helm", return_value=releases) as helm, contextlib.redirect_stdout(io.StringIO()):
            cli.preflight(args, "", settings(), changing=True)
        generated = {str(value) for value in helm.call_args.args[1:] if str(value).startswith("--")}
        self.assertTrue(generated <= supported, f"Unsupported list flags: {generated - supported}")
        self.assertEqual("--all" in generated, major == 3)

    def test_generated_upgrade_flags_exist_in_real_helm_help(self):
        binary = os.environ.get("ELVEN_HELM_BINARY", "helm")
        if not cli.shutil.which(binary):
            raise unittest.SkipTest("Helm unavailable; real argument compatibility was not executed")
        completed = subprocess.run([binary, "upgrade", "--help"], text=True, capture_output=True, check=True)
        supported = set(re.findall(r"(?<![A-Za-z0-9_-])--[a-z][a-z0-9-]*", completed.stdout))
        version = subprocess.check_output([binary, "version", "--short"], text=True)
        major = int(re.search(r"v(\d+)\.", version).group(1))
        effective = settings()
        contract = "data:\n  settings.json: " + json.dumps(json.dumps(effective)) + "\n"
        with tempfile.TemporaryDirectory(prefix="elven-cli-test-") as folder:
            with mock.patch.object(cli, "helm", side_effect=[contract, "kind: ConfigMap\n"]):
                _, actual, flags = cli.render(arguments(), Path(folder))
            with mock.patch.object(cli, "get_secret", return_value={"metadata": {"name": "synthetic-existing"}}), mock.patch.object(cli, "helm") as helm, contextlib.redirect_stdout(io.StringIO()):
                cli.install(arguments(), {"metadata": {"name": "synthetic-existing"}}, actual, flags, Path(folder), major)
        generated = {str(value) for value in helm.call_args.args[1:] if str(value).startswith("--")}
        self.assertTrue(generated <= supported, f"Unsupported upgrade flags: {generated - supported}")
        self.assertNotIn("--kube-version", generated)


class SyntheticRealPKITests(unittest.TestCase):
    """Real OpenSSL and ephemeral synthetic keys only; no cluster/process mocks."""
    @classmethod
    def setUpClass(cls):
        if not cli.shutil.which("openssl"):
            raise unittest.SkipTest("OpenSSL unavailable; real PKI verification was not executed")
        cls.temporary = tempfile.TemporaryDirectory(prefix="elven-cli-pki-test-")
        cls.folder = Path(cls.temporary.name)
        cls.args = arguments()
        cls.bundle = cli.generate_pki(cls.args, settings(), cls.folder)
        cls.secret = {"data": {key: base64.b64encode(value.encode()).decode() for key, value in cls.bundle.items()}}

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_generated_pki_has_expected_runtime_keys_and_validates(self):
        self.assertEqual(set(self.bundle), {"tls.crt", "tls.key", "ca.crt", "client.crt", "client.key"})
        self.assertNotIn("ca.key", self.bundle)
        cli.validate_tls(self.args, settings(), self.secret)

    def test_bootstrap_ca_declares_ca_constraints_and_signing_usage(self):
        certificate = cli.run(["openssl", "x509", "-in", self.folder / "ca.crt", "-noout", "-text"])
        self.assertIn("CA:TRUE", certificate)
        self.assertIn("Certificate Sign", certificate)
        self.assertIn("CRL Sign", certificate)

    def test_wrong_service_dns_is_rejected(self):
        with self.assertRaisesRegex(cli.Failure, "mTLS Secret failed"):
            cli.validate_tls(arguments(release="another-release"), settings(), self.secret)

    def test_private_key_mismatch_is_rejected_without_printing_material(self):
        altered = {"data": dict(self.secret["data"])}
        altered["data"]["client.key"] = altered["data"]["tls.key"]
        with self.assertRaisesRegex(cli.Failure, "mTLS Secret failed") as caught:
            cli.validate_tls(self.args, settings(), altered)
        self.assertNotIn("BEGIN", str(caught.exception))

    def test_server_certificate_cannot_be_used_as_client_identity(self):
        altered = {"data": dict(self.secret["data"])}
        altered["data"]["client.crt"] = altered["data"]["tls.crt"]
        altered["data"]["client.key"] = altered["data"]["tls.key"]
        with self.assertRaisesRegex(cli.Failure, "mTLS Secret failed"):
            cli.validate_tls(self.args, settings(), altered)

    def test_certificate_with_less_than_one_day_remaining_is_rejected(self):
        short = self.folder / "short-client.crt"
        cli.run(["openssl", "x509", "-req", "-in", self.folder / "client.csr", "-CA", self.folder / "ca.crt",
                 "-CAkey", self.folder / "ca.key", "-CAcreateserial", "-days", "0",
                 "-extfile", self.folder / "client.ext", "-out", short])
        altered = {"data": dict(self.secret["data"])}
        altered["data"]["client.crt"] = base64.b64encode(short.read_bytes()).decode()
        with self.assertRaisesRegex(cli.Failure, "mTLS Secret failed"):
            cli.validate_tls(self.args, settings(), altered)

    def test_ca_with_less_than_one_day_remaining_is_rejected(self):
        short = self.folder / "short-ca.crt"
        cli.run(["openssl", "x509", "-in", self.folder / "ca.crt", "-signkey", self.folder / "ca.key",
                 "-days", "0", "-out", short])
        altered = {"data": dict(self.secret["data"])}
        altered["data"]["ca.crt"] = base64.b64encode(short.read_bytes()).decode()
        with self.assertRaisesRegex(cli.Failure, "mTLS Secret failed"):
            cli.validate_tls(self.args, settings(), altered)


if __name__ == "__main__":
    unittest.main(verbosity=2)
