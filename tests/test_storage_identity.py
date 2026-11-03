"""Synthetic PVC reservation/receipt contracts; no Kubernetes or kubeconfig IO."""
import argparse
import base64
import copy
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
LOADER = importlib.machinery.SourceFileLoader("elven_storage_under_test", str(ROOT / "elven"))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
cli = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(cli)
PRIVATE = "SYNTHETIC_API_TOKEN_NEVER_IN_STORAGE"
TENANT = "synthetic-tenant"


class StorageIdentityTests(unittest.TestCase):
    def setUp(self):
        self.args = argparse.Namespace(release="elven-synthetic", namespace="elven-synthetic",
            context="synthetic-only", kubeconfig="/never/read", command="install",
            cluster_name="synthetic-cluster", confirmed_cluster_uid="cluster-uid",
            use_existing_secrets=True, expect_cluster_uid="cluster-uid", helm_major=4,
            allow_unrestricted_network=False, allow_overlapping_collection=False, timeout="3m")
        self.args.revision = 1
        self.settings = {"cluster": {"name": "synthetic-cluster", "domain": "cluster.local"},
            "credentials": {"existingSecret": "synthetic-ingest"}, "tls": {"existingSecret": "synthetic-tls"},
            "gateway": {"persistence": {"enabled": True, "size": "2Gi", "storageClass": "reviewed-storage"}},
            "networkPolicy": {"enabled": True, "exportCIDRs": ["192.0.2.1/32"]}, "modules": {}}
        self.sts_name, self.pvc_name = cli.storage_names(self.args)
        helm_annotations = {"meta.helm.sh/release-name": self.args.release,
                            "meta.helm.sh/release-namespace": self.args.namespace}
        self.secret = {"metadata": {"name": "synthetic-ingest", "uid": "ingest-uid"}, "data": {
            "tenant-id": base64.b64encode(TENANT.encode()).decode(),
            "api-token": base64.b64encode(PRIVATE.encode()).decode()}}
        self.sts = {"metadata": {"name": self.sts_name, "namespace": self.args.namespace,
            "uid": "statefulset-uid", "annotations": dict(helm_annotations), "labels": {
                "app.kubernetes.io/name": "elven-observability", "app.kubernetes.io/instance": self.args.release}},
            "spec": {"volumeClaimTemplates": [{"metadata": {"name": "data"}, "spec": {"accessModes": ["ReadWriteOnce"]}}]}}
        self.cm = {"metadata": {"annotations": dict(helm_annotations)},
                   "data": {"settings.json": json.dumps(self.settings)}}
        self.pvc = None
        self.calls = []
        self.patch_failures = 0
        patcher = mock.patch.object(cli, "kube", side_effect=self.kube)
        patcher.start()
        self.addCleanup(patcher.stop)
        process = mock.patch.object(cli.subprocess, "run", side_effect=AssertionError("No process is allowed"))
        process.start()
        self.addCleanup(process.stop)

    def kube(self, args, *command, data=None):
        self.calls.append((command, data))
        if command[:2] == ("get", "pvc"):
            return json.dumps(self.pvc) if self.pvc is not None else ""
        if command[:2] == ("get", "statefulset"):
            return json.dumps(self.sts) if self.sts is not None else ""
        if command[:2] == ("get", "configmap"):
            return json.dumps(self.cm) if self.cm is not None else ""
        if command[:2] == ("get", "secret"):
            return json.dumps(self.secret)
        if command[:2] == ("create", "-f"):
            if self.pvc is not None:
                raise cli.Failure("AlreadyExists")
            self.pvc = json.loads(data)
            self.pvc["metadata"].update(uid="pvc-uid", resourceVersion="1")
            return json.dumps(self.pvc)
        if command[:2] == ("patch", "pvc"):
            if self.patch_failures:
                self.patch_failures -= 1
                self.pvc["metadata"]["resourceVersion"] = str(int(self.pvc["metadata"]["resourceVersion"]) + 1)
                raise cli.Failure("synthetic CAS failure")
            patch = json.loads(data)
            self.assertEqual(patch[0], {"op": "test", "path": "/metadata/uid", "value": self.pvc["metadata"]["uid"]})
            self.assertEqual(patch[1]["value"], self.pvc["metadata"]["resourceVersion"])
            self.assertEqual(patch[2]["value"], self.pvc["metadata"]["annotations"][cli.STORAGE_IDENTITY])
            self.assertEqual(patch[3]["op"], "replace")
            self.pvc["metadata"]["annotations"][cli.STORAGE_IDENTITY] = patch[3]["value"]
            self.pvc["metadata"]["resourceVersion"] = str(int(self.pvc["metadata"]["resourceVersion"]) + 1)
            return "patched"
        raise AssertionError(f"Unexpected mocked kubectl command: {command!r}")

    def bound(self):
        cli.reserve_storage(self.args, self.settings)
        cli.write_storage_identity(self.args, self.settings)

    def test_initial_reservation_is_create_only_and_contains_no_token_or_raw_tenant(self):
        cli.check_storage_identity(self.args, self.settings)
        cli.reserve_storage(self.args, self.settings)
        creates = [(command, data) for command, data in self.calls if command[0] == "create"]
        self.assertEqual(len(creates), 1)
        command, payload = creates[0]
        self.assertEqual(command, ("create", "-f", "-", "-o", "json"))
        self.assertNotIn(PRIVATE, payload)
        self.assertNotIn(TENANT, payload)
        receipt = cli.storage_receipt(self.pvc)
        self.assertEqual(receipt["phase"], "reserved")
        self.assertEqual(receipt["credentialsSecretUID"], "ingest-uid")
        self.assertEqual(self.pvc["spec"]["storageClassName"], "reviewed-storage")
        self.assertEqual(self.pvc["spec"]["resources"]["requests"]["storage"], "2Gi")

    def test_successful_receipt_binds_physical_uids_and_uses_compare_and_swap(self):
        self.bound()
        receipt = cli.storage_receipt(self.pvc)
        self.assertEqual(receipt["phase"], "bound")
        self.assertEqual(receipt["pvcUID"], "pvc-uid")
        self.assertEqual(receipt["statefulSetUID"], "statefulset-uid")
        self.assertEqual(receipt["clusterUID"], "cluster-uid")
        patches = [(command, data) for command, data in self.calls if command[0] == "patch"]
        self.assertEqual(len(patches), 1)
        self.assertIn("--patch-file=/dev/stdin", patches[0][0])
        self.assertNotIn(PRIVATE, patches[0][1])
        self.assertNotIn(TENANT, patches[0][1])
        cli.check_storage_identity(self.args, self.settings)

    def test_normal_upgrade_reuses_only_bound_same_identity_without_new_writes(self):
        self.bound()
        self.calls.clear()
        cli.check_storage_identity(self.args, self.settings)
        cli.reserve_storage(self.args, self.settings)
        cli.write_storage_identity(self.args, self.settings)
        self.assertTrue(all(command[0] == "get" for command, _ in self.calls))

    def test_token_rotation_in_same_secret_and_tenant_remains_allowed(self):
        self.bound()
        self.secret["data"]["api-token"] = base64.b64encode(b"another-synthetic-token").decode()
        cli.check_storage_identity(self.args, self.settings)

    def test_foreign_claim_is_rejected_before_reading_any_secret_or_writing(self):
        self.pvc = {"metadata": {"name": self.pvc_name, "namespace": self.args.namespace, "uid": "foreign", "labels": {}}}
        with self.assertRaisesRegex(cli.Failure, "another owner"):
            cli.check_storage_identity(self.args, self.settings)
        self.assertEqual(len(self.calls), 1)

    def test_retained_claim_without_live_owned_statefulset_is_never_reinstalled(self):
        self.bound()
        self.sts = None
        self.calls.clear()
        with self.assertRaisesRegex(cli.Failure, "Manual recovery"):
            cli.check_storage_identity(self.args, self.settings)
        self.assertTrue(all(command[0] == "get" for command, _ in self.calls))

    def test_pending_receipt_after_interrupted_install_requires_manual_recovery(self):
        cli.reserve_storage(self.args, self.settings)
        with self.assertRaisesRegex(cli.Failure, "incomplete"):
            cli.check_storage_identity(self.args, self.settings)

    def test_direct_helm_claim_without_receipt_is_not_automatically_adopted(self):
        self.bound()
        self.pvc["metadata"]["annotations"] = {}
        with self.assertRaisesRegex(cli.Failure, "automatic adoption"):
            cli.check_storage_identity(self.args, self.settings)

    def test_tenant_secret_or_physical_identity_changes_are_rejected(self):
        self.bound()
        original = copy.deepcopy((self.args, self.settings, self.pvc, self.sts, self.secret, self.cm))
        for change in ("tenant", "secretUID", "pvcUID", "statefulSetUID", "clusterUID", "secretName", "clusterName"):
            self.args, self.settings, self.pvc, self.sts, self.secret, self.cm = copy.deepcopy(original)
            if change == "tenant":
                self.secret["data"]["tenant-id"] = base64.b64encode(b"another-tenant").decode()
            elif change == "secretUID":
                self.secret["metadata"]["uid"] = "recreated-secret"
            elif change == "pvcUID":
                self.pvc["metadata"]["uid"] = "recreated-pvc"
            elif change == "statefulSetUID":
                self.sts["metadata"]["uid"] = "recreated-sts"
            elif change == "clusterUID":
                self.args.confirmed_cluster_uid = "different-cluster"
            elif change == "secretName":
                self.settings["credentials"]["existingSecret"] = "other-ingest"
            else:
                self.settings["cluster"]["name"] = "different-logical-cluster"
            with self.subTest(change=change), self.assertRaises(cli.Failure):
                cli.check_storage_identity(self.args, self.settings)

    def test_foreign_owner_reference_is_rejected(self):
        self.bound()
        self.pvc["metadata"]["ownerReferences"] = [{"kind": "StatefulSet", "uid": "foreign-sts"}]
        with self.assertRaisesRegex(cli.Failure, "foreign owner"):
            cli.check_storage_identity(self.args, self.settings)

    def test_create_race_never_falls_back_to_reusing_newly_existing_claim(self):
        real = self.kube
        def racing(args, *command, data=None):
            if command[:2] == ("create", "-f"):
                self.pvc = {"metadata": {"uid": "foreign-raced-pvc"}}
                raise cli.Failure("AlreadyExists")
            return real(args, *command, data=data)
        with mock.patch.object(cli, "kube", side_effect=racing), self.assertRaisesRegex(cli.Failure, "Helm was not started"):
            cli.reserve_storage(self.args, self.settings)
        self.assertFalse(any(command[0] == "patch" for command, _ in self.calls))

    def test_receipt_compare_and_swap_retries_revalidated_controller_updates(self):
        cli.reserve_storage(self.args, self.settings)
        self.patch_failures = 1
        cli.write_storage_identity(self.args, self.settings)
        self.assertEqual(cli.storage_receipt(self.pvc)["phase"], "bound")
        self.assertEqual(sum(command[0] == "patch" for command, _ in self.calls), 2)

    def test_failed_receipt_write_preserves_claim_and_reports_post_helm_failure(self):
        cli.reserve_storage(self.args, self.settings)
        self.patch_failures = 3
        with self.assertRaisesRegex(cli.Failure, "Helm reconciled.*retained"):
            cli.write_storage_identity(self.args, self.settings)
        self.assertEqual(cli.storage_receipt(self.pvc)["phase"], "reserved")
        self.assertFalse(any(command[0] == "delete" for command, _ in self.calls))

    def test_install_reserves_before_helm_and_commits_receipt_only_after_success(self):
        expected_sts, expected_cm = self.sts, self.cm
        self.sts, self.cm = None, None
        def reconcile(*args, **kwargs):
            self.assertEqual(cli.storage_receipt(self.pvc)["phase"], "reserved")
            self.assertFalse(any(command[0] == "patch" for command, _ in self.calls))
            self.sts, self.cm = expected_sts, expected_cm
            return "reconciled"
        with tempfile.TemporaryDirectory(prefix="elven-storage-test-" ) as folder, \
             mock.patch.object(cli, "helm", side_effect=reconcile), mock.patch("sys.stdout", new_callable=io.StringIO):
            cli.install(self.args, {"metadata": {"name": self.args.namespace}}, self.settings, [], Path(folder), 4)
        self.assertEqual(cli.storage_receipt(self.pvc)["phase"], "bound")

    def test_helm_failure_keeps_reserved_claim_and_never_commits_or_deletes_it(self):
        with tempfile.TemporaryDirectory(prefix="elven-storage-test-") as folder, \
             mock.patch.object(cli, "helm", side_effect=cli.Failure("synthetic Helm failure")), \
             self.assertRaisesRegex(cli.Failure, "Helm failure"):
            cli.install(self.args, {"metadata": {"name": self.args.namespace}}, self.settings, [], Path(folder), 4)
        self.assertEqual(cli.storage_receipt(self.pvc)["phase"], "reserved")
        self.assertFalse(any(command[0] in ("patch", "delete") for command, _ in self.calls))

    def test_ephemeral_profile_has_no_claim_io(self):
        self.settings["gateway"]["persistence"]["enabled"] = False
        cli.check_storage_identity(self.args, self.settings)
        cli.reserve_storage(self.args, self.settings)
        cli.write_storage_identity(self.args, self.settings)
        self.assertEqual(self.calls, [])

    def test_preflight_rejects_foreign_claim_before_permission_checks_or_mutations(self):
        self.pvc = {"metadata": {"name": self.pvc_name, "namespace": self.args.namespace, "uid": "foreign"}}
        original = self.kube
        def reply(args, *command, data=None):
            if command == ("version", "-o", "json"):
                return json.dumps({"serverVersion": {"gitVersion": "v1.37.0"}})
            if command == ("get", "namespace", "kube-system", "-o", "json"):
                return json.dumps({"metadata": {"uid": "cluster-uid"}})
            if command == ("get", "namespace", self.args.namespace, "--ignore-not-found", "-o", "json"):
                return json.dumps({"metadata": {"name": self.args.namespace}})
            return original(args, *command, data=data)
        with mock.patch.object(cli, "kube", side_effect=reply), mock.patch.object(cli, "can_i") as permission, \
             self.assertRaisesRegex(cli.Failure, "another owner"):
            cli.preflight(self.args, "", self.settings, changing=True)
        permission.assert_not_called()

    def test_storage_read_failure_is_unknown_not_an_empty_safe_namespace(self):
        with mock.patch.object(cli, "kube", side_effect=cli.Failure("synthetic denied")), \
             self.assertRaisesRegex(cli.Failure, "read permission/API"):
            cli.check_storage_identity(self.args, self.settings)

    def test_preflight_checks_installer_pvc_and_cluster_rbac_patch_permissions(self):
        self.args.command = "preflight"
        original = self.kube
        def reply(args, *command, data=None):
            if command == ("version", "-o", "json"):
                return json.dumps({"serverVersion": {"gitVersion": "v1.37.0"}})
            if command == ("get", "namespace", "kube-system", "-o", "json"):
                return json.dumps({"metadata": {"uid": "cluster-uid"}})
            if command == ("get", "namespace", self.args.namespace, "--ignore-not-found", "-o", "json"):
                return json.dumps({"metadata": {"name": self.args.namespace}})
            if command == ("get", "storageclasses", "-o", "json"):
                return json.dumps({"items": [{"metadata": {"name": "reviewed-storage"}}]})
            if command[:3] == ("get", "secret", "synthetic-tls"):
                return json.dumps({"data": {key: base64.b64encode(b"synthetic").decode() for key in (
                    "tls.crt", "tls.key", "ca.crt", "client.crt", "client.key")}})
            return original(args, *command, data=data)
        with mock.patch.object(cli, "kube", side_effect=reply), mock.patch.object(cli, "can_i") as permission, \
             mock.patch.object(cli, "validate_tls"), mock.patch("sys.stdout", new_callable=io.StringIO):
            cli.preflight(self.args, "kind: ClusterRole\n", self.settings, changing=False)
        for verb in ("get", "create", "patch"):
            permission.assert_any_call(self.args, verb, "persistentvolumeclaims", True)
        for resource in ("clusterroles.rbac.authorization.k8s.io", "clusterrolebindings.rbac.authorization.k8s.io"):
            for verb in ("create", "patch"):
                permission.assert_any_call(self.args, verb, resource)

    def test_rollback_blocks_current_tenant_drift_before_reading_or_mutating_revision(self):
        self.bound()
        self.secret["data"]["tenant-id"] = base64.b64encode(b"different-synthetic-tenant").decode()
        with mock.patch.object(cli, "helm") as helm, self.assertRaisesRegex(cli.Failure, "identity changed"):
            cli.check_rollback_storage_identity(self.args, self.settings)
        helm.assert_not_called()

    def test_rollback_refuses_target_revision_identity_changes_without_rollback_mutation(self):
        self.bound()
        for field in ("cluster", "secret", "persistence", "fullname", "missing"):
            target = copy.deepcopy(self.settings)
            if field == "cluster":
                target["cluster"]["name"] = "other-cluster"
            elif field == "secret":
                target["credentials"]["existingSecret"] = "other-ingest"
            elif field == "persistence":
                target["gateway"]["persistence"]["enabled"] = False
            elif field == "fullname":
                target["fullnameOverride"] = "other-statefulset"
            else:
                target = {}
            with self.subTest(field=field), mock.patch.object(cli, "helm", return_value=json.dumps(target)) as helm, \
                 self.assertRaisesRegex(cli.Failure, "Rollback revision changes"):
                cli.check_rollback_storage_identity(self.args, self.settings)
            self.assertEqual(helm.call_count, 1)
            self.assertEqual(helm.call_args.args[1:3], ("get", "values"))

    def test_rollback_same_identity_requires_no_backend_tls_expiry_or_image_gate(self):
        self.bound()
        with mock.patch.object(cli, "helm", return_value=json.dumps(self.settings)) as helm, \
             mock.patch.object(cli, "validate_tls", side_effect=AssertionError("Expired TLS must not block recovery")), \
             mock.patch.object(cli, "require_promoted_images", side_effect=AssertionError("Recovery must not promote images")):
            cli.check_rollback_storage_identity(self.args, self.settings)
        self.assertIn("--all", helm.call_args.args)
        self.assertIn("--revision", helm.call_args.args)
        self.assertTrue(helm.call_args.kwargs["online"])

    def test_status_and_uninstall_do_not_enter_storage_or_ingest_guard(self):
        def reply(args, *command, data=None):
            if command == ("version", "-o", "json"):
                return json.dumps({"serverVersion": {"gitVersion": "v1.38.0"}})
            if command == ("get", "namespace", "kube-system", "-o", "json"):
                return json.dumps({"metadata": {"uid": "cluster-uid"}})
            if command == ("get", "namespace", self.args.namespace, "--ignore-not-found", "-o", "json"):
                return json.dumps({"metadata": {"name": self.args.namespace}})
            raise AssertionError("Status/uninstall must not read Secrets or PVC identity")
        for command in ("status", "uninstall"):
            self.args.command = command
            with self.subTest(command=command), mock.patch.object(cli, "kube", side_effect=reply), \
                 mock.patch.object(cli, "helm", return_value=json.dumps([{"name": self.args.release, "chart": "elven-observability-1.0.0-rc.1"}])), \
                 mock.patch.object(cli, "check_storage_identity", side_effect=AssertionError("No storage guard")), \
                 mock.patch.object(cli, "check_rollback_storage_identity", side_effect=AssertionError("No rollback guard")), \
                 mock.patch("sys.stdout", new_callable=io.StringIO):
                cli.preflight(self.args, "", self.settings, changing=command == "uninstall")

    def test_rollback_preflight_dispatches_tenant_guard_before_any_rollback(self):
        self.bound()
        self.args.command = "rollback"
        self.secret["data"]["tenant-id"] = base64.b64encode(b"different-synthetic-tenant").decode()
        original = self.kube
        def reply(args, *command, data=None):
            if command == ("version", "-o", "json"):
                return json.dumps({"serverVersion": {"gitVersion": "v1.38.0"}})
            if command == ("get", "namespace", "kube-system", "-o", "json"):
                return json.dumps({"metadata": {"uid": "cluster-uid"}})
            if command == ("get", "namespace", self.args.namespace, "--ignore-not-found", "-o", "json"):
                return json.dumps({"metadata": {"name": self.args.namespace}})
            return original(args, *command, data=data)
        with mock.patch.object(cli, "kube", side_effect=reply), \
             mock.patch.object(cli, "helm", return_value=json.dumps([{"name": self.args.release, "chart": "elven-observability-1.0.0-rc.1"}])) as helm, \
             self.assertRaisesRegex(cli.Failure, "identity changed"):
            cli.preflight(self.args, "", self.settings, changing=True)
        self.assertEqual(helm.call_count, 1)
        self.assertEqual(helm.call_args.args[1], "list")


if __name__ == "__main__":
    unittest.main(verbosity=2)
