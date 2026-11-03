"""Unit contracts for the disposable SDK laboratory, never live Kind evidence.

Archives contain synthetic bytes solely to exercise manifest identity checks.
Every process boundary is mocked; these tests do not build images, generate PKI,
contact a registry, or create a Docker/Kubernetes resource.
"""
from __future__ import annotations

import copy
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "elven_instrumentation_kind_under_test", ROOT / "scripts/test-instrumentation-kind.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SdkWireSummaryTests(unittest.TestCase):
    def capture(self, transfer=None, payload=b"synthetic nonempty OTLP body", **overrides):
        return {"transfer_encoding": transfer, "body": base64.b64encode(payload).decode(),
                "client_certificate_verified": True, "authorization_present": False, **overrides}

    def test_java_content_length_and_node_chunked_exports_are_summarized_without_credentials(self):
        summary = MODULE.sdk_wire_summary([self.capture(), self.capture("chunked"), self.capture("CHUNKED")])
        self.assertEqual(summary, {"verified_client_certificate_exports": 3, "chunked_exports": 2,
            "empty_chunked_exports": 0, "backend_bearer_credentials_in_sdk_exports": False})

    def test_empty_chunked_body_reproduces_the_old_sink_regression_and_must_fail(self):
        with self.assertRaisesRegex(AssertionError, "streamed SDK bodies"):
            MODULE.sdk_wire_summary([self.capture("chunked", b"")])

    def test_sdk_exports_require_verified_client_identity_without_backend_bearer(self):
        for captures in ([], [self.capture(client_certificate_verified=False)], [self.capture(authorization_present=True)]):
            with self.subTest(captures=captures), self.assertRaises(AssertionError):
                MODULE.sdk_wire_summary(captures)


class ManifestFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="elven-instrumentation-kind-unit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.candidate = self.root / "candidate"
        self.candidate.mkdir()
        self.manifest = self.candidate / "release.json"
        self.payload = {"images": {}}
        for index, (name, repository) in enumerate(MODULE.REPOSITORIES.items()):
            archive = self.candidate / (name + ".oci.tar")
            archive.write_bytes(("synthetic archive identity fixture " + name + "\n").encode())
            self.payload["images"][name] = {
                "tag": "docker.io/elvenobservability/" + repository + ":1.0.0-dev",
                "digest": "sha256:" + format(index + 1, "064x"),
                "archive": archive.name,
                "archiveSha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            }
        self.write_manifest()

    def write_manifest(self, payload=None):
        self.manifest.write_text(json.dumps(self.payload if payload is None else payload))


class ImageManifestTests(ManifestFixture):
    def test_complete_five_image_manifest_returns_exact_elven_references(self):
        images = MODULE.read_images(self.manifest)
        self.assertEqual(set(images), {"operator", "java", "nodejs", "nodejs20", "python"})
        for name, image in images.items():
            original = self.payload["images"][name]
            self.assertEqual(image["repository"], "docker.io/elvenobservability/" + MODULE.REPOSITORIES[name])
            self.assertEqual(image["tag"], "1.0.0-dev")
            self.assertEqual(image["digest"], original["digest"])
            self.assertEqual(image["reference"], original["tag"] + "@" + original["digest"])
            self.assertEqual(image["archive"], (self.candidate / original["archive"]).resolve())

    def test_every_instrumentation_component_is_required_including_explicit_node20(self):
        for missing in MODULE.REPOSITORIES:
            payload = copy.deepcopy(self.payload)
            del payload["images"][missing]
            self.write_manifest(payload)
            with self.subTest(missing=missing), self.assertRaisesRegex(ValueError, "five-image"):
                MODULE.read_images(self.manifest)

    def test_unexpected_components_are_not_accepted_as_a_complete_build(self):
        for extra in ("collector", "ruby", "node20"):
            payload = copy.deepcopy(self.payload)
            payload["images"][extra] = copy.deepcopy(payload["images"]["operator"])
            self.write_manifest(payload)
            with self.subTest(extra=extra), self.assertRaisesRegex(ValueError, "five-image"):
                MODULE.read_images(self.manifest)

    def test_missing_image_map_is_rejected(self):
        self.write_manifest({"version": "synthetic"})
        with self.assertRaisesRegex(ValueError, "five-image"):
            MODULE.read_images(self.manifest)

    def test_image_digests_must_be_complete_lowercase_sha256(self):
        for digest in ("", "latest", "sha256:abc", "sha256:" + "g" * 64,
                       "sha256:" + "A" * 64, "sha512:" + "a" * 64,
                       "sha256:" + "a" * 64 + "\n"):
            payload = copy.deepcopy(self.payload)
            payload["images"]["operator"]["digest"] = digest
            self.write_manifest(payload)
            with self.subTest(digest=digest), self.assertRaisesRegex(ValueError, "exact Elven images"):
                MODULE.read_images(self.manifest)

    def test_every_component_requires_its_own_elven_repository(self):
        for component in MODULE.REPOSITORIES:
            for tag in ("docker.io/foreign/runtime:1.0.0-dev",
                        "ghcr.io/elvenobservability/" + MODULE.REPOSITORIES[component] + ":1.0.0-dev",
                        "docker.io/elvenobservability/" + MODULE.REPOSITORIES[component] + "-foreign:1.0.0-dev"):
                payload = copy.deepcopy(self.payload)
                payload["images"][component]["tag"] = tag
                self.write_manifest(payload)
                with self.subTest(component=component, tag=tag), self.assertRaisesRegex(ValueError, "exact Elven images"):
                    MODULE.read_images(self.manifest)

    def test_a_component_cannot_be_substituted_by_another_elven_runtime(self):
        self.payload["images"]["java"]["tag"] = self.payload["images"]["operator"]["tag"]
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "exact Elven images"):
            MODULE.read_images(self.manifest)

    def test_archive_hash_must_match_actual_fixture_bytes(self):
        for recorded in ("", "0" * 64, "not-a-sha256"):
            payload = copy.deepcopy(self.payload)
            payload["images"]["operator"]["archiveSha256"] = recorded
            self.write_manifest(payload)
            with self.subTest(recorded=recorded), self.assertRaisesRegex(ValueError, "SHA-256 verification"):
                MODULE.read_images(self.manifest)

    def test_archive_tampering_after_manifest_creation_is_rejected(self):
        archive = self.candidate / self.payload["images"]["operator"]["archive"]
        archive.write_bytes(archive.read_bytes() + b"synthetic post-build modification\n")
        with self.assertRaisesRegex(ValueError, "SHA-256 verification"):
            MODULE.read_images(self.manifest)

    def escaped_archive(self, path):
        self.payload["images"]["operator"]["archive"] = str(path)
        # Give the foreign bytes a matching hash so only the directory boundary
        # can reject them; a hash mismatch must not mask a traversal regression.
        self.payload["images"]["operator"]["archiveSha256"] = hashlib.sha256(self.foreign.read_bytes()).hexdigest()
        self.write_manifest()
        with mock.patch.object(MODULE, "sha256", wraps=MODULE.sha256) as digest:
            with self.assertRaisesRegex(ValueError, "escaped its directory"):
                MODULE.read_images(self.manifest)
        # The directory boundary must be checked before opening a foreign file.
        self.assertFalse(any(Path(call.args[0]).resolve() == self.foreign.resolve() for call in digest.call_args_list))

    def test_relative_archive_escape_is_rejected_before_reading_foreign_bytes(self):
        self.foreign = self.root / "foreign.oci.tar"
        self.foreign.write_bytes(b"synthetic file outside the approved candidate directory\n")
        self.escaped_archive(Path("..") / self.foreign.name)

    def test_absolute_archive_escape_is_rejected(self):
        self.foreign = self.root / "foreign.oci.tar"
        self.foreign.write_bytes(b"synthetic file outside the approved candidate directory\n")
        self.escaped_archive(self.foreign)

    def test_archive_symlink_cannot_escape_the_candidate_directory(self):
        self.foreign = self.root / "foreign.oci.tar"
        self.foreign.write_bytes(b"synthetic file outside the approved candidate directory\n")
        link = self.candidate / "escape.oci.tar"
        link.symlink_to(self.foreign)
        self.escaped_archive(link.name)


class LaboratoryMetadataTests(ManifestFixture):
    def make_lab(self, combined=False):
        collector = "docker.io/elvenobservability/elven-collector:1.0.0-dev@sha256:" + "e" * 64
        archive = self.root / "synthetic-collector.oci.tar"
        archive.write_bytes(b"synthetic Collector constructor fixture; never imported\n")
        arguments = SimpleNamespace(images_manifest=self.manifest, node_image=MODULE.CORE.KIND_NODE,
            keep=False, collector_image=collector if combined else None,
            collector_image_archive=archive if combined else None)
        with mock.patch.object(MODULE.CORE, "ROOT", self.root / "lab-root"), \
             mock.patch.object(MODULE.CORE, "execute", side_effect=AssertionError("Unit construction must not spawn a process")):
            return MODULE.InstrumentationLab(arguments)

    def test_standalone_mode_explicitly_does_not_prove_gateway_or_installer_bootstrap(self):
        lab = self.make_lab()
        self.assertEqual(lab.report["mode"], "standalone-sdk-mtls-sink")
        self.assertFalse(lab.combined)
        self.assertIn("gateway privacy/durable queues in this standalone SDK run", lab.report["not_proven"])
        self.assertIn("gateway/instrumentation installer ownership bootstrap in this standalone SDK run",
                      lab.report["not_proven"])
        self.assertFalse(lab.report["completed"])
        self.assertFalse(lab.report["customer_cluster_access"])
        self.assertEqual(lab.report["checks"], [])

    def test_operator_values_include_the_complete_serving_pki_contract(self):
        lab = self.make_lab()
        lab.kube = mock.Mock(return_value=SimpleNamespace(stdout=json.dumps({"items": [{"status": {
            "addresses": [{"type": "InternalIP", "address": "192.0.2.10"}]}}]})))
        settings = lab.operator_values("https://sink.synthetic.invalid:443")
        self.assertEqual(settings["clusterDomain"], "cluster.local")
        self.assertEqual(settings["namespaces"], [lab.app_namespace])
        self.assertTrue(settings["runtimes"]["legacyNode20Approved"])

    def test_verified_public_jdbc_jar_remains_readable_by_the_nonroot_application(self):
        lab = self.make_lab()
        folder = self.root / "application-fixture-source"
        folder.mkdir()
        payload = b"synthetic public fixture dependency, not a Secret"
        pins = {"images": {case: "docker.io/library/synthetic@sha256:" + "a" * 64
                           for case in ("java17", "java21", "node22", "node20")},
                "h2": {"url": "https://synthetic.invalid/h2.jar", "file": "h2.jar",
                       "sha256": hashlib.sha256(payload).hexdigest()}}
        (folder / "fixtures.json").write_text(json.dumps(pins))
        for case, image in pins["images"].items():
            (folder / ("Dockerfile." + case)).write_text("FROM " + image + "\n")
        with mock.patch.object(MODULE, "FIXTURES", folder), \
             mock.patch.object(MODULE.urllib.request, "urlopen", return_value=io.BytesIO(payload)), \
             mock.patch.object(MODULE.CORE, "execute", return_value=SimpleNamespace(stdout="")), \
             mock.patch.object(lab, "check"):
            lab.prepare_fixtures()
        dependency = lab.directory / "application-fixtures/h2.jar"
        self.assertEqual(dependency.read_bytes(), payload)
        self.assertEqual(dependency.stat().st_mode & 0o777, 0o444)

    def test_unverified_or_oversized_jdbc_download_is_never_written_or_built(self):
        for payload in (b"synthetic hash mismatch", b"x" * (4 * 1024 * 1024 + 1)):
            with self.subTest(size=len(payload)):
                lab = self.make_lab()
                folder = self.root / ("invalid-fixture-" + str(len(payload)))
                folder.mkdir()
                (folder / "fixtures.json").write_text(json.dumps({"images": {}, "h2": {
                    "url": "https://synthetic.invalid/h2.jar", "file": "h2.jar", "sha256": "0" * 64}}))
                with mock.patch.object(MODULE, "FIXTURES", folder), \
                     mock.patch.object(MODULE.urllib.request, "urlopen", return_value=io.BytesIO(payload)), \
                     mock.patch.object(MODULE.CORE, "execute", side_effect=AssertionError("Unverified JAR must not reach Docker")), \
                     self.assertRaisesRegex(AssertionError, "pinned SHA-256"):
                    lab.prepare_fixtures()
                self.assertFalse((lab.directory / "application-fixtures/h2.jar").exists())

    def test_combined_mode_is_only_intent_until_real_boot_and_checks_finish(self):
        lab = self.make_lab(combined=True)
        self.assertTrue(lab.combined)
        self.assertEqual(lab.report["mode"], "gateway-and-installers")
        self.assertFalse(lab.report["completed"])
        self.assertEqual(lab.report["checks"], [])
        self.assertEqual(lab.report["collector_image_override"], lab.collector_image)

    def test_initial_modes_never_claim_architecture_python_or_production_acceptance(self):
        for combined in (False, True):
            with self.subTest(combined=combined):
                lab = self.make_lab(combined)
                for limit in MODULE.CORE.RUNTIME_LIMITS.values():
                    self.assertIn(limit, lab.report["not_proven"])
                self.assertIn("Python SDK application compatibility", lab.report["not_proven"])
                self.assertIn("customer infrastructure/tenant acceptance", lab.report["not_proven"])
                self.assertIn("NetworkPolicy enforcement (Kind default CNI)", lab.report["not_proven"])
                self.assertNotIn("runtime_platform", lab.report)
                self.assertNotIn("python", lab.report["runtime_cases"])

    def test_standalone_install_uses_fixture_pki_not_a_fabricated_installer_run(self):
        lab = self.make_lab()
        lab.tls_dir = lab.directory / "synthetic-tls"
        lab.tls_dir.mkdir()
        for name in ("ca.crt", "client.crt", "client.key"):
            (lab.tls_dir / name).write_text("synthetic fixture " + name)
        lab.install_gateway = mock.Mock(side_effect=AssertionError("Standalone mode must not claim a gateway install"))
        lab.operator_values = mock.Mock(return_value={"enabled": True})
        lab.apply = mock.Mock()
        lab.helm = mock.Mock(return_value=SimpleNamespace(stdout=""))
        lab.kube = mock.Mock(return_value=SimpleNamespace(stdout="no\n"))
        lab.check = mock.Mock()

        def fixture_pkcs8(args, **kwargs):
            self.assertEqual(args[:2], ["openssl", "pkcs8"])
            Path(args[args.index("-out") + 1]).write_text("synthetic pkcs8 fixture only")
            return SimpleNamespace(stdout="")

        serving = {"ca.crt": "synthetic serving CA", "tls.crt": "synthetic serving cert", "tls.key": "synthetic key"}
        with mock.patch.object(MODULE.INSTRUMENTATION, "generate_serving", return_value=serving), \
             mock.patch.object(MODULE.CORE, "execute", side_effect=fixture_pkcs8) as execute:
            lab.install_operator()
        execute.assert_called_once()
        lab.install_gateway.assert_not_called()
        self.assertEqual(lab.helm.call_args.args[:3], ("install", lab.operator_release, MODULE.ROOT / "charts/elven-instrumentation"))
        names = [call.args[0] for call in lab.check.call_args_list]
        self.assertIn("real Operator chart with verified serving PKI and mTLS SDK client fixture installed", names)
        self.assertFalse(any("CLI" in name or "bootstrap" in name for name in names))

    def test_combined_install_routes_through_instrumentation_cli_not_direct_helm(self):
        lab = self.make_lab(combined=True)
        endpoint = "https://elven-a-gateway.elven-e2e.svc.cluster.local:4318"
        lab.install_gateway = mock.Mock(return_value=endpoint)
        lab.operator_values = mock.Mock(return_value={"enabled": True})
        lab.helm = mock.Mock()
        lab.kube = mock.Mock(side_effect=[SimpleNamespace(stdout=json.dumps({"metadata": {"uid": "synthetic-kind-uid"}})),
                                         SimpleNamespace(stdout=""), SimpleNamespace(stdout="no\n")])
        lab.check = mock.Mock()
        with mock.patch.object(MODULE.CORE, "execute", return_value=SimpleNamespace(stdout="")) as execute, \
             mock.patch.object(MODULE.INSTRUMENTATION, "generate_serving") as serving:
            lab.install_operator()
        command = execute.call_args.args[0]
        self.assertEqual(command[:3], [MODULE.sys.executable, MODULE.ROOT / "scripts/instrumentation.py", "install"])
        self.assertEqual(command[command.index("--kubeconfig") + 1], lab.kubeconfig)
        self.assertEqual(command[command.index("--context") + 1], "kind-" + lab.name)
        self.assertIn("--expect-cluster-uid", command)
        self.assertIn("--development-images", command)
        lab.helm.assert_not_called()
        serving.assert_not_called()


class CoreInstallerRoutingTests(unittest.TestCase):
    def make_lab(self):
        lab = MODULE.CORE.Lab.__new__(MODULE.CORE.Lab)
        lab.namespace = "synthetic-elven-unit"
        lab.name = "elven-dist-synthetic-unit"
        lab.kubeconfig = Path("/synthetic/unit-only/kubeconfig")
        lab.provision = mock.Mock()
        lab.values = mock.Mock(return_value=Path("/synthetic/unit-only/values.yaml"))
        lab.cli = mock.Mock(return_value=SimpleNamespace(stdout=""))
        lab.helm = mock.Mock(return_value=SimpleNamespace(stdout="synthetic installed manifest\n"))
        lab.check = mock.Mock()
        return lab

    def test_core_install_uses_cli_before_reading_helm_manifest_for_storage_receipt_contract(self):
        lab = self.make_lab()
        calls = mock.Mock()
        for name in ("provision", "values", "cli", "helm", "check"):
            calls.attach_mock(getattr(lab, name), name)
        result = lab.install("elven-synthetic", cluster_metrics=True)
        source = lab.values.return_value
        self.assertEqual(result, source)
        lab.cli.assert_called_once_with("install", source, release="elven-synthetic")
        lab.helm.assert_called_once_with("get", "manifest", "elven-synthetic")
        self.assertEqual([call[0] for call in calls.mock_calls], ["provision", "values", "cli", "helm", "check"])
        self.assertEqual(lab.check.call_args.kwargs["manifest_sha256"],
                         hashlib.sha256(lab.helm.return_value.stdout.encode()).hexdigest())

    def test_failed_cli_cannot_emit_a_false_clean_install_check(self):
        lab = self.make_lab()
        lab.cli.side_effect = RuntimeError("synthetic installer rejected missing storage identity")
        with self.assertRaisesRegex(RuntimeError, "storage identity"):
            lab.install("elven-synthetic")
        lab.helm.assert_not_called()
        lab.check.assert_not_called()

    def test_core_cli_calls_real_entrypoint_with_explicit_isolation_and_existing_secrets(self):
        lab = self.make_lab()
        del lab.cli
        lab.kube = mock.Mock(return_value=SimpleNamespace(stdout=json.dumps({"metadata": {"uid": "synthetic-kind-uid"}})))
        source = Path("/synthetic/unit-only/values.yaml")
        with mock.patch.object(MODULE.CORE, "execute", return_value=SimpleNamespace(stdout="")) as execute:
            lab.cli("install", source, release="elven-synthetic")
        command = execute.call_args.args[0]
        self.assertEqual(command[:3], [MODULE.CORE.sys.executable, str(MODULE.CORE.ROOT / "elven"), "install"])
        self.assertEqual(command[command.index("--release") + 1], "elven-synthetic")
        self.assertEqual(command[command.index("--context") + 1], "kind-" + lab.name)
        self.assertEqual(command[command.index("--kubeconfig") + 1], str(lab.kubeconfig))
        self.assertEqual(command[command.index("--expect-cluster-uid") + 1], "synthetic-kind-uid")
        self.assertEqual(command[command.index("--values") + 1], str(source))
        self.assertIn("--use-existing-secrets", command)
        self.assertIn("--development-images", command)
        lab.kube.assert_called_once_with("get", "namespace/kube-system", "-o", "json")


if __name__ == "__main__":
    unittest.main(verbosity=2)
