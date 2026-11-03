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


class ReleasePolicyTests(ManifestFixture):
    """Synthetic local metadata exercises policy, not publication/signature proof."""

    def setUp(self):
        super().setUp()
        self.policy_root = self.root / "synthetic-project"
        self.chart_values = self.policy_root / "charts/elven-observability/values.yaml"
        self.chart_values.parent.mkdir(parents=True)
        self.collector_archive = self.root / "synthetic-core.oci.tar"
        self.collector_archive.write_bytes(b"synthetic metadata fixture; never imported\n")
        self.core_lock = {"schemaVersion": 1,
            "distribution": {"version": "1.0.0", "publicationStatus": "verified"}, "images": {}}
        self.sdk_lock = copy.deepcopy(self.core_lock)
        self.defaults = {"images": {}}
        self.expected = {}
        for index, (name, repository) in enumerate(MODULE.CORE_REPOSITORIES.items(), start=16):
            image = {"repository": "docker.io/elvenobservability/" + repository,
                     "tag": "v1.0.0", "digest": "sha256:" + format(index, "064x")}
            self.defaults["images"][name] = copy.deepcopy(image)
            self.core_lock["images"][name] = {"distribution": {**image, "status": "verified"}}
            self.expected["core." + name] = MODULE.image_reference(image)
        self.payload.update({"version": "v1.0.0", "publicationStatus": "verified"})
        for name, entry in self.payload["images"].items():
            entry["tag"] = entry["tag"].replace(":1.0.0-dev", ":v1.0.0")
            entry["publicationStatus"] = "verified"
            image = {"repository": entry["tag"].rsplit(":", 1)[0], "tag": "v1.0.0", "digest": entry["digest"]}
            self.sdk_lock["images"][name] = {"distribution": {**image, "status": "verified"}}
            self.expected["sdk." + name] = MODULE.image_reference(image)
        self.write_manifest()
        self.write_locks()

    def write_locks(self, core=None, sdk=None, defaults=None):
        (self.policy_root / "versions.lock.json").write_text(json.dumps(self.core_lock if core is None else core))
        (self.policy_root / "instrumentation.lock.json").write_text(json.dumps(self.sdk_lock if sdk is None else sdk))
        # JSON is a valid YAML document; no repository values or real release
        # metadata are changed by these isolated policy fixtures.
        self.chart_values.write_text(json.dumps(self.defaults if defaults is None else defaults))

    def arguments(self, **changes):
        return SimpleNamespace(**{"images_manifest": self.manifest, "development_images": False,
            "collector_image": self.expected["core.collector"],
            "collector_image_archive": self.collector_archive, "node_image": MODULE.CORE.KIND_NODE,
            "keep": False, **changes})

    def policy(self, args=None, images=None):
        selected = MODULE.read_images(self.manifest) if images is None else images
        with mock.patch.object(MODULE, "ROOT", self.policy_root):
            return MODULE.release_policy(self.arguments() if args is None else args, selected)

    def test_verified_local_metadata_matches_all_eight_exact_promoted_references(self):
        self.assertEqual(self.policy(), {"mode": "promoted-release", "development_images": False,
                                         "promoted_references": self.expected})

    def test_explicit_development_bypasses_production_locks_without_claiming_promotion(self):
        images = MODULE.read_images(self.manifest)
        with mock.patch.object(Path, "read_text", side_effect=AssertionError("Development must not read production locks")):
            policy = MODULE.release_policy(self.arguments(development_images=True), images)
        self.assertEqual(policy, {"mode": "explicit-development", "development_images": True,
                                  "promoted_references": {}})

    def test_missing_development_flag_uses_the_production_policy_not_an_inferred_fallback(self):
        args = self.arguments()
        del args.development_images
        self.assertEqual(self.policy(args)["mode"], "promoted-release")
        unpromoted = copy.deepcopy(self.core_lock)
        unpromoted["distribution"]["publicationStatus"] = "not-published"
        self.write_locks(core=unpromoted)
        with self.assertRaises(ValueError):
            self.policy(args)

    def test_development_choice_must_be_an_explicit_boolean(self):
        for value in (None, 1, "true", "false"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.policy(self.arguments(development_images=value))

    def test_production_requires_both_collector_reference_and_its_archive(self):
        for changes in ({"collector_image": None}, {"collector_image_archive": None},
                        {"collector_image": None, "collector_image_archive": None}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.policy(self.arguments(**changes))

    def test_both_release_locks_require_verified_top_level_publication(self):
        for lock_name in ("core", "sdk"):
            for status in (None, "not-published", "signed", "pending"):
                core, sdk = copy.deepcopy(self.core_lock), copy.deepcopy(self.sdk_lock)
                (core if lock_name == "core" else sdk)["distribution"]["publicationStatus"] = status
                self.write_locks(core=core, sdk=sdk)
                with self.subTest(lock=lock_name, status=status), self.assertRaises(ValueError):
                    self.policy()

    def test_every_one_of_eight_lock_entries_must_have_verified_status(self):
        for scope, baseline in (("core", self.core_lock), ("sdk", self.sdk_lock)):
            for component in baseline["images"]:
                core, sdk = copy.deepcopy(self.core_lock), copy.deepcopy(self.sdk_lock)
                (core if scope == "core" else sdk)["images"][component]["distribution"]["status"] = "not-published"
                self.write_locks(core=core, sdk=sdk)
                with self.subTest(scope=scope, component=component), self.assertRaises(ValueError):
                    self.policy()

    def test_each_release_lock_requires_the_complete_expected_component_set(self):
        for scope, baseline in (("core", self.core_lock), ("sdk", self.sdk_lock)):
            for component in baseline["images"]:
                core, sdk = copy.deepcopy(self.core_lock), copy.deepcopy(self.sdk_lock)
                del (core if scope == "core" else sdk)["images"][component]
                self.write_locks(core=core, sdk=sdk)
                with self.subTest(scope=scope, component=component), self.assertRaises(ValueError):
                    self.policy()

    def test_promoted_entries_require_matching_elven_repositories_and_stable_v1_tags(self):
        for scope in ("core", "sdk"):
            for change in ({"repository": "docker.io/foreign/runtime"}, {"tag": "1.0.0"},
                           {"tag": "v1.0.0-dev"}, {"tag": "v1.0.0-rc.1"}, {"tag": "latest"},
                           {"tag": "v2.0.0"}, {"digest": "sha256:abc"}):
                core, sdk = copy.deepcopy(self.core_lock), copy.deepcopy(self.sdk_lock)
                target = core if scope == "core" else sdk
                component = next(iter(target["images"]))
                target["images"][component]["distribution"].update(change)
                self.write_locks(core=core, sdk=sdk)
                with self.subTest(scope=scope, change=change), self.assertRaises(ValueError):
                    self.policy()

    def test_sdk_manifest_requires_verified_top_level_and_every_entry_publication(self):
        original = copy.deepcopy(self.payload)
        for component in (None, *MODULE.REPOSITORIES):
            self.payload = copy.deepcopy(original)
            target = self.payload if component is None else self.payload["images"][component]
            target["publicationStatus"] = "not-published"
            self.write_manifest()
            with self.subTest(component=component), self.assertRaises(ValueError):
                self.policy()

    def test_sdk_manifest_version_must_match_the_promoted_distribution(self):
        for version in ("1.0.0", "v1.0.1", "v1.0.0-dev", "v1.0.0-rc.1"):
            self.payload["version"] = version
            self.write_manifest()
            with self.subTest(version=version), self.assertRaises(ValueError):
                self.policy()

    def test_all_five_selected_sdk_references_must_match_the_promoted_lock(self):
        original = MODULE.read_images(self.manifest)
        for component in MODULE.REPOSITORIES:
            images = copy.deepcopy(original)
            images[component]["reference"] = images[component]["reference"].rsplit("@", 1)[0] + "@sha256:" + "f" * 64
            with self.subTest(component=component), self.assertRaises(ValueError):
                self.policy(images=images)

    def test_effective_core_defaults_and_collector_override_cannot_drift_from_promoted_refs(self):
        for component in ("beyla", "alloy"):
            defaults = copy.deepcopy(self.defaults)
            defaults["images"][component]["digest"] = "sha256:" + "f" * 64
            self.write_locks(defaults=defaults)
            with self.subTest(component=component), self.assertRaises(ValueError):
                self.policy()
        self.write_locks()
        for override in (self.expected["core.collector"].replace(":v1.0.0@", ":1.0.0-dev@"),
                         self.expected["core.collector"].rsplit("@", 1)[0] + "@sha256:" + "f" * 64):
            with self.subTest(override=override), self.assertRaises(ValueError):
                self.policy(self.arguments(collector_image=override))

    def test_policy_refusal_precedes_core_constructor_and_all_process_boundaries(self):
        with mock.patch.object(MODULE, "release_policy", side_effect=ValueError("synthetic promotion gate closed")), \
             mock.patch.object(MODULE.CORE.Lab, "__init__") as core_constructor, \
             mock.patch.object(MODULE.CORE, "execute") as execute:
            with self.assertRaisesRegex(ValueError, "promotion gate closed"):
                MODULE.InstrumentationLab(self.arguments())
        core_constructor.assert_not_called()
        execute.assert_not_called()

    def test_promoted_metadata_in_report_still_does_not_claim_independent_registry_or_customer_proof(self):
        with mock.patch.object(MODULE, "ROOT", self.policy_root), \
             mock.patch.object(MODULE.CORE, "ROOT", self.root / "synthetic-lab"), \
             mock.patch.object(MODULE.CORE, "execute", side_effect=AssertionError("Metadata checks must not spawn a process")):
            lab = MODULE.InstrumentationLab(self.arguments())
        self.assertEqual(lab.report["release_policy"], {"mode": "promoted-release", "development_images": False,
                                                       "promoted_references": self.expected})
        self.assertFalse(lab.report["completed"])
        self.assertEqual(lab.report["checks"], [])
        self.assertIn("independent registry/signature verification by this runtime harness", lab.report["not_proven"])
        self.assertIn("customer infrastructure/tenant acceptance", lab.report["not_proven"])


class LaboratoryMetadataTests(ManifestFixture):
    def make_lab(self, combined=False):
        collector = "docker.io/elvenobservability/elven-collector:1.0.0-dev@sha256:" + "e" * 64
        archive = self.root / "synthetic-collector.oci.tar"
        archive.write_bytes(b"synthetic Collector constructor fixture; never imported\n")
        arguments = SimpleNamespace(images_manifest=self.manifest, node_image=MODULE.CORE.KIND_NODE, development_images=True,
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

    def test_combined_install_routes_through_one_unified_helper_not_a_second_cli(self):
        lab = self.make_lab(combined=True)
        endpoint = "https://elven-a-gateway.elven-e2e.svc.cluster.local:4318"
        lab.install_gateway = mock.Mock()
        lab.operator_values = mock.Mock(return_value={"enabled": True})
        lab.helm = mock.Mock()
        lab.kube = mock.Mock(return_value=SimpleNamespace(stdout="no\n"))
        lab.check = mock.Mock()
        order = mock.Mock()
        order.attach_mock(lab.operator_values, "operator_values")
        order.attach_mock(lab.install_gateway, "install_gateway")
        with mock.patch.object(MODULE.CORE, "execute", return_value=SimpleNamespace(stdout="")) as execute, \
             mock.patch.object(MODULE.INSTRUMENTATION, "generate_serving") as serving:
            lab.install_operator()
        source = lab.directory / "operator-values.yaml"
        lab.operator_values.assert_called_once_with(endpoint)
        lab.install_gateway.assert_called_once_with(source)
        self.assertEqual(MODULE.yaml.safe_load(source.read_text()), {"enabled": True})
        self.assertEqual([call[0] for call in order.mock_calls], ["operator_values", "install_gateway"])
        execute.assert_not_called()
        lab.helm.assert_not_called()
        serving.assert_not_called()


class UnifiedCLICommandTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="elven-unified-cli-unit-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def laboratory(self, development):
        lab = MODULE.InstrumentationLab.__new__(MODULE.InstrumentationLab)
        lab.name, lab.namespace, lab.operator_release = "elven-dist-unit", "elven-unit", "elven-injector"
        lab.directory = self.directory
        lab.kubeconfig = self.directory / "isolated-kubeconfig"
        lab.development_images = development
        lab.report = {}
        values = self.directory / "core-values.yaml"
        values.write_text("{}\n")
        lab.values = mock.Mock(return_value=values)
        lab.provision = mock.Mock()
        lab.verify_combined_installation = mock.Mock()
        lab.check = mock.Mock()
        lab.kube = mock.Mock(side_effect=[SimpleNamespace(stdout=json.dumps({"items": [{"status": {
            "addresses": [{"type": "InternalIP", "address": "192.0.2.10"}]}}]})),
            SimpleNamespace(stdout=json.dumps({"metadata": {"uid": "synthetic-cluster-uid"}}))])
        return lab

    def command(self, development):
        lab = self.laboratory(development)
        profile = self.directory / "operator-values.yaml"
        profile.write_text("enabled: true\n")
        with mock.patch.object(MODULE.CORE, "execute", return_value=SimpleNamespace(stdout="")) as execute:
            lab.install_gateway(profile)
        execute.assert_called_once()
        command = list(map(str, execute.call_args.args[0]))
        self.assertEqual(command[:3], [MODULE.sys.executable, str(MODULE.ROOT / "elven"), "install"])
        self.assertEqual(command[command.index("--instrumentation-values") + 1], str(profile))
        self.assertEqual(command[command.index("--instrumentation-release") + 1], lab.operator_release)
        self.assertEqual(command[command.index("--kubeconfig") + 1], str(lab.kubeconfig))
        self.assertEqual(command[command.index("--expect-cluster-uid") + 1], "synthetic-cluster-uid")
        self.assertEqual(command[command.index("--timeout") + 1], "240s")
        self.assertEqual(execute.call_args.kwargs["timeout"], 720)
        self.assertEqual(command.count("--instrumentation-values"), 1)
        self.assertNotIn(str(MODULE.ROOT / "scripts/instrumentation.py"), command)
        self.assertNotIn("synthetic-test-token", command)
        lab.verify_combined_installation.assert_called_once_with("synthetic-cluster-uid")
        for name in ("tenant.txt", "token.txt"):
            self.assertEqual((self.directory / name).stat().st_mode & 0o777, 0o600)
        return command

    def test_explicit_development_flag_is_forwarded_to_the_one_core_install(self):
        self.assertIn("--development-images", self.command(True))

    def test_production_does_not_silently_add_the_development_flag(self):
        self.assertNotIn("--development-images", self.command(False))

    def test_failed_unified_install_does_not_verify_or_mark_single_command_success(self):
        lab = self.laboratory(True)
        with mock.patch.object(MODULE.CORE, "execute", side_effect=RuntimeError("synthetic install failure")):
            with self.assertRaisesRegex(RuntimeError, "install failure"):
                lab.install_gateway(self.directory / "operator-values.yaml")
        lab.verify_combined_installation.assert_not_called()
        lab.check.assert_not_called()
        self.assertNotIn("single_command_installation", lab.report)

    def test_post_install_identity_failure_cannot_emit_a_success_check(self):
        lab = self.laboratory(True)
        lab.verify_combined_installation.side_effect = AssertionError("synthetic receipt mismatch")
        with mock.patch.object(MODULE.CORE, "execute", return_value=SimpleNamespace(stdout="")):
            with self.assertRaisesRegex(AssertionError, "receipt mismatch"):
                lab.install_gateway(self.directory / "operator-values.yaml")
        lab.check.assert_not_called()
        self.assertNotIn("single_command_installation", lab.report)


class CombinedAPIIdentityTests(unittest.TestCase):
    """API metadata fixtures are not cryptographic certificate or registry proof."""

    def setUp(self):
        self.lab = MODULE.InstrumentationLab.__new__(MODULE.InstrumentationLab)
        self.lab.namespace, self.lab.app_namespace = "elven-unit", "synthetic-app"
        self.lab.operator_release, self.lab.development_images = "elven-injector", False
        self.lab.report = {}
        self.cluster_uid = "synthetic-cluster-uid"
        ca, certificate = b"synthetic public CA metadata", b"synthetic client certificate metadata"
        encoded = lambda value: base64.b64encode(value).decode()

        def owned(release, uid):
            return {"uid": uid, "labels": {"app.kubernetes.io/managed-by": "Helm",
                "app.kubernetes.io/part-of": "elven-observability"}, "annotations": {
                "meta.helm.sh/release-name": release, "meta.helm.sh/release-namespace": self.lab.namespace}}

        def core_secret(uid, data):
            return {"metadata": {"uid": uid, "labels": {"app.kubernetes.io/managed-by": "elven-cli",
                "app.kubernetes.io/instance": "elven-a", "elven.observability/namespace": self.lab.namespace}},
                "data": {key: encoded(value) for key, value in data.items()}}

        receipt = {"schemaVersion": 1, "phase": "bound", "release": "elven-a", "namespace": self.lab.namespace,
            "clusterUID": self.cluster_uid, "clusterName": "synthetic-kind", "credentialsSecret": "elven-a-ingest",
            "credentialsSecretUID": "ingest-uid", "tenantSHA256": hashlib.sha256(b"synthetic-tenant").hexdigest(),
            "pvcUID": "pvc-uid", "statefulSetUID": "sts-uid"}
        objects = {
            "pvc/data-elven-a-gateway-0": {"metadata": {"uid": "pvc-uid", "annotations": {
                "elven.observability/storage-identity": json.dumps(receipt)}}},
            "statefulset/elven-a-gateway": {"metadata": owned("elven-a", "sts-uid")},
            "secret/elven-a-ingest": core_secret("ingest-uid", {"tenant-id": b"synthetic-tenant", "api-token": b"synthetic-token"}),
            "secret/elven-a-internal-tls": core_secret("tls-uid", {"ca.crt": ca, "client.crt": certificate,
                "client.key": b"synthetic source key", "tls.crt": b"synthetic server certificate", "tls.key": b"synthetic server key"}),
            "configmap/elven-a-settings": {"metadata": owned("elven-a", "core-settings-uid"), "data": {"settings.json": json.dumps({
                "tls": {"existingSecret": "elven-a-internal-tls"}, "credentials": {"existingSecret": "elven-a-ingest"}})}},
            "configmap/elven-injector-settings": {"metadata": owned(self.lab.operator_release, "operator-settings-uid"),
                "data": {"settings.json": json.dumps({"gateway": {"sourceRelease": "elven-a", "sourceNamespace": self.lab.namespace,
                    "endpoint": f"https://elven-a-gateway.{self.lab.namespace}.svc.cluster.local:4318"}, "namespaces": [self.lab.app_namespace]})}},
            "secret/elven-instrumentation-tls": {"metadata": {"labels": {"app.kubernetes.io/managed-by": "elven-instrumentation-cli",
                "app.kubernetes.io/instance": self.lab.operator_release, "elven.observability/namespace": self.lab.namespace},
                "annotations": {"elven.observability/cluster-uid": self.cluster_uid, "elven.observability/tls-role": "client",
                    "elven.observability/source-ca-sha256": hashlib.sha256(ca).hexdigest()}},
                "data": {"ca.crt": encoded(ca), "client.crt": encoded(certificate),
                    "client.key": encoded(b"-----BEGIN PRIVATE KEY-----\nsynthetic PKCS8 marker fixture only\n")}},
        }
        self.original = objects
        self.objects = copy.deepcopy(objects)

        def get(*args, **kwargs):
            self.assertEqual(args[0], "get")
            namespace = args[args.index("-n") + 1]
            self.assertEqual(namespace, self.lab.app_namespace if args[1] == "secret/elven-instrumentation-tls" else self.lab.namespace)
            return SimpleNamespace(stdout=json.dumps(self.objects[args[1]]))

        self.lab.kube = mock.Mock(side_effect=get)

    def test_consistent_fixture_metadata_records_success_only_after_all_seven_reads(self):
        self.lab.verify_combined_installation(self.cluster_uid)
        self.assertEqual(self.lab.kube.call_count, 7)
        self.assertEqual(self.lab.report["single_command_installation"], {"cli_install_invocations": 1,
            "development_images": False, "core_release": "elven-a", "operator_release": "elven-injector",
            "bound_pvc_receipt": True, "owned_core_pki": True, "scoped_client_pki": True, "source_ownership": True})

    def test_invalid_receipt_ownership_or_scoped_client_material_never_records_success(self):
        for case in ("receipt-tenant", "foreign-helm", "foreign-core-secret", "ingest-in-client", "wrong-ca", "non-pkcs8"):
            self.objects = copy.deepcopy(self.original)
            self.lab.report = {}
            if case == "receipt-tenant":
                annotations = self.objects["pvc/data-elven-a-gateway-0"]["metadata"]["annotations"]
                receipt = json.loads(annotations["elven.observability/storage-identity"])
                receipt["tenantSHA256"] = "f" * 64
                annotations["elven.observability/storage-identity"] = json.dumps(receipt)
            elif case == "foreign-helm":
                self.objects["statefulset/elven-a-gateway"]["metadata"]["annotations"]["meta.helm.sh/release-name"] = "foreign-release"
            elif case == "foreign-core-secret":
                self.objects["secret/elven-a-ingest"]["metadata"]["labels"]["app.kubernetes.io/managed-by"] = "foreign-owner"
            else:
                data = self.objects["secret/elven-instrumentation-tls"]["data"]
                key, value = {"ingest-in-client": ("api-token", b"synthetic-ingestion-material"),
                    "wrong-ca": ("ca.crt", b"foreign CA metadata"),
                    "non-pkcs8": ("client.key", b"-----BEGIN RSA PRIVATE KEY-----\nsynthetic marker only\n")}[case]
                data[key] = base64.b64encode(value).decode()
            with self.subTest(case=case), self.assertRaises(AssertionError):
                self.lab.verify_combined_installation(self.cluster_uid)
            self.assertNotIn("single_command_installation", self.lab.report)


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
