"""Stdlib instrumentation CLI boundaries; no customer Kubernetes access."""
from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("instrumentation_cli_under_test", ROOT / "scripts/instrumentation.py")
cli = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cli)
UID = "00000000-0000-4000-8000-000000000001"
PRIVATE = "SYNTHETIC_PRIVATE_VALUE_MUST_NEVER_APPEAR_IN_ARGV_OR_ERRORS"


def arguments(**changes):
    values = dict(command="install", release="elven-operator", namespace="elven-observability",
                  context="synthetic-only", kubeconfig="/synthetic/never-read", expect_cluster_uid=UID,
                  cluster_uid=UID, values=[], render_kube_version="1.37.0", development_images=True,
                  timeout="3m", output=None)
    return argparse.Namespace(**{**values, **changes})


def settings():
    return {"enabled": True, "namespaces": ["elven-synthetic-app"], "clusterDomain": "cluster.local",
            "gateway": {"endpoint": "https://elven-gateway.elven-observability.svc.cluster.local:4318",
                        "sourceRelease": "elven", "sourceNamespace": "elven-observability"},
            "webhook": {"existingSecret": "elven-operator-webhook-tls", "caBundle": "", "port": 9443,
                        "servicePort": 443, "timeoutSeconds": 3},
            "clientTLS": {"secretName": "elven-instrumentation-tls"},
            "images": {name: {"repository": "docker.io/elvenobservability/" + repo,
                              "tag": "1.0.0-dev", "digest": "sha256:" + "a" * 64}
                       for name, repo in cli.IMAGE_REPOS.items()},
            "runtimes": {"java": True, "nodejs": True, "python": False, "nodejs20": False,
                         "legacyNode20Approved": False},
            "samplingRatio": "1", "sdkVolumeSizeMiB": 128,
            "networkPolicy": {"enabled": True, "apiServerCIDRs": ["192.0.2.10/32"]}}


def encoded(values, labels=None, annotations=None):
    return {"metadata": {"labels": labels or {}, "annotations": annotations or {}, "uid": "synthetic-secret-uid"},
            "data": {key: base64.b64encode(value.encode()).decode() for key, value in values.items()}}


def owned(args, values=None, release=None, namespace=None):
    return {"metadata": {"labels": {"app.kubernetes.io/managed-by": "Helm", "app.kubernetes.io/part-of": "elven-observability",
                                   "app.kubernetes.io/name": "elven-observability" if release == "elven" else "elven-instrumentation-operator"}, "annotations": {
                "meta.helm.sh/release-name": release or args.release,
                "meta.helm.sh/release-namespace": namespace or args.namespace}},
            "data": {"settings.json": json.dumps(values or {})}}


class ConfigurationTests(unittest.TestCase):
    def test_safe_values_pass_and_disabled_render_does_not_require_images(self):
        cli.validate_settings(settings(), "elven-observability")
        cli.validate_settings({"enabled": False}, "elven-observability")

    def test_namespace_endpoint_network_and_runtime_negatives(self):
        changes = [
            ("namespaces", []), ("namespaces", ["kube-system"]),
            ("namespaces", ["elven-observability"]), ("namespaces", ["elven-app", "elven-app"]),
            ("namespaces", ["INVALID"]),
        ]
        for key, value in changes:
            current = settings(); current[key] = value
            with self.subTest(value=value), self.assertRaises(cli.Failure):
                cli.validate_settings(current, "elven-observability")
        for endpoint in ("http://elven.invalid", "https://localhost:4318", "https://127.0.0.1:4318",
                         "https://u:p@elven.invalid", "https://elven.invalid/v1/traces",
                         "https://elven.invalid?token=x", "https://elven.invalid#x", "https://elven.invalid:99999"):
            current = settings(); current["gateway"]["endpoint"] = endpoint
            with self.subTest(endpoint=endpoint), self.assertRaises(cli.Failure):
                cli.validate_settings(current, "elven-observability")
        for cidrs in ([], ["0.0.0.0/0"], ["::/0"], ["192.0.2.1/24"], ["invalid"]):
            current = settings(); current["networkPolicy"]["apiServerCIDRs"] = cidrs
            with self.subTest(cidrs=cidrs), self.assertRaises(cli.Failure):
                cli.validate_settings(current, "elven-observability")
        current = settings(); current["networkPolicy"]["enabled"] = False
        with self.assertRaises(cli.Failure): cli.validate_settings(current, "elven-observability")
        current = settings(); current["runtimes"]["nodejs20"] = True
        with self.assertRaisesRegex(cli.Failure, "EOL"): cli.validate_settings(current, "elven-observability")

    def test_images_are_matching_elven_repositories_and_immutable(self):
        for changes in ({"repository": "docker.io/another/vendor"}, {"tag": "latest"},
                        {"digest": ""}, {"tag": "bad tag"}, {"digest": "sha256:abc"}):
            current = settings(); current["images"]["java"].update(changes)
            with self.subTest(changes=changes), self.assertRaises(cli.Failure):
                cli.validate_settings(current, "elven-observability")

    def test_publication_gate_validates_every_selected_runtime(self):
        current = settings()
        with tempfile.TemporaryDirectory() as folder:
            lock = Path(folder) / "lock.json"
            payload = {"schemaVersion": 1, "distribution": {"publicationStatus": "verified"}, "images": {
                name: {"distribution": {"repository": image["repository"], "digest": image["digest"], "status": "verified"}}
                for name, image in current["images"].items()}}
            lock.write_text(json.dumps(payload))
            with mock.patch.object(cli, "LOCK", lock):
                cli.require_images(current)
                payload["images"]["java"]["distribution"]["digest"] = "sha256:" + "b" * 64
                lock.write_text(json.dumps(payload))
                with self.assertRaises(cli.Failure): cli.require_images(current)
                cli.require_images(current, development=True)
                payload["distribution"]["publicationStatus"] = "not-published"
                lock.write_text(json.dumps(payload))
                with self.assertRaises(cli.Failure): cli.require_images(current)
                lock.unlink()
                with self.assertRaises(cli.Failure): cli.require_images(current)

    def test_long_names_are_deterministic_and_global_names_namespace_isolated(self):
        release = "elven-" + "a" * 44
        self.assertEqual(len(cli.fullname(release)), 44)
        self.assertEqual(cli.fullname(release), cli.fullname(release))
        self.assertNotEqual(cli.global_name(arguments(namespace="elven-a")), cli.global_name(arguments(namespace="elven-b")))


class ProcessBoundaries(unittest.TestCase):
    def test_offline_render_is_private_no_overwrite_and_never_touches_cluster_or_crypto(self):
        with tempfile.TemporaryDirectory(prefix="elven-instrumentation-render-test-") as temporary:
            folder = Path(temporary)
            values = folder / "synthetic-values.json"
            values.write_text(json.dumps(settings()))
            output = folder / "reviewed.yaml"
            with mock.patch.object(cli, "kube") as kube, mock.patch.object(cli, "generate_serving") as generate, \
                 contextlib.redirect_stdout(io.StringIO()):
                cli.main(["render", "--values", str(values), "--output", str(output)])
                with self.assertRaises(FileExistsError):
                    cli.main(["render", "--values", str(values), "--output", str(output)])
            kube.assert_not_called(); generate.assert_not_called()
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            manifest = output.read_text()
            self.assertIn("kind: MutatingWebhookConfiguration", manifest)
            self.assertNotIn("kind: Secret", manifest)
            self.assertNotIn("PRIVATE KEY", manifest)
            self.assertIn("elven.observability/inject", manifest)

    def test_uninstall_uses_owned_installed_settings_not_current_lock_values_or_crypto(self):
        args = arguments()
        def read(_args, kind, name, namespace=None):
            if kind == "namespace": return {"metadata": {"uid": UID}}
            if kind == "configmap": return owned(args, settings())
            raise AssertionError("Recovery must not read Secrets or source gateway material")
        def helm_reply(_args, *command, **kwargs):
            return json.dumps([{"name": args.release, "chart": "elven-instrumentation-1.0.0-rc.1"}]) if command[0] == "list" else ""
        with mock.patch.object(cli, "programs", return_value=4), \
             mock.patch.object(cli, "get_object", side_effect=read), \
             mock.patch.object(cli, "helm", side_effect=helm_reply) as helm, \
             mock.patch.object(cli, "preflight") as preflight, mock.patch.object(cli, "require_images") as images, \
             mock.patch.object(cli, "generate_serving") as generate, contextlib.redirect_stdout(io.StringIO()):
            cli.main(["uninstall", "--context", "synthetic-only", "--expect-cluster-uid", UID])
        preflight.assert_not_called(); images.assert_not_called(); generate.assert_not_called()
        self.assertEqual(helm.call_args.args[1:3], ("uninstall", "elven-operator"))
        self.assertTrue(helm.call_args.kwargs["online"])

    def test_recovery_refuses_another_chart_even_with_a_forged_owned_settings_configmap(self):
        args = arguments()
        with mock.patch.object(cli, "get_object", return_value=owned(args, settings())), \
             mock.patch.object(cli, "helm", return_value=json.dumps([{"name": args.release, "chart": "other-chart-1.0.0"}])):
            with self.assertRaisesRegex(cli.Failure, "another chart"):
                cli.owned_settings(args)

    def test_install_passes_only_public_ca_to_helm_and_creates_only_planned_secrets(self):
        args = arguments()
        current = settings()
        private = {"ca.crt": "synthetic-public-ca", "tls.crt": "synthetic-public-cert", "tls.key": PRIVATE}
        plan = {"namespace_exists": True, "serving": None, "missing_clients": ["elven-synthetic-app"],
                "client": {"ca.crt": "synthetic-source-ca", "client.crt": "synthetic-client", "client.key": PRIVATE},
                "fingerprint": "a" * 64}
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(cli, "generate_serving", return_value=private), \
             mock.patch.object(cli, "render", return_value=("", {}, ["--namespace", args.namespace])) as render, \
             mock.patch.object(cli, "create_secret") as create, mock.patch.object(cli, "helm", return_value="") as helm, \
             contextlib.redirect_stdout(io.StringIO()):
            cli.install(args, current, plan, Path(temporary), 4)
        override = render.call_args.args[2]
        self.assertEqual(override, {"webhook": {"caBundle": base64.b64encode(private["ca.crt"].encode()).decode()}})
        self.assertNotIn(PRIVATE, json.dumps(override))
        self.assertEqual(create.call_count, 2)
        self.assertEqual(create.call_args_list[1].args[1:3], ("elven-synthetic-app", "elven-instrumentation-tls"))
        self.assertNotIn(PRIVATE, str(helm.call_args))
        self.assertIn("--rollback-on-failure", helm.call_args.args)

    def test_process_errors_do_not_echo_private_payload_or_provider_output(self):
        failed = subprocess.CompletedProcess([], 1, PRIVATE, PRIVATE)
        with mock.patch.object(cli.subprocess, "run", return_value=failed) as process:
            with self.assertRaises(cli.Failure) as error:
                cli.run(["kubectl", "create", "-f", "-"], PRIVATE)
        self.assertNotIn(PRIVATE, str(error.exception))
        self.assertEqual(process.call_args.kwargs["input"], PRIVATE)
        self.assertNotIn(PRIVATE, process.call_args.args[0])

    def test_timeout_does_not_echo_partial_private_stdout_or_stderr(self):
        failure = subprocess.TimeoutExpired(["kubectl", "get"], 120, output=PRIVATE, stderr=PRIVATE)
        with mock.patch.object(cli.subprocess, "run", side_effect=failure) as process:
            with self.assertRaisesRegex(cli.Failure, "bounded timeout") as error:
                cli.run(["kubectl", "get", "secret"], PRIVATE)
        self.assertNotIn(PRIVATE, str(error.exception))
        self.assertIsNone(error.exception.__cause__)
        self.assertEqual(process.call_args.kwargs["timeout"], 120)

    def test_helm_rollout_deadline_respects_bounded_user_timeout(self):
        args = arguments(timeout="15m")
        with mock.patch.object(cli, "run", return_value="") as process:
            cli.helm(args, "upgrade", "--install", args.release, online=True)
            self.assertEqual(process.call_args.kwargs["timeout"], 990)
            cli.helm(args, "template", args.release)
            self.assertEqual(process.call_args.kwargs["timeout"], 120)
        for duration in ("0s", "2h", "99999h", "abc"):
            with self.subTest(duration=duration), self.assertRaises(cli.Failure):
                cli.duration_seconds(duration)
        self.assertEqual(cli.duration_seconds("1h"), 3600)

    def test_context_is_explicit_and_kubeconfig_forwarded(self):
        with mock.patch.object(cli, "run", return_value="ok") as process:
            cli.kube(arguments(), "get", "pods")
        self.assertEqual(process.call_args.args[0][:5], ["kubectl", "--kubeconfig", "/synthetic/never-read", "--context", "synthetic-only"])
        self.assertIn("--request-timeout=30s", process.call_args.args[0])
        with self.assertRaises(cli.Failure): cli.kube(arguments(context=None), "get", "pods")

    def test_uid_guard_is_read_only_and_requires_confirmation_before_writes(self):
        with mock.patch.object(cli, "get_object", return_value={"metadata": {"uid": UID}}):
            with self.assertRaises(cli.Failure): cli.cluster_identity(arguments(expect_cluster_uid=None), True)
            with self.assertRaises(cli.Failure): cli.cluster_identity(arguments(expect_cluster_uid="wrong"), True)
            self.assertEqual(cli.cluster_identity(arguments(), True), UID)

    def test_secret_create_uses_stdin_only_and_never_includes_server_or_backend_keys(self):
        args = arguments()
        values = {"ca.crt": "public-ca", "client.crt": "public-cert", "client.key": PRIVATE}
        with mock.patch.object(cli, "kube", return_value="") as process:
            cli.create_secret(args, "elven-app", "elven-client-tls", values, "client", "a" * 64)
        self.assertEqual(process.call_args.args[1:], ("create", "-f", "-"))
        obj = json.loads(process.call_args.kwargs["data"])
        self.assertEqual(set(obj["data"]), {"ca.crt", "client.crt", "client.key"})
        self.assertNotIn(PRIVATE, str(process.call_args.args))
        self.assertNotIn("tls.key", obj["data"])
        self.assertNotIn("api-token", obj["data"])

    def test_secret_owner_rejects_foreign_and_trust_changed_material(self):
        args = arguments()
        annotation = {cli.LABEL_PREFIX + "cluster-uid": UID, cli.LABEL_PREFIX + "source-ca-sha256": "a" * 64,
                      cli.LABEL_PREFIX + "tls-role": "client"}
        secret = encoded({"client.key": PRIVATE}, cli.secret_labels(args), annotation)
        cli.require_secret_owner(args, secret, "client", "a" * 64)
        for key, value in (("owner", "foreign"), ("fingerprint", "b" * 64), ("role", "server")):
            current = copy.deepcopy(secret)
            if key == "owner": current["metadata"]["labels"]["app.kubernetes.io/managed-by"] = value
            elif key == "fingerprint": current["metadata"]["annotations"][cli.LABEL_PREFIX + "source-ca-sha256"] = value
            else: current["metadata"]["annotations"][cli.LABEL_PREFIX + "tls-role"] = value
            with self.subTest(key=key), self.assertRaises(cli.Failure):
                cli.require_secret_owner(args, current, "client", "a" * 64)


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.args = arguments()
        self.current = settings()
        self.client = {"ca.crt": "synthetic-ca", "client.crt": "synthetic-cert", "client.key": "synthetic-pkcs8"}
        self.source = {"cluster": {"domain": "cluster.local"}, "ports": {"otlpHttp": 4318},
                       "networkPolicy": {"enabled": True}, "collection": {"namespaces": ["elven-synthetic-app"]},
                       "tls": {"existingSecret": "elven-internal-tls"}}
        source_labels = {"app.kubernetes.io/managed-by": "elven-cli", "app.kubernetes.io/instance": "elven",
                         "app.kubernetes.io/part-of": "elven-observability", cli.LABEL_PREFIX + "namespace": self.args.namespace}
        self.objects = {
            ("namespace", "kube-system", None): {"metadata": {"uid": UID}},
            ("namespace", self.args.namespace, None): {"metadata": {"name": self.args.namespace}},
            ("namespace", "elven-synthetic-app", None): {"metadata": {"name": "elven-synthetic-app"}},
            ("configmap", "elven-settings", self.args.namespace): owned(self.args, self.source, "elven", self.args.namespace),
            ("secret", "elven-internal-tls", self.args.namespace): encoded(self.client, source_labels),
        }
        self.stack = mock.patch.object(cli, "get_object", side_effect=lambda _args, kind, name, namespace=None: self.objects.get((kind, name, namespace)))
        self.stack.start(); self.addCleanup(self.stack.stop)
        def kube_reply(_args, *command, **kwargs):
            if command[:2] == ("get", "mutatingwebhookconfigurations.admissionregistration.k8s.io"):
                return json.dumps({"items": []})
            if command == ("version", "-o", "json"):
                return json.dumps({"serverVersion": {"gitVersion": "v1.37.0"}})
            raise AssertionError("Unexpected kubectl command in read-only preflight")
        for target, replacement in (("require_images", mock.Mock()), ("client_material", mock.Mock(return_value=self.client)),
                                    ("helm", mock.Mock(return_value="[]")),
                                    ("can_i", mock.Mock()), ("kube", mock.Mock(side_effect=kube_reply))):
            patcher = mock.patch.object(cli, target, replacement); patcher.start(); self.addCleanup(patcher.stop)

    def test_fresh_preflight_is_read_only_and_plans_only_namespaced_secrets(self):
        with mock.patch.object(cli, "generate_serving") as generate, mock.patch.object(cli, "create_secret") as create:
            plan = cli.preflight(self.args, self.current, self.folder)
        generate.assert_not_called(); create.assert_not_called()
        self.assertIsNone(plan["serving"])
        self.assertEqual(plan["missing_clients"], ["elven-synthetic-app"])

    def test_foreign_resource_is_rejected_before_crypto_or_writes(self):
        self.objects[("service", "elven-operator-webhook", self.args.namespace)] = {"metadata": {"labels": {"owner": "foreign"}}}
        with mock.patch.object(cli, "create_secret") as create, self.assertRaisesRegex(cli.Failure, "another owner"):
            cli.preflight(self.args, self.current, self.folder)
        create.assert_not_called()

    def test_foreign_helm_chart_and_forged_matching_release_annotations_are_rejected(self):
        with mock.patch.object(cli, "helm", return_value=json.dumps([{"name": self.args.release, "chart": "other-chart-1.0.0"}])):
            with self.assertRaisesRegex(cli.Failure, "another chart"):
                cli.preflight(self.args, self.current, self.folder)
        foreign = owned(self.args)
        foreign["metadata"]["labels"]["app.kubernetes.io/name"] = "other-chart"
        self.objects[("configmap", "elven-operator-settings", self.args.namespace)] = foreign
        with self.assertRaisesRegex(cli.Failure, "another owner"):
            cli.preflight(self.args, self.current, self.folder)
        with self.assertRaisesRegex(cli.Failure, "refusing recovery"):
            cli.owned_settings(self.args)

    def test_gateway_identity_scope_and_source_owner_are_checked(self):
        for defect in ("endpoint", "scope", "source-owner", "app-secret-owner"):
            current = copy.deepcopy(self.current)
            source_snapshot = copy.deepcopy(self.objects)
            if defect == "endpoint": current["gateway"]["endpoint"] = "https://other.elven.invalid:4318"
            elif defect == "scope":
                self.objects[("configmap", "elven-settings", self.args.namespace)]["data"]["settings.json"] = json.dumps({**self.source, "collection": {"namespaces": []}})
            elif defect == "source-owner": self.objects[("secret", "elven-internal-tls", self.args.namespace)]["metadata"]["labels"] = {}
            else: self.objects[("secret", "elven-instrumentation-tls", "elven-synthetic-app")] = encoded(self.client)
            with self.subTest(defect=defect), self.assertRaises(cli.Failure):
                cli.preflight(self.args, current, self.folder)
            self.objects = source_snapshot

    def test_supplied_ca_cannot_silently_be_replaced_during_bootstrap(self):
        self.current["webhook"]["caBundle"] = base64.b64encode(b"untrusted synthetic CA").decode()
        with self.assertRaisesRegex(cli.Failure, "already provisioned"):
            cli.preflight(self.args, self.current, self.folder)

    def test_overlap_claims_are_rejected_and_disjoint_namespaces_are_allowed(self):
        def claim(namespaces, runtimes):
            return {"metadata": {"name": "another-elven-operator"}, "webhooks": [{
                "namespaceSelector": {"matchExpressions": [{"key": "kubernetes.io/metadata.name", "operator": "In", "values": namespaces}]},
                "objectSelector": {"matchExpressions": [{"key": "elven.observability/inject", "operator": "In", "values": runtimes}]}}]}
        for other, rejected in ((claim(["elven-synthetic-app"], ["java"]), True),
                                (claim(["elven-other-app"], ["java"]), False),
                                (claim(["elven-synthetic-app"], ["python"]), True),
                                ({"metadata": {"name": "unscoped-legacy-elven"}, "webhooks": [{}]}, True)):
            with self.subTest(rejected=rejected), mock.patch.object(cli, "kube", return_value=json.dumps({"items": [other]})):
                if rejected:
                    with self.assertRaisesRegex(cli.Failure, "overlapping"):
                        cli.check_injection_claims(self.args, self.current)
                else:
                    cli.check_injection_claims(self.args, self.current)

    def test_missing_claim_discovery_is_unknown_not_empty(self):
        with mock.patch.object(cli, "kube", return_value="{}"), self.assertRaisesRegex(cli.Failure, "Cannot inspect"):
            cli.check_injection_claims(self.args, self.current)

    def test_namespace_wide_instrumentation_is_rejected_without_mutating_annotations(self):
        namespace = self.objects[("namespace", "elven-synthetic-app", None)]
        annotation = "instrumentation.opentelemetry.io/inject-java"
        for value in ("true", "another-namespace/agent", "false", ""):
            namespace["metadata"]["annotations"] = {annotation: value}
            with self.subTest(value=value):
                if value != "false":
                    with self.assertRaisesRegex(cli.Failure, "namespace-wide instrumentation"):
                        cli.preflight(self.args, self.current, self.folder)
                else:
                    cli.preflight(self.args, self.current, self.folder)
            self.assertEqual(namespace["metadata"]["annotations"], {annotation: value})

    def test_known_namespace_injector_labels_and_annotations_block_all_secret_writes(self):
        namespace = self.objects[("namespace", "elven-synthetic-app", None)]
        keys = ("instrumentation.opentelemetry.io/inject-nodejs", "admission.datadoghq.com/enabled",
                "admission.datadoghq.com/java-lib.version", "oneagent.dynatrace.com/inject",
                "oneagent.dynatrace.com/injected", "dynatrace.com/inject", "instrumentation.newrelic.com/inject",
                "newrelic.io/inject", "newrelic.com/inject", "newrelic.com/instrumentation",
                "newrelic-k8s-agents-operator-version", "newrelic-k8s-agents-operator-txid", "appdynamics.com/inject")
        for field in ("annotations", "labels"):
            for key in keys:
                namespace["metadata"].pop("annotations", None)
                namespace["metadata"].pop("labels", None)
                namespace["metadata"][field] = {key: "active-synthetic-version"}
                before = copy.deepcopy(namespace)
                with self.subTest(field=field, key=key), mock.patch.object(cli, "create_secret") as create, \
                     mock.patch.object(cli, "generate_serving") as generate, self.assertRaisesRegex(cli.Failure, "namespace-wide instrumentation"):
                    cli.preflight(self.args, self.current, self.folder)
                create.assert_not_called(); generate.assert_not_called()
                self.assertEqual(namespace, before)
                namespace["metadata"][field][key] = "false"
                cli.check_namespace_instrumentation(namespace)
                namespace["metadata"][field][key] = ""
                with self.assertRaises(cli.Failure): cli.check_namespace_instrumentation(namespace)

    def test_unknown_namespace_metadata_type_fails_closed(self):
        for field in ("labels", "annotations"):
            with self.subTest(field=field), self.assertRaises(cli.Failure):
                cli.check_namespace_instrumentation({"metadata": {field: ["not-a-map"]}})


@unittest.skipUnless(__import__("shutil").which("openssl"), "OpenSSL is required for real synthetic PKI tests")
class RealPKITests(unittest.TestCase):
    def test_real_serving_chain_san_key_pair_and_pkcs8_client(self):
        with tempfile.TemporaryDirectory(prefix="elven-instrumentation-pki-test-") as temporary:
            folder = Path(temporary)
            args = arguments()
            current = settings()
            values = cli.generate_serving(args, current, folder / "serving")
            self.assertEqual(set(values), {"ca.crt", "tls.crt", "tls.key"})
            with self.assertRaises(cli.Failure):
                cli.validate_material(values, folder / "wrong-host", "server", "wrong.elven.invalid")
            # Create a synthetic SEC1 key and proper clientAuth certificate under
            # the ephemeral test CA. Conversion must retain the matching key.
            source = folder / "serving"
            cli.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", source / "client.key"])
            cli.run(["openssl", "req", "-new", "-key", source / "client.key", "-subj", "/CN=Elven synthetic client", "-out", source / "client.csr"])
            (source / "client.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyAgreement\nextendedKeyUsage=clientAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
            cli.run(["openssl", "x509", "-req", "-in", source / "client.csr", "-CA", source / "ca.crt", "-CAkey", source / "ca.key", "-CAcreateserial", "-days", "2", "-extfile", source / "client.ext", "-out", source / "client.crt"])
            original = {key: (source / key).read_text() for key in ("ca.crt", "client.crt", "client.key")}
            self.assertIn("EC PRIVATE KEY", original["client.key"])
            converted = cli.client_material(encoded(original), folder / "converted")
            self.assertTrue(converted["client.key"].startswith("-----BEGIN PRIVATE KEY-----"))
            self.assertNotIn("tls.key", converted)
            cli.validate_material(converted, folder / "validated-client", "client")
            wrong_purpose = {"ca.crt": values["ca.crt"], "client.crt": values["tls.crt"], "client.key": values["tls.key"]}
            with self.assertRaises(cli.Failure): cli.client_material(encoded(wrong_purpose), folder / "wrong-purpose")


if __name__ == "__main__":
    unittest.main(verbosity=2)
