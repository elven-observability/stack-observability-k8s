"""Offline contracts for the optional Elven admission module; no cluster access."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "charts/elven-instrumentation"


def enabled_values():
    """Synthetic references only: these images are not claimed to exist remotely."""
    return {
        "enabled": True,
        "namespaces": ["elven-synthetic-app"],
        "webhook": {"caBundle": "c3ludGhldGljLXRlc3QtY2E="},
        "networkPolicy": {"apiServerCIDRs": ["192.0.2.10/32"]},
        "images": {name: {"digest": "sha256:" + "1" * 64} for name in ("operator", "java", "nodejs", "python", "nodejs20")},
    }


def render(values=None, release="elven-operator", namespace="elven-observability", version="1.37.0", check=True):
    with tempfile.TemporaryDirectory(prefix="elven-instrumentation-chart-") as folder:
        source = Path(folder) / "values.yaml"
        source.write_text(yaml.safe_dump(values or {}))
        result = subprocess.run(["helm", "template", release, str(CHART), "--namespace", namespace,
                                 "--kube-version", version, "--values", str(source)], text=True, capture_output=True)
    if check and result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    return result


def objects(values=None, **kwargs):
    return [obj for obj in yaml.safe_load_all(render(values, **kwargs).stdout) if obj]


def by_kind(rendered, kind):
    return next(obj for obj in rendered if obj["kind"] == kind)


class InstrumentationChartTests(unittest.TestCase):
    def test_defaults_are_disabled_without_cluster_global_side_effects(self):
        rendered = objects()
        self.assertEqual([obj["kind"] for obj in rendered], ["ConfigMap"])
        settings = json.loads(rendered[0]["data"]["settings.json"])
        self.assertFalse(settings["enabled"])
        self.assertEqual(settings["namespaces"], [])
        self.assertTrue(all(not image["digest"] for image in settings["images"].values()))

    def test_lint_and_supported_minor_matrix(self):
        result = subprocess.run(["helm", "lint", str(CHART), "--strict", "--kube-version", "1.37.0"], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for version in ("1.35.0", "1.36.0", "1.37.0"):
            with self.subTest(version=version):
                self.assertEqual(len(objects(enabled_values(), version=version)), 7)
        self.assertNotEqual(render(version="1.34.9", check=False).returncode, 0)

    def test_no_secret_crd_controllers_or_runtime_rbac(self):
        rendered = objects(enabled_values())
        kinds = {obj["kind"] for obj in rendered}
        self.assertEqual(kinds, {"ConfigMap", "ServiceAccount", "Deployment", "Service", "MutatingWebhookConfiguration", "NetworkPolicy"})
        self.assertFalse(kinds & {"Secret", "Namespace", "CustomResourceDefinition", "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"})
        service_account = by_kind(rendered, "ServiceAccount")
        self.assertFalse(service_account["automountServiceAccountToken"])

    def test_hardened_non_root_operator_has_no_host_or_api_access(self):
        pod = by_kind(objects(enabled_values()), "Deployment")["spec"]["template"]["spec"]
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertFalse(pod["enableServiceLinks"])
        self.assertFalse(pod.get("hostNetwork", False))
        self.assertFalse(pod.get("hostPID", False))
        self.assertFalse(any("hostPath" in volume for volume in pod["volumes"]))
        container = pod["containers"][0]
        security = container["securityContext"]
        self.assertTrue(security["runAsNonRoot"])
        self.assertEqual(security["runAsUser"], 10001)
        self.assertTrue(security["readOnlyRootFilesystem"])
        self.assertFalse(security["allowPrivilegeEscalation"])
        self.assertEqual(security["capabilities"], {"drop": ["ALL"]})
        self.assertEqual(security["seccompProfile"]["type"], "RuntimeDefault")
        self.assertNotIn("hostPort", container["ports"][0])
        self.assertTrue(container["image"].startswith("docker.io/elvenobservability/elven-instrumentation-operator:"))
        self.assertRegex(container["image"], r"@sha256:[a-f0-9]{64}$")
        self.assertEqual({item["key"] for item in pod["volumes"][0]["secret"]["items"]}, {"tls.crt", "tls.key"})

    def test_webhook_only_selects_approved_create_pods_with_explicit_runtime(self):
        webhook = by_kind(objects(enabled_values()), "MutatingWebhookConfiguration")["webhooks"][0]
        self.assertEqual(webhook["failurePolicy"], "Ignore")
        self.assertEqual(webhook["reinvocationPolicy"], "Never")
        self.assertEqual(webhook["sideEffects"], "None")
        self.assertEqual(webhook["timeoutSeconds"], 3)
        self.assertEqual(webhook["admissionReviewVersions"], ["v1"])
        self.assertEqual(webhook["rules"], [{"operations": ["CREATE"], "apiGroups": [""], "apiVersions": ["v1"], "resources": ["pods"], "scope": "Namespaced"}])
        namespaces = webhook["namespaceSelector"]["matchExpressions"]
        self.assertEqual(namespaces, [{"key": "kubernetes.io/metadata.name", "operator": "In", "values": ["elven-synthetic-app"]}])
        self.assertEqual(webhook["objectSelector"]["matchExpressions"], [
            {"key": "elven.observability/inject", "operator": "Exists"},
            {"key": "elven.observability/inject", "operator": "NotIn", "values": ["false"]},
        ])

    def test_operator_configuration_has_client_tls_reference_but_never_credentials(self):
        rendered = objects(enabled_values())
        config_obj = next(obj for obj in rendered if obj["kind"] == "ConfigMap" and "injection.json" in obj["data"])
        config = json.loads(config_obj["data"]["injection.json"])
        self.assertEqual(set(config), {"namespaces", "operatorNamespace", "endpoint", "tlsSecretName", "images", "samplingRatio", "sdkVolumeSizeMiB", "legacyNode20Approved"})
        self.assertEqual(config["tlsSecretName"], "elven-instrumentation-tls")
        self.assertTrue(config["endpoint"].startswith("https://"))
        self.assertEqual(set(config["images"]), {"java", "nodejs"})
        self.assertFalse(config["legacyNode20Approved"])
        for name, image in config["images"].items():
            self.assertTrue(image.startswith("docker.io/elvenobservability/elven-auto-" + name + ":"))
            self.assertRegex(image, r"@sha256:[a-f0-9]{64}$")
        self.assertNotIn("api-token", config_obj["data"]["injection.json"])
        self.assertNotIn("tenant", config_obj["data"]["injection.json"].lower())

    def test_ports_are_configurable_and_network_has_no_egress(self):
        values = enabled_values()
        values["webhook"].update(port=10443, servicePort=8443)
        rendered = objects(values)
        pod = by_kind(rendered, "Deployment")["spec"]["template"]["spec"]
        self.assertEqual(pod["containers"][0]["ports"][0]["containerPort"], 10443)
        self.assertEqual(by_kind(rendered, "Service")["spec"]["ports"][0]["port"], 8443)
        self.assertEqual(by_kind(rendered, "MutatingWebhookConfiguration")["webhooks"][0]["clientConfig"]["service"]["port"], 8443)
        policy = by_kind(rendered, "NetworkPolicy")["spec"]
        self.assertEqual(policy["egress"], [])
        self.assertEqual(policy["policyTypes"], ["Ingress", "Egress"])
        self.assertEqual(policy["ingress"][0]["from"], [{"ipBlock": {"cidr": "192.0.2.10/32"}}])
        self.assertEqual(policy["ingress"][0]["ports"], [{"protocol": "TCP", "port": 10443}])

    def test_global_webhook_names_do_not_collide_across_namespaces_and_releases(self):
        names = set()
        for release, namespace in (("elven-a", "elven-a"), ("elven-a", "elven-b"), ("elven-b", "elven-a")):
            rendered = objects(enabled_values(), release=release, namespace=namespace)
            names.add(by_kind(rendered, "MutatingWebhookConfiguration")["metadata"]["name"])
        self.assertEqual(len(names), 3)
        for obj in objects(enabled_values(), release="elven-" + "x" * 47):
            self.assertLessEqual(len(obj["metadata"]["name"]), 63)

    def test_node20_requires_explicit_legacy_approval_and_distinct_image_identity(self):
        values = enabled_values()
        values["runtimes"] = {"nodejs20": True}
        self.assertNotEqual(render(values, check=False).returncode, 0)
        values["runtimes"]["legacyNode20Approved"] = True
        rendered = objects(values)
        config = json.loads(next(obj for obj in rendered if obj["kind"] == "ConfigMap" and "injection.json" in obj["data"])["data"]["injection.json"])
        self.assertTrue(config["legacyNode20Approved"])
        self.assertIn("elven-auto-nodejs20:", config["images"]["nodejs20"])

    def test_rejects_unsafe_or_incomplete_enabled_configuration(self):
        cases = [
            {"enabled": True},
            {"namespaces": []}, {"namespaces": ["kube-system"]},
            {"namespaces": ["elven-observability"]}, {"namespaces": ["elven-app", "elven-app"]},
            {"gateway": {"endpoint": "http://elven-gateway:4318"}},
            {"gateway": {"endpoint": "https://user:password@elven-gateway:4318"}},
            {"gateway": {"endpoint": "https://elven-gateway:4318/v1/traces"}},
            {"gateway": {"endpoint": "https://elven-gateway:4318?token=secret"}},
            {"gateway": {"endpoint": "https://localhost:4318"}},
            {"gateway": {"endpoint": "https://[::1]:4318"}},
            {"networkPolicy": {"enabled": False}},
            {"networkPolicy": {"apiServerCIDRs": []}},
            {"networkPolicy": {"apiServerCIDRs": ["0.0.0.0/0"]}},
            {"images": {"java": {"digest": ""}}},
            {"images": {"operator": {"repository": "untrusted/operator"}}},
            {"images": {"nodejs": {"tag": "latest"}}},
            {"runtimes": {"java": False, "nodejs": False, "python": False, "nodejs20": False}},
            {"samplingRatio": "1.1"}, {"samplingRatio": "NaN"},
            {"sdkVolumeSizeMiB": 1}, {"webhook": {"port": 443}},
            {"podAnnotations": {"checksum/config": "untrusted"}},
            {"nodeSelector": {"kubernetes.io/os": "windows"}},
            {"unrecognized": True},
        ]
        for override in cases:
            with self.subTest(override=override):
                # The first case intentionally has no pins/scope. All other
                # overrides deep-merge onto the synthetic valid configuration.
                values = {} if override == {"enabled": True} else enabled_values()
                for key, value in override.items():
                    if isinstance(value, dict) and isinstance(values.get(key), dict):
                        for item_key, item in value.items():
                            if isinstance(item, dict) and isinstance(values[key].get(item_key), dict):
                                values[key][item_key].update(item)
                            else:
                                values[key][item_key] = item
                    else:
                        values[key] = copy.deepcopy(value)
                self.assertNotEqual(render(values, check=False).returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
