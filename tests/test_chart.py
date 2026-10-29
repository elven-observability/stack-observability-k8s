"""Chart contracts; rendered synthetic values only, never a kubeconfig."""
from __future__ import annotations

import copy
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "charts/elven-observability"
DEFAULTS = yaml.safe_load((CHART / "values.yaml").read_text())


def render(values=None, release="elven-test", namespace="elven-test", version="1.37.0", check=True):
    with tempfile.TemporaryDirectory(prefix="elven-render-") as directory:
        source = Path(directory) / "values.yaml"
        source.write_text(yaml.safe_dump(values or {}))
        result = subprocess.run(
            ["helm", "template", release, str(CHART), "--namespace", namespace,
             "--kube-version", version, "-f", str(source)], text=True, capture_output=True)
    if check and result.returncode:
        raise AssertionError("Synthetic chart render failed:\n" + result.stderr)
    return result


def objects(values=None, **kwargs):
    return [obj for obj in yaml.safe_load_all(render(values, **kwargs).stdout) if obj]


def podspec(obj):
    return obj.get("spec", {}).get("template", {}).get("spec")


def all_modules():
    return {
        "cluster": {"name": "synthetic-cluster"},
        "collection": {"namespaces": ["synthetic-app"]},
        "networkPolicy": {"exportCIDRs": ["192.0.2.10/32"], "apiServerCIDRs": ["192.0.2.11/32"],
                          "kubeletCIDRs": ["192.0.2.12/32"], "profileCIDRs": ["192.0.2.13/32"],
                          "profilePorts": [443, 8443]},
        "modules": {
            "logs": {"enabled": True, "hostAccessApproved": True},
            "clusterMetrics": {"enabled": True},
            "kubeletMetrics": {"enabled": True},
            "ebpf": {"enabled": True, "hostAccessApproved": True,
                     "workloads": [{"namespace": "synthetic-app", "deployment": "synthetic-http"}]},
            "profiles": {"enabled": True, "dataPolicyApproved": True, "targets": [{"name": "synthetic-pprof",
                "address": "pprof.example.invalid:8443", "scheme": "https",
                "path": "/debug/pprof", "secretName": "synthetic-pprof-client"}]},
        },
    }


class ChartTests(unittest.TestCase):
    def test_lint(self):
        result = subprocess.run(["helm", "lint", str(CHART), "--strict", "--kube-version", "1.37.0"],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_supported_kubernetes_render_matrix_and_rejected_versions(self):
        for version in ("1.35.0", "1.36.0", "1.37.0"):
            with self.subTest(version=version):
                self.assertTrue(objects(version=version))
        for version in ("1.34.9", "1.38.0"):
            with self.subTest(version=version):
                self.assertNotEqual(render(version=version, check=False).returncode, 0)

    def test_defaults_do_not_require_client_stack_or_host_access(self):
        rendered = objects()
        kinds = {obj["kind"] for obj in rendered}
        self.assertIn("StatefulSet", kinds)
        self.assertNotIn("DaemonSet", kinds)
        self.assertFalse(kinds & {"CustomResourceDefinition", "MutatingWebhookConfiguration",
                                  "ValidatingWebhookConfiguration", "Instrumentation", "Prometheus",
                                  "ServiceMonitor", "ClusterIssuer", "Namespace", "Secret"})
        for obj in rendered:
            pod = podspec(obj)
            if pod:
                self.assertFalse(pod.get("hostNetwork", False))
                self.assertFalse(pod.get("hostPID", False))
                self.assertFalse(pod.get("automountServiceAccountToken", True))
                self.assertFalse(any("hostPath" in volume for volume in pod.get("volumes", [])))
        config = "\n".join(value for obj in rendered if obj["kind"] == "ConfigMap"
                           for value in obj.get("data", {}).values())
        self.assertNotIn("/federate", config)
        self.assertNotIn("prometheus.io/", config)
        self.assertNotIn("opentelemetrycollector", config.lower())

    def test_all_modules_are_owned_and_cluster_names_are_isolated(self):
        first = objects(all_modules(), release="elven-a", namespace="elven-a")
        second = objects(all_modules(), release="elven-b", namespace="elven-a")
        third = objects(all_modules(), release="elven-a", namespace="elven-b")
        cluster_kinds = {"ClusterRole", "ClusterRoleBinding"}
        cluster_names = []
        for rendered, release in ((first, "elven-a"), (second, "elven-b"), (third, "elven-a")):
            names = set()
            for obj in rendered:
                labels = obj["metadata"]["labels"]
                self.assertEqual(labels["app.kubernetes.io/instance"], release)
                self.assertEqual(labels["app.kubernetes.io/part-of"], "elven-observability")
                if obj["kind"] in cluster_kinds:
                    names.add((obj["kind"], obj["metadata"]["name"]))
            cluster_names.append(names)
        self.assertFalse(cluster_names[0] & cluster_names[1])
        self.assertFalse(cluster_names[0] & cluster_names[2])
        first_ids = {(obj["kind"], obj["metadata"]["name"]) for obj in first}
        second_ids = {(obj["kind"], obj["metadata"]["name"]) for obj in second}
        self.assertFalse(first_ids & second_ids)

    def test_images_are_digest_pinned_and_rootless_default_is_hardened(self):
        for obj in objects():
            pod = podspec(obj)
            if not pod:
                continue
            for container in pod["containers"]:
                self.assertRegex(container["image"], r"@sha256:[0-9a-f]{64}$")
                security = container["securityContext"]
                self.assertTrue(security["runAsNonRoot"])
                self.assertGreater(security["runAsUser"], 0)
                self.assertTrue(security["readOnlyRootFilesystem"])
                self.assertFalse(security["allowPrivilegeEscalation"])
                self.assertEqual(security["capabilities"]["drop"], ["ALL"])
                self.assertEqual(security["seccompProfile"]["type"], "RuntimeDefault")
                self.assertTrue(container["resources"]["requests"])
                self.assertTrue(container["resources"]["limits"])
                self.assertFalse(any("hostPort" in port for port in container.get("ports", [])))

    def test_rbac_has_no_wildcard_secret_or_mutation_rights(self):
        for obj in objects(all_modules()):
            if obj["kind"] not in ("Role", "ClusterRole"):
                continue
            for rule in obj["rules"]:
                self.assertNotIn("*", rule.get("apiGroups", []))
                self.assertNotIn("*", rule.get("resources", []))
                self.assertNotIn("*", rule.get("verbs", []))
                self.assertFalse(set(rule.get("resources", [])) & {"secrets", "pods/exec", "pods/attach"})
                self.assertTrue(set(rule.get("verbs", [])) <= {"get", "list", "watch"})

    def test_secrets_remain_references_not_rendered_credentials(self):
        values = {"credentials": {"existingSecret": "synthetic-credentials"},
                  "tls": {"existingSecret": "synthetic-tls"}}
        rendered = objects(values)
        self.assertFalse(any(obj["kind"] == "Secret" for obj in rendered))
        workload = next(obj for obj in rendered if obj["kind"] == "StatefulSet")
        pod = podspec(workload)
        refs = [env.get("valueFrom", {}).get("secretKeyRef", {})
                for container in pod["containers"] for env in container.get("env", [])]
        self.assertTrue(any(ref.get("name") == "synthetic-credentials" and ref.get("key") == "api-token" for ref in refs))
        self.assertTrue(any(volume.get("secret", {}).get("secretName") == "synthetic-tls" for volume in pod["volumes"]))
        self.assertNotIn("Bearer eyJ", json.dumps(rendered))

    def test_gateway_and_readers_mount_only_their_tls_identity(self):
        for obj in objects(all_modules()):
            pod = podspec(obj)
            if not pod:
                continue
            component = obj["metadata"]["labels"].get("app.kubernetes.io/component")
            if component not in ("gateway", "node", "cluster-metrics", "node-agent"):
                continue
            tls = next(volume["secret"] for volume in pod["volumes"]
                       if volume.get("secret", {}).get("secretName") == "elven-internal-tls")
            mounted = {item["key"] for item in tls["items"]}
            if component == "gateway":
                self.assertEqual(mounted, {"tls.crt", "tls.key", "ca.crt"})
            else:
                self.assertEqual(mounted, {"client.crt", "client.key", "ca.crt"})
            for container in pod["containers"]:
                if component != "gateway":
                    self.assertFalse(any(env.get("valueFrom", {}).get("secretKeyRef", {}).get("name") == "elven-ingest"
                                         for env in container.get("env", [])))

    def test_invalid_configuration_is_rejected(self):
        invalid = (
            {"ports": {"otlpHttp": 70000}},
            {"ports": {"otlpHttp": 4317}},
            {"gateway": {"replicas": 0}},
            {"endpoints": {"logs": "http://plaintext.invalid/logs"}},
            {"endpoints": {"logs": "https://user:password@example.invalid/logs"}},
            {"endpoints": {"logs": "https://example.invalid/logs?token=synthetic"}},
            {"images": {"collector": {"digest": "latest"}}},
            {"collection": {"namespaces": ["kube-system"]}},
            {"networkPolicy": {"exportCIDRs": ["0.0.0.0/0"]}},
            {"privacy": {"preserveSpanLinks": True, "spanLinkAttributesApproved": False}},
            {"modules": {"logs": {"enabled": True, "hostAccessApproved": False}}},
            {"modules": {"ebpf": {"enabled": True, "hostAccessApproved": False}}},
            {"modules": {"ebpf": {"enabled": True, "hostAccessApproved": True,
                "workloads": [{"namespace": "synthetic-app", "deployment": "synthetic-http"}],
                "additionalCapabilities": ["SYS_ADMIN"], "additionalCapabilitiesApproved": False}},
             "collection": {"namespaces": ["synthetic-app"]},
             "networkPolicy": {"apiServerCIDRs": ["192.0.2.11/32"]}},
            {"modules": {"profiles": {"enabled": True, "targets": []}}},
        )
        for values in invalid:
            with self.subTest(values=values):
                self.assertNotEqual(render(values, check=False).returncode, 0)

    def test_ports_are_configurable_and_gateway_requires_mutual_tls(self):
        values = {"ports": {"otlpGrpc": 24317, "otlpHttp": 24318, "health": 23133,
                             "metrics": 28888, "localOtlpHttp": 24319}}
        rendered = objects(values)
        pod = podspec(next(obj for obj in rendered if obj["kind"] == "StatefulSet"))
        actual = {port["containerPort"] for container in pod["containers"] for port in container.get("ports", [])}
        self.assertTrue({24317, 24318, 23133, 28888} <= actual)
        cm = next(obj for obj in rendered if obj["kind"] == "ConfigMap" and "collector.yaml" in obj.get("data", {}))
        config = yaml.safe_load(cm["data"]["collector.yaml"])
        protocols = config["receivers"]["otlp"]["protocols"]
        for name in ("grpc", "http"):
            tls = protocols[name]["tls"]
            self.assertEqual(tls["client_ca_file"], "/etc/elven/tls/ca.crt")
            self.assertEqual(tls["min_version"], "1.2")
            self.assertNotIn("insecure_skip_verify", tls)

    def test_persistent_queue_is_after_sanitization_and_retry_does_not_expire(self):
        cm = next(obj for obj in objects() if obj["kind"] == "ConfigMap" and "collector.yaml" in obj.get("data", {}))
        config = yaml.safe_load(cm["data"]["collector.yaml"])
        self.assertTrue(any(storage.get("fsync") for name, storage in config["extensions"].items() if name.startswith("file_storage")))
        for exporter in config["exporters"].values():
            if "sending_queue" not in exporter:
                continue
            self.assertEqual(exporter["retry_on_failure"]["max_elapsed_time"], "0s")
            queue = exporter["sending_queue"]
            self.assertTrue(queue["storage"].startswith("file_storage"))
            self.assertTrue(queue["block_on_overflow"])
            self.assertLessEqual(queue["queue_size"], 20 * 1024 * 1024)
        for pipeline in config["service"]["pipelines"].values():
            self.assertFalse(any(name.startswith("batch") for name in pipeline.get("processors", [])))

    def test_volume_claim_template_labels_are_stable_across_chart_versions(self):
        gateway = next(obj for obj in objects() if obj["kind"] == "StatefulSet")
        for claim in gateway["spec"]["volumeClaimTemplates"]:
            labels = claim["metadata"]["labels"]
            self.assertNotIn("helm.sh/chart", labels)
            self.assertNotIn("app.kubernetes.io/version", labels)
            self.assertEqual(labels["app.kubernetes.io/instance"], "elven-test")

    def test_ebpf_has_a_scoped_optional_privilege_baseline(self):
        node = next(obj for obj in objects(all_modules()) if obj["kind"] == "DaemonSet")
        beyla = next(container for container in podspec(node)["containers"] if container["name"] == "beyla")
        capabilities = beyla["securityContext"]["capabilities"]
        self.assertEqual(set(capabilities["add"]), {"BPF", "PERFMON", "SYS_PTRACE", "DAC_READ_SEARCH", "CHECKPOINT_RESTORE", "NET_RAW"})
        self.assertNotIn("SYS_ADMIN", capabilities["add"])
        self.assertNotIn("NET_ADMIN", capabilities["add"])
        self.assertTrue(any(env.get("name") == "BEYLA_ENFORCE_SYS_CAPS" and env.get("value") == "1" for env in beyla["env"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
