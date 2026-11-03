#!/usr/bin/env python3
"""Actual Elven admission + SDK application traces in a disposable Kind cluster.

Standalone CI exercises the real Operator/SDK OCI archives against an mTLS
Python OTLP sink. Supplying the exact Collector archive additionally exercises
the gateway and both real installer bootstraps. Neither mode accesses the
caller's kubeconfig or claims NetworkPolicy enforcement with Kind's default CNI.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import urllib.request
from types import SimpleNamespace

import yaml


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("elven_core_kind", ROOT / "scripts/test-kind.py")
CORE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CORE)
CLI_SPEC = importlib.util.spec_from_file_location("elven_instrumentation_cli", ROOT / "scripts/instrumentation.py")
INSTRUMENTATION = importlib.util.module_from_spec(CLI_SPEC)
CLI_SPEC.loader.exec_module(INSTRUMENTATION)
FIXTURES = ROOT / "tests/instrumentation-fixtures"
REPOSITORIES = {"operator": "elven-instrumentation-operator", "java": "elven-auto-java",
                "nodejs": "elven-auto-nodejs", "nodejs20": "elven-auto-nodejs20", "python": "elven-auto-python"}
IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def sha256(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def read_images(path):
    path = Path(path).resolve()
    manifest = json.loads(path.read_text())
    if set(manifest.get("images", {})) != set(REPOSITORIES):
        raise ValueError("Supply the complete independent five-image instrumentation build manifest")
    images = {}
    for name, entry in manifest["images"].items():
        tag, digest = entry.get("tag", ""), entry.get("digest", "")
        prefix = "docker.io/elvenobservability/" + REPOSITORIES[name] + ":"
        if (not tag.startswith(prefix) or not IMAGE_DIGEST.fullmatch(digest)
                or not re.fullmatch(r"v?1\.[0-9]+\.[0-9]+(?:-dev|-rc\.[0-9]+)?", tag.removeprefix(prefix))):
            raise ValueError("The instrumentation manifest must identify exact Elven images")
        archive = (path.parent / entry["archive"]).resolve()
        if not archive.is_relative_to(path.parent) or sha256(archive) != entry["archiveSha256"]:
            raise ValueError("The instrumentation OCI archive escaped its directory or failed SHA-256 verification")
        repository, version = tag.rsplit(":", 1)
        images[name] = {"repository": repository, "tag": version, "digest": digest,
                        "reference": tag + "@" + digest, "archive": archive}
    return images


def sdk_wire_summary(accepted):
    assert accepted and all(item.get("client_certificate_verified") is True for item in accepted)
    assert all(not item.get("authorization_present") for item in accepted)
    chunked = [item for item in accepted if (item.get("transfer_encoding") or "").lower() == "chunked"]
    empty_chunked = sum(not base64.b64decode(item["body"]) for item in chunked)
    assert empty_chunked == 0, "The test sink must decode actual streamed SDK bodies, not acknowledge empty exports"
    return {"verified_client_certificate_exports": len(accepted), "chunked_exports": len(chunked),
            "empty_chunked_exports": empty_chunked, "backend_bearer_credentials_in_sdk_exports": False}


class InstrumentationLab(CORE.Lab):
    def __init__(self, args):
        self.images = read_images(args.images_manifest)
        super().__init__(args.node_image, args.keep, args.collector_image, args.collector_image_archive)
        target = self.directory.with_name("instrumentation-" + self.directory.name)
        self.directory.rename(target)
        self.directory = target
        self.kubeconfig = target / "kubeconfig"
        self.operator_release = "elven-injector"
        self.foreign_namespace = "synthetic-foreign"
        self.combined = bool(args.collector_image)
        self.fixture_images = {}
        self.report.update({"test": "actual Elven admission and auto-instrumentation SDKs",
            "mode": "gateway-and-installers" if self.combined else "standalone-sdk-mtls-sink",
            "images": {name: value["reference"] for name, value in self.images.items()},
            "runtime_cases": ["java17", "java21", "node22", "node20-explicit-eol-exception"],
            "not_proven": ["NetworkPolicy enforcement (Kind default CNI)", "customer infrastructure/tenant acceptance",
                "all supported Kubernetes versions live", "production scale/HA", "Python SDK application compatibility",
                "image publication/signature/promotion", *CORE.RUNTIME_LIMITS.values()]})
        if not self.combined:
            self.report["not_proven"] += ["gateway privacy/durable queues in this standalone SDK run",
                "gateway/instrumentation installer ownership bootstrap in this standalone SDK run"]

    def import_archive(self, image):
        CORE.execute(["kind", "load", "image-archive", image["archive"], "--name", self.name], timeout=240)
        tagged = image["repository"] + ":" + image["tag"]
        output = CORE.execute(["docker", "exec", self.name + "-control-plane", "ctr", "-n", "k8s.io", "images", "ls"]).stdout
        row = next((line.split() for line in output.splitlines() if line.split() and line.split()[0] == tagged), None)
        if not row or row[2] != image["digest"]:
            raise AssertionError("Kind imported an OCI index different from the verified SDK manifest")
        CORE.execute(["docker", "exec", self.name + "-control-plane", "ctr", "-n", "k8s.io", "images", "tag",
                      "--force", tagged, image["repository"] + "@" + image["digest"]])

    def prepare_fixtures(self):
        pins = json.loads((FIXTURES / "fixtures.json").read_text())
        context = self.directory / "application-fixtures"
        shutil.copytree(FIXTURES, context)
        h2 = pins["h2"]
        with urllib.request.urlopen(h2["url"], timeout=60) as source:
            payload = source.read(4 * 1024 * 1024 + 1)
        if len(payload) > 4 * 1024 * 1024 or hashlib.sha256(payload).hexdigest() != h2["sha256"]:
            raise AssertionError("The official Maven H2 JDBC fixture failed its pinned SHA-256")
        with (context / h2["file"]).open("xb") as output:
            output.write(payload)
        # Public fixture dependency, not a Secret. COPY preserves source modes;
        # umask077 would otherwise leave this root-owned JAR unreadable to the
        # application's unchanged non-root UID inside the fixture image.
        (context / h2["file"]).chmod(0o444)
        self.report["fixture_sources"] = pins
        for case in ("java17", "java21", "node22", "node20"):
            recipe = context / ("Dockerfile." + case)
            if pins["images"][case] not in recipe.read_text() or "@sha256:" not in pins["images"][case]:
                raise AssertionError("Application fixture must use the recorded immutable official runtime")
            tag = "elven-disposable/instrumentation-" + case + ":" + self.name.removeprefix("elven-dist-")
            CORE.execute(["docker", "build", "--file", recipe, "--tag", tag, context], timeout=600)
            self.fixture_images[case] = tag
            CORE.execute(["kind", "load", "docker-image", tag, "--name", self.name], timeout=180)
        self.check("official pinned Java17 Java21 Node22 and explicit EOL Node20 fixtures built without bundled SDKs",
                   h2_sha256=h2["sha256"])

    def fixture(self):
        super().fixture()
        if not self.combined:
            self.apply({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
                "name": "synthetic-sink-code", "namespace": self.namespace},
                "data": {"sink.py": (FIXTURES / "sink.py").read_text()}})
            self.kube("rollout", "restart", "deployment/synthetic-sink", "-n", self.namespace)
            self.kube("rollout", "status", "deployment/synthetic-sink", "-n", self.namespace, "--timeout=180s")
            # The old tunnel can still target the terminating sink Pod.
            self.sink_port = self.port_forward("service/sink", 443)
        self.apply({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": self.foreign_namespace}})
        pods = json.loads(self.kube("get", "pods", "-n", self.app_namespace,
                                   "-l", "app=synthetic-customer-app", "-o", "json").stdout)["items"]
        self.customer_pods_before = {pod["metadata"]["uid"]: [item.get("restartCount", 0)
            for item in pod.get("status", {}).get("containerStatuses", [])] for pod in pods}

    def install_gateway(self):
        node = json.loads(self.kube("get", "nodes", "-o", "json").stdout)["items"][0]
        self.node_ip = next(item["address"] for item in node["status"]["addresses"] if item["type"] == "InternalIP")
        self.provision("elven-a")
        source = self.values("elven-a", False)
        settings = yaml.safe_load(source.read_text())
        settings["tls"] = {"existingSecret": "elven-a-internal-tls"}
        settings["credentials"] = {"existingSecret": "elven-a-ingest"}
        source.write_text(yaml.safe_dump(settings))
        tenant, token = self.directory / "tenant.txt", self.directory / "token.txt"
        for path, text in ((tenant, "synthetic-tenant"), (token, "synthetic-test-token")):
            path.write_text(text + "\n")
            path.chmod(0o600)
        uid = json.loads(self.kube("get", "namespace/kube-system", "-o", "json").stdout)["metadata"]["uid"]
        CORE.execute([sys.executable, ROOT / "elven", "install", "--release", "elven-a", "--namespace", self.namespace,
            "--context", "kind-" + self.name, "--kubeconfig", self.kubeconfig, "--expect-cluster-uid", uid,
            "--cluster-name", "synthetic-kind", "--values", source, "--tenant-file", tenant, "--token-file", token,
            "--credentials-secret", "elven-a-ingest", "--tls-secret", "elven-a-internal-tls", "--development-images"], timeout=420)
        claim = json.loads(self.kube("get", "pvc/data-elven-a-gateway-0", "-n", self.namespace, "-o", "json").stdout)
        assert any("storage-identity" in key for key in claim["metadata"].get("annotations", {}))
        self.check("real gateway CLI bootstrap creates PKI credentials durable PVC and storage identity receipt")
        return "https://elven-a-gateway." + self.namespace + ".svc.cluster.local:4318"

    def operator_values(self, endpoint):
        node = json.loads(self.kube("get", "nodes", "-o", "json").stdout)["items"][0]
        node_ip = next(item["address"] for item in node["status"]["addresses"] if item["type"] == "InternalIP")
        settings = {"enabled": True, "clusterDomain": "cluster.local", "namespaces": [self.app_namespace],
            "gateway": {"endpoint": endpoint, "sourceRelease": "elven-a", "sourceNamespace": self.namespace},
            "runtimes": {"java": True, "nodejs": True, "python": False, "nodejs20": True, "legacyNode20Approved": True},
            "images": {name: {key: value[key] for key in ("repository", "tag", "digest")}
                       for name, value in self.images.items()}, "networkPolicy": {"apiServerCIDRs": [node_ip + "/32"]}}
        return settings

    def install_operator(self):
        endpoint = self.install_gateway() if self.combined else "https://sink." + self.namespace + ".svc.cluster.local:443"
        settings = self.operator_values(endpoint)
        source = self.directory / "operator-values.yaml"
        if self.combined:
            source.write_text(yaml.safe_dump(settings))
            uid = json.loads(self.kube("get", "namespace/kube-system", "-o", "json").stdout)["metadata"]["uid"]
            CORE.execute([sys.executable, ROOT / "scripts/instrumentation.py", "install", "--release", self.operator_release,
                "--namespace", self.namespace, "--context", "kind-" + self.name, "--kubeconfig", self.kubeconfig,
                "--expect-cluster-uid", uid, "--values", source, "--development-images", "--timeout", "240s"], timeout=420)
            self.check("real instrumentation CLI validates owned source gateway and provisions scoped PKI without patching apps")
        else:
            # Standalone SDK CI has no core-image cross-workflow dependency.
            # This is explicit test PKI + the real chart, never fabricated CLI ownership.
            folder = self.directory / "webhook-tls"
            args = SimpleNamespace(release=self.operator_release, namespace=self.namespace)
            serving = INSTRUMENTATION.generate_serving(args, settings, folder)
            settings["webhook"] = {"caBundle": base64.b64encode(serving["ca.crt"].encode()).decode()}
            client = {name: (self.tls_dir / name).read_text() for name in ("ca.crt", "client.crt", "client.key")}
            key = self.directory / "client-pkcs8.key"
            CORE.execute(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", self.tls_dir / "client.key", "-out", key])
            key.chmod(0o600)
            client["client.key"] = key.read_text()
            self.apply({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "elven-operator-webhook-tls", "namespace": self.namespace},
                        "stringData": serving},
                       {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "elven-instrumentation-tls", "namespace": self.app_namespace},
                        "stringData": client})
            source.write_text(yaml.safe_dump(settings))
            self.helm("install", self.operator_release, ROOT / "charts/elven-instrumentation", "--values", source,
                      "--wait", "--timeout", "240s", timeout=300)
            self.check("real Operator chart with verified serving PKI and mTLS SDK client fixture installed")
        self.kube("rollout", "status", "deployment/" + self.operator_release, "-n", self.namespace, "--timeout=180s")
        sa = self.kube("auth", "can-i", "list", "secrets", "-n", self.namespace,
                       "--as=system:serviceaccount:" + self.namespace + ":" + self.operator_release, check=False)
        assert sa.stdout.strip() == "no"
        self.check("Operator runtime has no Kubernetes Secret read permissions")

    def app(self, name, case, runtime=None, namespace=None, sidecar=False):
        # The application's own reviewed Pod supplies bounded scratch space.
        # Java agent bootstrap may need temporary JARs; the injector must not
        # weaken an application's read-only root filesystem to provide it.
        security = {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001,
                    "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}
        obj = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": namespace or self.app_namespace,
            "labels": {"app.kubernetes.io/name": name}}, "spec": {"automountServiceAccountToken": False,
            "securityContext": {"fsGroup": 10001}, "containers": [{"name": "app", "image": self.fixture_images[case],
                "imagePullPolicy": "Never", "securityContext": security,
                "volumeMounts": [{"name": "application-tmp", "mountPath": "/tmp"}],
                "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"cpu": "1000m", "memory": "512Mi"}},
                "ports": [{"containerPort": 8080}], "readinessProbe": {"httpGet": {"path": "/ready", "port": 8080},
                    "initialDelaySeconds": 2, "periodSeconds": 2, "failureThreshold": 90}}],
            "volumes": [{"name": "application-tmp", "emptyDir": {"sizeLimit": "32Mi"}}]}}
        if runtime is not None:
            obj["metadata"]["labels"]["elven.observability/inject"] = runtime
        if sidecar:
            obj["metadata"]["annotations"] = {"elven.observability/container-name": "app"}
            obj["spec"]["containers"].append({"name": "sidecar", "image": self.fixture_images["node22"],
                "imagePullPolicy": "Never", "command": ["node", "-e", "setInterval(()=>{},1000)"],
                "securityContext": copy.deepcopy(security),
                "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}, "limits": {"cpu": "100m", "memory": "64Mi"}}})
        return obj

    def create(self, obj, allowed=True):
        result = self.kube("create", "-f", "-", data=json.dumps(obj), check=False)
        if allowed:
            assert result.returncode == 0, result.stderr
        else:
            assert result.returncode != 0 and "denied" in result.stderr.lower(), result.stdout + result.stderr
            absent = self.kube("get", "pod/" + obj["metadata"]["name"], "-n", obj["metadata"]["namespace"], "--ignore-not-found", "-o", "json").stdout
            assert not absent.strip(), "Denied fixture was unexpectedly created"

    def applications(self):
        for name, case, runtime in (("java17", "java17", "java"), ("java21", "java21", "java"),
                                    ("node22", "node22", "nodejs"), ("node20", "node20", "nodejs20")):
            obj = self.app(name, case, runtime, sidecar=name == "node22")
            self.create(obj)
            self.kube("wait", "--for=condition=Ready", "pod/" + name, "-n", self.app_namespace, "--timeout=240s", timeout=260)
            actual = json.loads(self.kube("get", "pod/" + name, "-n", self.app_namespace, "-o", "json").stdout)
            init = next(item for item in actual["spec"]["initContainers"] if item["name"] == "elven-instrumentation-init")
            assert init["image"] == self.images[runtime]["reference"]
            status = next(item for item in actual["status"]["initContainerStatuses"] if item["name"] == init["name"])
            assert status["state"]["terminated"]["exitCode"] == 0
            app = actual["spec"]["containers"][0]
            assert app["securityContext"] == obj["spec"]["containers"][0]["securityContext"]
            assert "OTEL_EXPORTER_OTLP_HEADERS" not in {item["name"] for item in app["env"]}
            if name == "node22":
                untouched = actual["spec"]["containers"][1]
                assert not untouched.get("env") and not untouched.get("volumeMounts")
                assert untouched["securityContext"] == obj["spec"]["containers"][1]["securityContext"]
            self.check("actual SDK init copy and app readiness " + name, sdk_image=init["image"], init_exit_code=0)
            address = actual["status"]["podIP"]
            self.kube("exec", "deployment/synthetic-customer-app", "-n", self.app_namespace, "--", "python", "-c",
                "import urllib.request; r=urllib.request.urlopen('http://" + address + ":8080/exercise',timeout=20); assert r.status==200")
        self.check("explicit app-container target leaves Node sidecar security loader and mounts untouched")

    def boundaries(self):
        for name, namespace, runtime in (("no-opt-in", self.app_namespace, None),
                                         ("foreign-opt-in", self.foreign_namespace, "nodejs")):
            obj = self.app(name, "node22", runtime, namespace)
            self.create(obj)
            actual = json.loads(self.kube("get", "pod/" + name, "-n", namespace, "-o", "json").stdout)
            assert not actual["spec"].get("initContainers")
            assert not actual["spec"]["containers"][0].get("env")
            assert actual["spec"]["containers"][0].get("volumeMounts") == obj["spec"]["containers"][0]["volumeMounts"]
        self.check("unlabelled app and opted-in foreign namespace are not injected")
        self.create(self.app("unknown-runtime", "node22", "ruby"), allowed=False)
        conflict = self.app("existing-sdk", "node22", "nodejs")
        conflict["spec"]["containers"][0]["env"] = [{"name": "OTEL_SERVICE_NAME", "value": "external-owner"}]
        self.create(conflict, allowed=False)
        target = self.app("ambiguous-target", "node22", "nodejs", sidecar=True)
        target["metadata"].pop("annotations")
        self.create(target, allowed=False)
        self.check("unknown runtime existing SDK conflict and ambiguous multi-container target are denied before creation")
        unchanged = json.loads(self.kube("get", "deployment/synthetic-customer-app", "-n", self.app_namespace, "-o", "json").stdout)
        assert unchanged["metadata"]["uid"] == self.app_before["metadata"]["uid"]
        assert unchanged["spec"] == self.app_before["spec"]
        pods = json.loads(self.kube("get", "pods", "-n", self.app_namespace,
                                   "-l", "app=synthetic-customer-app", "-o", "json").stdout)["items"]
        after = {pod["metadata"]["uid"]: [item.get("restartCount", 0)
            for item in pod.get("status", {}).get("containerStatuses", [])] for pod in pods}
        assert after == self.customer_pods_before
        self.check("Operator install and admissions do not update or restart an existing application")

    def service_spans(self):
        result = {}
        for payload in self.decoded("traces"):
            for resource in payload.get("resource_spans", []):
                attrs = {item["key"]: item["value"].get("string_value") for item in resource.get("resource", {}).get("attributes", [])}
                for scope in resource.get("scope_spans", []):
                    for span in scope.get("spans", []):
                        result.setdefault(attrs.get("service.name"), []).append((scope.get("scope", {}).get("name", ""), span))
        return result

    def delivery(self):
        cases = {"java17", "java21", "node22", "node20"}
        def observed():
            actual = self.service_spans()
            self.report["observed_spans_by_service"] = {case: len(actual.get(case, [])) for case in sorted(cases)}
            return cases <= set(actual)
        self.wait_for(observed, "real automatically instrumented traces from all four runtimes", timeout=150)
        spans = self.service_spans()
        for case in sorted(cases):
            actual = spans[case]
            assert any(span.get("kind") in ("SPAN_KIND_SERVER", 2) for _, span in actual), (case, "no real HTTP server span")
            assert any(span.get("kind") in ("SPAN_KIND_CLIENT", 3) for _, span in actual), (case, "no real HTTP client span")
            if case.startswith("java"):
                statements = [attribute["value"].get("string_value", "") for scope, span in actual
                    for attribute in span.get("attributes", []) if attribute["key"] in ("db.statement", "db.query.text")]
                assert statements and any("SELECT" in value.upper() for value in statements), (case, "no actual JDBC statement span")
                assert all("4111111111111111" not in value and "synthetic-customer@example.invalid" not in value for value in statements)
            self.check("real auto-instrumented HTTP server client" + (" and JDBC SQL" if case.startswith("java") else "") + " spans " + case,
                       span_count=len(actual), scopes=sorted({scope for scope, _ in actual}))
        accepted = self.state()["accepted"]
        if self.combined:
            assert all(item["tenant"] == "synthetic-tenant" and item["authorization_valid"] for item in accepted)
            exported = json.dumps(self.decoded("traces"))
            assert "4111111111111111" not in exported and "synthetic-customer@example.invalid" not in exported
            self.check("actual SDK traces pass gateway selective privacy and authenticated tenant exporter")
        else:
            self.report["sink_wire"] = sdk_wire_summary(accepted)
            self.check("actual SDK OTLP exports authenticate with verified TLS client certificates")

    def run(self):
        self.boot()
        for image in self.images.values():
            self.import_archive(image)
        self.check("all five instrumentation OCI indices verified and loaded only into isolated Kind")
        self.prepare_fixtures()
        self.tls()
        self.fixture()
        self.install_operator()
        self.applications()
        self.boundaries()
        self.delivery()
        self.report["completed"] = True

    def cleanup(self):
        try:
            if self.created and self.kubeconfig.exists():
                diagnostics = self.kube("get", "pods,events", "-n", self.app_namespace, "-o", "wide", check=False).stdout
                for case in ("java17", "java21", "node22", "node20"):
                    diagnostics += "\n" + case + " SDK fixture logs:\n" + self.kube("logs", "pod/" + case, "-c", "app", "-n", self.app_namespace, "--tail=25", check=False).stdout
                    diagnostics += "\n" + case + " init logs:\n" + self.kube("logs", "pod/" + case, "-c", "elven-instrumentation-init", "-n", self.app_namespace, "--tail=25", check=False).stdout
                (self.directory / "sdk-diagnostics.txt").write_text(diagnostics)
        finally:
            try:
                super().cleanup()
            finally:
                if not self.keep:
                    for image in self.fixture_images.values():
                        CORE.execute(["docker", "image", "rm", image], check=False, timeout=60)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--images-manifest", required=True)
    parser.add_argument("--collector-image", default=os.environ.get("ELVEN_COLLECTOR_IMAGE"))
    parser.add_argument("--collector-image-archive")
    parser.add_argument("--node-image", default=CORE.KIND_NODE)
    parser.add_argument("--development-images", action="store_true")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--keep-on-failure", action="store_true", help="Maintainer diagnosis only: retain this disposable cluster if the run fails")
    args = parser.parse_args()
    if not args.development_images:
        parser.error("This unpublished-image test requires explicit --development-images; it cannot promote production images")
    if bool(args.collector_image) != bool(args.collector_image_archive):
        parser.error("Combined mode requires both exact --collector-image and --collector-image-archive")
    os.umask(0o077)
    lab = InstrumentationLab(args)
    try:
        lab.run()
    except BaseException as error:
        lab.report["error"] = str(error) or type(error).__name__
        if args.keep_on_failure:
            lab.keep = True
        raise
    finally:
        lab.cleanup()


if __name__ == "__main__":
    main()
