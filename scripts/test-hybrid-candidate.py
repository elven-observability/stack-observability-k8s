#!/usr/bin/env python3
"""Hosted, disposable, fail-closed candidate ZIP -> SDK/Beyla -> sink experiment.

Never a production installer. Requires an externally admitted ZIP hash, fresh
CI-scanned core/SDK OCI manifests and two explicit laboratory consents. The
production template admission path is not weakened for unsigned lab images.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import ipaddress
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import threading
import time
import uuid
import zipfile
from urllib.parse import urlsplit

import yaml

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


CORE = module("hybrid_core_lab", ROOT / "scripts/test-kind.py")
SDK = module("hybrid_sdk_archives", ROOT / "scripts/test-instrumentation-kind.py")
SDK_NAME, BPF_NAME = "elven-hybrid-sdk", "elven-hybrid-bpf"
SDK_SCOPE = "@opentelemetry/instrumentation-http"
CAPS = {"BPF", "PERFMON", "SYS_PTRACE", "DAC_READ_SEARCH", "CHECKPOINT_RESTORE", "NET_RAW"}


class Unsupported(RuntimeError):
    pass


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def extract_candidate(path, expected, target):
    # The verifier comes from the trusted checkout, never from the incoming ZIP.
    verifier = module("hybrid_candidate_verifier", ROOT / "scripts/package-candidate.py")
    with Path(path).open("rb") as stream:
        raw = stream.read(verifier.MAX_BYTES + 1)
    manifest = verifier.verify(raw, expected)
    if manifest.get("kind") != "ELVEN_LAB_CANDIDATE" or manifest.get("customerInstallable") is not False:
        raise ValueError("A laboratory-only candidate is required")
    target.mkdir(mode=0o700)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for info in archive.infolist():
            parts = PurePosixPath(info.filename).parts
            if (not parts or parts[0] != "elven-lab-candidate" or ".." in parts
                    or PurePosixPath(info.filename).is_absolute() or "\\" in info.filename):
                raise ValueError("Unsafe candidate member")
            if info.is_dir():
                continue
            relative = Path(*parts[1:])
            destination = target / relative
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with destination.open("xb") as stream:
                stream.write(archive.read(info))
            destination.chmod(0o600)
    return manifest


def core_images(path):
    path = Path(path).resolve()
    data = json.loads(path.read_text())
    if set(data.get("images", {})) != {"collector", "beyla", "alloy"}:
        raise ValueError("A complete exact core candidate manifest is required")
    result = {}
    for name, value in data["images"].items():
        tag, digest = value.get("tag", ""), value.get("digest", "")
        prefix = "docker.io/elvenobservability/" + {"collector": "elven-collector", "beyla": "elven-ebpf", "alloy": "elven-profiler"}[name] + ":"
        archive = (path.parent / value["archive"]).resolve()
        if (not tag.startswith(prefix) or not re.fullmatch(r"v?1\.[0-9]+\.[0-9]+(?:-dev|-rc\.[0-9]+)?", tag.removeprefix(prefix))
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
                or not archive.is_relative_to(path.parent) or sha(archive) != value["archiveSha256"]):
            raise ValueError("Core candidate archive/reference mismatch")
        repository, version = tag.rsplit(":", 1)
        result[name] = {"reference": tag + "@" + digest, "repository": repository,
                        "tag": version, "digest": digest, "archive": archive}
    return result


def fresh_scans(path, components, scanner, now=None):
    now = now or datetime.now(timezone.utc)
    path = Path(path).resolve()
    data = json.loads(path.read_text())
    if data.get("dirtySource") is not False:
        raise ValueError("Candidate source cleanliness is not established")
    for name in components:
        for platform in ("linux/amd64", "linux/arm64"):
            scan = data["images"][name]["scans"][platform]
            if (scan["status"] != "passed" or type(scan["highCriticalCount"]) is not int
                    or scan["highCriticalCount"] != 0 or scan["scanner"] != "trivy/" + scanner):
                raise ValueError("Candidate scan has not passed with the pinned scanner")
            for timestamp, limit in ((scan["scannedAt"], 24 * 3600), (scan["database"]["UpdatedAt"], 48 * 3600)):
                at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                if at.utcoffset() is None or not -30 <= (now - at).total_seconds() <= limit:
                    raise ValueError("Candidate scan/database freshness gate failed")
            for field in ("report", "sbom"):
                candidate = (path.parent / scan[field]).resolve()
                if not candidate.is_relative_to(path.parent) or sha(candidate) != scan[field + "Sha256"]:
                    raise ValueError("Candidate security evidence hash/path mismatch")


def attrs(values):
    return {item["key"]: next(iter(item["value"].values()), None) for item in values}


def bpf_scope(name):
    # v3.42.0 pinned source: vendor/.../pkg/export/otel/traces.go reporterName.
    # A look-alike prefix is not evidence from the actual instrumentation.
    return name in {"github.com/grafana/beyla", "go.opentelemetry.io/obi"}


def spans(messages):
    for message in messages:
        for resource in message.get("resource_spans", []):
            resource_attrs = attrs(resource.get("resource", {}).get("attributes", []))
            for scope in resource.get("scope_spans", []):
                for span in scope.get("spans", []):
                    yield resource_attrs, scope.get("scope", {}).get("name", ""), span


def exercise_span(span):
    values = attrs(span.get("attributes", []))
    for key in ("http.route", "http.target", "url.path", "http.url", "url.full"):
        value = values.get(key)
        if isinstance(value, str) and urlsplit(value).path.rstrip("/") == "/exercise":
            return True
    return span.get("name") in ("GET /exercise", "HTTP GET /exercise")


def classify(messages, after=0):
    result = {"sdk_server": [], "bpf_server": [], "bpf_on_sdk": [], "sdk_on_bpf": [], "unknown_selected_scope": [], "scopes": set()}
    for resource, scope, span in spans(messages):
        if span.get("kind") not in (2, "SPAN_KIND_SERVER") or int(span.get("start_time_unix_nano", 0)) < after:
            continue
        result["scopes"].add(scope)
        service = resource.get("service.name")
        deployment = resource.get("k8s.deployment.name")
        if (service in (SDK_NAME, BPF_NAME) or deployment in (SDK_NAME, BPF_NAME)) and scope != SDK_SCOPE and not bpf_scope(scope):
            result["unknown_selected_scope"].append(scope)
            continue
        # Kubelet readiness requests are not proof that the exercised request
        # reached either instrumentation path, including after rollback.
        if not exercise_span(span):
            continue
        if service == SDK_NAME or deployment == SDK_NAME:
            result["bpf_on_sdk" if bpf_scope(scope) else "sdk_server"].append(span)
        if service == BPF_NAME or deployment == BPF_NAME:
            result["bpf_server" if bpf_scope(scope) else "sdk_on_bpf"].append(span)
    return result


def assert_disjoint(observed, require_bpf=True):
    if observed["unknown_selected_scope"]:
        raise AssertionError("An unknown/empty selected server instrumentation scope is not capture proof")
    if observed["bpf_on_sdk"] or observed["sdk_on_bpf"]:
        raise AssertionError("SDK and Beyla overlapped on a selected service")
    if not observed["sdk_server"] or require_bpf and not observed["bpf_server"]:
        raise AssertionError("Actual independent SDK and Beyla server capture was not demonstrated")


def assert_node_scope(ds, node):
    pod = ds["spec"]["template"]["spec"]
    terms = pod["affinity"]["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]["nodeSelectorTerms"]
    if terms != [{"matchFields": [{"key": "metadata.name", "operator": "In", "values": [node]}]}]:
        raise AssertionError("The actual DaemonSet did not retain exact approvedNodes affinity")
    beyla = next(container for container in pod["containers"] if container["name"] == "beyla")
    security = beyla["securityContext"]
    if (security.get("privileged") is not False or security.get("allowPrivilegeEscalation") is not False
            or set(security["capabilities"]["add"]) != CAPS or set(security["capabilities"]["drop"]) != {"ALL"}):
        raise AssertionError("Beyla capability/privilege baseline was expanded")


def assert_sdk_injection(pod, expected_image, gateway):
    spec = pod["spec"]
    init = [c for c in spec.get("initContainers", []) if c["name"] == "elven-instrumentation-init"]
    status = [c for c in pod.get("status", {}).get("initContainerStatuses", []) if c["name"] == "elven-instrumentation-init"]
    app = next(c for c in spec["containers"] if c["name"] == "application")
    env = {item["name"]: item.get("value") for item in app.get("env", [])}
    mounts = {item["name"]: item for item in app.get("volumeMounts", [])}
    if (len(init) != 1 or init[0].get("image") != expected_image or len(status) != 1
            or status[0].get("state", {}).get("terminated", {}).get("exitCode") != 0
            or env.get("NODE_OPTIONS") != "--require=/elven-auto/autoinstrumentation.js"
            or env.get("OTEL_EXPORTER_OTLP_ENDPOINT") != gateway or env.get("OTEL_SERVICE_NAME") != SDK_NAME
            or "OTEL_EXPORTER_OTLP_HEADERS" in env
            or mounts.get("elven-instrumentation", {}).get("mountPath") != "/elven-auto"
            or mounts.get("elven-instrumentation", {}).get("readOnly") is not True
            or mounts.get("elven-instrumentation-tls", {}).get("mountPath") != "/var/run/elven/tls"
            or mounts.get("elven-instrumentation-tls", {}).get("readOnly") is not True):
        raise AssertionError("The exact SDK image/init/loader/mTLS mutation was not observed")


class HybridLab(CORE.Lab):
    def __init__(self, args):
        images = core_images(args.core_manifest)
        sdk = SDK.read_images(args.sdk_manifest)
        super().__init__(args.node_image, False, images["collector"]["reference"], images["collector"]["archive"])
        self.min_free_bytes = 12 * 1024**3
        self.images, self.sdk_images = images, sdk
        self.payload = self.directory / "candidate"
        manifest = extract_candidate(args.candidate, args.candidate_sha256, self.payload)
        lock = json.loads((self.payload / "versions.lock.json").read_text())
        sdk_lock = json.loads((self.payload / "instrumentation.lock.json").read_text())
        fresh_scans(args.core_manifest, ("collector", "beyla"), lock["tools"]["trivy"])
        fresh_scans(args.sdk_manifest, ("operator", "nodejs"), sdk_lock["tools"]["trivy"])
        self.report.update({"test": "verified ZIP real SDK/Beyla disjoint capture and rollback", "result": "FAIL",
            "candidate": {"sha256": args.candidate_sha256, "sourceRevision": manifest["sourceRevision"]},
            "image_build_revisions": {
                "core": json.loads(Path(args.core_manifest).read_text())["revision"],
                "sdk": json.loads(Path(args.sdk_manifest).read_text())["revision"]},
            "host_access_approved": True, "production_release_admission": "NOT_PROVEN_UNSIGNED_LAB_CANDIDATE",
            "kernel_probe_purge": "NOT_PROVEN", "sdk_bpf_disjoint": "NOT_PROVEN"})
        self.report["not_proven"] += ["production release/signatures", "kernel probe/map purge after process exit",
                                      "other CNI/kernel/architecture combinations", "eBPF SQL or internal SDK spans"]

    def cli(self, command, values=None, release="elven-a", revision=None):
        uid = self.get("namespace", "kube-system", "default")["metadata"]["uid"]
        arguments = [sys.executable, self.payload / "elven", command, "--release", release, "--namespace", self.namespace,
                     "--context", "kind-" + self.name, "--kubeconfig", self.kubeconfig, "--expect-cluster-uid", uid,
                     "--cluster-name", "synthetic-kind", "--use-existing-secrets", "--credentials-secret", "elven-ingest",
                     "--tls-secret", "elven-internal-tls", "--development-images", "--timeout", "180s"]
        if values:
            arguments += ["--values", values]
        if revision is not None:
            arguments += ["--revision", revision]
        return CORE.execute(arguments, timeout=1000)

    def get(self, kind, name, namespace=None):
        return json.loads(self.kube("get", kind + "/" + name, "-n", namespace or self.namespace, "-o", "json").stdout)

    def load(self, image):
        CORE.execute(["kind", "load", "image-archive", image["archive"], "--name", self.name], timeout=240)
        tag, digest = image["reference"].rsplit("@", 1)
        listing = CORE.execute(["docker", "exec", self.name + "-control-plane", "ctr", "-n", "k8s.io", "images", "ls"]).stdout
        row = next((line.split() for line in listing.splitlines() if line.split() and line.split()[0] == tag), None)
        if not row or row[2] != digest:
            raise AssertionError("Loaded OCI index differs from scanned candidate")
        CORE.execute(["docker", "exec", self.name + "-control-plane", "ctr", "-n", "k8s.io", "images", "tag", "--force", tag,
                      image["repository"] + "@" + digest])

    def host(self):
        nodes = json.loads(self.kube("get", "nodes", "-o", "json").stdout)["items"]
        if len(nodes) != 1:
            raise Unsupported("The closed pilot requires exactly one isolated Kind node")
        node = nodes[0]
        self.node_name, self.node_uid = node["metadata"]["name"], node["metadata"]["uid"]
        info = node["status"]["nodeInfo"]
        kernel = info.get("kernelVersion", "")
        parsed = re.match(r"^(\d+)\.(\d+)", kernel)
        btf = CORE.execute(["docker", "exec", self.node_name, "test", "-f", "/sys/kernel/btf/vmlinux"], check=False).returncode == 0
        cni = json.loads(self.kube("get", "daemonsets", "-n", "kube-system", "-o", "json").stdout)
        self.report["host"] = {"node": self.node_name, "uid": self.node_uid, "nodeInfo": info, "btfPresent": btf,
            "cniDaemonSets": [{"name": item["metadata"]["name"], "images": [c["image"] for c in item["spec"]["template"]["spec"]["containers"]]} for item in cni["items"]],
            "networkPolicyEnforcement": "NOT_PROVEN"}
        if (info.get("operatingSystem") != "linux" or info.get("architecture") not in ("amd64", "arm64")
                or not parsed or tuple(map(int, parsed.groups())) < (5, 11) or not btf):
            raise Unsupported("Host kernel/architecture/BTF prerequisites are not satisfied; no fallback permitted")
        self.kubelet_ca()

    def values(self, release, cluster_metrics):
        source = super().values(release, False)
        value = yaml.safe_load(source.read_text())
        value["selfMonitoring"] = {"enabled": False}
        value["nodeAgent"]["approvedNodes"] = [self.node_name]
        source.write_text(yaml.safe_dump(value))
        return source

    def operator(self):
        core_values = yaml.safe_load(self.core_values.read_text())
        value = {"enabled": True, "namespaces": [self.app_namespace], "samplingRatio": "1",
            "gateway": {"sourceRelease": "elven-a", "sourceNamespace": self.namespace,
                        "endpoint": f"https://elven-a-gateway.{self.namespace}.svc.cluster.local:4318"},
            "runtimes": {"java": False, "nodejs": True, "python": False, "nodejs20": False, "legacyNode20Approved": False},
            "images": {name: {k: v for k, v in image.items() if k in ("repository", "tag", "digest")}
                       for name, image in self.sdk_images.items()},
            "networkPolicy": {"enabled": True, "apiServerCIDRs": core_values["networkPolicy"]["apiServerCIDRs"]}}
        path = self.directory / "operator-values.yaml"
        path.write_text(yaml.safe_dump(value))
        uid = self.get("namespace", "kube-system", "default")["metadata"]["uid"]
        CORE.execute([sys.executable, self.payload / "scripts/instrumentation.py", "install", "--release", "elven-hybrid-operator",
                      "--namespace", self.namespace, "--context", "kind-" + self.name, "--kubeconfig", self.kubeconfig,
                      "--expect-cluster-uid", uid, "--values", path, "--development-images"], timeout=1000)

    def apps(self):
        pin = json.loads((ROOT / "tests/instrumentation-fixtures/fixtures.json").read_text())["images"]["node22"]
        context = self.directory / "go-fixture"
        context.mkdir()
        for name in ("Dockerfile.go", "app.go"):
            (context / name).write_text((ROOT / "tests/instrumentation-fixtures/multilang" / name).read_text())
        go_image = "elven-disposable/hybrid-go:" + self.name
        CORE.execute(["docker", "build", "--file", context / "Dockerfile.go", "--tag", go_image, context], timeout=600)
        CORE.execute(["kind", "load", "docker-image", go_image, "--name", self.name], timeout=240)
        self.apply({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "hybrid-node-code", "namespace": self.app_namespace},
                    "data": {"main.js": (ROOT / "tests/instrumentation-fixtures/main.js").read_text()}})
        security = {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001, "readOnlyRootFilesystem": True,
                    "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}
        for name, image, sdk in ((SDK_NAME, pin, True), (BPF_NAME, go_image, False)):
            meta = {"labels": {"app": name, "app.kubernetes.io/name": name}, "annotations": {}}
            container = {"name": "application", "image": image, "imagePullPolicy": "IfNotPresent" if sdk else "Never",
                "securityContext": security, "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"cpu": "1", "memory": "512Mi"}},
                "readinessProbe": {"httpGet": {"path": "/ready", "port": 8080}, "periodSeconds": 2}, "volumeMounts": []}
            volumes = []
            if sdk:
                meta["labels"]["elven.observability/inject"] = "nodejs"
                meta["annotations"] = {"elven.observability/container-name": "application", "elven.observability/service-name": SDK_NAME}
                container.update(command=["node", "/code/main.js"], volumeMounts=[{"name": "code", "mountPath": "/code", "readOnly": True}])
                volumes = [{"name": "code", "configMap": {"name": "hybrid-node-code"}}]
            self.apply({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name, "namespace": self.app_namespace},
                "spec": {"replicas": 1, "selector": {"matchLabels": {"app": name}}, "template": {"metadata": meta,
                    "spec": {"automountServiceAccountToken": False, "nodeName": self.node_name, "securityContext": {"fsGroup": 10001},
                             "containers": [container], "volumes": volumes}}}})
            self.kube("rollout", "status", "deployment/" + name, "-n", self.app_namespace, "--timeout=240s", timeout=260)
        self.app_pods = {}
        for name in (SDK_NAME, BPF_NAME):
            pod = json.loads(self.kube("get", "pods", "-n", self.app_namespace, "-l", "app=" + name, "-o", "json").stdout)["items"][0]
            injected = pod["metadata"].get("annotations", {}).get("elven.observability/injected")
            if (name == SDK_NAME and injected != "nodejs") or (name == BPF_NAME and (injected or pod["spec"].get("initContainers"))):
                raise AssertionError("SDK selection/injection was not exact and disjoint")
            if name == SDK_NAME:
                assert_sdk_injection(pod, self.sdk_images["nodejs"]["reference"],
                                     f"https://elven-a-gateway.{self.namespace}.svc.cluster.local:4318")
            elif any(item["name"].startswith("OTEL_") or item["name"] in ("NODE_OPTIONS", "JAVA_TOOL_OPTIONS")
                     for container in pod["spec"]["containers"] for item in container.get("env", [])):
                raise AssertionError("The SDK-less target acquired telemetry loader configuration")
            self.app_pods[name] = pod
        self.check("actual Node22 SDK admission and SDK-less Go deployment are disjoint")

    def snapshot(self):
        return {kind + "/" + name: self.get(kind, name)["metadata"]["uid"] for kind, name in
                (("pvc", "data-elven-a-gateway-0"), ("secret", "elven-ingest"), ("secret", "elven-internal-tls"))}

    def exercise(self):
        trace = uuid.uuid4().hex
        urls = ["http://" + str(ipaddress.ip_address(pod["status"]["podIP"])) + ":8080/exercise" for pod in self.app_pods.values()]
        program = "import urllib.request; urls=" + repr(urls) + "; " + \
            "[(lambda r: r.status==200 or (_ for _ in ()).throw(AssertionError('HTTP fixture failed')))(urllib.request.urlopen(urllib.request.Request(u,headers={'traceparent':'00-" + trace + "-0123456789abcdef-01'}),timeout=10)) for u in urls]"
        self.kube("exec", "deployment/synthetic-customer-app", "-n", self.app_namespace, "--", "python", "-c", program)

    def observed(self, after=0):
        return classify(self.decoded("traces"), after)

    def enable_bpf(self):
        value = yaml.safe_load(self.core_values.read_text())
        value["images"]["beyla"] = {k: v for k, v in self.images["beyla"].items() if k in ("repository", "tag", "digest")}
        value["modules"]["ebpf"] = {"enabled": True, "hostAccessApproved": True, "excludeSDKInstrumentedServices": True,
            "additionalCapabilities": [], "additionalCapabilitiesApproved": False,
            "routePatterns": ["/exercise", "/ready"], "workloads": [{"namespace": self.app_namespace, "deployment": BPF_NAME}]}
        path = self.directory / "hybrid-values.yaml"
        path.write_text(yaml.safe_dump(value))
        stop = threading.Event()
        captured = []
        def diagnostics():
            # The installer may roll back an unready DaemonSet. Capture its
            # actual loader denial before that cleanup removes the worker.
            while not stop.is_set():
                try:
                    text = self.kube("logs", "daemonset/elven-a-node", "-c", "beyla", "-n", self.namespace,
                                     "--tail=25", check=False, timeout=5).stdout[-8000:]
                    if text and (not captured or text != captured[-1]):
                        captured.append(text)
                        del captured[:-5]
                except Exception:
                    pass
                stop.wait(2)
        monitor = threading.Thread(target=diagnostics, daemon=True)
        monitor.start()
        try:
            self.cli("upgrade", path)
        except RuntimeError:
            text = "\n".join(captured)[-16000:]
            self.report["beyla_diagnostics"] = text
            if re.search(r"operation not permitted|missing.*capabilit|permission denied|unsupported kernel", text, re.I):
                raise Unsupported("Actual Beyla loader denied BPF/capability/kernel prerequisites; no fallback used") from None
            raise
        finally:
            stop.set()
            monitor.join(timeout=7)
        ds = self.get("daemonset", "elven-a-node")
        assert_node_scope(ds, self.node_name)
        config = self.get("configmap", "elven-a-node")["data"]["beyla.yaml"]
        parsed = yaml.safe_load(config)
        if parsed["discovery"]["instrument"] != [{"k8s_namespace": self.app_namespace, "k8s_deployment_name": BPF_NAME}] or not parsed["discovery"]["exclude_otel_instrumented_services"]:
            raise AssertionError("The installed Beyla selector is not exactly the disjoint approved workload")
        self.report["beyla_security"] = next(c["securityContext"] for c in ds["spec"]["template"]["spec"]["containers"] if c["name"] == "beyla")
        pods = json.loads(self.kube("get", "pods", "-n", self.namespace, "-l", "app.kubernetes.io/component=node", "-o", "json").stdout)["items"]
        if len(pods) != 1 or pods[0]["spec"]["nodeName"] != self.node_name:
            raise AssertionError("Actual agent scheduling escaped approvedNodes")
        if self.get("node", self.node_name, "default")["metadata"]["uid"] != self.node_uid:
            raise AssertionError("Approved node UID changed")
        self.check("installed ZIP chart retains exact node affinity and disjoint Beyla selector", nodeUid=self.node_uid)

    def red_metrics(self):
        for message in self.decoded("metrics"):
            for resource in message.get("resource_metrics", []):
                identity = attrs(resource.get("resource", {}).get("attributes", []))
                if identity.get("service.name") != BPF_NAME and identity.get("k8s.deployment.name") != BPF_NAME:
                    continue
                for scope in resource.get("scope_metrics", []):
                    for metric in scope.get("metrics", []):
                        if "duration" not in metric.get("name", ""):
                            continue
                        for point in metric.get("histogram", {}).get("data_points", []):
                            labels = attrs(point.get("attributes", []))
                            if (labels.get("http.route") == "/exercise" and str(labels.get("http.response.status_code", labels.get("http.status_code"))) == "200"
                                    and int(point.get("count", 0)) > 0 and point.get("explicit_bounds") and point.get("bucket_counts")):
                                return True
        return False

    def run(self):
        self.boot()
        self.host()
        for image in (self.images["beyla"], self.sdk_images["operator"], self.sdk_images["nodejs"]):
            self.load(image)
        self.tls()
        self.fixture()
        self.core_values = self.install("elven-a", False)
        self.operator()
        self.apps()
        baseline = self.snapshot()
        self.enable_bpf()
        start = time.time_ns()
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            self.exercise()
            observed = self.observed(start)
            if observed["bpf_on_sdk"] or observed["sdk_on_bpf"]:
                assert_disjoint(observed)
            if len(observed["sdk_server"]) >= 3 and len(observed["bpf_server"]) >= 3 and self.red_metrics():
                break
            time.sleep(3)
        else:
            diagnostics = self.kube("logs", "daemonset/elven-a-node", "-c", "beyla", "-n", self.namespace, "--tail=40", check=False).stdout
            self.report["beyla_diagnostics"] = diagnostics[-8000:]
            if re.search(r"operation not permitted|missing.*capabilit|permission denied|unsupported kernel", diagnostics, re.I):
                raise Unsupported("BPF/capability/kernel prerequisites denied actual capture; no fallback used")
            raise AssertionError("Beyla/SDK capture and RED evidence did not arrive within the bounded window")
        assert_disjoint(observed)
        self.report["sdk_bpf_disjoint"] = {k: len(v) if isinstance(v, list) else sorted(v) for k, v in observed.items()}
        self.check("actual SDK and Beyla server spans are disjoint, with real Beyla RED histogram")
        self.cli("rollback", revision=1)
        if self.kube("get", "daemonset/elven-a-node", "-n", self.namespace, "--ignore-not-found", "-o", "json").stdout.strip():
            raise AssertionError("Rollback retained the Beyla DaemonSet")
        self.wait_for(lambda: not json.loads(self.kube("get", "pods", "-n", self.namespace, "-l", "app.kubernetes.io/component=node", "-o", "json").stdout)["items"],
                      "Beyla process Pods terminated after rollback", timeout=120)
        if self.snapshot() != baseline:
            raise AssertionError("Rollback changed Secret or PVC physical identities")
        for name, old in self.app_pods.items():
            now = json.loads(self.kube("get", "pods", "-n", self.app_namespace, "-l", "app=" + name, "-o", "json").stdout)["items"]
            if len(now) != 1 or now[0]["metadata"]["uid"] != old["metadata"]["uid"]:
                raise AssertionError("Rollback restarted an application outside its scope")
        rollback_start = time.time_ns()
        for _ in range(4):
            self.exercise()
        self.wait_for(lambda: bool(self.observed(rollback_start)["sdk_server"]), "fresh SDK telemetry after Beyla rollback")
        time.sleep(15)
        rollback_observed = self.observed(rollback_start)
        assert_disjoint(rollback_observed, require_bpf=False)
        if rollback_observed["bpf_server"]:
            raise AssertionError("New Beyla spans appeared after the worker was removed")
        self.report["rollback"] = {"secretPvcUidsPreserved": True, "applicationPodUidsPreserved": True,
            "beylaWorkerPodsRemaining": 0, "freshSdkSpans": len(rollback_observed["sdk_server"]),
            "freshBeylaSpans": 0, "boundedObservationSeconds": 15, "kernelProbePurge": "NOT_PROVEN"}
        self.check("actual rollback removes Beyla worker, preserves identities and SDK delivery")
        self.report["functional_checks_passed"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--candidate-sha256", required=True)
    parser.add_argument("--core-manifest", type=Path, required=True)
    parser.add_argument("--sdk-manifest", type=Path, required=True)
    parser.add_argument("--node-image", default=CORE.KIND_NODE)
    parser.add_argument("--development-images", action="store_true")
    parser.add_argument("--host-access-approved", action="store_true")
    args = parser.parse_args()
    if not args.development_images or not args.host_access_approved:
        parser.error("Both disposable image and host-access consents are mandatory")
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        parser.error("This harness only runs on a dedicated disposable hosted CI runner")
    lab = HybridLab(args)
    try:
        lab.run()
    except Unsupported as error:
        lab.report.update(result="UNSUPPORTED", error=str(error))
        raise
    except Exception as error:
        lab.report.update(result="FAIL", error=str(error))
        raise
    finally:
        lab.cleanup()
    if not lab.report.get("functional_checks_passed") or lab.report.get("cluster_retained"):
        raise RuntimeError("Functional checks and complete owned-cluster teardown are both required")
    lab.report.update(completed=True, result="PASS_LAB_NOT_RELEASE")
    (lab.directory / "report.json").write_text(json.dumps(lab.report, indent=2) + "\n")
    print(json.dumps(lab.report, sort_keys=True))


if __name__ == "__main__":
    main()
