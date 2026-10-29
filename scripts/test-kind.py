#!/usr/bin/env python3
"""Disposable Kind integration; every Kubernetes/Helm command has an isolated kubeconfig.

Creates only an elven-dist-* Docker Kind cluster. Never uses the caller's active
Kubernetes context. The default Kind CNI does NOT enforce NetworkPolicy: this test
records that limitation and never presents schema validation as enforcement.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import time
import uuid
from pathlib import Path

import yaml
from google.protobuf.json_format import MessageToDict
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "charts/elven-observability"
HELM = os.environ.get("ELVEN_HELM_BINARY", "helm")
KUBECTL = os.environ.get("ELVEN_KUBECTL_BINARY", "kubectl")
KIND_NODE = "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
PYTHON_IMAGE = "python:3.14.0-slim@sha256:0aecac02dc3d4c5dbb024b753af084cafe41f5416e02193f1ce345d671ec966e"
SENTINEL = "SYNTHETIC_PRIVATE_DO_NOT_EXPORT"


def execute(args, data=None, check=True, timeout=300):
    result = subprocess.run([str(arg) for arg in args], input=data, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        # Commands only contain synthetic data, never credential values.
        raise RuntimeError(f"Command failed: {' '.join(str(arg) for arg in args[:6])}\n{result.stdout}\n{result.stderr}")
    return result


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Lab:
    def __init__(self, node_image, keep=False, collector_image=None, collector_archive=None):
        suffix = uuid.uuid4().hex[:10]
        self.name = "elven-dist-" + suffix
        self.namespace = "elven-e2e"
        self.app_namespace = "synthetic-app"
        self.directory = ROOT / ".artifacts" / ("kind-" + suffix)
        self.directory.mkdir(parents=True)
        self.directory.chmod(0o700)
        self.kubeconfig = self.directory / "kubeconfig"
        self.node_image, self.keep = node_image, keep
        self.collector_image, self.collector_archive = collector_image, collector_archive
        self.processes = []
        self.created = False
        self.report = {"completed": False, "cluster": self.name, "node_image": node_image,
            "fixture_image": PYTHON_IMAGE, "customer_cluster_access": False, "checks": [],
            "not_proven": ["NetworkPolicy enforcement (Kind default CNI)",
                "customer network/tenant ingestion", "native amd64 runtime", "eBPF/kernel compatibility",
                "production scale/HA", "all supported Kubernetes versions live"]}
        self.report["collector_image_override"] = collector_image

    def kube(self, *args, data=None, check=True, timeout=240):
        return execute([KUBECTL, "--kubeconfig", self.kubeconfig, "--context", "kind-" + self.name, *args],
                       data=data, check=check, timeout=timeout)

    def helm(self, *args, check=True, timeout=300):
        return execute([HELM, "--kubeconfig", self.kubeconfig, "--kube-context", "kind-" + self.name,
                        "--namespace", self.namespace, *args], check=check, timeout=timeout)

    def apply(self, *objects):
        self.kube("apply", "-f", "-", data=yaml.safe_dump_all(objects))

    def check(self, name, **evidence):
        self.report["checks"].append({"name": name, "result": "passed", **evidence})
        print("PASS", name, flush=True)

    def boot(self):
        if "@sha256:" not in self.node_image:
            raise ValueError("--node-image must be digest-pinned")
        configured_host = os.environ.get("DOCKER_HOST", "")
        endpoint = execute(["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"]).stdout.strip()
        if (configured_host and not configured_host.startswith("unix://")) or not endpoint.startswith("unix://"):
            raise ValueError("The disposable laboratory requires a local Unix Docker socket, never an SSH/TCP customer engine")
        self.created = True  # Cleanup also covers partial Kind creation failures.
        execute(["kind", "create", "cluster", "--name", self.name, "--image", self.node_image,
                 "--kubeconfig", self.kubeconfig, "--wait", "180s"], timeout=420)
        self.kubeconfig.chmod(0o600)
        if self.collector_archive:
            if not self.collector_image or "@sha256:" not in self.collector_image:
                raise ValueError("A local Collector archive requires its exact digest-pinned --collector-image")
            execute(["kind", "load", "image-archive", str(Path(self.collector_archive).resolve()), "--name", self.name], timeout=180)
            tagged, digest = self.collector_image.rsplit("@", 1)
            repository = tagged.rsplit(":", 1)[0]
            imported = execute(["docker", "exec", self.name + "-control-plane", "ctr", "-n", "k8s.io", "images", "ls"]).stdout
            source = next((row.split() for row in imported.splitlines() if row.split() and row.split()[0] == tagged), None)
            if not source or source[2] != digest:
                raise AssertionError("The imported OCI index does not match the supplied Collector image digest")
            # OCI archives preserve their tagged index, but CRI needs an
            # explicit immutable repo-digest alias to avoid a registry pull.
            # The alias points to the exact imported index, not a rebuilt image.
            execute(["docker", "exec", self.name + "-control-plane", "ctr", "-n", "k8s.io", "images", "tag",
                     "--force", tagged, repository + "@" + digest])
            self.check("local Collector OCI archive loaded into only the disposable Kind node", image=self.collector_image)
        version = json.loads(self.kube("version", "-o", "json").stdout)
        self.report["versions"] = version
        self.apply({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": self.namespace}},
                   {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": self.app_namespace}})
        self.check("isolated Kind boot", server=version["serverVersion"]["gitVersion"])

    def tls(self):
        tls = self.directory / "tls"
        tls.mkdir()
        self.tls_dir = tls
        ca, ca_key = tls / "ca.crt", tls / "ca.key"
        execute(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3",
                 "-subj", "/CN=synthetic-elven-kind-ca", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                 "-keyout", ca_key, "-out", ca])
        for name, eku in (("tls", "serverAuth"), ("client", "clientAuth")):
            key, request, cert = tls / (name + ".key"), tls / (name + ".csr"), tls / (name + ".crt")
            execute(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj",
                     "/CN=synthetic-elven-" + name, "-keyout", key, "-out", request])
            ext = tls / (name + ".ext")
            sans = ["localhost", "sink", f"sink.{self.namespace}.svc", f"sink.{self.namespace}.svc.cluster.local"]
            for release in ("elven-a", "elven-b"):
                sans.extend([f"{release}-gateway", f"{release}-gateway.{self.namespace}.svc",
                             f"{release}-gateway.{self.namespace}.svc.cluster.local"])
            ext.write_text("basicConstraints=critical,CA:FALSE\n"
                           "keyUsage=critical,digitalSignature,keyEncipherment\n"
                           "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"
                           "extendedKeyUsage=" + eku + "\nsubjectAltName=IP:127.0.0.1," +
                           ",".join("DNS:" + value for value in sans) + "\n")
            execute(["openssl", "x509", "-req", "-in", request, "-CA", ca, "-CAkey", ca_key,
                     "-CAcreateserial", "-days", "3", "-extfile", ext, "-out", cert])
        for path in tls.iterdir():
            path.chmod(0o600)
        def secret(name, contents):
            return {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": name, "namespace": self.namespace},
                    "type": "Opaque", "stringData": contents}
        self.apply(secret("elven-internal-tls", {name: (tls / name).read_text()
                    for name in ("ca.crt", "tls.crt", "tls.key", "client.crt", "client.key")}),
                   secret("elven-ingest", {"tenant-id": "synthetic-tenant", "api-token": "synthetic-test-token"}),
                   secret("synthetic-export-ca", {"ca.crt": ca.read_text()}))
        self.client_context = ssl.create_default_context(cafile=str(ca))
        self.client_context.load_cert_chain(str(tls / "client.crt"), str(tls / "client.key"))
        self.no_client_context = ssl.create_default_context(cafile=str(ca))
        self.check("synthetic TLS and ingestion Secrets created without argv values")

    def fixture(self):
        labels = {"app": "synthetic-sink"}
        security = {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001,
                    "readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False,
                    "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}
        self.apply(
            {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "customer-observability-sentinel", "namespace": self.namespace},
             "data": {"owner": "synthetic-customer", "preserve": "unchanged"}},
            {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "synthetic-sink-code", "namespace": self.namespace},
             "data": {"sink.py": (ROOT / "tests/sink.py").read_text()}},
            {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "synthetic-sink", "namespace": self.namespace},
             "spec": {"replicas": 1, "selector": {"matchLabels": labels}, "template": {"metadata": {"labels": labels}, "spec": {
                 "automountServiceAccountToken": False, "securityContext": {"fsGroup": 10001},
                 "containers": [{"name": "sink", "image": PYTHON_IMAGE, "command": ["python", "/code/sink.py"],
                    "securityContext": security, "resources": {"requests": {"cpu": "25m", "memory": "32Mi"}, "limits": {"cpu": "500m", "memory": "256Mi"}},
                    "ports": [{"containerPort": 8443}], "readinessProbe": {"tcpSocket": {"port": 8443}},
                    "volumeMounts": [{"name": "code", "mountPath": "/code", "readOnly": True}, {"name": "tls", "mountPath": "/tls", "readOnly": True}]}],
                 "volumes": [{"name": "code", "configMap": {"name": "synthetic-sink-code"}},
                             {"name": "tls", "secret": {"secretName": "elven-internal-tls", "defaultMode": 0o440}}]}}}},
            {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "sink", "namespace": self.namespace},
             "spec": {"selector": labels, "ports": [{"port": 443, "targetPort": 8443}]}})
        self.kube("rollout", "status", "deployment/synthetic-sink", "-n", self.namespace, "--timeout=180s")
        app_labels = {"app": "synthetic-customer-app"}
        self.apply({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "synthetic-app-code", "namespace": self.app_namespace},
                    "data": {"producer.py": (ROOT / "tests/producer.py").read_text()}},
                   {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "synthetic-customer-app", "namespace": self.app_namespace},
                    "spec": {"replicas": 1, "selector": {"matchLabels": app_labels}, "template": {"metadata": {"labels": app_labels}, "spec": {
                        "automountServiceAccountToken": False, "containers": [{"name": "app", "image": PYTHON_IMAGE,
                        "command": ["python", "-u", "/code/producer.py"], "securityContext": security,
                        "resources": {"requests": {"cpu": "25m", "memory": "32Mi"}, "limits": {"cpu": "500m", "memory": "128Mi"}},
                        "readinessProbe": {"tcpSocket": {"port": 8080}},
                        "volumeMounts": [{"name": "code", "mountPath": "/code", "readOnly": True}]}],
                        "volumes": [{"name": "code", "configMap": {"name": "synthetic-app-code"}}]}}}})
        self.kube("rollout", "status", "deployment/synthetic-customer-app", "-n", self.app_namespace, "--timeout=180s")
        self.app_before = json.loads(self.kube("get", "deployment/synthetic-customer-app", "-n", self.app_namespace, "-o", "json").stdout)
        self.sentinel = json.loads(self.kube("get", "configmap/customer-observability-sentinel", "-n", self.namespace, "-o", "json").stdout)
        self.sink_port = self.port_forward("service/sink", 443)
        self.check("synthetic HTTPS sink and customer-owned sentinel ready")

    def kubelet_ca(self):
        nodes = json.loads(self.kube("get", "nodes", "-o", "json").stdout)["items"]
        self.node_ip = next(address["address"] for address in nodes[0]["status"]["addresses"] if address["type"] == "InternalIP")
        # Public serving certificate only; never copy the kubelet private key.
        cert = execute(["docker", "exec", self.name + "-control-plane", "cat", "/var/lib/kubelet/pki/kubelet.crt"]).stdout
        ca = self.directory / "synthetic-kubelet-ca.crt"
        ca.write_text(cert)
        execute(["openssl", "verify", "-purpose", "sslserver", "-verify_hostname", self.name + "-control-plane", "-CAfile", ca, ca])
        self.apply({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "synthetic-kubelet-ca", "namespace": self.namespace},
                    "type": "Opaque", "stringData": {"ca.crt": cert}})
        self.check("Kind kubelet public serving identity trusted with exact SAN/DNS verification",
                   certificate_sha256=hashlib.sha256(cert.encode()).hexdigest())

    def port_forward(self, resource, remote):
        local = free_port()
        log = (self.directory / ("port-forward-" + str(local) + ".log")).open("w")
        args = [KUBECTL, "--kubeconfig", str(self.kubeconfig), "--context", "kind-" + self.name,
                "-n", self.namespace, "port-forward", "--address", "127.0.0.1", resource, f"{local}:{remote}"]
        process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
        self.processes.append((process, log))
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("Fixture port-forward exited")
            with socket.socket() as sock:
                if sock.connect_ex(("127.0.0.1", local)) == 0:
                    return local
            time.sleep(0.1)
        raise RuntimeError("Fixture port-forward not ready")

    def request(self, port, path, payload=None, context=None, token="synthetic-test-token"):
        connection = http.client.HTTPSConnection("127.0.0.1", port, context=context or self.client_context, timeout=10)
        try:
            headers = {"Content-Type": "application/json"}
            if token is not None:
                headers["Authorization"] = "Bearer " + token
            connection.request("GET" if payload is None else "POST", path,
                               None if payload is None else json.dumps(payload).encode(), headers)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def state(self):
        status, raw = self.request(self.sink_port, "/state")
        assert status == 200
        return json.loads(raw)

    def control(self, status):
        result, _ = self.request(self.sink_port, "/control", {"status": status})
        assert result == 200

    def decoded(self, signal):
        types = {"logs": ExportLogsServiceRequest, "metrics": ExportMetricsServiceRequest, "traces": ExportTraceServiceRequest}
        messages = []
        for capture in self.state()["accepted"]:
            if not capture["path"].endswith("/" + signal):
                continue
            message = types[signal]()
            message.ParseFromString(base64.b64decode(capture["body"]))
            messages.append(MessageToDict(message, preserving_proto_field_name=True))
        return messages

    def logs(self):
        return [record for payload in self.decoded("logs") for resource in payload.get("resource_logs", [])
                for scope in resource.get("scope_logs", []) for record in scope.get("log_records", [])]

    def wait_for(self, predicate, description, timeout=90):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.5)
        raise AssertionError("Timeout: " + description)

    def provision(self, release):
        # A deterministic synthetic hostPath PV lives only inside this Kind node.
        # Explicit directory ownership models a filesystem-backed volume for UID10001.
        directory = "/var/local/" + self.name + "/" + release
        execute(["docker", "exec", self.name + "-control-plane", "mkdir", "-p", directory])
        execute(["docker", "exec", self.name + "-control-plane", "chown", "10001:10001", directory])
        execute(["docker", "exec", self.name + "-control-plane", "chmod", "0700", directory])
        self.apply({"apiVersion": "storage.k8s.io/v1", "kind": "StorageClass", "metadata": {"name": "synthetic-elven-static"},
                    "provisioner": "kubernetes.io/no-provisioner", "volumeBindingMode": "WaitForFirstConsumer"},
                   {"apiVersion": "v1", "kind": "PersistentVolume", "metadata": {"name": self.name + "-" + release},
                    "spec": {"capacity": {"storage": "2Gi"}, "accessModes": ["ReadWriteOnce"],
                       "persistentVolumeReclaimPolicy": "Retain", "storageClassName": "synthetic-elven-static",
                       "claimRef": {"namespace": self.namespace, "name": "data-" + release + "-gateway-0"},
                       "hostPath": {"path": directory, "type": "Directory"},
                       "nodeAffinity": {"required": {"nodeSelectorTerms": [{"matchExpressions": [
                           {"key": "kubernetes.io/hostname", "operator": "In", "values": [self.name + "-control-plane"]}]}]}}}})

    def values(self, release, cluster_metrics):
        service = json.loads(self.kube("get", "service/sink", "-n", self.namespace, "-o", "json").stdout)
        pod = json.loads(self.kube("get", "pods", "-n", self.namespace, "-l", "app=synthetic-sink", "-o", "json").stdout)["items"][0]
        cidrs = [service["spec"]["clusterIP"] + "/32", pod["status"]["podIP"] + "/32"]
        api = json.loads(self.kube("get", "service/kubernetes", "-n", "default", "-o", "json").stdout)
        endpoints = json.loads(self.kube("get", "endpoints/kubernetes", "-n", "default", "-o", "json").stdout)
        api_cidrs = [api["spec"]["clusterIP"] + "/32"] + [address["ip"] + "/32"
                      for subset in endpoints["subsets"] for address in subset["addresses"]]
        settings = {"cluster": {"name": "synthetic-kind", "environment": "test"},
            "gateway": {"persistence": {"storageClass": "synthetic-elven-static"}},
            "collection": {"namespaces": [self.app_namespace]},
            "modules": {"clusterMetrics": {"enabled": cluster_metrics},
                        "logs": {"enabled": cluster_metrics, "hostAccessApproved": cluster_metrics},
                        "kubeletMetrics": {"enabled": cluster_metrics, "caSecretName": "synthetic-kubelet-ca", "endpointAddress": "hostname"}},
            "nodeAgent": {"hostAliases": [{"ip": self.node_ip, "hostnames": [self.name + "-control-plane"]}]},
            "endpoints": {signal: f"https://sink.{self.namespace}.svc/{'http/v1' if signal == 'traces' else 'otlp/v1'}/{signal}"
                          for signal in ("logs", "metrics", "traces")},
            "exportTLS": {"existingCASecret": "synthetic-export-ca"},
            "networkPolicy": {"exportCIDRs": cidrs, "exportPorts": [443, 8443], "apiServerCIDRs": api_cidrs,
                              "kubeletCIDRs": [self.node_ip + "/32"]}}
        if self.collector_image:
            if "@sha256:" not in self.collector_image:
                raise ValueError("--collector-image must contain its immutable digest")
            tagged, digest = self.collector_image.rsplit("@", 1)
            repository, tag = tagged.rsplit(":", 1)
            settings["images"] = {"collector": {"repository": repository, "tag": tag, "digest": digest}}
        source = self.directory / (release + "-values.yaml")
        source.write_text(yaml.safe_dump(settings))
        return source

    def install(self, release, cluster_metrics=False):
        self.provision(release)
        source = self.values(release, cluster_metrics)
        self.helm("install", release, str(CHART), "-f", str(source), "--wait", "--timeout", "240s")
        installed = self.helm("get", "manifest", release).stdout
        self.check("clean Helm install " + release, manifest_sha256=hashlib.sha256(installed.encode()).hexdigest())
        return source

    def cli(self, command, values=None):
        uid = json.loads(self.kube("get", "namespace/kube-system", "-o", "json").stdout)["metadata"]["uid"]
        args = [sys.executable, str(ROOT / "elven"), command, "--release", "elven-a", "--namespace", self.namespace,
                "--context", "kind-" + self.name, "--kubeconfig", str(self.kubeconfig),
                "--expect-cluster-uid", uid, "--cluster-name", "synthetic-kind", "--use-existing-secrets",
                "--credentials-secret", "elven-ingest", "--tls-secret", "elven-internal-tls", "--development-images"]
        if values:
            args.extend(["--values", str(values)])
        return execute(args)

    def send(self, gateway_port, signal, level=17):
        resource = {"attributes": [{"key": "service.name", "value": {"stringValue": "synthetic-app"}},
                                    {"key": "k8s.namespace.name", "value": {"stringValue": self.app_namespace}}]}
        now = str(time.time_ns())
        if signal == "logs":
            payload = {"resourceLogs": [{"resource": resource, "scopeLogs": [{"logRecords": [{
                "timeUnixNano": now, "severityNumber": level, "severityText": SENTINEL, "body": {"stringValue": SENTINEL},
                "attributes": [{"key": "email", "value": {"stringValue": "synthetic@example.invalid"}}]}]}]}]}
        elif signal == "traces":
            payload = {"resourceSpans": [{"resource": resource, "scopeSpans": [{"spans": [{
                "traceId": "112233445566778899aabbccddeeff00", "spanId": "1122334455667788", "name": SENTINEL,
                "kind": 2, "startTimeUnixNano": now, "endTimeUnixNano": str(int(now) + 123000000),
                "attributes": [{"key": "http.request.method", "value": {"stringValue": "GET"}}],
                "status": {"message": SENTINEL},
                "events": [{"timeUnixNano": now, "name": SENTINEL, "attributes": [
                    {"key": "exception.message", "value": {"stringValue": SENTINEL}}]}],
                "links": [{"traceId": "ffeeddccbbaa99887766554433221100", "spanId": "8877665544332211",
                    "attributes": [{"key": "email", "value": {"stringValue": SENTINEL}}]}]}]}]}]}
        else:
            payload = {"resourceMetrics": [{"resource": resource, "scopeMetrics": [{"metrics": [{
                "name": "synthetic_e2e_gauge", "gauge": {"dataPoints": [{"asDouble": 42, "timeUnixNano": now}]}}]}]}]}
        status, response = self.request(gateway_port, "/v1/" + signal, payload)
        assert status == 200, (signal, status, response[:700].decode(errors="replace"))

    def run(self):
        self.boot()
        self.tls()
        self.fixture()
        self.kubelet_ca()
        conflict = {"apiVersion": "v1", "kind": "ConfigMap",
                    "metadata": {"name": "elven-collision-gateway", "namespace": self.namespace},
                    "data": {"owner": "synthetic-customer-must-not-be-adopted"}}
        self.apply(conflict)
        collision_values = self.values("elven-collision", False)
        collision = self.helm("install", "elven-collision", str(CHART), "-f", str(collision_values),
                              "--wait", "--timeout", "15s", check=False)
        assert collision.returncode != 0 and "ownership" in (collision.stderr + collision.stdout).lower()
        preserved = json.loads(self.kube("get", "configmap/elven-collision-gateway", "-n", self.namespace, "-o", "json").stdout)
        assert preserved["data"] == conflict["data"]
        assert preserved["metadata"].get("labels", {}).get("app.kubernetes.io/managed-by") != "Helm"
        self.check("existing customer resource with the intended name is rejected, not adopted")
        values = self.install("elven-a", cluster_metrics=True)
        self.cli("preflight", values)
        self.cli("status")
        self.cli("upgrade", values)
        self.check("actual Elven CLI preflight status and upgrade succeed with explicit context UID and existing mTLS Secrets")
        self.gateway_port = self.port_forward("service/elven-a-gateway", 4318)
        for signal in ("logs", "metrics", "traces"):
            self.send(self.gateway_port, signal)
        self.wait_for(lambda: all(self.decoded(signal) for signal in ("logs", "metrics", "traces")), "positive delivery of all OTLP signals")
        assert self.logs()[0]["body"]["string_value"] == "[REDACTED]"
        exported = json.dumps({signal: self.decoded(signal) for signal in ("logs", "metrics", "traces")})
        assert SENTINEL not in exported and "synthetic@example.invalid" not in exported
        assert all(capture["tenant"] == "synthetic-tenant" and capture["authorization_valid"] for capture in self.state()["accepted"])
        self.check("positive OTLP logs metrics traces; privacy and outbound tenant/auth headers verified")
        # A rejected TLS handshake can close the entire kubectl port-forward
        # stream. Negative probes must not reuse the positive-delivery tunnel.
        no_client_port = self.port_forward("service/elven-a-gateway", 4318)
        try:
            self.request(no_client_port, "/v1/logs", {}, context=self.no_client_context)
        except ssl.SSLError:
            self.check("mTLS rejects a client without a certificate")
        else:
            raise AssertionError("Gateway accepted a client without mTLS certificate")
        untrusted_ca_port = self.port_forward("service/elven-a-gateway", 4318)
        try:
            self.request(untrusted_ca_port, "/v1/logs", {}, context=ssl.create_default_context())
        except ssl.SSLCertVerificationError:
            self.check("untrusted server CA fails certificate verification")
        else:
            raise AssertionError("Untrusted server CA was accepted")
        status, _ = self.request(self.sink_port, "/state", token="wrong-synthetic-token")
        assert status == 401
        self.check("synthetic backend rejects invalid Bearer credentials")
        def own_metrics():
            return any(metric["name"].startswith("k8s.") for payload in self.decoded("metrics")
                for resource in payload.get("resource_metrics", []) for scope in resource.get("scope_metrics", [])
                for metric in scope.get("metrics", []))
        self.wait_for(own_metrics, "own Kubernetes API metrics", timeout=120)
        self.check("own cluster reader exports Kubernetes API metrics without customer Prometheus")
        def kubelet_metrics():
            return any(metric["name"].startswith(("container.cpu", "container.memory", "k8s.pod.cpu", "k8s.pod.memory"))
                for payload in self.decoded("metrics") for resource in payload.get("resource_metrics", [])
                for scope in resource.get("scope_metrics", []) for metric in scope.get("metrics", []))
        self.wait_for(kubelet_metrics, "verified-TLS native kubelet metrics", timeout=120)
        self.check("own kubelet collector exports usage metrics with verified TLS, not skip_verify")
        before = len(self.logs())
        self.kube("exec", "deployment/synthetic-customer-app", "-n", self.app_namespace, "--", "python", "-c",
                  "import urllib.request; r=urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8080/emit',data=b'x')); assert r.status==200")
        self.wait_for(lambda: len(self.logs()) > before, "CRI stdout delivery without SDK or customer gateway")
        assert all(record["body"]["string_value"] == "[REDACTED]" for record in self.logs()[before:])
        self.check("node log collector reads actual CRI stdout and exports sanitized data without application SDK")
        for account, verb, resource, expected in (("elven-a-gateway", "list", "secrets", "no"),
                ("elven-a-cluster-metrics", "list", "pods", "yes"),
                ("elven-a-cluster-metrics", "create", "deployments", "no")):
            target_namespace = self.app_namespace if resource == "pods" else self.namespace
            result = self.kube("auth", "can-i", verb, resource, "-n", target_namespace,
                               "--as=system:serviceaccount:" + self.namespace + ":" + account, check=False)
            assert result.stdout.strip() == expected, (account, verb, resource, result.stdout)
        self.check("runtime RBAC denies Secret access and writes; cluster-reader Pod discovery allowed")
        before = len(self.logs())
        attempts = self.state()["attempts"].get("/otlp/v1/logs", 0)
        self.control(503)
        self.send(self.gateway_port, "logs", level=13)
        self.wait_for(lambda: self.state()["attempts"].get("/otlp/v1/logs", 0) > attempts, "503 export attempt")
        time.sleep(40)
        assert len(self.logs()) == before
        self.control(200)
        self.wait_for(lambda: len(self.logs()) == before + 1, "original record after 40s outage", timeout=70)
        self.check("original log survives outage longer than 30 seconds without new input")
        before = len(self.logs())
        attempts = self.state()["attempts"].get("/otlp/v1/logs", 0)
        self.control(503)
        self.send(self.gateway_port, "logs", level=9)
        self.wait_for(lambda: self.state()["attempts"].get("/otlp/v1/logs", 0) > attempts, "pending record persisted")
        queue_directory = "/var/local/" + self.name + "/elven-a/exports"
        for forbidden in (SENTINEL, "synthetic@example.invalid", "synthetic-test-token"):
            found = execute(["docker", "exec", self.name + "-control-plane", "grep", "--recursive",
                             "--binary-files=text", "--fixed-strings", "--quiet", forbidden, queue_directory], check=False)
            assert found.returncode == 1, "Private marker or credential found in the persistent queue, or queue inspection failed"
        sanitized = execute(["docker", "exec", self.name + "-control-plane", "grep", "--recursive",
                             "--binary-files=text", "--fixed-strings", "--quiet", "[REDACTED]", queue_directory], check=False)
        assert sanitized.returncode == 0, "Queue inspection must observe real persisted sanitized data"
        self.check("persistent queue contains sanitized data, not private body/link sentinels or exporter token")
        pod = json.loads(self.kube("get", "pod/elven-a-gateway-0", "-n", self.namespace, "-o", "json").stdout)
        claim = json.loads(self.kube("get", "pvc/data-elven-a-gateway-0", "-n", self.namespace, "-o", "json").stdout)
        self.kube("delete", "pod/elven-a-gateway-0", "-n", self.namespace, "--grace-period=0", "--force", "--wait=true")
        self.control(200)
        self.kube("rollout", "status", "statefulset/elven-a-gateway", "-n", self.namespace, "--timeout=180s")
        self.wait_for(lambda: len(self.logs()) == before + 1, "replay after Pod recreation", timeout=70)
        new_pod = json.loads(self.kube("get", "pod/elven-a-gateway-0", "-n", self.namespace, "-o", "json").stdout)
        new_claim = json.loads(self.kube("get", "pvc/data-elven-a-gateway-0", "-n", self.namespace, "-o", "json").stdout)
        assert new_pod["metadata"]["uid"] != pod["metadata"]["uid"]
        assert new_claim["metadata"]["uid"] == claim["metadata"]["uid"]
        self.check("persistent sanitized queue replays after forced Pod recreation with the same PVC")
        upgraded_chart = self.directory / "upgraded-chart"
        shutil.copytree(CHART, upgraded_chart)
        metadata = yaml.safe_load((upgraded_chart / "Chart.yaml").read_text())
        previous_version = metadata["version"]
        metadata["version"] = "1.0.1-rc.1"
        metadata["appVersion"] = "1.0.1-rc.1"
        (upgraded_chart / "Chart.yaml").write_text(yaml.safe_dump(metadata))
        self.helm("upgrade", "elven-a", str(upgraded_chart), "-f", str(values), "--set", "ports.health=23133", "--wait", "--timeout", "180s")
        self.check("upgrade with changed chart version and health port succeeds without changing immutable PVC labels",
                   previous_chart_version=previous_version, new_chart_version=metadata["version"])
        history_before = json.loads(self.helm("history", "elven-a", "-o", "json").stdout)
        failed = self.helm("upgrade", "elven-a", str(CHART), "-f", str(values), "--set", "ports.otlpHttp=70000", check=False)
        assert failed.returncode != 0 and "schema" in (failed.stderr + failed.stdout).lower()
        history_after = json.loads(self.helm("history", "elven-a", "-o", "json").stdout)
        assert history_after == history_before
        self.check("invalid configuration rejected by Helm before apply")
        self.helm("rollback", "elven-a", "1", "--wait", "--timeout", "180s")
        self.check("Helm rollback restores the prior revision")
        self.install("elven-b")
        current = json.loads(self.kube("get", "configmap/customer-observability-sentinel", "-n", self.namespace, "-o", "json").stdout)
        assert current["metadata"]["uid"] == self.sentinel["metadata"]["uid"] and current["data"] == self.sentinel["data"]
        app_after = json.loads(self.kube("get", "deployment/synthetic-customer-app", "-n", self.app_namespace, "-o", "json").stdout)
        assert app_after["metadata"]["uid"] == self.app_before["metadata"]["uid"] and app_after["spec"] == self.app_before["spec"]
        self.check("two releases coexist without overwriting customer-owned sentinel")
        for release in ("elven-b", "elven-a"):
            self.helm("uninstall", release, "--wait", "--timeout", "180s")
        retained = json.loads(self.kube("get", "pvc", "-n", self.namespace, "-o", "json").stdout)["items"]
        assert len(retained) == 2
        self.kube("get", "configmap/customer-observability-sentinel", "-n", self.namespace)
        self.check("uninstall preserves both PVCs and customer-owned sentinel")
        self.report["completed"] = True

    def cleanup(self):
        if self.created and self.kubeconfig.exists():
            try:
                diagnostics = self.kube("get", "pods,pvc,events", "-n", self.namespace, "-o", "wide", check=False).stdout
                for resource in ("statefulset/elven-a-gateway", "deployment/elven-a-cluster-metrics"):
                    output = self.kube("logs", resource, "-n", self.namespace, "--tail=30", check=False).stdout
                    diagnostics += "\n" + resource + " synthetic runtime logs:\n" + output
                diagnostics = diagnostics.replace("synthetic-test-token", "[REDACTED:SYNTHETIC_TOKEN]")
            except Exception as error:
                diagnostics = "Unable to obtain disposable-cluster diagnostics: " + str(error)
            (self.directory / "diagnostics.txt").write_text(diagnostics)
        for process, log in self.processes:
            process.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=5)
            if process.poll() is None:
                process.kill()
            log.close()
        self.report["cluster_retained"] = self.created
        try:
            if self.created and not self.keep:
                # Kind also edits kubeconfig during deletion. Pass the same
                # private file used at creation, never $KUBECONFIG or ~/.kube/config.
                # CI deliberately sets KUBECONFIG=/dev/null, whose adjacent lock
                # file is not writable by an unprivileged runner.
                execute(["kind", "delete", "cluster", "--name", self.name,
                         "--kubeconfig", self.kubeconfig], timeout=180)
                self.report["cluster_retained"] = False
        except Exception as error:
            self.report["cleanup_error"] = str(error)
            raise
        finally:
            # Preserve functional results even when teardown fails. The exception
            # still fails CI, and retained=True records incomplete cleanup.
            (self.directory / "report.json").write_text(json.dumps(self.report, indent=2) + "\n")
            print("Evidence:", self.directory / "report.json", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-image", default=KIND_NODE)
    parser.add_argument("--keep", action="store_true", help="Keep only this disposable Kind cluster for diagnosis")
    parser.add_argument("--collector-image", default=os.environ.get("ELVEN_COLLECTOR_IMAGE"), help="Exact digest-pinned local/published Collector image to exercise")
    parser.add_argument("--collector-image-archive", help="Load this local OCI archive only into this disposable Kind cluster")
    parser.add_argument("--development-images", action="store_true", help="Explicitly acknowledge an unpromoted disposable laboratory image test")
    args = parser.parse_args()
    if not args.development_images:
        parser.error("Disposable laboratory runs require --development-images; this is not a production installation")
    lab = Lab(args.node_image, args.keep, args.collector_image, args.collector_image_archive)
    try:
        lab.run()
    except Exception as error:
        lab.report["error"] = str(error)
        raise
    finally:
        lab.cleanup()


if __name__ == "__main__":
    main()
