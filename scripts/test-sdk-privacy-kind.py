#!/usr/bin/env python3
"""Real injected SDK -> raw mTLS control, then owned Collector -> HTTPS sink.

Two fully disposable hosted Kind clusters. Never an OTLP corpus generator,
release promotion, customer installer or permission to use a shared cluster.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import sys
from types import SimpleNamespace
import uuid

import yaml

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/sdk-privacy-fixtures"


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


SDK = module("sdk_privacy_injection_lab", "scripts/test-instrumentation-kind.py")
HYBRID = module("sdk_privacy_archives", "scripts/test-hybrid-candidate.py")
CORE = SDK.CORE
CASES = ("java17", "java21", "node22")


def attributes(items):
    return {item["key"]: next(iter(item["value"].values()), None) for item in items}


def check_capture(service_spans, private, *, sanitized, required_traces=None):
    """Fail-closed oracle; unit use is not evidence of application execution."""
    summary = {}
    for case in CASES:
        spans = service_spans.get(case, [])
        if required_traces:
            spans = [(scope, span) for scope, span in spans if span.get("trace_id") in required_traces[case]]
        if not spans:
            raise AssertionError("Missing SDK spans: " + case)
        if sanitized and any(value in json.dumps(spans) for value in private["forbidden"]):
            raise AssertionError("Known private sentinel crossed the actual Collector: " + case)
        java = case.startswith("java")
        sql_scope = "io.opentelemetry.jdbc" if java else "@opentelemetry/instrumentation-pg"
        # Pinned Java agent v2.33.1 JedisSingletons.java for Jedis 4+:
        # INSTRUMENTATION_NAME = "io.opentelemetry.jedis-4.0".
        redis_scopes = {"io.opentelemetry.jedis-1.4", "io.opentelemetry.jedis-3.0", "io.opentelemetry.jedis-4.0"} if java else {
            "@opentelemetry/instrumentation-redis", "@opentelemetry/instrumentation-redis-4"}
        server_scope = "io.opentelemetry.java-http-server" if java else "@opentelemetry/instrumentation-http"
        servers = [s for scope, s in spans if scope == server_scope and s.get("kind") in (2, "SPAN_KIND_SERVER")]
        sql = [s for scope, s in spans if scope == sql_scope and s.get("kind") in (3, "SPAN_KIND_CLIENT")]
        redis = [s for scope, s in spans if scope in redis_scopes and s.get("kind") in (3, "SPAN_KIND_CLIENT")]
        exceptions = [s for _, s in spans if s.get("name") == "elven.privacy.exception"]
        if not servers or not sql or not redis or not exceptions:
            raise AssertionError("Missing real HTTP/SQL/Redis/exception SDK capture: " + case)
        for name, client_spans in (("SQL", sql), ("Redis", redis)):
            if not any(span.get("status", {}).get("code") in (2, "STATUS_CODE_ERROR") for span in client_spans):
                raise AssertionError("Real " + name + " client error status missing: " + case)
        statements = [attributes(s.get("attributes", [])).get(key, "") for s in sql for key in ("db.statement", "db.query.text")]
        if not any("SELECT" in value.upper() for value in statements if isinstance(value, str)):
            raise AssertionError("SQL query shape was not preserved: " + case)
        operations = []
        for span in redis:
            values = attributes(span.get("attributes", []))
            operation = values.get("db.operation.name", values.get("db.operation"))
            if operation is None:
                match = re.fullmatch(r"(?:redis\s+)?(SET|GET)(?:\s+.*)?", span.get("name", ""), re.I)
                operation = match.group(1) if match else ""
            operations.append(str(operation).upper())
        if not {"SET", "GET"}.issubset(operations):
            raise AssertionError("Real Redis SET/GET operations were lost: " + case)
        diagnostics = set()
        for exception in exceptions:
            if not any(server.get("trace_id") == exception.get("trace_id") and server.get("span_id") == exception.get("parent_span_id") for server in servers):
                raise AssertionError("SDK exception is not a child of the real HTTP server span: " + case)
            context = attributes(exception.get("attributes", []))
            if context.get("http.route") != "/exercise" or context.get("http.request.method") != "GET" or context.get("http.response.status_code") != 502:
                raise AssertionError("Exception HTTP diagnostic context was lost: " + case)
            if exception.get("status", {}).get("code") not in (2, "STATUS_CODE_ERROR"):
                raise AssertionError("SDK error status was lost: " + case)
            events = [attributes(e.get("attributes", [])) for e in exception.get("events", []) if e.get("name") == "exception"]
            if not events:
                raise AssertionError("Real recordException event missing: " + case)
            for event in events:
                kind, message, stack = (event.get("exception." + name, "") for name in ("type", "message", "stacktrace"))
                if kind != ("java.lang.IllegalStateException" if java else "Error"):
                    raise AssertionError("Exception type was altered: " + case)
                if "checkout failed" not in message or "retry=false" not in message or "exercise" not in stack:
                    raise AssertionError("Useful exception message/frames were removed: " + case)
                if sanitized:
                    if "[REDACTED]" not in message or "[REDACTED]" not in stack:
                        raise AssertionError("Selective masking was not demonstrated: " + case)
                elif not all(value in message and value in stack for value in (private["email"], private["exceptionSecret"])):
                    raise AssertionError("RAW SDK positive control did not contain known exception sentinels: " + case)
                expected_message = message.replace(private["email"], "[REDACTED]").replace(private["exceptionSecret"], "[REDACTED]")
                frames = stack.splitlines()[1:]
                if len(frames) < 2 or not any("fetchPrice" in line for line in frames) or not any("exercise" in line for line in frames):
                    raise AssertionError("Required real exception application frames were lost: " + case)
                # Only a digest leaves the raw phase. Comparison across identical
                # app images proves full frame/message preservation, not merely
                # presence of one useful word after blanket redaction.
                diagnostics.add(hashlib.sha256(json.dumps([kind, expected_message, frames]).encode()).hexdigest())
        summary[case] = {"httpServerSpans": len(servers), "sqlClientSpans": len(sql), "redisClientSpans": len(redis),
                         "exceptionSpans": len(exceptions), "selectiveMasking": sanitized,
                         "selectiveDiagnosticDigests": sorted(diagnostics),
                         "realSdkScopes": sorted({scope for scope, _ in spans})}
    return summary


class PrivacyLab(SDK.InstrumentationLab):
    def __init__(self, args, fixtures=None):
        super().__init__(args)
        directory = self.directory.with_name("sdk-privacy-" + self.directory.name)
        self.directory.rename(directory)
        self.directory, self.kubeconfig = directory, directory / "kubeconfig"
        self.fixture_images = dict(fixtures or {})
        self.pins = json.loads((FIXTURES / "fixtures.json").read_text())
        self.report.update(test="real SDK SQL Redis exceptions privacy", completed=False,
                           input_origin="actual_sdk_injected_application_execution", customer_acceptance=False)
        self.report["runtime_coverage"] = {case: {} for case in CASES}
        self.request_traces = {case: set() for case in CASES}

    def prepare_fixtures(self):
        if not self.fixture_images:
            context = self.directory / "apps"
            shutil.copytree(FIXTURES, context)
            CORE.execute([sys.executable, context / "prepare.py", "--directory", context], timeout=180)
            for case in CASES:
                tag = "elven-disposable/sdk-privacy-" + case + ":" + self.name
                CORE.execute(["docker", "build", "--file", context / ("Dockerfile." + case), "--tag", tag, context], timeout=600)
                self.fixture_images[case] = tag
        for tag in self.fixture_images.values():
            CORE.execute(["kind", "load", "docker-image", tag, "--name", self.name], timeout=240)
        self.report["fixture_sources"] = self.pins

    def databases(self):
        for name, port, image, uid, command, env, mounts in (
            ("redis", 6379, self.pins["dbImages"]["redis"], 10001,
             ["redis-server", "--save", "", "--appendonly", "no", "--protected-mode", "no"], [], []),
            ("postgres", 5432, self.pins["dbImages"]["postgres"], 999, None,
             [{"name": "POSTGRES_PASSWORD", "value": "synthetic-db-password"}, {"name": "POSTGRES_USER", "value": "synthetic"},
              {"name": "POSTGRES_DB", "value": "synthetic"}, {"name": "PGDATA", "value": "/data/pg"}],
             [{"name": name, "mountPath": path} for name, path in (("data", "/data"), ("tmp", "/tmp"), ("run", "/var/run/postgresql"))]),
        ):
            if "@sha256:" not in image:
                raise ValueError("Database fixture must have an immutable official digest")
            container = {"name": name, "image": image, "ports": [{"containerPort": port}], "env": env,
                "securityContext": {"runAsUser": uid, "runAsGroup": uid, "runAsNonRoot": True, "readOnlyRootFilesystem": True,
                                    "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}},
                "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"cpu": "1", "memory": "512Mi"}},
                "volumeMounts": mounts, "readinessProbe": {"tcpSocket": {"port": port}, "periodSeconds": 2}}
            if command:
                container["command"] = command
            self.apply({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name, "namespace": self.app_namespace},
                "spec": {"replicas": 1, "selector": {"matchLabels": {"fixture-db": name}}, "template": {
                    "metadata": {"labels": {"fixture-db": name}}, "spec": {"automountServiceAccountToken": False,
                        "securityContext": {"fsGroup": uid}, "containers": [container],
                        "volumes": [{"name": mount["name"], "emptyDir": {"sizeLimit": "128Mi"}} for mount in mounts]}}}},
                {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name, "namespace": self.app_namespace},
                 "spec": {"selector": {"fixture-db": name}, "ports": [{"port": port, "targetPort": port}]}})
            self.kube("rollout", "status", "deployment/" + name, "-n", self.app_namespace, "--timeout=180s", timeout=200)

    def app(self, name, case, runtime=None, namespace=None, sidecar=False):
        obj = super().app(name, case, runtime, namespace, False)
        obj["spec"]["containers"][0]["env"] = [{"name": key, "value": value} for key, value in {
            "REDIS_HOST": "redis", "REDIS_PORT": "6379", "PGHOST": "postgres", "PGPORT": "5432",
            "PGDATABASE": "synthetic", "PGUSER": "synthetic", "PGPASSWORD": "synthetic-db-password"}.items()]
        return obj

    def exercise(self):
        for case in CASES:
            pod = json.loads(self.kube("get", "pod/" + case, "-n", self.app_namespace, "-o", "json").stdout)
            trace = uuid.uuid4().hex
            # Exported OTLP JSON encodes bytes as base64, not hexadecimal.
            import base64
            self.request_traces[case].add(base64.b64encode(bytes.fromhex(trace)).decode())
            program = "import urllib.request,urllib.error,json; req=urllib.request.Request('http://" + pod["status"]["podIP"] + ":8080/exercise',headers={'traceparent':'00-" + trace + "-0123456789abcdef-01'}); "
            program += "\ntry: r=urllib.request.urlopen(req,timeout=30)\nexcept urllib.error.HTTPError as e: r=e\n"
            program += "d=json.load(r); assert r.status==502 and all(d.get(k) is True for k in ('ok','sql','sqlError','redisSet','redisGet','redisError','exception','activeSpan')), 'Application work failed'"
            self.kube("exec", "deployment/synthetic-customer-app", "-n", self.app_namespace, "--", "python", "-c", program)

    def applications(self):
        for case in CASES:
            runtime = "java" if case.startswith("java") else "nodejs"
            self.create(self.app(case, case, runtime))
            self.kube("wait", "--for=condition=Ready", "pod/" + case, "-n", self.app_namespace, "--timeout=240s", timeout=260)
            pod = json.loads(self.kube("get", "pod/" + case, "-n", self.app_namespace, "-o", "json").stdout)
            init = next(c for c in pod["spec"]["initContainers"] if c["name"] == "elven-instrumentation-init")
            status = next(c for c in pod["status"]["initContainerStatuses"] if c["name"] == init["name"])
            if init["image"] != self.images[runtime]["reference"] or status["state"]["terminated"]["exitCode"] != 0:
                raise AssertionError("Exact injected SDK/init execution was not observed")
            self.check("actual SDK injection " + case, image=init["image"], initExitCode=0)
        self.exercise()

    def delivery(self):
        result = None
        def arrived():
            nonlocal result
            try:
                result = check_capture(self.service_spans(), self.pins["privacy"], sanitized=self.combined, required_traces=self.request_traces)
                return True
            except AssertionError as error:
                self.report["captureFailure"] = str(error)
                self.report["scope_inventory"] = {case: sorted({scope for scope, _ in spans})
                                                  for case, spans in self.service_spans().items() if case in CASES}
                return False
        self.wait_for(arrived, "actual SDK SQL Redis exceptions and selective privacy", timeout=150)
        self.report["capture"] = result
        if self.combined:
            if not all(item["tenant"] == "synthetic-tenant" and item["authorization_valid"] for item in self.state()["accepted"]):
                raise AssertionError("Authenticated synthetic tenant export failed")
        else:
            self.report["sink_wire"] = SDK.sdk_wire_summary(self.state()["accepted"])
        self.check("real SDK exports " + ("selectively sanitized after Collector" if self.combined else "raw positive exception control"))

    def cli(self, command, values=None, release="elven-a", revision=None):
        uid = json.loads(self.kube("get", "namespace/kube-system", "-o", "json").stdout)["metadata"]["uid"]
        args = [sys.executable, ROOT / "elven", command, "--release", release, "--namespace", self.namespace,
                "--context", "kind-" + self.name, "--kubeconfig", self.kubeconfig, "--expect-cluster-uid", uid,
                "--cluster-name", "synthetic-kind", "--use-existing-secrets", "--credentials-secret", release + "-ingest",
                "--tls-secret", release + "-internal-tls", "--development-images", "--timeout", "240s"]
        if values:
            args += ["--values", values]
        if revision is not None:
            args += ["--revision", revision]
        CORE.execute(args, timeout=500)

    def rollback(self):
        def identity():
            return {kind + "/" + name: json.loads(self.kube("get", kind + "/" + name, "-n", ns, "-o", "json").stdout)["metadata"]["uid"]
                    for kind, name, ns in [("pvc", "data-elven-a-gateway-0", self.namespace),
                        ("secret", "elven-a-ingest", self.namespace), ("secret", "elven-a-internal-tls", self.namespace),
                        ("secret", "elven-instrumentation-tls", self.app_namespace)] + [("pod", case, self.app_namespace) for case in CASES]}
        baseline = identity()
        path = self.directory / "elven-a-values.yaml"
        settings = yaml.safe_load(path.read_text())
        settings.setdefault("ports", {})["health"] = 13136
        upgraded = self.directory / "upgrade.yaml"
        upgraded.write_text(yaml.safe_dump(settings))
        self.cli("upgrade", upgraded)
        self.cli("rollback", revision=1)
        if identity() != baseline:
            raise AssertionError("Rollback changed application/Secret/PVC identities")
        self.request_traces = {case: set() for case in CASES}
        self.exercise()
        self.delivery()
        self.report["rollback"] = {"identitiesPreserved": True, "freshActualSdkCaptureAfterRollback": self.report["capture"]}

    def run(self):
        self.boot()
        for image in self.images.values():
            self.import_archive(image)
        self.prepare_fixtures()
        self.tls()
        self.fixture()
        self.databases()
        self.install_operator()
        self.applications()
        self.delivery()
        if self.combined:
            self.rollback()
        self.report["functional_checks_passed"] = True

    def cleanup(self):
        # Do not upload raw SDK payloads or app logs from the positive control.
        # Fixture images survive only until the second owned cluster finishes.
        CORE.Lab.cleanup(self)


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--core-manifest", type=Path, required=True)
    parser.add_argument("--sdk-manifest", type=Path, required=True)
    parser.add_argument("--development-images", action="store_true")
    args = parser.parse_args()
    if not args.development_images or os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        parser.error("Explicit development images and a dedicated disposable hosted CI runner required")
    core = HYBRID.core_images(args.core_manifest)
    # Full fresh eight-image admission runs independently before the lab too.
    CORE.execute([sys.executable, ROOT / "scripts/qualify-candidate-artifacts.py", "--core-manifest", args.core_manifest,
                  "--sdk-manifest", args.sdk_manifest], timeout=180)
    fixtures = {}
    raw_diagnostics = None
    try:
        for combined in (False, True):
            options = SimpleNamespace(images_manifest=args.sdk_manifest, development_images=True, node_image=CORE.KIND_NODE,
                keep=False, collector_image=core["collector"]["reference"] if combined else None,
                collector_image_archive=core["collector"]["archive"] if combined else None)
            lab = PrivacyLab(options, fixtures)
            try:
                lab.run()
                observed = {case: lab.report["capture"][case]["selectiveDiagnosticDigests"] for case in CASES}
                if combined:
                    if observed != raw_diagnostics:
                        raise AssertionError("Post-Collector exception types, selective messages or full frames differ from the real RAW SDK control")
                    lab.report["rawControlDiagnosticComparison"] = "PASS_EXACT_TYPE_SELECTIVE_MESSAGE_FULL_FRAMES"
                else:
                    raw_diagnostics = observed
            except Exception as error:
                lab.report.update(result="FAIL", error=str(error))
                raise
            finally:
                fixtures.update(lab.fixture_images)
                lab.cleanup()
            if not lab.report.get("functional_checks_passed") or lab.report.get("cluster_retained"):
                raise RuntimeError("Actual application checks and owned-cluster teardown are mandatory")
            lab.report.update(completed=True, result="PASS_LAB_NOT_RELEASE")
            (lab.directory / "report.json").write_text(json.dumps(lab.report, indent=2) + "\n")
            print(json.dumps({"result": lab.report["result"], "combined": combined, "report": str(lab.directory / "report.json")}))
    finally:
        for tag in fixtures.values():
            CORE.execute(["docker", "image", "rm", tag], check=False, timeout=60)


if __name__ == "__main__":
    main()
