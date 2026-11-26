"""Offline assertion/admission regressions, never actual BPF/SDK evidence."""
import base64
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("hybrid_candidate_under_test", ROOT / "scripts/test-hybrid-candidate.py")
H = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(H)


def trace(service, scope, start=100, route="/exercise"):
    return {"resource_spans": [{"resource": {"attributes": [{"key": "service.name", "value": {"string_value": service}}]},
        "scope_spans": [{"scope": {"name": scope}, "spans": [{"kind": "SPAN_KIND_SERVER", "start_time_unix_nano": str(start),
            "attributes": [{"key": "http.target", "value": {"string_value": route}}]}]}]}]}


def daemonset():
    return {"spec": {"template": {"spec": {
        "affinity": {"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": [
            {"matchFields": [{"key": "metadata.name", "operator": "In", "values": ["approved-node"]}]}]}}},
        "containers": [{"name": "beyla", "securityContext": {"privileged": False, "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"], "add": sorted(H.CAPS)}}}]}}}}


class HybridCandidateTests(unittest.TestCase):
    def test_independent_actual_scopes_are_required_and_crossovers_fail(self):
        messages = [trace(H.SDK_NAME, "@opentelemetry/instrumentation-http"),
                    trace(H.BPF_NAME, "go.opentelemetry.io/obi")]
        result = H.classify(messages)
        H.assert_disjoint(result)
        self.assertEqual(len(result["sdk_server"]), 1)
        self.assertEqual(len(result["bpf_server"]), 1)
        for extra in (trace(H.SDK_NAME, "github.com/grafana/beyla"),
                      trace(H.BPF_NAME, "@opentelemetry/instrumentation-http")):
            with self.assertRaises(AssertionError):
                H.assert_disjoint(H.classify(messages + [extra]))
        for missing in (messages[:1], messages[1:], []):
            with self.assertRaises(AssertionError):
                H.assert_disjoint(H.classify(missing))
        for unknown in ("", "unknown", "not-a-real-ebpf-scope"):
            with self.assertRaises(AssertionError):
                H.assert_disjoint(H.classify([trace(H.SDK_NAME, unknown), messages[1]]))
        # An old span cannot stand in for fresh post-rollback telemetry.
        self.assertFalse(H.classify(messages, after=101)["sdk_server"])
        H.assert_disjoint(H.classify(messages[:1]), require_bpf=False)
        readiness = [trace(H.SDK_NAME, H.SDK_SCOPE, route="/ready"),
                     trace(H.BPF_NAME, "go.opentelemetry.io/obi", route="/ready")]
        with self.assertRaises(AssertionError):
            H.assert_disjoint(H.classify(readiness))

    def test_sdk_evidence_requires_exact_image_init_loader_and_mtls_mounts(self):
        image, gateway = "docker.io/elvenobservability/elven-auto-nodejs:1.0.9-dev@sha256:" + "a"*64, "https://elven-gateway.svc:4318"
        pod = {"spec": {"initContainers": [{"name": "elven-instrumentation-init", "image": image}], "containers": [{
            "name": "application", "env": [{"name": "NODE_OPTIONS", "value": "--require=/elven-auto/autoinstrumentation.js"},
                {"name": "OTEL_EXPORTER_OTLP_ENDPOINT", "value": gateway}, {"name": "OTEL_SERVICE_NAME", "value": H.SDK_NAME}],
            "volumeMounts": [{"name": "elven-instrumentation", "mountPath": "/elven-auto", "readOnly": True},
                             {"name": "elven-instrumentation-tls", "mountPath": "/var/run/elven/tls", "readOnly": True}]}]},
            "status": {"initContainerStatuses": [{"name": "elven-instrumentation-init", "state": {"terminated": {"exitCode": 0}}}]}}
        H.assert_sdk_injection(pod, image, gateway)
        for edit in (lambda p: p["spec"]["initContainers"][0].update(image="wrong"),
                     lambda p: p["status"]["initContainerStatuses"][0]["state"]["terminated"].update(exitCode=1),
                     lambda p: p["spec"]["containers"][0].update(env=[]),
                     lambda p: p["spec"]["containers"][0].update(volumeMounts=[])):
            changed = copy.deepcopy(pod); edit(changed)
            with self.assertRaises(AssertionError):
                H.assert_sdk_injection(changed, image, gateway)

    def test_installed_affinity_and_security_cannot_expand(self):
        expected = daemonset()
        H.assert_node_scope(expected, "approved-node")
        edits = (
            lambda p: p["affinity"]["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]["nodeSelectorTerms"].append({}),
            lambda p: p["affinity"]["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]["nodeSelectorTerms"][0]["matchFields"][0].update(values=["*"]),
            lambda p: p["containers"][0]["securityContext"].update(privileged=True),
            lambda p: p["containers"][0]["securityContext"]["capabilities"]["add"].append("SYS_ADMIN"),
            lambda p: p["containers"][0]["securityContext"].update(allowPrivilegeEscalation=True),
        )
        for edit in edits:
            changed = copy.deepcopy(expected); edit(changed["spec"]["template"]["spec"])
            with self.assertRaises(AssertionError):
                H.assert_node_scope(changed, "approved-node")

    def test_core_oci_archives_are_exact_and_cannot_escape_or_mutate(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            manifest = {"images": {}}
            for name, repository in (("collector", "elven-collector"), ("beyla", "elven-ebpf"), ("alloy", "elven-profiler")):
                raw = ("synthetic-" + name).encode()
                (root / (name + ".tar")).write_bytes(raw)
                manifest["images"][name] = {"tag": "docker.io/elvenobservability/" + repository + ":1.0.9-dev",
                    "digest": "sha256:" + "a" * 64, "archive": name + ".tar", "archiveSha256": hashlib.sha256(raw).hexdigest()}
            path = root / "release.json"
            path.write_text(json.dumps(manifest))
            self.assertEqual(set(H.core_images(path)), {"collector", "beyla", "alloy"})
            manifest["images"]["collector"]["tag"] = "docker.io/customer/collector:1.0.9-dev"
            path.write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                H.core_images(path)
            manifest["images"]["collector"]["tag"] = "docker.io/elvenobservability/elven-collector:1.0.9-dev"
            path.write_text(json.dumps(manifest))
            (root / "collector.tar").write_bytes(b"changed")
            with self.assertRaises(ValueError):
                H.core_images(path)

    def test_both_scan_platforms_must_be_fresh_pinned_and_hash_bound(self):
        now = datetime(2026, 11, 26, 12, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            raw = b'{"Results": []}'
            (root / "report.json").write_bytes(raw)
            item = {"status": "passed", "highCriticalCount": 0, "scanner": "trivy/0.76.2", "scannedAt": now.isoformat(),
                "database": {"UpdatedAt": now.isoformat()}, "report": "report.json", "reportSha256": hashlib.sha256(raw).hexdigest(),
                "sbom": "report.json", "sbomSha256": hashlib.sha256(raw).hexdigest()}
            data = {"dirtySource": False, "images": {"beyla": {"scans": {p: copy.deepcopy(item) for p in ("linux/amd64", "linux/arm64")}}}}
            path = root / "manifest.json"
            path.write_text(json.dumps(data))
            H.fresh_scans(path, ["beyla"], "0.76.2", now)
            edits = (lambda s: s.update(highCriticalCount=False), lambda s: s.update(highCriticalCount=1),
                lambda s: s.update(scannedAt=(now - timedelta(hours=25)).isoformat()),
                lambda s: s.update(database={"UpdatedAt": (now - timedelta(hours=49)).isoformat()}),
                lambda s: s.update(scanner="trivy/other"), lambda s: s.update(report="../outside.json"))
            for edit in edits:
                changed = copy.deepcopy(data); edit(changed["images"]["beyla"]["scans"]["linux/arm64"])
                path.write_text(json.dumps(changed))
                with self.assertRaises((ValueError, FileNotFoundError)):
                    H.fresh_scans(path, ["beyla"], "0.76.2", now)

    def test_extraction_uses_verified_bytes_not_reopened_zip(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            path = folder / "candidate.zip"
            def archive(content):
                output = io.BytesIO()
                with zipfile.ZipFile(output, "w") as z:
                    z.writestr("elven-lab-candidate/elven", content)
                return output.getvalue()
            original = archive("verified, not executed")
            path.write_bytes(original)
            def verify(raw, expected):
                self.assertEqual(raw, original)
                self.assertEqual(expected, hashlib.sha256(original).hexdigest())
                path.write_bytes(archive("mutated after verification"))
                return {"kind": "ELVEN_LAB_CANDIDATE", "customerInstallable": False, "sourceRevision": "a"*40}
            verifier = SimpleNamespace(MAX_BYTES=1_000_000, verify=verify)
            with mock.patch.object(H, "module", return_value=verifier):
                H.extract_candidate(path, hashlib.sha256(original).hexdigest(), folder / "payload")
            self.assertEqual((folder / "payload/elven").read_text(), "verified, not executed")

    def test_host_consent_and_hosted_ci_are_required_before_lab_construction(self):
        common = ["test", "--candidate", "unused.zip", "--candidate-sha256", "a"*64,
                  "--core-manifest", "core.json", "--sdk-manifest", "sdk.json"]
        for flags, environment in (([], {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}),
                                   (["--development-images", "--host-access-approved"], {})):
            with mock.patch.object(sys, "argv", common + flags), mock.patch.dict(os.environ, environment, clear=True), \
                 mock.patch.object(H, "HybridLab") as lab, redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    H.main()
                lab.assert_not_called()

    def test_no_pass_is_written_if_owned_teardown_fails(self):
        lab = mock.Mock()
        lab.report = {"result": "FAIL", "completed": False, "functional_checks_passed": True}
        lab.cleanup.side_effect = RuntimeError("synthetic teardown failure")
        argv = ["test", "--candidate", "unused.zip", "--candidate-sha256", "a"*64, "--core-manifest", "core.json",
                "--sdk-manifest", "sdk.json", "--development-images", "--host-access-approved"]
        with mock.patch.object(sys, "argv", argv), mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}), \
             mock.patch.object(H, "HybridLab", return_value=lab):
            with self.assertRaisesRegex(RuntimeError, "teardown"):
                H.main()
        self.assertFalse(lab.report["completed"])
        self.assertEqual(lab.report["result"], "FAIL")


if __name__ == "__main__":
    unittest.main()
