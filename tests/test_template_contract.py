"""Engine-facing closed plans with real offline chart renders and negative scope."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tarfile
import unittest
from unittest.mock import patch
from uuid import UUID

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("template_adapter", ROOT / "scripts/template_contract.py")
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
NOW = datetime(2026, 11, 23, 12, tzinfo=timezone.utc)
def uid(value): return str(UUID(int=value))


def request(catalog):
    return {"contractVersion": C.VERSION, "catalogSha256": catalog["catalogSha256"],
            "cluster": {"uid": uid(1), "serverSha256": "1"*64, "caSha256": "2"*64, "name": "elven-lab"},
            "observedAt": NOW.isoformat(), "namespace": "elven-system-pilot", "release": "elven", "operatorRelease": "elven-operator",
            "tenantId": "elven-synthetic", "namespaces": [{"name": "elven-pilot-app", "uid": uid(2)}],
            "apps": [{"namespaceUid": uid(2), "name": "elven-pilot", "uid": uid(3), "resourceVersion": "11",
                      "templateSha256": "3"*64, "container": "app", "runtime": "java", "existingInstrumentation": "none"}],
            "nodes": [], "collection": {"stdout": False, "hostAccessApproved": False, "clusterMetrics": False,
                                      "clusterWideMetricsApproved": False, "privacy": "selective"},
            "storage": {"class": "elven-lab-storage", "sizeGiB": 2},
            "network": {"exports": ["192.0.2.1/32"], "api": ["192.0.2.2/32"], "dnsNamespace": "kube-system", "dns": []},
            "traceSampling": "1", "ebpf": None}


class TemplateContract(unittest.TestCase):
    def setUp(self):
        self.catalog = C.catalog()
        self.request = request(self.catalog)

    def test_published_schemas_and_synthetic_fixtures_are_reproducible(self):
        folder = ROOT / "contracts/template/v1"
        for name, schema in (("request", C.request_schema()), ("plan", C.plan_schema()),
                             ("baseline", C.baseline_schema())):
            self.assertEqual(C.read_document(folder / (name + ".schema.json")), schema)
            jsonschema.Draft202012Validator.check_schema(schema)
        fixtures = folder / "fixtures"
        selected = C.read_document(fixtures / "request.json")
        # Synthetic binding is deliberately NOT the admitted source catalogue.
        synthetic = {**self.catalog, "catalogSha256": selected["catalogSha256"]}
        self.assertNotEqual(selected["catalogSha256"], self.catalog["catalogSha256"])
        proposal = C.plan(selected, synthetic, now=NOW)
        self.assertEqual(proposal, C.read_document(fixtures / "plan.json"))
        self.assertEqual(C.materialize(proposal, synthetic, now=NOW),
                         C.read_document(fixtures / "materialized.json"))
        baseline = C.read_document(fixtures / "baseline.json")
        self.assertEqual(C.rollback(proposal, baseline, synthetic, now=NOW),
                         C.read_document(fixtures / "rollback.json"))
        with self.assertRaisesRegex(C.ContractError, "CATALOG_CHANGED"):
            C.plan(selected, self.catalog, now=NOW)

    def test_catalog_binds_files_both_locks_and_exact_signatures(self):
        self.assertEqual(self.catalog, C.catalog())
        self.assertEqual(len(self.catalog["images"]), 8)
        unsigned = dict(self.catalog); unsigned.pop("catalogSha256")
        self.assertEqual(self.catalog["catalogSha256"], C.sha(unsigned))
        for name, image in self.catalog["images"].items():
            self.assertEqual(image["attestations"]["subjectDigest"], image["digest"])
            self.assertTrue(image["signature"]["identity"].endswith("@refs/tags/v1.0.1"))
            self.assertEqual(image["signature"]["verification"], "REQUIRED_AT_ADMISSION")
        self.assertEqual(self.catalog["dataCapabilities"]["redis"], "REQUIRES_NEW_PROMOTED_COLLECTOR")

    def test_deterministic_closed_plan_and_materialization_are_not_approval(self):
        first = C.plan(self.request, self.catalog, now=NOW)
        self.assertEqual(first, C.plan(copy.deepcopy(self.request), self.catalog, now=NOW + timedelta(seconds=1)))
        self.assertEqual([a["kind"] for a in first["actions"]], ["CORE_APPLY", "OPERATOR_APPLY", "APP_OPT_IN"])
        self.assertTrue(all(gate == "UNKNOWN" for gate in first["gates"].values()))
        material = C.materialize(first, self.catalog, now=NOW)
        self.assertEqual(material["execution"], "ENGINE_PHASE_PORT")
        self.assertEqual(material["coreValues"]["modules"]["ebpf"], {"enabled": False})
        self.assertEqual(material["operatorValues"]["runtimes"]["java"], True)
        self.assertNotIn(self.request["tenantId"], json.dumps(material))
        self.assertNotIn("token", json.dumps(material).lower())
        jsonschema.Draft202012Validator(C.request_schema(), format_checker=jsonschema.FormatChecker()).validate(self.request)
        jsonschema.Draft202012Validator(C.plan_schema(), format_checker=jsonschema.FormatChecker()).validate(first)

    def test_rendered_public_values_satisfy_actual_core_and_operator_charts(self):
        material = C.materialize(C.plan(self.request, self.catalog, now=NOW), self.catalog, now=NOW)
        self.assertNotIn("approvedNodes", json.dumps(material))
        archive = os.environ.get("ELVEN_TEST_ARCHIVE")
        if archive:
            # Bind compatibility to the exact immutable payload, not new charts.
            import hashlib
            self.assertEqual(hashlib.sha256(Path(archive).read_bytes()).hexdigest(), C.ARTIFACT["sha256"])
            with tarfile.open(archive) as payload:
                for chart, field in (("elven-observability", "coreValues"), ("elven-instrumentation", "operatorValues")):
                    prefix = "elven-observability-v1.0.1/charts/" + chart + "/"
                    defaults = yaml.safe_load(payload.extractfile(prefix + "values.yaml"))
                    schema = json.load(payload.extractfile(prefix + "values.schema.json"))
                    def merge(base, desired):
                        for key, value in desired.items():
                            if isinstance(value, dict) and isinstance(base.get(key), dict):
                                merge(base[key], value)
                            else:
                                base[key] = copy.deepcopy(value)
                        return base
                    jsonschema.Draft202012Validator(schema).validate(merge(defaults, material[field]))
        for name, field in (("elven-observability", "coreValues"), ("elven-instrumentation", "operatorValues")):
            with self.subTest(chart=name), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "values.json"
                path.write_text(json.dumps(material[field]))
                result = subprocess.run(["helm", "template", "elven", str(ROOT / "charts" / name), "-n",
                                         self.request["namespace"], "--kube-version", "1.35.2", "-f", str(path)], capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                objects = [v for v in yaml.safe_load_all(result.stdout) if v]
                self.assertFalse(any(v["kind"] == "Secret" for v in objects))

    def test_untrusted_fields_and_privilege_shortcuts_fail(self):
        for edit in (
            lambda r: r.update(command="curl secret"),
            lambda r: r.update(token="SYNTHETIC_PRIVATE"),
            lambda r: r["cluster"].update(kubeconfig="SYNTHETIC_PRIVATE"),
            lambda r: r["apps"][0].update(runtime="nodejs20"),
            lambda r: r["apps"][0].update(existingInstrumentation="sdk"),
            lambda r: r["apps"][0].update(namespaceUid=uid(9)),
            lambda r: r["namespaces"][0].update(name="kube-system"),
            lambda r: r["network"].update(exports=["0.0.0.0/0"]),
            lambda r: r.update(catalogSha256="0"*64),
            lambda r: r["storage"].update(sizeGiB=True),
            lambda r: r["collection"].update(stdout=True),
        ):
            altered = copy.deepcopy(self.request); edit(altered)
            with self.subTest(altered=altered), self.assertRaises(C.ContractError):
                C.plan(altered, self.catalog, now=NOW)
        for seconds in (-31, 601):
            with self.assertRaisesRegex(C.ContractError, "STALE"):
                C.plan(self.request, self.catalog, now=NOW + timedelta(seconds=seconds))

    def test_plan_hash_does_not_launder_modified_operations_or_gate(self):
        original = C.plan(self.request, self.catalog, now=NOW)
        for edit in (lambda p: p["gates"].update(FRESH_APPROVAL_REQUIRED="PASS"),
                     lambda p: p["actions"][0]["target"].update(namespace="foreign"),
                     lambda p: p.update(command="shell")):
            changed = copy.deepcopy(original); edit(changed)
            unsigned = dict(changed); unsigned.pop("planSha256")
            changed["planSha256"] = C.sha(unsigned)
            with self.assertRaises(C.ContractError):
                C.materialize(changed, self.catalog, now=NOW)

    def test_diff_reports_application_removal_and_rejects_rebinding(self):
        old = C.plan(self.request, self.catalog, now=NOW)
        changed = copy.deepcopy(self.request); changed["apps"] = []
        new = C.plan(changed, self.catalog, now=NOW)
        result = C.diff(old, new, self.catalog, now=NOW)
        self.assertTrue(result["destructiveChangesRequireNewApproval"])
        self.assertIn("app-" + uid(3), result["removed"])
        changed["tenantId"] = "different"
        with self.assertRaisesRegex(C.ContractError, "BINDING"):
            C.diff(old, C.plan(changed, self.catalog, now=NOW), self.catalog, now=NOW)

    def test_diff_includes_operator_when_effective_runtime_changes(self):
        old = C.plan(self.request, self.catalog, now=NOW)
        changed = copy.deepcopy(self.request); changed["apps"][0]["runtime"] = "nodejs"
        result = C.diff(old, C.plan(changed, self.catalog, now=NOW), self.catalog, now=NOW)
        self.assertIn("operator", result["changed"])

    def test_hybrid_binds_evidence_exact_scope_and_refuses_unknown_loader(self):
        selected = copy.deepcopy(self.request)
        evidence = json.loads((ROOT / "contracts/fixtures/ebpf-hybrid-v1.json").read_text())
        evidence["observedAt"] = int(NOW.timestamp())
        evidence["clusterUid"] = selected["cluster"]["uid"]
        selected["nodes"] = evidence["approvedNodes"]
        workload = evidence["workloads"][0]
        selected["namespaces"].append({"name": workload["namespace"], "uid": workload["namespaceUid"]})
        selected["ebpf"] = evidence
        plan = C.plan(selected, self.catalog, now=NOW)
        self.assertEqual(plan["ebpfDecision"]["mode"], "hybrid")
        jsonschema.Draft202012Validator(C.plan_schema(), format_checker=jsonschema.FormatChecker()).validate(plan)
        with self.assertRaisesRegex(C.ContractError, "TEMPLATE_REPACKAGE_REQUIRED"):
            C.materialize(plan, self.catalog, now=NOW)
        overlap = copy.deepcopy(selected)
        overlap["apps"][0].update(namespaceUid=workload["namespaceUid"], name=workload["deployment"], uid=uid(999))
        with self.assertRaisesRegex(C.ContractError, "SCOPE_CHANGED"):
            C.plan(overlap, self.catalog, now=NOW)
        selected["ebpf"]["nodeEvidence"][0]["bpfLoad"] = "unknown"
        unsupported = C.plan(selected, self.catalog, now=NOW)
        self.assertEqual(unsupported["ebpfDecision"]["mode"], "unsupported")
        self.assertIn("ebpf_loader_unconfirmed", unsupported["ebpfDecision"]["reasons"])
        with self.assertRaisesRegex(C.ContractError, "RUNTIME_UNSUPPORTED"):
            C.materialize(unsupported, self.catalog, now=NOW)
        selected["ebpf"]["clusterUid"] = uid(909)
        with self.assertRaisesRegex(C.ContractError, "SCOPE"):
            C.plan(selected, self.catalog, now=NOW)

    def test_rollback_after_plan_expiry_requires_fresh_exact_private_baseline(self):
        first = C.plan(self.request, self.catalog, now=NOW)
        later = NOW + timedelta(hours=1)
        baseline = {"planSha256": first["planSha256"], "clusterUid": uid(1), "snapshotSha256": "4"*64,
                    "coreReleaseUid": uid(4), "operatorReleaseUid": uid(5), "currentCoreRevision": 2, "currentOperatorRevision": 2,
                    "observedAt": later.isoformat(), "coreRevision": 1, "operatorRevision": 1,
                    "apps": [{"uid": uid(3), "snapshotSha256": "5"*64, "currentResourceVersion": "12", "currentTemplateSha256": "6"*64}]}
        result = C.rollback(first, baseline, self.catalog, now=later)
        self.assertEqual([a["kind"] for a in result["actions"]], ["APP_RESTORE", "OPERATOR_ROLLBACK", "CORE_ROLLBACK"])
        self.assertFalse(result["deleteSecrets"] or result["deletePVCs"])
        for edit in (lambda b: b.update(clusterUid=uid(20)), lambda b: b.update(apps=[]),
                     lambda b: b.update(operatorRevision=0), lambda b: b.update(observedAt=NOW.isoformat())):
            altered = copy.deepcopy(baseline); edit(altered)
            with self.assertRaises(C.ContractError):
                C.rollback(first, altered, self.catalog, now=later)

    def test_parser_rejects_oversized_duplicate_nonfinite_without_echo(self):
        for payload in (b'{"a":1,"a":2}', b'{"a":NaN}', b"x"*256_001):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "input.json"; path.write_bytes(payload)
                with self.assertRaisesRegex(C.ContractError, "^INVALID_DOCUMENT$"):
                    C.read_document(path)


if __name__ == "__main__":
    unittest.main()
