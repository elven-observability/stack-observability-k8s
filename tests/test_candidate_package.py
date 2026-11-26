"""Offline candidate integrity, extracted chart/contract and rollback contracts."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 23, 12, tzinfo=timezone.utc)


def uid(value):
    return str(UUID(int=value))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


P = load("candidate_package", ROOT / "scripts/package-candidate.py")


class CandidatePackage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        cls.source = subprocess.check_output(["git", "archive", "--format=tar", cls.revision, *P.PATHS], cwd=ROOT)

    def unpack(self, directory):
        raw, manifest = P.build(self.source, self.revision)
        verified = P.verify(raw, P.digest(raw))
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            # All member identities, kinds, sizes and hashes checked first.
            archive.extractall(directory)
        return Path(directory) / P.PREFIX, verified

    def test_reproducible_zip_manifest_and_no_customer_installer(self):
        first, manifest = P.build(self.source, self.revision)
        self.assertEqual((first, manifest), P.build(self.source, self.revision))
        verified = P.verify(first, P.digest(first))
        self.assertEqual(verified["sourceRevision"], self.revision)
        self.assertFalse(verified["customerInstallable"])
        self.assertEqual(verified["runtimeAcceptance"], "NOT_PROVEN")
        self.assertFalse(any(name.startswith("kit/") or name == "instalar" for name in verified["files"]))
        for raw, checksum in ((first + b"tampered", P.digest(first)), (first, "0" * 64)):
            with self.assertRaises(ValueError):
                P.verify(raw, checksum)

    def test_member_tamper_and_traversal_rejected_even_with_new_outer_checksum(self):
        raw, _ = P.build(self.source, self.revision)
        for target in ("elven-lab-candidate/../../escape", "elven-lab-candidate/LAB-ONLY.txt"):
            changed = io.BytesIO()
            with zipfile.ZipFile(io.BytesIO(raw)) as original, zipfile.ZipFile(changed, "w") as altered:
                for entry in original.infolist():
                    altered.writestr(entry, b"changed" if entry.filename == target else original.read(entry))
                if "escape" in target:
                    altered.writestr(target, b"changed")
            data = changed.getvalue()
            with self.assertRaises(ValueError):
                P.verify(data, P.digest(data))

    def test_extracted_exact_node_chart_and_beyla_exclusions(self):
        import yaml
        with tempfile.TemporaryDirectory() as directory:
            root, _ = self.unpack(directory)
            values = {"cluster": {"name": "elven-candidate-lab"}, "collection": {"namespaces": ["synthetic-app"]},
                      "networkPolicy": {"exportCIDRs": ["192.0.2.1/32"], "apiServerCIDRs": ["192.0.2.2/32"]},
                      "nodeAgent": {"approvedNodes": ["worker-b", "worker-a"], "nodeSelector": {"elven.lab/pool": "pilot"}},
                      "modules": {"ebpf": {"enabled": True, "hostAccessApproved": True,
                                            "workloads": [{"namespace": "synthetic-app", "deployment": "synthetic-http"}]}}}
            path = Path(directory) / "values.json"
            path.write_text(json.dumps(values))
            def render():
                return subprocess.run(["helm", "template", "elven-candidate", str(root / "charts/elven-observability"),
                                       "-n", "elven-candidate-lab", "-f", str(path)], capture_output=True, text=True, timeout=30)
            result = render()
            self.assertEqual(result.returncode, 0, result.stderr)
            objects = [obj for obj in yaml.safe_load_all(result.stdout) if obj]
            pod = next(obj["spec"]["template"]["spec"] for obj in objects if obj["kind"] == "DaemonSet")
            self.assertEqual(pod["nodeSelector"], {"kubernetes.io/os": "linux", "elven.lab/pool": "pilot"})
            terms = pod["affinity"]["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]["nodeSelectorTerms"]
            self.assertEqual(terms, [{"matchFields": [{"key": "metadata.name", "operator": "In", "values": [name]}]}
                                     for name in ("worker-a", "worker-b")])
            cm = next(obj for obj in objects if obj["kind"] == "ConfigMap" and "beyla.yaml" in obj.get("data", {}))
            beyla = yaml.safe_load(cm["data"]["beyla.yaml"])
            self.assertTrue(beyla["discovery"]["exclude_otel_instrumented_services"])
            self.assertEqual(beyla["discovery"]["instrument"],
                             [{"k8s_namespace": "synthetic-app", "k8s_deployment_name": "synthetic-http"}])
            for bad_nodes in (["*"], ["worker-a", "worker-a"]):
                values["nodeAgent"]["approvedNodes"] = bad_nodes
                path.write_text(json.dumps(values))
                self.assertNotEqual(render().returncode, 0)
            values["nodeAgent"]["approvedNodes"] = ["worker-a"]
            values["modules"]["ebpf"]["workloads"][0]["deployment"] = ".*"
            path.write_text(json.dumps(values))
            self.assertNotEqual(render().returncode, 0)

    def test_extracted_contract_rejects_sdk_ebpf_overlap_and_keeps_exact_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _ = self.unpack(directory)
            contract = load("candidate_contract", root / "scripts/template_contract.py")
            cat = contract.catalog()
            selected = json.loads((root / "contracts/template/v1/fixtures/request.json").read_text())
            selected["catalogSha256"] = cat["catalogSha256"]
            evidence = json.loads((root / "contracts/fixtures/ebpf-hybrid-v1.json").read_text())
            evidence["clusterUid"], evidence["observedAt"] = selected["cluster"]["uid"], int(NOW.timestamp())
            target = evidence["workloads"][0]
            selected["namespaces"].append({"name": target["namespace"], "uid": target["namespaceUid"]})
            selected["nodes"], selected["ebpf"] = copy.deepcopy(evidence["approvedNodes"]), evidence
            proposal = contract.plan(selected, cat, now=NOW)
            self.assertEqual(proposal["ebpfDecision"]["mode"], "hybrid")
            # Candidate packaging must not turn stable materialization into a bypass.
            with self.assertRaisesRegex(contract.ContractError, "TEMPLATE_REPACKAGE_REQUIRED"):
                contract.materialize(proposal, cat, now=NOW)
            for edit in (lambda s: s["apps"][0].update(uid=target["uid"]),
                         lambda s: s["apps"][0].update(namespaceUid=target["namespaceUid"], name=target["deployment"])):
                altered = copy.deepcopy(selected); edit(altered)
                with self.assertRaisesRegex(contract.ContractError, "SCOPE_CHANGED"):
                    contract.plan(altered, cat, now=NOW)
            later = NOW + timedelta(hours=1)
            baseline = {"planSha256": proposal["planSha256"], "clusterUid": uid(1), "snapshotSha256": "4"*64,
                        "coreReleaseUid": uid(4), "operatorReleaseUid": uid(5), "currentCoreRevision": 2,
                        "currentOperatorRevision": 2, "observedAt": later.isoformat(), "coreRevision": 1, "operatorRevision": 1,
                        "apps": [{"uid": uid(3), "snapshotSha256": "5"*64, "currentResourceVersion": "12", "currentTemplateSha256": "6"*64}]}
            rollback = contract.rollback(proposal, baseline, cat, now=later)
            self.assertEqual([a["kind"] for a in rollback["actions"]], ["APP_RESTORE", "OPERATOR_ROLLBACK", "CORE_ROLLBACK"])
            self.assertEqual(len([a for a in rollback["actions"] if a["kind"] == "APP_RESTORE"]), 1)
            self.assertFalse(rollback["deleteSecrets"] or rollback["deletePVCs"])
            baseline["apps"] *= 2
            with self.assertRaises(contract.ContractError):
                contract.rollback(proposal, baseline, cat, now=later)
            baseline["apps"] = []
            with self.assertRaises(contract.ContractError):
                contract.rollback(proposal, baseline, cat, now=later)
