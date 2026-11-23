"""Eligibility and exact rendered scheduling from synthetic reader evidence only."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

import jsonschema

from test_chart import all_modules, objects, podspec, render


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ebpf_contract", ROOT / "scripts/ebpf-contract.py")
contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contract)
REQUEST = json.loads((ROOT / "contracts/fixtures/ebpf-hybrid-v1.json").read_text())
LOCK = json.loads((ROOT / "versions.lock.json").read_text())
SCHEMA = json.loads((ROOT / "contracts/ebpf-eligibility-v1.schema.json").read_text())


def check(request, lock=None):
    return contract.assess(request, lock or LOCK, now=REQUEST["observedAt"])


class EvidenceTests(unittest.TestCase):
    def test_complete_bound_eligibility_never_claims_runtime(self):
        jsonschema.Draft202012Validator.check_schema(SCHEMA)
        jsonschema.validate(REQUEST, SCHEMA)
        before = copy.deepcopy(REQUEST)
        result = check(REQUEST)
        output_schema = json.loads((ROOT / "contracts/ebpf-assessment-v1.schema.json").read_text())
        jsonschema.Draft202012Validator.check_schema(output_schema)
        jsonschema.validate(result, output_schema)
        self.assertEqual(REQUEST, before)
        self.assertEqual(result["mode"], "hybrid")
        self.assertEqual(result["runtimeAcceptance"], "NOT_PROVEN")
        self.assertEqual(result["reasons"], [])
        self.assertEqual(result["imageDigest"], LOCK["images"]["beyla"]["distribution"]["digest"])
        self.assertEqual(result["inputSha256"], contract.sha(REQUEST))
        self.assertEqual(result["lockSha256"], contract.sha(LOCK))
        self.assertNotIn("SYS_ADMIN", result["requirements"]["capabilities"])
        self.assertNotIn("NET_ADMIN", result["requirements"]["capabilities"])
        result["requirements"]["capabilities"].append("SYNTHETIC")
        self.assertNotIn("SYNTHETIC", check(REQUEST)["requirements"]["capabilities"])
        result["approvedNodes"][0]["name"] = "other"
        result["targets"][0]["nodeUids"].clear()
        self.assertEqual(REQUEST, before)

    def test_sdk_only_does_not_enable_host_modules_even_with_unknown_observations(self):
        selected = copy.deepcopy(REQUEST)
        selected.update(optIn=False, hostAccessApproved=False, approvedNodes=[], workloads=[], nodeEvidence=[])
        result = check(selected)
        self.assertEqual(result["mode"], "sdk-only")
        self.assertEqual(result["approvedNodes"], [])
        self.assertEqual(result["runtimeAcceptance"], "NOT_PROVEN")

    def test_failed_unknown_or_stale_prerequisites_hold_without_widening(self):
        cases = [
            ("root", "hostAccessApproved", False, "ebpf_host_access_not_approved"),
            ("root", "excludeSDKInstrumentedServices", False, "ebpf_sdk_exclusion_required"),
            ("root", "observedAt", REQUEST["observedAt"] - 601, "ebpf_observation_expired"),
            ("root", "observedAt", REQUEST["observedAt"] + 31, "ebpf_observation_expired"),
            ("node", "os", "windows", "ebpf_platform_unsupported"),
            ("node", "architecture", "unknown", "ebpf_platform_unsupported"),
            ("node", "kernel", "5.10.99-vendor", "ebpf_kernel_unsupported"),
            ("node", "kernel", "4.18.0-backport", "ebpf_kernel_unsupported"),
            ("node", "btf", "unknown", "ebpf_btf_not_verified"),
            ("node", "btf", "absent", "ebpf_btf_not_verified"),
            ("node", "ready", False, "ebpf_node_not_ready"),
            ("node", "freePodSlots", 0, "ebpf_capacity_unconfirmed"),
            ("node", "freePodSlots", None, "ebpf_capacity_unconfirmed"),
            ("node", "freeCpuMilli", 199, "ebpf_capacity_unconfirmed"),
            ("node", "freeMemoryMiB", 1279, "ebpf_capacity_unconfirmed"),
            ("node", "admission", "unknown", "ebpf_admission_unconfirmed"),
            ("node", "capabilities", "fail", "ebpf_capabilities_unconfirmed"),
            ("node", "bpfLoad", "unknown", "ebpf_loader_unconfirmed"),
            ("workload", "sdkInstrumented", True, "ebpf_sdk_target_overlap"),
            ("workload", "namespace", "kube-system", "ebpf_protected_namespace"),
            ("workload", "nodeUids", [], "ebpf_workload_outside_approved_nodes"),
            ("workload", "nodeUids", ["00000000-0000-4000-8000-000000000099"], "ebpf_workload_outside_approved_nodes"),
        ]
        for source, key, value, reason in cases:
            with self.subTest(source=source, key=key, value=value):
                request = copy.deepcopy(REQUEST)
                target = request if source == "root" else request["nodeEvidence" if source == "node" else "workloads"][0]
                target[key] = value
                result = check(request)
                self.assertEqual(result["mode"], "unsupported")
                self.assertIn(reason, result["reasons"])

    def test_recreated_node_and_new_workload_bound_to_other_node_fail(self):
        request = copy.deepcopy(REQUEST)
        request["nodeEvidence"][0]["uid"] = "00000000-0000-4000-8000-000000000098"
        self.assertIn("ebpf_node_identity_changed", check(request)["reasons"])
        request["nodeEvidence"] = []
        self.assertIn("ebpf_node_identity_changed", check(request)["reasons"])

    def test_blocked_old_image_and_changed_lock_never_become_a_fallback(self):
        for digest in ("sha256:be51d39658483814b3739f35a9ef876fc39a7f72892d7cc36daf496dfc77ab7f", "sha256:" + "9" * 64):
            request = copy.deepcopy(REQUEST)
            request["imageDigest"] = digest
            self.assertIn("ebpf_image_not_promoted_or_blocked", check(request)["reasons"])
        lock = copy.deepcopy(LOCK)
        lock["runtimeBlocks"][REQUEST["imageDigest"]] = {"reason": "synthetic-new-advisory"}
        self.assertIn("ebpf_image_not_promoted_or_blocked", check(REQUEST, lock)["reasons"])
        lock = copy.deepcopy(LOCK)
        lock["distribution"]["publicationStatus"] = "pending"
        self.assertIn("ebpf_image_not_promoted_or_blocked", check(REQUEST, lock)["reasons"])

    def test_closed_contract_rejects_extra_unknown_unbounded_and_coerced_values(self):
        for operation in (
            lambda doc: doc.update(command="kubectl"),
            lambda doc: doc.update(schemaVersion=True),
            lambda doc: doc.update(optIn="true"),
            lambda doc: doc.update(clusterUid="00000000-0000-0000-0000-000000000000"),
            lambda doc: doc.update(approvedNodes=doc["approvedNodes"] * 2),
            lambda doc: doc["nodeEvidence"][0].update(freePodSlots=True),
            lambda doc: doc["nodeEvidence"][0].update(evidenceSha256="0" * 64),
            lambda doc: doc["workloads"][0].update(namespace="*"),
            lambda doc: doc["workloads"][0].update(nodeUids=doc["workloads"][0]["nodeUids"] * 2),
            lambda doc: doc.update(workloads=doc["workloads"] * 101),
        ):
            request = copy.deepcopy(REQUEST)
            operation(request)
            with self.assertRaises(contract.ContractError):
                check(request)


class ExactSchedulingTests(unittest.TestCase):
    def test_required_exact_node_affinity_intersects_existing_selector(self):
        values = all_modules()
        values["nodeAgent"] = {"nodeSelector": {"pool": "approved"}, "approvedNodes": ["worker-b", "worker-a"]}
        daemon = next(obj for obj in objects(values) if obj["kind"] == "DaemonSet")
        pod = podspec(daemon)
        self.assertEqual(pod["nodeSelector"], {"kubernetes.io/os": "linux", "pool": "approved"})
        terms = pod["affinity"]["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]["nodeSelectorTerms"]
        self.assertEqual(terms, [{"matchFields": [{"key": "metadata.name", "operator": "In", "values": [name]}]}
                                 for name in ("worker-a", "worker-b")])
        self.assertFalse(next(container for container in pod["containers"] if container["name"] == "beyla")["securityContext"]["privileged"])

    def test_legacy_no_affinity_preserved_and_invalid_exact_nodes_rejected(self):
        daemon = next(obj for obj in objects(all_modules()) if obj["kind"] == "DaemonSet")
        self.assertNotIn("affinity", podspec(daemon))
        for nodes in (["*"], ["worker-a", "worker-a"], ["worker-a"] * 101):
            values = all_modules()
            values["nodeAgent"] = {"approvedNodes": nodes}
            self.assertNotEqual(render(values, check=False).returncode, 0)


if __name__ == "__main__":
    unittest.main()
