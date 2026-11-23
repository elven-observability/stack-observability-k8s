#!/usr/bin/env python3
"""Evaluate trusted, minimized eBPF observations; never inspect or mutate a host.

The engine supplies evidence collected by its own authorized reader. JSON is
data, not an attestation. A PASS here is eligibility to propose a bounded pilot,
not admission, signature verification, running instrumentation or delivery.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import time
from uuid import UUID


class ContractError(ValueError):
    pass


CAPABILITIES = ("BPF", "PERFMON", "SYS_PTRACE", "DAC_READ_SEARCH", "CHECKPOINT_RESTORE", "NET_RAW")
REQUIREMENTS = {"minimumKernel": "5.11", "btf": True, "hostPID": True,
                "capabilities": list(CAPABILITIES), "nodeAgentRequests": {"cpuMilli": 200, "memoryMiB": 384},
                "startupMemoryMiB": 1280}
NAME = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z")
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")
IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
KERNEL = re.compile(r"([0-9]{1,3})\.([0-9]{1,3})(?:\.[A-Za-z0-9.+_-]{1,96})?\Z")
ROOT_KEYS = {"schemaVersion", "clusterUid", "optIn", "hostAccessApproved", "excludeSDKInstrumentedServices",
             "imageDigest", "approvedNodes", "workloads", "observedAt", "nodeEvidence"}
NODE_KEYS = {"name", "uid", "os", "architecture", "kernel", "btf", "ready", "freePodSlots", "freeCpuMilli",
             "freeMemoryMiB", "admission", "capabilities", "bpfLoad", "evidenceSha256"}
WORKLOAD_KEYS = {"namespace", "namespaceUid", "deployment", "uid", "nodeUids", "sdkInstrumented"}
PROTECTED = {"default", "kube-system", "kube-public", "kube-node-lease", "elven-observability", "elven-system"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def closed(value, keys):
    if type(value) is not dict or set(value) != keys:
        raise ContractError("invalid_ebpf_contract")


def uid(value):
    try:
        parsed = UUID(value)
        if type(value) is not str or str(parsed) != value or not parsed.int:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise ContractError("invalid_ebpf_identity") from None


def name(value, *, label=False):
    if (type(value) is not str or not (LABEL if label else NAME).fullmatch(value)
            or any(not LABEL.fullmatch(part) for part in value.split("."))):
        raise ContractError("invalid_ebpf_name")


def bounded_list(value, maximum):
    if type(value) is not list or len(value) > maximum:
        raise ContractError("invalid_ebpf_collection")


def validate(request):
    closed(request, ROOT_KEYS)
    if type(request["schemaVersion"]) is not int or request["schemaVersion"] != 1:
        raise ContractError("unsupported_ebpf_contract")
    uid(request["clusterUid"])
    if any(type(request[key]) is not bool for key in ("optIn", "hostAccessApproved", "excludeSDKInstrumentedServices")):
        raise ContractError("invalid_ebpf_choice")
    if type(request["imageDigest"]) is not str or not IMAGE.fullmatch(request["imageDigest"]):
        raise ContractError("invalid_ebpf_image")
    if type(request["observedAt"]) is not int or not 0 <= request["observedAt"] < 2**53:
        raise ContractError("invalid_ebpf_timestamp")
    bounded_list(request["approvedNodes"], 100)
    bounded_list(request["nodeEvidence"], 100)
    bounded_list(request["workloads"], 100)
    for node in request["approvedNodes"]:
        closed(node, {"name", "uid"})
        name(node["name"])
        uid(node["uid"])
    for node in request["nodeEvidence"]:
        closed(node, NODE_KEYS)
        name(node["name"])
        uid(node["uid"])
        if node["os"] not in ("linux", "windows", "unknown") or node["architecture"] not in ("amd64", "arm64", "unknown"):
            raise ContractError("invalid_ebpf_platform")
        if type(node["kernel"]) is not str or not KERNEL.fullmatch(node["kernel"]):
            raise ContractError("invalid_ebpf_kernel")
        if node["btf"] not in ("present", "absent", "unknown") or type(node["ready"]) is not bool:
            raise ContractError("invalid_ebpf_observation")
        for key in ("admission", "capabilities", "bpfLoad"):
            if node[key] not in ("pass", "fail", "unknown"):
                raise ContractError("invalid_ebpf_observation")
        for key, limit in (("freePodSlots", 100000), ("freeCpuMilli", 100000000), ("freeMemoryMiB", 100000000)):
            if node[key] is not None and (type(node[key]) is not int or not 0 <= node[key] <= limit):
                raise ContractError("invalid_ebpf_capacity")
        if type(node["evidenceSha256"]) is not str or not HASH.fullmatch(node["evidenceSha256"]) or node["evidenceSha256"] == "0" * 64:
            raise ContractError("invalid_ebpf_evidence")
    for workload in request["workloads"]:
        closed(workload, WORKLOAD_KEYS)
        name(workload["namespace"], label=True)
        name(workload["deployment"])
        uid(workload["namespaceUid"])
        uid(workload["uid"])
        if type(workload["sdkInstrumented"]) is not bool:
            raise ContractError("invalid_ebpf_coexistence")
        bounded_list(workload["nodeUids"], 100)
        for value in workload["nodeUids"]:
            uid(value)
        if len(set(workload["nodeUids"])) != len(workload["nodeUids"]):
            raise ContractError("duplicate_ebpf_identity")
    for items, fields in ((request["approvedNodes"], ("name", "uid")), (request["nodeEvidence"], ("name", "uid")),
                          (request["workloads"], ("uid",))):
        if any(len({item[field] for item in items}) != len(items) for field in fields):
            raise ContractError("duplicate_ebpf_identity")
    if len({(item["namespace"], item["deployment"]) for item in request["workloads"]}) != len(request["workloads"]):
        raise ContractError("duplicate_ebpf_identity")
    namespaces = {}
    for item in request["workloads"]:
        if namespaces.setdefault(item["namespace"], item["namespaceUid"]) != item["namespaceUid"]:
            raise ContractError("inconsistent_ebpf_namespace_identity")
    if len(set(namespaces.values())) != len(namespaces):
        raise ContractError("inconsistent_ebpf_namespace_identity")


def assess(request: dict, lock: dict, *, now: int) -> dict:
    """Return sdk-only/hybrid/unsupported; input must be trusted reader evidence."""
    validate(request)
    request = json.loads(canonical(request))
    if type(now) is not int or not 0 <= now < 2**53:
        raise ContractError("invalid_ebpf_clock")
    try:
        image = lock["images"]["beyla"]["distribution"]
        promoted = (type(lock["schemaVersion"]) is int and lock["schemaVersion"] == 1 and lock["distribution"]["publicationStatus"] == "verified"
                    and image["status"] == "verified" and image["repository"] == "docker.io/elvenobservability/elven-ebpf"
                    and image["digest"] == request["imageDigest"] and request["imageDigest"] not in lock.get("runtimeBlocks", {}))
    except (KeyError, TypeError):
        raise ContractError("invalid_ebpf_lock") from None
    reasons = set()
    if request["optIn"]:
        if not promoted:
            reasons.add("ebpf_image_not_promoted_or_blocked")
        if not request["hostAccessApproved"]:
            reasons.add("ebpf_host_access_not_approved")
        if not request["excludeSDKInstrumentedServices"]:
            reasons.add("ebpf_sdk_exclusion_required")
        if not -30 <= now - request["observedAt"] <= 600:
            reasons.add("ebpf_observation_expired")
        if not request["approvedNodes"] or not request["workloads"]:
            reasons.add("ebpf_exact_scope_required")
        expected = {(node["name"], node["uid"]) for node in request["approvedNodes"]}
        observed = {(node["name"], node["uid"]) for node in request["nodeEvidence"]}
        if expected != observed:
            reasons.add("ebpf_node_identity_changed")
        permitted = {node["uid"] for node in request["approvedNodes"]}
        for workload in request["workloads"]:
            if workload["namespace"] in PROTECTED or workload["namespace"].startswith("elven-"):
                reasons.add("ebpf_protected_namespace")
            if workload["sdkInstrumented"]:
                reasons.add("ebpf_sdk_target_overlap")
            if not workload["nodeUids"] or not set(workload["nodeUids"]) <= permitted:
                reasons.add("ebpf_workload_outside_approved_nodes")
        for node in request["nodeEvidence"]:
            kernel = KERNEL.fullmatch(node["kernel"])
            if node["os"] != "linux" or node["architecture"] not in ("amd64", "arm64"):
                reasons.add("ebpf_platform_unsupported")
            if tuple(map(int, kernel.groups())) < (5, 11):
                reasons.add("ebpf_kernel_unsupported")
            if node["btf"] != "present":
                reasons.add("ebpf_btf_not_verified")
            if not node["ready"]:
                reasons.add("ebpf_node_not_ready")
            for key, minimum in (("freePodSlots", 1), ("freeCpuMilli", 200), ("freeMemoryMiB", 1280)):
                if node[key] is None or node[key] < minimum:
                    reasons.add("ebpf_capacity_unconfirmed")
            for key, code in (("admission", "ebpf_admission_unconfirmed"), ("capabilities", "ebpf_capabilities_unconfirmed"),
                              ("bpfLoad", "ebpf_loader_unconfirmed")):
                if node[key] != "pass":
                    reasons.add(code)
    return {"schemaVersion": 1, "mode": "sdk-only" if not request["optIn"] else "unsupported" if reasons else "hybrid",
            "reasons": sorted(reasons), "inputSha256": sha(request), "lockSha256": sha(lock),
            "imageDigest": request["imageDigest"], "runtimeAcceptance": "NOT_PROVEN",
            "requirements": json.loads(canonical(REQUIREMENTS)),
            "approvedNodes": sorted(request["approvedNodes"], key=lambda item: item["name"]),
            "targets": sorted([{key: value for key, value in item.items() if key != "sdkInstrumented"}
                               for item in request["workloads"]], key=lambda item: (item["namespace"], item["deployment"]))}


def pairs(items):
    obj = dict(items)
    if len(obj) != len(items):
        raise ContractError("ambiguous_ebpf_json")
    return obj


def invalid_constant(_value):
    raise ContractError("ambiguous_ebpf_json")


def read_json(path):
    with Path(path).open("rb") as source:
        raw = source.read(1_000_001)
    if not 1 <= len(raw) <= 1_000_000:
        raise ContractError("ebpf_input_size")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_constant)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--lock", type=Path, default=Path(__file__).resolve().parents[1] / "versions.lock.json")
    args = parser.parse_args()
    try:
        result = assess(read_json(args.input), read_json(args.lock), now=int(time.time()))
    except (ContractError, OSError, ValueError, RecursionError):
        parser.exit(2, "ebpf_contract_rejected\n")
    print(canonical(result).decode("ascii"))
    return 1 if result["mode"] == "unsupported" else 0


if __name__ == "__main__":
    raise SystemExit(main())
