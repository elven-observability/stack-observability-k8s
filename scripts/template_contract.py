"""Closed template adapter for a stateful engine. No cluster, shell or secret I/O."""
from __future__ import annotations
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import sys
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
VERSION = "elven.template/v1"
ARTIFACT = {"version": "1.0.1",
            "url": "https://github.com/elven-observability/stack-observability-k8s/releases/download/v1.0.1/elven-observability-v1.0.1.tar.gz",
            "sha256": "fdd3dfb6fe621a5c69b6f8a79dc6f4601c6e764b524b66c00681deb56da352db"}
PROTECTED = {"default", "kube-system", "kube-public", "kube-node-lease", "elven-observability", "elven-system"}
REASONS = ("INVALID_DOCUMENT", "CATALOG_CHANGED", "BINDING_CHANGED", "STALE_OBSERVATION",
           "SCOPE_CHANGED", "EXISTING_INSTRUMENTATION", "HOST_CONSENT_REQUIRED",
           "SIGNATURE_VERIFICATION_REQUIRED", "PREFLIGHT_REQUIRED", "CAPACITY_UNPROVEN",
           "INDEPENDENT_DELIVERY_REQUIRED", "EXACT_BASELINE_REQUIRED",
           "FRESH_APPROVAL_REQUIRED", "ROLLBACK_BASELINE_REQUIRED", "RUNTIME_UNSUPPORTED",
           "COLLECTOR_REPROMOTION_REQUIRED", "TEMPLATE_REPACKAGE_REQUIRED")
NAME = {"type": "string", "pattern": r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$", "minLength": 1, "maxLength": 63}
UID = {"type": "string", "format": "uuid", "maxLength": 36}
HASH = {"type": "string", "pattern": "^[0-9a-f]{64}$", "not": {"const": "0"*64}}
BOOL = {"type": "boolean"}


class ContractError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def obj(properties):
    return {"type": "object", "additionalProperties": False, "properties": properties, "required": list(properties)}


def arr(item, minimum=0, maximum=32):
    return {"type": "array", "items": item, "minItems": minimum, "maxItems": maximum, "uniqueItems": True}


def request_schema():
    return {"$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://elvenobservability.com/contracts/template/v1/request", **obj({
        "contractVersion": {"const": VERSION}, "catalogSha256": HASH,
        "cluster": obj({"uid": UID, "serverSha256": HASH, "caSha256": HASH,
                        "name": {"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$"}}),
        "observedAt": {"type": "string", "format": "date-time", "maxLength": 40},
        "namespace": NAME, "release": NAME, "operatorRelease": NAME,
        "tenantId": {"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"},
        "namespaces": arr(obj({"name": NAME, "uid": UID}), 1),
        "apps": arr(obj({"namespaceUid": UID, "name": NAME, "uid": UID,
                         "resourceVersion": {"type": "string", "pattern": r"^[A-Za-z0-9_.:-]{1,128}$"},
                         "templateSha256": HASH, "container": NAME, "runtime": {"enum": ["java", "nodejs", "python"]},
                         "existingInstrumentation": {"enum": ["none", "sdk", "unknown"]}}), 0, 100),
        "nodes": arr(obj({"name": {"type": "string", "pattern": r"^[a-z0-9][a-z0-9.-]{0,252}$"}, "uid": UID}), 0, 100),
        "collection": obj({"stdout": BOOL, "hostAccessApproved": BOOL, "clusterMetrics": BOOL,
                           "clusterWideMetricsApproved": BOOL, "privacy": {"enum": ["strict", "selective"]}}),
        "storage": obj({"class": NAME, "sizeGiB": {"type": "integer", "minimum": 1, "maximum": 1000}}),
        "network": obj({"exports": arr({"type": "string", "format": "cidr", "maxLength": 64}, 1),
                        "api": arr({"type": "string", "format": "cidr", "maxLength": 64}, 1),
                        "dnsNamespace": NAME, "dns": arr({"type": "string", "format": "cidr", "maxLength": 64})}),
        "traceSampling": {"enum": ["1", "0.5", "0.1", "0.01"]},
        "ebpf": {"oneOf": [{"type": "null"}, read_document(ROOT / "contracts/ebpf-eligibility-v1.schema.json")]},
    })}


def baseline_schema():
    return obj({
        "planSha256": HASH, "clusterUid": UID, "snapshotSha256": HASH,
        "observedAt": {"type": "string", "format": "date-time", "maxLength": 40},
        "coreReleaseUid": UID, "operatorReleaseUid": {"oneOf": [UID, {"type": "null"}]},
        "coreRevision": {"type": "integer", "minimum": 1, "maximum": 1000000},
        "operatorRevision": {"type": "integer", "minimum": 0, "maximum": 1000000},
        "currentCoreRevision": {"type": "integer", "minimum": 1, "maximum": 1000000},
        "currentOperatorRevision": {"type": "integer", "minimum": 0, "maximum": 1000000},
        "apps": arr(obj({"uid": UID, "snapshotSha256": HASH,
                        "currentResourceVersion": {"type": "string", "pattern": r"^[A-Za-z0-9_.:-]{1,128}$"},
                        "currentTemplateSha256": HASH}), 0, 100),
    })


def plan_schema():
    release_target = obj({"namespace": NAME, "release": NAME})
    app_target = obj({"namespace": NAME, **{key: spec for key, spec in request_schema()["properties"]["apps"]["items"]["properties"].items()
                                           if key != "existingInstrumentation"}})
    phase = {"oneOf": [
        obj({"id": {"enum": ["core"]}, "kind": {"enum": ["CORE_APPLY"]}, "target": release_target}),
        obj({"id": {"enum": ["operator"]}, "kind": {"enum": ["OPERATOR_APPLY"]}, "target": release_target}),
        obj({"id": {"type": "string", "pattern": r"^app-[0-9a-f-]{36}$"}, "kind": {"enum": ["APP_OPT_IN"]}, "target": app_target}),
    ]}
    decision = {"oneOf": [
        obj({"mode": {"const": "sdk-only"}, "reasons": {"const": []}, "runtimeAcceptance": {"const": "NOT_PROVEN"}}),
        read_document(ROOT / "contracts/ebpf-assessment-v1.schema.json"),
    ]}
    return {"$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://elvenobservability.com/contracts/template/v1/plan", **obj({
        "contractVersion": {"const": VERSION}, "catalogSha256": HASH, "artifact": {"const": ARTIFACT},
        "requestSha256": HASH, "planSha256": HASH, "selection": request_schema(),
        "actions": arr(phase, 1, 102), "validUntil": {"type": "string", "format": "date-time"},
        "gates": obj({name: {"const": "UNKNOWN"} for name in catalog()["preconditions"]}),
        "ebpfDecision": decision, "state": {"const": "REQUIRES_ENGINE_APPROVAL"},
        "rollbackPolicy": {"const": "EXACT_BASELINE_RETAIN_SECRETS_AND_PVCS"},
    })}


def validate(value, spec, depth=0):
    if (depth > 24 or ("const" in spec and value != spec["const"]) or ("enum" in spec and value not in spec["enum"])
            or "not" in spec and value == spec["not"].get("const")):
        raise ContractError("INVALID_DOCUMENT")
    kind = spec.get("type")
    if "oneOf" in spec:
        matches = 0
        for choice in spec["oneOf"]:
            try:
                validate(value, choice, depth + 1)
                matches += 1
            except ContractError:
                pass
        if matches != 1:
            raise ContractError("INVALID_DOCUMENT")
        return
    if kind == "null" and value is not None:
        raise ContractError("INVALID_DOCUMENT")
    if kind == "object":
        if type(value) is not dict or not set(spec["required"]) <= set(value) or set(value) - set(spec["properties"]):
            raise ContractError("INVALID_DOCUMENT")
        for key, item in value.items():
            validate(item, spec["properties"][key], depth + 1)
    elif kind == "array":
        if type(value) is not list or not spec.get("minItems", 0) <= len(value) <= spec.get("maxItems", 100) or len({sha(v) for v in value}) != len(value):
            raise ContractError("INVALID_DOCUMENT")
        for item in value:
            validate(item, spec["items"], depth + 1)
    elif kind == "boolean":
        if type(value) is not bool:
            raise ContractError("INVALID_DOCUMENT")
    elif kind == "integer":
        if type(value) is not int or not spec.get("minimum", 0) <= value <= spec.get("maximum", 2**53):
            raise ContractError("INVALID_DOCUMENT")
    elif kind == "string":
        if type(value) is not str or not spec.get("minLength", 0) <= len(value) <= spec.get("maxLength", 4096):
            raise ContractError("INVALID_DOCUMENT")
        if "pattern" in spec and re.fullmatch(spec["pattern"], value) is None:
            raise ContractError("INVALID_DOCUMENT")
        try:
            if spec.get("format") == "uuid" and (str(UUID(value)) != value or UUID(value).int == 0):
                raise ValueError
            if spec.get("format") == "cidr":
                network = ipaddress.ip_network(value, strict=True)
                if str(network) != value or network.prefixlen == 0:
                    raise ValueError
            if spec.get("format") == "date-time" and datetime.fromisoformat(value.replace("Z", "+00:00")).utcoffset() != timedelta(0):
                raise ValueError
        except (ValueError, TypeError):
            raise ContractError("INVALID_DOCUMENT") from None


def read_document(path):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ContractError("INVALID_DOCUMENT")
            result[key] = value
        return result
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(256_001)
        if len(raw) > 256_000:
            raise ValueError
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (OSError, ValueError, RecursionError, UnicodeError):
        raise ContractError("INVALID_DOCUMENT") from None


def catalog(root=ROOT):
    """Bind exact source files and historical image predicates; no Git/network."""
    root = Path(root)
    locks = [read_document(root / name) for name in ("versions.lock.json", "instrumentation.lock.json")]
    images = {}
    for lock in locks:
        if lock["distribution"]["publicationStatus"] != "verified" or lock["distribution"]["version"] != ARTIFACT["version"]:
            raise ContractError("CATALOG_CHANGED")
        for name, item in lock["images"].items():
            image = item["distribution"]
            if (image["status"] != "verified" or image["digest"] in locks[0]["runtimeBlocks"]
                    or not re.fullmatch(r"docker.io/elvenobservability/elven-[a-z0-9-]+", image["repository"])
                    or not re.fullmatch(r"sha256:[0-9a-f]{64}", image["digest"])
                    or image["attestations"]["subjectDigest"] != image["digest"]):
                raise ContractError("CATALOG_CHANGED")
            images[name] = {key: image[key] for key in ("repository", "digest", "sourceRevision", "attestations")}
            workflow = "images.yaml" if name in ("collector", "beyla", "alloy") else "instrumentation.yaml"
            images[name]["signature"] = {
                "issuer": "https://token.actions.githubusercontent.com",
                "identity": "https://github.com/elven-observability/stack-observability-k8s/.github/workflows/" + workflow + "@refs/tags/" + image["tag"],
                "verification": "REQUIRED_AT_ADMISSION",
            }
    paths = [root / "elven", *(root / name for name in ("versions.lock.json", "instrumentation.lock.json"))]
    for directory in ("charts", "scripts", "processor", "operator", "contracts"):
        paths.extend(p for p in (root / directory).rglob("*") if p.is_file()
                     and "__pycache__" not in p.parts and p.suffix != ".pyc")
    paths = sorted({p for p in paths if "/fixtures/" not in p.as_posix() and p.name != "CATALOG.json"})
    files = []
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ContractError("CATALOG_CHANGED")
        files.append({"path": path.relative_to(root).as_posix(), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    result = {"contractVersion": VERSION, "templateId": "elven-kubernetes", "artifact": ARTIFACT,
              "adapterContentSha256": sha(files), "files": files, "images": images,
              "modules": ["gateway", "stdout", "cluster-metrics", "sdk-java", "sdk-nodejs", "sdk-python", "ebpf"],
              "actions": ["CORE_APPLY", "OPERATOR_APPLY", "APP_OPT_IN", "CORE_ROLLBACK", "OPERATOR_ROLLBACK", "APP_RESTORE"],
              "limits": {"namespaces": 32, "apps": 100, "nodes": 100, "phaseSeconds": 900, "observationAgeSeconds": 600, "actionCount": 102},
              "preconditions": ["SIGNATURE_VERIFICATION_REQUIRED", "COLLECTOR_REPROMOTION_REQUIRED", "PREFLIGHT_REQUIRED", "CAPACITY_UNPROVEN",
                                "EXACT_BASELINE_REQUIRED", "FRESH_APPROVAL_REQUIRED", "INDEPENDENT_DELIVERY_REQUIRED"],
              "reasonCodes": list(REASONS), "engineOwns": ["authorization", "state", "discovery", "dispatch", "verification"],
              "executionAdapter": "MATERIALIZATION_ONLY",
              "dataCapabilities": {"http": "method.route.status", "exceptions": "selective.known-patterns",
                                   "sql": "sanitized.structure", "redis": "REQUIRES_NEW_PROMOTED_COLLECTOR",
                                   "exactNodeHostCollection": "REQUIRES_REPACKAGED_TEMPLATE"}}
    return {**result, "catalogSha256": sha(result)}


def checked_request(request, selected_catalog, now):
    request = json.loads(canonical(request))
    validate(request, request_schema())
    if request["catalogSha256"] != selected_catalog["catalogSha256"]:
        raise ContractError("CATALOG_CHANGED")
    observed = datetime.fromisoformat(request["observedAt"].replace("Z", "+00:00"))
    if now.utcoffset() != timedelta(0) or not -30 <= (now - observed).total_seconds() <= 600:
        raise ContractError("STALE_OBSERVATION")
    namespaces = {item["uid"]: item["name"] for item in request["namespaces"]}
    if (len(namespaces) != len(request["namespaces"]) or len(set(namespaces.values())) != len(namespaces)
            or PROTECTED.intersection(namespaces.values()) or request["namespace"] in namespaces.values()
            or request["release"] == request["operatorRelease"] or len(request["release"]) > 40 or len(request["operatorRelease"]) > 40):
        raise ContractError("SCOPE_CHANGED")
    if len({app["uid"] for app in request["apps"]}) != len(request["apps"]) or len({(app["namespaceUid"], app["name"]) for app in request["apps"]}) != len(request["apps"]):
        raise ContractError("SCOPE_CHANGED")
    if len({node["uid"] for node in request["nodes"]}) != len(request["nodes"]) or len({node["name"] for node in request["nodes"]}) != len(request["nodes"]):
        raise ContractError("SCOPE_CHANGED")
    for app in request["apps"]:
        if app["namespaceUid"] not in namespaces:
            raise ContractError("SCOPE_CHANGED")
        if app["existingInstrumentation"] != "none":
            raise ContractError("EXISTING_INSTRUMENTATION")
    collection = request["collection"]
    if collection["stdout"] != collection["hostAccessApproved"] or collection["stdout"] and not request["nodes"]:
        raise ContractError("HOST_CONSENT_REQUIRED")
    if collection["clusterMetrics"] != collection["clusterWideMetricsApproved"]:
        raise ContractError("SCOPE_CHANGED")
    for field in ("namespaces", "apps", "nodes"):
        request[field].sort(key=lambda item: item["uid"])
    return request


def plan(request, selected_catalog=None, *, now=None):
    selected_catalog = catalog() if selected_catalog is None else selected_catalog
    now = datetime.now(timezone.utc) if now is None else now
    request = checked_request(request, selected_catalog, now)
    decision = assess_ebpf(request, now)
    namespaces = {item["uid"]: item["name"] for item in request["namespaces"]}
    actions = [{"id": "core", "kind": "CORE_APPLY", "target": {"namespace": request["namespace"], "release": request["release"]}}]
    if request["apps"]:
        actions.append({"id": "operator", "kind": "OPERATOR_APPLY", "target": {"namespace": request["namespace"], "release": request["operatorRelease"]}})
    for app in request["apps"]:
        actions.append({"id": "app-" + app["uid"], "kind": "APP_OPT_IN", "target": {
            "namespace": namespaces[app["namespaceUid"]], "namespaceUid": app["namespaceUid"],
            **{key: app[key] for key in ("name", "uid", "resourceVersion", "templateSha256", "container", "runtime")}}})
    result = {"contractVersion": VERSION, "catalogSha256": selected_catalog["catalogSha256"], "artifact": ARTIFACT,
              "requestSha256": sha(request), "selection": request, "actions": actions,
              "validUntil": (datetime.fromisoformat(request["observedAt"].replace("Z", "+00:00")) + timedelta(seconds=600)).isoformat(),
              "gates": {name: "UNKNOWN" for name in selected_catalog["preconditions"]},
              "ebpfDecision": decision,
              "state": "REQUIRES_ENGINE_APPROVAL", "rollbackPolicy": "EXACT_BASELINE_RETAIN_SECRETS_AND_PVCS"}
    return {**result, "planSha256": sha(result)}


def assess_ebpf(selection, now):
    evidence = selection["ebpf"]
    if evidence is None:
        return {"mode": "sdk-only", "reasons": [], "runtimeAcceptance": "NOT_PROVEN"}
    spec = importlib.util.spec_from_file_location("elven_ebpf_template", ROOT / "scripts/ebpf-contract.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        decision = module.assess(evidence, read_document(ROOT / "versions.lock.json"), now=int(now.timestamp()))
    except (module.ContractError, KeyError, ValueError, TypeError):
        raise ContractError("INVALID_DOCUMENT") from None
    known_namespaces = {item["uid"]: item["name"] for item in selection["namespaces"]}
    sdk_names = {(known_namespaces[app["namespaceUid"]], app["name"]) for app in selection["apps"]}
    if (evidence["clusterUid"] != selection["cluster"]["uid"]
            or sorted(evidence["approvedNodes"], key=lambda n: n["uid"]) != selection["nodes"]
            or any(known_namespaces.get(item["namespaceUid"]) != item["namespace"] for item in evidence["workloads"])
            or {a["uid"] for a in selection["apps"]}.intersection(item["uid"] for item in evidence["workloads"])
            or sdk_names.intersection((item["namespace"], item["deployment"]) for item in evidence["workloads"])):
        raise ContractError("SCOPE_CHANGED")
    # Preserve unsupported with fixed reasons so hosts can explain the blocked
    # proposal. Materialization below refuses to emit host capture values.
    return decision


def validate_plan(value, selected_catalog=None, *, now=None, historical=False):
    reconstruction_time = datetime.fromisoformat(value["selection"]["observedAt"].replace("Z", "+00:00")) if historical else now
    expected = plan(value["selection"], selected_catalog, now=reconstruction_time)
    if canonical(value) != canonical(expected):
        raise ContractError("INVALID_DOCUMENT")
    return expected


def materialize(value, selected_catalog=None, *, now=None):
    """Re-derive fixed public values, never accept caller-authored YAML/commands."""
    value = validate_plan(value, selected_catalog, now=now)
    if value["ebpfDecision"]["mode"] == "unsupported":
        raise ContractError("RUNTIME_UNSUPPORTED")
    # The immutable advertised v1.0.1 bundle predates approvedNodes. Never
    # silently drop exact host scope or emit values its closed schema rejects.
    if value["selection"]["nodes"] or value["ebpfDecision"]["mode"] == "hybrid":
        raise ContractError("TEMPLATE_REPACKAGE_REQUIRED")
    return _public_values(value)


def _public_values(value):
    """Pure values for diffing; not an execution/compatibility admission port."""
    selection = value["selection"]
    collection, network = selection["collection"], selection["network"]
    namespaces = [item["name"] for item in selection["namespaces"]]
    runtimes = {app["runtime"] for app in selection["apps"]}
    core = {"cluster": {"name": selection["cluster"]["name"]}, "collection": {"namespaces": namespaces},
            "privacy": {"logBodyMode": collection["privacy"]},
            "gateway": {"persistence": {"enabled": True, "size": str(selection["storage"]["sizeGiB"]) + "Gi", "storageClass": selection["storage"]["class"]}},
            "modules": {"logs": {"enabled": collection["stdout"], "hostAccessApproved": collection["stdout"]},
                        "clusterMetrics": {"enabled": collection["clusterMetrics"], "clusterWideApproved": collection["clusterMetrics"]},
                        "ebpf": {"enabled": False}, "profiles": {"enabled": False}},
            "networkPolicy": {"enabled": True, "exportCIDRs": network["exports"], "apiServerCIDRs": network["api"],
                              "dnsNamespace": network["dnsNamespace"], "dnsCIDRs": network["dns"]}}
    operator = {"enabled": bool(selection["apps"]), "namespaces": namespaces,
                "gateway": {"sourceRelease": selection["release"], "sourceNamespace": selection["namespace"],
                            "endpoint": f"https://{selection['release']}-gateway.{selection['namespace']}.svc.cluster.local:4318"},
                "runtimes": {**{runtime: runtime in runtimes for runtime in ("java", "nodejs", "python")}, "nodejs20": False, "legacyNode20Approved": False},
                "samplingRatio": selection["traceSampling"], "networkPolicy": {"enabled": True, "apiServerCIDRs": network["api"]}}
    if selection["nodes"]:
        core["nodeAgent"] = {"approvedNodes": [item["name"] for item in selection["nodes"]]}
    if value["ebpfDecision"]["mode"] == "hybrid":
        core["modules"]["ebpf"] = {
            "enabled": True, "hostAccessApproved": True, "excludeSDKInstrumentedServices": True,
            "additionalCapabilities": [], "additionalCapabilitiesApproved": False,
            "workloads": [{"namespace": target["namespace"], "deployment": target["deployment"]}
                          for target in value["ebpfDecision"]["targets"]],
        }
    return {"contractVersion": VERSION, "planSha256": value["planSha256"], "coreValues": core,
            "operatorValues": operator, "applicationActions": [a for a in value["actions"] if a["kind"] == "APP_OPT_IN"],
            "tenantSource": "ENGINE_SECRET_BINDING", "execution": "ENGINE_PHASE_PORT"}


def diff(previous, desired, selected_catalog=None, *, now=None):
    selected_catalog = catalog() if selected_catalog is None else selected_catalog
    old = validate_plan(previous, selected_catalog, now=now, historical=True)
    new = validate_plan(desired, selected_catalog, now=now)
    if old["selection"]["cluster"] != new["selection"]["cluster"] or any(old["selection"][key] != new["selection"][key]
                                                                 for key in ("namespace", "release", "operatorRelease", "tenantId")):
        raise ContractError("BINDING_CHANGED")
    before, after = {a["id"]: a for a in old["actions"]}, {a["id"]: a for a in new["actions"]}
    changed = sorted(key for key in before.keys() & after.keys() if before[key] != after[key])
    if old["requestSha256"] != new["requestSha256"] and "core" not in changed:
        changed.append("core")
    if ("operator" in before.keys() & after.keys()
            and _public_values(old)["operatorValues"] != _public_values(new)["operatorValues"]
            and "operator" not in changed):
        changed.append("operator")
    result = {"contractVersion": VERSION, "beforePlanSha256": old["planSha256"], "afterPlanSha256": new["planSha256"],
              "added": sorted(after.keys() - before.keys()), "removed": sorted(before.keys() - after.keys()), "changed": sorted(changed),
              "destructiveChangesRequireNewApproval": bool(before.keys() - after.keys()), "execution": "NONE"}
    return {**result, "diffSha256": sha(result)}


def rollback(value, baseline, selected_catalog=None, *, now=None):
    value = validate_plan(value, selected_catalog, now=now, historical=True)
    validate(baseline, baseline_schema())
    if baseline["planSha256"] != value["planSha256"] or baseline["clusterUid"] != value["selection"]["cluster"]["uid"]:
        raise ContractError("ROLLBACK_BASELINE_REQUIRED")
    observed = datetime.fromisoformat(baseline["observedAt"].replace("Z", "+00:00"))
    now = now or datetime.now(timezone.utc)
    if now.utcoffset() != timedelta(0) or not -30 <= (now - observed).total_seconds() <= 60:
        raise ContractError("STALE_OBSERVATION")
    apps = {app["uid"]: app for app in baseline["apps"]}
    if set(apps) != {app["uid"] for app in value["selection"]["apps"]} or len(apps) != len(baseline["apps"]):
        raise ContractError("ROLLBACK_BASELINE_REQUIRED")
    if baseline["coreRevision"] > baseline["currentCoreRevision"] or baseline["operatorRevision"] > baseline["currentOperatorRevision"]:
        raise ContractError("ROLLBACK_BASELINE_REQUIRED")
    actions = [{"kind": "APP_RESTORE", "uid": app["uid"], "snapshotSha256": apps[app["uid"]]["snapshotSha256"],
                "expectedResourceVersion": apps[app["uid"]]["currentResourceVersion"],
                "expectedTemplateSha256": apps[app["uid"]]["currentTemplateSha256"]} for app in reversed(value["selection"]["apps"])]
    if value["selection"]["apps"]:
        if not baseline["operatorRevision"] or baseline["operatorReleaseUid"] is None:
            raise ContractError("ROLLBACK_BASELINE_REQUIRED")
        actions.append({"kind": "OPERATOR_ROLLBACK", "revision": baseline["operatorRevision"],
                        "namespace": value["selection"]["namespace"], "release": value["selection"]["operatorRelease"],
                        "expectedReleaseUid": baseline["operatorReleaseUid"], "expectedCurrentRevision": baseline["currentOperatorRevision"]})
    actions.append({"kind": "CORE_ROLLBACK", "revision": baseline["coreRevision"],
                    "namespace": value["selection"]["namespace"], "release": value["selection"]["release"],
                    "expectedReleaseUid": baseline["coreReleaseUid"], "expectedCurrentRevision": baseline["currentCoreRevision"]})
    result = {"contractVersion": VERSION, "planSha256": value["planSha256"], "baselineSha256": sha(baseline),
              "snapshotSha256": baseline["snapshotSha256"], "actions": actions,
              "state": "REQUIRES_FRESH_ENGINE_APPROVAL", "deleteSecrets": False, "deletePVCs": False, "unknownOutcome": "HOLD_WITHOUT_REPLAY"}
    return {**result, "rollbackSha256": sha(result)}


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("command", choices=("catalog", "schema", "plan", "apply", "materialize", "diff", "rollback"))
    parser.add_argument("--schema", choices=("request", "plan", "baseline"), default="request")
    parser.add_argument("--input", type=Path)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--baseline", type=Path)
    args = parser.parse_args()
    if args.command == "catalog":
        result = catalog()
    elif args.command == "schema":
        result = {"request": request_schema, "plan": plan_schema, "baseline": baseline_schema}[args.schema]()
    else:
        if not args.input:
            raise ContractError("INVALID_DOCUMENT")
        value = read_document(args.input)
        if args.command == "plan":
            result = plan(value)
        elif args.command in ("materialize", "apply"):
            result = materialize(value)
        elif args.command == "diff" and args.previous:
            result = diff(read_document(args.previous), value)
        elif args.command == "rollback" and args.baseline:
            result = rollback(value, read_document(args.baseline))
        else:
            raise ContractError("INVALID_DOCUMENT")
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ContractError, KeyError, TypeError, ValueError, OSError):
        print('{"error":"INVALID_DOCUMENT_OR_BINDING","execution":"NONE"}', file=sys.stderr)
        raise SystemExit(1) from None
