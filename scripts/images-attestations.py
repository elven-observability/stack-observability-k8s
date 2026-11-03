"""Bind Cosign-verified DSSE predicates to the exact approved Elven evidence.

This is NOT a signature verifier. Call it only with stdout from a successful
Cosign verification retaining issuer, identity and transparency-log checks.
Cosign v3.1.4 emits a JSON stream of DSSE envelopes. SPDX/custom-URI inputs
become the predicate directly; only the unrelated `custom` alias adds a wrapper.
"""
from __future__ import annotations

import base64
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re


SPDX_TYPE = "https://spdx.dev/Document"
CANONICALIZATION = "elven-json-v1"
PLATFORMS = {"linux/amd64", "linux/arm64"}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
MAX_BYTES = 64 * 1024 * 1024
MAX_STATEMENTS = 64


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate JSON member in attestation evidence")
        result[key] = value
    return result


def _constant(_):
    raise ValueError("Non-finite JSON number in attestation evidence")


DECODER = json.JSONDecoder(object_pairs_hook=_pairs, parse_int=Decimal,
                          parse_float=Decimal, parse_constant=_constant)


def _load(value):
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_BYTES:
        raise ValueError("Attestation JSON is absent or exceeds its bounded size")
    try:
        return DECODER.decode(value)
    except (ValueError, RecursionError) as error:
        raise ValueError("Malformed attestation JSON") from error


def canonical_hash(value):
    """Elven JSON v1: sorted keys, ASCII strings, normalized exact JSON numbers.

    Decimal parsing makes 1 and 1.0 equivalent after Cosign's protobuf JSON
    round-trip without silently accepting float rounding of large integers.
    This named format is not a claim of RFC 8785/JCS compliance.
    """
    budget = [1_000_000]

    def encode(item, depth=0):
        budget[0] -= 1
        if depth > 64 or budget[0] < 0:
            raise ValueError("Attestation JSON exceeds canonicalization limits")
        if item is None:
            return "null"
        if isinstance(item, bool):
            return "true" if item else "false"
        if isinstance(item, str):
            item.encode("utf-8")  # Reject unpaired surrogates rather than hash them differently from Go.
            return json.dumps(item, ensure_ascii=True)
        if isinstance(item, (int, float, Decimal)):
            number = item if isinstance(item, Decimal) else Decimal(str(item))
            if not number.is_finite() or len(number.as_tuple().digits) > 1024 or abs(number.adjusted()) > 4096:
                raise ValueError("Unsupported JSON numeric range in attestation evidence")
            if not number:
                return "0"
            rendered = format(number, "f")
            return rendered.rstrip("0").rstrip(".") if "." in rendered else rendered
        if isinstance(item, list):
            return "[" + ",".join(encode(entry, depth + 1) for entry in item) + "]"
        if isinstance(item, dict) and all(isinstance(key, str) for key in item):
            return "{" + ",".join(encode(key, depth + 1) + ":" + encode(item[key], depth + 1)
                                  for key in sorted(item)) + "}"
        raise ValueError("Unsupported value in attestation JSON")

    try:
        encoded = encode(value).encode("ascii")
    except (UnicodeError, RecursionError) as error:
        raise ValueError("Invalid Unicode or nesting in attestation JSON") from error
    if len(encoded) > MAX_BYTES:
        raise ValueError("Canonical attestation JSON exceeds its bounded size")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def validate_policy(policy, subject_digest, build_type, platforms=PLATFORMS):
    if (not isinstance(policy, dict) or policy.get("schemaVersion") != 1
            or policy.get("canonicalization") != CANONICALIZATION
            or not isinstance(subject_digest, str) or not DIGEST.fullmatch(subject_digest)
            or policy.get("subjectDigest") != subject_digest
            or set(platforms) != PLATFORMS):
        raise ValueError("Missing or incompatible exact-attestation policy")
    spdx = policy.get("spdx")
    build = policy.get("build")
    if (not isinstance(spdx, dict) or set(spdx) != set(platforms)
            or any(not isinstance(value, str) or not DIGEST.fullmatch(value) for value in spdx.values())
            or len(set(spdx.values())) != len(platforms)
            or not isinstance(build, dict) or build.get("predicateType") != build_type
            or not isinstance(build.get("sha256"), str) or not DIGEST.fullmatch(build["sha256"])):
        raise ValueError("Both platform SPDX predicates and the exact build predicate are required")
    return {SPDX_TYPE: set(spdx.values()), build_type: {build["sha256"]}}


def evidence_policy(directory, image, build_type, platforms=PLATFORMS):
    directory = Path(directory).resolve()

    def read(name, checksum):
        if not isinstance(name, str) or Path(name).name != name:
            raise ValueError("Attestation evidence must be a local archive companion file")
        path = directory / name
        if path.is_symlink() or path.resolve().parent != directory:
            raise ValueError("Attestation evidence escapes its approved directory")
        if path.stat().st_size > MAX_BYTES:
            raise ValueError("Attestation evidence exceeds its bounded size")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != checksum:
            raise ValueError("Approved attestation evidence checksum changed")
        return canonical_hash(_load(raw.decode("utf-8")))

    policy = {"schemaVersion": 1, "canonicalization": CANONICALIZATION,
              "subjectDigest": image["digest"], "spdx": {},
              "build": {"predicateType": build_type,
                        "sha256": read(image["metadata"], image["metadataSha256"])}}
    for platform in platforms:
        entry = image["scans"][platform]
        policy["spdx"][platform] = read(entry["sbom"], entry["sbomSha256"])
    validate_policy(policy, image["digest"], build_type, platforms)
    return policy


def verify_predicates(stdout, policy, subject_digest, predicate_type, build_type):
    """Validate the predicates AFTER cryptographic Cosign verification succeeds."""
    approved = validate_policy(policy, subject_digest, build_type)
    if predicate_type not in approved:
        raise ValueError("Unexpected verified predicate type")
    expected = approved[predicate_type]
    if not isinstance(stdout, str) or len(stdout.encode("utf-8")) > MAX_BYTES:
        raise ValueError("Cosign attestation output is absent or oversized")
    envelopes, offset = [], 0
    while offset < len(stdout):
        while offset < len(stdout) and stdout[offset] in " \t\r\n":
            offset += 1
        if offset == len(stdout):
            break
        try:
            item, offset = DECODER.raw_decode(stdout, offset)
        except (ValueError, RecursionError) as error:
            raise ValueError("Cosign attestation output is not a JSON stream") from error
        envelopes.extend(item if isinstance(item, list) else [item])
        if len(envelopes) > MAX_STATEMENTS:
            raise ValueError("Too many verified attestation envelopes")
    actual = set()
    for envelope in envelopes:
        if (not isinstance(envelope, dict) or envelope.get("payloadType") != "application/vnd.in-toto+json"
                or not isinstance(envelope.get("payload"), str)
                or not isinstance(envelope.get("signatures"), list) or not envelope["signatures"]):
            raise ValueError("Malformed verified DSSE envelope")
        try:
            for signature in envelope["signatures"]:
                if (not isinstance(signature, dict) or not isinstance(signature.get("sig"), str)
                        or not base64.b64decode(signature["sig"], validate=True)):
                    raise ValueError("Malformed verified DSSE signature")
            statement = _load(base64.b64decode(envelope["payload"], validate=True).decode("utf-8"))
        except (ValueError, UnicodeError) as error:
            raise ValueError("Malformed verified DSSE payload") from error
        if (not isinstance(statement, dict)
                or statement.get("_type") not in ("https://in-toto.io/Statement/v0.1", "https://in-toto.io/Statement/v1")
                or statement.get("predicateType") != predicate_type
                or not isinstance(statement.get("subject"), list) or len(statement["subject"]) != 1
                or not isinstance(statement["subject"][0], dict)
                or statement["subject"][0].get("digest") != {"sha256": subject_digest.removeprefix("sha256:")}
                or not isinstance(statement.get("predicate"), dict)):
            raise ValueError("Verified attestation has an unexpected subject, type or predicate")
        actual.add(canonical_hash(statement["predicate"]))
    # Repeated copies of one envelope cannot stand in for the other platform.
    # Exact duplicate valid envelopes are harmless on an idempotent retry.
    if actual != expected:
        raise ValueError("Verified predicates do not match all exact approved SPDX/build evidence")
    return {"predicateType": predicate_type, "verifiedPredicateCount": len(actual),
            "predicateSha256": sorted(actual)}
