#!/usr/bin/env python3
"""Package or verify a reproducible source-only laboratory ZIP; never install."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PATHS = ("charts", "contracts", "scripts", "processor", "operator", "elven",
         "versions.lock.json", "instrumentation.lock.json")
PREFIX = "elven-lab-candidate"
MAX_BYTES = 30_000_000
NOTICE = ("ELVEN LAB ONLY - NOT A CUSTOMER INSTALL KIT\n"
          "No promotion, admission, signature or runtime acceptance is granted.\n"
          "Production bootstrap and immutable v1.0.1 pins are unchanged.\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def safe_name(name):
    path = PurePosixPath(name)
    return (bool(name) and not path.is_absolute() and ".." not in path.parts
            and "\\" not in name and path.as_posix() == name
            and all(part not in ("", ".", ".git", "__pycache__") for part in path.parts))


def build(source, revision):
    """Consume a Git tar, not a working directory or an older release bundle."""
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Exact Git source revision required")
    payload = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(source), mode="r:") as archive:
        for entry in archive:
            if entry.isdir():
                continue
            if (not entry.isfile() or not safe_name(entry.name) or entry.name in payload
                    or not any(entry.name == p or entry.name.startswith(p + "/") for p in PATHS)):
                raise ValueError("Unsafe or unexpected source member")
            total += entry.size
            if entry.size > 4_000_000 or total > MAX_BYTES:
                raise ValueError("Candidate size limit exceeded")
            payload[entry.name] = archive.extractfile(entry).read()
    required = {"charts/elven-observability/values.schema.json", "charts/elven-observability/values.yaml",
                "charts/elven-observability/templates/node-agent.yaml", "charts/elven-instrumentation/values.schema.json",
                "scripts/template_contract.py", "scripts/ebpf-contract.py", "versions.lock.json", "instrumentation.lock.json",
                "contracts/ebpf-eligibility-v1.schema.json", "contracts/template/v1/request.schema.json"}
    if not required <= payload.keys():
        raise ValueError("Candidate chart/contract closure is incomplete")
    schema = json.loads(payload["charts/elven-observability/values.schema.json"])
    if "approvedNodes" not in schema["properties"]["nodeAgent"]["properties"]:
        raise ValueError("Candidate must carry the exact-node chart schema")
    payload["LAB-ONLY.txt"] = NOTICE
    files = {name: digest(raw) for name, raw in sorted(payload.items())}
    manifest = {"schemaVersion": 1, "kind": "ELVEN_LAB_CANDIDATE", "customerInstallable": False,
                "promotion": "NOT_PROMOTED", "runtimeAcceptance": "NOT_PROVEN",
                "sourceRevision": revision, "files": files, "payloadSha256": digest(canonical(files)),
                "productionBootstrap": "UNCHANGED_IMMUTABLE_V1_0_1",
                "requiredGates": ["EXPLICIT_LAB_APPROVAL", "EXACT_TARGET_BINDINGS", "SDK_EBPF_DISJOINT",
                                  "SIGNATURE_VERIFICATION", "KERNEL_BTF_CAPACITY_CNI", "ROLLBACK_READBACK"]}
    raw_manifest = canonical(manifest)
    payload["candidate.manifest.json"] = raw_manifest
    result = io.BytesIO()
    with zipfile.ZipFile(result, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, raw in sorted(payload.items()):
            entry = zipfile.ZipInfo(PREFIX + "/" + name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | 0o644) << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, raw, compresslevel=9)
    return result.getvalue(), raw_manifest


def verify(raw, expected_sha256):
    """Check external trusted SHA before parsing; do not extract or execute."""
    if (not re.fullmatch(r"[0-9a-f]{64}", expected_sha256) or digest(raw) != expected_sha256
            or len(raw) > MAX_BYTES):
        raise ValueError("Candidate checksum or size mismatch")
    payload, total = {}, 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for entry in archive.infolist():
            name = entry.filename
            relative = name.removeprefix(PREFIX + "/")
            total += entry.file_size
            mode = entry.external_attr >> 16
            if (name == relative or not safe_name(relative) or relative in payload or total > MAX_BYTES
                    or entry.file_size > 4_000_000 or stat.S_IFMT(mode) != stat.S_IFREG):
                raise ValueError("Unsafe candidate member")
            payload[relative] = archive.read(entry)
    manifest_raw = payload.pop("candidate.manifest.json", b"")
    manifest = json.loads(manifest_raw)
    files = {name: digest(value) for name, value in sorted(payload.items())}
    if (manifest.get("kind") != "ELVEN_LAB_CANDIDATE" or manifest.get("customerInstallable") is not False
            or manifest.get("promotion") != "NOT_PROMOTED" or manifest.get("runtimeAcceptance") != "NOT_PROVEN"
            or manifest.get("files") != files or manifest.get("payloadSha256") != digest(canonical(files))
            or payload.get("LAB-ONLY.txt") != NOTICE or canonical(manifest) != manifest_raw):
        raise ValueError("Candidate manifest mismatch")
    return manifest


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    sub = parser.add_subparsers(dest="command", required=True)
    pack = sub.add_parser("pack", allow_abbrev=False)
    pack.add_argument("--output-dir", type=Path, required=True)
    check = sub.add_parser("verify", allow_abbrev=False)
    check.add_argument("--archive", type=Path, required=True)
    check.add_argument("--sha256", required=True, help="Trusted out-of-band archive checksum")
    args = parser.parse_args()
    if args.command == "verify":
        with args.archive.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        print(json.dumps(verify(raw, args.sha256), sort_keys=True))
        return
    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT).strip():
        raise ValueError("Commit the exact clean candidate source first")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    source = subprocess.check_output(["git", "archive", "--format=tar", revision, *PATHS], cwd=ROOT)
    raw, manifest = build(source, revision)
    verify(raw, digest(raw))
    stem = PREFIX + "-" + revision[:12]
    files = {stem + ".zip": raw, stem + ".manifest.json": manifest}
    files["SHA256SUMS"] = "".join(digest(content) + "  " + name + "\n" for name, content in files.items()).encode()
    args.output_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    if any(os.path.lexists(args.output_dir / name) for name in files):
        raise ValueError("Refusing to overwrite candidate outputs")
    for name, content in files.items():
        with (args.output_dir / name).open("xb") as stream:
            stream.write(content)
        print(args.output_dir / name)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, tarfile.TarError, subprocess.SubprocessError) as error:
        raise SystemExit("Elven laboratory candidate: " + str(error))
