#!/usr/bin/env python3
"""Read-only CI admission for exact, fresh, unpromoted lab OCI archives."""
from __future__ import annotations
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat

ROOT = Path(__file__).resolve().parents[1]


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def regular(folder, name):
    if not isinstance(name, str) or Path(name).name != name or name in ("", ".", ".."):
        raise ValueError("Unsafe evidence filename")
    path = folder / name
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("Evidence must be a regular file")
    return path


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def fresh(value, now, hours):
    observed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if observed.utcoffset() != timedelta(0) or not -30 <= (now - observed).total_seconds() <= hours * 3600:
        raise ValueError("Evidence is stale or from the future")


def qualify(folder, manifest, lock, expected_inputs, *, now):
    if manifest.get("dirtySource") is not False or not re.fullmatch(r"[0-9a-f]{40}", manifest.get("revision", "")):
        raise ValueError("Unchanged, clean image source identity required")
    if set(manifest.get("images", {})) != set(lock["images"]):
        raise ValueError("Complete image family required")
    result = {}
    for name, image in manifest["images"].items():
        wanted = lock["images"][name]["distribution"]["repository"]
        if (not re.fullmatch(re.escape(wanted) + r":v?1\.[0-9]+\.[0-9]+(?:-dev|-rc\.[0-9]+)?", image["tag"])
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", image["digest"])
                or image["digest"] in lock.get("runtimeBlocks", {})):
            raise ValueError("Unexpected or blocked Elven candidate image")
        if image["inputsSha256"] != expected_inputs(name, lock["images"][name]):
            raise ValueError("Image build inputs changed; rebuild rather than reusing an old archive")
        if digest(regular(folder, image["archive"])) != image["archiveSha256"]:
            raise ValueError("OCI archive checksum mismatch")
        if set(image["scans"]) != {"linux/amd64", "linux/arm64"}:
            raise ValueError("Both architecture scans are required")
        for platform, scan in image["scans"].items():
            if (scan.get("status") != "passed" or type(scan.get("highCriticalCount")) is not int
                    or scan["highCriticalCount"] != 0 or scan.get("scanner") != "trivy/" + lock["tools"]["trivy"]):
                raise ValueError("Fresh pinned scans with zero High/Critical required")
            fresh(scan["scannedAt"], now, 24)
            fresh(scan["database"]["UpdatedAt"], now, 48)
            for key in ("report", "sbom"):
                if digest(regular(folder, scan[key])) != scan[key + "Sha256"]:
                    raise ValueError("Scan/SBOM checksum mismatch")
        if name == "collector":
            audits = image.get("govulncheck", {})
            if set(audits) != set(image["scans"]):
                raise ValueError("Both exact Collector binaries need Govulncheck")
            for audit in audits.values():
                if (audit.get("status") != "passed" or type(audit.get("exitCode")) is not int
                        or audit["exitCode"] != 0 or audit.get("tool") != "govulncheck/" + lock["tools"]["govulncheck"]
                        or audit.get("image") != image["tag"] + "@" + image["digest"]):
                    raise ValueError("Exact Collector Govulncheck gate failed")
                fresh(audit["scannedAt"], now, 24)
                if digest(regular(folder, audit["report"])) != audit["reportSha256"]:
                    raise ValueError("Govulncheck checksum mismatch")
        result[name] = image["tag"] + "@" + image["digest"]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--core-manifest", type=Path, required=True)
    parser.add_argument("--sdk-manifest", type=Path, required=True)
    args = parser.parse_args()
    core, sdk = module("candidate_core", "images-release.py"), module("candidate_sdk", "images-instrumentation.py")
    now = datetime.now(timezone.utc)
    families = {}
    for name, path, lock, inputs in (
        ("core", args.core_manifest, core.lock_data(), lambda n, i: {str(p.relative_to(ROOT)): core.sha256(p) for p in core.build_input_files(i)}),
        ("sdk", args.sdk_manifest, sdk.read_lock(), lambda n, i: {str(p.relative_to(ROOT)): core.sha256(p) for p in sdk.input_files(n, i)}),
    ):
        folder = path.parent.resolve()
        source = json.loads(regular(folder, path.name).read_text())
        families[name] = qualify(folder, source, lock, inputs, now=now)
    print(json.dumps({"schemaVersion": 1, "qualification": "LAB_ONLY_NOT_RELEASE_ADMISSION",
                      "customerInstallable": False, "families": families}, sort_keys=True))


if __name__ == "__main__":
    main()
