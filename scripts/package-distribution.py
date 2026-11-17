#!/usr/bin/env python3
"""Package a clean promoted release, without legacy scripts or recursive kits."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
PATHS = (".gitattributes", ".github", ".gitignore", "CHANGELOG.md", "Makefile", "README.md",
         "charts", "docs", "elven", "examples", "images", "instrumentation.lock.json",
         "operator", "processor", "requirements-test.txt", "scripts", "tests", "versions.lock.json")


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def release_identity(core, sdk):
    version = core.get("distribution", {}).get("version")
    if not isinstance(version, str) or not re.fullmatch(r"1\.[0-9]+\.[0-9]+", version):
        raise ValueError("An exact stable release version is required.")
    sources, images = set(), {}
    for lock, components in ((core, {"collector", "beyla", "alloy"}),
                             (sdk, {"operator", "java", "nodejs", "nodejs20", "python"})):
        if (lock.get("distribution", {}).get("publicationStatus") != "verified"
                or lock["distribution"].get("version") != version or set(lock.get("images", {})) != components):
            raise ValueError("Both complete release locks must be promoted to the same stable version.")
        for name, value in lock["images"].items():
            image = value["distribution"]
            if (image.get("status") != "verified" or image.get("tag") != "v" + version
                    or not re.fullmatch(r"sha256:[0-9a-f]{64}", image.get("digest") or "")
                    or not re.fullmatch(r"[0-9a-f]{40}", image.get("sourceRevision") or "")
                    or image["digest"] in core.get("runtimeBlocks", {})):
                raise ValueError(f"{name}: absent promotion, source identity or blocked runtime.")
            sources.add(image["sourceRevision"])
            images[name] = image["repository"] + "@" + image["digest"]
    if len(sources) != 1:
        raise ValueError("Release images do not share the approved build revision.")
    return {"schemaVersion": 1, "version": version, "imageBuildTag": "v" + version,
            "imageSourceRevision": sources.pop(), "images": images,
            "sourceRepository": "https://github.com/elven-observability/stack-observability-k8s"}


def archive(source, manifest):
    prefix = "elven-observability-v" + manifest["version"]
    expected = {prefix + "/" + name for name in ("elven", "versions.lock.json", "instrumentation.lock.json",
                "charts/elven-observability/Chart.yaml", "charts/elven-instrumentation/Chart.yaml", "scripts/instrumentation.py")}
    seen, total = set(), 0
    target = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(source), mode="r:") as original, tarfile.open(fileobj=target, mode="w", format=tarfile.PAX_FORMAT) as output:
        for member in original:
            path = PurePosixPath(member.name)
            if (not path.parts or path.parts[0] != prefix or path.is_absolute() or ".." in path.parts
                    or "\\" in member.name or member.name in seen or not (member.isdir() or member.isfile())):
                raise ValueError("Unsafe or duplicate member in Git archive.")
            if len(path.parts) > 1 and path.parts[1] in {"kit", "legacy", ".git", ".artifacts", "artifacts", "helmfile.yaml"}:
                raise ValueError("Private, legacy or recursive kit content cannot ship.")
            total += member.size
            if total > 30_000_000 or member.size > 4_000_000:
                raise ValueError("Distribution content exceeded the reviewed size bound.")
            seen.add(member.name)
            output.addfile(member, original.extractfile(member) if member.isfile() else None)
        if not expected <= seen:
            raise ValueError("Distribution is missing a required installer/chart/lock.")
        raw = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
        if prefix + "/INSTALL-MANIFEST.json" in seen:
            raise ValueError("A pre-existing install manifest cannot be replaced.")
        entry = tarfile.TarInfo(prefix + "/INSTALL-MANIFEST.json")
        entry.size, entry.mode, entry.mtime = len(raw), 0o644, 0
        output.addfile(entry, io.BytesIO(raw))
    result = io.BytesIO()
    with gzip.GzipFile(fileobj=result, mode="wb", filename="", mtime=0, compresslevel=9) as compressed:
        compressed.write(target.getvalue())
    if len(result.getvalue()) > 600_000:
        raise ValueError("Distribution exceeds the install kit's verified download bound.")
    return result.getvalue()


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT).strip():
        raise ValueError("Commit the exact source first; no dirty-source release package.")
    core = module("elven_package_core", "images-release.py").lock_data()
    sdk = module("elven_package_sdk", "images-instrumentation.py").read_lock()
    manifest = release_identity(core, sdk)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    manifest["installConfigRevision"] = revision
    prefix = "elven-observability-v" + manifest["version"]
    source = subprocess.check_output(["git", "archive", "--format=tar", "--prefix=" + prefix + "/", revision, *PATHS], cwd=ROOT)
    raw = archive(source, manifest)
    name = prefix + ".tar.gz"
    files = {name: raw, prefix + ".manifest.json": (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(),
             "SHA256SUMS": (hashlib.sha256(raw).hexdigest() + "  " + name + "\n").encode()}
    args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(os.path.lexists(args.output_dir / name) for name in files):
        raise ValueError("Refusing to overwrite existing release artifacts.")
    for name, content in files.items():
        with (args.output_dir / name).open("xb") as output:
            output.write(content)
        print(args.output_dir / name)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit("Elven distribution package: " + str(error))
