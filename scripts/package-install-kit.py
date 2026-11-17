#!/usr/bin/env python3
"""Build the public, credential-free install kit from an exact clean Git revision."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("elven_install_bootstrap", ROOT / "kit/plataforma/instalar.py")
BOOTSTRAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOTSTRAP)
NAME = "elven-instalacao-v" + BOOTSTRAP.VERSION
FILES = ("instalar", "COMECE-AQUI.md", "plataforma/PREPARAR.md",
         "plataforma/cliente.exemplo.toml", "plataforma/instalar.py")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def build(output, bundle, revision, root=ROOT):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Use a full Git source revision.")
    if len(bundle) > 600_000 or digest(bundle) != BOOTSTRAP.ARCHIVE_SHA:
        raise ValueError("The inner bundle must match the pinned official release asset.")
    payload = {name: BOOTSTRAP.ler_limite(root / "kit" / name, 300_000) for name in FILES}
    payload["plataforma/" + BOOTSTRAP.ARCHIVE_NAME] = bundle
    manifest = {
        "schemaVersion": 1, "kitVersion": BOOTSTRAP.VERSION,
        "sourceRepository": "https://github.com/elven-observability/stack-observability-k8s",
        "sourceRevision": revision, "baseBundleUrl": BOOTSTRAP.ARCHIVE_URL,
        "baseBundleSha256": BOOTSTRAP.ARCHIVE_SHA,
        "files": {name: digest(raw) for name, raw in sorted(payload.items())},
    }
    raw_manifest = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    payload["kit.manifest.json"] = raw_manifest
    output.mkdir(parents=True, mode=0o700, exist_ok=True)
    archive = output / (NAME + ".zip")
    manifest_path = output / (NAME + ".manifest.json")
    checksum = output / (NAME + ".zip.sha256")
    if any(os.path.lexists(p) for p in (archive, manifest_path, checksum)):
        raise ValueError("Refusing to overwrite an existing kit, manifest or checksum.")
    with zipfile.ZipFile(archive, mode="x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as package:
        for name, raw in sorted(payload.items()):
            entry = zipfile.ZipInfo(NAME + "/" + name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | (0o755 if name == "instalar" else 0o644)) << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            package.writestr(entry, raw, compresslevel=9)
    BOOTSTRAP.escrever(manifest_path, raw_manifest)
    BOOTSTRAP.escrever(checksum, f"{digest(archive.read_bytes())}  {archive.name}\n".encode())
    return archive, manifest_path, checksum


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, help="Optional local copy of the pinned release asset; never an arbitrary bundle")
    args = parser.parse_args()
    status = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT)
    if status.strip():
        raise ValueError("Commit the source first; a public kit must come from a clean Git checkout.")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    bundle = BOOTSTRAP.ler_limite(args.bundle, 600_000) if args.bundle else BOOTSTRAP.baixar_pacote()
    for path in build(args.output_dir, bundle, revision):
        print(path)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, BOOTSTRAP.Refusa) as error:
        print(f"Elven kit: {error}", file=sys.stderr)
        sys.exit(1)
