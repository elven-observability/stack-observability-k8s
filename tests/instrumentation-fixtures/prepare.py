#!/usr/bin/env python3
"""Prepare a reproducible fixture Docker context without building/running images."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import urllib.request


SOURCE = Path(__file__).resolve().parent
ROOT = SOURCE.parents[1]


def prepare(output):
    output = output.resolve()
    if not output.is_relative_to((ROOT / ".artifacts").resolve()):
        raise ValueError("Fixture output must remain inside this repository's .artifacts directory")
    output.mkdir(parents=True, exist_ok=True)
    lock = json.loads((SOURCE / "fixtures.json").read_text())
    artifact = lock["h2"]
    jar = output / "h2.jar"
    if jar.exists():
        payload = jar.read_bytes()
    else:
        with urllib.request.urlopen(artifact["url"], timeout=30) as response:
            payload = response.read(4 * 1024 * 1024 + 1)
    if len(payload) > 4 * 1024 * 1024:
        raise ValueError("H2 fixture artifact exceeds its 4 MiB download budget")
    digest = hashlib.sha256(payload).hexdigest()
    if digest != artifact["sha256"]:
        raise ValueError("H2 fixture SHA-256 mismatch; no downloaded artifact was written")
    if not jar.exists():
        jar.write_bytes(payload)
    # Public test dependency: Docker COPY preserves host modes, and the app
    # deliberately runs as UID10001 without relaxing its security context.
    jar.chmod(0o444)
    for name in ("JavaFixture.java", "main.js", "Dockerfile.java17", "Dockerfile.java21",
                 "Dockerfile.node22", "Dockerfile.node20", "fixtures.json", "sink.py"):
        shutil.copy2(SOURCE / name, output / name)
    return {"context": str(output), "h2_sha256": digest, "images": lock["images"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / ".artifacts/instrumentation-fixtures")
    arguments = parser.parse_args()
    print(json.dumps(prepare(arguments.output), indent=2))
