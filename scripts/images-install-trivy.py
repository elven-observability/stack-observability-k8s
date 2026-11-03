#!/usr/bin/env python3
"""Install a checksum-pinned release binary only in disposable hosted CI.

No installer from a mutable upstream branch, tracking/download redirect service,
package manager, root writes, registry credential or Kubernetes access is used.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 512 * 1024 * 1024


def read_pin(path):
    tools = json.loads(Path(path).read_text())["tools"]
    version, pin = tools["trivy"], tools["trivyLinuxAmd64"]
    if (not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
            or pin.get("url") != f"https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_Linux-64bit.tar.gz"
            or not isinstance(pin.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", pin["sha256"])):
        raise ValueError("Trivy requires an exact official release URL and SHA-256 matching its version")
    return version, pin


def extract_verified(archive, directory, expected):
    archive, directory = Path(archive), Path(directory)
    if archive.stat().st_size > MAX_BYTES:
        raise ValueError("Trivy archive exceeds its bounded size")
    with archive.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != expected:
            raise ValueError("Trivy archive SHA-256 mismatch; executable was not installed")
    destination = directory / "trivy"
    with tarfile.open(archive, "r:gz") as source:
        member = source.getmember("trivy")
        if not member.isfile() or not 0 < member.size <= MAX_BYTES:
            raise ValueError("Trivy archive must contain one bounded regular executable")
        with source.extractfile(member) as payload, destination.open("xb") as target:
            shutil.copyfileobj(payload, target)
        if destination.stat().st_size != member.size:
            raise ValueError("Trivy extraction did not preserve the approved file size")
    destination.chmod(0o755)
    return destination


def install(path):
    expected = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64"}
    if (any(os.environ.get(key) != value for key, value in expected.items())
            or platform.system() != "Linux" or platform.machine() != "x86_64"):
        raise ValueError("Trivy installation is restricted to the disposable Linux/X64 hosted CI runner")
    temporary = Path(os.environ.get("RUNNER_TEMP", ""))
    github_path = Path(os.environ.get("GITHUB_PATH", ""))
    if not temporary.is_absolute() or not temporary.is_dir() or not github_path.is_absolute() or not github_path.is_file():
        raise ValueError("Explicit existing RUNNER_TEMP and GITHUB_PATH are required")
    version, pin = read_pin(path)
    directory = Path(tempfile.mkdtemp(prefix="elven-trivy-", dir=temporary))
    archive = directory / "trivy.tar.gz"
    subprocess.run(["curl", "--fail", "--silent", "--show-error", "--location", "--retry", "3",
                    "--retry-all-errors", "--retry-delay", "2", "--connect-timeout", "15", "--max-time", "120",
                    "--max-filesize", str(MAX_BYTES), pin["url"], "--output", str(archive)], check=True, timeout=540)
    binary = extract_verified(archive, directory, pin["sha256"])
    result = subprocess.run([str(binary), "version", "--format", "json"], text=True,
                            capture_output=True, check=True, timeout=30)
    if json.loads(result.stdout).get("Version") != version:
        raise ValueError("Downloaded Trivy runtime version differs from the approved lock")
    with github_path.open("a") as output:
        print(directory, file=output)
    print(json.dumps({"version": version, "sha256": pin["sha256"], "official_release": pin["url"],
                      "mutable_installer_used": False, "registry_access": False}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", choices=("versions.lock.json", "instrumentation.lock.json"), required=True)
    args = parser.parse_args()
    install(ROOT / args.lock)


if __name__ == "__main__":
    main()
