#!/usr/bin/env python3
"""Verify pinned test clients and prepare their Docker context, never install.

The CI harness copies this directory into its owned .artifacts context first.
No SDK/provider/exporter, npm installation, compiler or Docker command runs here.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import time
import urllib.error
import urllib.request

SOURCE = Path(__file__).resolve().parent
MAX_JAR_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024


def fetch_jar(url):
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=20) as response:
                return response.read(MAX_JAR_BYTES + 1)
        except urllib.error.HTTPError as error:
            if error.code != 429 and not 500 <= error.code < 600:
                raise
        except urllib.error.URLError as error:
            if isinstance(error.reason, ssl.SSLCertVerificationError) or not isinstance(error.reason, (TimeoutError, ConnectionError, OSError)):
                raise
        except (TimeoutError, ConnectionError):
            pass
        if attempt == 2:
            raise ValueError("Pinned Maven test dependency unavailable after three bounded attempts")
        time.sleep(attempt + 1)


def node_lock(directory):
    package = json.loads((directory / "package.json").read_text())
    lock = json.loads((directory / "package-lock.json").read_text())
    if (lock.get("lockfileVersion") != 3 or lock["packages"][""]["dependencies"] != package["dependencies"]
            or set(package["dependencies"]) != {"@opentelemetry/api", "@redis/client", "pg"}):
        raise ValueError("Unexpected application dependency closure")
    for name, metadata in lock["packages"].items():
        if not name:
            continue
        if (not name.startswith("node_modules/") or not re.fullmatch(r"\d+\.\d+\.\d+", metadata["version"])
                or not metadata.get("resolved", "").startswith("https://registry.npmjs.org/")
                or not re.fullmatch(r"sha512-[A-Za-z0-9+/]+={0,2}", metadata.get("integrity", ""))):
            raise ValueError("Unpinned or non-registry test client dependency")
        if "opentelemetry" in name and name != "node_modules/@opentelemetry/api":
            raise ValueError("Fixture must not bundle an OpenTelemetry SDK/exporter")
        for dependency in metadata.get("dependencies", {}):
            if "node_modules/" + dependency not in lock["packages"]:
                raise ValueError("Incomplete transitive npm lock")
    return hashlib.sha256((directory / "package-lock.json").read_bytes()).hexdigest()


def prepare(directory):
    directory = directory.resolve()
    if directory != SOURCE:
        raise ValueError("Prepare only the directory containing this copied fixture script")
    lock = json.loads((directory / "fixtures.json").read_text())
    npm_sha = node_lock(directory)
    observed, total = {}, 0
    for name, dependency in lock["javaDependencies"].items():
        filename, url, expected = dependency["file"], dependency["url"], dependency["sha256"]
        if (Path(filename).name != filename or not filename.endswith(".jar")
                or not url.startswith("https://repo.maven.apache.org/maven2/")
                or not re.fullmatch(r"[0-9a-f]{64}", expected)):
            raise ValueError("Unsafe/unpinned Java client dependency")
        target = directory / filename
        if target.is_symlink():
            raise ValueError("Test dependency must not be a symlink")
        if target.exists():
            if not target.is_file() or target.stat().st_size > MAX_JAR_BYTES:
                raise ValueError("Existing test dependency exceeds its budget")
            raw = target.read_bytes()
        else:
            raw = fetch_jar(url)
        total += len(raw)
        if len(raw) > MAX_JAR_BYTES or total > MAX_TOTAL_BYTES:
            raise ValueError("Bounded fixture download budget exceeded")
        actual = hashlib.sha256(raw).hexdigest()
        if actual != expected:
            raise ValueError("Java test dependency SHA-256 mismatch: " + name)
        # Verified bytes only; an existing different file is never overwritten.
        if not target.exists():
            with target.open("xb") as out:
                out.write(raw)
        target.chmod(0o444)
        observed[name] = actual
    return {"schemaVersion": 1, "evidence_boundary": "dependency_preparation_only_not_runtime_acceptance",
            "javaSha256": observed, "nodePackageLockSha256": npm_sha,
            "downloadBytes": total, "sdkBundled": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        parser.error("Dependency preparation is confined to the disposable hosted CI laboratory")
    print(json.dumps(prepare(args.directory), sort_keys=True))
