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
JAVA_GRAPH = {
    "opentelemetry-api": {"opentelemetry-context": "1.67.0"},
    "opentelemetry-context": {"opentelemetry-common": "1.67.0"},
    "opentelemetry-common": {},
    "jedis": {"slf4j-api": "1.7.36", "commons-pool2": "2.12.0", "json": "20240303", "gson": "2.11.0"},
    "gson": {"error_prone_annotations": "2.27.0"},
    "error_prone_annotations": {}, "slf4j-api": {}, "commons-pool2": {}, "json": {}, "h2": {},
}


def java_lock(lock):
    dependencies = lock["javaDependencies"]
    if set(dependencies) != set(JAVA_GRAPH):
        raise ValueError("Complete API/client-only Java dependency closure required; SDK/providers are forbidden")
    for name, required in JAVA_GRAPH.items():
        if dependencies[name].get("dependsOn", {}) != required:
            raise ValueError("Java dependency graph was changed or omitted: " + name)
        if name.startswith("opentelemetry-") and dependencies[name]["version"] != "1.67.0":
            raise ValueError("API/context/common must match the pinned agent BOM 1.67.0")
        for child, version in required.items():
            if dependencies[child]["version"] != version:
                raise ValueError("Java transitive dependency version mismatch: " + child)
    return len(dependencies)


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


def python_lock(directory, lock):
    # Complete mandatory closure for Linux CPython3.14, without optional extras.
    graph = {"flask": {"blinker": "1.9.0", "click": "8.3.1", "itsdangerous": "2.2.0", "jinja2": "3.1.6", "markupsafe": "3.0.3", "werkzeug": "3.1.5"},
             "jinja2": {"markupsafe": "3.0.3"}, "werkzeug": {"markupsafe": "3.0.3"},
             "redis": {}, "blinker": {}, "click": {}, "itsdangerous": {}, "markupsafe": {}}
    dependencies = lock["pythonDependencies"]
    if set(dependencies) != set(graph):
        raise ValueError("Complete application-only Python closure required; no SDK/provider/exporter")
    runtime = lock["pythonRuntime"]
    if (runtime["case"] != "python314" or runtime["version"] != "3.14.10" or runtime["libc"] != "glibc"
            or runtime["baseImage"] != lock["images"]["python314"]
            or not re.fullmatch(r"docker.io/library/python:3\.14-slim-bookworm@sha256:[0-9a-f]{64}", runtime["baseImage"])):
        raise ValueError("Python fixture must retain its exact declared CPython3.14 glibc base")
    expected = []
    for name, metadata in sorted(dependencies.items()):
        if metadata.get("dependsOn", {}) != graph[name] or not re.fullmatch(r"\d+\.\d+\.\d+", metadata["version"]):
            raise ValueError("Python dependency graph/version changed: " + name)
        for child, version in graph[name].items():
            if dependencies[child]["version"] != version:
                raise ValueError("Python transitive version mismatch: " + child)
        wheels = metadata["wheels"]
        if not wheels or len({item["sha256"] for item in wheels}) != len(wheels):
            raise ValueError("Unique immutable Python wheels required")
        for item in wheels:
            if (Path(item["file"]).name != item["file"] or not item["file"].endswith(".whl")
                    or not item["url"].startswith("https://files.pythonhosted.org/")
                    or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])):
                raise ValueError("Unpinned or non-official Python wheel")
        if name == "markupsafe":
            if not all(any("cp314-cp314-" in item["file"] and "manylinux" in item["file"] and arch in item["file"] for item in wheels)
                       for arch in ("x86_64", "aarch64")):
                raise ValueError("Both CPython3.14 glibc MarkupSafe architectures required")
        elif any(not item["file"].endswith("-py3-none-any.whl") for item in wheels):
            raise ValueError("Only pure Python wheels allowed outside MarkupSafe")
        expected.append(name + "==" + metadata["version"] + " " + " ".join("--hash=sha256:" + item["sha256"] for item in wheels))
    requirements = directory / "requirements-python.lock"
    actual = [line for line in requirements.read_text().splitlines() if line and not line.startswith("#")]
    if actual != expected:
        raise ValueError("Python requirements differ from their complete pinned wheel closure")
    return hashlib.sha256(requirements.read_bytes()).hexdigest()


def prepare(directory):
    directory = directory.resolve()
    if directory != SOURCE:
        raise ValueError("Prepare only the directory containing this copied fixture script")
    lock = json.loads((directory / "fixtures.json").read_text())
    java_count = java_lock(lock)
    npm_sha = node_lock(directory)
    python_sha = python_lock(directory, lock)
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
            "pythonRequirementsSha256": python_sha, "pythonDependencyCount": len(lock["pythonDependencies"]),
            "javaDependencyCount": java_count, "missingJavaDependencies": [],
            "downloadBytes": total, "sdkBundled": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        parser.error("Dependency preparation is confined to the disposable hosted CI laboratory")
    print(json.dumps(prepare(args.directory), sort_keys=True))
