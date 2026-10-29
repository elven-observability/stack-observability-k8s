#!/usr/bin/env python3
"""Offline chart contracts, strict schemas and optional real runtime validation.

Never reads kubeconfig or contacts a Kubernetes cluster. Network access is only
for pinned container images and Kubernetes JSON schema downloads.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from test_chart import CHART, DEFAULTS, all_modules, render


def command(args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError(f"Command failed: {' '.join(str(arg) for arg in args[:5])}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def validate_schemas(directory):
    if not shutil.which("kubeconform"):
        raise RuntimeError("Install kubeconform before validation; schema checks were not run.")
    results = {}
    for version in ("1.35.0", "1.36.0", "1.37.0"):
        manifest = directory / f"all-modules-{version}.yaml"
        manifest.write_text(render(all_modules(), version=version).stdout)
        output = command(["kubeconform", "-strict", "-summary", "-kubernetes-version", version, str(manifest)])
        results[version] = output.strip()
    return results


def certificates(directory):
    # Ephemeral synthetic CA used only for config validation in an isolated mount.
    key, cert = directory / "key.pem", directory / "cert.pem"
    command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=synthetic-elven-validation", "-keyout", str(key), "-out", str(cert)])
    for name in ("tls.crt", "ca.crt", "client.crt"):
        shutil.copyfile(cert, directory / name)
    for name in ("tls.key", "client.key"):
        shutil.copyfile(key, directory / name)
    (directory / "token").write_text("synthetic-validation-token")
    (directory / "namespace").write_text("synthetic-validation")
    directory.chmod(0o755)
    # Synthetic keys must be readable to the runtime UID in this read-only fixture.
    for path in directory.iterdir():
        path.chmod(0o644)


def runtime_checks(directory):
    if not shutil.which("docker"):
        raise RuntimeError("Docker is required for --runtime; no runtime config checks ran.")
    command(["docker", "info", "--format", "{{.OSType}}"])
    tls = directory / "synthetic-tls"
    tls.mkdir()
    certificates(tls)
    rendered = list(yaml.safe_load_all(render(all_modules()).stdout))
    results = []
    for obj in rendered:
        if not obj or obj["kind"] != "ConfigMap":
            continue
        for key, contents in obj.get("data", {}).items():
            if key not in ("collector.yaml", "profile.alloy"):
                continue
            source = directory / f"{obj['metadata']['name']}-{key}"
            source.write_text(contents)
            source.chmod(0o644)
            image_name = "alloy" if key.endswith("alloy") else "collector"
            image = DEFAULTS["images"][image_name]
            ref = f"{image['repository']}:{image['tag']}@{image['digest']}"
            image_variable = {"collector": "ELVEN_COLLECTOR_IMAGE", "alloy": "ELVEN_ALLOY_IMAGE"}[image_name]
            if os.environ.get(image_variable):
                ref = os.environ[image_variable]
                if "@sha256:" not in ref:
                    raise ValueError(image_variable + " must be digest-pinned")
            args = ["docker", "run", "--rm", "--network", "none", "--read-only",
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                    "--user", "10001:10001", "-e", "TENANT_ID=synthetic-tenant",
                    "-e", "API_TOKEN=synthetic-test-token", "-e", "NODE_NAME=synthetic-node",
                    "-e", "ELVEN_TENANT_ID=synthetic-tenant", "-e", "ELVEN_API_TOKEN=synthetic-test-token",
                    "-e", "K8S_NODE_NAME=synthetic-node", "-e", "K8S_NODE_IP=127.0.0.1",
                    "-e", "KUBERNETES_SERVICE_HOST=127.0.0.1", "-e", "KUBERNETES_SERVICE_PORT=443",
                    "--mount", f"type=bind,source={source},target=/config/{key},readonly",
                    "--mount", f"type=bind,source={tls},target=/etc/elven/tls,readonly",
                    "--mount", f"type=bind,source={tls},target=/var/run/secrets/kubernetes.io/serviceaccount,readonly",
                    "--tmpfs", "/data:rw,uid=10001,gid=10001,mode=0700,size=128m",
                    "--tmpfs", "/var/lib/elven:rw,uid=10001,gid=10001,mode=0700,size=128m",
                    "--tmpfs", "/var/lib/elven/positions:rw,uid=10001,gid=10001,mode=0700,size=32m",
                    ref, "validate", f"/config/{key}"]
            if image_name == "collector":
                args[-1:] = ["--config", f"/config/{key}"]
            command(args)
            results.append({"config": obj["metadata"]["name"], "config_sha256": hashlib.sha256(contents.encode()).hexdigest(),
                            "image": ref, "result": "passed"})
    if not any("gateway" in result["config"] for result in results):
        raise AssertionError("No gateway config was exercised")
    profile_test = ROOT / "tests/profiles-runtime.py"
    if not profile_test.is_file():
        raise RuntimeError("Profiles HTTPS runtime test is missing; full runtime validation did not run")
    output = command([sys.executable, str(profile_test)])
    results.append({"test": "profiles HTTPS scrape and export", "result": "passed", "output": output.strip()})
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", action="store_true", help="Validate rendered configs with pinned real Docker images")
    parser.add_argument("--skip-schema", action="store_true", help="Explicitly skip network-backed schema checks; report records the gap")
    args = parser.parse_args()
    evidence = ROOT / ".artifacts" / ("validation-" + time.strftime("%Y%m%dT%H%M%S"))
    evidence.mkdir(parents=True, exist_ok=False)
    report = {"completed": False, "cluster_access": "none", "runtime_requested": args.runtime,
              "schema_requested": not args.skip_schema, "tests": None, "schemas": None, "runtime": None}
    try:
        suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        report["tests"] = {"run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
                           "skipped": len(result.skipped)}
        if not result.wasSuccessful():
            raise RuntimeError("Chart contracts failed")
        with tempfile.TemporaryDirectory(prefix="elven-validation-") as temporary:
            directory = Path(temporary)
            if not args.skip_schema:
                report["schemas"] = validate_schemas(directory)
            if args.runtime:
                report["runtime"] = runtime_checks(directory)
        report["completed"] = True
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        (evidence / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"Evidence: {evidence / 'report.json'}")


if __name__ == "__main__":
    main()
