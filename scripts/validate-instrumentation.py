#!/usr/bin/env python3
"""Validate the Elven admission chart/CLI contracts without accessing a cluster.

Only sanitized summary reports are retained. Generated manifests contain fixture
image digests and a synthetic public CA marker, never usable private material.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from test_instrumentation_chart import CHART, enabled_values, render


def command(argv):
    result = subprocess.run(argv, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f"{Path(str(argv[0])).name} validation failed; no cluster or Secret was accessed.\n{result.stdout}\n{result.stderr}")
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-schema", action="store_true", help="Explicitly skip network-backed Kubernetes schemas; the report records this gap")
    args = parser.parse_args()
    os.umask(0o077)
    evidence = ROOT / ".artifacts" / ("instrumentation-validation-" + time.strftime("%Y%m%dT%H%M%S"))
    evidence.mkdir(parents=True, exist_ok=False)
    report = {"completed": False, "cluster_access": "none", "schema_requested": not args.skip_schema,
              "tests": None, "lint": None, "schemas": {}, "manifests": {},
              "not_proven": ["image publication/signature/promotion", "SDK injection in Kubernetes", "real application signal delivery", "NetworkPolicy enforcement", "customer infrastructure and tenant acceptance"]}
    try:
        if not shutil.which("helm"):
            raise RuntimeError("Install the pinned Helm tool and place it on PATH before validation.")
        suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), pattern="test_instrumentation_*.py")
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        report["tests"] = {"run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors), "skipped": len(result.skipped)}
        if not result.wasSuccessful():
            raise RuntimeError("Elven instrumentation contracts failed")
        report["lint"] = command(["helm", "lint", str(CHART), "--strict", "--kube-version", "1.37.0"])
        if not args.skip_schema and not shutil.which("kubeconform"):
            raise RuntimeError("Install kubeconform before schema validation; schemas were not executed.")
        values = enabled_values()
        values["runtimes"] = {"java": True, "nodejs": True, "python": True, "nodejs20": True, "legacyNode20Approved": True}
        with tempfile.TemporaryDirectory(prefix="elven-instrumentation-schema-") as temporary:
            folder = Path(temporary)
            for version in ("1.35.0", "1.36.0", "1.37.0"):
                text = render(values, version=version).stdout
                manifest = folder / ("enabled-" + version + ".yaml")
                manifest.write_text(text)
                resources = [item for item in yaml.safe_load_all(text) if item]
                report["manifests"][version] = {"sha256": hashlib.sha256(text.encode()).hexdigest(), "resources": len(resources), "fixture_only": True}
                if not args.skip_schema:
                    report["schemas"][version] = command(["kubeconform", "-strict", "-summary", "-kubernetes-version", version, str(manifest)])
        report["completed"] = True
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        (evidence / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print("Evidence:", evidence / "report.json", flush=True)


if __name__ == "__main__":
    main()
