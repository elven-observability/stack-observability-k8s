"""The lab candidate path must never become a release or shared-cluster port."""
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]


class CandidateWorkflow(unittest.TestCase):
    def test_candidate_is_manual_readonly_and_consumes_fresh_admitted_artifacts(self):
        text = (ROOT / ".github/workflows/template-candidate.yaml").read_text()
        doc = yaml.safe_load(text)
        self.assertEqual(doc["permissions"], {"contents": "read", "actions": "read"})
        self.assertEqual(doc["env"]["KUBECONFIG"], "/dev/null")
        self.assertNotIn("push:", text)
        self.assertNotIn("pull_request:", text)
        steps = doc["jobs"]["lab"]["steps"]
        guard = next(i for i,s in enumerate(steps) if "qualify-candidate-artifacts.py" in s.get("run", ""))
        pack = next(i for i,s in enumerate(steps) if "package-candidate.py pack" in s.get("run", ""))
        run = next(i for i,s in enumerate(steps) if "test-hybrid-candidate.py" in s.get("run", ""))
        self.assertLess(guard, pack)
        self.assertLess(pack, run)
        self.assertIn("--host-access-approved", steps[run]["run"])
        self.assertIn("--development-images", steps[run]["run"])
        self.assertNotIn("continue-on-error", steps[run])
        for forbidden in ("id-token: write", "environment:", "images-release.py publish", "images-release.py promote",
                          "helmfile apply", "eo-production", "insecure-skip-tls", "--privileged", "SYS_ADMIN"):
            self.assertNotIn(forbidden, text)
        evidence = [s for s in steps if s.get("name") == "Preserve only sanitized laboratory receipts"][0]
        self.assertEqual(evidence["if"], "always()")
        self.assertNotIn("kubeconfig", evidence["with"]["path"])
        self.assertNotIn("**/*", evidence["with"]["path"])

    def test_sdk_build_stops_only_its_owned_builder_before_kind(self):
        doc = yaml.safe_load((ROOT / ".github/workflows/instrumentation.yaml").read_text())
        steps = doc["jobs"]["build-and-test"]["steps"]
        clean = next(i for i,s in enumerate(steps) if "buildx prune" in s.get("run", ""))
        lab = next(i for i,s in enumerate(steps) if "test-instrumentation-kind.py" in s.get("run", ""))
        self.assertLess(clean, lab)
        self.assertEqual(steps[clean]["env"]["ELVEN_CI_BUILDER"], "${{ steps.builder.outputs.name }}")
        run = steps[clean]["run"]
        self.assertIn('docker buildx stop "$ELVEN_CI_BUILDER"', run)
        self.assertLess(run.index('image["archiveSha256"]'), run.index("docker buildx stop"))
        self.assertNotIn("docker stop", run)
