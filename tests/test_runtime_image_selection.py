"""A missing CI export must fail before pulling an old vulnerable default."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("elven_runtime_selection", ROOT / "scripts/validate.py")
VALIDATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATION)


class RuntimeImageSelectionTests(unittest.TestCase):
    def setUp(self):
        self.defaults = copy.deepcopy(VALIDATION.DEFAULTS)
        self.lock = json.loads((ROOT / "versions.lock.json").read_text())
        self.environment = {variable: "docker.io/elvenobservability/" + name + ":candidate@sha256:" + str(index) * 64
                            for index, (name, variable) in enumerate((("collector", "ELVEN_COLLECTOR_IMAGE"), ("alloy", "ELVEN_ALLOY_IMAGE"), ("beyla", "ELVEN_BEYLA_IMAGE")), 1)}

    def test_all_exact_candidates_are_required_without_any_stale_fallback(self):
        self.lock["distribution"]["publicationStatus"] = "not-published"
        self.assertEqual(len(VALIDATION.resolve_runtime_images(self.defaults, self.lock, self.environment)), 3)
        for variable in self.environment:
            environment = dict(self.environment)
            del environment[variable]
            with self.subTest(variable=variable), self.assertRaisesRegex(ValueError, "not a fallback"):
                VALIDATION.resolve_runtime_images(self.defaults, self.lock, environment)

    def test_known_blocked_digest_is_rejected_even_with_an_explicit_override(self):
        digest = "sha256:" + "3" * 64
        self.lock.setdefault("runtimeBlocks", {})[digest] = {"component": "beyla", "reason": "synthetic block"}
        with self.assertRaisesRegex(ValueError, "security-blocked"):
            VALIDATION.resolve_runtime_images(self.defaults, self.lock, self.environment)

    def test_unpinned_or_malformed_overrides_are_not_executed(self):
        for value in ("repo:latest", "repo@sha256:short", "repo:tag --privileged@sha256:" + "1" * 64):
            environment = {**self.environment, "ELVEN_COLLECTOR_IMAGE": value}
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "digest-pinned"):
                VALIDATION.resolve_runtime_images(self.defaults, self.lock, environment)

    def test_defaults_require_matching_promotions_for_every_component(self):
        self.lock["distribution"]["publicationStatus"] = "verified"
        for name in ("collector", "alloy", "beyla"):
            selected = self.defaults["images"][name]
            selected["digest"] = "sha256:" + "f" * 64
            self.lock["images"][name]["distribution"].update(status="verified", repository=selected["repository"], digest=selected["digest"])
        self.assertEqual(len(VALIDATION.resolve_runtime_images(self.defaults, self.lock, {})), 3)
        self.defaults["images"]["beyla"]["digest"] = "sha256:" + "e" * 64
        with self.assertRaisesRegex(ValueError, "not a fallback"):
            VALIDATION.resolve_runtime_images(self.defaults, self.lock, {})

    def test_workflow_does_not_shadow_the_candidate_environment_variable_with_report_keys(self):
        workflow = (ROOT / ".github/workflows/images.yaml").read_text()
        self.assertIn('for report_key in ("report", "sbom"):', workflow)
        self.assertNotIn('for key in ("report", "sbom"):', workflow)


if __name__ == "__main__":
    unittest.main()
