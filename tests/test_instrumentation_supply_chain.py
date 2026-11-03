"""The opt-in SDK publication contract is separate from the core three images."""
import importlib.util
import base64
import json
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("elven_sdk_images", ROOT / "scripts/images-instrumentation.py")
SDK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SDK)


class SDKSupplyChainTests(unittest.TestCase):
    def test_five_independent_identities_have_consistent_publication_state(self):
        lock = SDK.read_lock()
        self.assertEqual(set(lock["images"]), {"operator", "java", "nodejs", "nodejs20", "python"})
        self.assertIn(lock["distribution"]["publicationStatus"], ("not-published", "verified"))
        for image in lock["images"].values():
            published = image["distribution"]
            if published["status"] == "not-published":
                self.assertIsNone(published["digest"])
            else:
                self.assertRegex(published["digest"], r"^sha256:[0-9a-f]{64}$")
                self.assertRegex(published["tag"], r"^v1\.[0-9]+\.[0-9]+$")

    def test_node20_is_a_distinct_explicit_eol_exception(self):
        lock = SDK.read_lock()
        self.assertNotEqual(lock["images"]["nodejs"]["distribution"]["repository"], lock["images"]["nodejs20"]["distribution"]["repository"])
        self.assertFalse(lock["legacyProfiles"]["nodejs20"]["enabledByDefault"])
        self.assertEqual(lock["legacyProfiles"]["nodejs20"]["runtimeEOL"], "2026-04-30")
        self.assertIn("0.81.2", lock["images"]["nodejs20"]["upstream"]["tag"])

    def test_wrappers_preserve_the_exact_upstream_filesystem_and_licenses(self):
        lock = SDK.read_lock()
        for name in ("java", "nodejs", "nodejs20", "python"):
            image = lock["images"][name]
            recipe = (ROOT / image["dockerfile"]).read_text()
            self.assertIn("FROM ${UPSTREAM_IMAGE}", recipe)
            self.assertIn(SDK.source_ref(image), recipe)
            self.assertIn("images/licenses/APACHE-2.0.txt", recipe)
            self.assertNotRegex(recipe, r"(?m)^\s*(RUN|ENTRYPOINT|CMD)\b")
            self.assertNotIn(":latest", recipe)
            ignore = (ROOT / (image["dockerfile"] + ".dockerignore")).read_text()
            self.assertTrue(ignore.startswith("**\n"))

    def test_operator_build_requires_unit_tests_and_pinned_stdlib_toolchain(self):
        recipe = (ROOT / SDK.read_lock()["images"]["operator"]["dockerfile"]).read_text()
        self.assertIn("go test ./...", recipe)
        self.assertIn("FROM scratch", recipe)
        self.assertIn("GO-LICENSE", recipe)

    def test_unpublished_verify_stops_before_any_external_command(self):
        lock = SDK.read_lock()
        lock["distribution"]["publicationStatus"] = "not-published"
        with mock.patch.object(SDK.OCI, "run") as command, self.assertRaises(ValueError):
            SDK.verify(SimpleNamespace(component="all"), lock)
        command.assert_not_called()

    def test_sdk_identity_is_exact_workflow_and_not_the_core_workflow(self):
        calls = []
        digest = "sha256:" + "a" * 64
        sboms = [{"SPDXID": "SPDXRef-" + arch} for arch in ("amd64", "arm64")]
        metadata = {"source": "synthetic"}
        exact = SDK.OCI.ATTESTATIONS
        policy = {"schemaVersion": 1, "canonicalization": exact.CANONICALIZATION, "subjectDigest": digest,
                  "spdx": {platform: exact.canonical_hash(value) for platform, value in zip(("linux/amd64", "linux/arm64"), sboms)},
                  "build": {"predicateType": SDK.BUILD_TYPE, "sha256": exact.canonical_hash(metadata)}}
        def command(args, **kwargs):
            calls.append(args)
            if args[:2] == ["cosign", "version"]:
                return json.dumps({"gitVersion": "v3.1.4"})
            if args[:2] == ["cosign", "verify-attestation"]:
                kind = args[args.index("--type") + 1]
                predicate_type = exact.SPDX_TYPE if kind == "spdxjson" else SDK.BUILD_TYPE
                values = sboms if kind == "spdxjson" else [metadata]
                return "\n".join(json.dumps({"payloadType": "application/vnd.in-toto+json",
                    "payload": base64.b64encode(json.dumps({"_type": "https://in-toto.io/Statement/v0.1",
                        "subject": [{"digest": {"sha256": digest.removeprefix("sha256:")}}],
                        "predicateType": predicate_type, "predicate": value}).encode()).decode(),
                    "signatures": [{"sig": base64.b64encode(b"synthetic-signature").decode()}]}) for value in values)
            return "{}"
        with mock.patch.object(SDK.OCI, "run", side_effect=command):
            SDK.verify_reference("docker.io/elvenobservability/elven-auto-java@" + digest, "v1.0.0", SDK.read_lock(), policy)
        identity = calls[1][calls[1].index("--certificate-identity-regexp") + 1]
        self.assertTrue(re.fullmatch(identity, "https://github.com/elven-observability/stack-observability-k8s/.github/workflows/instrumentation.yaml@refs/tags/v1.0.0"))
        self.assertFalse(re.fullmatch(identity, "https://github.com/elven-observability/stack-observability-k8s/.github/workflows/images.yaml@refs/tags/v1.0.0"))
        self.assertFalse(re.fullmatch(identity, "https://github.com/attacker/stack-observability-k8s/.github/workflows/instrumentation.yaml@refs/tags/v1.0.0"))

    def test_workflow_cannot_publish_without_actual_native_injection_tests(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/instrumentation.yaml").read_text())
        self.assertEqual(workflow["jobs"]["publish"]["needs"], "build-and-test")
        steps = workflow["jobs"]["build-and-test"]["steps"]
        native = next(step for step in steps if "test-instrumentation-kind.py" in step.get("run", ""))
        self.assertNotIn("if", native)
        self.assertIn("--images-manifest artifacts/instrumentation/instrumentation-release.json", native["run"])
        self.assertIn("--development-images", native["run"])
        cleanup = next(step for step in steps if "buildx prune" in step.get("run", ""))
        self.assertEqual(cleanup["env"]["ELVEN_CI_BUILDER"], "${{ steps.builder.outputs.name }}")
        self.assertIn('--builder "$ELVEN_CI_BUILDER"', cleanup["run"])
        self.assertNotIn("system prune", cleanup["run"])
        for step in steps + workflow["jobs"]["publish"]["steps"]:
            if "uses" in step:
                self.assertRegex(step["uses"], r"@[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
