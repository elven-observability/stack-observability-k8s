"""Offline fail-closed source/patch/builder binding for the modified Java agent."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("java_source_sdk", ROOT / "scripts/images-instrumentation.py")
SDK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SDK)


class JavaSourceBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="elven-java-source-policy-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.relative = "images/autoinstrumentation/java/jedis4-terminal-error.patch"
        self.patch = self.root / self.relative
        self.patch.parent.mkdir(parents=True)
        self.patch.write_bytes(b"diff --git a/Advice.java b/Advice.java\n+synthetic terminal error\n")
        self.build = {
            "repository": "https://github.com/open-telemetry/opentelemetry-java-instrumentation.git",
            "revision": "a" * 40,
            "buildImage": "gradle:9.8.2-jdk21@sha256:" + "b" * 64,
            "gradleVersion": "9.8.2", "wrapperDistributionSha256": "d" * 64,
            "patches": [{"path": self.relative, "sha256": hashlib.sha256(self.patch.read_bytes()).hexdigest()}],
        }
        self.image = {"sourceBuild": self.build, "upstream": {
            "repository": "ghcr.io/open-telemetry/opentelemetry-operator/autoinstrumentation-java",
            "tag": "2.33.1-2", "digest": "sha256:" + "c" * 64, "sourceVersion": "2.33.1"}}
        self.recipe = "\n".join((
            f"ARG UPSTREAM_IMAGE={SDK.source_ref(self.image)}",
            f"FROM --platform=$BUILDPLATFORM {self.build['buildImage']} AS builder",
            f"ADD --keep-git-dir=true {self.build['repository']}#{self.build['revision']} /src",
            f"COPY {self.relative} /tmp/{self.patch.name}",
            f"RUN git apply --check /tmp/{self.patch.name} && git apply /tmp/{self.patch.name} && "
            + "\\" + "\n ./gradlew --no-daemon :javaagent:assemble",
            "RUN grep -Fx 'distributionUrl=https\\://services.gradle.org/distributions/gradle-9.8.2-bin.zip' gradle/wrapper/gradle-wrapper.properties"
            + " && grep -Fx 'distributionSha256Sum=" + "d" * 64 + "' gradle/wrapper/gradle-wrapper.properties",
            "FROM ${UPSTREAM_IMAGE}",
            "LABEL org.opencontainers.image.description=\"Elven patched Java agent\"",
            "COPY --from=builder /src/javaagent/build/libs/opentelemetry-javaagent.jar /javaagent.jar",
        ))
        context = mock.patch.object(SDK, "ROOT", self.root)
        context.start()
        self.addCleanup(context.stop)

    def validate(self, image=None, recipe=None):
        SDK.validate_java_source_build(self.image if image is None else image,
                                       self.recipe if recipe is None else recipe)

    def test_exact_immutable_modified_agent_contract_is_accepted(self):
        self.validate()

    def test_source_revision_builder_and_omitted_provenance_fail_closed(self):
        edits = (
            lambda image: image.pop("sourceBuild"),
            lambda image: image["sourceBuild"].update(repository="https://github.com/other/repo.git"),
            lambda image: image["sourceBuild"].update(revision="main"),
            lambda image: image["sourceBuild"].update(revision="d" * 40),
            lambda image: image["sourceBuild"].update(buildImage="gradle:latest"),
            lambda image: image["sourceBuild"].update(buildImage="gradle:9.8.2-jdk21@sha256:" + "d" * 64),
            lambda image: image["sourceBuild"].update(gradleVersion="9.8.1"),
            lambda image: image["sourceBuild"].update(wrapperDistributionSha256="e" * 64),
            lambda image: image["upstream"].update(sourceVersion="2.32.0"),
            lambda image: image["upstream"].update(digest="sha256:" + "d" * 64),
        )
        for edit in edits:
            image = copy.deepcopy(self.image)
            edit(image)
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                self.validate(image)

    def test_changed_missing_or_symlink_patch_is_rejected(self):
        self.patch.write_bytes(b"changed reviewed patch")
        with self.assertRaises(ValueError):
            self.validate()
        self.patch.unlink()
        with self.assertRaises(ValueError):
            self.validate()
        target = self.root / "outside.patch"
        target.write_bytes(b"synthetic")
        self.patch.symlink_to(target)
        self.build["patches"][0]["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):
            self.validate()

    def test_patch_path_hash_and_exactly_one_patch_are_required(self):
        for patches in ([], [self.build["patches"][0]] * 2, [{"path": self.relative, "sha256": "bad"}],
                        [{"path": "images/autoinstrumentation/java/../java/jedis4-terminal-error.patch",
                          "sha256": self.build["patches"][0]["sha256"]}],
                        [{"path": str(self.patch), "sha256": self.build["patches"][0]["sha256"]}]):
            image = copy.deepcopy(self.image)
            image["sourceBuild"]["patches"] = patches
            with self.subTest(patches=patches), self.assertRaises(ValueError):
                self.validate(image)

    def test_recipe_cannot_claim_unmodified_or_skip_reviewed_patch_and_transfer(self):
        for old, new in (("Elven patched Java agent", "unmodified pinned upstream payload"),
                         ("git apply --check", "echo git-apply-check"),
                         ("git apply --check", "echo git apply --check"),
                         ("git apply /tmp/", "echo no-apply /tmp/"),
                         ("COPY images/", "# COPY images/"),
                         ("COPY --from=builder", "# COPY --from=builder"),
                         (":javaagent:assemble", ":unrelated:assemble"),
                         ("FROM ${UPSTREAM_IMAGE}", "FROM scratch"),
                         ("FROM --platform=$BUILDPLATFORM", "FROM"),
                         ("ADD --keep-git-dir=true", "# ADD --keep-git-dir=true")):
            with self.subTest(old=old), self.assertRaises(ValueError):
                self.validate(recipe=self.recipe.replace(old, new))

    def test_read_lock_calls_java_policy_without_mutating_publication_history(self):
        source = json.loads((ROOT / "instrumentation.lock.json").read_text())
        original = copy.deepcopy(source["images"]["java"]["distribution"])
        # Keep the actual checkout for recipe paths; the sentinel proves every
        # command using read_lock reaches the Java provenance gate before build.
        with mock.patch.object(SDK, "ROOT", ROOT), mock.patch.object(SDK, "validate_java_source_build", side_effect=ValueError("java policy gate")) as gate:
            with self.assertRaisesRegex(ValueError, "java policy gate"):
                SDK.read_lock()
            gate.assert_called_once()
        self.assertEqual(source["images"]["java"]["distribution"], original)

    def test_actual_checkout_recipe_validates_without_promoting_candidate_source(self):
        source = json.loads((ROOT / "instrumentation.lock.json").read_text())
        with mock.patch.object(SDK, "ROOT", ROOT):
            validated = SDK.read_lock()
            inputs = SDK.input_files("java", validated["images"]["java"])
        self.assertEqual(validated["images"]["java"]["distribution"], source["images"]["java"]["distribution"])
        self.assertEqual(validated["distribution"], source["distribution"])
        self.assertIn(ROOT / "instrumentation.lock.json", inputs)
        for patch in validated["images"]["java"]["sourceBuild"]["patches"]:
            self.assertIn(ROOT / patch["path"], inputs)


if __name__ == "__main__":
    unittest.main()
