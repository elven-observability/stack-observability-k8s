"""Offline fail-closed source/patch/builder binding for the modified Java agent."""
import copy
import hashlib
import io
import importlib.util
import json
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest import mock
import zipfile

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
            "buildImage": SDK.JAVA_BUILD_IMAGE, "javaVersion": 25,
            "auxiliaryJdk17Image": SDK.JAVA_AUXILIARY_JDK17_IMAGE,
            "auxiliaryJdk21Image": SDK.JAVA_AUXILIARY_JDK21_IMAGE,
            "gradleVersion": "9.8.2", "wrapperDistributionSha256": "d" * 64,
            "patches": [{"path": self.relative, "sha256": hashlib.sha256(self.patch.read_bytes()).hexdigest()}],
            "restletSources": copy.deepcopy(SDK.JAVA_RESTLET_SOURCES),
        }
        helpers = []
        for key, filename, destination in (
                ("restletBuildScript", "build-restlet-compile-only.sh", "/tmp/build-restlet-compile-only.sh"),
                ("restletRepositoryInit", "restlet-compile-only.init.gradle", "/tmp/restlet-compile-only.init.gradle"),
                ("restletPayloadCheck", "verify-restlet-payload.sh", "/tmp/verify-restlet-payload.sh"),
                ("restletPreflightSettings", "restlet-preflight.settings.gradle", "/opt/elven-restlet-preflight/settings.gradle"),
                ("restletPreflightBuild", "restlet-preflight.build.gradle", "/opt/elven-restlet-preflight/build.gradle")):
            relative = "images/autoinstrumentation/java/" + filename
            raw = (ROOT / relative).read_bytes()
            (self.root / relative).write_bytes(raw)
            self.build[key] = {"path": relative, "sha256": hashlib.sha256(raw).hexdigest()}
            helpers.append(f"COPY {relative} {destination}")
        self.image = {"sourceBuild": self.build, "upstream": {
            "repository": "ghcr.io/open-telemetry/opentelemetry-operator/autoinstrumentation-java",
            "tag": "2.33.1-2", "digest": "sha256:" + "c" * 64, "sourceVersion": "2.33.1"}}
        self.recipe = "\n".join((
            f"ARG UPSTREAM_IMAGE={SDK.source_ref(self.image)}",
            f"FROM --platform=$BUILDPLATFORM {SDK.JAVA_AUXILIARY_JDK17_IMAGE} AS build-jdk17",
            f"FROM --platform=$BUILDPLATFORM {SDK.JAVA_AUXILIARY_JDK21_IMAGE} AS build-jdk21",
            f"FROM --platform=$BUILDPLATFORM {self.build['buildImage']} AS builder",
            "COPY --from=build-jdk17 /opt/java/openjdk /opt/elven-toolchains/jdk17",
            "COPY --from=build-jdk21 /opt/java/openjdk /opt/elven-toolchains/jdk21",
            *(f"ADD {source['repository']}#{source['revision']}:{source['subdirectory']} /opt/elven-restlet-sources/{source['version']}"
              for source in SDK.JAVA_RESTLET_SOURCES),
            *helpers,
            "RUN sh /tmp/build-restlet-compile-only.sh",
            f"ADD --keep-git-dir=true {self.build['repository']}#{self.build['revision']} /src",
            f"COPY {self.relative} /tmp/{self.patch.name}",
            "RUN ./gradlew --no-daemon --no-parallel -Pkotlin.compiler.execution.strategy=in-process "
            + "-Porg.gradle.java.installations.auto-download=false -Porg.gradle.java.installations.auto-detect=false "
            + '"-Porg.gradle.java.installations.paths=$JAVA_HOME,/opt/elven-toolchains/jdk17,/opt/elven-toolchains/jdk21" '
            + '--init-script /tmp/restlet-compile-only.init.gradle --project-dir /opt/elven-restlet-preflight verifyRepositoryBoundaries',
            f"RUN git apply --check /tmp/{self.patch.name} && git apply /tmp/{self.patch.name} && "
            + "\\" + "\n ./gradlew --no-daemon --no-parallel -Pkotlin.compiler.execution.strategy=in-process "
            + "-Porg.gradle.java.installations.auto-download=false -Porg.gradle.java.installations.auto-detect=false "
            + '"-Porg.gradle.java.installations.paths=$JAVA_HOME,/opt/elven-toolchains/jdk17,/opt/elven-toolchains/jdk21" '
            + '--init-script /tmp/restlet-compile-only.init.gradle :javaagent:assemble',
            "RUN sh /tmp/verify-restlet-payload.sh /src/javaagent/build/libs/opentelemetry-javaagent.jar",
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

    def test_bounded_network_retry_preserves_every_gradle_policy(self):
        self.validate(recipe=self.recipe.replace(
            " ./gradlew --no-daemon", " if ./gradlew --no-daemon"))
        recipe = (ROOT / "images/autoinstrumentation/java/Dockerfile").read_text()
        self.assertIn('"$attempt" -ge 3', recipe)
        self.assertIn('Received status code (429|5[0-9][0-9])', recipe)
        self.assertIn('There were failing tests', recipe)
        self.assertIn('exit "$result"', recipe)
        self.assertNotIn("|| true", recipe)

    def test_source_revision_builder_and_omitted_provenance_fail_closed(self):
        edits = (
            lambda image: image.pop("sourceBuild"),
            lambda image: image["sourceBuild"].update(repository="https://github.com/other/repo.git"),
            lambda image: image["sourceBuild"].update(revision="main"),
            lambda image: image["sourceBuild"].update(revision="d" * 40),
            lambda image: image["sourceBuild"].update(buildImage="gradle:latest"),
            lambda image: image["sourceBuild"].update(buildImage="gradle:9.8.2-jdk21@sha256:" + "d" * 64),
            lambda image: image["sourceBuild"].update(javaVersion=21),
            lambda image: image["sourceBuild"].update(javaVersion="25"),
            lambda image: image["sourceBuild"].pop("auxiliaryJdk17Image"),
            lambda image: image["sourceBuild"].update(auxiliaryJdk17Image="docker.io/library/eclipse-temurin:17-jdk-jammy"),
            lambda image: image["sourceBuild"].update(auxiliaryJdk17Image=SDK.JAVA_AUXILIARY_JDK17_IMAGE.replace("8133", "a133")),
            lambda image: image["sourceBuild"].pop("auxiliaryJdk21Image"),
            lambda image: image["sourceBuild"].update(auxiliaryJdk21Image="docker.io/library/eclipse-temurin:21-jdk-jammy"),
            lambda image: image["sourceBuild"].update(auxiliaryJdk21Image=SDK.JAVA_AUXILIARY_JDK21_IMAGE.replace("4b1a", "ab1a")),
            lambda image: image["sourceBuild"].update(buildImage=SDK.JAVA_BUILD_IMAGE.replace("e46e", "a46e")),
            lambda image: image["sourceBuild"].update(gradleVersion="9.8.1"),
            lambda image: image["sourceBuild"].update(wrapperDistributionSha256="e" * 64),
            lambda image: image["sourceBuild"].pop("restletSources"),
            lambda image: image["sourceBuild"]["restletSources"][0].update(revision="b" * 40),
            lambda image: image["sourceBuild"]["restletSources"][1].update(version="2.5.0"),
            lambda image: image["sourceBuild"]["restletBuildScript"].update(sha256="e" * 64),
            lambda image: image["sourceBuild"]["restletRepositoryInit"].update(path="/tmp/init.gradle"),
            lambda image: image["sourceBuild"].pop("restletPreflightBuild"),
            lambda image: image["sourceBuild"]["restletPreflightSettings"].update(sha256="e" * 64),
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

    def test_restlet_helper_bytes_and_recomputed_broad_repository_are_rejected(self):
        for key in ("restletBuildScript", "restletRepositoryInit", "restletPayloadCheck", "restletPreflightSettings", "restletPreflightBuild"):
            path = self.root / self.build[key]["path"]
            raw = path.read_bytes()
            path.write_bytes(raw + b"\n# changed\n")
            with self.subTest(helper=key), self.assertRaises(ValueError):
                self.validate()
            path.write_bytes(raw)
            target = self.root / (key + ".outside")
            target.write_bytes(raw)
            path.unlink()
            path.symlink_to(target)
            with self.subTest(symlink=key), self.assertRaises(ValueError):
                self.validate()
            path.unlink()
            path.write_bytes(raw)
        path = self.root / self.build["restletBuildScript"]["path"]
        raw = path.read_bytes()
        original_hash = self.build["restletBuildScript"]["sha256"]
        path.write_bytes(raw.replace(b"--release 8", b"--release 17"))
        self.build["restletBuildScript"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "--release 8"):
            self.validate()
        path.write_bytes(raw)
        self.build["restletBuildScript"]["sha256"] = original_hash
        path = self.root / self.build["restletRepositoryInit"]["path"]
        raw = path.read_text().replace("includeVersion('org.restlet', 'org.restlet', '1.1.5')", "includeGroup('org.restlet')")
        path.write_text(raw)
        self.build["restletRepositoryInit"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "three original exact coordinates"):
            self.validate()

    def test_offline_payload_oracle_preserves_instrumentation_but_rejects_library_payloads(self):
        checker = ROOT / "images/autoinstrumentation/java/verify-restlet-payload.sh"
        legitimate = {"inst/io/opentelemetry/javaagent/instrumentation/restlet/v1_1/Advice.class": b"fixture",
                      "inst/io/opentelemetry/javaagent/instrumentation/restlet/v2_0/Advice.class": b"fixture"}

        def check(extra=None, entries=None, corrupt_crc=False):
            jar = self.root / "synthetic-agent.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                for name, raw in {**(legitimate if entries is None else entries), **(extra or {})}.items():
                    archive.writestr(name, raw)
            if corrupt_crc:
                with zipfile.ZipFile(jar) as archive:
                    first = archive.infolist()[0]
                raw = bytearray(jar.read_bytes())
                offset = first.header_offset + 30 + len(first.filename.encode()) + len(first.extra)
                raw[offset] ^= 1  # Retain a valid directory/listing, break payload CRC.
                jar.write_bytes(raw)
            return subprocess.run(["sh", str(checker), str(jar)], capture_output=True, timeout=10).returncode

        self.assertEqual(check(), 0)
        self.assertNotEqual(check(corrupt_crc=True), 0)
        for name in ("org/restlet/Request.class", "inst/org/restlet/Request.class",
                     "com/noelios/restlet/Engine.class", "inst/com/noelios/restlet/Engine.class",
                     "lib/org.restlet-1.1.5.jar"):
            with self.subTest(name=name):
                self.assertNotEqual(check({name: b"fixture"}), 0)
        nested = io.BytesIO()
        with zipfile.ZipFile(nested, "w") as archive:
            archive.writestr("org/restlet/Request.class", b"fixture")
        self.assertNotEqual(check({"lib/renamed.jar": nested.getvalue()}), 0)
        safe_nested = io.BytesIO()
        with zipfile.ZipFile(safe_nested, "w") as archive:
            archive.writestr("com/example/Safe.class", b"fixture")
        self.assertEqual(check({"lib/other.jar": safe_nested.getvalue()}), 0)
        self.assertNotEqual(check({"lib/invalid.jar": b"not a ZIP"}), 0)
        self.assertNotEqual(check(entries={"unrelated.class": b"fixture"}), 0)

    def test_global_repository_injection_or_noop_preflight_cannot_be_relocked(self):
        for key, old, new in (
                ("restletRepositoryInit", "if (path in [", "if (true || path in ["),
                ("restletPreflightSettings", "mavenCentral()", "mavenLocal()"),
                ("restletPreflightBuild", "assert project.repositories.isEmpty()", "assert true"),
                ("restletPreflightBuild", "assert resolved == expected", "assert true"),
                ("restletPreflightBuild", "assert java.nio.file.Files.mismatch(artifact.file.toPath(), original.toPath()) == -1L", "assert true")):
            path = self.root / self.build[key]["path"]
            raw, old_hash = path.read_bytes(), self.build[key]["sha256"]
            self.assertIn(old.encode(), raw)
            path.write_bytes(raw.replace(old.encode(), new.encode()))
            self.build[key]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.subTest(helper=key, mutation=old), self.assertRaises(ValueError):
                self.validate()
            path.write_bytes(raw)
            self.build[key]["sha256"] = old_hash

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
                         (" AS build-jdk17", " AS unused-jdk17"),
                         ("COPY --from=build-jdk17", "# COPY --from=build-jdk17"),
                         ("COPY --from=build-jdk17 /opt/java/openjdk /opt/elven-toolchains/jdk17", "COPY --from=build-jdk17 /opt/java/openjdk /opt/other-jdk17"),
                         (" AS build-jdk21", " AS unused-jdk21"),
                         ("COPY --from=build-jdk21", "# COPY --from=build-jdk21"),
                         ("COPY --from=build-jdk21 /opt/java/openjdk /opt/elven-toolchains/jdk21", "COPY --from=build-jdk21 /opt/java/openjdk /opt/other-jdk21"),
                         ("--no-parallel", "--parallel"),
                         ("-Pkotlin.compiler.execution.strategy=in-process", "-Pkotlin.compiler.execution.strategy=daemon"),
                         ("-Porg.gradle.java.installations.auto-download=false", "-Porg.gradle.java.installations.auto-download=true"),
                         ("-Porg.gradle.java.installations.auto-download=false", "-Dorg.gradle.java.installations.auto-download=false"),
                         ("-Porg.gradle.java.installations.auto-detect=false", ""),
                         ("-Porg.gradle.java.installations.paths=$JAVA_HOME", "-Porg.gradle.java.installations.paths=/downloaded/jdk"),
                         ("$JAVA_HOME,/opt/elven-toolchains/jdk17", "$JAVA_HOME"),
                         (",/opt/elven-toolchains/jdk21", ""),
                         ("--init-script /tmp/restlet-compile-only.init.gradle", ""),
                         ("--init-script /tmp/restlet-compile-only.init.gradle", "--init-script /tmp/other.init.gradle"),
                         ("RUN sh /tmp/build-restlet-compile-only.sh", "RUN echo sh /tmp/build-restlet-compile-only.sh"),
                         ("RUN sh /tmp/verify-restlet-payload.sh", "RUN echo sh /tmp/verify-restlet-payload.sh"),
                         ("--project-dir /opt/elven-restlet-preflight", "--project-dir /opt/unreviewed-project"),
                         ("verifyRepositoryBoundaries", "help"),
                         ("RUN ./gradlew", "RUN echo ./gradlew"),
                         ("FROM ${UPSTREAM_IMAGE}", "FROM ${UPSTREAM_IMAGE}\nCOPY --from=builder /opt/elven-restlet-maven /runtime-restlet"),
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
        for key in ("restletBuildScript", "restletRepositoryInit", "restletPayloadCheck", "restletPreflightSettings", "restletPreflightBuild"):
            self.assertIn(ROOT / validated["images"]["java"]["sourceBuild"][key]["path"], inputs)


if __name__ == "__main__":
    unittest.main()
