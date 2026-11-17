"""Beyla's official latest image is not a security fix unless its binary is fixed."""
import json
from pathlib import Path
import re
import subprocess
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]


class EbpfSourceBuildTests(unittest.TestCase):
    def test_source_and_submodule_are_immutable_and_match_the_release_lock(self):
        recipe = (ROOT / "images/ebpf/Dockerfile").read_text()
        source = (ROOT / "images/ebpf/build-source.sh").read_text()
        image = json.loads((ROOT / "versions.lock.json").read_text())["images"]["beyla"]
        build = image["sourceBuild"]
        for key, variable in (("revision", "revision"), ("obiRevision", "obi_revision")):
            self.assertRegex(build[key], r"^[0-9a-f]{40}$")
            self.assertIn(variable + "=" + build[key], source)
            self.assertIn(build[key], recipe)
        self.assertIn('rev-parse HEAD)', source)
        self.assertIn('git -C "$destination" fetch --depth=1 origin "$revision"', source)
        self.assertNotIn("--remote", source)
        self.assertIn(build["goImage"], recipe)

    def test_go_dependency_is_patched_before_bpf_generation_and_offline_compile(self):
        recipe = (ROOT / "images/ebpf/Dockerfile").read_text()
        patch = recipe.index("go mod edit -require=golang.org/x/net@v0.62.0")
        generation = recipe.index("make -C .obi-src generate")
        self.assertLess(patch, generation)
        self.assertIn("BPF_TARGETS=amd64,arm64", recipe)
        self.assertIn("go mod vendor && go mod verify", recipe)
        self.assertIn("GOFLAGS=-mod=mod", recipe)
        self.assertIn("GOPROXY=off", recipe)
        self.assertIn("go build -mod=vendor", recipe)
        self.assertIn("FROM scratch", recipe)

    def test_java_overlay_native_libraries_and_jar_are_not_dropped(self):
        recipe = (ROOT / "images/ebpf/Dockerfile").read_text()
        for value in ("/src/beyla/internal/java/agent/", "linux-amd64/libobijni.so", "linux-aarch64/libobijni.so",
                      "/usr/share/elven-ebpf/build/obi-java-agent.jar", "generateLicenseReport"):
            self.assertIn(value, recipe)
        self.assertNotIn("unmodified", (ROOT / "images/ebpf/NOTICE").read_text().lower())
        self.assertIn("gcc-aarch64-linux-gnu libc6-dev-arm64-cross", recipe)
        self.assertIn("gcc-x86-64-linux-gnu libc6-dev-amd64-cross", recipe)

    def test_local_build_code_is_an_explicit_deny_all_context_exception(self):
        context = (ROOT / "images/ebpf/Dockerfile.dockerignore").read_text()
        self.assertTrue(context.startswith("**\n"))
        for name in ("build-source.sh", "license-bundle.go"):
            self.assertIn("!images/ebpf/" + name, context)
        self.assertNotIn("!**", context)

    def test_source_fetch_script_has_valid_shell_syntax(self):
        result = subprocess.run(["sh", "-n", str(ROOT / "images/ebpf/build-source.sh")], capture_output=True)
        self.assertEqual(result.returncode, 0)

    def test_ci_validates_the_real_scanned_beyla_config_without_host_capabilities(self):
        workflow = (ROOT / ".github/workflows/images.yaml").read_text()
        validator = (ROOT / "scripts/validate.py").read_text()
        self.assertIn("docker load --input artifacts/images/beyla.oci.tar", workflow)
        self.assertIn('("beyla", "ELVEN_BEYLA_IMAGE")', workflow)
        self.assertIn('"beyla.yaml": "beyla"', validator)
        self.assertIn('["config", "migrate", f"/config/{key}"]', validator)
        self.assertIn('["config", "validate", "/config/beyla-v2.yaml"]', validator)
        self.assertNotIn('"--allow-partial"', validator)
        self.assertIn('"--cap-drop", "ALL"', validator)

    def test_native_arm_is_a_required_gate_over_the_same_scanned_archives(self):
        for name, build in (("images.yaml", "build-and-scan"), ("instrumentation.yaml", "build-and-test")):
            workflow = yaml.safe_load((ROOT / ".github/workflows" / name).read_text())
            jobs = workflow["jobs"]
            self.assertEqual(jobs["publish"]["needs"], [build, "native-arm"])
            arm = jobs["native-arm"]
            self.assertEqual(arm["runs-on"], "ubuntu-24.04-arm")
            self.assertEqual(arm["needs"], build)
            steps = json.dumps(arm["steps"])
            self.assertIn("archiveSha256", steps)
            self.assertIn("linux/arm64", steps)
            self.assertIn("docker", steps)
            self.assertNotIn("setup-qemu", steps)
            self.assertNotIn("images-release.py build", steps)

    def test_fast_configuration_qualification_cannot_publish_or_change_image_sources(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/images.yaml").read_text())
        jobs = workflow["jobs"]
        self.assertIn("inputs.candidate_run == ''", jobs["publish"]["if"])
        self.assertEqual(jobs["candidate-runtime"]["permissions"], {"contents": "read", "actions": "read"})
        steps = json.dumps(jobs["candidate-runtime"]["steps"])
        self.assertIn("inputsSha256", steps)
        self.assertIn("archiveSha256", steps)
        self.assertIn("highCriticalCount", steps)
        self.assertIn("timedelta(hours=24)", steps)
        self.assertNotIn("id-token", steps)
        self.assertNotIn("images-release.py publish", steps)
        self.assertNotIn("cosign sign", steps)


if __name__ == "__main__":
    unittest.main()
