"""Beyla's official latest image is not a security fix unless its binary is fixed."""
import json
from pathlib import Path
import re
import subprocess
import unittest

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
        self.assertIn("GOPROXY=off", recipe)
        self.assertIn("go build -mod=vendor", recipe)
        self.assertIn("FROM scratch", recipe)

    def test_java_overlay_native_libraries_and_jar_are_not_dropped(self):
        recipe = (ROOT / "images/ebpf/Dockerfile").read_text()
        for value in ("/src/beyla/internal/java/agent/", "linux-amd64/libobijni.so", "linux-aarch64/libobijni.so",
                      "/usr/share/elven-ebpf/build/obi-java-agent.jar", "generateLicenseReport"):
            self.assertIn(value, recipe)
        self.assertNotIn("unmodified", (ROOT / "images/ebpf/NOTICE").read_text().lower())

    def test_local_build_code_is_an_explicit_deny_all_context_exception(self):
        context = (ROOT / "images/ebpf/Dockerfile.dockerignore").read_text()
        self.assertTrue(context.startswith("**\n"))
        for name in ("build-source.sh", "license-bundle.go"):
            self.assertIn("!images/ebpf/" + name, context)
        self.assertNotIn("!**", context)

    def test_source_fetch_script_has_valid_shell_syntax(self):
        result = subprocess.run(["sh", "-n", str(ROOT / "images/ebpf/build-source.sh")], capture_output=True)
        self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
