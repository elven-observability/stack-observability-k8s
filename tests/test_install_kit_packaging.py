"""Public ZIP and launcher contracts; no real Kubernetes or credentials."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pty
import select
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile
import sys

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("install_kit_package", ROOT / "scripts/package-install-kit.py")
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


class KitPackagingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="elven-kit-contract-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.bundle = b"synthetic-bundle-for-packaging-only"
        self.revision = "1" * 40

    def build(self, name="build", root=ROOT):
        with patch.object(P.BOOTSTRAP, "ARCHIVE_SHA", hashlib.sha256(self.bundle).hexdigest()):
            return P.build(self.folder / name, self.bundle, self.revision, root)

    def test_deterministic_whitelist_hashes_and_executable(self):
        first, manifest_path, sums = self.build("first")
        second, *_ = self.build("second")
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(sums.read_text(), f"{hashlib.sha256(first.read_bytes()).hexdigest()}  {first.name}\n")
        manifest = json.loads(manifest_path.read_bytes())
        with zipfile.ZipFile(first) as package:
            names = package.namelist()
            expected = {P.NAME + "/" + name for name in P.FILES}
            expected.update({P.NAME + "/kit.manifest.json", P.NAME + "/plataforma/" + P.BOOTSTRAP.ARCHIVE_NAME})
            self.assertEqual(set(names), expected)
            self.assertEqual(len(names), len(expected))
            self.assertTrue(all(not name.startswith("/") and ".." not in Path(name).parts for name in names))
            for name, expected_hash in manifest["files"].items():
                self.assertEqual(hashlib.sha256(package.read(P.NAME + "/" + name)).hexdigest(), expected_hash)
            mode = package.getinfo(P.NAME + "/instalar").external_attr >> 16
            self.assertEqual(stat.S_IMODE(mode), 0o755)
            self.assertTrue(stat.S_ISREG(mode))
            self.assertEqual(package.read(P.NAME + "/kit.manifest.json"), manifest_path.read_bytes())

    def test_foreign_bundle_dirty_checkout_and_overwrite_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "official"):
            P.build(self.folder, b"foreign", self.revision)
        self.build()
        with self.assertRaisesRegex(ValueError, "overwrite"):
            self.build()
        with (patch.object(P.subprocess, "check_output", return_value=b" M source\n"),
              patch.object(P.BOOTSTRAP, "baixar_pacote") as download,
              patch.object(P.sys, "argv", ["package-install-kit.py", "--output-dir", str(self.folder)])):
            with self.assertRaisesRegex(ValueError, "clean Git"):
                P.main()
        download.assert_not_called()

    def test_private_customer_file_and_reviews_never_enter_archive(self):
        source = self.folder / "source"
        for name in P.FILES:
            target = source / "kit" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / "kit" / name, target)
        (source / "kit/plataforma/cliente.toml").write_text("PRIVATE-CUSTOMER-CONFIG")
        review = source / "kit/plataforma/revisao-v1.0.0"
        review.mkdir()
        (review / "revisao.json").write_text("PRIVATE-REVIEW")
        archive, *_ = self.build(root=source)
        with zipfile.ZipFile(archive) as package:
            combined = b"\n".join(package.read(name) for name in package.namelist())
        self.assertNotIn(b"PRIVATE-CUSTOMER-CONFIG", combined)
        self.assertNotIn(b"PRIVATE-REVIEW", combined)

    def test_launcher_missing_config_never_calls_python_or_kubernetes(self):
        kit = self.folder / "kit space"
        kit.mkdir()
        launcher = kit / "instalar"
        shutil.copyfile(ROOT / "kit/instalar", launcher)
        result = subprocess.run(["/bin/sh", str(launcher)], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, cwd=self.folder, env={"PATH": "/usr/bin:/bin"})
        self.assertEqual(result.returncode, 1)
        self.assertIn("Falta a configuração", result.stderr)
        self.assertIn("Nenhum token", result.stderr)

    def test_launcher_spaces_and_different_working_directory(self):
        kit = self.folder / "kit space"
        platform = kit / "plataforma"
        platform.mkdir(parents=True)
        shutil.copyfile(ROOT / "kit/instalar", kit / "instalar")
        (platform / "cliente.toml").touch()
        tools = self.folder / "bin"
        tools.mkdir()
        fake = tools / "python3"
        fake.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
        fake.chmod(0o755)
        result = subprocess.run(["/bin/sh", str(kit / "instalar")], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, cwd=self.folder,
                                env={"PATH": str(tools) + ":/usr/bin:/bin"})
        self.assertEqual(result.returncode, 0, result.stderr)
        canonical = platform.resolve()
        self.assertEqual(result.stdout.splitlines()[2:], ["-I", str(canonical / "instalar.py"), "guiado",
            "--pacote", str(canonical / P.BOOTSTRAP.ARCHIVE_NAME), "--config", str(canonical / "cliente.toml"),
            "--revisao", str(canonical / "revisao-v1.0.0")])
        for extra in ("--development-images", "synthetic-token"):
            result = subprocess.run(["/bin/sh", str(kit / "instalar"), extra], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(extra, result.stdout + result.stderr)

    def terminal(self, script, prompt, answer):
        pid, master = pty.fork()
        if pid == 0:
            os.execv(sys.executable, [sys.executable, "-I", "-c", script])
        output, answered, result = b"", False, None
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                readable, _, _ = select.select([master], [], [], 0.1)
                if readable:
                    try:
                        data = os.read(master, 65536)
                    except OSError:
                        data = b""
                    output += data
                    if not answered and prompt.encode() in output:
                        os.write(master, (answer + "\n").encode())
                        answered = True
                done, status = os.waitpid(pid, os.WNOHANG)
                if done:
                    result = status
                    break
            self.assertIsNotNone(result, "Terminal flow timed out: " + output.decode(errors="replace"))
            self.assertTrue(answered, "The actual terminal prompt did not appear")
            self.assertEqual(os.waitstatus_to_exitcode(result), 0, output.decode(errors="replace"))
            return output
        finally:
            if result is None:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            os.close(master)

    def test_actual_tty_confirmation_works_without_a_seekable_stream(self):
        script = (
            f"import pathlib,runpy; m=runpy.run_path({str(ROOT / 'kit/plataforma/instalar.py')!r}); "
            "m['confirmar_plano']({'nome_cluster':'synthetic-test','contexto':'no-cluster',"
            "'uid_cluster':'12345678-1234-4321-8765-123456789abc','tenant_id':'SyntheticTenant'},"
            "{'collection':{'namespaces':['synthetic-app']},'modules':{'logs':{'enabled':False},"
            "'clusterMetrics':{'enabled':False}}},"
            "{'runtimes':{'java':True,'nodejs':False,'nodejs20':False,'python':False}},"
            f"pathlib.Path({str(self.folder)!r})); print('APPROVAL_OK',flush=True)"
        )
        output = self.terminal(script, "para continuar:", "INSTALAR synthetic-test")
        self.assertIn(b"APPROVAL_OK", output)

    def test_actual_tty_token_has_no_echo(self):
        synthetic = "synthetic-tty-token-only"
        script = (
            f"import runpy; m=runpy.run_path({str(ROOT / 'kit/plataforma/instalar.py')!r}); "
            f"assert m['pedir_token']()=={synthetic.encode()!r}; print('TOKEN_OK',flush=True)"
        )
        output = self.terminal(script, "(sem eco):", synthetic)
        self.assertNotIn(synthetic.encode(), output)
        self.assertIn(b"TOKEN_OK", output)

    @unittest.skipUnless(os.environ.get("ELVEN_TEST_ARCHIVE"), "pinned release bundle required for the real ZIP test")
    def test_real_release_bundle_is_included_unchanged(self):
        bundle = P.BOOTSTRAP.ler_limite(os.environ["ELVEN_TEST_ARCHIVE"], 600_000)
        archive, *_ = P.build(self.folder / "real", bundle, self.revision)
        with zipfile.ZipFile(archive) as package:
            self.assertEqual(package.read(P.NAME + "/plataforma/" + P.BOOTSTRAP.ARCHIVE_NAME), bundle)
            self.assertEqual(package.testzip(), None)


if __name__ == "__main__":
    unittest.main()
