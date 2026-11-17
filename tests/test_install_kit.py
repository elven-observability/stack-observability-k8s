"""Testes locais. Nenhuma chamada a um cluster real."""
import base64
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1] / "kit" / "plataforma"
SPEC = importlib.util.spec_from_file_location("bootstrap", HERE / "instalar.py")
B = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B)
UID = "12345678-1234-4321-8765-123456789abc"
TOKEN = "token-exclusivamente-sintetico"


class Teste(unittest.TestCase):
    def setUp(self):
        anterior = os.umask(0o077)
        self.addCleanup(os.umask, anterior)
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.tmp = Path(td.name)
        self.kube = self.tmp / "kubeconfig"
        self.kube.touch()
        self.config = (HERE / "cliente.exemplo.toml").read_text()
        for k, v in {
            'kubeconfig = "~/.kube/config"': f'kubeconfig = "{self.kube}"',
            'contexto = ""': 'contexto = "eks-piloto"',
            'uid_cluster = ""': f'uid_cluster = "{UID}"',
            'nome_cluster = ""': 'nome_cluster = "eks-piloto"',
            'tenant_id = ""': 'tenant_id = "Tenant-Piloto"',
            'classe = ""': 'classe = "storage-piloto"',
            'namespaces = []': 'namespaces = ["app-piloto"]',
            'cidrs_exportacao = []': 'cidrs_exportacao = ["192.0.2.5/32"]',
            'cidrs_origem_webhook = []': 'cidrs_origem_webhook = ["198.51.100.6/32"]',
        }.items():
            self.config = self.config.replace(k, v)
        self.alvo, _, _ = B.perfis(self.config.encode())

    def test_defaults_and_no_secrets_in_values(self):
        _, core, sdk = B.perfis(self.config.encode())
        self.assertTrue(core["gateway"]["persistence"]["enabled"])
        self.assertTrue(core["networkPolicy"]["enabled"])
        self.assertFalse(core["modules"]["logs"]["enabled"])
        self.assertFalse(core["modules"]["ebpf"]["enabled"])
        self.assertEqual(core["collection"]["namespaces"], sdk["namespaces"])
        self.assertNotIn(b"Tenant-Piloto", B.json_bytes(core))
        self.assertNotIn(b"Tenant-Piloto", B.json_bytes(sdk))
        self.assertNotIn("endpoints", core)

    def test_bad_profiles(self):
        for old, new in [
            ('tenant_id = "Tenant-Piloto"', 'tenant_id = "x|y"'),
            ('uid_cluster = "' + UID + '"', 'uid_cluster = ""'),
            ('contexto = "eks-piloto"', 'contexto = "--development-images"'),
            ('["app-piloto"]', '["*"]'),
            ('["app-piloto"]', '["kube-system"]'),
            ('["app-piloto"]', '["app-piloto", "app-piloto"]'),
            ('"192.0.2.5/32"', '"0.0.0.0/0"'),
            ('"192.0.2.5/32"', '"0.0.0.0/1", "128.0.0.0/1"'),
            ('"198.51.100.6/32"', '"::/0"'),
            ('"198.51.100.6/32"', '"198.51.100.6/24"'),
            ('cidrs_exportacao = ["192.0.2.5/32"]', 'cidrs_exportacao = []'),
            ('logs_stdout = false', 'logs_stdout = true'),
            ('nodejs20 = false', 'nodejs20 = true'),
            ('metricas_estado_k8s = false', 'metricas_estado_k8s = true'),
            ('java = true', 'java = true\ntoken = "nunca"'),
        ]:
            with self.subTest(old=old, new=new), self.assertRaises(B.Refusa):
                B.perfis(self.config.replace(old, new).encode())
        with self.assertRaises(B.Refusa):
            B.perfis(self.config.replace('[instrumentacao]\n', '[instrumentacao]\n', 1)
                     .replace('namespaces = ["app-piloto"]', 'namespaces = ["fora"]', 1).encode())

    def logs_config(self):
        return self.config.replace("logs_stdout = false", "logs_stdout = true").replace(
            "acesso_host_logs_aprovado = false", "acesso_host_logs_aprovado = true").replace(
            "seletor_nodes_logs = {}", 'seletor_nodes_logs = { "pool" = "piloto" }').replace(
            "metricas_estado_k8s = false", "metricas_estado_k8s = true").replace(
            "cidrs_api_k8s = []", 'cidrs_api_k8s = ["203.0.113.8/32"]')

    def test_host_and_metrics_only_by_opt_in(self):
        cfg = self.logs_config()
        _, core, _ = B.perfis(cfg.encode())
        self.assertEqual(core["nodeAgent"]["nodeSelector"], {"pool": "piloto"})
        self.assertTrue(core["modules"]["logs"]["enabled"])
        self.assertFalse(core["modules"]["clusterMetrics"]["clusterWideApproved"])
        with self.assertRaises(B.Refusa):
            B.perfis(cfg.replace("seletor_nodes_logs = { \"pool\" = \"piloto\" }", "seletor_nodes_logs = {}").encode())

    def ebpf_config(self):
        return self.config.split("\n[ebpf]", 1)[0].replace("cidrs_api_k8s = []", 'cidrs_api_k8s = ["203.0.113.8/32"]') + '''
[ebpf]
habilitado = true
acesso_host_aprovado = true
seletor_nodes = { pool = "piloto" }
todos_nodes_elegiveis_aprovados = false
aplicacoes = [{ namespace = "app-piloto", deployment = "api-sem-sdk" }]
'''

    def test_ebpf_is_explicit_disjoint_and_keeps_the_default_privilege_budget(self):
        with patch.object(B, "VERSION", "1.0.1"):
            _, core, _ = B.perfis(self.ebpf_config().encode())
        ebpf = core["modules"]["ebpf"]
        self.assertTrue(ebpf["enabled"])
        self.assertTrue(ebpf["hostAccessApproved"])
        self.assertTrue(ebpf["excludeSDKInstrumentedServices"])
        self.assertEqual(ebpf["workloads"], [{"namespace": "app-piloto", "deployment": "api-sem-sdk"}])
        self.assertEqual(core["nodeAgent"]["nodeSelector"], {"pool": "piloto"})
        self.assertNotIn("additionalCapabilities", ebpf)

    def test_ebpf_refuses_unapproved_or_ambiguous_scope(self):
        for old, new in (("acesso_host_aprovado = true", "acesso_host_aprovado = false"),
                         ('seletor_nodes = { pool = "piloto" }', "seletor_nodes = {}"),
                         ('namespace = "app-piloto"', 'namespace = "fora"'),
                         ('deployment = "api-sem-sdk"', 'deployment = "*"'),
                         ('cidrs_api_k8s = ["203.0.113.8/32"]', "cidrs_api_k8s = []")):
            with self.subTest(old=old), patch.object(B, "VERSION", "1.0.1"), self.assertRaises(B.Refusa):
                B.perfis(self.ebpf_config().replace(old, new).encode())
        with patch.object(B, "VERSION", "1.0.0"), self.assertRaisesRegex(B.Refusa, "kit corrigido"):
            B.perfis(self.ebpf_config().encode())

    def test_logs_and_ebpf_cannot_silently_expand_each_others_node_scope(self):
        cfg = self.ebpf_config().replace("logs_stdout = false", "logs_stdout = true").replace(
            "acesso_host_logs_aprovado = false", "acesso_host_logs_aprovado = true").replace(
            "seletor_nodes_logs = {}", 'seletor_nodes_logs = { pool = "outro" }')
        with patch.object(B, "VERSION", "1.0.1"), self.assertRaisesRegex(B.Refusa, "mesmo escopo"):
            B.perfis(cfg.encode())

    def test_bad_bundle_refused_before_extraction(self):
        fake = self.tmp / "bad.tar.gz"
        fake.write_bytes(b"not the pinned package")
        with self.assertRaisesRegex(B.Refusa, "SHA-256"):
            B.extrair(fake, self.tmp)
        self.assertFalse((self.tmp / B.ARCHIVE_ROOT).exists())

    def test_wrong_cluster_uid_or_insecure_transport_stops(self):
        safe = {"clusters": [{"cluster": {"server": "https://kube.example.invalid"}}]}
        wrong_uid = {"metadata": {"uid": "different"}}
        with patch.object(B, "kube", side_effect=[B.json_bytes(safe), B.json_bytes(wrong_uid)]):
            with self.assertRaisesRegex(B.Refusa, "UID"):
                B.conferir_alvo(self.alvo, {}, [])
        safe["clusters"][0]["cluster"]["insecure-skip-tls-verify"] = True
        with patch.object(B, "kube", return_value=B.json_bytes(safe)) as request:
            with self.assertRaisesRegex(B.Refusa, "validação TLS"):
                B.conferir_alvo(self.alvo, {}, [])
            self.assertEqual(request.call_count, 1)

    def secret(self, tenant="Tenant-Piloto", dono="elven-cli"):
        return {
            "type": "Opaque",
            "metadata": {"name": B.INGEST_SECRET, "namespace": B.NAMESPACE, "uid": "uid-secret",
                         "resourceVersion": "42", "labels": {"app.kubernetes.io/managed-by": dono,
                         "app.kubernetes.io/instance": B.CORE, "app.kubernetes.io/part-of": "elven-observability",
                         "elven.observability/namespace": B.NAMESPACE}},
            "data": {"tenant-id": base64.b64encode(tenant.encode()).decode(),
                     "api-token": base64.b64encode(TOKEN.encode()).decode()},
        }

    def test_secret_absence_owner_and_tenant(self):
        with patch.object(B, "kube", return_value=b""):
            self.assertIsNone(B.identidade_secret(self.alvo, {}))
        for tenant, dono, match in [("outro", "elven-cli", "tenant"), ("Tenant-Piloto", "estranho", "adotar")]:
            with patch.object(B, "kube", side_effect=[b"namespace/elven-observability", B.json_bytes(self.secret(tenant, dono))]):
                with self.assertRaisesRegex(B.Refusa, match):
                    B.identidade_secret(self.alvo, {})
        with patch.object(B, "kube", side_effect=[b"namespace/elven-observability", B.json_bytes(self.secret())]):
            self.assertEqual(B.identidade_secret(self.alvo, {}), ("uid-secret", "42"))

    def test_not_found_differs_from_rbac_denial(self):
        with patch.object(B, "kube", side_effect=[b"namespace/elven-observability", B.Refusa("forbidden")]):
            with self.assertRaisesRegex(B.Refusa, "forbidden"):
                B.identidade_secret(self.alvo, {})

    def test_child_output_does_not_surface_credentials(self):
        with patch.object(B.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, TOKEN.encode(), TOKEN.encode())):
            with self.assertRaises(B.Refusa) as raised:
                B.executar(["fixture"], "Falha sintética", {})
        self.assertNotIn(TOKEN, str(raised.exception))

    def test_hidden_prompt_refuses_fallback(self):
        with patch.object(B.os, "open", side_effect=OSError), patch.object(B, "getpass") as prompt:
            with self.assertRaisesRegex(B.Refusa, "terminal seguro"):
                B.pedir_token()
            prompt.assert_not_called()

    def test_credentials_read_by_child_and_closed(self):
        child = ("import pathlib,stat,sys;"
                 "assert all(stat.S_IMODE(pathlib.Path(p).stat().st_mode)==0o600 for p in sys.argv[1:]);"
                 "assert pathlib.Path(sys.argv[1]).read_bytes()==b'Tenant-Piloto';"
                 "assert pathlib.Path(sys.argv[2]).read_bytes()==b'token-exclusivamente-sintetico'")
        with B.credenciais(self.tmp, "Tenant-Piloto", TOKEN.encode()) as (paths, fds):
            subprocess.run([sys.executable, "-I", "-c", child, *paths], pass_fds=fds, check=True)
        self.assertTrue(all(not Path(p).exists() for p in paths))

    def test_review_reuse_and_first_install(self):
        cfg = self.tmp / "cliente.toml"
        cfg.write_text(self.config)
        for existente in (None, ("uid-secret", "42")):
            review = self.tmp / f"plano-{bool(existente)}"
            called = []
            def executar(cmd, etapa, env, timeout=180, fds=()):
                called.append(cmd)
                self.assertNotIn("--development-images", cmd)
                self.assertNotIn(TOKEN, cmd)
                if "install" in cmd and existente is None:
                    p = cmd[cmd.index("--token-file") + 1]
                    self.assertEqual(Path(p).read_text(), TOKEN)
                return b"fixture render"
            def rodar(acao):
                with patch.object(sys, "argv", ["instalar.py", acao, "--config", str(cfg), "--revisao", str(review)]):
                    B.main()
            with (patch.object(B, "extrair", return_value=self.tmp), patch.object(B, "garantir_pacote"),
                  patch.object(B, "conferir_openssl"),
                  patch.object(B, "conferir_alvo"), patch.object(B, "executar", side_effect=executar),
                  patch.object(B.shutil, "which", return_value="/fixture/tool"),
                  patch.object(B, "identidade_secret", side_effect=[existente, existente, existente, ("uid-secret", "42")]),
                  patch.object(B, "pedir_token", return_value=TOKEN.encode()) as prompt, redirect_stdout(io.StringIO())):
                rodar("plano")
                prompt.assert_not_called()
                self.assertFalse(any("install" in cmd for cmd in called))
                rodar("instalar")
                self.assertEqual(prompt.call_count, int(existente is None))
                writes = [cmd for cmd in called if "install" in cmd]
                self.assertEqual(len(writes), 1)
                self.assertIn("--instrumentation-values", writes[0])
                self.assertEqual("--token-file" in writes[0], existente is None)

    def test_review_tampering_aborts_before_contact(self):
        cfg = self.tmp / "cliente.toml"
        cfg.write_text(self.config)
        review = self.tmp / "plano"
        review.mkdir()
        (review / "core.values.json").write_text("{}")
        with (patch.object(B, "extrair", return_value=self.tmp), patch.object(B, "garantir_pacote"),
              patch.object(B, "conferir_openssl"),
              patch.object(B, "executar", return_value=b"fixture"),
              patch.object(B.shutil, "which", return_value="/fixture/tool"),
              patch.object(B, "conferir_alvo") as kube, patch.object(B, "pedir_token") as prompt,
              patch.object(sys, "argv", ["instalar.py", "instalar", "--config", str(cfg), "--revisao", str(review)])):
            with self.assertRaisesRegex(B.Refusa, "revisão"):
                B.main()
            kube.assert_not_called()
            prompt.assert_not_called()

    def test_guiado_requires_explicit_approval_then_reuses_it(self):
        cfg = self.tmp / "cliente.toml"
        cfg.write_text(self.config)
        review = self.tmp / "revisao-v1.0.0"
        commands, order = [], []
        def executar(cmd, etapa, env, timeout=180, fds=()):
            commands.append(cmd)
            if "install" in cmd:
                order.append("install")
                self.assertTrue((review / "aprovacao.json").is_file())
                self.assertNotIn(TOKEN, cmd)
            return b"fixture render"
        def confirmar(*_):
            order.append("aprovar")
        def pedir():
            order.append("token")
            return TOKEN.encode()
        same = ("uid-secret", "42")
        with (patch.object(B, "extrair", return_value=self.tmp), patch.object(B, "garantir_pacote"),
              patch.object(B, "conferir_openssl"),
              patch.object(B, "conferir_alvo"), patch.object(B, "executar", side_effect=executar),
              patch.object(B.shutil, "which", return_value="/fixture/tool"),
              patch.object(B, "identidade_secret", side_effect=[None, None, same, same, same, same]),
              patch.object(B, "confirmar_plano", side_effect=confirmar) as approval,
              patch.object(B, "pedir_token", side_effect=pedir) as prompt,
              patch.object(sys, "argv", ["instalar.py", "guiado", "--config", str(cfg), "--revisao", str(review)]),
              redirect_stdout(io.StringIO()) as output):
            B.main()
            B.main()
        self.assertEqual(order, ["aprovar", "token", "install", "install"])
        self.assertEqual(approval.call_count, 1)
        self.assertEqual(prompt.call_count, 1)
        self.assertNotIn(TOKEN, output.getvalue())
        self.assertEqual((review / "aprovacao.json").stat().st_mode & 0o777, 0o600)
        self.assertFalse(any("--development-images" in cmd for cmd in commands))

    def test_declining_plan_cannot_approve_it_for_the_next_run(self):
        cfg = self.tmp / "cliente.toml"
        cfg.write_text(self.config)
        review = self.tmp / "revisao-v1.0.0"
        commands = []
        def executar(cmd, *_args, **_kwargs):
            commands.append(cmd)
            return b"fixture render"
        with (patch.object(B, "extrair", return_value=self.tmp), patch.object(B, "garantir_pacote"),
              patch.object(B, "conferir_openssl"),
              patch.object(B, "conferir_alvo"), patch.object(B, "executar", side_effect=executar),
              patch.object(B.shutil, "which", return_value="/fixture/tool"),
              patch.object(B, "identidade_secret", return_value=None),
              patch.object(B, "confirmar_plano", side_effect=B.Refusa("não aprovado")) as approval,
              patch.object(B, "pedir_token") as prompt,
              patch.object(sys, "argv", ["instalar.py", "guiado", "--config", str(cfg), "--revisao", str(review)]),
              redirect_stdout(io.StringIO())):
            for _ in range(2):
                with self.assertRaisesRegex(B.Refusa, "não aprovado"):
                    B.main()
            self.assertEqual(approval.call_count, 2)
            prompt.assert_not_called()
        self.assertFalse((review / "aprovacao.json").exists())
        self.assertFalse(any("install" in cmd for cmd in commands))

    def test_approval_mismatch_does_not_prompt(self):
        review = self.tmp / "review"
        review.mkdir()
        (review / "aprovacao.json").write_text("{}")
        alvo, core, op = B.perfis(self.config.encode())
        with patch.object(B, "confirmar_plano") as approve:
            with self.assertRaisesRegex(B.Refusa, "aprovação"):
                B.aprovar_revisao(alvo, core, op, review, b"receipt")
        approve.assert_not_called()

    def test_incompatible_local_ssl_is_rejected_before_any_cluster_io(self):
        for version in (b"LibreSSL 3.3.6", b"OpenSSL 1.1.1", b"unknown"):
            with patch.object(B, "executar", return_value=version), self.assertRaisesRegex(B.Refusa, "OpenSSL 3"):
                B.conferir_openssl({})
        with patch.object(B, "executar", return_value=b"OpenSSL 3.6.4 25 Aug 2026\n"):
            B.conferir_openssl({})

    def test_confirmation_requires_a_real_terminal(self):
        alvo, core, op = B.perfis(self.config.encode())
        with patch("builtins.open", side_effect=OSError), redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(B.Refusa, "Sem terminal"):
                B.confirmar_plano(alvo, core, op, self.tmp)

    def test_download_never_allows_plaintext_foreign_host_or_invalid_bytes(self):
        for url in ("http://github.com/asset", "https://github.com.evil.invalid/asset",
                    "https://user@github.com/asset", "https://github.com:444/asset"):
            with self.subTest(url=url), self.assertRaises(B.Refusa):
                B.url_pacote(url)
        for host in ("github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"):
            B.url_pacote("https://" + host + "/asset")
        with patch.object(B, "build_opener") as opener:
            response = opener.return_value.open.return_value.__enter__.return_value
            response.geturl.return_value = B.ARCHIVE_URL
            response.read.return_value = b"not the official bundle"
            with self.assertRaisesRegex(B.Refusa, "SHA-256"):
                B.baixar_pacote()
            response.read.assert_called_once_with(600_001)
        with self.assertRaises(B.Refusa):
            B.RedirecionamentoHTTPS().redirect_request(None, None, 302, "Found", {}, "http://github.com/asset")

    def test_source_download_never_overwrites_an_existing_path(self):
        path = self.tmp / B.ARCHIVE_NAME
        with patch.object(B, "baixar_pacote", return_value=b"synthetic bundle") as download, redirect_stdout(io.StringIO()):
            B.garantir_pacote(path)
            self.assertEqual(path.read_bytes(), b"synthetic bundle")
            B.garantir_pacote(path)
            self.assertEqual(download.call_count, 1)
        link = self.tmp / "broken-link"
        link.symlink_to(self.tmp / "absent")
        with patch.object(B, "baixar_pacote") as download:
            B.garantir_pacote(link)
        download.assert_not_called()
        with self.assertRaises(OSError):
            B.ler_limite(link, 100)

    @unittest.skipUnless(os.environ.get("ELVEN_TEST_ARCHIVE") and shutil.which("helm"), "defina o asset oficial e Helm no PATH")
    def test_renders_real_asset_twice_for_two_profiles(self):
        cfgs = (self.config, self.logs_config())
        for cfg in cfgs:
            raws = []
            for _ in range(2):
                with tempfile.TemporaryDirectory(dir=self.tmp) as sub:
                    tmp = Path(sub)
                    root = B.extrair(os.environ["ELVEN_TEST_ARCHIVE"], tmp)
                    alvo, core, op = B.perfis(cfg.encode())
                    arquivos, recibo, *_ = B.preparar(root, tmp, cfg.encode(), alvo, core, op, B.ambiente())
                    self.assertIn(b"kind: MutatingWebhookConfiguration", arquivos["instrumentation.render.yaml"])
                    self.assertIn(b"elvenobservability/elven-collector", arquivos["core.render.yaml"])
                    self.assertNotIn(b"Tenant-Piloto", arquivos["core.render.yaml"])
                    self.assertIn(b"/var/log/pods/app-piloto_" if core["modules"]["logs"]["enabled"] else b"kind: StatefulSet",
                                  arquivos["core.render.yaml"])
                    raws.append(recibo)
            self.assertEqual(raws[0], raws[1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
