#!/usr/bin/env python3
"""Bootstrap interativo, independente, para o pacote oficial Elven v1.0.0."""
import argparse
import base64
from contextlib import contextmanager
from getpass import GetPassWarning, getpass
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, Request
import uuid
import warnings

if sys.version_info < (3, 11):
    sys.exit("Elven: use Python 3.11 ou superior.")
import tomllib

VERSION = "1.0.0"
ARCHIVE_NAME = "elven-observability-v1.0.0.tar.gz"
ARCHIVE_SHA = "0231a910f0f22c4c132fb25e99878eaf86bc341439c557eb785d91d4d36bcf00"
ARCHIVE_ROOT = "elven-observability-v1.0.0"
ARCHIVE_URL = ("https://github.com/elven-observability/stack-observability-k8s/"
               "releases/download/v1.0.0/" + ARCHIVE_NAME)
NAMESPACE, CORE, OPERATOR = "elven-observability", "elven", "elven-operator"
INGEST_SECRET = "elven-ingest"
IDENTIFIER = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
DNS = r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?"
KEY = r"(?:[a-z0-9][a-z0-9.-]{0,251}/)?[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?"
LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?"


class Refusa(Exception):
    pass


def exigir(condicao, mensagem):
    if not condicao:
        raise Refusa(mensagem)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def json_bytes(obj):
    return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def ler_limite(path, limite):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        exigir(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "É obrigatório um arquivo regular.")
        raw = stream.read(limite + 1)
    exigir(len(raw) <= limite, "Arquivo excede o limite do kit.")
    return raw


def escrever(path, raw):
    with Path(path).open("xb") as stream:
        stream.write(raw)


def url_pacote(url):
    parsed = urlsplit(url)
    exigir(parsed.scheme == "https" and parsed.hostname in {
        "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"
    } and parsed.username is None and parsed.password is None and parsed.port in (None, 443),
        "Download recusado: o pacote deve permanecer no GitHub por HTTPS validado.")


class RedirecionamentoHTTPS(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        url_pacote(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def baixar_pacote():
    """Somente o asset fixado; nunca executa scripts remotos ou usa uma URL do cliente."""
    url_pacote(ARCHIVE_URL)
    request = Request(ARCHIVE_URL, headers={"User-Agent": "elven-install-kit/1.0.0"})
    with build_opener(RedirecionamentoHTTPS()).open(request, timeout=30) as response:
        url_pacote(response.geturl())
        raw = response.read(600_001)
    exigir(len(raw) <= 600_000 and sha(raw) == ARCHIVE_SHA,
           "Download recusado: tamanho ou SHA-256 diferente do asset oficial.")
    return raw


def garantir_pacote(path):
    if not os.path.lexists(path):
        print("Baixando o pacote oficial do GitHub e conferindo SHA-256…", flush=True)
        escrever(path, baixar_pacote())


def secao(config, nome, campos):
    dado = config.get(nome)
    exigir(type(dado) is dict and set(dado) == set(campos), f"Seção [{nome}]: use exatamente os campos do exemplo.")
    return dado


def texto(dado, campo, regex):
    valor = dado[campo]
    exigir(type(valor) is str and re.fullmatch(regex, valor) is not None, f"Preencha corretamente {campo}.")
    return valor


def bools(dado, campos):
    for nome in campos:
        exigir(type(dado[nome]) is bool, f"{nome} deve ser true ou false.")


def lista_ns(valor, nome):
    protegidos = {NAMESPACE, "default", "kube-system", "kube-public", "kube-node-lease"}
    exigir(type(valor) is list and 1 <= len(valor) <= 100
           and all(type(v) is str and re.fullmatch(IDENTIFIER, v) and v not in protegidos for v in valor),
           f"{nome}: informe namespaces de aplicações explícitos, sem curingas nem namespaces protegidos.")
    exigir(len(set(valor)) == len(valor), f"{nome}: há namespaces repetidos.")
    return valor


def cidrs(valor, nome, obrigatorio=False):
    exigir(type(valor) is list and len(valor) <= 128 and all(type(v) is str for v in valor),
           f"{nome}: informe lista de CIDRs.")
    exigir(not obrigatorio or valor, f"{nome}: é obrigatório preencher os CIDRs efetivos e aprovados.")
    try:
        redes = [ipaddress.ip_network(v, strict=True) for v in valor]
    except ValueError:
        raise Refusa(f"{nome}: CIDR inválido ou não canônico.") from None
    exigir(all(str(r) == v for r, v in zip(redes, valor)), f"{nome}: use a representação canônica.")
    exigir(len(set(redes)) == len(redes), f"{nome}: há CIDRs repetidos.")
    for versao in (4, 6):
        exigir(not any(r.prefixlen == 0 for r in ipaddress.collapse_addresses(r for r in redes if r.version == versao)),
               f"{nome}: rede irrestrita não é aceita, nem dividida em prefixos menores.")
    return valor


def labels(valor, nome, vazio=True):
    exigir(type(valor) is dict and (vazio or valor) and len(valor) <= 16
           and all(re.fullmatch(KEY, k) and type(v) is str and re.fullmatch(LABEL, v) for k, v in valor.items()),
           f"{nome}: informe um mapa de labels Kubernetes exatas.")
    return valor


def perfis(raw):
    try:
        config = tomllib.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise Refusa("TOML inválido. O conteúdo não foi exibido.") from None
    exigir(set(config) == {"alvo", "storage", "coleta", "instrumentacao", "rede"},
           "Use apenas as cinco seções do exemplo; token e overrides arbitrários não são aceitos.")
    alvo = secao(config, "alvo", ("kubeconfig", "contexto", "uid_cluster", "nome_cluster", "dominio_cluster", "tenant_id"))
    texto(alvo, "contexto", r"[A-Za-z0-9][A-Za-z0-9.:_/@-]{0,511}")
    texto(alvo, "nome_cluster", r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
    exigir(alvo["nome_cluster"] not in {"example-cluster", "your-cluster", "CHANGE_ME"}, "Use o nome lógico real.")
    dominio = texto(alvo, "dominio_cluster", DNS)
    exigir(all(re.fullmatch(IDENTIFIER, parte) for parte in dominio.split(".")), "dominio_cluster inválido.")
    texto(alvo, "tenant_id", r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
    try:
        exigir(str(uuid.UUID(alvo["uid_cluster"])) == alvo["uid_cluster"], "uid_cluster deve ser o UUID canônico de kube-system.")
    except (ValueError, TypeError, AttributeError):
        raise Refusa("Preencha uid_cluster com o UID real de kube-system.") from None
    texto(alvo, "kubeconfig", r"[^\x00-\x1f\x7f]{1,4096}")
    kubeconfig = Path(alvo["kubeconfig"]).expanduser()
    exigir(kubeconfig.is_absolute() and kubeconfig.is_file(), "kubeconfig deve apontar a um arquivo confiável, com caminho absoluto ou ~/.")
    alvo = {**alvo, "kubeconfig": str(kubeconfig.resolve(strict=True))}
    storage = secao(config, "storage", ("classe", "tamanho"))
    texto(storage, "classe", DNS)
    texto(storage, "tamanho", r"(?:[1-9][0-9]{0,2})Gi")
    coleta = secao(config, "coleta", ("namespaces", "logs_stdout", "acesso_host_logs_aprovado",
                  "seletor_nodes_logs", "todos_nodes_elegiveis_aprovados", "metricas_estado_k8s", "privacidade_logs"))
    bools(coleta, ("logs_stdout", "acesso_host_logs_aprovado", "todos_nodes_elegiveis_aprovados", "metricas_estado_k8s"))
    namespaces = lista_ns(coleta["namespaces"], "coleta.namespaces")
    seletor = labels(coleta["seletor_nodes_logs"], "seletor_nodes_logs")
    exigir("kubernetes.io/os" not in seletor, "O DaemonSet deste kit já fixa Linux.")
    if coleta["logs_stdout"]:
        exigir(coleta["acesso_host_logs_aprovado"], "Logs stdout exigem aprovação explícita de leitura do host.")
        exigir(bool(seletor) != coleta["todos_nodes_elegiveis_aprovados"],
               "Logs stdout exigem seletor piloto OU aprovação explícita de todos os nodes elegíveis.")
    else:
        exigir(not coleta["acesso_host_logs_aprovado"] and not seletor and not coleta["todos_nodes_elegiveis_aprovados"],
               "Com logs stdout desativados, não configure acesso ao host ou seleção de nodes.")
    exigir(coleta["privacidade_logs"] in ("selective", "strict"), "privacidade_logs aceita selective ou strict.")
    sdk = secao(config, "instrumentacao", ("namespaces", "java", "nodejs", "nodejs20", "python",
                "excecao_eol_nodejs20_aprovada", "amostragem_traces"))
    bools(sdk, ("java", "nodejs", "nodejs20", "python", "excecao_eol_nodejs20_aprovada"))
    alvos_sdk = lista_ns(sdk["namespaces"], "instrumentacao.namespaces")
    exigir(set(alvos_sdk) <= set(namespaces), "Os namespaces de instrumentação devem estar na lista da coleta.")
    exigir(any(sdk[k] for k in ("java", "nodejs", "nodejs20", "python")), "Escolha pelo menos um runtime.")
    exigir(sdk["nodejs20"] == sdk["excecao_eol_nodejs20_aprovada"], "Node.js 20 exige exceção EOL explícita.")
    texto(sdk, "amostragem_traces", r"(?:0\.[0-9]{1,8}|1(?:\.0{1,8})?)")
    exigir(float(sdk["amostragem_traces"]) > 0, "Use uma amostragem positiva para o piloto.")
    rede = secao(config, "rede", ("cidrs_exportacao", "cidrs_origem_webhook", "cidrs_api_k8s",
                 "namespace_dns", "labels_pods_dns", "cidrs_dns"))
    exportacao = cidrs(rede["cidrs_exportacao"], "cidrs_exportacao", True)
    origem_webhook = cidrs(rede["cidrs_origem_webhook"], "cidrs_origem_webhook", True)
    api = cidrs(rede["cidrs_api_k8s"], "cidrs_api_k8s", coleta["metricas_estado_k8s"])
    dns_cidrs = cidrs(rede["cidrs_dns"], "cidrs_dns")
    dns_ns = texto(rede, "namespace_dns", IDENTIFIER)
    dns_labels = labels(rede["labels_pods_dns"], "labels_pods_dns", vazio=False)
    core = {
        "cluster": {"environment": "production", "domain": dominio},
        "gateway": {"persistence": {"enabled": True, "storageClass": storage["classe"], "size": storage["tamanho"]}},
        "collection": {"namespaces": namespaces},
        "modules": {"logs": {"enabled": coleta["logs_stdout"], "hostAccessApproved": coleta["acesso_host_logs_aprovado"]},
                    "clusterMetrics": {"enabled": coleta["metricas_estado_k8s"], "clusterWideApproved": False},
                    "kubeletMetrics": {"enabled": False}, "ebpf": {"enabled": False}, "profiles": {"enabled": False}},
        "nodeAgent": {"nodeSelector": seletor},
        "privacy": {"logBodyMode": coleta["privacidade_logs"]},
        "networkPolicy": {"enabled": True, "exportCIDRs": exportacao, "apiServerCIDRs": api,
                          "dnsNamespace": dns_ns, "dnsPodLabels": dns_labels, "dnsCIDRs": dns_cidrs},
    }
    operador = {
        "enabled": True, "clusterDomain": dominio, "namespaces": alvos_sdk,
        "gateway": {"sourceRelease": CORE, "sourceNamespace": NAMESPACE,
                    "endpoint": f"https://{CORE}-gateway.{NAMESPACE}.svc.{dominio}:4318"},
        "runtimes": {**{k: sdk[k] for k in ("java", "nodejs", "nodejs20", "python")},
                     "legacyNode20Approved": sdk["excecao_eol_nodejs20_aprovada"]},
        "samplingRatio": sdk["amostragem_traces"],
        "networkPolicy": {"enabled": True, "apiServerCIDRs": origem_webhook},
    }
    return alvo, core, operador


def extrair(pacote, destino):
    raw = ler_limite(pacote, 600_000)
    exigir(sha(raw) == ARCHIVE_SHA, "SHA-256 diferente do asset oficial v1.0.0. Não extraí nem executei o pacote.")
    total, vistos = 0, set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        for membro in tar:
            nome = PurePosixPath(membro.name)
            exigir(bool(nome.parts) and nome.parts[0] == ARCHIVE_ROOT and ".." not in nome.parts
                   and nome not in vistos and (membro.isdir() or membro.isfile()), "Entrada de pacote não autorizada.")
            vistos.add(nome)
            caminho = destino.joinpath(*nome.parts)
            if membro.isdir():
                caminho.mkdir(parents=True, exist_ok=True, mode=0o700)
            else:
                total += membro.size
                exigir(total <= 30_000_000, "Pacote descompactado excede o limite.")
                caminho.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with tar.extractfile(membro) as entrada, caminho.open("xb") as saida:
                    shutil.copyfileobj(entrada, saida)
    return destino / ARCHIVE_ROOT


def ambiente():
    # Sem override implícito de credencial, driver, contexto ou binário Helm.
    return {k: v for k, v in os.environ.items()
            if not k.startswith(("ELVEN_", "HELM_KUBE", "PYTHON"))
            and k not in {"KUBECONFIG", "HELM_DRIVER", "HELM_NAMESPACE", "HELM_DEBUG"}}


def executar(args, etapa, env, timeout=180, fds=()):
    try:
        res = subprocess.run(args, env=env, stdin=subprocess.DEVNULL, capture_output=True,
                             timeout=timeout, pass_fds=fds, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Refusa(f"{etapa}: falhou ou expirou; saídas internas omitidas.") from None
    exigir(res.returncode == 0, f"{etapa}: saída {res.returncode}; saídas internas omitidas.")
    return res.stdout


def conferir_openssl(env):
    versao = executar(["openssl", "version"], "Versão do OpenSSL", env).decode("ascii", errors="replace").strip()
    exigir(re.fullmatch(r"OpenSSL 3\.[0-9]+\.[0-9]+(?:\S+)?(?: .*)?", versao) is not None,
           "Use OpenSSL 3.x no PATH deste terminal, não LibreSSL. Nenhum recurso Kubernetes foi escrito.")


def kube(alvo, env, args, etapa):
    return executar(["kubectl", "--kubeconfig", alvo["kubeconfig"], "--context", alvo["contexto"],
                     "--request-timeout=20s", *args], etapa, env, timeout=30)


def conferir_alvo(alvo, env, namespaces):
    raw = kube(alvo, env, ["config", "view", "--minify", "-o", "json"], "Verificação TLS do kubeconfig")
    clusters = json.loads(raw)["clusters"]
    exigir(len(clusters) == 1, "Não foi possível identificar um único endpoint Kubernetes.")
    cluster = clusters[0]["cluster"]
    endereco = urlsplit(cluster["server"])
    exigir(endereco.scheme == "https" and endereco.hostname and endereco.username is None
           and endereco.password is None and not cluster.get("insecure-skip-tls-verify"),
           "Kubeconfig exige HTTPS com validação TLS do apiserver.")
    raw = kube(alvo, env, ["get", "namespace", "kube-system", "-o", "json"], "Leitura da identidade do cluster")
    exigir(json.loads(raw)["metadata"]["uid"] == alvo["uid_cluster"], "UID não confere; nada foi escrito.")
    for nome in namespaces:
        kube(alvo, env, ["get", "namespace", nome, "-o", "name"], f"Namespace aprovado {nome}")


def identidade_secret(alvo, env):
    raw = kube(alvo, env, ["get", "namespace", NAMESPACE, "--ignore-not-found", "-o", "name"], "Leitura do namespace Elven")
    if not raw.strip():
        return None
    raw = kube(alvo, env, ["-n", NAMESPACE, "get", "secret", INGEST_SECRET, "--ignore-not-found", "-o", "json"],
               "Leitura do Secret de ingestão (sem exibir dados)")
    if not raw.strip():
        return None
    obj = json.loads(raw)
    md = obj["metadata"]
    esperadas = {"app.kubernetes.io/managed-by": "elven-cli", "app.kubernetes.io/instance": CORE,
                 "app.kubernetes.io/part-of": "elven-observability", "elven.observability/namespace": NAMESPACE}
    exigir(obj.get("type") == "Opaque" and md.get("name") == INGEST_SECRET and md.get("namespace") == NAMESPACE
           and all(md.get("labels", {}).get(k) == v for k, v in esperadas.items()),
           "Secret existente não é do bootstrap deste kit; não vou adotar nem sobrescrever.")
    exigir(base64.b64decode(obj["data"]["tenant-id"], validate=True) == alvo["tenant_id"].encode(),
           "O tenant configurado não corresponde ao Secret existente; preserve a fila e investigue.")
    exigir(bool(base64.b64decode(obj["data"]["api-token"], validate=True)), "Secret existente sem token utilizável.")
    exigir(bool(md["uid"]) and bool(md["resourceVersion"]), "Identidade do Secret incompleta.")
    return md["uid"], md["resourceVersion"]


def pedir_token():
    try:
        fd = os.open("/dev/tty", os.O_RDONLY | os.O_NOCTTY)
        try:
            exigir(os.isatty(fd), "Bootstrap inicial exige um terminal privado com eco desativável.")
        finally:
            os.close(fd)
        with warnings.catch_warnings():
            warnings.simplefilter("error", GetPassWarning)
            token = getpass("Token de ingestão Elven (sem eco): ")
    except (OSError, EOFError, GetPassWarning):
        raise Refusa("Não há terminal seguro; recusado o fallback com eco ou leitura por pipe.") from None
    exigir(re.fullmatch(r"[!-~]{1,16384}", token) is not None,
           "Token vazio ou inválido. Informe só o token, sem Bearer, espaços ou quebra de linha.")
    return token.encode()


@contextmanager
def credenciais(folder, tenant, token):
    arquivos = (("tenant", tenant.encode()), ("token", token))
    if sys.platform.startswith("linux") and hasattr(os, "memfd_create") and Path("/proc/self/fd").is_dir():
        fds = []
        try:
            for nome, raw in arquivos:
                fd = os.memfd_create("elven-" + nome, os.MFD_CLOEXEC)
                fds.append(fd)
                os.fchmod(fd, 0o600)
                with os.fdopen(os.dup(fd), "wb") as stream:
                    stream.write(raw)
                os.lseek(fd, 0, os.SEEK_SET)
            yield [f"/proc/self/fd/{fd}" for fd in fds], tuple(fds)
        finally:
            for fd in fds:
                os.close(fd)
    else:
        with tempfile.TemporaryDirectory(prefix="credenciais-", dir=folder) as priv:
            caminhos = [str(Path(priv) / nome) for nome, _ in arquivos]
            for caminho, (_, raw) in zip(caminhos, arquivos):
                escrever(caminho, raw)
            yield caminhos, ()


def preparar(root, tmp, raw, alvo, core, operador, env):
    core_path = tmp / "core.values.json"
    sdk_path = tmp / "instrumentation.values.json"
    escrever(core_path, json_bytes(core))
    escrever(sdk_path, json_bytes(operador))
    cli = [sys.executable, "-I", str(root / "elven")]
    sdk = [sys.executable, "-I", str(root / "scripts/instrumentation.py")]
    base = ["--namespace", NAMESPACE, "--release", CORE, "--cluster-name", alvo["nome_cluster"], "--values", str(core_path)]
    online = ["--kubeconfig", alvo["kubeconfig"], "--context", alvo["contexto"], "--expect-cluster-uid", alvo["uid_cluster"]]
    arquivos = {
        core_path.name: core_path.read_bytes(), sdk_path.name: sdk_path.read_bytes(),
        "core.render.yaml": executar([*cli, "render", *base], "Render offline do core", env),
        "instrumentation.render.yaml": executar([*sdk, "render", "--namespace", NAMESPACE, "--release", OPERATOR,
                                              "--values", str(sdk_path)], "Render offline do Operator", env),
    }
    recibo = json_bytes({"release": VERSION, "assetSha256": ARCHIVE_SHA, "clienteTomlSha256": sha(raw),
                         "arquivos": {k: sha(v) for k, v in arquivos.items()}})
    return arquivos, recibo, cli, base, online, sdk_path


def conferir_revisao(revisao, arquivos, recibo):
    exigir(not revisao.is_symlink(), "A pasta da revisão não pode ser um link simbólico.")
    for nome, conteudo in {**arquivos, "revisao.json": recibo}.items():
        exigir(ler_limite(revisao / nome, 4_000_000) == conteudo,
               "A revisão não coincide com o pacote e configuração efetivos; preserve a anterior e revise um plano novo.")


def gravar_revisao(revisao, arquivos, recibo):
    revisao.mkdir(mode=0o700, exist_ok=False)
    for nome, conteudo in {**arquivos, "revisao.json": recibo}.items():
        escrever(revisao / nome, conteudo)


def confirmar_plano(alvo, core, operador, revisao):
    print(f"\nCluster: {alvo['nome_cluster']}\nContexto: {alvo['contexto']}\nUID: {alvo['uid_cluster']}")
    print(f"Tenant: {alvo['tenant_id']}\nNamespace da instalação: {NAMESPACE}")
    print("Namespaces autorizados: " + ", ".join(core["collection"]["namespaces"]))
    print("Logs stdout: " + ("habilitados com acesso ao host aprovado" if core["modules"]["logs"]["enabled"] else "desativados"))
    print("Métricas de estado Kubernetes: " + ("habilitadas" if core["modules"]["clusterMetrics"]["enabled"] else "desativadas"))
    print("Runtimes: " + ", ".join(k for k in ("java", "nodejs", "nodejs20", "python") if operador["runtimes"][k]))
    print(f"Revise os values e manifests em: {revisao.resolve()}")
    print("Nenhum recurso Kubernetes foi escrito. A instalação não reinicia aplicações.", flush=True)
    esperado = "INSTALAR " + alvo["nome_cluster"]
    try:
        with (open("/dev/tty", "r", encoding="utf-8") as entrada,
              open("/dev/tty", "w", encoding="utf-8") as saida):
            exigir(entrada.isatty() and saida.isatty(),
                   "A aprovação exige um terminal privado, sem confirmação por pipe.")
            saida.write(f"Após revisar o plano, digite {esperado} para continuar: ")
            saida.flush()
            resposta = entrada.readline(1024).rstrip("\r\n")
    except (OSError, EOFError):
        raise Refusa("Sem terminal para aprovar o plano. Nada foi instalado; execute em um terminal privado.") from None
    exigir(resposta == esperado, "Instalação não aprovada. Nenhum token foi solicitado nem recurso Kubernetes escrito.")


def aprovar_revisao(alvo, core, operador, revisao, recibo):
    path = revisao / "aprovacao.json"
    aprovado = json_bytes({"revisaoSha256": sha(recibo), "uidCluster": alvo["uid_cluster"],
                           "contexto": alvo["contexto"]})
    if os.path.lexists(path):
        exigir(ler_limite(path, 4096) == aprovado, "A aprovação não corresponde à revisão. Preserve os arquivos e revise o estado.")
    else:
        confirmar_plano(alvo, core, operador, revisao)
        escrever(path, aprovado)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("acao", choices=("plano", "instalar", "guiado"))
    parser.add_argument("--pacote", type=Path, default=Path(ARCHIVE_NAME))
    parser.add_argument("--config", type=Path, default=Path("cliente.toml"))
    parser.add_argument("--revisao", type=Path, default=Path("revisao-v1.0.0"))
    args = parser.parse_args()
    env = ambiente()
    exigir(args.config.is_file(),
           "Preencha plataforma/cliente.toml a partir de cliente.exemplo.toml. Não coloque o token no arquivo.")
    for programa in ("kubectl", "helm", "openssl"):
        exigir(shutil.which(programa) is not None, f"Ferramenta ausente no PATH confiável: {programa}.")
    conferir_openssl(env)
    raw = ler_limite(args.config, 65536)
    alvo, core, operador = perfis(raw)
    garantir_pacote(args.pacote)
    with tempfile.TemporaryDirectory(prefix="elven-onboarding-") as trabalho:
        tmp = Path(trabalho)
        root = extrair(args.pacote, tmp)
        arquivos, recibo, cli, base, online, sdk_path = preparar(root, tmp, raw, alvo, core, operador, env)
        if args.acao == "instalar" or (args.acao == "guiado" and os.path.lexists(args.revisao)):
            conferir_revisao(args.revisao, arquivos, recibo)
        conferir_alvo(alvo, env, core["collection"]["namespaces"])
        executar([*cli, "preflight", *base, *online], "Preflight do core: versão, RBAC, StorageClass, ownership e imagens", env, timeout=None)
        anterior = identidade_secret(alvo, env)
        if args.acao == "plano":
            gravar_revisao(args.revisao, arquivos, recibo)
            print("Plano gerado; revise os quatro arquivos de values/render. Nenhum recurso Kubernetes foi escrito.")
            print("O preflight online completo do Operator ocorre depois que o gateway existe.")
            return
        if args.acao == "guiado":
            if not os.path.lexists(args.revisao):
                gravar_revisao(args.revisao, arquivos, recibo)
            aprovar_revisao(alvo, core, operador, args.revisao, recibo)
        print(f"Alvo conferido: {alvo['contexto']} / {NAMESPACE}; pacote v{VERSION}.", flush=True)
        if anterior is None:
            token = pedir_token()
        else:
            print("Secret da própria release e tenant confirmados; reutilizando sem pedir token.", flush=True)
            token = None
        conferir_alvo(alvo, env, [])
        exigir(identidade_secret(alvo, env) == anterior, "O Secret mudou durante a revisão; não prossiga com concorrência.")
        comando = [*cli, "install", *base, *online, "--instrumentation-release", OPERATOR,
                   "--instrumentation-values", str(sdk_path), "--timeout", "15m"]
        print("Reconciliando core e Operator. Aguarde; não execute outra instalação em paralelo.", flush=True)
        etapa = "Instalação: se falhar, confira estado parcial/indeterminado; nada será apagado pelo bootstrap"
        if token is None:
            executar(comando, etapa, env, timeout=None)
        else:
            with credenciais(tmp, alvo["tenant_id"], token) as (caminhos, fds):
                executar([*comando, "--tenant-file", caminhos[0], "--token-file", caminhos[1]], etapa, env, timeout=None, fds=fds)
        conferir_alvo(alvo, env, [])
        atual = identidade_secret(alvo, env)
        exigir(atual is not None and (anterior is None or atual == anterior),
               "Identidade pós-instalação mudou ou não foi confirmada; não amplie o rollout.")
        print("Core e Operator reconciliados; Secret confirmado. Nenhum workload do cliente recebeu rollout pelo bootstrap.")
        print("Ainda não é aceite de entrega: confirme o canary e os sinais no tenant, conforme o roteiro.")


if __name__ == "__main__":
    try:
        main()
    except Refusa as exc:
        print(f"Elven: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("Elven: interrompido. Se a instalação iniciou, inspecione estado parcial antes de repetir.", file=sys.stderr)
        sys.exit(130)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError):
        print("Elven: arquivo/API/resposta inválida ou acesso negado. Saídas e dados internos omitidos.", file=sys.stderr)
        sys.exit(1)
