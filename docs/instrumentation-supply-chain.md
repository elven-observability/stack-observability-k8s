# Cadeia de fornecimento da auto-instrumentação opt-in

Este módulo possui lock, imagens, assinatura e promoção próprios. Não altera o conjunto de três imagens da coleta principal. O Operator Elven é um admission webhook Go sem CRDs, acesso à API Kubernetes ou SDK Kubernetes; não é apresentado como o binário do OpenTelemetry Operator. Os SDKs são payloads oficiais OpenTelemetry preservados em wrappers Elven.

## Pins verificados em 03/11/2026

Todos os digests completos estão em [`instrumentation.lock.json`](../instrumentation.lock.json), incluindo os manifests Linux amd64/arm64 consultados no registry. Nenhuma tag `latest` é utilizada.

| Componente | Upstream selecionado | Limite importante |
|---|---|---|
| Operator Elven | Go 1.27.3 pinado por digest; runtime scratch | Binário próprio, API de admission apenas; sem controllers/CRDs/RBAC de runtime. |
| Java | Agent 2.33.1, imagem 2.33.1-2, SDK 1.67.0 | Java 17/21; Java SDK não equivale a todos os métodos de negócio instrumentados. |
| Node.js atual | Auto-instrumentação 0.82.0-3, SDK 3.x | Exige Node.js ≥22.15.0; mudanças de convenções HTTP/network/database em relação às linhas anteriores. |
| Node.js 20 legado | Auto-instrumentação 0.81.2-1, SDK 2.x | Imagem Elven distinta e aprovação explícita; Node.js 20 está EOL desde 30/04/2026. Compatibilidade não é suporte upstream da runtime. |
| Python opcional | Auto-instrumentação 0.66b2-2, SDK 1.45.2 | Auto-instrumentação **beta**; selecionar libc correta e validar a runtime/aplicação efetivamente utilizada. |

Fontes: [Java](https://github.com/open-telemetry/opentelemetry-java-instrumentation/releases/tag/v2.33.1), [Node atual](https://github.com/open-telemetry/opentelemetry-js-contrib/releases/tag/auto-instrumentations-node-v0.82.0), [Node legado](https://github.com/open-telemetry/opentelemetry-js-contrib/releases/tag/auto-instrumentations-node-v0.81.2), [Python](https://github.com/open-telemetry/opentelemetry-python-contrib/releases/tag/v0.66b2), [ciclo Node](https://github.com/nodejs/Release/blob/main/schedule.json).

As imagens públicas Elven antigas não são substituídas por suposição: a inspeção encontrou tags `latest` desatualizadas, Node amd64-only e versões locais diferentes das imagens publicadas. Este módulo constrói novos wrappers a partir dos pins oficiais, não atribui o código local aos artefatos antigos.

## Payload, licenças e orçamento

Os wrappers herdam o filesystem, utilitário `cp`, entrypoint e licenças upstream; não executam instalação de pacotes no startup. Java mantém `/javaagent.jar`; Node mantém `/autoinstrumentation`; Python mantém `/autoinstrumentation` e `/autoinstrumentation-musl`. A identificação Elven não transfere autoria ou remove licenças dos projetos de origem. A licença Apache-2.0 e NOTICE Elven são adicionados sem substituir os avisos herdados; SPDX e proveniência são gerados por arquitetura.

A cópia real foi medida nas duas arquiteturas, em container com rootfs read-only, UID 10001, rede desativada, capabilities removidas e tmpfs descartável. Java ocupou 25,28 MiB; Node atual 66,82 MiB; Node 20 legado 75,06 MiB; Python até 23,75 MiB por libc selecionada. O volume padrão de 128 MiB comporta esses artefatos exatos, com pelo menos 52,94 MiB restantes. Isso não autoriza manter o orçamento sem medir uma futura atualização. A execução da ferramenta de cópia amd64 em host arm64 não é prova de execução nativa da aplicação amd64. [Recibo de footprint](../images/autoinstrumentation/payload-sizes-2026-11-03.json).

## Build, scans e publicação

Ferramentas de release: Buildx 0.38.1, BuildKit 0.34.2, Trivy 0.76.1, Cosign 3.1.4 e Crane 0.22.1. BuildKit 0.34.2 é um patch de segurança publicado em 03/11/2026; seu digest está no lock. [Release oficial](https://github.com/moby/buildkit/releases/tag/v0.34.2). Os builds locais desta revisão utilizaram o Buildx instalado 0.37.1 e o daemon BuildKit 0.34.2 pinado; o CI instala o cliente 0.38.1 pinado. Não confundir ferramenta local com a versão exigida pelo pipeline de release.

```bash
python3 scripts/images-instrumentation.py check
docker buildx create --name elven-instrumentation-build --driver docker-container --driver-opt image=docker.io/moby/buildkit:v0.34.2@sha256:c5f8862f52499773af85bc07695b2379ef08e8002352b0df2c4864c91d78dabe --bootstrap
BUILDX_BUILDER=elven-instrumentation-build python3 scripts/images-instrumentation.py build --platform linux/amd64,linux/arm64
python3 scripts/images-instrumentation.py scan
python3 scripts/validate-instrumentation.py
python3 scripts/test-instrumentation-kind.py --images-manifest artifacts/instrumentation/instrumentation-release.json --development-images
```

O comando de criação é para um builder dedicado novo e não altera o default global. Se esse nome já existir, confirme sua propriedade antes de reutilizá-lo. Não faça prune global para liberar espaço: preserve os archives/evidências e limpe somente o builder descartável criado para essa execução.

O build registra SHA-256 de todos os inputs do SDK e do Operator, incluindo testes e lock, antes/depois da execução; adição, remoção ou alteração de arquivo invalida a evidência. `SOURCE_DATE_EPOCH` vem do commit. O Operator é compilado com testes Go no Dockerfile. Arquivos/variáveis de cliente, kubeconfigs e credenciais não pertencem ao contexto deny-all dos Dockerfiles. Fonte local suja e builds `-dev` são evidência de laboratório, nunca publicação aprovada.

O [workflow independente](../.github/workflows/instrumentation.yaml) constrói as cinco imagens multiarch, valida os arquivos OCI após limpar **somente** o builder descartável da execução, escaneia todas as severidades e bloqueia qualquer High/Critical. Não há ignorelist ou exclusão do Java JAR. A primeira tentativa local expirou no download inicial do JavaDB; o retry completo usou timeout explícito de 30 minutos e passou. O pipeline também exige contratos, Helm/schema e teste Kind nativo amd64 usando os archives escaneados exatos; não reconstrói binários depois do scan.

Os dez scans finais de 03/11 passaram com 0 High/Critical, DB atual. Node atual e Node 20 legado mantêm dois Medium por arquitetura: **CVE-2026-118773** (`glob` 10.5.0) e **CVE-2026-118764** (`minimatch` 9.0.9). Não foram ocultados ou substituídos silenciosamente por overrides npm. Operator, Java e Python não tiveram achados reportados pelo scanner nessa execução; isso não prova ausência de vulnerabilidades desconhecidas. [Recibo completo](../images/autoinstrumentation/validation-2026-11-03.json).

Publicação requer tag estável protegida `v1.x.y`, Environment com required reviewers e credenciais Docker Hub de escrita somente nos cinco repositórios Elven. Antes do primeiro push, todas as tags remotas são consultadas: digest conflitante ou lookup inconclusivo bloqueia o conjunto; mesmo digest é idempotente. Esse preflight não é CAS contra escritores externos: imutabilidade de tags também precisa ser aplicada no registry. Os consumers devem conseguir pull anônimo, sem PAT ou `imagePullSecret` de registry.

Imagem, SPDX e metadados de build recebem assinatura GitHub OIDC. Verificação exige issuer `https://token.actions.githubusercontent.com` e identidade exata `https://github.com/elven-observability/stack-observability-k8s/.github/workflows/instrumentation.yaml@refs/tags/v1.x.y`, nunca qualquer repositório/workflow. `promote` gera somente `artifacts/instrumentation/instrumentation.promoted.lock.json` para revisão; não altera automaticamente lock, chart ou workloads.

Além da verificação criptográfica, os dois SPDX assinados e os metadados devem corresponder aos hashes semânticos da evidência aprovada. Essa política fica persistida no lock promovido, com subject digest e tipos exatos; `verify` posterior não depende do diretório local de build. Ver o [formato de verificação e o pacote instalável pós-promoção](supply-chain.md#fonte-de-build-versus-pacote-instalável). O comando combinado `./elven install --instrumentation-values ...` continua exigindo os dois locks verificados; não acrescenta `--development-images` implicitamente.

**Estado da release 1.0.0:** os cinco componentes foram publicados e assinados; o comando oficial de promoção conferiu novamente ambos SPDX, metadata e labels remotos e gerou o lock promovido usado nesta revisão. Os defaults agora coincidem com esses digests reais. O [registro da release](release-v1.0.0.md) preserva as falhas de revalidação de CI, a promoção completa verificada pelo mantenedor e a verificação pública independente por componente. Instalação normal não requer `--development-images`; isso não habilita runtimes/namespaces implicitamente. Nenhum cluster de cliente foi acessado.

## Privacidade e limites da granularidade

Não habilitar captura indiscriminada de corpos, headers, parâmetros ou resultados. Java mantém a sanitização comum de DB ativada, mas Node/Python podem produzir literais em SQL mesmo com captura de parâmetros desativada. Assim, atributos de query precisam passar pela política sanitizadora Elven antes da exportação/fila; falha de parsing não significa liberar o texto original. Proteção de PII deve preservar conteúdo diagnóstico não sensível, sem prometer que qualquer texto arbitrário é identificável com perfeição. Instrumentação de bibliotecas suportadas não equivale a capturar automaticamente toda função/método da aplicação.
