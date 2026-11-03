# Elven Observability 1.0.0

As oito imagens foram publicadas no namespace público `docker.io/elvenobservability`, assinadas por GitHub OIDC e promovidas nos dois locks e defaults dos charts. A tag de build `v1.0.0` permanece no source `0c41057c3cfae6d3e0887b5c4eecd44cdb9031f3`; a revisão de configuração instalável é posterior e consta no manifest do pacote. Não mover a tag nem usar seu arquivo automático Source code como se contivesse os locks promovidos.

## Referências imutáveis

| Imagem em `docker.io/elvenobservability` | Índice amd64/arm64 |
|---|---|
| `elven-collector:v1.0.0` | `sha256:87f81a2b66be0d0b50ab8c1604843f2cc701d8c74b8c43d2d5d6ca425fe2125e` |
| `elven-ebpf:v1.0.0` | `sha256:be51d39658483814b3739f35a9ef876fc39a7f72892d7cc36daf496dfc77ab7f` |
| `elven-profiler:v1.0.0` | `sha256:6cd5a07c5523dc42bc1abdf5d1de1f35a3f2800fcaee34023bad547cd80bf57d` |
| `elven-instrumentation-operator:v1.0.0` | `sha256:3ec69a046b372dcdba63b84ebc83af42ea231f3f3695eeb6239eb64806ba555a` |
| `elven-auto-java:v1.0.0` | `sha256:ec2574d99213343efe19ab486673590a0f9af7be0a466fee1cd49a28c962066f` |
| `elven-auto-nodejs:v1.0.0` | `sha256:932c4acfec934a8fc0048d4b92b1f8ba880c444612ad2f10462aac7d310aa45d` |
| `elven-auto-nodejs20:v1.0.0` | `sha256:992cd9dff8972a5da40de66996e3dac2b1229918162d7cc6b1ba018e1c8bef04` |
| `elven-auto-python:v1.0.0` | `sha256:9faaadb399238567cea1a941e6d9b2dbb0aaf70a55a9e718c7e6bf641aed6055` |

Cada componente guarda no lock a identidade exata de workflow/tag, a revisão original e os hashes semânticos dos dois SPDX e metadata aprovados. A verificação mantém TLS, CA, identidade OIDC e transparency log; não usa flags inseguras. Os reports preservam Medium/Low/UNKNOWN existentes: zero High/Critical não significa zero vulnerabilidades.

## Evidência e incidente de revalidação

- [Contratos da fonte](https://github.com/elven-observability/stack-observability-k8s/actions/runs/41707769636): 308 testes, Python 3.12/3.14 e schemas Kubernetes.
- [Núcleo, tag original](https://github.com/elven-observability/stack-observability-k8s/actions/runs/41707828398): build multiarch, seis scans sem High/Critical, Govuln/licenças, configurações/profiling, PII15/WAL/cleanup, Core25 amd64 e publicação/promoção verificada.
- [SDKs, tag original](https://github.com/elven-observability/stack-observability-k8s/actions/runs/41707828308): 91 contratos, 13 testes de atestação, fixtures TLS, dez scans e SDK20 amd64 passaram. A primeira publicação escreveu os cinco componentes e o manifest global como `verified`; a revalidação posterior de promoção falhou em `cosign verify-attestation`. A tentativa 2 falhou em leitura `crane digest`, com os mesmos bytes/policies. Essas execuções falhas não são declaradas verdes.
- O comando oficial `images-instrumentation.py promote` foi então executado pelo mantenedor com Cosign 3.1.4, sem credenciais de registry para as verificações públicas, e concluiu para os cinco SDKs, conferindo assinaturas, ambos SPDX, metadata e labels nas duas arquiteturas. Nenhum campo `verified` foi inventado para contornar os checks.
- Uma checagem repetida posterior registrou `registry_rate_limit` no Docker Hub anônimo. O stderr original das falhas de CI não foi preservado, portanto sua causa específica permanece UNKNOWN; o limite observado agora não é apresentado como diagnóstico retroativo certo.
- O [workflow independente](../.github/workflows/verify-published.yaml) verifica as oito imagens separadamente, sem secrets ou permissão de escrita, e mantém os checks criptográficos. Seu resultado e a prova do comando único sem dev devem ser conferidos nos checks da [PR de release](https://github.com/elven-observability/stack-observability-k8s/pull/4) e nos artefatos anexados à release.

O ZIP técnico da primeira tentativa foi preservado com SHA-256 `b70bbc6f11f8ee62b7ac7de36325b1d71c3f764715bd3b4d40098fd1dde029df` antes de liberar somente seu nome de artifact para a segunda tentativa; imagens, tags e fontes não foram removidas ou sobrescritas.

## Instalação em uma chamada

Baixe o asset `elven-observability-v1.0.0.tar.gz`, confira SHA256SUMS e revise os dois perfis e arquivos privados. Dentro do pacote:

```bash
./elven install --context "$ELVEN_CONTEXT" \
  --expect-cluster-uid "$ELVEN_CLUSTER_UID" --cluster-name "$ELVEN_CLUSTER_NAME" \
  --values "$ELVEN_VALUES" --instrumentation-values "$ELVEN_INSTRUMENTATION_VALUES" \
  --tenant-file "$ELVEN_TENANT_FILE" --token-file "$ELVEN_TOKEN_FILE"
```

Não há flag de desenvolvimento. O comando valida e reconcilia núcleo + Operator, provisiona PKI/Secrets próprios e protege o recibo do PVC; falha da segunda fase retorna estado parcial e preserva dados. Não seleciona/reinicia aplicações nem habilita módulos de host por conta própria. Contexto/UID, CIDRs, namespaces, storage e runtimes precisam de revisão real: não há perfil universal seguro contendo apenas tenant/token.

O ensaio usa Kind descartável, endpoints/credenciais sintéticos e archives OCI exatos pré-carregados. Não demonstra pulls ilimitados em NAT de cliente, CNI/CSI efetivos, captura eBPF por kernel, tenant real, escala ou HA. O pacote não contém PAT de publicação, kubeconfig ou dados de clientes. Node20 é exceção EOL; Python é beta opcional. SDKs não instrumentam todo método/statement, e PII básica não é detecção universal.
