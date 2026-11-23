# POC de uma aplicação: caminho disponível hoje

Use o [kit imutável v1.0.1](https://github.com/elven-observability/stack-observability-k8s/releases/download/v1.0.1/elven-instalacao-v1.0.1.zip)
com seu checksum, ou o bundle técnico abaixo. Não é necessário modo de
desenvolvimento. Esta receita é para **um serviço sintético Java 17/21**,
sem Redis, dados reais, eBPF ou acesso de host. Não é um aceite de cliente.
MCP/engine e o adaptador novo têm qualificação separada da release publicada.

## Identidade dos artefatos

Bundle: `elven-observability-v1.0.1.tar.gz`, SHA-256
`fdd3dfb6fe621a5c69b6f8a79dc6f4601c6e764b524b66c00681deb56da352db`.

Imagens usadas nesta receita (índices amd64/arm64):

| Componente | Referência imutável |
| --- | --- |
| Collector | `docker.io/elvenobservability/elven-collector@sha256:d6cb61db477227ed6b6bb673a43ba87dd2c893a61c6eb3febfeda3476ae398e4` |
| Operator | `docker.io/elvenobservability/elven-instrumentation-operator@sha256:02bbd134aeb266b847acdcbce101b87f939d1dcfc0504644e658ad7ec169d9fb` |
| SDK Java | `docker.io/elvenobservability/elven-auto-java@sha256:d12eb4f89103253645a387728a882a6834b5a7f2016bd3809ab4987cff2be87d` |

Assinaturas, predicados e fonte de build estão nos dois locks promovidos.
Verifique as identidades exatas dos workflows `images.yaml` e
`instrumentation.yaml` na tag `v1.0.1`, emissor GitHub Actions, conforme
[cadeia de fornecimento](supply-chain.md#assinatura-identidade-e-promoção).
O instalador compara os locks, mas isso não substitui a verificação Cosign.

## Preparar e instalar

Pré-requisitos: Kubernetes 1.35–1.37 autorizado, contexto e UID de
`kube-system` conferidos, Linux amd64/arm64, Python 3.11+, OpenSSL,
kubectl compatível, Helm 4.3.1+ ou 3.22.1+, capacidade de Pod/CPU/memória,
StorageClass e PVC de 2 GiB, DNS/egress HTTPS e CNI aplicando NetworkPolicy.
Escolha um namespace de aplicação exclusivo, sem outro injector ou SDK.
Confirme que a imagem da aplicação não embute agentes/loader flags.

Em uma pasta nova, baixe somente o asset oficial, confira o hash e extraia:

```sh
curl --fail --show-error --location --proto '=https' --proto-redir '=https' \
  https://github.com/elven-observability/stack-observability-k8s/releases/download/v1.0.1/elven-observability-v1.0.1.tar.gz \
  --output elven-observability-v1.0.1.tar.gz
echo 'fdd3dfb6fe621a5c69b6f8a79dc6f4601c6e764b524b66c00681deb56da352db  elven-observability-v1.0.1.tar.gz' | shasum -a 256 -c - &&
  tar -xzf elven-observability-v1.0.1.tar.gz &&
  cd elven-observability-v1.0.1
```

Prepare dois arquivos privados de configuração a partir de
`examples/minimal.yaml` e `examples/instrumentation.yaml`. No gateway,
preencha StorageClass, `collection.namespaces` com **um** namespace e
`networkPolicy.exportCIDRs` com os IPs/CIDRs efetivos aprovados do SaaS.
Mantenha todos os módulos de host desligados. No Operator, escolha esse
mesmo namespace, `runtimes.java: true`, os outros runtimes `false` e
`networkPolicy.apiServerCIDRs` com as origens reais vistas pelo CNI.
Mantenha o endpoint mTLS e os nomes próprios padrões.

Defina as variáveis abaixo localmente. Os caminhos de tenant/token apontam
para arquivos 0600/0400 fora do Git; não coloque seus valores em argumentos,
values, planos ou chat. Para token solicitado sem eco, prefira `./instalar`
do ZIP, conforme o [guia do kit](../kit/plataforma/PREPARAR.md).

```sh
ELVEN_CONTEXT='CONTEXTO_APROVADO'
ELVEN_CLUSTER_UID='UID_CONFERIDO_DE_KUBE_SYSTEM'
ELVEN_CLUSTER_NAME='NOME_LOGICO_APROVADO'
ELVEN_VALUES='/caminho/privado/gateway.yaml'
ELVEN_INSTRUMENTATION_VALUES='/caminho/privado/instrumentation.yaml'
ELVEN_TENANT_FILE='/caminho/privado/tenant'
ELVEN_TOKEN_FILE='/caminho/privado/token'

./elven preflight --context "$ELVEN_CONTEXT" \
  --expect-cluster-uid "$ELVEN_CLUSTER_UID" --cluster-name "$ELVEN_CLUSTER_NAME" \
  --values "$ELVEN_VALUES"

# Somente depois da revisão e aprovação do plano:
./elven install --context "$ELVEN_CONTEXT" \
  --expect-cluster-uid "$ELVEN_CLUSTER_UID" --cluster-name "$ELVEN_CLUSTER_NAME" \
  --values "$ELVEN_VALUES" --instrumentation-values "$ELVEN_INSTRUMENTATION_VALUES" \
  --tenant-file "$ELVEN_TENANT_FILE" --token-file "$ELVEN_TOKEN_FILE"
```

Não prosseguir se o preflight ou install falhar. A instalação não altera a
aplicação. Seu dono revisa e aplica somente este opt-in no Pod template do
Deployment piloto, pelo fluxo normal autorizado de rollout:

```yaml
spec:
  template:
    metadata:
      labels:
        elven.observability/inject: java
      annotations:
        elven.observability/container-name: NOME_REAL_DO_CONTAINER
```

Não aplicar esse trecho como objeto completo nem reiniciar namespaces.
Preserve previamente o template exato e os UIDs/RVs; confirme os digests
injetados nos Pods novos e o namespace aprovado. Código/GitOps de terceiros
segue exclusivamente em PR, sem aplicação por esta receita.

## Estado, entrega e rollback

`./elven status --context "$ELVEN_CONTEXT"` e
`python3 scripts/instrumentation.py status --context "$ELVEN_CONTEXT"`
leem recursos próprios. Ready não comprova entrega. Gere requests sintéticos
com identificador único e procure trace/log/métrica no tenant correto,
conferindo erros de exportação, filas, identidade e PII suportada removida.
O suporte de logs/métricas depende do SDK/biblioteca: não declarar três sinais
da aplicação a partir de self-metrics ou de um probe independente.

Para desfazer a instrumentação, o dono restaura **somente** o opt-in ao
baseline revisado e faz rollout autorizado. Não restaure um objeto antigo
inteiro sobre alterações concorrentes; valide UID/RV/template atual.
Pods antigos continuam instrumentados até serem substituídos. Preserve os
Secrets mTLS enquanto houver consumidores. Para remover uma primeira
instalação isolada, após retirar os consumidores e conferir/drenar filas:

```sh
python3 scripts/instrumentation.py uninstall --context "$ELVEN_CONTEXT" \
  --expect-cluster-uid "$ELVEN_CLUSTER_UID"
./elven uninstall --context "$ELVEN_CONTEXT" \
  --expect-cluster-uid "$ELVEN_CLUSTER_UID"
```

Esses comandos retêm Secrets/namespaces/PVC. Para uma instalação já existente,
use revisões Helm realmente observadas e compatíveis, não uninstall;
veja [rollback](operations.md#atualização-e-rollback). Helm/app não formam
transação; resultado desconhecido exige leitura, não replay automático.

## O que ainda não está entregue na v1.0.1

Correções novas de Redis e testes ampliados de exceções estão na fonte do
processor, **não nesse digest**. Exigem novo Collector construído, escaneado,
testado, assinado e promovido, incluindo privacidade antes da WAL e entrega.
Não usar Redis ou payloads sensíveis para anunciar o conserto na POC atual.
O [contrato novo](template-engine-contract.md) materializa planos; a engine
é responsável por OAuth, aprovação, state, execução CAS e aceite runtime.
