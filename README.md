# Elven Observability Distribution

Distribuição Kubernetes da Elven para receber e coletar telemetria com componentes próprios, isolamento por release e segurança por padrão. O caminho atual usa a CLI `./elven` e o chart `charts/elven-observability`.

Não requer o gateway, Prometheus, Alloy ou Operator do cliente. Não instala CRDs, webhooks, cert-manager ou SDKs nas aplicações. O baseline é um gateway OTLP com mTLS, exportação HTTPS autenticada e filas persistentes. Logs de containers, métricas Kubernetes/kubelet, eBPF e profiles são módulos explícitos, não uma coleta global implícita.

**Candidato da linha 1.0 — instalação de produção bloqueada até publicação, assinatura e promoção verificadas das imagens Elven.** O lock desta revisão está `not-published`; a CLI recusa `preflight`, `install` e `upgrade` de produção nesse estado e também recusa imagens que não coincidam com repository/digest promovidos. Não há fallback automático para a imagem contrib completa: seu scan identificou uma dependência High e motivou o Collector Elven mínimo corrigido. Ver [supply chain](docs/supply-chain.md).

Configuração renderizada, reconciliação Helm, scan/build local, testes em laboratório e aceitação no cliente são evidências diferentes. Conferir o [relatório de validação e artefatos](docs/validation-2026-10-29.md) e [suporte/gates de release](docs/support.md). Um artefato OCI local não é uma imagem publicada/assinada para produção.

## Instalação mínima após promoção da release

Este é o caminho de produção **depois** que o mantenedor concluir publicação/assinatura/verificação/promoção do lock e dos defaults do chart. Na revisão candidata atual, interromper no render offline ou usar somente o ensaio isolado descrito abaixo; não contornar o gate para instalar em cliente.

Pré-requisitos: Python 3.11+, `kubectl` compatível com o cluster, Helm 4.3.1+ (preferido) ou 3.22.1+ para compatibilidade, OpenSSL para gerar/verificar PKI e Kubernetes 1.35–1.37. É necessário StorageClass selecionado/default para o PVC do gateway, autorização de instalação e liberação dos destinos HTTPS. Não é necessário Helmfile, pip, Prometheus ou Operator do cliente.

1. Confirme contexto e UID do cluster; não use o contexto ativo implicitamente:

```bash
kubectl config get-contexts
kubectl --context "CONTEXTO_CONFIRMADO" get namespace kube-system -o jsonpath='{.metadata.uid}'
./elven version
```

2. Copie [`examples/minimal.yaml`](examples/minimal.yaml) para um arquivo local privado e revise os CIDRs reais de `networkPolicy.exportCIDRs`, a identidade lógica do cluster e o storage. O exemplo vem com egress fechado: isso é um bloqueio seguro, não uma instalação pronta para ignorar a rede. Os nomes em maiúsculas e os caminhos `/caminho/privado/...` abaixo são placeholders e devem ser substituídos.

```bash
ELVEN_CONTEXT="CONTEXTO_CONFIRMADO"
ELVEN_CLUSTER_NAME="NOME_REAL_DO_CLUSTER"
ELVEN_CLUSTER_UID="UID_CONFERIDO_NO_COMANDO_ANTERIOR"
ELVEN_VALUES="/caminho/privado/elven/customer.yaml"
```

Prepare tenant e token em arquivos privados, com permissões 0600 ou 0400, fora do Git. Não coloque o token em values ou como argumento literal. Para usar credenciais/PKI previamente gerenciadas, veja [segurança](docs/security.md).

3. Renderize/revise, faça preflight e instale:

```bash
./elven render --cluster-name "$ELVEN_CLUSTER_NAME" \
  --values "$ELVEN_VALUES" --output elven-reviewed.yaml

./elven preflight --context "$ELVEN_CONTEXT" \
  --cluster-name "$ELVEN_CLUSTER_NAME" --expect-cluster-uid "$ELVEN_CLUSTER_UID" \
  --values "$ELVEN_VALUES"

./elven install --context "$ELVEN_CONTEXT" \
  --cluster-name "$ELVEN_CLUSTER_NAME" --expect-cluster-uid "$ELVEN_CLUSTER_UID" \
  --values "$ELVEN_VALUES" \
  --tenant-file /caminho/privado/elven/tenant \
  --token-file /caminho/privado/elven/token
```

O render é offline e não contém valores de Secrets; o arquivo de saída é privado e não é sobrescrito. Preflight é somente leitura, não faz server-side apply/dry-run nem gera certificados. A instalação valida a identidade, aplica somente recursos próprios, provisiona Secrets separadamente do Helm quando necessário e aguarda a reconciliação da release.

Os defaults são `--release elven` e `--namespace elven-observability`. Para mudá-los, forneça os mesmos parâmetros em todos os comandos. `--values` pode ser repetido; mantenha os arquivos/revisão utilizados como parte do registro de instalação, sem credenciais. Não reaplique uma configuração parcial sem revisar quais valores serão removidos ou voltarão ao padrão.

```bash
./elven status --context "$ELVEN_CONTEXT"
```

`status`, Pods Ready e sucesso do Helm não comprovam recebimento no tenant. Siga os [testes de coleta e entrega](docs/operations.md#aceite-de-coleta-e-entrega).

### Ensaio descartável antes da publicação

`--development-images` é uma exceção explícita somente para laboratório controlado; não é um modo GA, não aprova uma imagem e não ignora os guards de cluster, ownership, configuração, TLS ou rede. Construa o Collector Elven mínimo corrigido e use o artefato OCI/local e os values correspondentes da execução de teste, conforme [supply chain](docs/supply-chain.md). Não use a imagem upstream vulnerável por conveniência, nem substitua digests por `latest`.

Depois de preparar um cluster isolado, seus endpoints sintéticos e o artefato/values corretos:

```bash
./elven preflight --development-images --context "$ELVEN_CONTEXT" \
  --cluster-name "$ELVEN_CLUSTER_NAME" --expect-cluster-uid "$ELVEN_CLUSTER_UID" \
  --values "$ELVEN_VALUES"
```

Para ensaiar a instalação nesse mesmo laboratório, o `install` exige novamente `--development-images` e todos os demais argumentos de identidade/credenciais do exemplo anterior. Não copiar esse override para configurações de cliente, automações ou procedimento de produção.

## Escolha o escopo

| Perfil/módulo | Finalidade |
|---|---|
| [`examples/minimal.yaml`](examples/minimal.yaml) | Gateway OTLP com mTLS e storage; sem acesso ao host, injeção ou descoberta automática de aplicações. |
| [`examples/kubernetes.yaml`](examples/kubernetes.yaml) | Ponto de partida para coleta Kubernetes selecionada. Revisar namespaces, APIs/kubelet, CAs, CIDRs e aprovação de logs antes de habilitar. |
| eBPF/Beyla | Opcional, workloads e permissões de host explícitos; não oferece spans internos/de negócio completos nem propagação de headers por padrão. |
| [`examples/profiles.yaml`](examples/profiles.yaml) | Profiles de alvos pprof HTTPS/mTLS existentes e aprovados; não instala nem ativa pprof na aplicação. |

As versões/digests selecionados estão em [versões e compatibilidade](docs/versions.md); builds, SBOM, scans, proveniência, assinatura e registry estão em [supply chain](docs/supply-chain.md). O Collector Elven usa build mínimo OCB com componentes explícitos; Beyla/Alloy preservam seus runtimes upstream. Licenças e rastreabilidade são mantidas, sem atribuir à Elven a autoria do código upstream.

## Operação segura

- Gateway: uma réplica, PVC padrão de 2Gi e fila de 20Mi de payload serializado por sinal OTLP, com `fsync`. Há overhead adicional e capacidade finita.
- Módulos de host/eBPF/profiles: desativados por padrão. Namespace próprio não elimina os riscos de acesso ao node.
- Portas configuráveis sem hostPort/hostNetwork no baseline; mTLS exige CA e SAN corretos, não `insecure_skip_verify`.
- Sem adoção/remoção automática de recursos do cliente. Não importar posições de seus agents nem usar annotations genéricas para descobrir alvos.
- Uninstall retém namespace, Secrets de credenciais/TLS e PVCs. Drene as filas antes de remover; não há garantia de perda zero ou exactly-once.

## Documentação

- [Arquitetura, módulos, portas e coexistência](docs/architecture.md)
- [Segurança, RBAC, mTLS, credenciais e riscos](docs/security.md)
- [Dimensionamento, instalação, diagnóstico e ciclo operacional](docs/operations.md)
- [Migração e rollback do template anterior](docs/migration.md)
- [Suporte, matriz e gates de validação](docs/support.md)
- [Diagnóstico que orientou a refatoração](docs/audit-baseline.md)
- [Histórico de mudanças](CHANGELOG.md)

## Instalações antigas

O template anterior está em [`legacy/v0/`](legacy/v0/UNSUPPORTED.md). Não existe atualização automática do antigo `helmfile apply` para esta distribuição. O `helmfile.yaml` da raiz é apenas uma sentinela, sem releases nem hooks: não instala, migra ou remove recursos. Os scripts shell legados são bloqueados por padrão; a exceção explícita `ELVEN_ALLOW_UNSUPPORTED_LEGACY=1` existe somente para recuperação histórica revisada, não para novas instalações nem migração automática. Não execute o destroy legado para “limpar” um cluster antes de migrar.
