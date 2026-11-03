# Elven Observability Distribution

Distribuição Kubernetes da Elven para receber e coletar telemetria com componentes próprios, isolamento por release e segurança por padrão. O caminho atual usa a CLI `./elven` e o chart `charts/elven-observability`.

Não requer gateway, agentes ou Operator do cliente. O baseline não instala CRDs, webhooks, cert-manager ou SDKs nas aplicações: é um gateway OTLP com mTLS, exportação HTTPS autenticada e filas persistentes. Logs de containers, métricas Kubernetes/kubelet, eBPF e profiles são módulos explícitos. O módulo opcional **Elven Instrumentation Operator** acrescenta um webhook próprio, sem CRDs e sem acesso à API pelo runtime, para injetar SDKs somente nos Pods/containers autorizados.

**Release 1.0.0 — oito imagens Elven públicas, assinadas por GitHub OIDC e fixadas por digest nos dois locks promovidos.** A instalação normal não usa `--development-images`; a CLI continua recusando imagens que não coincidam com os locks. Não há fallback para upstream ou `latest`. Consulte o [registro da release](docs/release-v1.0.0.md) e a [cadeia de fornecimento](docs/supply-chain.md).

Configuração renderizada, reconciliação Helm, scan/build local, testes em laboratório e aceitação no cliente são evidências diferentes. Conferir o [hardening de 03/11 e seus gates](docs/hardening-2026-11-03.md), o [histórico de validação de 29/10](docs/validation-2026-10-29.md) e [suporte/gates de release](docs/support.md). Um artefato OCI local não é uma imagem publicada/assinada para produção.

## Instalação de produção

Use o asset **`elven-observability-v1.0.0.tar.gz`** da [release](https://github.com/elven-observability/stack-observability-k8s/releases/tag/v1.0.0), confira seu SHA-256 e extraia o pacote, ou use a revisão pós-promoção indicada no manifest. O arquivo automático **Source code** da tag de build não é esse pacote: a tag é imutável e foi criada antes dos locks promovidos.

Pré-requisitos: Python 3.11+, `kubectl` compatível com o cluster, Helm 4.3.1+ (preferido) ou 3.22.1+ para compatibilidade, OpenSSL para gerar/verificar PKI e Kubernetes 1.35–1.37. É necessário StorageClass selecionado/default para o PVC do gateway, autorização de instalação e liberação dos destinos HTTPS. Não é necessário Helmfile, pip, Prometheus ou Operator do cliente.

Pull público não significa quota ilimitada: revise os limites do Docker Hub e o volume inicial de pulls por NAT/node. O PAT de publicação da Elven **não** pertence ao cliente. Rate limits não autorizam desabilitar assinatura/TLS nem substituir digests; use uma política de acesso/cache do registry aprovada pelo administrador da infraestrutura se o ambiente exigir.

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

### Gateway e Operator em um comando

Depois de ambos os locks e os defaults das imagens serem publicados, assinados, verificados e promovidos, a mesma CLI pode reconciliar o núcleo e o Operator opcional em uma única invocação, sem modo de desenvolvimento:

```bash
./elven install --context "$ELVEN_CONTEXT" \
  --cluster-name "$ELVEN_CLUSTER_NAME" --expect-cluster-uid "$ELVEN_CLUSTER_UID" \
  --values "$ELVEN_VALUES" \
  --instrumentation-values /caminho/privado/elven/instrumentation.yaml \
  --instrumentation-release elven-operator \
  --tenant-file /caminho/privado/elven/tenant \
  --token-file /caminho/privado/elven/token
```

O arquivo do Operator é separado do perfil do núcleo. Use [examples/instrumentation.yaml](examples/instrumentation.yaml) como roteiro de revisão: ele precisa declarar namespaces de aplicações aprovados, runtimes necessários, gateway correspondente à release/namespace/porta/domain escolhidos e CIDRs reais do apiserver, conforme o [guia de injeção](charts/elven-instrumentation/README.md). Todos os namespaces de injeção também precisam estar explicitamente autorizados em `collection.namespaces` do núcleo. Não colocar tenant, token ou chaves privadas em nenhum dos dois values. Os nomes de contexto/cluster, CIDRs, storage e escopo não são adivinhados pela CLI. O comando `install` já inclui validação/preflight; render e preflight separados são opções adicionais de revisão, não outras instalações obrigatórias.

`--values` e `--instrumentation-values` podem ser repetidos para camadas revisadas, mantendo a ordem. O perfil efetivo do Operator é renderizado, validado contra seu lock e congelado em arquivo temporário privado **antes de qualquer escrita do núcleo**. As duas fases usam o mesmo contexto, UID esperado, namespace, kubeconfig e timeout. As releases Helm precisam ter nomes diferentes; o padrão do Operator é `elven-operator`. Para atualizar as duas fases, use `./elven upgrade` com os mesmos perfis completos revisados e argumentos de identidade.

Essa operação não é uma transação atômica entre releases. O preflight online de ownership/permissões/PKI do Operator ocorre depois que o gateway existe. Se a segunda fase falhar ou expirar, a CLI retorna erro de estado parcial/UNKNOWN e preserva núcleo, Secrets e PVCs; não executa limpeza destrutiva, não reinicia aplicações e não trata essa situação como sucesso completo. Inspecione `./elven status` e `python3 scripts/instrumentation.py status` com o mesmo contexto, namespace e respectivas releases antes de repetir o comando. A instalação do Operator **não** seleciona ou reinicia workloads: o opt-in e o aceite real de sinais continuam explícitos.

### Desenvolvimento isolado de futuras imagens

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
| [Elven Instrumentation Operator](charts/elven-instrumentation/README.md) | Injeção opcional de SDKs Elven por namespace/Pod/container explicitamente selecionados; independente de operadores/CRDs do cliente. |

## Instrumentação granular e privacidade seletiva

O Operator Elven injeta imagens próprias fixadas por digest para Java, Node.js e Python. SDKs e eBPF têm coberturas diferentes: bibliotecas HTTP/banco/mensageria suportadas podem produzir spans granulares, mas não existe garantia de instrumentar todo método, statement, log ou fluxo de negócio. Não há reinício, alteração de Deployments ou opt-in global automáticos. Conflitos detectáveis no Pod/namespace são recusados; SDKs e loader flags embutidos no `ENV` da imagem exigem inventário e canary, pois o webhook não consulta o registry.

Java 17/21 usa o mesmo agente compatível. Node.js atual exige 22.15+; o perfil Node.js 20 é legado EOL, separado e exige aprovação explícita. Python permanece opcional e depende de versão, libc e bibliotecas suportadas. O [guia do módulo](charts/elven-instrumentation/README.md) contém a matriz e o procedimento de canary. Tenant/token de ingestão nunca são injetados nas aplicações; SDKs usam mTLS até o gateway.

`privacy.logBodyMode: selective` é o padrão. O processor Elven sanitiza recursivamente o envelope OTLP e preserva texto operacional, estrutura JSON, IDs de correlação e forma das queries. Senhas, tokens, padrões básicos de PII e valores SQL são mascarados **antes da fila persistente**. Exemplo de saída: `Pedido aprovado; email=[REDACTED]; duração=42ms`; query: `SELECT id FROM elven_accounts WHERE email=? AND amount>?`. O arquivo/log original da aplicação não é reescrito.

`strict` continua disponível para retirar o corpo inteiro. Inputs malformados ou acima dos limites recebem máscara no ramo afetado, sem fallback cru. Regras básicas não reconhecem qualquer PII de negócio: valide seu corpus, acrescente controles na origem e revise a [política de dados](docs/security.md#dados-sensíveis). Statements, parâmetros e payloads irrestritos não são habilitados como atalho para granularidade.

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
