# Diagnóstico do template anterior

Inspeção local em 29/10/2026, sobre o commit `3978bcc`. Os arquivos originais foram preservados em [`legacy/v0/`](../legacy/v0/), com um guard fail-closed acrescentado no início dos scripts shell. Os números de linha abaixo já incluem esse guard e se referem aos arquivos em `legacy/v0/`, não aos novos templates. A inspeção não envolveu acesso ou alteração de cluster de cliente.

## Arquitetura encontrada

| Sinal/função | Caminho anterior |
|---|---|
| Métricas Kubernetes/host | kube-prometheus-stack, com Prometheus Operator, kube-state-metrics e node-exporter próprios → Mimir por remote write. |
| Logs | Alloy DaemonSet, arquivos stdout/stderr dos Pods e posições em hostPath → Loki. |
| Traces/métricas de aplicações | Instrumentação das aplicações ou Beyla opcional → Collector próprio → Tempo/Mimir. |
| Injeção SDK | OpenTelemetry Operator, webhooks/CRDs e um Instrumentation genérico distribuído por namespaces. |
| Frontend | Collector Faro próprio → Loki. |
| Certificados | cert-manager e ClusterIssuer global, associados ao ingress Kong. |
| MySQL | Exporter opcional, com ServiceMonitor/PrometheusRule. |

Este template já instalava seus próprios componentes de coleta. Não deve ser confundido com integrações específicas que faziam fan-out de um gateway do cliente. A fragilidade aqui era instalar/controlar recursos globais e caminhos do host sem uma fronteira suficiente de ownership, além de defaults e operação sem validação automatizada.

## Achados e decisões da refatoração

| Risco | Evidência no legado | Decisão para a nova distribuição |
|---|---|---|
| `diff`, `template` e `lint` alteravam o cluster | `helmfile-global-hooks.sh:24–26` chama `bootstrap/prepare.sh`; `bootstrap/ensure-secrets.sh:67–110` aplica Namespace/Secrets. | Render/validação não criam recursos; operação mutante é separada e exige identidade de cluster. |
| Instalação pós-falha e restarts desnecessários | `helmfile-global-hooks.sh:20–22`; `apply-local-resources.sh:40–52` aplica locais em cleanup e força restarts, sem verificar a falha da release. | Recursos declarativos pertencem à release; alterações em configuração dirigem rollout, sem restart global incondicional. |
| Remoção de recursos potencialmente alheios | `apply-local-resources.sh:44–48`; `destroy-kustomize-resources.sh:67–71` removem nomes genéricos sem verificar ownership. | Nunca remover/adotar recurso de terceiros por semelhança de nome. |
| Exclusão de Instrumentation do cliente | `destroy-kustomize-resources.sh:38–40` exclui `instrumentation/instrumentation` em namespaces descobertos por deny-list. | A nova distribuição não instala CRDs, webhooks ou Instrumentation. Migração é manual e orientada por ownership. |
| Conflito com cert-manager/Prometheus Operator existentes | `helmfile.yaml:38–42`; `elven-prometheus/values-prometheus.yaml:33–34,2639–2640`. | Baseline sem esses operadores nem CRDs. Coleta Kubernetes própria diretamente da API/kubelet, conforme módulos habilitados. |
| Webhooks OTel de alcance global | `elven-otel-operator/opentelemetry-operator.yaml:18010–18116`, sem selectors de namespace/objeto; várias operações usam `failurePolicy: Fail`. | Sem auto-injeção ou webhook no baseline. Instrumentação SDK continua sendo uma integração explícita, não uma mutação implícita. |
| Permissões muito amplas do Operator | Mesmo arquivo: `17603–17610` lê Secrets no cluster; `17580–17785` inclui CRUD de workloads e políticas, inclusive SCC OpenShift. | Separar instalação de runtime; SAs por componente e apenas verbos/recursos necessários. Nenhum runtime exige leitura de Secrets pela API. |
| Namespace configurável só parcialmente | `bootstrap/ensure-secrets.sh:67`, `render-prometheus-values.sh:16`, Helmfile/manifests fixam `monitoring`, apesar de `ELVEN_NAMESPACE` anunciado. | Namespace/release são parte de um único contrato de instalação e dos nomes/seletores gerados. |
| Segredos no argv e entropia inadequada | `bootstrap/ensure-secrets.sh:73–75,104–108`; `elven-mysql/create-secret.sh:29–30`; fallback `date +%s` em `ensure-secrets.sh:59–64`. | Arquivos de credenciais privados; nada de token como argumento literal. TLS usa geração criptográfica apropriada; sem fallback previsível. |
| Collector sem hardening/health checks | `elven-otel-collector/collector-deploy.yaml:17–32` não define probes/security context e reserva 1Gi, com limite de 16Gi. | Gateway não-root, capabilities removidas, filesystem somente leitura, probes e recursos explícitos. |
| Filas voláteis e retries finitos | `elven-otel-collector/collector-config.yaml:70–96`; não há extensão de storage. | Filas persistentes limitadas por sinal, sanitização antes da fila, retries transitórios sem prazo automático e limites documentados. |
| Observabilidade interna desativada | `elven-otel-collector/collector-config.yaml:258–262`. | Métricas internas e critérios de verificação de entrada, fila, falha e exportação. Readiness não significa entrega. |
| Posições compartilhadas com agentes do cliente | `elven-logs-collector/values-alloy.yaml:306–319` monta `/var/lib/alloy-data` e `/run/promtail` genéricos. | Sem importar nem escrever posições de terceiros. Storage próprio, com retenção e limites explícitos. |
| Escopo de logs amplo e nível inventado | Mesmo arquivo: `14–47` coleta todos os namespaces fora da deny-list; `256–258` converte nível desconhecido em INFO. | Escopo explícito dos módulos de host e classificação sem atribuir semântica não comprovada. |
| eBPF com privilégios sem orçamento | `elven-ebpf/values.yaml:49–82` usa privileged e recursos vazios; `121–124` seleciona namespace wildcard; `160–163` habilita rastreamento de headers. | Módulo desligado por padrão, aprovação e alvos explícitos, permissões justificadas e propagação por headers desabilitada. |
| Imagens mutáveis e sem cadeia de fornecimento | Collector-FE `values.yaml:8–12`; Instrumentation `instrumentation.yaml:40`; imagens runtime sem digest. Não havia pipeline de build/scan/assinatura. | Releases com digest, proveniência, SBOM, scan, atribuição e verificação; publicação é um gate separado da implementação. |
| Scrape duplicado de aplicações | `elven-otel-collector/collector-config.yaml:10–55` descobre qualquer Pod com `prometheus.io/scrape`. | Não assumir annotations de outra stack; integrações precisam de seleção própria e revisão de dupla coleta. |
| Perda deliberada de traces não explicitada no quickstart | `elven-otel-collector/collector-config.yaml:139–164` mantém somente erros/alta latência; o Instrumentation usa sampler 100%. | Sem apresentar volume de origem como garantia de retenção; políticas precisam ser explícitas. |
| Porta anunciada sem listener | `elven-otel-collector/collector-service.yaml:14–16` anuncia 9090; config abre somente OTLP e health. | Tabela de portas e listeners deriva do contrato do chart; verificar alterações de portas nos dois lados. |
| Acoplamento a ingress/certificado específicos | `cert-manager/cluster-issuer.yaml:4–14`: nome global `letsencrypt-prod`, email genérico, solver Kong. | Nenhum ingress ou emissor global instalado por padrão; PKI própria da distribuição ou integração revisada. |
| Falhas parciais ocultadas | `apply-otel-operator.sh:41–64` aplica Instrumentation por namespaces e pode terminar com exit zero apesar de falhas. | Erros de configuração/pré-requisitos devem falhar antes da instalação e identificar correção, sem imprimir segredos. |

## Inventário anterior de versões

| Componente | Configuração encontrada |
|---|---|
| kube-prometheus-stack / Prometheus | Chart 86.1.0 / imagem v3.9.1. |
| Alloy | Chart 1.8.2 / imagem v1.16.1. |
| OpenTelemetry Collector contrib | 0.150.1. |
| OpenTelemetry Operator | 0.148.0, bundle estático com cerca de 18 mil linhas. |
| cert-manager | Chart v1.20.2. |
| Faro Collector | Chart 1.1.0 / imagem `latest`. |
| Beyla opcional | Chart 1.16.7, imagem herdada do chart, sem digest. |
| MySQL exporter opcional | Chart 2.14.0, imagem herdada do chart. |
| Injeção Node/Python | Imagem Node `latest`; Python 0.1.1. |

Não havia matriz de suporte, pipeline de CI, testes de configuração/runtime, Dockerfiles, SBOM ou política de atualização versionada. Esta inspeção não classifica cada versão como vulnerável: a avaliação de versões/advisories atuais é tratada separadamente na documentação de versões e supply chain.

## Evidência executada na inspeção

`bash -n` dos scripts legados e `kubectl kustomize .` passaram antes da movimentação dos arquivos. Isso demonstra apenas sintaxe shell e montagem local do Kustomize. Não demonstra aceitação pelo servidor, segurança, compatibilidade do Collector ou entrega de telemetria.

Não foram executados `helmfile lint`, `helmfile template` ou `helmfile diff` do legado: seus hooks poderiam escrever no cluster. A refatoração não usa esses comandos como mecanismo de migração nem autoriza destruição do legado.
