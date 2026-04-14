# Stack de Observabilidade para Clientes Elven

Este repositório é o template que seus clientes instalam no cluster deles para enviar telemetria ao SaaS LGTM da Elven Observability.

Arquitetura da stack:

- `Prometheus`: métricas de infra e Kubernetes
- `OpenTelemetry Collector`: traces e métricas OTLP das apps, mais scrape genérico de pods anotados com `prometheus.io/*`
- `OpenTelemetry Operator`: auto-instrumentação e `inject-sdk`
- `Grafana Alloy`: logs stdout para Loki
- `collector-fe`: frontend collector da Elven
- `Beyla`: opcional, desligado por padrão

## Fluxo rápido

### 1. Criar o namespace

```bash
kubectl apply -f ./monitoring-namespace.yaml
```

### 2. Criar a secret central

```bash
kubectl create secret generic elven-observability-credentials \
  -n monitoring \
  --from-literal=tenantId="seu-tenant" \
  --from-literal=apiToken="<SEU_API_TOKEN>"
```

Essa secret alimenta automaticamente:

- `OpenTelemetry Collector`
- `Prometheus remoteWrite`
- `Grafana Alloy`
- `collector-fe` para o `LOKI_API_TOKEN`

O tenant do Prometheus nao fica mais hardcoded no repo. O `helmfile` resolve `tenantId` direto dessa secret durante o render.

### 3. Ajustes opcionais

`collector-fe`

- O release sobe por padrao.
- A secret [collector-fe/collector-fe-env-secret.yaml](/Users/leonardozwirtes/Documents/Elven/elven-observability/stack-observability-k8s/collector-fe/collector-fe-env-secret.yaml) ja vem com defaults funcionais.
- So ajuste esse arquivo se o cliente precisar personalizar `SECRET_KEY`, `LOKI_URL`, `ALLOW_ORIGINS` ou `JWT_ISSUER`.

`Beyla`

- Fica fora do baseline e nao sobe no `helmfile apply` padrao.
- O release ja esta preparado no [helmfile.yaml](/Users/leonardozwirtes/Documents/Elven/elven-observability/stack-observability-k8s/helmfile.yaml), mas permanece com `installed: false`.
- So habilite se o cliente realmente precisar de observabilidade por eBPF.

`Instrumentation`

- A stack aplica o [opentelemetry-operator/instrumentation.yaml](/Users/leonardozwirtes/Documents/Elven/elven-observability/stack-observability-k8s/opentelemetry-operator/instrumentation.yaml) automaticamente no fim do `helmfile apply`.
- Por padrao ela instrumenta todos os namespaces elegiveis e ignora namespaces operacionais.
- Se quiser limitar explicitamente, use `INSTRUMENTATION_TARGET_NAMESPACES="app,worker"`.

### 4. Subir tudo

```bash
helmfile apply
```

Exemplo com namespace-alvo explicito para instrumentacao:

```bash
INSTRUMENTATION_TARGET_NAMESPACES="app,worker" helmfile apply
```

## O que o `helmfile apply` faz

- instala `cert-manager`
- instala `kube-prometheus-stack`
- instala `Grafana Alloy`
- instala `collector-fe`
- aplica o `ClusterIssuer`
- aplica a `kustomization.yaml` da raiz
- sobe o `OpenTelemetry Collector`
- sobe o `elven-instrumentation-operator`
- espera a CRD e o controller do Operator
- aplica o `Instrumentation` nos namespaces elegiveis
- faz rollout dos componentes locais que dependem de secret/config para garantir convergencia

## Contrato operacional

### Prometheus

- continua responsavel por infra e Kubernetes
- faz `remoteWrite` para o Mimir da Elven
- o `X-Scope-OrgID` agora vem da secret central, sem edicao manual no values

### OpenTelemetry Collector

- recebe OTLP em `4317` e `4318`
- exporta traces para Tempo
- exporta metricas para Mimir
- faz scrape generico de pods anotados com:

```yaml
metadata:
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "8080"
    prometheus.io/path: "/metrics"
    prometheus.io/scheme: "http"
```

- separa pipelines de metricas por origem:
  - `metrics/otlp`
  - `metrics/prometheus`
- faz `tail_sampling` para manter apenas traces de erro ou acima de `1.5s`

### OpenTelemetry Operator

- usa o release renomeado `elven-instrumentation-operator`
- aplica o `Instrumentation` moderno do repo com `OTLP HTTP/protobuf` em `4318`
- preserva as imagens custom da Elven para `Node.js` e `Python`
- usa `inject-sdk` como fallback para `Ruby`, `Rust` e workloads com SDK proprio

### Alloy

- substitui o Promtail no baseline
- coleta logs stdout dos pods Kubernetes
- envia para Loki usando a mesma secret central

## Verificacoes rapidas

Depois do `helmfile apply`, valide:

```bash
kubectl get pods -n monitoring
kubectl get instrumentations -A
kubectl logs -n monitoring deploy/opentelemetrycollector --since=2m
kubectl logs -n monitoring deploy/elven-instrumentation-operator-controller-manager --since=2m
```

Checagens esperadas:

- pods de `monitoring` em `Running`
- pelo menos um `Instrumentation` criado nos namespaces elegiveis
- collector sem warnings de alias deprecated
- operator pronto e sem erro de admission/injection

## Remocao

Para desmontar a stack:

```bash
helmfile destroy
```

Esse fluxo remove:

- releases Helm da stack
- `ClusterIssuer`
- manifests locais do collector e do operator
- `Instrumentation` aplicado pela stack
- secret de config do collector
- secret de env do `collector-fe`

Ele nao remove:

- o namespace `monitoring`
- a secret central `elven-observability-credentials`

Isso e intencional, para nao apagar recursos adicionais do cliente por acidente.

## Documentacao complementar

- [opentelemetry-operator/README.md](/Users/leonardozwirtes/Documents/Elven/elven-observability/stack-observability-k8s/opentelemetry-operator/README.md)
- [otel-collector/README.md](/Users/leonardozwirtes/Documents/Elven/elven-observability/stack-observability-k8s/otel-collector/README.md)
