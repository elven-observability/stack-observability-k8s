# Stack de Observabilidade para Clientes Elven

Template de instalacao da stack Kubernetes que envia telemetria para o SaaS LGTM da Elven Observability.

Componentes instalados:

- `cert-manager`
- `kube-prometheus-stack`, com `remoteWrite` para Mimir
- `Grafana Alloy`, coletando logs stdout dos pods para Loki
- `OpenTelemetry Collector`, recebendo OTLP e scrape generico de pods anotados
- `OpenTelemetry Operator`, aplicando auto-instrumentacao
- `collector-fe`
- `Beyla`, preparado como opcional e desligado por padrao

## Instalar

Pre-requisitos locais:

- `kubectl` apontando para o cluster correto
- `helm`
- `helmfile`

Primeira instalacao:

```bash
export ELVEN_TENANT_ID="seu-tenant"
export ELVEN_API_TOKEN="<SEU_API_TOKEN>"

helmfile apply
```

Depois da primeira instalacao, as secrets ficam no cluster. Para reconciliar novamente:

```bash
helmfile apply
```

O `helmfile apply` e o unico comando de instalacao esperado. Ele cria o namespace, cria/atualiza as secrets, renderiza valores derivados da secret, instala os charts Helm e aplica os manifests locais.

## Variaveis de bootstrap

Obrigatorias apenas quando a secret central ainda nao existe:

- `ELVEN_TENANT_ID`
- `ELVEN_API_TOKEN`

Opcionais:

- `ELVEN_NAMESPACE`, default `monitoring`
- `COLLECTOR_FE_LOKI_URL`, default `https://logs.elvenobservability.com`
- `COLLECTOR_FE_ALLOW_ORIGINS`, default `https://*.elvenobservability.com`
- `COLLECTOR_FE_JWT_ISSUER`, default `elven-observability`
- `COLLECTOR_FE_SECRET_KEY`, default gerado automaticamente e reaproveitado nas proximas execucoes
- `INSTRUMENTATION_TARGET_NAMESPACES`, lista separada por virgula para limitar onde o `Instrumentation` sera aplicado

Existe um exemplo em `bootstrap/env.example`.

## O que o Helmfile faz

Durante `prepare`:

- valida `kubectl` e `helm`
- cria o namespace `monitoring`
- cria ou atualiza `elven-observability-credentials`
- cria ou atualiza `elven-collector-fe-env-secret`, sem secret fixa versionada no repo
- renderiza `elven-prometheus/values-prometheus.rendered.yaml` com o tenant atual

Durante a instalacao:

- instala `cert-manager`
- instala `kube-prometheus-stack`
- instala `Grafana Alloy`
- instala `collector-fe`

Durante `cleanup` de `apply`/`sync`:

- aplica o `ClusterIssuer`
- aplica a `kustomization.yaml`
- sobe o `OpenTelemetry Collector`
- sobe o `elven-instrumentation-operator`
- espera a CRD e o controller do Operator
- aplica o `Instrumentation` nos namespaces elegiveis
- reinicia os componentes locais para garantir convergencia com secrets/configs atuais

## Contrato operacional

### Prometheus

- coleta metricas de infra e Kubernetes
- envia metricas para Mimir via `remoteWrite`
- usa `X-Scope-OrgID` renderizado a partir da secret central

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

### OpenTelemetry Operator

- usa o deployment `elven-instrumentation-operator-controller-manager`
- aplica `Instrumentation` moderno com OTLP HTTP/protobuf em `4318`
- preserva imagens custom da Elven para `Node.js` e `Python`
- usa `inject-sdk` como fallback para `Ruby`, `Rust` e workloads com SDK proprio

### Alloy

- substitui Promtail no baseline
- coleta logs stdout dos pods Kubernetes
- envia para Loki usando `Bearer` token e `X-Scope-OrgID` da secret central

## Verificacoes rapidas

```bash
kubectl get pods -n monitoring
kubectl get secret elven-observability-credentials elven-collector-fe-env-secret -n monitoring
kubectl get instrumentations -A
kubectl logs -n monitoring deploy/elven-otel-collector --since=2m
kubectl logs -n monitoring deploy/elven-instrumentation-operator-controller-manager --since=2m
```

Esperado:

- pods de `monitoring` em `Running`
- secrets de bootstrap presentes
- pelo menos um `Instrumentation` nos namespaces elegiveis
- collector sem erro de exportacao
- operator pronto e sem erro de admission/injection

## Remover

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

- namespace `monitoring`
- secret central `elven-observability-credentials`

Isso evita apagar credenciais e recursos adicionais do cliente por acidente.

## Documentacao complementar

- `bootstrap/README.md`
- `elven-otel-operator/README.md`
- `elven-otel-collector/README.md`
