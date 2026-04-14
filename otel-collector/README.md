# OpenTelemetry Collector da Stack

O collector desta stack tem um papel bem definido:

- receber traces e metricas OTLP das instrumentacoes
- fazer scrape generico de apps anotadas com `prometheus.io/*`
- exportar traces para Tempo
- exportar metricas para Mimir

Ele nao substitui o Prometheus de infra.

## Divisao de responsabilidade

- `Prometheus`: infra e Kubernetes
- `OpenTelemetry Collector`: OTLP das apps e scrape generico de apps
- `Alloy`: logs stdout para Loki

## Arquivos

- [collector-config.yaml](/Users/leonardozwirtes/Documents/Elven/elven-observability/stack-observability-k8s/otel-collector/collector-config.yaml)
- [collector-deploy.yaml](/Users/leonardozwirtes/Documents/Elven/elven-observability/stack-observability-k8s/otel-collector/collector-deploy.yaml)
- [collector-rbac.yaml](/Users/leonardozwirtes/Documents/Elven/elven-observability/stack-observability-k8s/otel-collector/collector-rbac.yaml)
- [collector-service.yaml](/Users/leonardozwirtes/Documents/Elven/elven-observability/stack-observability-k8s/otel-collector/collector-service.yaml)

## Receivers

- `otlp`
  - `4317` para gRPC
  - `4318` para HTTP/protobuf
- `prometheus`
  - um unico job `kubernetes-pods`
  - scrape apenas de pods anotados com `prometheus.io/scrape: "true"`
  - sem jobs fixos de cliente no baseline

## Pipelines

- `metrics/otlp`
  - recebe so `otlp`
  - nao derruba familias inteiras de metricas
  - faz apenas pruning seguro de atributos volateis
- `metrics/prometheus`
  - recebe so `prometheus`
  - remove apenas ruido generico de scrape, como `scrape_*`, `promhttp_*` e `target_info`
- `traces`
  - recebe `otlp`
  - filtra probes e smoke tests sinteticos
  - aplica `tail_sampling`
  - mantem apenas erro ou latencia acima de `1.5s`

## Annotations para scrape generico

```yaml
metadata:
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "8080"
    prometheus.io/path: "/metrics"
    prometheus.io/scheme: "http"
```

## O que nao entra no baseline

- scrape dedicado de cliente, como `Keycloak`
- filtro pesado de familias de infra dentro do collector

Essa reducao de cardinalidade de infra fica do lado do Prometheus.

## Deploy

O collector sobe via `kustomization.yaml` da raiz e e aplicado automaticamente no `helmfile apply`.

Se quiser aplicar isoladamente:

```bash
kubectl apply -k .
```

## Verificacoes uteis

```bash
kubectl get pods -n monitoring
kubectl logs -n monitoring deploy/elven-otel-collector --since=5m
kubectl get secret -n monitoring secrets-collector-config -o jsonpath='{.data.collector-config\\.yaml}' | base64 --decode
```
