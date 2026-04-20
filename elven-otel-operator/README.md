# OpenTelemetry Operator e Instrumentation

Este diretorio entrega o baseline de auto-instrumentacao da stack Elven para `2026`.

## O que sobe

- `elven-instrumentation-operator`
- um `Instrumentation` padrao chamado `instrumentation`

Arquivos principais:

- [opentelemetry-operator.yaml](/Users/leonardozwirtes/Documents/Elven/elven-observability/stack-observability-k8s/elven-otel-operator/opentelemetry-operator.yaml)
- [instrumentation.yaml](/Users/leonardozwirtes/Documents/Elven/elven-observability/stack-observability-k8s/elven-otel-operator/instrumentation.yaml)
- [apply-operator-and-instrumentation.sh](/Users/leonardozwirtes/Documents/Elven/elven-observability/stack-observability-k8s/elven-otel-operator/apply-operator-and-instrumentation.sh)

## Fluxo padrao da stack

No fluxo normal do repo, voce nao precisa aplicar esse diretorio manualmente.

O `helmfile apply` faz:

- aplicar o operator pela `kustomization.yaml`
- esperar a CRD `instrumentations.opentelemetry.io`
- esperar o deployment `elven-instrumentation-operator-controller-manager`
- aplicar o `Instrumentation` automaticamente nos namespaces elegiveis

Se quiser restringir os namespaces:

```bash
INSTRUMENTATION_TARGET_NAMESPACES="app,worker" helmfile apply
```

## Fluxo manual

Se quiser testar o operator isoladamente:

```bash
INSTRUMENTATION_NAMESPACE=default ./apply-operator-and-instrumentation.sh
```

## Contrato do `Instrumentation`

- `exporter.endpoint`: `http://elven-otel-collector.monitoring.svc.cluster.local:4318`
- `OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf`
- `OTEL_SEMCONV_STABILITY_OPT_IN=http,db,messaging`
- `OTEL_TRACES_EXPORTER=otlp`
- `OTEL_METRICS_EXPORTER=otlp`
- `sampler.type=parentbased_traceidratio`
- `sampler.argument="1"`
- `defaults.useLabelsForResourceAttributes=true`
- `resource.addK8sUIDAttributes=true`

## Linguagens e runtimes cobertos

- `Java`
- `Node.js`
- `Python`
- `.NET`
- `Go`
- `Apache HTTPD`
- `Nginx`
- `inject-sdk` para `Ruby`, `Rust` e workloads com SDK proprio

Observacoes importantes:

- `Node.js` usa a imagem custom da Elven
- `Python` usa a imagem custom da Elven
- `.NET` sobe com logs OTel desligados por padrao
- `Go` exige a annotation `instrumentation.opentelemetry.io/otel-go-auto-target-exe`
- `Nginx` segue as limitacoes upstream do Operator

## Annotations de injecao

```yaml
metadata:
  annotations:
    instrumentation.opentelemetry.io/inject-java: "true"
    instrumentation.opentelemetry.io/inject-nodejs: "true"
    instrumentation.opentelemetry.io/inject-python: "true"
    instrumentation.opentelemetry.io/inject-dotnet: "true"
    instrumentation.opentelemetry.io/inject-go: "true"
    instrumentation.opentelemetry.io/inject-apache-httpd: "true"
    instrumentation.opentelemetry.io/inject-nginx: "true"
    instrumentation.opentelemetry.io/inject-sdk: "true"
```

## Casos especiais

### Python musl

```yaml
metadata:
  annotations:
    instrumentation.opentelemetry.io/inject-python: "true"
    instrumentation.opentelemetry.io/otel-python-platform: "musl"
```

### .NET musl

```yaml
metadata:
  annotations:
    instrumentation.opentelemetry.io/inject-dotnet: "true"
    instrumentation.opentelemetry.io/otel-dotnet-auto-runtime: "linux-musl-x64"
```

### Go

```yaml
metadata:
  annotations:
    instrumentation.opentelemetry.io/inject-go: "true"
    instrumentation.opentelemetry.io/otel-go-auto-target-exe: "/app/seu-binario"
```

## Verificacoes uteis

```bash
kubectl get instrumentations -A
kubectl logs -n monitoring deploy/elven-instrumentation-operator-controller-manager --since=5m
kubectl get instrumentation -n default instrumentation -o yaml
```
