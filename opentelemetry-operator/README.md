# Instrumentando Aplicações no Kubernetes

Este diretório entrega um setup atualizado para `2026` com o `elven-instrumentation-operator` baseado no release oficial `v0.148.0` do OpenTelemetry Operator.

O `instrumentation.yaml` foi desenhado para:

- padronizar OTLP em `http/protobuf` pela porta `4318`
- habilitar toda a superfície nativa do `Instrumentation` CR
- manter `Alloy -> Loki` como caminho padrão para logs stdout
- oferecer fallback via `inject-sdk` para workloads com SDK próprio, incluindo `Ruby`, `Rust` e legados
- preservar as imagens custom da Elven para `Node.js` e `Python`

## Componentes deste diretório

- `opentelemetry-operator.yaml`: manifesto do Operator renomeado para `elven-instrumentation-operator`
- `instrumentation.yaml`: perfil moderno de instrumentação para traces e métricas
- `apply-operator-and-instrumentation.sh`: aplica o Operator, espera o controller ficar disponível e cria o `Instrumentation` no namespace desejado

Na raiz do repositório, o script [apply-otel-operator.sh](/Users/leonardozwirtes/Documents/Elven/elven-observability/stack-observability-k8s/apply-otel-operator.sh) é usado pelo `helmfile` para aplicar esse mesmo `Instrumentation` em lote nos namespaces elegíveis do cluster.

No `helmfile`, essa aplicação é disparada pela release sentinela `elven-bootstrap`, que roda ao final do `sync`, aplica os manifests locais da `kustomization.yaml`, espera a CRD e o controller do Operator ficarem prontos, e só então cria os recursos `Instrumentation`.

No `helmfile destroy`, o teardown desses recursos é disparado por hooks globais do Helmfile via [helmfile-global-hooks.sh](/Users/leonardozwirtes/Documents/Elven/elven-observability/stack-observability-k8s/helmfile-global-hooks.sh). Antes do uninstall dos releases Helm, ele executa [destroy-kustomize-resources.sh](/Users/leonardozwirtes/Documents/Elven/elven-observability/stack-observability-k8s/destroy-kustomize-resources.sh) para remover os `Instrumentation` criados pela stack, o Operator e o Collector local. O namespace `monitoring` não é removido automaticamente.

## Versões oficiais consumidas pelo Operator `v0.148.0`

- Java auto-instrumentation: `1.33.6`
- .NET auto-instrumentation: `1.2.0`
- Node.js auto-instrumentation: `0.71.0`
- Python auto-instrumentation: `0.60b1`
- Go auto-instrumentation: `0.23.0`
- Apache HTTPD auto-instrumentation: `1.0.4`
- Nginx auto-instrumentation: `1.0.4`

## Aplicação rápida

Para instalar o Operator em `monitoring` e criar o `Instrumentation` no namespace da aplicação:

```bash
INSTRUMENTATION_NAMESPACE=default ./apply-operator-and-instrumentation.sh
```

Se preferir aplicar manualmente:

```bash
kubectl apply -f opentelemetry-operator.yaml
kubectl wait --for=condition=established crd/instrumentations.opentelemetry.io --timeout=60s
kubectl wait -n monitoring --for=condition=Available deployment/elven-instrumentation-operator-controller-manager --timeout=180s
kubectl apply -n <application-namespace> -f instrumentation.yaml
```

Para aplicação em lote via `helmfile`, use opcionalmente:

```bash
INSTRUMENTATION_TARGET_NAMESPACES="app,worker" helmfile sync
```

Sem essa env, a release `elven-bootstrap` aplica o `Instrumentation` em todos os namespaces elegíveis, excluindo por padrão namespaces operacionais e de plataforma, como `kube-*`, `cert-manager`, `monitoring`, `ingress-nginx`, `kong`, `cnpg-system`, `calico-*`, `tigera-operator`, `argocd`, `flux-system`, `istio-system`, `linkerd`, `kyverno*`, `gatekeeper-system` e namespaces que casem com `mgk-*`.

Para produção, o mais seguro é usar `INSTRUMENTATION_TARGET_NAMESPACES` explícito. Se precisar customizar a exclusão automática para outro ambiente, ajuste a env `EXCLUDED_NAMESPACES_REGEX` no momento do `helmfile sync`.

## O que o `instrumentation.yaml` já entrega

- `exporter.endpoint`: `http://opentelemetrycollector.monitoring.svc.cluster.local:4318`
- `propagators`: `tracecontext`, `baggage`, `b3`, `b3multi`
- `sampler`: `parentbased_traceidratio` com argumento `1`
- `defaults.useLabelsForResourceAttributes: true`
- `resource.addK8sUIDAttributes: true`
- `OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf`
- `OTEL_SEMCONV_STABILITY_OPT_IN=http,db,messaging`
- `OTEL_TRACES_EXPORTER=otlp`
- `OTEL_METRICS_EXPORTER=otlp`
- `nodejs.image`: `docker.io/elvenobservability/nodejs-k8s-operator:latest`
- `python.image`: `docker.io/elvenobservability/python-k8s-operator:0.1.1`
- `volumeLimitSize`: `1Gi` para todos os blocos de auto-instrumentação
- baseline de recursos do sidecar/init de instrumentação: `requests 50m/64Mi`, `limits 500m/512Mi`
- `.NET` com logs OTel desligados por padrão, porque a stack atual mantém logs em `Alloy/Loki`

## Annotations de injeção

Use uma destas annotations no `Deployment`, `StatefulSet` ou `Pod`:

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

Valores suportados para essas annotations:

- `"true"`: usa o `Instrumentation` do namespace atual
- `"instrumentation"`: usa um `Instrumentation` específico no namespace atual
- `"outro-namespace/instrumentation"`: usa um `Instrumentation` de outro namespace
- `"false"`: não injeta

## Casos especiais por linguagem

### Python

Para imagens `musl`, defina a platform explicitamente:

```yaml
metadata:
  annotations:
    instrumentation.opentelemetry.io/inject-python: "true"
    instrumentation.opentelemetry.io/otel-python-platform: "musl"
```

Em imagens `glibc`, a annotation de plataforma pode ser omitida ou definida como `glibc`.

### .NET

Para workloads `musl`, ajuste o runtime identifier:

```yaml
metadata:
  annotations:
    instrumentation.opentelemetry.io/inject-dotnet: "true"
    instrumentation.opentelemetry.io/otel-dotnet-auto-runtime: "linux-musl-x64"
```

O padrão é `linux-x64`.

## Semantic conventions estáveis

O perfil global desta stack já injeta:

```yaml
OTEL_SEMCONV_STABILITY_OPT_IN=http,db,messaging
```

Observação importante:

- nesta stack o valor padronizado é `db`, conforme o contrato que você pediu para os clientes
- essa env faz sentido para workloads instrumentados por SDK/auto-instrumentation
- ela não muda o comportamento de scrape Prometheus puro no collector ou no Prometheus

### Go

Go exige informar o binário-alvo via annotation:

```yaml
metadata:
  annotations:
    instrumentation.opentelemetry.io/inject-go: "true"
    instrumentation.opentelemetry.io/otel-go-auto-target-exe: "/app/my-go-binary"
```

Observações importantes:

- Go auto-instrumentation requer privilégios elevados, configurados automaticamente pelo Operator
- Go não suporta multi-container pods para auto-instrumentation
- não configure `OTEL_GO_AUTO_TARGET_EXE` globalmente no `instrumentation.yaml`; ele deve ser definido por workload

### Apache HTTPD

Use:

```yaml
metadata:
  annotations:
    instrumentation.opentelemetry.io/inject-apache-httpd: "true"
```

O perfil padrão do repositório assume `Apache HTTPD 2.4`.

### Nginx

Use:

```yaml
metadata:
  annotations:
    instrumentation.opentelemetry.io/inject-nginx: "true"
```

Limitação upstream atual:

- suporte oficial restrito a `1.22.0`, `1.23.0` e `1.23.1`
- o layout padrão esperado é `configFile=/etc/nginx/nginx.conf` com `conf.d/*.conf`

### Ruby, Rust e workloads legados

Para apps que já usam SDK OpenTelemetry próprio, ou para stacks sem bloco nativo no `Instrumentation` CR, use:

```yaml
metadata:
  annotations:
    instrumentation.opentelemetry.io/inject-sdk: "true"
```

Esse modo injeta apenas as envs de SDK, sem auto-instrumentação binária. É o caminho recomendado neste repositório para:

- `Ruby`
- `Rust`
- workloads legados com SDK OTel já embutido
- aplicações que não podem usar os agentes automáticos do Operator

## Multi-container e multi-instrumentation

O Operator desta stack já sobe com `--enable-multi-instrumentation=true`.

### Mesmo runtime em mais de um container

Use `instrumentation.opentelemetry.io/container-names`:

```yaml
metadata:
  annotations:
    instrumentation.opentelemetry.io/inject-java: "true"
    instrumentation.opentelemetry.io/container-names: "app,worker"
```

### Runtimes diferentes no mesmo Pod

Use annotations específicas por linguagem:

```yaml
metadata:
  annotations:
    instrumentation.opentelemetry.io/inject-java: "true"
    instrumentation.opentelemetry.io/java-container-names: "api"
    instrumentation.opentelemetry.io/inject-python: "true"
    instrumentation.opentelemetry.io/python-container-names: "worker"
    instrumentation.opentelemetry.io/inject-sdk: "true"
    instrumentation.opentelemetry.io/sdk-container-names: "legacy"
```

Annotations suportadas por linguagem:

- `instrumentation.opentelemetry.io/java-container-names`
- `instrumentation.opentelemetry.io/nodejs-container-names`
- `instrumentation.opentelemetry.io/python-container-names`
- `instrumentation.opentelemetry.io/dotnet-container-names`
- `instrumentation.opentelemetry.io/go-container-names`
- `instrumentation.opentelemetry.io/apache-httpd-container-names`
- `instrumentation.opentelemetry.io/inject-nginx-container-names`
- `instrumentation.opentelemetry.io/sdk-container-names`

## Verificação

Confira se o Operator subiu com os gates esperados:

```bash
kubectl logs -n monitoring deployment/elven-instrumentation-operator-controller-manager
```

Você deve ver o Operator iniciando com `0.148.0` e com `go`, `nginx` e `multi-instrumentation` habilitados.

Depois confirme:

- traces chegando no Tempo via collector
- métricas chegando no Mimir via collector
- labels e metadata Kubernetes preenchendo `service.name`, `service.version`, namespace, pod, node e UIDs
- logs stdout continuando em `Alloy -> Loki`
