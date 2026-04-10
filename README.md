# Stack de Observabilidade - Elven Observability

Este repositório é a base que seus clientes instalam no cluster deles para enviar telemetria ao seu SaaS LGTM da Elven Observability.

A stack foi alinhada para `2026` com a seguinte divisão de responsabilidades:

- `Prometheus`: métricas de infraestrutura e componentes Kubernetes
- `Grafana Alloy`: logs stdout de workloads Kubernetes para Loki
- `OpenTelemetry Operator`: auto-instrumentação e env injection para aplicações
- `OpenTelemetry Collector`: traces e métricas OTLP das aplicações, além de scrape genérico via `prometheus.io/*`

Você visualizará métricas, logs e dashboards no Grafana da Elven:

- [Grafana Elven Observability](https://grafana.elvenobservability.com/)

## Estrutura

```text
stack-observability-k8s/
├── monitoring-namespace.yaml
├── alloy/
│   └── values-alloy.yaml
├── cert-manager/
│   ├── cluster-issuer.yaml
│   └── values.yaml
├── collector-fe/
│   ├── collector-fe-env-secret.yaml
│   └── values.yaml
├── opentelemetry-operator/
│   ├── apply-operator-and-instrumentation.sh
│   ├── instrumentation.yaml
│   ├── opentelemetry-operator.yaml
│   └── README.md
├── otel-collector/
│   ├── collector-config.yaml
│   ├── collector-deploy.yaml
│   ├── collector-rbac.yaml
│   ├── collector-service.yaml
│   └── README.md
├── prometheus/
│   └── values-prometheus.yaml
├── helmfile.yaml
├── kustomization.yaml
└── apply-otel-operator.sh
```

## Pré-requisitos

1. Cluster Kubernetes funcional.
2. `kubectl`.
3. `helm`.
4. `helmfile`.

## 1. Namespace e credenciais

Crie ou reaplique o namespace `monitoring`:

```bash
kubectl apply -f ./monitoring-namespace.yaml
```

Crie a secret com as credenciais do tenant:

```bash
kubectl create secret generic elven-observability-credentials \
  -n monitoring \
  --from-literal=tenantId="<SEU_TENANT_ID>" \
  --from-literal=apiToken="<SEU_API_TOKEN>"
```

Essa secret é compartilhada pela stack para autenticação no SaaS da Elven, incluindo:

- `OpenTelemetry Collector`
- `Prometheus remoteWrite`
- `Grafana Alloy`
- `collector-fe` para o `LOKI_API_TOKEN`

## 2. Prometheus

O `Prometheus` continua sendo o agente de métricas de infraestrutura desta stack.

Ele faz:

- scrape de componentes Kubernetes e infraestrutura
- redução de cardinalidade dessas métricas
- envio para o Mimir da Elven via `remoteWrite`

Revise [values-prometheus.yaml](/Users/leonardozwirtes/Documents/Elven/elven-observability/stack-observability-k8s/prometheus/values-prometheus.yaml) e confirme principalmente o `X-Scope-OrgID`.

## 3. Alloy para logs

O fluxo de logs foi modernizado para `Alloy -> Loki`.

O Alloy desta stack foi configurado para:

- rodar como `DaemonSet`
- ler logs de `/var/log/pods`
- manter offsets em `/var/lib/alloy-data`
- importar automaticamente a `positions.yaml` legada do Promtail em `/run/promtail/positions.yaml`
- enviar para `https://loki.elvenobservability.com/loki/api/v1/push`
- autenticar com `Bearer ${API_TOKEN}` e `X-Scope-OrgID=${TENANT_ID}`

O arquivo principal é [values-alloy.yaml](/Users/leonardozwirtes/Documents/Elven/elven-observability/stack-observability-k8s/alloy/values-alloy.yaml).

### Filtro por namespace

O filtro padrão continua por regex de namespace:

```yaml
logs:
  namespaceRegex: "^(default|monitoring|namespace1|namespace2)$"
```

Ajuste essa regex para os namespaces que o cliente realmente quer coletar.

### Filtro opcional por annotation

Se quiser exigir opt-in por pod, habilite:

```yaml
logs:
  annotationFilter:
    enabled: true
```

Quando isso estiver ligado, o Alloy aceitará estas annotations:

```yaml
metadata:
  annotations:
    alloy_logs: "true"
```

Por compatibilidade, `promtail_logs: "true"` também continua funcionando.

### Nota de migração

No [helmfile.yaml](/Users/leonardozwirtes/Documents/Elven/elven-observability/stack-observability-k8s/helmfile.yaml), o chart agora é `grafana/alloy` e o release padrão desta stack é `elven-logs-collector`.

## 3.1 Collector FE

O `collector-fe` também reutiliza a secret central [elven-observability-credentials](/Users/leonardozwirtes/Documents/Elven/elven-observability/stack-observability-k8s/README.md#1-namespace-e-credenciais) para o token Loki.

Nesta stack:

- `LOKI_API_TOKEN` vem de `elven-observability-credentials.apiToken`
- a secret [collector-fe-env-secret.yaml](/Users/leonardozwirtes/Documents/Elven/elven-observability/stack-observability-k8s/collector-fe/collector-fe-env-secret.yaml) fica apenas com parâmetros específicos do `collector-fe`, como `SECRET_KEY`, `LOKI_URL`, `ALLOW_ORIGINS` e `JWT_ISSUER`

Isso evita duplicar o mesmo token em dois segredos diferentes.

## 4. OpenTelemetry Operator

O diretório [opentelemetry-operator](/Users/leonardozwirtes/Documents/Elven/elven-observability/stack-observability-k8s/opentelemetry-operator) já vem preparado com o `elven-instrumentation-operator` em `v0.148.0`.

O `instrumentation.yaml` foi padronizado para:

- enviar traces e métricas em `OTLP HTTP/protobuf` para `4318`
- habilitar Java, Node.js, Python, .NET, Go, Apache HTTPD e Nginx
- usar `inject-sdk` como fallback para `Ruby`, `Rust` e workloads legados com SDK OTel próprio
- aplicar `OTEL_SEMCONV_STABILITY_OPT_IN=http,db,messaging`
- manter logs stdout no fluxo atual `Alloy -> Loki`

Para aplicar tudo em ordem:

```bash
INSTRUMENTATION_NAMESPACE=<namespace-da-sua-app> \
  ./opentelemetry-operator/apply-operator-and-instrumentation.sh
```

Mais detalhes estão em [opentelemetry-operator/README.md](/Users/leonardozwirtes/Documents/Elven/elven-observability/stack-observability-k8s/opentelemetry-operator/README.md).

## 5. OpenTelemetry Collector

O collector desta stack não substitui o Prometheus.

Ele foi desenhado para:

- receber traces e métricas OTLP das instrumentações
- fazer scrape genérico de aplicações anotadas com `prometheus.io/*`
- exportar traces para o Tempo e métricas para o Mimir
- não carregar scrapes fixos de cliente no baseline

Arquitetura resumida:

- `Prometheus`: infra/Kubernetes
- `Alloy`: logs stdout
- `OpenTelemetry Collector`: OTLP + scrape genérico de apps

Mais detalhes estão em [otel-collector/README.md](/Users/leonardozwirtes/Documents/Elven/elven-observability/stack-observability-k8s/otel-collector/README.md).

## 6. Instalação com Helmfile

Depois de ajustar credenciais e arquivos:

```bash
helmfile sync
```

O fluxo de `helmfile sync` desta stack faz:

- instalar `cert-manager` com CRDs
- esperar o `cert-manager` ficar disponível
- instalar os releases Helm principais da stack
- executar a release sentinela `elven-bootstrap`
- aplicar o `ClusterIssuer`
- aplicar a `kustomization.yaml` da raiz
- esperar o `elven-instrumentation-operator`
- aplicar o `Instrumentation` nos namespaces elegíveis

O `Instrumentation` não fica mais dependente de hooks acoplados ao release `cert-manager`. A aplicação agora acontece de forma explícita no final do `helmfile sync`, pela release local `elven-bootstrap`, com `wait` para CRD e controller antes da criação dos recursos `Instrumentation`.

Se quiser limitar a instrumentação automática a alguns namespaces durante o `helmfile sync`, use:

```bash
INSTRUMENTATION_TARGET_NAMESPACES="app,worker" helmfile sync
```

O apply automático também exclui por padrão namespaces operacionais e de plataforma, como:

- `kube-*`
- `cert-manager`
- `monitoring`
- `ingress-nginx`
- `kong`
- `cnpg-system`
- `calico-*`
- `tigera-operator`
- `argocd`
- `flux-system`
- `istio-system`
- `linkerd`
- `kyverno*`
- `gatekeeper-system`
- `mgk-*`

Para produção, o mais seguro é usar `INSTRUMENTATION_TARGET_NAMESPACES` explícito. Se precisar adaptar a exclusão automática ao cluster do cliente, use `EXCLUDED_NAMESPACES_REGEX`.

## 6.1 Remoção com Helmfile

O `helmfile destroy` desta stack agora também faz o teardown dos manifests locais que não pertencem a charts Helm.

Fluxo de remoção:

- o hook global `prepare` do `helmfile` executa [helmfile-global-hooks.sh](/Users/leonardozwirtes/Documents/Elven/elven-observability/stack-observability-k8s/helmfile-global-hooks.sh)
- esse hook chama [destroy-kustomize-resources.sh](/Users/leonardozwirtes/Documents/Elven/elven-observability/stack-observability-k8s/destroy-kustomize-resources.sh) antes do teardown dos releases Helm
- esse script remove:
  - recursos `Instrumentation` aplicados pela stack
  - `ClusterIssuer`
  - manifests do `OpenTelemetry Collector`
  - manifests do `OpenTelemetry Operator`
  - secrets locais gerenciadas pela `kustomization`

O namespace `monitoring` não é removido automaticamente. Isso é intencional, para evitar apagar recursos adicionais do cliente que eventualmente estejam no mesmo namespace.

Com isso, o `helmfile destroy` deixa de remover só os charts Helm e passa a desmontar também a parte local da stack, sem tentar destruir o namespace inteiro.

## 7. O que será instalado

1. `cert-manager`
2. `Prometheus` com `kube-prometheus-stack`
3. `Alloy` para logs
4. `collector-fe`
5. `OpenTelemetry Collector`
6. `OpenTelemetry Operator`

## Notas importantes

1. O `Prometheus` é o caminho de métricas de infraestrutura.
2. O `Alloy` é o caminho de logs.
3. O `OpenTelemetry Operator` + `Collector` são o caminho de métricas e traces de aplicações.
4. O collector baseline não deve carregar scrapes específicos de cliente por padrão.

## Suporte

Se precisar ajustar essa stack para um perfil de cliente específico, abra uma issue ou siga com uma customização por valores/overlays em cima desta base.
