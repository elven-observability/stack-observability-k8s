# Stack de Observabilidade para Clientes Elven

Template de instalacao da stack Kubernetes que envia telemetria para o SaaS LGTM da Elven Observability.

Componentes instalados:

- `cert-manager`, como dependencia padrao upstream
- `elven-prometheus`, com `kube-prometheus-stack` e `remoteWrite` para Mimir
- `elven-logs-collector`, com Grafana Alloy coletando logs stdout dos pods para Loki
- `elven-otel-collector`, recebendo OTLP e scrape generico de pods anotados
- `elven-instrumentation-operator`, aplicando auto-instrumentacao
- `elven-collector-fe`
- `elven-mysql`, preparado como opcional para MySQL dentro do Kubernetes
- `elven-beyla`, preparado como opcional e desligado por padrao

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

- instala release `cert-manager`
- instala release `elven-prometheus`
- instala release `elven-logs-collector`
- instala release `elven-collector-fe`
- mantem release opcional `elven-mysql`, desligada por padrao
- mantem release opcional `elven-beyla`, desligada por padrao

Durante `cleanup` de `apply`/`sync`:

- aplica o `ClusterIssuer`
- aplica a `kustomization.yaml`
- sobe o `OpenTelemetry Collector`
- sobe o `elven-instrumentation-operator`
- espera a CRD e o controller do Operator
- aplica o `Instrumentation` nos namespaces elegiveis
- reinicia os componentes locais para garantir convergencia com secrets/configs atuais

## Contrato operacional

### Releases e nomes esperados

| Camada | Release/manifests | Workloads principais |
| --- | --- | --- |
| Certificados | `cert-manager` | `cert-manager`, `cert-manager-webhook`, `cert-manager-cainjector` |
| Prometheus | `elven-prometheus` | `elven-prometheus-operator`, `elven-prometheus-kube-state-metrics`, `elven-prometheus-node-exporter` |
| Logs | `elven-logs-collector` | `elven-logs-collector` |
| OTLP | manifests locais | `elven-otel-collector` |
| Auto-instrumentacao | manifests locais | `elven-instrumentation-operator-controller-manager` |
| Frontend collector | `elven-collector-fe` | `elven-collector-fe` |
| MySQL opcional | `elven-mysql` | `elven-mysql` |
| eBPF opcional | `elven-beyla` | `elven-beyla` |

Os componentes da stack Elven usam prefixo `elven-*`. A excecao intencional e `cert-manager`, que mantem os nomes upstream para evitar surpresa operacional.

Para habilitar Beyla, altere a release `elven-beyla` no `helmfile.yaml` de `installed: false` para `installed: true` e rode `helmfile apply`.

### MySQL no Kubernetes

`elven-mysql` monitora MySQL via `prometheus-mysql-exporter` e `ServiceMonitor`. A release fica desligada por padrao porque cada cliente tem host, namespace e senha proprios.

Fluxo recomendado:

```bash
export ELVEN_MYSQL_PASSWORD="<MYSQL_EXPORTER_PASSWORD>"
./elven-mysql/create-secret.sh
```

Depois ajuste `elven-mysql/values.yaml` com o Service DNS do MySQL:

```yaml
mysql:
  host: mysql.default.svc.cluster.local
  port: 3306
  user: exporter
```

Habilite a release no `helmfile.yaml`:

```yaml
- name: elven-mysql
  installed: true
```

E aplique:

```bash
helmfile apply
```

As metricas chegam ao Mimir pelo `remoteWrite` do `elven-prometheus`, com `job="elven-mysql"` e labels como `elven_component="mysql"`, `db_system="mysql"` e `scrape_source="serviceMonitor"`.

O exporter desativa `prometheus.io/scrape` no pod para evitar scrape duplicado pelo `elven-otel-collector`; o scrape oficial e somente pelo `ServiceMonitor`.

Permissao sugerida para o usuario do exporter:

```sql
CREATE USER 'exporter'@'%' IDENTIFIED BY '<MYSQL_EXPORTER_PASSWORD>' WITH MAX_USER_CONNECTIONS 3;
GRANT PROCESS, REPLICATION CLIENT, SELECT ON *.* TO 'exporter'@'%';
FLUSH PRIVILEGES;
```

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

Filtros de namespace ficam em `elven-logs-collector/values-alloy.yaml`:

```yaml
logs:
  namespaces:
    include: []
    includeRegex: ".+"
    exclude:
      - kube-system
      - monitoring
      - cert-manager
    excludeRegex: "^(mgk-.*|sentinel)$"
```

Regras simples:

- `include: []` coleta todos os namespaces que nao cairem no deny-list.
- `include: ["app", "worker"]` coleta somente esses namespaces.
- `exclude` remove nomes exatos de namespace.
- `excludeRegex` remove padroes avancados, como `mgk-*`.

Exemplo para coletar somente `app` e `worker`:

```yaml
logs:
  namespaces:
    include:
      - app
      - worker
    exclude: []
    excludeRegex: ""
```

## Verificacoes rapidas

```bash
helmfile list
kubectl get pods -n monitoring
kubectl get secret elven-observability-credentials elven-collector-fe-env-secret -n monitoring
kubectl get instrumentations -A
kubectl get deploy,daemonset,statefulset -n monitoring | grep elven
kubectl get servicemonitor,prometheusrule -n monitoring | grep elven
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
