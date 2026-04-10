# Configuração do OpenTelemetry Collector no Kubernetes

Este collector faz parte da arquitetura base da stack em `2026` com o seguinte papel:

- receber traces e métricas OTLP das instrumentações automáticas
- fazer scrape genérico de aplicações anotadas com `prometheus.io/*`
- exportar traces para o Tempo e métricas para o Mimir
- não carregar scrapes específicos de cliente no baseline

## Papel de cada componente

- `Prometheus`: scrape de infraestrutura/Kubernetes e redução de cardinalidade dessas métricas
- `OpenTelemetry Collector`: OTLP das instrumentações e scrape genérico de aplicações
- `Alloy`: logs stdout para Loki

## Arquivos usados pelo collector

- `collector-config.yaml`: configuração principal do collector
- `collector-deploy.yaml`: deployment do collector
- `collector-service.yaml`: portas OTLP do serviço
- `collector-rbac.yaml`: permissões necessárias para discovery e enrich de alvos

Observação importante:

- o `kustomization.yaml` usado no deploy fica na raiz do repositório, não dentro desta pasta

## Como o collector está configurado

### Receivers

- `otlp`: recebe traces e métricas em `4317` e `4318`
- `prometheus`: mantém apenas o scrape genérico de pods anotados

O baseline não inclui mais jobs fixos de cliente, como `keycloak`.

### Pipelines

- `metrics/otlp`: trata apenas métricas vindas de instrumentações OTLP
- `metrics/prometheus`: trata apenas métricas de apps scraped via annotations `prometheus.io/*`
- `traces`: recebe OTLP, faz `tail_sampling` para `errors` e alta latência, e exporta para o Tempo

### Processamento

- `memory_limiter`, `k8sattributes` e `batch` seguem ativos
- `tail_sampling` mantém no collector a política de traces de `errors` e latência alta
- métricas OTLP e scraped passam por pruning seguro de atributos voláteis
- o filtro pesado de métricas de infraestrutura não fica mais no collector; isso pertence ao Prometheus

## Como habilitar scrape genérico de aplicação

Para uma aplicação ser scraped pelo collector, use annotations no pod template:

```yaml
metadata:
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "8080"
    prometheus.io/path: "/metrics"
    prometheus.io/scheme: "http"
```

Use esse modelo apenas para aplicações que realmente expõem métricas Prometheus/OpenMetrics.

## Scrapes específicos de cliente

O baseline da stack não ativa jobs específicos de cliente.

Se um cliente precisar de scrape dedicado para um componente específico, como `Keycloak`, isso deve entrar depois como configuração opt-in, revisada caso a caso.

Exemplo conceitual de regra futura para Keycloak:

- métricas expostas em `/metrics`
- management interface do Keycloak
- porta padrão `9000`
- somente quando `metrics-enabled` estiver ativo

## Deploy

O collector é aplicado pela `kustomization.yaml` da raiz do repositório:

```bash
kubectl apply -k .
```

Isso gera o secret de configuração a partir de `otel-collector/collector-config.yaml` e aplica:

- `collector-rbac.yaml`
- `collector-deploy.yaml`
- `collector-service.yaml`

## Verificações recomendadas

- confirmar que não existe mais `job_name: "keycloak"` no `collector-config.yaml`
- confirmar que a pipeline `metrics/prometheus` só usa o scrape genérico de pods anotados
- confirmar que a pipeline `metrics/otlp` recebe apenas `otlp`
- validar no runtime que apps anotadas com `prometheus.io/*` continuam sendo descobertas
- validar que traces e métricas OTLP das instrumentações continuam chegando normalmente
