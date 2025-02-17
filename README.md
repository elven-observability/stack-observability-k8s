# 🌟 Stack de Observabilidade - Elven Observability

Bem-vindo ao repositório da **Stack de Observabilidade**! Este guia foi criado para ajudá-lo a configurar facilmente uma stack de monitoramento e instrumentação utilizando ferramentas modernas como Prometheus, Promtail e OpenTelemetry. 🚀

Você utilizará o **Grafana da Elven Observability** para visualizar suas métricas, logs e dashboards no seguinte endereço:

🌐 [**Grafana Elven Observability**](https://grafana.elvenobservability.com/)

---

## 🧰 Conteúdo do Repositório

```
📂 stack-observability/
├── opentelemetry-operator/
│   ├── instrumentation.yaml
│   ├── values.yaml
│   ├── README.md
├── otel-collector/
│   ├── collector-config.yaml
│   ├── collector-deploy.yaml
│   ├── collector-service.yaml
│   ├── kustomization.yaml
│   ├── secrets.env
│   ├── README.md
├── prometheus/
│   ├── values-prometheus.yaml
├── promtail/
│   ├── values-promtail.yaml
├── helmfile.yaml
└── README.md
```

---

## ⚙️ Pré-requisitos

Antes de iniciar, certifique-se de ter o seguinte configurado no seu ambiente:

1. **Kubernetes**: Cluster funcional e configurado 🛠️
2. **kubectl**: Para gerenciar recursos no Kubernetes ⚡
3. **Helm**: Para instalar os charts 🎛️
4. **Helmfile**: Se ainda não tiver instalado, use o comando abaixo:

```bash
curl -sL https://github.com/helmfile/helmfile/releases/download/v1.0.0-rc.7/helmfile_1.0.0-rc.7_linux_amd64.tar.gz | sudo tar -xz -C /usr/local/bin
```

---

## 🚀 Instalação: Passo a Passo

Siga a ordem correta de configuração para evitar problemas.

---

### 1️⃣ Primeiramente faça o clone do reposotório:

Faça o clone do repositório via SSH ou HTTPS

SSH:

```bash
git clone git@github.com:elven-observability/stack-observability-k8s.git
```

HTTPS:

```bash
git clone https://github.com/elven-observability/stack-observability-k8s.git
```

### 2️⃣ Configurar Namespace e Credenciais

Primeiro, crie o Namespace `monitoring` para organizar os recursos de monitoramento:

```bash
kubectl create ns monitoring
```

Em seguida, configure uma `Secret` para armazenar as credenciais necessárias. Substitua `<SEU_TENANT_ID>` e `<SEU_API_TOKEN>` pelos valores fornecidos pelo time da Elven Observability. Caso ainda não tenha recebido essas informações, entre em contato com o suporte:

```bash
kubectl create secret generic elven-observability-credentials \
  -n monitoring \
  --from-literal=tenantId="<SEU_TENANT_ID>" \
  --from-literal=apiToken="<SEU_API_TOKEN>"
```
---

### 3️⃣ Configurar o Prometheus

Edite o arquivo `prometheus/values-prometheus.yaml` para incluir seu Tenant ID:

```yaml
remoteWrite:
  - url: https://mimir.elvenobservability.com/api/v1/push
    authorization:
      type: Bearer
      credentials:
        key: apiToken
        name: elven-observability-credentials
    headers:
      X-Scope-OrgID: <TENANT_ID>
    relabelConfigs:
      - sourceLabels: [__name__]
        regex: "^(prometheus|go|promhttp|scrape).*"
        action: drop
```

Certifique-se de substituir `<SEU_TENANT_ID>` pelo valor correto do seu ambiente.

---

### 4️⃣ Configuração do Promtail: Filtros por Namespace ou Annotation

Na configuração do **Promtail**, você pode usar filtros para controlar quais logs serão coletados com base no namespace ou em annotations específicas nos pods. Isso ajuda a reduzir o volume de dados coletados e direcionar apenas os logs relevantes para o Loki.

### Exemplo de Configuração

```yaml
config:
  snippets:
    common:
      # Filtro por annotation
      # - action: keep
      #   source_labels: [__meta_kubernetes_pod_annotation_promtail_logs]
      #   regex: "true"   # Somente os pods com a annotation `promtail_logs: "true"` serão incluídos
      # Filtro por namespace
      - action: keep
        source_labels: [__meta_kubernetes_namespace]
        regex: "^(default|monitoring|namespace1|namespace2)$" # Adicione os namespaces separados por pipe
```

### Explicação

1. **Por Namespace**:

   - A linha:
     ```yaml
     - action: keep
       source_labels: [__meta_kubernetes_namespace]
       regex: "^(default|monitoring|namespace1|namespace2)$"
     ```
     Permite especificar os namespaces que devem ser incluídos. Substitua `default`, `monitoring`, `namespace1`, `namespace2` pelos namespaces do seu ambiente.

2. **Por Annotation**:
   - A linha:
     ```yaml
     - action: keep
       source_labels: [__meta_kubernetes_pod_annotation_promtail_logs]
       regex: "true"
     ```
     Inclui apenas os pods que possuem a annotation `promtail_logs: "true"`. Isso é útil para habilitar a coleta de logs de maneira granular por pod.

### Como Usar

1. **Namespace**:
   - Utilize o filtro por namespace se deseja coletar logs de todos os pods dentro de determinados namespaces.
2. **Annotation**:
   - Use o filtro por annotation para controlar individualmente os pods que terão seus logs coletados. Adicione a seguinte annotation no deployment ou pod que deseja incluir:
     ```yaml
     metadata:
       annotations:
         promtail_logs: "true"
     ```

---

### 5️⃣ Configurar o OpenTelemetry Operator

Edite o arquivo `opentelemetry-operator/instrumentation.yaml` para definir os namespaces das aplicações que deseja instrumentar. Exemplo básico:

```yaml
apiVersion: opentelemetry.io/v1alpha1
kind: Instrumentation
metadata:
  name: instrumentation
  namespace: default
spec:
  nodejs:
    env:
      - name: OTEL_NODE_DISABLED_INSTRUMENTATIONS
        value: fs
      - name: OTEL_NODE_RESOURCE_DETECTORS
        value: all
  exporter:
    endpoint: "http://opentelemetrycollector.monitoring.svc.cluster.local:4318"
  propagators:
    - tracecontext
    - baggage
  sampler:
    type: parentbased_traceidratio
    argument: "1"
```

Aplique as configurações no cluster:

```bash
kubectl apply -f opentelemetry-operator/instrumentation.yaml
```

### 📚 Exemplos de Instrumentação

Você pode encontrar exemplos prontos de instrumentação na pasta `opentelemetry-operator`.

📂 Estrutura da pasta:

```
📂 opentelemetry-operator/
├── instrumentation.yaml  # Configurações de instrumentação para aplicações
├── values.yaml           # Valores padrão do Helm Chart do OpenTelemetry Operator
├── README.md             # Guia detalhado de uso e exemplos práticos
```

💡 **Dica:** Consulte o arquivo `README.md` dentro da pasta para mais informações e exemplos sobre como configurar a instrumentação no OpenTelemetry Operator.

---

### 6️⃣ Instalar os Componentes com Helmfile

Depois de configurar todas as credenciais e arquivos necessários, instale os componentes da stack usando o comando abaixo:

```bash
helmfile sync
```

---

## 🌐 Acesso ao Grafana

Utilize o Grafana já configurado pela **Elven Observability**:

🌐 [**Acesse o Grafana**](https://grafana.elvenobservability.com/)

Você precisará das credenciais fornecidas para acessar o painel.

---

## 📊 Recursos Instalados

Os seguintes componentes serão instalados e configurados no seu cluster:

1. **Prometheus**: Monitoramento e alertas 📊
2. **Promtail**: Coletor de logs 📜
3. **OpenTelemetry Operator**: Instrumentação automática para aplicações 🔧
4. **OpenTelemetry Collector**: Centralização de traces e métricas ⚙️

---

## 📝 Notas Importantes

1. **Configuração Inicial**: Certifique-se de criar as credenciais e ajustar os arquivos antes de executar o comando `helmfile sync`.
2. **Namespaces**: Certifique-se de definir corretamente os namespaces das suas aplicações no arquivo `instrumentation.yaml`.
3. **URLs e Tokens**: Substitua os valores `<SEU_TENANT_ID>` e `<SEU_API_TOKEN>` pelos fornecidos no momento da configuração.

---

## 🛠️ Suporte

Se encontrar dificuldades ou tiver dúvidas, abra uma issue neste repositório. Estamos aqui para ajudar! 😊

---
