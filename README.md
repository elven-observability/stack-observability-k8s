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
4. **Kustomize**: Para gerenciar recursos personalizados no Kubernetes 🌀
5. **Helmfile**: Se ainda não tiver instalado, use o comando abaixo:

```bash
curl -sL https://github.com/helmfile/helmfile/releases/download/v1.0.0-rc.7/helmfile_1.0.0-rc.7_linux_amd64.tar.gz | sudo tar -xz -C /usr/local/bin
```

---

## 🚀 Instalação: Passo a Passo

Siga a ordem correta de configuração para evitar problemas.

---

### 1️⃣ Configurar Credenciais no Prometheus

Crie uma `Secret` para armazenar as credenciais do tenant no Prometheus. Use o comando abaixo, substituindo `<SEU_TENANT_ID>` e `<SEU_BEARER_TOKEN>` pelos valores do seu ambiente:

```bash
kubectl create secret generic elven-observability-token \
  -n monitoring \
  --from-literal=tenantId=$(echo -n "<SEU_TENANT_ID>" | base64) \
  --from-literal=bearerToken=$(echo -n "<SEU_BEARER_TOKEN>" | base64)
```

---

### 2️⃣ Configurar o OpenTelemetry Collector

Edite o arquivo `otel-collector/secrets.env` para incluir as credenciais:

```
TENANT_ID=<SEU_TENANT_ID>
API_TOKEN=<SEU_API_TOKEN>
```

Depois, aplique a configuração do OpenTelemetry Collector:

```bash
kubectl apply -k otel-collector/
```

---

### 3️⃣ Configurar o Promtail

Edite o arquivo `promtail/values-promtail.yaml` para incluir suas credenciais:

```yaml
clients:
  - url: https://loki.elvenobservability.com/loki/api/v1/push
    headers:
      X-Scope-OrgID: <SEU_TENANT_ID>
      Authorization: "Bearer <SEU_API_TOKEN>"
```

Certifique-se de substituir `<SEU_TENANT_ID>` e `<SEU_API_TOKEN>` pelos valores corretos do seu ambiente.

---

### 4️⃣ Configurar o OpenTelemetry Operator

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

---

### 5️⃣ Instalar os Componentes com Helmfile

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