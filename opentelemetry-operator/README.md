# OpenTelemetry Operator

Este projeto configura o OpenTelemetry Operator no Kubernetes para instrumentar automaticamente seus aplicativos com suporte a métricas, traces e logs.

## Instalação do OpenTelemetry Operator

Para instalar o OpenTelemetry Operator usando o Helm, você pode seguir os passos abaixo. Certifique-se de que o repositório Helm do OpenTelemetry esteja corretamente adicionado ao seu ambiente.

### Pré-requisitos

- Kubernetes Cluster
- Helm 3.x
- Namespace `monitoring` criado

### Passo 1: Instalar o Operator com Helm

Execute o seguinte comando para instalar o OpenTelemetry Operator no namespace `monitoring`:

```bash
helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
helm repo update

helm install opentelemetry-operator open-telemetry/opentelemetry-operator -f opentelemetry-operator/values.yaml -n monitoring
```

Isso irá instalar o Operator no namespace `monitoring`, com as configurações definidas no arquivo `values.yaml`.

## Instrumentando Aplicações

Depois de instalar o Operator, você precisa instrumentar os aplicativos que deseja monitorar em seus namespaces específicos. Para isso, é necessário aplicar um arquivo `instrumentation.yaml` em cada namespace que contenha os aplicativos que você deseja instrumentar.

### Passo 2: Aplicar Instrumentação no Namespace

Crie um arquivo `instrumentation.yaml` contendo as definições de instrumentação e aplique-o no namespace desejado. Exemplo de um `instrumentation.yaml`:

```yaml
apiVersion: opentelemetry.io/v1alpha1
kind: Instrumentation
metadata:
  name: instrumentation
  namespace: default # Defina o(s) namspace(s) onde sua app está
spec:
  exporter:
    endpoint: "http://opentelemetrycollector.monitoring.svc.cluster.local:4317"
  propagators:
    - tracecontext
    - baggage
  sampler:
    type: parentbased_traceidratio
    argument: "1"
```

Para aplicar esse arquivo, execute:

```bash
kubectl apply -f instrumentation.yaml
```

Isso irá configurar a instrumentação no namespace especificado, direcionando os traces para o endereço do seu coletor OpenTelemetry.

### Passo 3: Adicionar Anotações nas Aplicações

Para que os aplicativos sejam automaticamente instrumentados pelo OpenTelemetry Operator, você precisa adicionar as anotações adequadas nos Deployments, StatefulSets, ou Pods que deseja instrumentar.

Aqui estão algumas das anotações suportadas pelo OpenTelemetry:

- **Java**:
    
    ```yaml
    annotations:
      instrumentation.opentelemetry.io/inject-java: "true"
    ```
    
- **Node.js**:
    
    ```yaml
    annotations:
      instrumentation.opentelemetry.io/inject-nodejs: "true"
    ```
    
- **Python**:
    
    ```yaml
    annotations:
      instrumentation.opentelemetry.io/inject-python: "true"
    ```
    
- **Go**:
    
    ```yaml
    annotations:
      instrumentation.opentelemetry.io/inject-go: "true"
    ```
    
- **DotNet (C#)**:
    
    ```yaml
    annotations:
      instrumentation.opentelemetry.io/inject-dotnet: "true"
    ```
    

Essas anotações devem ser adicionadas aos arquivos de configuração das suas aplicações (Deployments, StatefulSets, etc.) para habilitar a instrumentação automática.

### Passo 4: Verificar a Instrumentação

Depois de aplicar as anotações, verifique se os contêineres de suas aplicações estão sendo instrumentados corretamente. O Operator irá automaticamente injetar os agentes do OpenTelemetry para coletar métricas e traces de suas aplicações.

---

## Suporte e Documentação

Para mais informações, consulte a documentação oficial.