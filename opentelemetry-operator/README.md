# 🎯 Instrumentando Aplicações

Depois de instalar o **OpenTelemetry Operator**, você precisa configurar a instrumentação para monitorar suas aplicações em namespaces específicos. A seguir, detalhamos os passos para realizar isso de forma simples e eficiente. 🌟

---

## ⚡ Passo 1: Criar o Arquivo de Instrumentação

Crie um arquivo chamado `instrumentation.yaml` com as definições de instrumentação necessárias. Um exemplo básico de configuração:

```yaml
apiVersion: opentelemetry.io/v1alpha1
kind: Instrumentation
metadata:
  name: instrumentation
  namespace: default # Substitua pelo namespace onde sua aplicação está
spec:
  exporter:
    endpoint: "http://opentelemetrycollector.monitoring.svc.cluster.local:4318"
  propagators:
    - tracecontext
    - baggage
  sampler:
    type: parentbased_traceidratio
    argument: "1"
```

---

## 🚀 Passo 2: Aplicar o Arquivo de Instrumentação

Aplique o arquivo no namespace onde suas aplicações estão rodando, utilizando o comando abaixo:

```bash
kubectl apply -f instrumentation.yaml
```

📌 **Resultado esperado**: Suas aplicações começarão a reportar traces para o coletor OpenTelemetry configurado no endpoint especificado.

---

## 🛠️ Passo 3: Adicionar Anotações para Instrumentação Automática

Para que suas aplicações sejam instrumentadas automaticamente pelo **OpenTelemetry Operator**, você precisa adicionar anotações específicas nos recursos de configuração (como `Deployments`, `StatefulSets` ou `Pods`).

Aqui estão exemplos de anotações por linguagem:

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
    

📝 **Dica**: Adicione essas anotações diretamente nos arquivos de configuração das aplicações (exemplo: `deployment.yaml`).

---

## ✅ Passo 4: Verificar a Instrumentação

Após aplicar as anotações, o **OpenTelemetry Operator** injetará automaticamente os agentes nas suas aplicações para coletar métricas e traces.

🎯 **Como verificar**:

1. Certifique-se de que os contêineres estão sendo executados com o agente do OpenTelemetry.
2. Verifique no seu **Grafana** ou sistema de monitoramento se os traces e métricas estão sendo enviados corretamente.

---

## 📝 Notas Adicionais

- **Namespace**: Certifique-se de que o `namespace` especificado no arquivo `instrumentation.yaml` coincide com o das suas aplicações.
- **Ajustes Avançados**: Para configurações mais específicas, consulte a documentação oficial do **OpenTelemetry Operator**.

---

✨ **Pronto!** Agora suas aplicações estão instrumentadas e integradas à stack de observabilidade. 🚀

---