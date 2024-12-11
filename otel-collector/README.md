# ****📊 Configuração do OpenTelemetry Collector no Kubernetes****

Bem-vindo ao guia detalhado de configuração do OpenTelemetry Collector no Kubernetes. Neste guia, explicaremos como configurar o OpenTelemetry Collector no Kubernetes usando arquivos de configuração e boas práticas para gerenciamento de credenciais.

## **📋Pré-requisitos**

Antes de começar, você deve ter o seguinte:

- **`kubectl`** instalado e configurado para interagir com seu cluster Kubernetes.

## **🚦Passo 1: Preparação dos Arquivos de Configuração**

Certifique-se de que os seguintes arquivos estejam configurados corretamente em seu ambiente:

- **`collector-config.yaml`**
- **`collector-deploy.yaml`**
- **`collector-service.yaml`**
- **`kustomization.yaml`**
- **`secrets.env`**

## **📦Passo 2: Configurar o Arquivo de Coleta - `collector-config.yaml`**

O arquivo **`collector-config.yaml`** é fundamental para a configuração do OpenTelemetry Collector. Certifique-se de que ele esteja devidamente configurado. Este arquivo define como o OpenTelemetry Collector coleta, processa e exporta os dados de telemetria.

## ⏬**Passo 3: Implantar o OpenTelemetry Collector - `collector-deploy.yaml`**

O arquivo **`collector-deploy.yaml`** descreve a implantação do OpenTelemetry Collector no Kubernetes. Certifique-se de que este arquivo aponte para o arquivo de configuração apropriado.

## ⏩**Passo 4: Configurar o Serviço do OpenTelemetry Collector - `collector-service.yaml`**

O arquivo **`collector-service.yaml`** define o serviço do OpenTelemetry Collector no Kubernetes, expondo as portas necessárias para a comunicação.

## **🔄Passo 5: Configurar com Kustomize - `kustomization.yaml`**

O Kustomize é usado para automatizar a aplicação das configurações. Certifique-se de que o arquivo **`kustomization.yaml`** esteja configurado corretamente e aponte para os recursos e segredos corretos.

## **🛡Passo 6: Configurar as Credenciais - `secrets.env`**

O arquivo **`secrets.env`** contém as credenciais necessárias, como tokens de API, para a configuração do OpenTelemetry Collector. Certifique-se de adicionar as credenciais corretas ao arquivo.

Exemplo de configuração:

```bash
TENANT_ID=elven

API_TOKEN=token123456789
```

Lembre-se de que é uma boa prática manter essas credenciais em um cofre seguro e não commitar elas em repositórios públicos.

## **🖋Passo 7: Implantar no Cluster Kubernetes**

Agora você pode implantar o OpenTelemetry Collector no seu cluster Kubernetes com o seguinte comando:

```bash
kubectl apply -k .
```

Isso aplicará todas as configurações e segredos necessários para o OpenTelemetry Collector funcionar corretamente no seu ambiente Kubernetes.

## **✅Conclusão**

**📝**Com a configuração concluída, o OpenTelemetry Collector estará pronto para coletar e exportar telemetria no seu cluster Kubernetes. Certifique-se de manter suas credenciais em segurança e não cometê-las em repositórios públicos. Se você encontrar algum problema ou tiver sugestões, não hesite em contribuir!