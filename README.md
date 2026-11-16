# Elven Observability para Kubernetes

Envie logs, métricas e traces do seu cluster para a Elven. A instalação não depende dos agentes ou do gateway que você já usa.

## Instalar com o kit da Elven

1. [Baixe o kit completo v1.0.0](https://github.com/elven-observability/stack-observability-k8s/releases/download/v1.0.0/elven-instalacao-v1.0.0.zip), [confira o checksum](kit/plataforma/PREPARAR.md#verificação-do-download) e extraia em uma pasta nova.
2. Preencha **plataforma/cliente.toml** usando o modelo do kit, junto da sua equipe de plataforma: cluster, tenant e namespaces/sinais aprovados. **Não coloque o token no arquivo.** Veja [Preparar a configuração](kit/plataforma/PREPARAR.md).
3. Na pasta extraída, em um terminal preparado com acesso ao cluster, rode:

   ```sh
   ./instalar
   ```

O instalador confere o ambiente, mostra o plano e pede confirmação antes de instalar. Se pedir o token, cole-o no terminal: ele não aparece na tela e fica em um Secret do Kubernetes. É reutilizado nas próximas execuções compatíveis, enquanto válido.

O ZIP inclui `./instalar` e o pacote da stack. A [fonte do kit](kit/COMECE-AQUI.md) também está neste repositório. Se precisar de ajuda, compartilhe só a mensagem de erro, sem token ou kubeconfig.

## O que acontece depois

A instalação não reinicia suas aplicações. Se a coleta de logs de containers for habilitada, ela fica limitada aos namespaces aprovados. A instrumentação de aplicações também exige seleção explícita.

Comece por um serviço piloto e confirme com a Elven que os sinais chegaram ao tenant certo antes de ampliar a coleta.

## Para a equipe de plataforma

O [guia técnico](docs/installation.md) cobre configuração e instalação pela CLI. Não use `helmfile apply` para esta versão.

[Operação](docs/operations.md) · [Segurança](docs/security.md) · [Migração do legado](docs/migration.md)
