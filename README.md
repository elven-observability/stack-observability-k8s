# Elven Observability para Kubernetes

Envie logs, métricas e traces do seu cluster para a Elven. A instalação não depende dos agentes ou do gateway que você já usa.

## Instalar com o kit da Elven

1. Peça à Elven o **kit preparado para o seu cluster**. A Elven e sua equipe de plataforma configuram o tenant e combinam o que entra no piloto.
2. Na pasta do kit extraído, abra um terminal com acesso ao cluster e rode:

   ```sh
   ./instalar
   ```

3. Se for solicitado, cole o token Elven recebido por canal seguro. O token não aparece na tela e fica em um Secret do Kubernetes. Enquanto o instalador puder reutilizar esse Secret, não pede o token de novo.

O comando `./instalar` vem no **kit entregue ao cliente**. Ele não está neste repositório nem no pacote público da release. Se precisar de ajuda, compartilhe apenas a mensagem de erro, sem o token.

## O que acontece depois

A instalação não reinicia suas aplicações. Se a coleta de logs de containers for habilitada, ela fica limitada aos namespaces aprovados. A instrumentação de aplicações também exige seleção explícita.

Comece por um serviço piloto e confirme com a Elven que os sinais chegaram ao tenant certo antes de ampliar a coleta.

## Para a equipe de plataforma

O [guia técnico de instalação](docs/installation.md) explica como preparar o kit ou instalar a [release v1.0.0](https://github.com/elven-observability/stack-observability-k8s/releases/tag/v1.0.0) diretamente pela CLI. Não use `helmfile apply` para esta versão.

[Operação](docs/operations.md) · [Segurança](docs/security.md) · [Migração do legado](docs/migration.md)
