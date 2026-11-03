# Changelog

## 1.0.0 — imagens assinadas e promovidas

- Instalação opcional do núcleo e Operator por um único `./elven install/upgrade --instrumentation-values ...`, com validação local antes das escritas e estado parcial explícito em falha da segunda fase.
- Exemplo mínimo alinhado à privacidade seletiva; `strict` permanece uma escolha explícita.
- Verificação exata dos dois SPDX e do metadata assinados, persistida nos locks promovidos; publicador recusa repos/tag estrangeiros antes do primeiro push.
- Oito imagens públicas assinadas por GitHub OIDC, ambos locks e defaults promovidos. Tag de build imutável separada da revisão/pacote instalável; detalhes e limitações em `docs/release-v1.0.0.md`.
- Verificação pública independente por imagem e diagnóstico sem dados sensíveis para limites/erros do registry; histórico das revalidações de CI preservado, sem alegar que uma execução falha passou.

## Unreleased — distribuição Elven modular

### Hardening de 03/11/2026

- Processor Elven recursivo com sanitização seletiva de PII/credenciais e valores SQL antes da WAL, sem substituir por padrão todo o log. Links/correlação preservados após sanitização; strict segue disponível.
- Elven Instrumentation Operator opcional: webhook CRD-free, sem acesso de runtime à API, imagens SDK Elven por digest, namespaces/containers opt-in e prevenção de dupla instrumentação. SDKs não recebem tenant/token SaaS.
- Reserva atômica e recibo de identidade de PVC para impedir adoção/replay de WAL estrangeiro ou troca implícita de tenant; falhas preservam o volume.
- Publicação com proteção de tags imutáveis; BuildKit pinado após correções de segurança; metadados de arquitetura de laboratório deixam de presumir amd64 ausente.
- Identidade de produto exclusivamente Elven; exemplos de clientes anonimizados. Licenças, fontes e atribuições upstream obrigatórias preservadas.

### Arquitetura e segurança

- Novo caminho de instalação por CLI e chart próprio, com identidade de cluster, ownership por release e configurações modulares.
- Baseline sem instalação de Prometheus, cert-manager, OpenTelemetry Operator, CRDs ou webhooks. Não exige gateway/Prometheus do cliente para funcionar.
- Gateway OTLP com mTLS de entrada e HTTPS verificado para os destinos SaaS; credenciais provisionadas fora dos valores Helm.
- Gateway não-root com filesystem somente leitura, probes e fila persistente limitada por sinal. Módulos que acessam o host são opcionais e têm permissões separadas.
- Módulos próprios para coleta Kubernetes, logs de containers, eBPF e scrape de profiles pprof, com escopo explícito e limitações documentadas.
- Processo de imagens Elven com versões/digests, atribuição upstream, SBOM, análise de vulnerabilidades, proveniência e assinatura/verificação conforme infraestrutura disponível.
- Collector Elven mínimo via OCB, com componentes upstream explícitos e correção de dependência após o scan da imagem contrib completa; produção bloqueada até publicação/assinatura/promoção dos digests aprovados. `--development-images` é uma exceção apenas de laboratório.

### Mudanças incompatíveis

- O template anterior está em `legacy/v0/`, apenas como histórico. O comando antigo `helmfile apply` não é o instalador da nova distribuição.
- O Helmfile da raiz não possui releases/hooks; scripts shell legados exigem opt-in explícito e não são mecanismo de migração.
- Não há atualização automática sobre releases/recursos legados nem adoção de CRDs, operadores, posições ou storage de terceiros.
- Não há criação de CRDs Instrumentation nem injeção global implícita. A injeção Elven é opcional e selecionada; eBPF/SDKs não garantem spans internos/de negócio completos de qualquer aplicação.
- Logs, métricas de host e profiles não são coletados de aplicações/nodes não selecionados no perfil. Profiles pprof exigem endpoints disponibilizados explicitamente.

### Evidência e release

- O diagnóstico original foi registrado em `docs/audit-baseline.md`.
- Resultados de teste, publicação das imagens e validações de plataforma precisam ser conferidos na evidência da revisão; a existência de um workflow não significa que ele executou com sucesso.
- Esta seção não declara uma release GA, publicação assinada, implantação em cliente ou ausência de impacto. Ver os gates em `docs/support.md`.
