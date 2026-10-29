# Changelog

## Unreleased — distribuição Elven modular

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
- Não há criação automática de Instrumentation em namespaces ou injeção de SDK nas aplicações. eBPF e integração OTLP não equivalem a spans internos/de negócio completos.
- Logs, métricas de host e profiles não são coletados de aplicações/nodes não selecionados no perfil. Profiles pprof exigem endpoints disponibilizados explicitamente.

### Evidência e release

- O diagnóstico original foi registrado em `docs/audit-baseline.md`.
- Resultados de teste, publicação das imagens e validações de plataforma precisam ser conferidos na evidência da revisão; a existência de um workflow não significa que ele executou com sucesso.
- Esta seção não declara uma release GA, publicação assinada, implantação em cliente ou ausência de impacto. Ver os gates em `docs/support.md`.
