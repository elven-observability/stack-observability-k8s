# Hardening Elven — 03/11/2026

Linha candidata `1.0.0-rc.2`. Esta rodada acrescenta funcionalidades e fecha defeitos reproduzidos; não é uma declaração de GA, implantação em cliente, detecção universal de PII ou coleta de todo código de negócio. Merge de código, publicação assinada e aprovação de produção são etapas separadas.

## Implementação

- Processor Elven `elven_privacy` nos três sinais e no node agent: sanitização recursiva de strings, mapas, arrays, JSON, atributos, resources, scopes, status, events e links. Preserva texto operacional útil e IDs de correlação; mascara credenciais/PII básicas PT-BR/inglês e valores sensíveis em SQL. O modo `strict` continua explícito. A profundidade máxima de 24 mantém headroom para os wrappers protobuf; limites excedidos e inputs não reconhecidos falham com máscara, nunca com fallback cru. Isso não constitui detecção universal de PII nem garantia de aceitação de todo payload pelo backend.
- Elven Instrumentation Operator opcional, CRD-free e sem acesso à API no runtime: SDKs Elven por digest, opt-in por namespace/Pod/container, TLS verificado, mTLS SDK → gateway e nenhum tenant/token SaaS nas aplicações. Java 17/21, Node 22.15+ e perfil Node 20 legado EOL; Python beta opcional. Não reinicia workloads existentes nem detecta todo SDK embutido numa imagem.
- Reserva atômica e recibo CAS do PVC: cluster, namespace/release, Secret UID, tenant hash, PVC e StatefulSet. Impede adoção implícita de filas e recusa troca de identidade também no rollback. Volumes retidos/interrompidos exigem recuperação manual, sem deleção automática.
- Guards de release/ownership, conflitos conhecidos de instrumentação, namespaces e coleta global kubelet. Subprocessos limitados; timeout mantém conclusão UNKNOWN e preserva recursos. Cleanup tem checagem estrita e entrada de kubeconfig explícita; falha de remoção não vira PASS.
- Tags publicadas não podem ser sobrescritas silenciosamente. Hashes abrangem o módulo local completo e sua licença. BuildKit 0.34.2 pinado após as correções de 03/11; imagens/SDKs têm SBOM/proveniência/scans próprios.
- Identidade de produto Elven, exemplos históricos anonimizados, fontes técnicas e atribuições obrigatórias upstream preservadas.

## Artefatos e prova do digest final

A imagem final exercitada localmente é `docker.io/elvenobservability/elven-collector:1.0.0-dev@sha256:34c6be1ccf08bbb6c81224c327f1b4ff77548b08602265896f3c05e3938d986b`, em Linux arm64. O Operator usado pelos testes SDK/integrados é `sha256:2749ef30d24e022739b8990ea40de35478e4b625170377ce516ef42642f23df2`; os digests completos dos SDKs constam nos JSONs de evidência.

A imagem intermediária `bd2eb81…` passou o corpus inicial de 13 logs, mas **falhou** no corpus ampliado de 15: senha com vírgula e payload JSON composto após prefixo humano. Esse PASS antigo não é aprovação do artefato final. Os dois vazamentos foram reproduzidos, corrigidos no scanner Go e cobertos por regressões; o corpus ampliado passou no digest `34c6be1…`.

Os [JSONs sanitizados desta rodada](evidence/2026-11-03/) preservam resultados, digests, config hashes, limites e hash do relatório de origem. Não incluem chaves privadas, valores de credenciais, caminhos privados da estação ou payloads brutos de fixtures.

## Resultados locais executados

| Rodada | Resultado efetivo | Evidência e limite |
|---|---|---|
| Contratos/schema finais | **241 testes**, sem falhas, erros ou skips; **23 recursos válidos em cada schema 1.35/1.36/1.37** | [Relatório final](evidence/2026-11-03/validation-final-contracts.json). Sem runtime nessa rodada; não transformar schema em compatibilidade live de todas as minors. |
| Runtime/render completo | 230 testes da rodada anterior às 11 regressões finais de cleanup, mesmos três schemas, **4 configurações reais** e profiles HTTPS/mTLS | [Relatório runtime](evidence/2026-11-03/validation-runtime-arm64.json). Collector final `34c6be1…`; Alloy profiles por digest. A fixture de profiles observou 2 scrapes mTLS e 1 POST autenticado, não retenção durável ou tenant real. |
| Privacidade final | Corpus de **15 logs**, métricas e traces; texto/correlação/link preservados; valores sensíveis conhecidos ausentes; segunda fronteira idempotente; WAL sanitizado/replay e strict explícito | [Relatório de privacidade](evidence/2026-11-03/privacy-final-arm64.json). PASS com cleanup concluído no Collector `34c6be1…`; não prova todos os dialetos SQL, PII universal, limites de produção ou SaaS. |
| Kind núcleo final | **25 checks**, `completed: true`, cluster não retido | [Núcleo arm64](evidence/2026-11-03/core-final-arm64.json). CLI/PVC, três sinais, API/kubelet/CRI, TLS/RBAC, outage/replay, upgrade, **CLI rollback com identidade de storage/tenant**, coexistência e uninstall com retenção. Kind 1.37.0 arm64; não é prova de CNI enforcement ou eBPF. |
| SDK standalone final | **20 checks**, quatro SDKs reais e Operator `2749ef30…`, cluster não retido | [SDK standalone arm64](evidence/2026-11-03/sdk-standalone-arm64.json). Java 17/21: HTTP server/client e JDBC SQL; Node 22/20: HTTP server/client. Sink mTLS direto, sem atribuir a essa rodada prova de gateway/WAL/privacy ou bootstrap das duas CLIs. |
| Cadeia integrada final | **22 checks**, `completed: true`, cluster não retido | [CLI → SDK → gateway arm64](evidence/2026-11-03/sdk-integrated-final-arm64.json). As duas CLIs reais criaram/revisaram PKI/ingest/recibo de PVC e PKI scoped; SDKs → mTLS → Collector `34c6be1…` selective → backend HTTPS com Bearer/tenant sintéticos. Spans observados: Java 17 = 15, Java 21 = 10, Node 20 = 6, Node 22 = 6. Não comprova cobertura de todos os spans ou aplicações privadas. |

Os ensaios SDK também verificaram target explícito de sidecar, ausência de injeção sem opt-in/em namespace externo, rejeição de runtime desconhecido/SDK conflitante/target ambíguo, proibição de ler Secrets pelo runtime e preservação de aplicações existentes. Os contadores de spans pertencem às fixtures e execuções identificadas, não a uma expectativa universal de cobertura.

Outras verificações da implementação: processor Go corrigido com 92 testes/subcasos e race detector; campanhas anteriores de fuzz de JSON/SQL orientaram regressões, sem substituir o teste da fonte final. Operator Go com 155 testes/subcasos, race/vet, AdmissionReview HTTPS, TLS negativos e JSONPatch append-only sem reemitir envs privados existentes. Essas verificações não substituem o wiring no binário final, comprovado separadamente acima. Actionlint e `git diff --check` passaram na revisão local final.

## CI observada e fronteira da revisão final

Os resultados abaixo pertencem ao head `67c44745583eed895d06678f3ce69715877242cb`, não são uma declaração antecipada de CI verde para qualquer commit posterior. O [registro sanitizado da observação](evidence/2026-11-03/ci-observed.json) mantém essa distinção.

- [SDKs/Operator amd64 — sucesso](https://github.com/elven-observability/stack-observability-k8s/actions/runs/41667783827): 20 checks de SDK standalone e 10 scans de SDKs sem High/Critical. O Operator foi `2749ef30…`. Node atual/legado mantêm Medium documentados; não são imagens livres de CVEs. Esse modo não é a cadeia integrada com o Collector final.
- [Contratos da distribuição — sucesso](https://github.com/elven-observability/stack-observability-k8s/actions/runs/41667783478): contratos e schemas com Python 3.12/3.14 na revisão observada. Não aprova por si só a configuração/runtime de outra imagem.
- [Núcleo — falha](https://github.com/elven-observability/stack-observability-k8s/actions/runs/41667783458): o corpus de 15 logs e os demais checks funcionais de privacidade amd64 passaram antes da falha de teardown com UID 1001; o estágio Kind foi skipped. **O workflow não passou e não conta como Kind amd64 aprovado.** Entrada por stdin e cleanup estrito foram corrigidos e receberam 11 regressões adicionais; a execução local arm64 final passou. A CI do head final ainda é um gate separado.

O status atualizado dos workflows da revisão final deve ser conferido na PR. Não editar este registro para converter uma execução anterior com falha/skipped em PASS, nem transferir sucesso de um digest para outro.

## Diagnósticos e limitações importantes

O primeiro ensaio local foi interrompido por ENOSPC na VM Docker compartilhada. Não houve prune global nem remoção de dados alheios; os ensaios Kind passaram a usar VM Colima exclusiva, sem mudar o contexto global. Os relatórios finais registram remoção dos clusters; isso não demonstra comportamento de CSI ou plataforma de cliente.

O sink Python inicial lia apenas Content-Length e confirmava 200 para requests Node chunked com corpo vazio. A correção foi comprovada alterando somente o sink: mesmos Pods/UIDs, sem restart, passaram a entregar spans. TLS/DNS, `node:http` e suporte mTLS genérico foram testados e refutados como causas. Resource detectors Node restritos a `env` evitam descoberta cloud/processo, mas não foram a causa dessa falha de teste.

No teste de profundidade, o limite anterior de 32 gerou wire depth 103 e o decoder OTLP protobuf do laboratório rejeitou por MaxDepth 100. O chart usa agora padrão/máximo 24. Isso é evidência de interoperabilidade com o decoder testado, não uma rejeição observada no SaaS. Limites do processor (24 níveis, strings de 262.144 bytes e até 4.096 itens por coleção) também não substituem limites de ingestão. Rever payloads e limites efetivos do tenant; erros definitivos do backend não se tornam retryable apenas por existir fila/WAL.

## Gates antes de liberar

1. CI do head final, incluindo lifecycle/teardown completos nas arquiteturas correspondentes. Os resultados locais finais acima fecham o gate local, não o da CI final nem toda a matriz de plataformas.
2. Publicação, assinatura e promoção verificadas de ambos os locks. Nesta candidata continuam `not-published`; não usar `--development-images` em clientes. Builds/scans locais e merge não equivalem a uma imagem promovida.
3. CNI efetivo, plataforma/CSI/admission real, captura eBPF por kernel/runtime, tenant do cliente e sizing/impacto. Gateway singleton; não há garantia de perda zero, HA ou exactly-once. Checkpoints CRI do agent são efêmeros, e profiles não passam pela política OTLP.
4. Python SDK continua beta e sem prova de compatibilidade de aplicação nesta matriz. Node 20 é exceção legada EOL, não recomendação para novas aplicações.

Consulte o [quickstart](../README.md), [guia de injeção](../charts/elven-instrumentation/README.md), [segurança](security.md), [operação/storage](operations.md), [migração](migration.md) e [supply chain SDK](instrumentation-supply-chain.md). Esta evidência não autoriza deploy em clientes.
