# Hardening Elven — 03/11/2026

Linha candidata `1.0.0-rc.2`. Esta rodada acrescenta funcionalidades e fecha defeitos reproduzidos; não é uma declaração de GA, implantação em cliente, detecção universal de PII ou coleta de todo código de negócio. Merge de código, publicação assinada e aprovação de produção são etapas separadas.

## Implementação

- Processor próprio `elven_privacy` nos três sinais e no node agent: sanitização recursiva, texto/JSON úteis, IDs e links preservados, credenciais/PII básicas PT-BR/inglês e forma SQL sem valores sensíveis. Strict continua explícito. Profundidade máxima24 evita exceder limites comuns de recursão protobuf; limites excedidos/inputs desconhecidos falham com máscara, nunca com fallback cru.
- Elven Instrumentation Operator opcional, CRD-free e sem acesso à API no runtime: SDKs Elven por digest, opt-in por namespace/Pod/container, TLS verificado, mTLS SDK→gateway e nenhum tenant/token SaaS nas aplicações. Java17/21, Node22.15+ e perfil Node20 legado EOL; Python beta opcional. Não reinicia workloads existentes nem detecta todo SDK embutido numa imagem.
- Reserva atômica e recibo CAS do PVC: cluster, namespace/release, Secret UID, tenant hash, PVC e StatefulSet. Impede adoção implícita de filas e recusa troca de identidade também no rollback. Volumes retidos/interrompidos exigem recuperação manual, sem deleção automática.
- Guards de release/ownership, conflitos conhecidos de instrumentação, namespaces e coleta global kubelet. Subprocessos limitados; timeout mantém conclusão UNKNOWN e preserva recursos.
- Tags publicadas não podem ser sobrescritas silenciosamente. Hashes abrangem o módulo local completo e sua licença. BuildKit0.34.2 pinado após as correções de03/11; imagens/SDKs têm SBOM/proveniência/scans próprios.
- Identidade de produto Elven, exemplos históricos anonimizados, fontes e atribuições obrigatórias upstream preservadas.

## Evidência e fronteiras

A fonte e os artefatos precisam ser vinculados por digest. A imagem intermediária `bd2eb81…` passou o corpus inicial de13 logs, mas **falhou** no corpus ampliado de15 (senha com vírgula e payload composto). Esse digest não é aceito como imagem final; os escapes foram reproduzidos e corrigidos no scanner Go, com regressões. A aprovação requer build e execução do corpus15 na fonte corrigida, não transferência do PASS antigo.

Resultados já executados nesta rodada:

- Contratos Python com Helm4.3.1 e dependências pinadas:227 testes na rodada pré-CI, sem falhas/erros/skips; contagens adicionais devem ser conferidas no relatório final da revisão.
- Processor Go corrigido:92 testes/subcasos, race detector e fuzz de JSON/SQL; não substituem a prova de wiring no binário final.
- Operator Go:155 testes/subcasos, race/vet, AdmissionReview HTTPS, TLS negativos e JSONPatch append-only que não reemite envs privados existentes.
- Módulo de injeção:67 contratos, lint e7recursos válidos em cada schema1.35/1.36/1.37. Núcleo:23recursos por minor.
- SDKs/Operator:10scans por arquitetura sem High/Critical, sem ignorelist. Node atual/legado mantêm2Medium documentados; não são imagens declaradas livres de CVEs. Cópia real UID10001/rootfsRO/networknone: maior payload75,06MiB, dentro do volume128MiB desses digests.
- Kind arm64 do núcleo:25checks com CLI/PVC/3sinais/API/kubelet/CRI/TLS/RBAC/outage/replay/coexistência. A imagem intermediária e o contrato exato de rollback dessa execução ficam identificados no relatório; a nova imagem exige repetição.
- Kind arm64 SDK standalone:20checks, imagem Operator`2749ef30…`, quatro SDKs fixados. Java17/21 produziram HTTP server/client e JDBC SQL; Node22/20 produziram HTTP server/client; mTLS, target de sidecar, no-opt-in/namespace externo, conflitos e aplicação anterior preservada. Esse modo usa sink mTLS sintético, **não comprova sozinho** gateway/filas/privacy ou bootstrap integrado.

### Diagnósticos que não contam como PASS

O primeiro ensaio local foi interrompido por ENOSPC na VM Docker compartilhada. Não houve prune global nem remoção de dados alheios; os ensaios Kind passaram a usar VM Colima exclusiva, sem mudar o contexto global. As imagens/arquiteturas não executadas ficam pendentes até a CI correspondente.

O sink Python inicial lia só Content-Length e confirmava200 para requests Node chunked com corpo vazio. A correção foi comprovada mudando somente o sink: mesmos Pods, UIDs e restartCount0 passaram a entregar30spans por Node. TLS/DNS, `node:http` e suporte mTLS genérico foram testados e refutados como causas. O hardening de resource detectors Node para `env` evita descoberta cloud/processo, mas não foi a causa dessa falha de teste.

## Gates antes de liberar

1. Build/scan e execução do corpus15 no Collector final corrigido, com archive/digest e fonte registrados; repetir runtime arm64 no artefato final quando o build local não puder ser executado com segurança.
2. CI da revisão final, incluindo SDKs reais amd64 e lifecycle do Collector, e ensaio integrado das duas CLIs→SDKs→gateway/privacy→sink. Um Pod Ready, teste antigo, job cancelado ou parser permissivo não substitui esses gates.
3. Publicação, assinatura e promoção verificadas de ambos locks. Nesta candidata continuam `not-published`; não usar `--development-images` em clientes.
4. CNI efetivo, plataforma/CSI/admission real, captura eBPF por kernel/runtime, tenant do cliente e sizing/impacto. Gateway singleton; não há garantia de perda zero, HA ou exactly-once. Checkpoints CRI do agent são efêmeros, e profiles não passam pela política OTLP.

Consulte o [quickstart](../README.md), [guia de injeção](../charts/elven-instrumentation/README.md), [segurança](security.md), [operação/storage](operations.md), [migração](migration.md) e [supply chain SDK](instrumentation-supply-chain.md). A conclusão atualizada da CI deve ser conferida na PR; esta evidência não autoriza deploy em clientes.
