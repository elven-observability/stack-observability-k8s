# Suporte, compatibilidade e critérios de release

Data de referência: 29/10/2026. A distribuição é um candidato da linha 1.0. Versão aceita pelo schema, requisito upstream, teste de laboratório e suporte comprovado em uma plataforma são categorias diferentes.

**Não está liberada para instalação de produção enquanto a publicação/assinatura/promoção das imagens Elven permanecer pendente.** A CLI exige lock `verified` e correspondência dos repository/digests selecionados; não faz fallback para contrib upstream ou `latest`. `--development-images` existe somente para ensaio explicitamente aceito e não amplia o suporte declarado. Recuperação de uma release já instalada não depende desse gate nem da disponibilidade do SaaS.

## Matriz declarada

| Dimensão | Escopo desta linha | Limite |
|---|---|---|
| Kubernetes | Minors 1.35, 1.36 e 1.37, com patch estável de segurança | O chart/CLI rejeitam novas instalações fora da faixa. Não é afirmação de teste em cada patch/provedor. |
| Helm | 4.3.1+ preferido; 3.22.1+ como ponte de compatibilidade | Versões mais novas da mesma major precisam de CI/revisão; um limite mínimo não comprova toda versão futura. |
| CLI local | Python 3.11+, kubectl compatível, OpenSSL para gerar PKI inicial | Sem dependencies pip; o acesso/credencial Kubernetes é fornecido pelo operador humano. |
| Gateway e módulos sem eBPF | Linux amd64/arm64 conforme imagens e compatibilidade de plataforma | Verificar manifests multiarch e testes do digest entregue. Não há suporte Windows declarado para os agents desta linha. |
| eBPF/Beyla | Piso desta distribuição Linux ≥5.11, BTF, arquitetura suportada, permissões/admission aprovadas | O mínimo upstream 5.8 não é nossa validação. Captura por kernel/runtime segue pendente; capacidades adicionais exigem aprovação específica, sem fallback privileged. |
| Storage | StorageClass/CSI que ofereça o PVC RWO e permissões necessárias ao gateway | Validar persistência, fsync, expansão, recuperação e retenção no CSI real. |
| NetworkPolicy | CNI com enforcement e destinos/portas efetivos revisados | Objeto aceito não demonstra enforcement, DNS/DNAT ou ausência de bypass pela plataforma. |
| Profiles | Alvos pprof HTTPS/mTLS explícitos | Não instrumenta automaticamente Java/Python/Node nem instala pprof na aplicação. |

AKS, EKS, GKE, RKE2, OKE, OpenShift, Fargate, nodes ARM, hardening corporativo e meshes têm particularidades. Não tratar essa lista como provedores já homologados. Fargate/serverless e clusters sem acesso a arquivos/processos do host não suportam os módulos de host apenas porque aceitam o gateway.

As versões de componentes, datas de release, digests e exceções upstream são registradas em [versions.md](versions.md). As exceções de imagens/mirrors, publicação, assinatura e advisories ficam em [supply-chain.md](supply-chain.md).

O runtime Collector entregue é uma distribuição mínima construída por OCB, com componentes selecionados e dependências pinadas/corrigidas; não oferece todo receiver/exporter/processador do pacote contrib completo. Copiar uma configuração antiga pode falhar por componente ausente ou nome canônico alterado. A validação precisa usar o binário Elven exato, incluindo os nomes `file_log`, `kubelet_stats` e `otlp_http` quando aplicáveis.

## Evidência: o que pode ser afirmado

| Nível | Evidência exigida | O que não comprova |
|---|---|---|
| Estático | Schema/Helm, manifests, RBAC, policies, portas e ausência de recursos globais inesperados | Runtime, admissão, enforcement de rede ou ingestão. |
| Runtime de componente | Configuração aceita pelo binário/imagem pinados; entrega sintética positiva; falhas/recovery/privacy | Descoberta real de workloads, eBPF, CSI ou workload do cliente. |
| Kubernetes isolado | Instalação limpa, upgrade, rollback, restart com PVC, permissões insuficientes e coexistência | Nuvem privada, escala de produção, tenant real ou impacto em aplicação privada. |
| eBPF real | Captura positiva com kernel/BTF/capabilities/runtimes identificados e preservação do SDK atual | Cobertura universal ou tracing distribuído completo. OTLP sintético não substitui captura. |
| Aceite no cliente | Identidade real, política/admissão/rede/storage, sinais e fontes esperados no tenant, privacidade e baseline de impacto | Rollout para alvos não exercitados ou garantia permanente sem monitoramento. |

No diagnóstico do legado foram executados apenas `bash -n` dos scripts e montagem local por Kustomize. Os novos testes precisam registrar comandos, revisão/digest, resultados, plataforma e limitações. Workflows escritos, jobs que não iniciaram por billing/permissão, testes skipped e builds planejados não contam como sucesso.

Uma atualização deve manter os exemplos compatíveis com os templates/schema, incluir testes de parâmetros inválidos e preservar a fronteira de ownership. A revisão não deve importar resultados históricos de Cappta, EmiteAI, WeHandle ou outro cliente como evidência da distribuição nova.

## Gates para GA/publicação de produção

Antes de declarar uma release GA pronta para rollout, registrar explicitamente:

1. Versões estáveis verificadas nas fontes oficiais, compatibilidade entre componentes e triagem de advisories/CVEs na data da release.
2. Builds/artefatos imutáveis Elven, SBOM, proveniência e assinatura gerados e verificados para os digests entregues; bases/licenças/atribuições preservadas.
3. Scan de imagem/configuração e triagem documentada de vulnerabilidades exploráveis; nenhuma exceção crítica sem dono, justificativa, mitigação e validade.
4. Instalação limpa, update e rollback com TLS/Secrets fora do Helm, PVC/WAL preservados e confirmação de sinais originais após falha transitória.
5. Coexistência real ou fixtures representativas com agentes/operadores do cliente, sem adoção de recursos, dupla exportação ou conflito de host. Declarar o que foi simulado e o que foi real.
6. Testes negativos: configuração inválida, contexto/UID incorreto, ownership alheio, permissão insuficiente, CA/SAN incorretos e destino indisponível. Erros devem ocorrer sem exibir segredos.
7. Matriz de plataforma e kernels efetivamente exercitados; eBPF só é aprovado nas combinações comprovadas. Não usar um chart renderizado para declarar BTF/captura funcionando.
8. Piloto autorizado com consumo/latência/cobertura reais e capacidade de storage/rede, antes de ampliação no cliente.
9. Responsáveis por operação, rotação TLS, atualização de CIDRs, incidentes, retenção, rollback e correções de segurança.

Se uma infraestrutura estiver indisponível, a entrega deve nomear o gate pendente e o procedimento para concluí-lo. Não criar badges ou texto “validated/secure/production-ready” para um gate não executado.

## Política de manutenção da distribuição

- A intenção de suporte é a minor atual da distribuição (N) e a imediatamente anterior (N−1), enquanto suas dependências upstream estiverem dentro da política de segurança compatível. Esta política não estende o suporte upstream de Kubernetes, Helm ou kernels.
- Correções de segurança e bugs compatíveis devem usar patch releases com changelog e repetição dos testes afetados. Upgrade de minor/dependência que mude configuração, storage, permissões ou semântica exige migration notes.
- Revalidar versões, digests e advisories em cada release e em revisão periódica. “Era o stable mais recente em outubro” não é uma política de manutenção contínua.
- Vulnerabilidades devem ser priorizadas por explorabilidade/contexto, não somente por contagem de CVEs. Registrar prazo, responsável e exceção quando a correção depender de upstream/cliente.
- Não modificar ou substituir um digest já publicado; publicar nova versão e preservar rastreabilidade. Tratar rotação de chave/identidade de assinatura como mudança operacional.
- SLAs, plantão e prazos comerciais precisam ser acordados separadamente. Este repositório não cria compromisso comercial de resposta ou garantia de ausência de perda/impacto.

O legado v0 está fora dessa linha de suporte, bloqueado por padrão e disponível apenas para análise/recuperação histórica revisada. Não há backport automático nem autorização para executar seus scripts em clientes.
