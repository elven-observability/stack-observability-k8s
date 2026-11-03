# Refatoração e validação — 29/10/2026

## Veredito

Candidato `1.0.0-rc.1` implementado, com imagens Elven construídas localmente e testes positivos no laboratório. **Não é uma release GA nem deployment de cliente.** A CLI bloqueia instalação de produção até publicação, assinatura e promoção verificadas. Nenhuma credencial ou contexto de cliente foi usado.

Evidências sanitizadas:

- [95 testes, schemas e runtimes reais](evidence/2026-10-29/validation.json).
- [25 verificações Kubernetes reais no índice final](evidence/2026-10-29/kind.json).
- [Builds, SBOMs, scans, hashes e licenças](../images/validation-2026-10-29.json).
- [Versões oficiais, compatibilidade e advisories](versions.md).

Os arquivos grandes estão em `artifacts/images-minimal-licensed/` e `artifacts/images-wrappers-final/`, ignorados pelo Git. São OCI archives locais, **não** imagens disponíveis no Docker Hub. A evidência registra `dirtySource: true` e hashes dos inputs usados; esses artefatos de desenvolvimento não podem ser promovidos como release de fonte limpa.

## O que mudou e por quê

1. Legado preservado em `legacy/v0/`, com bloqueio dos 12 scripts antes de qualquer ação. Não há migração automática nem deleção para “abrir espaço”. [Diagnóstico](audit-baseline.md).
2. Chart próprio sem CRDs, operadores, webhooks, cert-manager ou dependência de agentes do cliente. Namespace/release/recursos globais têm fronteiras explícitas de ownership.
3. Gateway não-root, rootfs somente leitura, capabilities removidas, mTLS de entrada e HTTPS autenticado de saída. Credenciais ficam fora dos values/histórico Helm; chaves de servidor não são montadas nos agents.
4. CLI stdlib com contexto/UID explícitos, render offline, preflight não-mutante e validação de PKI, CIDRs, RBAC, storage e sobreposição de fontes Elven. Secrets/PVCs são retidos deliberadamente.
5. Métricas próprias por API Kubernetes/kubelet, leitura CRI sem SDK, eBPF e pprof opcionais. Escopo, permissões de host e policy de dados exigem opt-in; aplicações existentes não são alteradas.
6. Sanitização anterior à fila, `fsync`, retries transitórios sem expiração, capacidade finita e batching após persistência. Não há promessa de armazenamento infinito ou exactly-once.
7. Collector mínimo compilado com dependências corrigidas; builds multiarch, SPDX, proveniência, licenças, scans e gates de publicação/assinatura implementados.

Faro, MySQL exporter e auto-injeção antiga **não foram apresentados como módulos portados**. A [migração](migration.md) documenta essa quebra e as alternativas. Métricas nativas diferem dos antigos KSM/node-exporter; dashboards/regras precisam de revisão, não de promessa de equivalência.

## Versões e artefatos gerados

| Artefato | Origem selecionada | Prova local |
|---|---|---|
| Collector Elven mínimo | OCB/core 0.164.0; contrib 0.164.1; Go 1.27.3; go-jose 4.1.6; x/net 0.62.0 | Build/scan amd64 e arm64, Govulncheck dos dois binários; execução real arm64. |
| Elven eBPF | Beyla 3.40.0 | Build/scan nas duas arquiteturas; captura eBPF não executada. |
| Elven profiler | Alloy 1.21.3 | Build/scan nas duas arquiteturas; pprof HTTPS/mTLS/exportação autenticada em arm64. |
| Helm | 4.3.1 executado; 3.22.1 como ponte declarada | CLI real/Helm 4 no laboratório; não atribuir lifecycle real ao Helm 3. |
| Kubernetes | Alvos 1.35–1.37 | Schemas das três minors; lifecycle real somente Kind 1.37.0 arm64. |

Índices OCI locais exatos:

```text
elven-collector: sha256:02347a34e3ace128dec632e19b0abbb63f92d604dbe453f6ea970c557b872dff
elven-ebpf:      sha256:a792fc040ad08cb1921984d9dda29bda19240c258ac31f396b6a808a7da11071
elven-profiler:  sha256:53fa99c19d5587a468c0a4da18f8728059e3b26f14d675d5f9671363095442f5
```

O Collector completo upstream falhou com uma High e não recebeu exceção silenciosa. O build mínimo remove componentes desnecessários e corrige dependências. Os três artefatos finais tiveram **0 High/Critical em ambas as arquiteturas**, com Trivy 0.76.1 e DB da execução. Isso não significa “zero vulnerabilidades”: UNKNOWNs permanecem e o Alloy tem Medium/Low, com IDs/contexto e relatórios completos registrados, sem ignorelist.

Govulncheck 1.9.0 passou nos dois binários mínimos. O alerta OpenPGP no inventário x/crypto não apresentou símbolos vulneráveis; não é prova de ausência de vulnerabilidades desconhecidas. Foram conferidos por SHA **571 textos de licença/notice de 480 identidades módulo/Go**, extraídos da imagem final nas duas arquiteturas. SBOM/proveniência foram gerados; assinatura OIDC não foi executada localmente.

## Testes executados

| Verificação | Resultado |
|---|---|
| Contratos chart/CLI, PKI, probe, gates de imagem, CI e legado | **95 aprovados; zero falhas/erros/skips.** |
| Schemas Kubernetes estritos | **23/23 recursos válidos em cada minor 1.35, 1.36 e 1.37.** |
| Configs gateway, node e cluster-reader | Aceitas pelo binário Elven final **02347…**, sem rede, cap-drop e rootfs read-only. |
| Profiler próprio | Config aceita; scrape pprof mTLS e POST autenticado positivos. |
| Kind 1.37 arm64 | **25 checks aprovados** no índice final licenciado. |
| OCI/scans/licenças/proveniência | Construídos/inspecionados nos mesmos archives registrados; não publicados/assinados. |

A rodada Kind comprovou:

- Instalação limpa, CLI real preflight/status/upgrade e rejeição de nomes já pertencentes ao cliente, sem adoção.
- Entrega dos três sinais; sanitização de nome/status/events/links de spans.
- Rejeição de cliente sem mTLS, CA incorreta e Bearer incorreto no backend sintético. Falha TCP não foi contada como prova de erro de certificado.
- Métricas por API Kubernetes, kubelet com CA/SAN/DNS corretos e stdout CRI de aplicação sem SDK.
- RBAC de execução negando Secrets/escritas, com descoberta permitida só no namespace aprovado.
- HTTP 503 por 40 segundos seguido de entrega do registro original, sem exigir nova entrada.
- Inspeção do WAL com dados sanitizados e ausência das sentinelas privadas/token sintético.
- Recriação forçada do Pod com UID novo e mesmo PVC, seguida de replay.
- Upgrade com mudança de versão do chart/porta de health, config inválida rejeitada e rollback.
- Duas releases, sentinela e spec/UID de aplicação anterior preservados; uninstall retém os dois PVCs.

Clusters descartáveis e túneis foram encerrados. Não houve alteração de kernel/sysctl, execução eBPF no host Desktop ou interação com kubeconfig ativo de cliente.

A primeira rodada Linux amd64 concluiu 24 checks funcionais com a imagem upstream de desenvolvimento, mas falhou no teardown: Kind tentou gravar `/dev/null.lock` devido ao `KUBECONFIG` defensivo da CI. A correção usa o kubeconfig privado explicitamente também na remoção e preserva o relatório mesmo se o teardown falhar; seis regressões cobrem essa fronteira. A [rodada corrigida de validação](https://github.com/elven-observability/stack-observability-k8s/actions/runs/40910973670) passou: 95 testes em cada Python 3.12/3.14 e 24 checks amd64, incluindo teardown concluído. Isso não substitui o job separado com a imagem Elven construída/escaneada, que acrescenta a verificação de carregamento do OCI exato. A CI inclui explicitamente os relatórios em diretórios ocultos, sem enviar chaves/kubeconfigs. O build descarta somente o cache do builder descartável próprio, verificando novamente os hashes dos três archives. Conferir no PR a conclusão dos workflows da revisão atual; o primeiro job com falha não conta como CI verde.

## Instalação e migração

O [README](../README.md) contém quickstart completo: render offline, preflight sem apply, contexto/UID explícitos e credenciais em arquivos privados/Secrets externos. Instalação normal depende de imagens promovidas. `scripts/probe.py` envia três sinais sintéticos por mTLS e retorna trace ID correlacionado; indica explicitamente que aceitação pelo gateway não comprova ingestão no tenant.

A [operação](operations.md) cobre sizing, filas, health, diagnóstico, rotação, rollback e uninstall. A [migração](migration.md) exige baseline, dono por recurso/sinal, canary sem dupla ingestão, drenagem e cutover autorizado. Não aplicar por cima do Helmfile antigo nem remover CRDs/operadores do cliente.

## Pendências de produção

1. **Publicação/assinatura/promoção:** configurar Secrets GitHub `ELVEN_DOCKERHUB_USERNAME`/`ELVEN_DOCKERHUB_TOKEN` e environment com revisores obrigatórios. Executar a tag aprovada a partir de fonte limpa, verificar anonimamente imagens/blobs/assinaturas/attestations e atualizar lock/defaults juntos. [Procedimento](supply-chain.md). Produção continua bloqueada até concluir.
2. **CI remota:** workflows implementados; conferir conclusão no PR. Resultados locais não se transformam automaticamente em CI verde.
3. **amd64 nativo:** houve build, scan e análise binária; lifecycle nativo depende do job correspondente. Build multiarch/emulação não substitui a prova.
4. **CNI:** schema/render válidos, mas Kind padrão não comprova enforcement. Repetir conexões autorizadas/negadas em CNI com policy efetiva.
5. **eBPF:** falta captura por kernel/BTF/runtime/política real. Piso conservador ≥5.11; seis capabilities padrão, extras aprovados separadamente; nenhum fallback privileged.
6. **Plataformas/clientes:** EKS/AKS/RKE2, CSI/admission, serviços privados, tenant real, cobertura e estabilidade não foram aprovados pelo laboratório. 1.35/1.36 têm schema válido, não lifecycle real nesta rodada.
7. **Escala/HA/impacto:** sem benchmark de produção ou garantia de zero impacto. Gateway singleton é imposto nesta RC. Filas finitas, buffers upstream, erro permanente, disco cheio e rotação ainda podem perder dados; retries podem duplicá-los.
8. **Dados:** strict reduz texto/correlação; `redact`, links preservados e profiles têm riscos/opt-ins próprios. Revisar privacidade e utilidade antes de ampliar.

Não substituir esses gates por Pod Ready, HTTP 200, workflow escrito, limite configurado ou assinatura ainda não executada.
