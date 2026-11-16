# Versões, compatibilidade e suporte

Seleção inicial do núcleo em **29/10/2026**; hardening de SDKs, Operator, tooling e novos scans em **03/11/2026**, com releases oficiais, manifests OCI e advisories públicos. As fontes consumíveis por automação são [`versions.lock.json`](../versions.lock.json) e o lock independente [`instrumentation.lock.json`](../instrumentation.lock.json). Tags nunca substituem os digests no deployment. Não usar `latest`.

## Pesquisa atualizada — 16/11/2026

Esta pesquisa não substitui os digests assinados da v1.0.0 nem aprova automaticamente uma atualização. O piloto SaaS usa as imagens Elven promovidas; as correções de chart/installer são uma candidata separada, não uma alteração silenciosa do ZIP publicado.

**Bloqueio de segurança confirmado em 16/11:** o novo scan nas duas arquiteturas encontrou High nas bases pinadas de eBPF e profiling da v1.0.0. O eBPF foi desabilitado no piloto; profiling nunca esteve habilitado. O Collector passou nesse gate, mas isso não certifica a instalação inteira. A candidata da CLI bloqueia os dois digests opcionais em `runtimeBlocks`, sem alterar os registros históricos de assinatura/promoção. **O ZIP v1.0.0 já publicado é imutável e não contém esse novo bloqueio: não habilitar eBPF/profiles nele.**

| Upstream verificado | Novidade / decisão |
|---|---|
| [OBI 1.0.0, 30/10](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases/tag/v1.0.0) | Primeira versão estável; configuração v2 e matriz de suporte precisam de qualificação própria. Métricas de runtime experimentais não viram substituto universal de SDK. |
| [Beyla 3.42.0, 12/11](https://github.com/grafana/beyla/releases/tag/v3.42.0) | A API oficial consultada em 16/11 retorna `prerelease=false`; as notas incluem atualização de x/net para 0.62.0 e correções de spans Go/propagação .NET. A imagem Elven publicada permanece no 3.40.0 e está bloqueada para nova habilitação. A sanitização SQL opt-in entrou na [3.41.0](https://github.com/grafana/beyla/releases/tag/v3.41.0); não habilitar captura de parâmetros/payload para obter mais detalhe. |
| [Alloy 1.22.0, publicado em 13/11](https://github.com/grafana/alloy/releases/tag/v1.22.0) | Atualiza x/net para 0.62.0, OTel 0.164.1 e profiling; contém mudanças incompatíveis em conectores/enrichment. Candidato, não evidência de correção de todos os pacotes da imagem. Exigir scan de SO e binário por arquitetura, configuração real e entrega pprof antes de assinar/promover. |
| [Collector 0.165.0, 07/11](https://github.com/open-telemetry/opentelemetry-collector-releases/releases/tag/v0.165.0) | Candidato a novo build mínimo Elven, não troca direta pelo contrib completo. Repetir regressões de privacy/WAL, SCA, SBOM, assinatura e gates nativos. |
| [Auto-instrumentação Node 0.83.1, 12/11](https://github.com/open-telemetry/opentelemetry-js-contrib/releases/tag/auto-instrumentations-node-v0.83.1) | Candidata; a imagem atual continua 0.82.0. Validar CJS/ESM, dependências e mTLS antes de promover. |
| [Java agent 2.33.1](https://github.com/open-telemetry/opentelemetry-java-instrumentation/releases/tag/v2.33.1) | Já é a base pinada e exercitada com Java 17/21. Python pinado 0.66b2/SDK 1.45.2 foi exercitado com Flask/sqlite3; continua beta. |
| [Operator upstream 0.163.0, 11/11](https://github.com/open-telemetry/opentelemetry-operator/releases/tag/v0.163.0) | Referência técnica atualizada; não é dependência de runtime do nosso webhook Elven mínimo. |

Arquitetura exercitada por sinal: SDK como autoridade de spans internos/runtime; eBPF complementar em deployments sem SDK; logs stdout por namespace aprovado; sanitização recursiva antes do WAL/export. O ensaio com SDK+eBPF no mesmo processo produziu traces paralelos sem correlação completa; o padrão da candidata exclui SDKs detectados e recomenda seletores disjuntos. A captura eBPF comprovada é histórica: o módulo está agora desabilitado até a correção de segurança. Não é seguro vender isso como “captura tudo”.

### Gate atual e contenção

O [CI 43900514132](https://github.com/elven-observability/stack-observability-k8s/actions/runs/43900514132) reconstruiu as mesmas bases upstream pinadas, sem publicar, e usou Trivy 0.76.1 com DB atualizada em **16/11 às 13:03 UTC**. São scans desses novos archives OCI, não um novo scan dos índices assinados históricos; os wrappers preservam os binários e pacotes upstream que motivaram o bloqueio preventivo daqueles digests.

| Base do módulo | High/Critical por arquitetura | Achados que bloquearam |
|---|---|---|
| Beyla 3.40.0 | 1 / 0 | [CVE-2026-78661 / GO-2026-6860](https://pkg.go.dev/vuln/GO-2026-6860): x/net 0.61.0; correção 0.62.0. |
| Alloy 1.21.3 | 3 / 0 | Mesmo x/net; [CVE-2026-109518 / USN-8996-1](https://ubuntu.com/security/notices/USN-8996-1) em `apt` e `libapt-pkg6.0t64` 2.8.3; correção Ubuntu 24.04: 2.8.4ubuntu0.1. |
| Collector mínimo Elven | 0 / 0 | Nenhum High/Critical nesse scan. Não é alegação de ausência de outros achados ou vulnerabilidades futuras. |

Contagens iguais em amd64/arm64. A presença de dependência vulnerável não demonstra exploração no perfil específico; também não é uma dispensa do gate. O pipeline corretamente não executou os testes posteriores de runtime/WAL/Kind do núcleo nem publicou imagens após a falha. O [pipeline SDK/Operator da mesma candidata](https://github.com/elven-observability/stack-observability-k8s/actions/runs/43900514508) passou seus scans nas duas arquiteturas e o ensaio nativo de injeção, sem publicar.

No SaaS, as 11 aplicações de laboratório permaneceram prontas após retirar apenas o Beyla do DaemonSet próprio. SDKs, logs, métricas e traces continuam no piloto; o node agent voltou a conter somente o Collector e não usa `hostPID`. Profiling permanece desligado. Assinaturas válidas continuam válidas como prova de origem, mas não autorizam usar os componentes bloqueados. Ver [recibo sanitizado do piloto](evidence/2026-11-16/saas-pilot.json).

Para ampliar os canários, foram selecionados [Go 1.27.3](https://go.dev/doc/devel/release), [.NET 10 LTS com servicing 10.0.15](https://dotnet.microsoft.com/en-us/platform/support/policy) e [PHP 8.5.12](https://www.php.net/downloads.php), com imagens de laboratório por digest e sem ingress público. Esses fixtures não equivalem a novos módulos de auto-injeção ou imagens SDK Elven promovidas. A [limitação documentada de sqlite3](https://opentelemetry-python-contrib.readthedocs.io/en/latest/instrumentation/sqlite3/sqlite3.html) requer cursor explícito; `connection.execute` não foi apresentado como caminho coberto.

## Runtimes selecionados

| Papel Elven | Upstream | Release | Justificativa / exceção |
|---|---|---|---|
| Collector | Elven mínimo: OCB/core **0.164.0**, contrib **0.164.1** | [core/artefatos de 26/10/2026](https://github.com/open-telemetry/opentelemetry-collector-releases/releases/tag/v0.164.0) | Exceção de segurança: o runtime completo oficial tem CVE High publicada após a release. Build com Go 1.27.3, go-jose 4.1.6 quando transitivo e x/net 0.62.0. O [patch contrib 0.164.1](https://github.com/open-telemetry/opentelemetry-collector-contrib/releases/tag/v0.164.1) corrige módulos OTTL; não presumir imagem oficial `:0.164.1`. |
| eBPF opcional | Grafana Beyla **3.40.0** | [26/10/2026](https://github.com/grafana/beyla/releases/tag/v3.40.0) | Versão selecionada no snapshot da v1.0.0, não a mais nova em 16/11. Um patch da série antiga 3.38.1 saiu depois: ordenar releases por data, sozinho, selecionaria a série errada. |
| Profiler opcional | Grafana Alloy **1.21.3** | [28/10/2026](https://github.com/grafana/alloy/releases/tag/v1.21.3) | Componentes nativos para pprof/eBPF. O runtime mantém suas dependências upstream integradas (OTel 0.162.0, Beyla 3.38.1), não substituídas manualmente. O chart usa o Beyla standalone quando habilitado. |

Os três manifests OCI upstream foram consultados anonimamente, incluindo `linux/amd64` e `linux/arm64`; seus digests estão no lock. **Isso não é execução nativa em ambas as arquiteturas.** Beyla/Alloy preservam os runtimes upstream. O Collector passa a ser build mínimo próprio devido ao achado de segurança, com receita pública/revisável, componentes pinados e informações de build incluídas na imagem.

Os archives OCI de desenvolvimento da rodada de hardening eram evidência local, não imagens publicadas. A [release v1.0.0](release-v1.0.0.md) posterior aponta para imagens Elven assinadas, fixadas pelos digests promovidos. O Collector upstream não contém o processor próprio `elven_privacy` e não é fallback compatível.

## SDKs e Operator Elven opcionais — 03/11/2026

O webhook de injeção é código Elven mínimo, sem CRDs/controllers externos ou cliente da API no runtime. As imagens SDK Elven preservam payloads, licenças e rastreabilidade dos agentes upstream pinados no lock independente:

| Perfil | Agente selecionado | Compatibilidade/limite |
|---|---|---|
| Java | 2.33.1-2, SDK 1.67.0 | Java 17/21; [release oficial](https://github.com/open-telemetry/opentelemetry-java-instrumentation/releases/tag/v2.33.1). Bibliotecas suportadas, não todos os métodos de negócio. |
| Node.js atual | 0.82.0-3, SDK 3.x | Node >=22.15; [release oficial](https://github.com/open-telemetry/opentelemetry-js-contrib/releases/tag/auto-instrumentations-node-v0.82.0). Não usar essa imagem em Node 20. |
| Node.js legado | 0.81.2-1, SDK 2.x | Node 20 >=20.6 somente com aprovação EOL explícita e imagem Elven separada. Não amplia suporte upstream ao runtime. |
| Python | 0.66b2-2, SDK 1.45.2 | Auto-instrumentation beta, libc/versão/bibliotecas devem ser validadas; desabilitado por padrão. |

O upstream Operator 0.162.0 foi pesquisado como referência de compatibilidade, não é instalado como dependência do módulo Elven. [Release e limitações oficiais](https://github.com/open-telemetry/opentelemetry-operator/releases/tag/v0.162.0). Injeção por si só não prova spans/queries úteis nem preservação das aplicações; conferir a evidência por runtime/digest.

BuildKit **0.34.2**, pinado por digest, incorpora as correções de segurança publicadas em 03/11. [Release oficial](https://github.com/moby/buildkit/releases/tag/v0.34.2). Cada builder de laboratório é isolado; a limpeza nunca usa prune global do Docker.

Nos scans SDK de 03/11, os dois perfis Node mantêm achados Medium **CVE-2026-118773** (`glob` 10.5.0) e **CVE-2026-118764** (`minimatch` 9.0.9). Permanecem visíveis, sem ignorelist ou override de majors npm não testado. O gate High/Critical não torna esses achados inexistentes; triagem/patch upstream e revalidação continuam necessários. Contagens, scanner/DB e demais achados ficam nos recibos da rodada.

## Mudanças upstream que afetam a arquitetura

- Alloy 1.21 passou a exigir `--stability.level=experimental` para `loki.write.wal.enabled=true`; sem a flag a configuração não carrega. O caminho de logs duráveis desta distribuição utiliza as filas persistentes do Collector, não esse WAL experimental. [Release 1.21.0](https://github.com/grafana/alloy/releases/tag/v1.21.0).
- Beyla foi doado ao OpenTelemetry como **OBI**. A revisão inicial consultou [0.15.2](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases/tag/v0.15.2), de 16/10/2026; a pesquisa de 16/11 já confirma **1.0.0**. A migração de código não torna os números/configurações intercambiáveis nem significa abandono do runtime Beyla atualmente publicado. [Aviso do projeto](https://github.com/grafana/beyla/blob/v3.40.0/README.md#important-update-for-current-and-future-beyla-contributors).
- Grafana Agent está EOL desde [01/11/2025](https://grafana.com/docs/agent/latest/); Promtail desde [02/03/2026](https://grafana.com/docs/loki/latest/send-data/promtail/). Não fazem parte da nova distribuição.
- Pyroscope [2.4.2](https://github.com/grafana/pyroscope/releases/tag/v2.4.2), de 26/10/2026, é o backend e usa AGPLv3. Não é necessário instalar esse backend no cluster cliente para exportar profiles com Alloy. As três imagens entregues usam projetos principais Apache-2.0; dependências mantêm suas próprias licenças.

## Matriz e limites

| Superfície | Política / requisito | Evidência necessária |
|---|---|---|
| Kubernetes novos clientes | Alvo mantido **1.35–1.37**; patches oficiais consultados: 1.35.10, 1.36.6, 1.37.2 | Render/schema não substituem install/upgrade/rollback nas distribuições reais EKS/AKS/GKE/RKE2/OpenShift. Ver o relatório de testes desta revisão para o subconjunto efetivamente executado. |
| Kubernetes legado | Exceção explícita, nunca suporte upstream implícito | 1.34 terminou suporte em 27/10/2026; versões anteriores, inclusive 1.28, são EOL. Compatibilidade do template antigo não comprova suporte da nova distribuição. |
| Helm | **4.3.1** recomendado; **3.22.1** como ponte | Helm 4.3 suporta Kubernetes 1.34–1.37. Testar comandos nas versões realmente utilizadas. Helm 3 recebe somente segurança até 10/02/2027. |
| Arquiteturas de entrega | Linux amd64 / arm64 | Build multiarch, scan por arquitetura e smoke nativo correspondentes. Emulação não é prova nativa. Windows não está incluído. |
| Beyla | Piso conservador da distribuição **Linux ≥5.11**, BTF e políticas aprovadas; upstream admite ≥5.8 com outras permissões | Seis capabilities padrão; SYS_ADMIN/SYS_RESOURCE exigem aprovação adicional quando necessários. Conferir BTF, lockdown, LSM/seccomp, runtime/protocolo; captura real continua pendente. |
| Propagação Beyla | Desativada por padrão | Headers HTTP exigem **≥5.17** e permissões/rede adicionais. Capturar spans não garante uma cadeia distribuída completa. |
| Profiles pprof | Endpoints pprof explicitamente selecionados | A aplicação precisa expor os perfis; não promete profiles em todos os runtimes sem instrumentação. |
| Profiles eBPF | **Fora dos módulos entregues nesta revisão**; requisitos upstream não são implementação no chart | Exigiria root/hostPID e capacidades específicas em um módulo separado, com validação própria. A opção profiles entregue coleta pprof, não profiling automático de todos os processos. |

Fontes: [releases Kubernetes](https://kubernetes.io/releases/), [patches oficiais](https://github.com/kubernetes/kubernetes/releases), [skew Helm](https://helm.sh/docs/topics/version_skew/), [EOL Helm 3](https://helm.sh/blog/helm-v3-end-of-life/), [Beyla/contexto](https://grafana.com/docs/beyla/latest/distributed-traces/), [profiler eBPF](https://grafana.com/docs/alloy/latest/reference/components/pyroscope/pyroscope.ebpf/). A página Kubernetes estava atrasada nos números dos patches: o lock usa as releases GitHub publicadas em 28/10/2026, sem confundi-las com a política de suporte das séries.

## Segurança e atualização

Ferramentas de release pinadas: **Trivy 0.76.1** ([21/10/2026](https://github.com/aquasecurity/trivy/releases/tag/v0.76.1)) e **Cosign 3.1.4** ([20/10/2026](https://github.com/sigstore/cosign/releases/tag/v3.1.4)). Ambas atualizam o toolchain Go para 1.27.3. A release Trivy registra mitigação do incidente eMudhra/CA; não usar silenciosamente as versões antigas instaladas na estação para o gate novo.

Advisories oficiais revisados incluem Collector [OIDC/chaves revogadas](https://github.com/open-telemetry/opentelemetry-collector-contrib/security/advisories/GHSA-xpvr-wrwx-rm99) (corrigido ≥0.160.0), [Prometheus receiver/dependência](https://github.com/open-telemetry/opentelemetry-collector-contrib/security/advisories/GHSA-8hxm-mxr2-qf9h) e [Azure auth replay](https://github.com/open-telemetry/opentelemetry-collector-contrib/security/advisories/GHSA-pjv4-3c63-699f); Helm [verificação de plugins fail-open](https://github.com/helm/helm/security/advisories/GHSA-q5jf-9vfq-h4h7) (corrigido em 4.1.4). A ausência de advisory publicado para um repo não prova ausência de CVEs na imagem.

**Bloqueio efetivamente encontrado no scan de 29/10/2026:** o wrapper Collector baseado no runtime oficial 0.164.0 contém `github.com/go-jose/go-jose/v4 v4.1.5`, afetado pela High **CVE-2026-116587 / [GHSA-mgcc-cww5-fp2q](https://github.com/advisories/GHSA-mgcc-cww5-fp2q)** (DoS no parsing de chaves RSA em JWK; correção 4.1.6). O advisory foi publicado em 27/10, após a imagem oficial. O gate foi executado com Trivy 0.76.1/DB atual e falhou, sem ignorelist. Os wrappers Beyla e Alloy não tiveram High/Critical nesse scan arm64. Isso não autoriza publicar/promover o Collector como release segura; uma nova base upstream corrigida ou build/mitigação formalmente revisado e retestado é necessário. Os relatórios completos e SPDX locais ficam em `artifacts/images/`; o scan não é prova de explorabilidade na configuração particular nem de ausência de vulnerabilidades futuras.

**Correção executada:** o Collector mínimo foi construído para `linux/amd64` e `linux/arm64`, com dependências pinadas e x/net 0.62.0 (corrige também CVE-2026-78661 e CVE-2026-97045). Os scans completos de ambas as arquiteturas passaram com **0 High/Critical**, sem waiver. O registro final de artefatos/digests locais fica em [evidência das imagens](../images/validation-2026-10-29.json); esses digests não são publicação no Docker Hub. Componentes upstream do manifest incluem estágios Alpha/Beta: versão estável do Collector não converte automaticamente cada componente em GA.

Permanece **1 achado de severidade UNKNOWN** no Collector mínimo: [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) para pacotes abandonados `golang.org/x/crypto/openpgp*`, sem versão corrigida. Não equivale a vulnerabilidade em todos os pacotes x/crypto. `govulncheck 1.9.0` analisou os símbolos de **ambos os binários reais**, com saída 0 e sem símbolos vulneráveis identificados. É evidência de código vulnerável não presente na análise estática, **não** prova de ausência de vulnerabilidades ou de execução nativa amd64; o UNKNOWN continua visível no relatório, sem ignorelist.

**Resultado histórico de 29/10, superado pelo scan de 16/11 acima:** os wrappers finais Beyla e Alloy foram construídos/escaneados nas duas arquiteturas, com **0 High/Critical** por arquitetura naquele momento. Havia 3 UNKNOWN no Beyla; no Alloy, 22 Medium, 4 Low e 3 UNKNOWN por arquitetura. Os UNKNOWN incluíam **CVE-2026-78661**, **CVE-2026-97045** (x/net HTML, corrigidas no Collector mínimo mas ainda presentes nos wrappers upstream) e **GO-2026-5932**. O novo scan classifica CVE-2026-78661 como High e inclui o novo advisory APT. Não houve análise de símbolos dos wrappers nem patch manual de seus binários. A validação local histórica executou o Collector e o profiler em arm64, inclusive entrega pprof HTTPS autenticada; o piloto SaaS posterior capturou HTTP eBPF em amd64 antes da contenção. Nada disso converte o gate atual bloqueado em aprovado.

Cadência Elven: revisar patches/advisories semanalmente; triagem de Critical em até um dia útil e High em até três; publicar correção somente após reprodução/regressão/gates, com prazo e mitigação comunicados caso bloqueados. A linha v1 mantém um lock publicado por release; não há suporte automático a versões arbitrárias do upstream. Minor/breaking change exige novo piloto e migração explícita. Cada atualização atualiza lock, Dockerfiles, SBOM, scans, assinatura, compatibilidade e exemplos juntos. Nunca trocar digest sob uma tag previamente promovida. Ver [supply chain](supply-chain.md).
