# Segurança, credenciais e riscos residuais

## Defaults

O baseline mantém módulos de host/eBPF/profiles desabilitados, não instala CRDs/operadores/webhooks, usa TLS verificado para exportação e mTLS no gateway OTLP. Os componentes sem acesso especial executam como não-root, com filesystem somente leitura, `allowPrivilegeEscalation: false`, capabilities removidas e seccomp RuntimeDefault.

A CLI bloqueia instalação/upgrade/preflight de produção enquanto o lock não registrar `publicationStatus: verified` e as imagens selecionadas não coincidirem com repository/digest promovidos. A verificação criptográfica pertence ao procedimento de publicação/promoção descrito em supply chain; o gate de instalação não é uma nova execução de Cosign a cada pull nem uma política de admissão do cluster. Consumir revisão/tag aprovada e proteger a integridade do repositório/lock continuam necessários. `--development-images` é somente um override explícito de laboratório, não uma aprovação de segurança ou produção.

A NetworkPolicy vem habilitada e egress externo fechado. `networkPolicy.exportCIDRs`, `apiServerCIDRs`, `kubeletCIDRs` e `profileCIDRs` precisam conter somente os destinos aplicáveis e aprovados. DNS é necessário, mas descobrir um IP por DNS não autoriza egress irrestrito. A eficácia da política depende do CNI e do caminho real de tráfego/DNAT. Não apresentar render ou aceitação do objeto como prova de enforcement.

## Instalação versus runtime

| Identidade | Permissões necessárias |
|---|---|
| Responsável pela instalação | Ler identidade/inventário do cluster e autorização; gerenciar os recursos exatos da release e os Secrets selecionados no namespace. Módulos com ClusterRole exigem permissão para criar/bindar os papéis correspondentes. Não instalar usando credencial de runtime. |
| Gateway | Sem necessidade de descoberta Kubernetes ou leitura de Secrets pela API; credenciais montadas/injetadas pelo kubelet. |
| Collector de estado Kubernetes | List/watch/get apenas dos recursos necessários ao receiver. Não ler Secrets e não escrever workloads. Escopo de leitura e escopo de exportação não são conceitos equivalentes; revisar ambos. |
| Receiver kubelet | Acesso de leitura requerido para estatísticas e CA apropriada. Não usar `nodes/proxy` genericamente como substituto de uma análise de autorização. |
| Logs | UID 0 para arquivos CRI root-owned quando necessário; `/var/log/pods` somente leitura, sem socket do runtime nem escrita no host. Capabilities removidas. |
| Beyla | Acesso especial a processos/kernel; ver seção abaixo. Não recebe as credenciais SaaS de exportação do gateway. |
| Profiles | Sem token da API Kubernetes; alvos e certificados de cliente explícitos. |

Pré-flight não elimina a necessidade de revisão de um administrador. A CLI usa contexto explícito e UID esperado do namespace `kube-system` para impedir operações no cluster errado; um nome lógico amigável não basta como identidade.

## Credenciais fora dos values Helm

Tenant/token não devem aparecer em values, comandos literais, histórico de shell, exemplos, ConfigMaps, Git ou corpo de PR. Forneça `--tenant-file`/`--token-file`, ou `ELVEN_TENANT_FILE`/`ELVEN_TOKEN_FILE`, apontando para arquivos privados de origem confiável. Os nomes/chaves dos Secrets podem ser declarados; os seus valores não.

A CLI provisiona, quando necessário, `<release>-ingest` e `<release>-internal-tls` separadamente da release Helm e os retém no uninstall. O Secret de ingestão usa chaves `tenant-id` e `api-token`. O Secret interno contém a CA e os materiais de servidor/cliente esperados pelo chart. Não imprimir o conteúdo desses Secrets para diagnosticar readiness.

Para ExternalSecrets, SealedSecrets ou PKI já gerenciados, provisionar os nomes/chaves esperados e usar `--use-existing-secrets` após revisão de ownership. Os nomes customizados podem ser passados por `--credentials-secret` e `--tls-secret`; não confiar em um nome implícito de outro proprietário. Isso não transfere o gerenciamento desses recursos para a CLI nem autoriza sobrescrevê-los. O Kubernetes não fornece criptografia de dados em repouso automaticamente só por usar o tipo Secret; configure encryption-at-rest, acesso ao etcd, backups e RBAC na plataforma.

## TLS interno e exportação

O nome do gateway é `<release>-gateway.<namespace>.svc.<cluster-domain>`. A CLI rejeita `fullnameOverride` para não divergir do nome usado na PKI. Se `cluster.domain`, namespace ou release mudarem, revisar SANs e clientes. Secrets de TLS existentes passam por verificação de CA/cadeia, SAN do servidor, purpose, correspondência de chaves e validade mínima remanescente de 24 horas. Esse piso não substitui renovação antecipada. Não aceitar `insecure_skip_verify`, CA errada ou hostname incorreto como workaround.

Para kubelet, `modules.kubeletMetrics.endpointAddress` seleciona `ip` (padrão, com SAN de IP válido) ou `hostname` (nome do node, com SAN/DNS correspondente). Configure a CA real e a porta do serviço. `nodeAgent.hostAliases` pode fornecer mapeamentos explícitos revisados, como em um laboratório controlado, mas não é descoberta dinâmica de IP nem política de DNS para nodes efêmeros. Não há `serverNameOverride` fictício no receiver: se DNS/CA/SAN não fecharem, corrigir a plataforma ou manter o módulo desabilitado.

A geração inicial usa OpenSSL, não instala cert-manager e não cria emissores globais. A CA vale 365 dias; certificados de servidor/cliente, 364 dias. A validação é estrita e exige SAN, usos de chave e finalidade corretos. Registrar expiração, responsável e renovação antes de produção; não existe renovação automática implicitamente validada. O bootstrap guarda no Secret os materiais de servidor/cliente usados pela distribuição, não uma CA emissora gerenciada com serviço de renovação; a chave emissora temporária não é retida nem enviada ao cluster. Para gestão contínua de identidades/renovação, usar PKI externa aprovada e referências de Secrets revisadas. Tratar CA/chaves como credenciais críticas. Rotação exige janela planejada, período de confiança compatível, alteração coordenada de gateway/agents/clientes e read-after-write; nunca substituir uma CA às cegas com dados pendentes.

O gateway exige certificado de cliente para ingestão; conhecer o Service DNS não autoriza enviar OTLP. Para SDKs externos à distribuição, emitir/distribuir credenciais específicas e restringir namespaces/rede. Não reutilizar o token SaaS como certificado de cliente e não copiar chaves indiscriminadamente para todas as aplicações. mTLS autentica a conexão, não torna automaticamente confiáveis os atributos de serviço/tenant enviados por uma aplicação.

A exportação para a Elven usa HTTPS, validação do servidor e autenticação de ingestão. CA privada pode ser configurada em `exportTLS.existingCASecret`; não desabilitar validação. Credenciais de registry e credenciais de ingestão têm funções diferentes.

## eBPF: exceção explícita

Beyla fica desabilitado por padrão. Habilitar requer `modules.ebpf.hostAccessApproved`, workload/namespace explícitos e revisão dos nodes escolhidos. O piso conservador desta distribuição é Linux ≥5.11 com BTF; o mínimo upstream de 5.8 não é automaticamente a nossa matriz validada. Ainda falta captura real por kernel/runtime, incluindo lockdown, seccomp, AppArmor e admission.

O manifesto padrão para Beyla usa UID 0, hostPID e seis capabilities: BPF, PERFMON, SYS_PTRACE, DAC_READ_SEARCH, CHECKPOINT_RESTORE e NET_RAW, com seccomp/AppArmor Unconfined somente para esse container. NET_RAW permanece necessário ao filtro HTTP genérico, não só a network flows. `BEYLA_ENFORCE_SYS_CAPS=1` exige falha clara quando faltarem permissões. BTF é montado somente leitura; estado temporário fica em `emptyDir`. Não há hostNetwork, socket containerd ou volume de escrita no host. O Collector acompanhante não herda essas capabilities/exceções.

BPF/PERFMON permitem carregar/observar probes; acesso a processos, mapas e dados protegidos exige análise por plataforma. A [checagem upstream pinada](https://github.com/grafana/beyla/blob/v3.40.0/vendor/go.opentelemetry.io/obi/pkg/obi/os.go#L174-L248) não equivale a captura comprovada. Algumas políticas de uprobes/perf_event_paranoid podem exigir SYS_ADMIN, inclusive em EKS/AKS; ele e SYS_RESOURCE só entram por `modules.ebpf.additionalCapabilities` **e** `additionalCapabilitiesApproved: true`, após aprovação específica. Não há fallback automático, NET_ADMIN nem modo privileged. `privileged: false` não significa isolamento restrito ao namespace; não alterar sysctls/políticas globais para fazer o Pod passar.

A propagação por alteração de headers fica desabilitada. Isso reduz interferência e limita correlação distribuída automática. eBPF observa operações suportadas, não reproduz todos os spans internos, spans de negócio, filas, links de spans ou propagação de SDK. Preservação do SDK e do destino atual precisa ser medida no piloto.

## Dados sensíveis

`privacy.logBodyMode: strict` é o padrão conservador: texto arbitrário de logs não deve sair como conteúdo livre. O modo `redact` exige opt-in e revisão de amostras locais; regex de redaction não é garantia universal de remoção de PII, segredos, documentos ou payloads de negócio.

Dados devem ser tratados antes da fila de exportação do gateway. Ainda assim, arquivos originais do node, buffers upstream, checkpoints/fingerprints e dumps de diagnóstico podem conter dados sensíveis. Restrinja acesso ao storage e evite anexar manifests, logs de aplicações ou dumps brutos em tickets. Traces/profiles também podem conter nomes de operações, stack frames e atributos privados; revisar política por sinal, não apenas o body de logs.

Profiles pprof não passam pela transformação OTLP e podem conter frames/labels privados. Exigem `modules.profiles.dataPolicyApproved: true` além de targets/TLS explícitos. O módulo não oferece WAL durável nem sanitização universal de perfis.

A política conservadora também reduz texto livre/nome de operação e mensagens de erro nos traces. Links de spans, incluindo seus IDs, são removidos por padrão porque seus atributos não são sanitizados pela mesma transformação; preservar links requer `privacy.preserveSpanLinks` e `privacy.spanLinkAttributesApproved`, com revisão explícita. Os IDs primários trace/span/parent permanecem. Isso limita correlação assíncrona/batch; não apresentar o resultado como cópia integral dos SDKs existentes ou instrumentação completa de negócio. Datapoints de métricas usam allow-list operacional, não uma promessa de sanitizar qualquer label por regex.

## Riscos residuais e gates

- Compartilhar CPU, memória, I/O e kernel com aplicações continua podendo causar impacto, mesmo sem alterar Deployments do cliente.
- Capacidade finita e falhas permanentes podem perder telemetria; duplicação também é possível em retries.
- Policies, certificados, RBAC e imagens precisam ser verificados no ambiente-alvo; CI local não comprova as políticas do cliente.
- Assinaturas/SBOM/proveniência só são evidência quando geradas e verificadas para o digest entregue. Um Dockerfile ou workflow existente não basta.
- Acesso ao host/eBPF requer aprovação de segurança; namespace próprio não neutraliza essas permissões.

Ver [supply chain](supply-chain.md), [suporte e critérios de release](support.md) e [operação/diagnóstico sem vazamento](operations.md).
