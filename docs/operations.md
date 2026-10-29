# Instalação, dimensionamento e operação

## Contrato da CLI

| Comando | Efeito |
|---|---|
| `./elven version` | Versão local da distribuição. |
| `./elven render` | Render offline; sem cluster, Secret real ou geração de PKI. `--output` cria arquivo privado novo. |
| `./elven preflight` | Leituras de identidade/compatibilidade/configuração/autorização, storage/egress e gate de imagens promovidas; não aplica recursos nem relaxa políticas. |
| `./elven install` | Provisionamento inicial de recursos próprios e reconciliação Helm, somente com imagens promovidas/verificadas. |
| `./elven upgrade` | Reconciliação revisada da linha atual e gate de imagens; não migra chart legado automaticamente. |
| `./elven status` | Estado dos recursos próprios; não prova a entrega no backend. |
| `./elven rollback --revision N` | Rollback Helm para revisão positiva explicitamente escolhida. Formato de storage e credenciais exigem compatibilidade. |
| `./elven uninstall` | Remove a release; retém namespace, Secrets e PVCs do gateway. |

Operações online usam `--context` explícito. Operações mutantes exigem `--expect-cluster-uid`, conferido pelo UID de `kube-system`; instalação/upgrade usam também `--cluster-name`. O nome lógico serve para identificar a telemetria; não substitui o UID como proteção contra contexto incorreto. `--kubeconfig` pode selecionar um arquivo específico. Não use comandos antigos como fallback automático para falha do preflight.

`status`, `rollback` e `uninstall` obtêm a configuração da ConfigMap de settings da release instalada, verificando ownership Helm; não dependem do arquivo values original, do render atual, da disponibilidade dos backends ou de Secrets válidos. O nome lógico instalado é recuperado; se um `--cluster-name` for fornecido e divergir, a CLI rejeita. Isso preserva o caminho de recuperação mesmo com o SaaS indisponível ou a PKI expirada.

Nesta revisão candidata, `publicationStatus` ainda não é `verified`: `preflight/install/upgrade` de produção permanecem bloqueados. O mantenedor precisa concluir a promoção de imagens assinadas descrita em [supply chain](supply-chain.md), com repository/digest selecionados iguais aos aprovados. O `helmfile.yaml` da raiz não contém releases ou hooks; não é uma segunda via de instalação sem esse gate.

Use `--help` para a interface completa. Os exemplos abaixo usam release `elven`, namespace `elven-observability`, domínio `cluster.local` e as variáveis preparadas no README. Se alterar esses parâmetros, ajuste comandos, certificados, clientes e consultas de diagnóstico.

## Preparação e perfis

Antes de instalar, conferir:

1. Contexto, UID, minor Kubernetes suportada, Linux/arquitetura dos nodes e quotas/limites do namespace.
2. StorageClass e política de retenção do PVC. `gateway.persistence.enabled: true` é o padrão; não trocar para `emptyDir` para contornar erro de provisionamento em produção.
3. Destinos reais HTTPS, DNS, proxy/firewall e CIDRs de egress. Allow-lists de IP precisam de manutenção quando o DNS do SaaS mudar. Confirmar também Service/API após DNAT e CA/porta do kubelet, quando usados.
4. Credenciais e certificados privados, origem/ownership dos Secrets e validade da PKI. O install pode reaproveitar Secrets próprios existentes; trocar somente os arquivos locais não é um comando de rotação automática.
5. Sinais, namespaces/workloads/nodes autorizados. Revisar agentes e exportações existentes para evitar dupla ingestão, loops ou dupla leitura de perfis.
6. Segurança/admissão: não relaxar PSA/AppArmor/seccomp globalmente. Aprovar exceções mínimas para os módulos de host/eBPF ou manter esses módulos desligados.

Para ensaio explicitamente aceito em um cluster descartável, `--development-images` permite usar o Collector Elven mínimo corrigido e os artefatos/values locais gerados pelo teste. Não é uma aprovação da imagem upstream completa que falhou no scan, nem deve acompanhar operações em cliente. Os demais guards continuam valendo.

O perfil mínimo recebe OTLP de fontes explicitamente configuradas e coleta a telemetria interna do gateway. Não cria instrumentação em aplicações. Habilitar coleta própria Kubernetes exige ajustar o exemplo correspondente; habilitar profiles exige endpoints pprof e Secrets de TLS dos alvos, sem os quais não há coleta.

## Parâmetros essenciais

O contrato completo está em `charts/elven-observability/values.yaml` e no schema do chart; ambos devem ser revisados ao atualizar. Não inserir tokens em nenhum desses campos.

| Grupo | Parâmetros relevantes |
|---|---|
| Identidade | `cluster.name`, `cluster.environment`, `cluster.domain`; release/namespace da CLI. |
| Imagens | `images.<componente>.repository/tag/digest`, `imagePullSecrets`; preferir artefato promovido/verificado. |
| Ingestão/PKI | `credentials.existingSecret`, `tls.existingSecret`, `exportTLS.existingCASecret`. |
| Destinos | `endpoints.logs/metrics/traces/profiles`, sempre HTTPS validado. |
| Gateway/storage | `gateway.resources`, `gateway.persistence.enabled/size/storageClass`, `gateway.queueSizeBytes`, `gateway.terminationGracePeriodSeconds`. |
| Escopo | `collection.namespaces`, `modules.*.enabled`, aprovações de host e workloads/targets explícitos. Estado cluster-wide sem namespaces exige `modules.clusterMetrics.clusterWideApproved: true`. |
| Recursos opcionais | `nodeAgent.resources`, `clusterMetrics.resources`, `profiles.resources`, selectors/tolerations e `nodeAgent.hostAliases` revisados. |
| Rede/portas | `ports`, `modules.kubeletMetrics.port`, `networkPolicy.*CIDRs`, `apiServerPorts`, `profilePorts`. |
| TLS kubelet | `modules.kubeletMetrics.endpointAddress` (`ip` ou `hostname`), `caFile`, `caSecretName`; o endereço precisa coincidir com SAN e resolver corretamente. |
| Privacidade | `privacy.logBodyMode`: `strict` por padrão; `redact` é exceção revisada, não garantia de PII zero. `privacy.preserveSpanLinks` exige aprovação separada de atributos de links. |
| Telemetria interna | `selfMonitoring.enabled/interval` para os Collectors; verificar séries locais e no tenant. O endpoint operacional Alloy profiles não implica exportação automática de seus próprios indicadores. |

A CLI rejeita `fullnameOverride` para manter o contrato de nomes/PKI. Nomes externos de Secrets usam `--credentials-secret`/`--tls-secret` com `--use-existing-secrets`; não usá-los nem mudar o domínio do cluster para contornar colisões sem conferir ownership/SANs. Para instalações paralelas, preferir outra release/namespace e PKI/Secrets próprios; não compartilhar WAL, PVC ou posições de agents.

A inspeção de claims das releases Elven detecta sobreposição em DaemonSets/Deployments identificados e falha se não conseguir conferir esse inventário. `--allow-overlapping-collection` só deve ser usado após revisão explícita de fontes, destinos e duplicação, como em um ensaio de coexistência; não é deduplicação ou garantia de descobrir agentes de terceiros. `--allow-unrestricted-network` é uma exceção explícita para política de rede externa revisada, não a correção recomendada para egress ausente.

## Dimensionamento inicial

Valores de configuração, não consumo medido:

| Unidade | Request CPU/RAM | Limit CPU/RAM |
|---|---|---|
| Gateway | 100m / 128Mi | 1 CPU / 512Mi |
| Collector de node | 100m / 128Mi | 500m / 256Mi |
| Beyla, quando habilitado | 100m / 128Mi adicionais por node | 500m / 256Mi adicionais por node |
| Coletor de estado Kubernetes | 100m / 128Mi | 500m / 256Mi |
| Profiles | 100m / 128Mi | 500m / 256Mi |

Conferir o manifesto renderizado para sidecars e módulos habilitados, inclusive Beyla. Collector de node + Beyla reservam 200m/256Mi e somam limites de 1 CPU/512Mi por node com os valores acima. Um DaemonSet multiplica sua reserva por node elegível; limites de containers não incluem todo o trabalho dos probes no kernel. Cardinalidade, volume de logs, RPS, número de processos, targets pprof e métricas do cluster alteram CPU/RAM/I/O. Não reaproveitar benchmarks de templates/clientes anteriores como prova desta revisão.

Começar em escopo pequeno, com baseline de aplicações e telemetria existente. Medir p95/p99 e erros das aplicações, CPU, throttling, memória, OOMs, I/O/fsync, volume usado, tamanho/capacidade da fila e taxa de exportação. Reduzir requests não reduz automaticamente o trabalho; limites apertados podem adicionar perda/backpressure.

O gateway singleton não é HA. `gateway.pdb.enabled` não cria redundância; indisponibilidade e manutenção precisam de janela/retentativa upstream. Aumentar réplicas dos módulos de scrape sem eleição/sharding pode duplicar coleta e não está aprovado como configuração HA nesta linha.

## Aceite de coleta e entrega

Separar quatro provas:

1. **Render/configuração:** chart/schema e configuração do runtime são aceitos pelo binário pinado.
2. **Execução:** Pods prontos, mounts/RBAC/rede/CA corretos; sem reinícios contínuos.
3. **Coleta:** uma fonte sintética autorizada realmente produz o sinal; receiver aceitou os registros esperados.
4. **Entrega útil:** o tenant/datasource correto contém o sinal, com identidade e privacidade previstas; contadores/cobertura concordam. Um HTTP 200 ou fila vazia isoladamente não prova isso.

```bash
./elven status --context "$ELVEN_CONTEXT"

kubectl --context "$ELVEN_CONTEXT" -n elven-observability \
  get pods,pvc -l app.kubernetes.io/instance=elven

kubectl --context "$ELVEN_CONTEXT" -n elven-observability \
  logs statefulset/elven-gateway --since=5m
```

Não compartilhar logs sem verificar se contêm dados privados. Para métricas locais, faça um port-forward de curta duração em um terminal separado e encerre-o ao terminar:

```bash
kubectl --context "$ELVEN_CONTEXT" -n elven-observability \
  port-forward service/elven-gateway 18888:8888
```

Em outro terminal, `curl --fail http://127.0.0.1:18888/metrics` permite observar famílias `otelcol_receiver_*`, `otelcol_exporter_*` e métricas de fila/capacidade. Nomes/sufixos exatos seguem a versão pinada. Correlacionar entrada, falhas, fila e envios ao longo de uma janela; não concluir entrega porque apenas um contador aumentou.

Para uma canary OTLP de aplicação, usar um produtor sintético com CA e certificado de cliente aprovados, o Service FQDN correto e um identificador de teste novo. Produzir pelo menos um log, uma métrica e um trace, sem dados de cliente. Registrar seus horários/IDs e confirmar no Loki/Mimir/Tempo do tenant esperado. Isso não requer nem autoriza modificar a aplicação real. Os testes automatizados do repositório usam destinos sintéticos e não substituem essa validação no tenant.

O produtor stdlib pronto do repositório envia somente dados sintéticos. Obtenha os arquivos de cliente pela PKI aprovada, fora do Git, com chave em modo 0600/0400. Em terminal separado, abra `kubectl --context "$ELVEN_CONTEXT" -n elven-observability port-forward service/elven-gateway 14318:4318`. Então:

```bash
python3 scripts/probe.py \
  --endpoint https://elven-gateway.elven-observability.svc.cluster.local:4318 \
  --connect-address 127.0.0.1:14318 \
  --ca-file /caminho/privado/cliente/ca.crt \
  --cert-file /caminho/privado/cliente/client.crt \
  --key-file /caminho/privado/cliente/client.key
```

O encaminhamento TCP não muda o hostname/SNI verificado. O resultado traz `service_name=elven-probe`, `metric_name=elven_probe_gauge` e um trace ID correlacionado com o log. **`backend_delivery: NOT_VERIFIED` é intencional**: o comando comprova aceitação pelo gateway, não recebimento no SaaS. Procure esse ID no Tempo e no log correspondente, e a métrica/cluster no Mimir, usando o tenant correto. Encerre o port-forward ao terminar.

Para logs de node, confirmar stdout/stderr e namespace realmente selecionado, produzir uma linha sintética nova e observar coleta/exportação; histórico não é automaticamente uma fonte confiável para o teste. Para estado Kubernetes/kubelet, conferir métricas correspondentes aos objetos/nodes selecionados, não somente self-metrics. Para eBPF, exigir um request real do workload/protocolo selecionado e preservação do SDK/destino atual. Para profiles, confirmar alvo HTTPS/mTLS e um profile válido, sem inferir que uma aplicação sem endpoint pprof está coberta.

## Falha de destino e storage

Retry infinito de falhas transitórias não é armazenamento infinito. A fila padrão tem 20Mi de payload serializado por sinal, dentro do intervalo permitido de 8Mi a 64Mi; o PVC padrão de 2Gi (mínimo 1Gi) inclui overhead. O storage efêmero, quando explicitamente selecionado para ensaio, usa disco com mínimo de 1Gi e não é tmpfs nem fallback para PVC indisponível. Quando a fila encher, upstream precisa respeitar backpressure/retentativa, com buffers finitos. Corrigir 401/403, payloads rejeitados, limites ou configuração inválida na origem; esses casos não devem ser tratados como outage transitório indefinido.

Durante outage, não recriar/delete Pods ou PVCs para “limpar” erro. Preserve WAL/filas; verifique localmente DNS, certificado/SAN, autenticação, policy/firewall, resposta do backend e espaço disponível. Após recuperação, comprovar envio dos registros anteriores à falha, drenagem e estabilidade, não somente entrada de dados novos.

## Atualização e rollback

1. Registrar revisão Helm, values sem segredos, digests, configuração, tamanho das filas, PVCs, validade TLS e baseline de entrega.
2. Ler changelog/versões/advisories e compatibilidade do storage. Testar em ambiente isolado antes do cluster real.
3. Renderizar o conjunto completo dos values na nova revisão e revisar diff/ownership. Um render novo deve usar outro `--output`; não destruir o anterior.
4. Drenar filas sempre que o destino estiver saudável; não prometer rollback automático de formato de WAL.
5. Executar upgrade e repetir aceite de coleta/entrega e janela de estabilidade.

```bash
./elven upgrade --context "$ELVEN_CONTEXT" \
  --cluster-name "$ELVEN_CLUSTER_NAME" --expect-cluster-uid "$ELVEN_CLUSTER_UID" \
  --values "$ELVEN_VALUES"
```

Para rollback, escolha uma revisão Helm real e previamente conferida; o número abaixo é ilustrativo, não uma revisão descoberta automaticamente:

```bash
./elven rollback --context "$ELVEN_CONTEXT" \
  --cluster-name "$ELVEN_CLUSTER_NAME" --expect-cluster-uid "$ELVEN_CLUSTER_UID" \
  --revision 1
```

O rollback não restaura versões de Secrets externos, credenciais rotacionadas, dados perdidos ou alterações do backend. Antes de downgrade, confirmar compatibilidade do Collector com a fila existente e manter backup/restauração de volume conforme política aprovada. Não copiar um banco ativo como se fosse um backup consistente.

## Rotação de credenciais e PKI

Não há rotação automática por reaplicar arquivos locais. Para credenciais externas, alterar a fonte segura/ExternalSecret sob seu dono e observar propagação; para Secrets CLI-owned, planejar substituição controlada sem imprimir valores, rollback de credencial e restart/convergência dos consumidores conforme seu modo de leitura. Troca de CA exige período de confiança coordenado e novos certificados válidos para gateway/agents/clientes. A CLI não deve ser usada para adotar ou sobrescrever um Secret externo.

Verificar certificados antes do prazo de 365 dias e alertar antes da expiração. Não remover TLS de entrada para fazer um cliente antigo conectar.

## Uninstall e retenção

Antes de desinstalar: interromper/adaptar os produtores em escopo, registrar o baseline e drenar as filas quando possível. Em um rollback emergencial, declarar qualquer janela de perda possível.

```bash
./elven uninstall --context "$ELVEN_CONTEXT" \
  --cluster-name "$ELVEN_CLUSTER_NAME" --expect-cluster-uid "$ELVEN_CLUSTER_UID"
```

Namespace, Secrets de ingestão/TLS e PVCs do gateway são retidos. Isso protege dados/credenciais e impede remoção acidental de recursos adicionais; não é limpeza completa de dados pessoais. A remoção definitiva desses itens exige inventário de ownership, política de retenção e aprovação separada. Não excluir CRDs, operadores ou namespaces do cliente, e não executar destroy legado.

## Troubleshooting

| Sintoma | Checagens e ação segura |
|---|---|
| Identidade/UID divergente | Pare; reconfirme contexto/kubeconfig e UID do cluster. Não contorne o guard para alcançar outro ambiente. |
| Imagens não promovidas | Produção está bloqueada até publicação/assinatura/verificação e atualização conjunta de lock/defaults. Não usar `--development-images` em cliente. |
| Secret de outro dono | Use nome/release próprio ou referência externa explícita revisada; não adote/aplique por cima. |
| PVC Pending | StorageClass, quota, capacidade, topologia e provisionador. Não trocar silenciosamente por storage efêmero. |
| Collector não inicia | Eventos, mounts, chaves/CA dos Secrets, schema e validação da configuração com a versão pinada; não imprimir Secret. |
| TLS/SAN incorreto | DNS real do Service/destino, CA, validade e certificado de cliente; nunca `insecure_skip_verify`. |
| 401/403 no SaaS | Tenant/token, escopo, endpoint e origem segura da credencial; readiness não valida autenticação. |
| Fonte ausente | Escopo aprovado, stdout/stderr/pprof/SDK reais, RBAC e seleção; sinal não emitido não é falha automática do backend. |
| Kubelet scrape falha | CA, `endpointAddress` IP/hostname e SAN, DNS do node, porta, RBAC e CNI/DNAT. `hostAliases` só é mapeamento explícito revisado; não usar credencial administrativa, override de SAN inexistente ou TLS inseguro como atalho. |
| Sobreposição de coleta | Conferir a release apontada, namespaces/fontes e destinos antes de decidir migração ou exceção. O override explícito não elimina duplicação. |
| Logs duplicados | Mais de um leitor/exporter para o mesmo destino, mudança de checkpoint, rotação e retries após confirmação perdida. Não zerar posições para investigar. |
| eBPF não carrega | BTF/kernel/arquitetura, lockdown/admission/capabilities, processos/protocolos selecionados e agente existente. Manter desabilitado até revisar exceções. |
| Sem profile | Endpoint pprof precisa estar ativo e autorizado; verificar HTTPS/mTLS, path, CA e custo da amostra. Não injetar profiler automaticamente. |
| Apply/upgrade falhou | Ler diagnóstico local sanitizado; verificar que etapa foi reconciliada e o que foi retido. Não assumir transação global entre Helm, Secrets e armazenamento. |

Ao abrir incidente, enviar versão da distribuição, digests, módulos/escopo, janela UTC/BRT, mensagem sanitizada e contagens agregadas. Não enviar token, kubeconfig, chave privada, Secrets, payloads brutos ou logs de clientes.
