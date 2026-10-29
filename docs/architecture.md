# Arquitetura da distribuição

## Fronteira de responsabilidade

A distribuição instala os seus próprios componentes de coleta/processamento/exportação no namespace escolhido. Não depende de um gateway, Alloy, Prometheus, Beyla ou Operator do cliente. Não instala Prometheus, cert-manager, CRDs ou webhooks, não altera Deployments de aplicações e não injeta SDKs automaticamente.

Kubernetes, rede, DNS, armazenamento e permissões aprovadas continuam sendo dependências da plataforma. Um endpoint pprof precisa existir na aplicação; OTLP de aplicação exige instrumentação configurada por seu responsável. eBPF oferece uma alternativa para operações/protocolos suportados, não uma promessa de tracing completo de qualquer aplicação.

## Fluxos

```text
Aplicação OTLP autorizada ───────────────┐
                                      │ mTLS
Agent por node: logs/kubelet/Beyla ─────┼──→ Gateway Elven ──HTTPS/auth──→ Loki/Mimir/Tempo
                                      │      │
Coletor de estado Kubernetes ──────────┘      └─ filas persistentes por sinal, após privacidade

Alvos pprof explícitos ──HTTPS/mTLS──→ Alloy profiles ──HTTPS/auth──→ Pyroscope
```

Os destinos canônicos são configuráveis em `endpoints`:

| Sinal | Destino padrão |
|---|---|
| Logs OTLP/HTTP | `https://loki.elvenobservability.com/otlp/v1/logs` |
| Métricas OTLP/HTTP | `https://mimir.elvenobservability.com/otlp/v1/metrics` |
| Traces OTLP/HTTP | `https://tempo.elvenobservability.com/http/v1/traces` |
| Profiles | `https://pyroscope.elvenobservability.com` |

Não usar o hostname legado `logs.elvenobservability.com` nem desabilitar TLS para contornar um certificado incorreto. Alterar destino implica revisar autenticação, contrato do backend, CIDRs da NetworkPolicy e prova de entrega.

## Componentes e módulos

| Componente | Ativação | Responsabilidade e limite |
|---|---|---|
| Gateway | Baseline | StatefulSet do Collector Elven mínimo, compilado por OCB a partir de componentes upstream explícitos. OTLP com mTLS, processamento, credenciais de ingestão e filas em PVC. Não descobre automaticamente aplicações do cliente. |
| Logs por node | `modules.logs.enabled` e `hostAccessApproved` | Leitura de stdout/stderr CRI de namespaces selecionados; hostPath somente leitura. Não lê arquivos privados arbitrários das aplicações. |
| Métricas de estado | `modules.clusterMetrics.enabled` | Collector singleton com RBAC de leitura da API Kubernetes. Não consulta `/federate` nem exige Prometheus/Operator do cliente. |
| Métricas kubelet | `modules.kubeletMetrics.enabled` | Receiver por node, TLS com CA validada e RBAC específico. Não desabilitar verificação quando o certificado do kubelet não corresponder ao endereço usado. |
| eBPF | `modules.ebpf.enabled`, `hostAccessApproved`, workloads explícitos | Beyla separado, com privilégios de host documentados. Não instala SDKs; context propagation por alteração de headers fica desabilitada. |
| Profiles pprof | `modules.profiles.enabled`, targets explícitos | Alloy não-root faz scrape de endpoints HTTPS/mTLS aprovados. Não ativa pprof na aplicação e não equivale a profiler eBPF ou injeção Java/Python. |

`collection.namespaces` é uma allow-list da coleta em escopo. Não é uma descoberta automática por `prometheus.io/scrape`, nem autorização para ampliar o piloto a todos os namespaces. Os módulos que necessitam escopo devem falhar quando habilitados sem seleção válida. O coletor de estado usa Roles nos namespaces selecionados, sem leitura de Nodes/PVs nesse modo; coleta de estado cluster-wide sem allow-list exige `modules.clusterMetrics.clusterWideApproved: true` e revisão do RBAC ampliado.

## Portas e exposição

| Parâmetro | Padrão | Exposição |
|---|---|---|
| `ports.otlpGrpc` | 4317/TCP | Pod/Service do gateway; mTLS obrigatório. |
| `ports.otlpHttp` | 4318/TCP | Pod/Service do gateway; mTLS obrigatório. |
| `ports.health` | 13133/TCP | Health checks dos Collectors. Não é endpoint de ingestão nem prova do backend. |
| `ports.metrics` | 8888/TCP | Telemetria interna; também listener HTTP operacional do Alloy profiles em seu próprio Pod. |
| `ports.localOtlpHttp` | 14318/TCP | Loopback dentro do Pod do agent para Beyla → Collector; não publicar como hostPort/Service. |
| `modules.kubeletMetrics.port` | 10250/TCP | Destino remoto TLS; precisa coincidir com kubelet e NetworkPolicy. |
| `networkPolicy.apiServerPorts` | 443 e 6443/TCP | Destinos da API Kubernetes, considerando Service e endereço efetivo após DNAT. |
| `networkPolicy.exportPorts` | 443/TCP | Portas de saída HTTPS para os destinos SaaS aprovados. |
| `networkPolicy.dnsPort` | 53/UDP e TCP | DNS do cluster; revisar selectors/CIDRs para CoreDNS, kube-dns ou NodeLocal DNS reais. |
| `networkPolicy.profilePorts` | 443/TCP | Portas dos alvos pprof explícitos, junto de seus CIDRs. |

Não há hostNetwork, hostPort, NodePort ou LoadBalancer no baseline. Portas iguais em Pods distintos não criam conflito de bind no host; renumerá-las não resolve conflitos de CRD, diretório ou ownership. Quando mudar uma porta, revisar listener, Service, probes, clientes, certificado quando aplicável e NetworkPolicy do manifesto renderizado.

`selfMonitoring.enabled: true` habilita coleta das métricas internas dos Collectors (gateway, node e estado Kubernetes, quando presentes) para o pipeline de métricas, com identidade de instância para distinguir séries. O endpoint operacional do Alloy profiles continua disponível para diagnóstico; não equivale a scrape/exportação automática dos seus próprios indicadores para Mimir. O mesmo backend indisponível pode impedir a chegada dessas métricas de diagnóstico; mantenha observação local durante incidentes de saída.

## Isolamento e coexistência

- Nomes locais derivam da release; RBAC de escopo global inclui identidade de namespace/release para evitar colisão entre instalações próprias.
- A distribuição não deve adotar recursos já existentes sem verificação/consentimento explícito. Seus labels não são permissão para sobrescrever um recurso de outro dono.
- ServiceAccounts são separados por função. O runtime não lê Secrets pela API; credenciais são fornecidas por volumes/env de Secrets selecionados.
- Não há descoberta de ServiceMonitors, PodMonitors ou annotations genéricas de outros fornecedores. Não há importação de posições Promtail/Alloy do cliente.
- Cada fonte/sinal em escopo deve ter uma única origem de envio para a Elven. Coletar para um backend do cliente e para a Elven pode ser intencional, mas precisa de orçamento e aprovação; duas cópias para a mesma Elven não são HA automática.
- A CLI inspeciona claims de coleta das releases Elven identificadas por labels/annotations em DaemonSets/Deployments de outros namespaces. Sobreposição deve falhar por padrão. `--allow-overlapping-collection` é uma aprovação explícita após revisar fontes/destinos; não cria deduplicação. Essa inspeção não descobre toda coleta de terceiros, por isso o inventário humano continua necessário.
- Antes de habilitar Beyla ou outro módulo de host, inventariar agentes existentes e alvos sobrepostos. Duas instâncias eBPF podem observar o mesmo processo e disputar recursos mesmo com namespaces diferentes.

## Storage, filas e disponibilidade

O gateway usa PVC de 2Gi por padrão, com mínimo validado de 1Gi. Cada sinal OTLP tem fila de exportação limitada a 20Mi de payload serializado, configurável entre 8Mi e 64Mi, com `fsync`; índices, páginas livres e compactação também consomem storage. O volume não é uma retenção garantida em minutos. A capacidade depende do volume por sinal e do overhead real. O modo efêmero é uma exceção explícita, com orçamento mínimo validado de 1Gi em disco (não tmpfs) e headroom para filas/compactação; não é fallback de storage para produção.

Falhas transitórias de exportação usam retry sem expiração automática e backpressure. Isso protege dados já admitidos nas filas dentro de seus limites; não assegura perda zero. Rotação de logs antes da leitura, buffers upstream, rejeições permanentes, limites do backend, PVC cheio/corrompido, perda do volume e confirmações perdidas precisam ser considerados. Retentativas podem causar duplicação quando o backend ingere mas a confirmação não chega.

Storage local do agent e buffers de profiles não devem ser confundidos com a fila durável do gateway. Recriar um Pod com `emptyDir` remove seu estado local. O módulo profiles não oferece a mesma retenção/replay OTLP do gateway.

O gateway e a coleta de estado Kubernetes têm contrato singleton nesta revisão. Uma réplica evita dupla coleta e não constitui alta disponibilidade. PDB, várias réplicas, dois collectors ou outro backend de storage não devem ser habilitados como um atalho para HA: demandam desenho de eleição/sharding, ordenação, deduplicação, capacidade e testes próprios.

Ver [segurança](security.md), [operação](operations.md), [migração](migration.md) e [matriz de suporte/evidência](support.md).
