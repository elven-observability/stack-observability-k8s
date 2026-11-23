# Contrato eBPF v1: decisão antes da proposta

`scripts/ebpf-contract.py` é um avaliador puro de observações minimizadas. A
engine pode importar `assess(request, lock, now=<epoch UTC inteiro>)`. O input
segue [o schema fechado](../contracts/ebpf-eligibility-v1.schema.json); a
[fixture híbrida](../contracts/fixtures/ebpf-hybrid-v1.json) contém apenas fatos
sintéticos. CLI: `python3 scripts/ebpf-contract.py --input observacao.json`.
Saída JSON canônica; exit 0 para `sdk-only`/`hybrid`, 1 para `unsupported`, 2
para contrato inválido, sem imprimir input ou diagnóstico de outro processo.

As três decisões têm significado limitado:

| Decisão | Efeito |
| --- | --- |
| `sdk-only` | Não propor nem habilitar acesso eBPF ao host. SDK continua sujeito ao seu próprio gate. |
| `hybrid` | Observações atendem o recorte e permitem propor eBPF nos alvos exatos sem SDK; aprovação/execução continuam separadas. |
| `unsupported` | Não habilitar eBPF: `reasons` lista os códigos fixos que faltam comprovar. Não há fallback de permissões, kernel ou imagem. |

Toda saída preserva `runtimeAcceptance: NOT_PROVEN`. O avaliador não lê o host,
não coleta evidência, não aprova e não altera recursos. Os fatos precisam vir
do leitor autorizado da engine, não do modelo ou de um formulário público.
`evidenceSha256` vincula um recibo externo verificável; não autentica JSON por si
só. A engine deve conservar esse recibo, verificar identidade/tempo e reobservar
imediatamente antes de cada escrita. O hash canônico de input e lock vincula a
decisão ao plano e permite detectar drift; não é uma assinatura de release.

## Recorte que pode passar

- Opt-in e aprovação do acesso ao host, imagem exata promovida pelo lock atual
  e fora de `runtimeBlocks`; não adotar tag upstream ou digest v1.0.0 bloqueado.
  A assinatura e as atestações por digest ainda precisam ser verificadas no
  caminho de distribuição, antes de escrever ou executar.
- Nome **e UID** de cada nó e de cada namespace/deployment, com lista fechada de
  nós onde as réplicas do alvo foram observadas; recriação ou réplica fora desse
  recorte bloqueia a proposta. Namespace protegido e wildcard são recusados.
- Observação de até 600 segundos, com tolerância futura de 30 segundos: Linux
  amd64/arm64, kernel >=5.11, nó Ready e BTF em `/sys/kernel/btf/vmlinux`.
  A presença precisa ser conferida no host correto por mecanismo autorizado;
  `hostPath.type=File` no YAML não prova que existe. Labels fornecidos pelo
  usuário não são observação de BTF ou de capacidade.
- Pelo menos um slot de Pod livre, 200m CPU e 1280 MiB livres por nó para o
  perfil padrão Collector + Beyla. CPU é allocatable menos requests ativos;
  slots são allocatable menos todos os Pods não terminados do nó; memória
  precisa reservar o pico do perfil (Collector 256Mi + Beyla 1Gi), não apenas
  mostrar RSS baixo. Dados parciais de namespaces não provam capacidade livre.
  São pisos conservadores do perfil padrão, não dimensionamento ou garantia de
  agendamento. Overrides de requests/limits exigem outro gate/perfil.
- Recibos `pass` de admissão para o Pod renderizado, capabilities efetivas e
  loader eBPF no kernel/nó exato. Um dry-run não prova carga de BPF. A carga
  real depende de ensaio autorizado e não é executada por este avaliador.
  Ausente/unknown não passa. Isso permite declarar impossibilidade com prova,
  sem criar um Pod privilegiado como efeito de um simples scan.

O chart aceita o campo aditivo `nodeAgent.approvedNodes`, uma lista única com
até 100 nomes. Ele rende termos `matchFields metadata.name In [nome]` de um
único nome cada, ordenados e unidos por OR, em interseção com o nodeSelector
Linux e os selectors existentes. A engine MCP deve sempre preencher essa lista
para eBPF/host logs e comparar seus nomes/UIDs com a observação atual. A lista
vazia preserva a compatibilidade do instalador antigo, não concede autorização
de escopo ao MCP. `approvedNodes` não tolera taints automaticamente.

## Permissões, coexistência e sinais

O perfil usa `hostPID`, BPF/PERFMON/SYS_PTRACE/DAC_READ_SEARCH/
CHECKPOINT_RESTORE/NET_RAW, BTF somente leitura e storage temporário; o
container não recebe modo privileged nem NET_ADMIN. Seccomp/AppArmor
Unconfined e execução UID 0 permanecem necessidades explícitas do perfil e
exigem admissão revisada no namespace. O RBAC de metadados Beyla faz list/watch
de Pods/Services/Nodes/ReplicaSets; essa leitura não é isolamento de metadados
por tenant. O Pod que compartilha hostPID deve ser avaliado pelo cliente.

A distribuição mantém exclusão de processos já instrumentados e o contrato
recusa targets que tenham SDK observado. Para combinar SDK/eBPF no cluster,
selecione aplicações disjuntas. Não interpretar ausência de duplicate span IDs
como prova suficiente de ausência de spans duplicados: conferir o mesmo
request/serviço e cobertura ao longo de uma janela de tráfego.

O perfil eBPF atual exporta HTTP/gRPC e métricas RED; usa rotas aprovadas e
wildcard para unmatched. Propagação por eBPF está desabilitada, sem NET_ADMIN.
Não promete spans internos, exceptions completas, SQL/Redis granulares ou
correlação perfeita entre runtimes; esses requisitos pertencem aos SDKs e aos
ensaios por linguagem. Toda saída passa pelo Collector de nó e pelo gateway,
incluindo a política seletiva de privacidade antes de export. Nenhum export de
SQL literal, binds ou chaves Redis é autorizado por este contrato.

## O que estava bloqueado

O lock mantém os digests eBPF/profiler v1.0.0 afetados por advisories, com
recibos e motivos. O digest promovido eBPF v1.0.1 é
`sha256:68cd44f1aeafce7305a555e124f9687b1760db62bf7ea3e81e7d67af4f538f62`.
Seu build usa Beyla 3.42.0 fixado e x/net 0.62.0 para corrigir o High ainda
presente na imagem upstream. Não remover `runtimeBlocks` para aceitar versões
antigas. Um kernel/admissão/capacidade incompatível é outro bloqueio e não é
resolvido pela imagem corrigida.

Para rollback, a engine deve renderizar o estado anterior revisado, verificar
release/UID/revision e obter nova autorização. Desabilitar o eBPF remove o
container Beyla na reconciliação; aguardar o término real e confirmar que não
restou Pod/probe eBPF do plano. Preservar Secret/PVC da stack. Se Collector e
Beyla dividirem o DaemonSet, a atualização reinicia esse Pod: registrar a janela
e verificar retomada de logs/filas. Os sinais persistidos no backend não devem
ser apagados. Timeout ou escrita incerta mantém HOLD e exige readback; o
avaliador não executa rollback nem pode garantir remoção de probes por JSON.

## Fontes e verificação

Primárias consultadas em 23/11/2026: [requisitos do Beyla](https://grafana.com/docs/beyla/latest/requirements-and-security/requirements/),
[permissões em Kubernetes](https://grafana.com/docs/beyla/latest/setup/kubernetes/)
e [seleção/coexistência](https://grafana.com/docs/beyla/latest/configure/service-discovery/).
A documentação atual lista kernel 5.8+ e backports; o recorte da distribuição
continua >=5.11 para evitar fallback SYS_RESOURCE/SYS_ADMIN. Não converter
recursos novos do upstream em capacidades já liberadas da imagem pinada.

Os testes deste commit são sintéticos e de renderização. Não foi iniciado
ensaio de kernel nem alterado cluster/VM. Com APFS quase cheio, pulls/builds
adicionais devem aguardar capacidade de laboratório; source green não equivale
a ensaio eBPF ou três sinais de aplicação.
