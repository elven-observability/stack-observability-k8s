# Migração do template anterior

## Não é um upgrade automático

A nova distribuição tem outro chart, fronteira de ownership, PKI, storage e contrato de dados. Mover o código antigo para `legacy/v0/` não altera uma instalação existente. `./elven upgrade` não deve adotar releases do Helmfile antigo nem CRDs, webhooks ou operadores de terceiros.

O `helmfile.yaml` da raiz é uma sentinela sem releases/hooks, não uma instalação alternativa. A CLI mantém a produção bloqueada até a promoção de imagens assinadas. O Collector Elven agora é um build mínimo OCB com componentes explícitos e correção de dependência; a configuração completa do Collector contrib antigo não é um drop-in. Identificadores canônicos como `file_log`, `kubelet_stats` e `otlp_http` precisam corresponder aos componentes compilados, não ser copiados de versões antigas por semelhança de nome.

Começar com outra release/namespace e um escopo de piloto limitado. Não renomear/relabelar recursos do cliente para fazê-los parecer da Elven. Não executar `helmfile destroy` do legado para “abrir espaço”: ele contém deleções históricas sem validação de ownership e está bloqueado por padrão.

## Diferenças que exigem decisão

| Antes | Linha nova | Consequência |
|---|---|---|
| kube-prometheus-stack/Prometheus Operator/KSM/node-exporter | Receivers próprios Kubernetes/kubelet e OTLP | Não assume CRDs do cliente nem instala outro Prometheus. Nomes, atributos, cobertura e consultas de métricas podem mudar; não prometer equivalência de dashboards/regras. |
| Alloy logs com diretórios de host genéricos e posições Promtail | Agent próprio selecionado por namespace, storage separado e privacidade explícita | Não copiar/zerar posições de terceiros. Planejar janela de troca e evitar dois leitores enviando a mesma fonte para a Elven. |
| Operator/webhooks/Instrumentation distribuídos pelo template | Nenhuma auto-injeção na instalação nova; ingestão OTLP explícita ou eBPF opcional | Preservar SDKs existentes até validar o novo destino/PKI. Mudar endpoint de aplicação exige revisão do proprietário, não um patch automático. |
| OTLP interno sem mTLS | Gateway com certificado de cliente obrigatório | Clientes/agents precisam da CA e identidade apropriadas. Um emissor incompatível não deve levar ao desligamento de TLS. |
| Filas/configurações voláteis e scripts pós-sync | Gateway StatefulSet com PVC e fila persistente por sinal | Novos paths/formato de fila; não importar WAL de outra versão/agente sem migração validada. |
| Faro e MySQL exporter instaláveis pelo Helmfile | Não são módulos nativos deste chart | Não alegar cobertura automática desses sinais. Preservar integração anterior revisada, ou planejar implementação/integração separada, sem chamar isso de migração concluída. |
| Namespace padrão `monitoring` e comandos Helmfile | Namespace padrão `elven-observability` e CLI explícita | Não mover recursos em uso só para mudar identidade. Guard de cluster/ownership não deve ser desabilitado para encaixar o legado. |

## 1. Baseline e inventário

Registrar, em diretório privado fora do Git:

- Releases/revisões Helm, fontes GitOps e proprietários responsáveis. Não extrair Secrets ou kubeconfig para um pacote de suporte.
- Componentes ativos do cliente e da Elven: Prometheus/Alloy/Collector/Beyla/Operators, webhooks/CRDs, exporters, alvos SDK/pprof e destinos.
- Recursos efetivamente próprios versus compartilhados: namespaces, SAs/RBAC, Secrets, PVCs/WAL, volumes/caminhos de host, portas expostas e políticas.
- Cobertura e volumes por sinal, tenant/datasource, serviços esperados e janela temporal. Um dashboard preenchido não comprova todas as fontes.
- CPU/RAM/I/O do node e das aplicações, latência/erros e condições de saturação. Definir limiares de abortar o piloto antes de instalar.
- Validade/rotação de certificados e responsáveis por credenciais. Revisar retenção/backup de volumes sem copiar bancos ativos de forma inconsistente.

Essa etapa não autoriza seed, cutover, remoção de recursos nem alteração no gateway/Prometheus do cliente. O inventário precisa corresponder ao cluster real e à fonte instalada, não apenas ao gerador deste repositório.

## 2. Render e revisão isolada

1. Selecionar release/namespace novos, o UID real do cluster e apenas os sinais/alvos autorizados.
2. Preencher um perfil com CIDRs/CAs/storage reais e credenciais em arquivos privados ou Secrets externos referenciados.
3. Renderizar a nova revisão offline; revisar todos os objetos e nomes globais. Não aceitar CRDs/webhooks inesperados ou paths do host compartilhados.
4. Validar configuração/binários e as versões da matriz. Confirmar que os novos sinais e os dashboards/consultas necessários são compatíveis. A promoção dos digests Elven precisa estar concluída para produção; `--development-images` só cabe no ensaio descartável, nunca como exceção para migrar um cliente.
5. Instalar somente o piloto autorizado. Não instalar sobre uma release legada com o mesmo nome.

## 3. Piloto sem dupla ingestão

Preferir um serviço/node de teste ou fontes sintéticas sem sobreposição com as fontes produtivas. Se um período de observação paralela for necessário, decidir explicitamente para quais destinos cada fonte envia; não fazer duas exportações do mesmo sinal ao mesmo tenant Elven e tratá-las como HA.

Confirmar coleta efetiva, privacidade antes da fila, autenticação, TLS/SAN, enforcement da policy, metadados e ingestão no tenant. Para eBPF, testar requisições do protocolo/runtime selecionado e preservação do SDK/destino atual. Profiles só entram no piloto após endpoint pprof autorizado e avaliação de seu custo.

Exercitar indisponibilidade de um destino sintético, capacidade/retries, drenagem e restart do Collector com storage preservado. Não injetar outage na produção do cliente sem autorização separada. Readiness e HTTP 200 não substituem contagem dos registros originais após recuperação.

## 4. Cutover por fonte/sinal

Depois de obter os critérios de aceite:

1. Registrar valores finais, digests, revisão, baseline e plano de rollback.
2. Drenar filas antigas quando o destino estiver disponível; documentar qualquer janela ainda pendente.
3. Suspender apenas a exportação antiga da fonte/sinal em escopo pelo seu proprietário/fonte GitOps, preservando as outras pipelines.
4. Ativar a nova fonte/rota correspondente e repetir prova de entrega, cobertura, privacidade e estabilidade.
5. Ampliar gradualmente. Mudanças em aplicação/SDK, observabilidade do cliente ou recurso global exigem decisão explícita; a CLI não faz esse cutover automaticamente.

O cutover não deve desligar a coleta de métricas/traces atual do cliente para compensar consumo da nova distribuição. Não mover aplicações de node nem aumentar permissões sem aprovação só para fazer o piloto passar.

## 5. Rollback e retirada do legado

Se um critério de abortar for atingido, interromper o novo sinal/coletor em escopo e restaurar a rota anterior revisada. Evitar duas rotas ativas para o mesmo tenant durante a reversão. Preservar PVCs/WAL/Secrets e comprovar que o destino antigo voltou a receber; Pod Running não é recuperação.

Após uma janela acordada de estabilidade, remover apenas componentes antigos comprovadamente próprios e não compartilhados, pela fonte responsável. Verificar explicitamente dependências e CRs antes de considerar remover um operador. Não excluir CRDs de Prometheus/OTel, cert-manager ou ClusterIssuer porque o template antigo um dia os aplicou: eles podem ser usados por outras equipes e sua remoção pode destruir CRs.

Uninstall da distribuição nova retém namespace, credenciais/TLS e PVCs. Remoção definitiva de dados é uma ação separada com política de retenção e aprovação. Manter o registro da janela, cobertura, mudanças e pendências; uma POC aceita não implica rollout em todos os nodes ou aplicações.
