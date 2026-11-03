# Elven Instrumentation Operator

Módulo **opcional e independente** de injeção de SDKs Elven por admission webhook. Não depende de Operator, agentes, CRDs ou cert-manager do cliente. O processo não possui token de ServiceAccount, client Kubernetes ou permissões de API; somente devolve um JSONPatch para Pods explicitamente selecionados.

Esta é uma RC. As imagens em [`instrumentation.lock.json`](../../instrumentation.lock.json) precisam ser construídas, escaneadas, publicadas, assinadas, verificadas e promovidas antes de uma instalação de produção. Digests vazios não são artefatos publicados. A CLI bloqueia produção enquanto o lock não comprovar a promoção.

## Instalação e identidade

Use [`scripts/instrumentation.py`](../../scripts/instrumentation.py), não `helm install` diretamente. O chart sozinho não executa os guards de ownership/cluster, nem verifica/provisiona PKI privada. Um render offline pode deliberadamente conter `caBundle` vazio e **não está pronto para apply** nesse estado.

Pré-requisitos: Python 3.11+, Helm 4.3.1+ ou ponte 3.22.1+, kubectl compatível, OpenSSL, Kubernetes 1.35–1.37, gateway Elven instalado, namespaces das aplicações já existentes e fontes reais de ingress do apiserver revisadas. O namespace da distribuição e namespaces de sistema não podem ser alvos.

Prepare um arquivo de values privado com:

- `enabled: true`, namespaces aprovados e somente runtimes necessários.
- Imagens Elven com repository/tag/digest reais correspondentes ao lock promovido.
- Endpoint HTTPS do gateway Elven instalado e `sourceRelease`/`sourceNamespace` explícitos.
- CIDRs do apiserver observados no CNI, inclusive após NAT. Nunca usar `0.0.0.0/0` ou `::/0`.
- Os mesmos namespaces autorizados no `collection.namespaces` do gateway quando sua NetworkPolicy estiver habilitada.

Os nomes/caminhos abaixo são placeholders; substitua-os após conferir o cluster:

```bash
python3 scripts/instrumentation.py render \
  --values /caminho/privado/elven-instrumentation.yaml \
  --output /caminho/privado/elven-instrumentation-reviewed.yaml

python3 scripts/instrumentation.py preflight \
  --context CONTEXTO_CONFIRMADO --expect-cluster-uid UID_KUBE_SYSTEM \
  --values /caminho/privado/elven-instrumentation.yaml

python3 scripts/instrumentation.py install \
  --context CONTEXTO_CONFIRMADO --expect-cluster-uid UID_KUBE_SYSTEM \
  --values /caminho/privado/elven-instrumentation.yaml
```

Release/namespace padrão: `elven-operator` / `elven-observability`. Se alterar, mantenha os mesmos argumentos em todas as operações. `--values` pode ser repetido. `--development-images` é somente a exceção explícita de laboratório; não publica imagens nem aprova uso em cliente.

O preflight é somente leitura: confere versão/UID/contexto, ownership, imagens, namespaces, permissões, fonte do gateway e material TLS existente. Se o material próprio ainda não existir, informa a criação planejada, sem gerar certificados. O install gera/verifica localmente a PKI antes da primeira escrita e usa `create`, nunca overwrite/adoption, para os Secrets. Erros de provider não reproduzem conteúdo de Secrets no terminal.

## Opt-in explícito, sem restart automático

Depois da instalação e do canary aprovado, selecione o runtime no **Pod template** de um workload gerenciado por GitOps:

```yaml
spec:
  template:
    metadata:
      labels:
        elven.observability/inject: java
      annotations:
        elven.observability/container-name: application
```

`container-name` é obrigatório para Pods com múltiplos containers e deve referenciar um container regular. Em Pods de um container ele pode ser omitido. O Operator não detecta uma linguagem de forma especulativa e não altera labels/annotations de namespaces ou workloads. Uma mudança de template/rollout é responsabilidade do GitOps da aplicação; a instalação não reinicia nenhum Pod existente.

Só `CREATE` de Pods no namespace aprovado e com a label de opt-in presente e diferente de `false` chega ao webhook. Sem opt-in, nada é injetado. Labels vazias, runtimes desconhecidos/desabilitados e configuração conflitante são rejeitados explicitamente, não tratados como coleta bem-sucedida. O handler repete a validação do namespace e recusa dois SDKs/agentes, loader flags, `OTEL_*`, `envFrom` que poderia ocultá-los, volumes/mounts reservados e alvos ambíguos; nada disso é sobrescrito silenciosamente. Definir uma label não substitui a autorização de rollout de produção.

Esses guards não inspecionam as camadas/`ENV` da imagem da aplicação nem garantem a ordem de outros webhooks. Antes do opt-in, inventariar SDKs e loader flags embutidos (`JAVA_TOOL_OPTIONS`, `NODE_OPTIONS`, `PYTHONPATH` etc.) e os demais injectors. Um `ENV` herdado da imagem não aparece no objeto Pod: não presumir sua ausência nem aprovar a injeção sem canary. A distribuição não promete detecção universal de agentes já empacotados.

O preflight recusa namespaces compartilhados com outro webhook Elven de injeção e metadados conhecidos de outros injectors em labels/annotations do namespace. Valores presentes ambíguos/vazios não são tratados como ausência; somente `false` desativa um marcador conhecido. Ele não remove configurações de outro dono nem garante descobrir qualquer admission controller customizado. Revisar também o inventário real de webhooks do cluster e canary com o Pod final, pois a ordem de mutação de controladores externos não é uma garantia de coexistência.

## Cobertura e limites

| Perfil | Requisito | Limite explícito |
|---|---|---|
| `java` | Java 17/21; imagem pinada no lock | Bibliotecas suportadas pelo agente; não equivale a tracing de todo método/código de negócio. |
| `nodejs` | Node.js ≥22.15 | SDK atual não suporta Node.js 20; compatibilidade das bibliotecas/CJS/ESM deve ser validada. |
| `nodejs20` | Node.js ≥20.6, imagem Elven separada | Linha EOL: exige `runtimes.nodejs20` e `runtimes.legacyNode20Approved`; não é o padrão e não elimina a necessidade de migração. |
| `python` | Runtime/ABI suportado pelo SDK pinado; seleção glibc/musl explícita quando necessária | Módulo opcional; auto-instrumentação upstream permanece beta. |

`.NET`, Go, PHP, Ruby, profiling automático e chamadas de código não cobertas por bibliotecas não são apresentados como módulos implementados. eBPF continua sendo um módulo complementar separado. Nenhum desses caminhos garante capturar “tudo”, todos os statements ou todas as linhas de log.

Traces, métricas e logs seguem o suporte real do SDK/biblioteca. Logging manual, providers de logs, dados de negócio e integrações específicas podem exigir SDK/API na aplicação. Não contar `Pod Ready`, init container concluído ou um span genérico como cobertura completa.

## PII, SQL e segredos

Os SDKs exportam por **HTTPS/mTLS** somente ao gateway Elven. Aplicações recebem um Secret local ao namespace com `ca.crt`, `client.crt` e `client.key` PKCS#8; não recebem tenant, token de backend, chave de servidor ou chave de assinatura da CA. O Operator não monta sequer o certificado privado de cliente. Secrets externos/conflitantes não são adotados.

Headers HTTP, body/payload e baggage não são habilitados para captura. Sanitização de statements Java permanece ligada; parâmetros/bind values não devem ser habilitados. Para Node/Python, não presumir que o SDK sanitiza literais SQL: o processador `elven_privacy` do gateway é a autoridade antes da fila persistente/exportação, cobrindo corpos, estruturas/atributos, eventos, links e statements. Ele preserva a parte operacional e mascara os padrões/valores sensíveis suportados. Não é uma garantia universal contra PII desconhecida; políticas mais restritivas e o modo strict continuam disponíveis.

Os logs originais da aplicação não são reescritos. A transformação atua somente na cópia de telemetria enviada ao gateway. Validar amostras sintéticas com email/CPF/token/senha/SQL e confirmar **utilidade preservada e ausência dos valores sensíveis**, inclusive no WAL, antes de ampliar o escopo.

## Portas, permissões e falhas

- Serviço: HTTPS `webhook.servicePort` (padrão 443) → `webhook.port` (9443, não privilegiada), `/mutate` e `/healthz`.
- Operator: UID/GID 10001, rootfs read-only, cap-drop ALL, RuntimeDefault, sem host access/API token. Sem Roles/ClusterRoles de execução e sem egress de rede.
- Installer: leitura do gateway/TLS/namespaces e CRUD do release metadata Helm; create de Secrets próprios nos namespaces aprovados; create/patch do webhook global com nome hash namespace/release. Não precisa patch/restart de aplicações.
- NetworkPolicy: ingress apenas dos CIDRs revisados do apiserver; egress vazio. O CNI deve efetivamente aplicar a policy; render/schema/Kind padrão não comprovam enforcement.
- `failurePolicy: Ignore`: indisponibilidade/timeout de transporte do webhook não bloqueia a disponibilidade da aplicação. Pode haver Pod **não instrumentado**; isso é falta de cobertura, não sucesso de coleta. Rejeições explícitas de conflito/configuração em um Pod selecionado são falhas de admission intencionais.
- Sem CA/cert-manager do cliente. PKI temporária é descartada após provisionamento; certificados exigem renovação/rotação revisada antes de expirar, não renovação automática implícita.

## Verificação e remoção

```bash
python3 scripts/instrumentation.py status --context CONTEXTO_CONFIRMADO

python3 scripts/instrumentation.py uninstall \
  --context CONTEXTO_CONFIRMADO --expect-cluster-uid UID_KUBE_SYSTEM
```

Aceite: criar canary sintético em namespace aprovado, comprovar o patch/SDK correto, requests reais e telemetria útil/PII mascarada no destino; testar namespace e Pod sem opt-in, conflito de agentes, múltiplos containers e TLS incorreto. Registrar imagem/digest/runtime/arquitetura exatos. Validação local/Kind não aprova rede, admission, tenant e aplicações reais do cliente.

Uninstall remove o webhook e os recursos da release; retém namespaces e Secrets privados deliberadamente. Não desfaz Pods já mutados nem reinicia aplicações. Para remover o SDK de workloads existentes, revisar/remover o opt-in no GitOps e executar um rollout autorizado. Não remover os Secrets antes de retirar seus consumidores.
