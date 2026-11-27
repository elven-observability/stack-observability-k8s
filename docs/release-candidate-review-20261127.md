# Revisão independente: próximo bundle sem modo de desenvolvimento

Data: 27/11/2026. Base inspecionada: `d803199` (`main`, PR #12), na branch
`codex/real-sdk-privacy-20261127`. Revisão estática/read-only; somente este
documento foi criado. Não foram executados builds, downloads, assinatura,
publicação, promoção, acesso a EIP/EO/Auth ou instalação em cliente.

## Decisão atual: HOLD para novo kit de cliente

O candidato `3681f04f095e4e04a72f8ab1591d6d8694f5601d` tem recibo permanente
em `docs/evidence/2026-11-26/README.md:10` e `lab-candidate.json`. O recibo
registra entrega SDK/Beyla disjunta, RED e rollback no laboratório exato. Não
registra assinatura/promoção dos candidatos nem qualifica outro host/CNI. Java,
Node e Python-shaped exceptions pós-Collector são fixtures OTLP, não prova de
exceções reais dos três SDKs (`README.md:26`). Não converter esse PASS em aceite
de release sem os gates abaixo.

As oito imagens dos dois locks continuam `v1.0.1`, `publicationStatus=verified`
e `sourceRevision=7dea21b4391f5d0107bec8c280518fe097f9c494`. Isso descreve a
publicação histórica, **não** promove os fontes/correções atuais. As revogações
históricas `runtimeBlocks` de Beyla/Alloy continuam distintas dos digests atuais.
Nenhum digest novo é proposto neste documento.

## Alterações concretas necessárias

| Ponto atual na fonte | Alteração exigida para a nova release |
| --- | --- |
| `scripts/package-distribution.py:30–53` exige os três componentes core e cinco SDK, mesma versão estável e uma única revisão de build | Construir/qualificar/publicar os oito componentes a partir da mesma revisão aprovada. Não misturar Collector novo com SDKs de outra revisão e não reutilizar tags imutáveis v1.0.1. Se houver intenção de permitir revisões diferentes, isso é mudança explícita do contrato de release, não opção já suportada. |
| `scripts/images-release.py:582–609` e `scripts/images-instrumentation.py:288–308` geram locks promovidos separados | Consumir os locks produzidos pela promoção real, com digests, `sourceRevision`, `verifiedAt`, hashes de predicados e estados verificados. Atualizar `versions.lock.json` e `instrumentation.lock.json` por revisão; não preencher estados manualmente. Preservar `runtimeBlocks`. |
| `scripts/package-distribution.py:56–65,119–120` compara repository/tag/digest dos defaults | Atualizar juntos `charts/elven-observability/values.yaml` e `charts/elven-instrumentation/values.yaml` para os oito resultados promovidos; revisar metadata/version dos dois `Chart.yaml`. Locks novos com chart velho serão recusados, como desejado. |
| `scripts/template_contract.py:16–18,110,195` fixa artefato v1.0.1 e SHA `fdd3…352db` | Vincular o adaptador ao **novo tar.gz real**, URL estável e SHA exato. Regenerar schema de plano e fixtures determinísticas que contêm `artifact`; não editar somente o rótulo de versão. Recalcular catálogo/hashes após congelar os arquivos. |
| `scripts/template_contract.py:226–232,327–330` declara repromoção/reempacotamento pendentes e bloqueia qualquer nodes/hybrid | Só substituir o bloqueio incondicional por admissão positiva de capacidade/schema do novo artefato depois do empacotamento/qualificação. Manter recusa para bundle antigo/desconhecido. Atualizar `dataCapabilities` somente para recursos realmente qualificados; não remover `SIGNATURE_VERIFICATION_REQUIRED` ou gates do engine. |
| `kit/plataforma/instalar.py:29–34` fixa versão/nome/URL/SHA v1.0.1 | Atualizar o pin somente para o bundle novo pronto. `scripts/package-install-kit.py:30–42` recusa bundle arbitrário e deve continuar recusando; gerar novo ZIP com o tar.gz correto embutido. Não usar o ZIP LAB como pacote interno. |
| `kit/plataforma/instalar.py:181–190,204–234,254` oferece labels ou aprovação de todos os nós, mas não materializa `approvedNodes` | O kit ainda não expõe o escopo exato novo. Adicionar configuração fechada/revisável de nós identificados por nome+UID (ou resolver labels em plano com esse vínculo), gravar nomes em `nodeAgent.approvedNodes` e revalidar UIDs/conjunto antes da escrita. Se mantiver o fluxo legacy por labels, identificá-lo como legacy e não alegar a garantia estrita MCP nesse fluxo. Logs/eBPF compartilham o mesmo DaemonSet: exigir mesmo conjunto autorizado. Atualizar exemplo TOML, ajuda curta, receipt e testes, sem aceitar overrides livres. |

O chart atual **já** carrega o recurso necessário: `values.schema.json:60`
limita `approvedNodes` a 100 nomes DNS únicos; `values.yaml:68` mantém vazio
compatível com perfis antigos; `templates/node-agent.yaml:265–275` produz
required affinity por `metadata.name`, com OR entre nomes exatos e AND com o
`nodeSelector` existente. Não trocar isso por um label supostamente equivalente
nem por affinity preferencial. O bundle v1.0.1 anunciado pelo adaptador não
contém esse schema novo, por isso o bloqueio atual é correto.

## Supply chain: o que precisa ser provado, não apenas escrito

`scripts/images-release.py:412–436` e
`scripts/images-instrumentation.py:186–212` verificam digest imutável,
Cosign pinado, issuer GitHub OIDC, identidade do workflow/tag estável e os
predicados SPDX/build pelos hashes admitidos. A promoção ainda confere
registro público e labels da origem por plataforma. Usar esses caminhos para
os novos resultados; não flexibilizar identidade para branch/PR/dev.

Os guardas de instalação `elven:562–600` e
`scripts/instrumentation.py:191–211` comparam imagens aos locks promovidos;
eles **não executam Cosign online em cada instalação**. O receipt de release
deve, portanto, comprovar a verificação pública real de assinaturas/predicados
antes de distribuir o kit. No EIP, o gate de assinatura continua pertencendo à
admissão do engine. Não descrever comparação ao lock como uma verificação
criptográfica nova realizada no cliente.

Os gates precisam cobrir ambas as plataformas declaradas pelos locks, com
scan/DB frescos, SBOM e proveniência ligados aos digests finais. O sucesso com
imagens dev no laboratório não dispensa a execução pós-promoção com os
digests finais, nem prova acesso anônimo ao registry e aos assets publicados.

## Gate do instalador limpo, realmente sem dev

O empacotador interno já usa `git archive` de HEAD limpo, fecha paths,
recusa links e limita conteúdo a 30 MB/4 MB por membro e gzip a 600 KB
(`scripts/package-distribution.py:68–125`). O kit externo também exige árvore
limpa e pin exato, sem sobrescrever outputs (`package-install-kit.py:30–75`).
Medir o novo tamanho; se exceder 600 KB, revisar o conteúdo/limite em todos os
consumidores e seus testes. Não truncar nem desabilitar a checagem.

Antes de disponibilizar ao cliente, o gate deve baixar/extrair **o ZIP final**
em diretório limpo, fora do checkout, sem `.artifacts`, caches de imagens de
teste, arquivos locais ocultos, `LAB-ONLY.txt` ou flags/env de laboratório.
O ZIP deve fornecer `./instalar`, exemplo TOML, bootstrap e bundle embutido.
Validar plano/render, instalação combinada core+Operator, repetição segura,
token sem eco e reaproveitamento do Secret do tenant correto, rejeição de
tenant divergente, ownership estrangeiro, UID de cluster/nó alterado,
namespace protegido, falta de consentimento e imagem não promovida/revogada.

O caminho atual usa `python -I`, gera values/render/recibo para revisão
(`kit/plataforma/instalar.py:400–417`) e não acrescenta `--development-images`
à instalação (`:528–536`). Preservar isso. `elven:30–35` bloqueia uso online
acidental de pacote LAB; não remover o marcador de um candidato para
transformá-lo artificialmente em release.

O bootstrap instala core e Operator, mas **não opta aplicações nem faz rollout**
(`instalar.py:541`). Para prometer “Kubernetes e aplicações prontos”, ainda é
necessário um opt-in explícito/revisado de workloads exatos, readback da imagem
injetada e dos spans/logs/métricas reais no destino, não só Pod Ready ou
reconciliação Helm. Manter semântica de sucesso parcial/UNKNOWN de
`elven:687–698`; não apagar o core para esconder falha na fase Operator.

## SDK/eBPF, rollback e compatibilidade EIP

O contrato já recusa sobreposição por UID **e** por namespace/nome
(`template_contract.py:301–308`), vincula nós, namespaces, cluster e evidência
fresca e deixa runtime como `NOT_PROVEN`. A nova release deve preservar isso,
o `excludeSDKInstrumentedServices=true`, capabilities aprovadas e as recusas
de kernel/BTF/capacidade/CNI desconhecidos; não deduzir essas provas de um
scan de inventário ou do laboratório Kind.

O rollback contratual (`template_contract.py:388–416`) exige baseline exato e
observação de até 60 segundos, rejeita apps ausentes/duplicadas e restaura
apps em ordem reversa antes de Operator/core. CAS de resourceVersion/template,
UID/revisão de release, preservação de Secrets/PVCs e
`HOLD_WITHOUT_REPLAY` são parte do contrato. O ensaio híbrido 26/11 prova
remoção do worker com SDK preservado; **não** prova a execução de todo esse
plano APP_RESTORE pelo EIP ou o purge de probes/maps do kernel. Qualificar
esses pontos separadamente, sem inferir atomicidade entre releases.

Compatibilidade EIP desta revisão é **somente estática do lado template**:
não foi lido nem alterado código do EIP. Manter `elven.template/v1`, os nomes
das ações e schemas fechados se o wire contract não mudar. O catálogo novo
terá hash novo; request/plan/schema/artefato de versões diferentes precisam
ser recusados. O EIP deve selecionar adaptador+catálogo+artefato imutáveis
da instalação, inclusive para validar planos históricos/rollback; o
`validate_plan` atual reconstrói contra o catálogo fornecido (`:314–319`), não
migra automaticamente planos antigos ao catálogo novo. Reaprovação e novo
scan são necessários para um plano novo. Gate de compatibilidade real no
EIP permanece pendente e não autoriza acesso ou mudança naquele ambiente.

## Critério de saída

O próximo kit só deixa HOLD quando houver: revisão final de fonte; SDKs reais
nos cenários prometidos; oito imagens finais assinadas/promovidas; bundle
novo com `approvedNodes` e pins coerentes; qualificação sem dev consumindo o
ZIP público exato; instalação/opt-in/entrega/rollback com recibos e limites
explícitos. Nenhum desses resultados pode ser substituído por alterar um
`publicationStatus`, por hash sem assinatura, ou pelo PASS LAB de 26/11.
