# Contrato consumível do template para a engine

`scripts/template_contract.py` é um adaptador stdlib de materialização. A
engine controla autenticação, aprovação, observação, despacho e estado.
O adaptador faz a parte determinística do template: resolve seleção fechada,
compila valores dos dois charts, enumera ações por alvo, compara planos e
prepara a restauração. Não recebe comandos, patches, manifests livres, URLs
de download, endpoint de exportação, token ou kubeconfig no documento.

## Identidade e compatibilidade

`contractVersion=elven.template/v1`. O catálogo contém hashes de todos os
scripts/charts/locks/processor/operator e schemas, oito referências Elven por
digest, hashes dos predicados e a identidade OIDC exata da assinatura esperada.
Seu hash é SHA-256 do JSON canônico sem `catalogSha256`. A canonicalização
é JSON ASCII com chaves ordenadas, sem whitespace e sem NaN/Infinity.
Não é declarada como RFC 8785.

A engine deve admitir o hash do catálogo por canal próprio e comparar a closure
com os arquivos instalados. O JSON não é uma assinatura, e registrar
`status=verified` no lock não substitui verificar Cosign e os predicados.
A função `catalog()` lê somente o pacote local, sem Git, rede ou credenciais.
Em produção, recusar catálogos/arquivos fora do hash admitido.

O artefato público v1.0.1 continua pinado pelo SHA-256
`fdd3dfb6fe621a5c69b6f8a79dc6f4601c6e764b524b66c00681deb56da352db`.
Essa identidade é a do **bundle antigo**, não a fonte nova deste adaptador.
Não substituir o conteúdo/asset da release. Uma futura distribuição contendo
o adaptador requer revisão/identidade de configuração e pacote próprios.
Os exemplos são sintéticos e não autorizam um deploy.

## API e schemas

Carregar o módulo por caminho local fixo controlado pela engine:

```python
catalog = template.catalog()
proposal = template.plan(selection, catalog, now=trusted_utc_clock)
public_values = template.materialize(proposal, catalog, now=trusted_utc_clock)
delta = template.diff(previous_plan, proposal, catalog, now=trusted_utc_clock)
recovery = template.rollback(proposal, private_baseline, catalog, now=trusted_utc_clock)
```

Schemas em `contracts/template/v1/`; fixtures de entrada/saída em
`contracts/template/v1/fixtures/`. A CLI também permite:

```sh
python3 scripts/template_contract.py catalog
python3 scripts/template_contract.py plan --input selection.json
python3 scripts/template_contract.py apply --input approved-plan.json
python3 scripts/template_contract.py diff --previous before.json --input after.json
python3 scripts/template_contract.py rollback --input plan.json --baseline baseline.json
```

`apply` é o contrato de **materialização**, com
`execution=ENGINE_PHASE_PORT`. Ele retorna valores JSON e operações tipadas,
sem tocar Kubernetes. Cada saída é rederivada: alterar um campo de ação/gate e
recalcular o hash não cria uma variante válida.

| Ação | Alvo/limite | Execução pelo port confiável da engine |
| --- | --- | --- |
| `CORE_APPLY` | Uma release/namespace; 900 s; valores fechados | Usar o instalador `elven` do pacote admitido, com contexto, cluster UID e refs de secrets locais |
| `OPERATOR_APPLY` | Outra release; namespaces aprovados | Usar `scripts/instrumentation.py`; validar admissão e mTLS antes das apps |
| `APP_OPT_IN` | Deployment UID/RV/template SHA, namespace UID, container/runtime | Engine lê o objeto exato, valida o baseline e faz CAS da metadata de Pod template; nunca reinício abrangente |
| `APP_RESTORE` | UID, RV/template atual e snapshot SHA privados | Restaurar só a mudança autorizada, validando estado atual; snapshot não vai ao modelo |
| `CORE_ROLLBACK` / `OPERATOR_ROLLBACK` | Release UID/revisão atual e revisão de destino | Grant novo, readback e ordem de restauração; não apagar Secrets/PVC |

As ações são especificações para esses ports; elas não habilitam um executor
no chat e não prometem transação atômica entre Helm e aplicações. A engine
deve verificar o grant imediatamente antes de cada escrita e durabilizar o
resultado/recibo. Efeito incerto é HOLD sem replay automático. IDs/hashes
identificam conteúdo; não são bearer de aprovação.

## Seleção e eBPF

Até 32 namespaces, 100 apps e 100 nodes. Namespaces e aplicações usam UID;
Deployment tem RV e hash do template. Aplicações com instrumentação existente
ou desconhecida são recusadas para evitar adoção silenciosa. Java, Node.js
mantido e Python beta são escolhas explícitas; o contrato não adivinha runtime.
Node 20/EOL exige um contrato de exceção futuro, não um override.

Para stdout, precisa de consentimento de host e nodes exatos. O chart usa
`nodeAgent.approvedNodes`; nomes são confirmados pela engine por UID antes
do despacho. Métricas cluster-wide também pedem consentimento explícito.

`ebpf=null` resulta em `sdk-only`. Um recorte híbrido inclui no plano
a evidência minimizada do leitor autorizado conforme
[contrato eBPF](ebpf-eligibility-contract.md). São verificados cluster,
namespace/app/node UID, kernel, BTF, admissão, carregamento BPF e capacidade.
Os alvos SDK/eBPF são disjuntos e a exclusão de SDK permanece ativa.
`unsupported` mantém os motivos, mas recusa materializar captura no host.
O leitor e as evidências devem ser confiáveis: nunca aceitar os fatos do host
MCP como prova de kernel/capacidade/permissão.

## Privacidade, rollback e gates

HTTP preserva método/rota normalizada/status. SQL preserva estrutura com
literais/binds removidos segundo os formatos testados. Erros/exceptions têm
redação seletiva de padrões conhecidos; não se promete PII arbitrária.
O conserto Redis remove operandos e requer novo Collector compilado,
escaneado, assinado e promovido. O catálogo registra
`COLLECTOR_REPROMOTION_REQUIRED=UNKNOWN`; o digest v1.0.1 não adquire
esse conserto por Helm. Não anunciar Redis corrigido antes desse gate.

Um plano expira para novas instalações em dez minutos. Ler o plano antigo
para preparar rollback não estende a autorização: o baseline de recuperação
deve vir de observação recente (60 s), com UID/revisões atuais das releases
e snapshot privado para cada app. Aprovação nova e verificação independente
continuam obrigatórias. Não há delete automático nem unfence por timeout.

Os gates de fonte estão testados; [laboratório runtime](telemetry-laboratory.md)
tem limites separados. Em 23/11, o host sem capacidade e com Docker de outro
projeto foi recusado antes de Kind/pulls. Esse recibo é bloqueio, não aceite.
