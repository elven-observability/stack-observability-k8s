# ZIP candidato: somente laboratório

Este pacote **não é o kit do cliente** e não é uma release. Não altera as URLs,
digests, assinaturas ou o bootstrap de produção v1.0.1. O `materialize` público
continua recusando host collection/eBPF até um novo bundle ser qualificado e
promovido. Não contém `./instalar` nem credenciais.

Em um checkout limpo e commitado, sem rede, Docker ou acesso ao cluster:

```sh
python3 scripts/package-candidate.py pack --output-dir /caminho/novo/candidato
```

Saídas: `elven-lab-candidate-<source-sha12>.zip`, manifesto externo e
`SHA256SUMS`. O ZIP contém `elven-lab-candidate/` com charts atuais (incluindo
`nodeAgent.approvedNodes`), contratos/adaptadores, fontes auxiliares e locks.
Ele **não** embute o antigo bundle v1.0.1. Permissões e timestamps do ZIP são
fixos; o mesmo commit produz os mesmos bytes. O manifesto inclui SHA completo
da fonte, hash de cada arquivo e `payloadSha256` do mapa canônico de hashes.
`SHA256SUMS` identifica tanto o ZIP quanto o manifesto, sem autorreferência.
Com o marcador `LAB-ONLY.txt`, os CLIs do ZIP recusam operações online normais
antes de chamar programas externos. O laboratório exige imagem dev explícita
e ambiente hosted aprovado; esse guard previne uso acidental, não é autenticação
nem atestação do runner. Render offline continua disponível. Fora do ZIP, a
ausência do marcador não altera os gates existentes de produção.

Antes de extrair, o harness CI confere o SHA esperado obtido pelo canal de
artefatos confiável (um checksum dentro do próprio ZIP não é confiança):

```sh
python3 scripts/package-candidate.py verify --archive /caminho/candidato.zip --sha256 SHA_ESPERADO
```

O verificador não extrai, instala ou executa conteúdo. Ele recusa arquivos
duplicados, travessia de diretórios, links, tamanho excessivo e divergência de
hash/manifesto. `customerInstallable=false`, `promotion=NOT_PROMOTED` e
`runtimeAcceptance=NOT_PROVEN` são obrigatórios. Hashes não são assinatura nem
aprovação de instalação.

O ensaio CI autorizado consome **charts, CLIs e contratos extraídos do ZIP**,
com perfil sintético fechado; não usa charts do checkout por conveniência.
A opção de imagens de desenvolvimento existente só pertence ao laboratório.
Não há bypass novo de materialização/assinatura de produção. Kernel/BTF,
capacidade/CNI, consentimento host, nós e workloads exatos, exclusão SDK/eBPF,
entrega real e rollback com readback continuam gates independentes.

Os testes offline deste pacote verificam os bytes, render de seletores exatos,
rejeição de wildcard/duplicata e contradição UID/nome SDK/eBPF. O contrato de
rollback restaura cada aplicação SDK uma única vez antes dos releases e
preserva Secrets/PVCs. Isso não substitui a execução/readback do rollback no
laboratório; nenhuma evidência de runtime é fabricada pelo empacotador.

## Ensaio isolado no CI

O workflow manual `template-candidate.yaml` recebe IDs de **dois builds próprios**:
core (`images.yaml`) e SDKs (`instrumentation.yaml`). Ambos devem corresponder
integralmente às entradas da revisão de teste e ter scans aprovados nas duas
arquiteturas (até 24h; DB até 48h). Archives, reports e SBOMs têm SHA conferido;
os dois binários Collector também exigem Govulncheck recente aprovado.

```sh
gh workflow run template-candidate.yaml --ref REVISAO_APROVADA \
  -f core_run=ID_CORE_APROVADO -f sdk_run=ID_SDK_APROVADO
```

O job gera o ZIP da fonte limpa, verifica seu SHA/manifesto e entrega esse
artefato ao harness. A prova deve usar os charts/CLIs extraídos, um nó aprovado,
Node 22 com SDK e um serviço Go sem SDK selecionado somente para Beyla.
Exige captura real, RED, ausência de sobreposição e rollback com leitura dos
UIDs/estado. Flags de imagem de desenvolvimento e consentimento de host são
somente para esse laboratório descartável. Nenhuma concessão de privilégio,
sysctl ou fallback SYS_ADMIN é adicionada para contornar kernel incompatível.

O kernel, BTF, CNI e capacidades efetivos são registrados. Se o runner não
suportar BPF, o gate falha como `UNSUPPORTED`, não como PASS sintético. O CNI
padrão de Kind não comprova enforcement de NetworkPolicy de produção.

O gate separado `tests/privacy-runtime.py` exige envio real por mTLS através
do Collector compilado e leitura da exportação para exceptions nos formatos
Java/Node/Python, preservando tipos, frames, contexto HTTP e correlação enquanto
remove email/password conhecidos. A origem desses registros é corpus OTLP
sintético: isso **não** prova execução/injeção dos três SDKs nem PII universal.

ZIP e reports ficam nos artifacts do CI (`elven-lab-candidate` e
`elven-lab-candidate-evidence`), nunca em release. Somente gates reais aprovados
permitem propor assinatura, promoção e um kit de cliente posterior; os locks e
o bootstrap estável continuam intactos.

## Recibo executado

Em 26/11/2026, o [candidato exato e seus gates de laboratório](evidence/2026-11-26/README.md)
passaram: privacidade pós-Collector em amd64/arm64, scans frescos, captura real
SDK/Beyla disjunta e rollback com readback. O recibo explicita kernel/CNI,
baseline host e limites da prova. Isso não promove o ZIP nem o torna um kit
instalável no cliente.
