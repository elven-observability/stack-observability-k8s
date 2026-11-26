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
