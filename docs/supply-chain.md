# Imagens Elven e cadeia de fornecimento

## O que é distribuído

Uma distribuição Collector mínima compilada a partir de componentes upstream explícitos e dois wrappers de runtimes oficiais. Nenhuma imagem final instala pacotes de sistema no startup:

| Imagem preparada | Base | Papel |
|---|---|---|
| `docker.io/elvenobservability/elven-collector` | OCB/core 0.164.0 + módulos contrib 0.164.1, Go 1.27.3, runtime scratch | Collector mínimo; somente componentes declarados em `images/collector/builder-config.yaml`. |
| `docker.io/elvenobservability/elven-ebpf` | Grafana Beyla | Captura eBPF opcional. |
| `docker.io/elvenobservability/elven-profiler` | Grafana Alloy | Profiles opcionais. |

Os wrappers Beyla/Alloy preservam filesystem, entrypoint e licenças upstream. O Collector usa `/elven-collector` como entrypoint e UID/GID 10001, sem shell/package manager; o payload executável é o binário estático, acompanhado de CA, informações de build e licenças. A CA vem da imagem oficial pinada. O build usa OCB e módulos pinados, `GOSUMDB=sum.golang.org`, proxy oficial sem fallback não verificado, `CGO_ENABLED=0`, `-trimpath` e build ID vazio. O manifest de componentes, `go.mod`, `go.sum` gerados e `go version -m` são incluídos para auditoria. Os replaces de go-jose 4.1.6 e x/net 0.62.0 corrigem os achados identificados, sem ignorelist nem patch oculto no código funcional dos componentes.

Todos incluem labels OCI e atribuições em `/usr/share/licenses/elven-*`, licença Apache-2.0 integral, NOTICE/CSV de terceiros do Beyla e LICENSING.md do Alloy. Identidade Elven não é reivindicação de autoria nem endorsement dos projetos de origem. Dependências continuam sujeitas às respectivas licenças, registradas nos SBOMs; não remover os avisos herdados dos wrappers.

O Collector mínimo possui um passo adicional de empacotamento legal: após `go mod verify`, `images/collector/license-bundle.go` coleta textos LICENSE/LICENCE/NOTICE/COPYING/COPYRIGHT dos módulos disponíveis no grafo Go verificado, adiciona a licença do Go e grava manifest com SHA-256 de cada texto em `/usr/share/licenses/elven-collector/dependencies/`. Não executa downloads próprios nem substitui revisão jurídica. O SBOM não é tratado como substituto dos textos de licença.

O candidato local final contém **571 textos**, com **480 identidades de módulo/Go com avisos**. O gate extrai o diretório da imagem OCI real em ambas as arquiteturas e confere o SHA-256 de cada texto contra o manifest, antes de aceitar publicação. Os binários amd64/arm64 permaneceram idênticos por SHA-256 ao candidato anterior exercitado, mas o índice da imagem mudou pelo empacotamento legal; a validação de runtime é repetida sobre esse índice final, não atribuída automaticamente ao digest anterior.

## Build local sem publicar

Pré-requisitos: Python ≥3.12, Docker/Buildx com export OCI/attestations, espaço para as imagens e Trivy na versão exata do lock. A execução não lê kubeconfig nem chama Kubernetes. Usar somente fontes não secretas; o `.dockerignore` específico de cada Dockerfile usa deny-all e permite apenas os arquivos necessários.

```bash
python3 scripts/images-release.py check
python3 scripts/images-release.py build --version 1.0.0-dev --platform linux/arm64
python3 scripts/images-release.py scan
docker load --input artifacts/images/collector.oci.tar
python3 scripts/images-release.py govulncheck
```

Em host amd64, usar `--platform linux/amd64`. Para a entrega multiarch: `--platform linux/amd64,linux/arm64`. O build não executa binários de outro ISA, mas isso não substitui smoke nativo nas duas arquiteturas.

Em `artifacts/images/` são produzidos os archives OCI, digests reais **locais**, metadados BuildKit, SBOMs, proveniência, relatórios Trivy completos e `release.json`. Os arquivos são artefatos ignorados pelo Git; não são imagens publicadas. `SOURCE_DATE_EPOCH` vem do commit e normaliza timestamps de payload; bases e gerador SBOM são pinados por digest. Metadados de execução/proveniência/assinatura incluem informação variável: não prometer igualdade bit a bit dos índices de duas execuções sem compará-los. Builds locais com fonte suja ficam marcados e não podem ser publicados pelo script.

O script `scan` usa o archive exato, grava relatório para **todas as vulnerabilidades** e bloqueia a release se houver qualquer High/Critical, inclusive sem correção. Cada arquitetura precisa de resultado próprio. Publicação recusa scan com mais de 24 h ou DB com mais de 48 h; uma aprovação manual tardia exige repetição com evidência fresca. Não há ignorelist ou flag para contornar o gate. Falha de rede/DB/scanner não é um scan aprovado. Atualização upstream, substituição da base ou exceção de segurança formalmente revisada exigem alteração de código/política, não esconder o achado.

## Publicação controlada

O workflow [`images.yaml`](../.github/workflows/images.yaml) constrói OCI multiarch com BuildKit SBOM/proveniência e executa o gate de vulnerabilidades antes de publicar. Também carrega **os archives escaneados exatos** do Collector e profiler, analisa símbolos Go nos dois binários Collector, valida configurações e entrega pprof HTTPS autenticada e executa install/entrega/outage/replay/coexistência/upgrade/rollback em Kind **nativo amd64**. O job de publicação depende do sucesso dessa bateria completa; não reconstrói uma imagem diferente depois do scan. O engine Docker pinado utiliza o image store containerd para preservar índices OCI e attestations no load. Actions são pinadas por commit. PRs e dispatch na branch só constroem/validam: **não publicam**.

Para habilitar publicação real, o administrador precisa configurar:

1. Repositórios Docker Hub Elven **públicos** e credencial de escopo mínimo de escrita somente nesses três repos, armazenada nos Secrets `ELVEN_DOCKERHUB_USERNAME` e `ELVEN_DOCKERHUB_TOKEN`. O consumidor não deve precisar de PAT/`imagePullSecret` de registry. Não tornar público código/configurações privadas: as imagens contêm somente runtimes/licenças/receita de build, nunca credenciais ou dados de clientes.
2. Environment GitHub `elven-distribution-release` com **required reviewers** e aprovação manual; idealmente impedir autoaprovação e restringir deployment às tags de release. O workflow e o script consultam a API e recusam environment ausente/sem reviewers, inclusive quando o GitHub o cria automaticamente desprotegido.
3. Tags imutáveis/protegidas `v1.x.y` apontando para revisão aprovada. O job de publicação só é elegível numa tag estável; a assinatura usa GitHub OIDC, sem chave privada persistente.

Após aprovação, o job verifica checksums de cada archive/scan/SBOM, publica os mesmos manifests OCI que passaram pelo gate, consulta novamente o digest remoto e confere blobs nas duas arquiteturas **anonimamente**, com `DOCKER_CONFIG` vazio. Assina e verifica imagem, SPDX e metadados de build; a verificação também não usa a credencial do publicador. Se push/assinatura/verificação falhar, a imagem não é promovida ao lock. Uma falha posterior ao push pode deixar um artefato **não promovido** no registry: não consumi-lo por tag. O processo não faz deploy no cliente.

## Assinatura, identidade e promoção

Verificação exige emissor `https://token.actions.githubusercontent.com` e identidade do workflow exato deste repositório:

```text
^https://github\.com/elven-observability/stack-observability-k8s/\.github/workflows/images\.yaml@refs/tags/v1\.[0-9]+\.[0-9]+$
```

A verificação por release restringe ainda mais à tag exata. Não usar `.*` para qualquer repo/workflow, `--insecure-ignore-tlog`, `--insecure-ignore-sct` ou desabilitar TLS. Os SBOMs SPDX e os metadados BuildKit recebem attestations assinadas; BuildKit também inclui sua proveniência nativa no OCI. Isso **não é certificação de um nível SLSA** nem prova de ausência de vulnerabilidades futuras.

```bash
python3 scripts/images-release.py verify
python3 scripts/images-release.py promote
```

`verify` usa os digests Elven já promovidos no lock e falha enquanto não existirem. `promote` usa `release.json` verificado, consulta novamente as imagens no registry, valida assinatura/attestations e labels de base/revisão nas duas arquiteturas. Emite `artifacts/images/versions.promoted.lock.json` para revisão; **não altera automaticamente o lock, chart ou instalação de ninguém**. Depois de revisar, o mantenedor atualiza lock e os defaults do chart juntos, executa os testes e cria a release. Não inventar digests nem apontar o chart para imagens que ainda não foram publicadas.

## Estado desta revisão e gates pendentes

Em 29/10 foram construídos OCI multiarch e escaneadas separadamente **ambas as arquiteturas** dos três runtimes finais, com Trivy 0.76.1 e DB atual. O Collector completo oficial falhou com **1 High** (CVE-2026-116587); o novo Collector mínimo e os wrappers finais Beyla/Alloy passaram com **0 High/Critical**. Permanecem achados UNKNOWN e, no Alloy, Medium/Low, detalhados em [versões e advisories](versions.md#segurança-e-atualização). `govulncheck 1.9.0` passou na análise de símbolos de ambos os binários mínimos; não é execução nativa amd64 nem prova de ausência de vulnerabilidades. Consulte [evidência sanitizada das imagens](../images/validation-2026-10-29.json) e os relatórios completos nos artefatos locais.

A validação arm64 executou o Collector mínimo real, o profiler wrapper e o ciclo de vida Kind com entrega TLS, outage e replay. A captura Beyla/eBPF no host **não foi executada**. Build/scan amd64 foram executados por cross-build/análise do artefato; execução nativa amd64 é um gate preparado no CI, **ainda não executado nesta estação**.

Publicação Docker Hub, assinatura GitHub OIDC, verificação remota de identidade e promoção real **não foram executadas**. O lock permanece `not-published`, com digests Elven nulos. O chart continua usando os digests upstream reais somente para desenvolvimento, e a CLI bloqueia instalação normal enquanto não houver promoção verificada; usar `--development-images` é uma autorização explícita de laboratório, não aprovação de produção. Configurar credenciais/environment, executar a tag aprovada, conferir as imagens públicas e revisar lock/defaults é necessário para concluir esses gates. Os builds locais `1.0.0-dev` com fonte suja não podem ser promovidos como release.
