# Instalação de produção

Este guia é para a equipe de plataforma. Escolha um caminho: **baixar o kit completo com `./instalar`** ou **instalar pela CLI** a partir do pacote técnico. Ambos estão no GitHub; não é necessário obter arquivos da máquina da Elven.

## Instalar com o kit público

Baixe `elven-instalacao-v1.0.0.zip` e `elven-instalacao-v1.0.0.zip.sha256` na [release v1.0.0](https://github.com/elven-observability/stack-observability-k8s/releases/tag/v1.0.0). Confira o checksum antes de extrair. O ZIP inclui launcher, bootstrap, modelo TOML e o pacote técnico original, com SHA-256 fixado. O [manifesto do kit](https://github.com/elven-observability/stack-observability-k8s/releases/download/v1.0.0/elven-instalacao-v1.0.0.manifest.json) vincula os arquivos à revisão Git do instalador. A tag, as imagens e o pacote original da v1.0.0 não são substituídos.

Siga [Preparar a configuração](../kit/plataforma/PREPARAR.md), também incluído no download. Preencha `plataforma/cliente.toml` uma vez, sem token, e rode `./instalar`. O modo guiado gera o plano de leitura e exige confirmação explícita antes da primeira escrita. Cancelar não cria aprovação; reexecuções conferem os hashes dos arquivos aprovados. Mudanças de configuração exigem preservar e revisar outro plano. O token é pedido sem eco só quando não há Secret próprio compatível com o tenant.

### Fonte, testes e reprodução

O diretório [`kit/`](../kit/COMECE-AQUI.md) contém a fonte pública. Quem clonar o repositório pode configurar `kit/plataforma/cliente.toml` e usar `cd kit && ./instalar`; se faltar o pacote interno, ele é baixado apenas da URL oficial por HTTPS e conferido pelo hash fixado. O ZIP já inclui o pacote e não depende desse download adicional.

Mantenedores podem gerar o ZIP a partir de um checkout **limpo e commitado**, sem arquivos de cliente, usando `python3 -I scripts/package-install-kit.py --output-dir .artifacts/install-kit`. O builder usa uma lista fechada de arquivos, recusa sobrescrita e gera ZIP determinístico, manifesto e checksum. O workflow `install-kit.yaml` executa testes do bootstrap, aprovação, launcher, ZIP e renders reais, sem cluster. Não sobrescreva um asset já publicado: mudanças posteriores exigem outro nome/versão de kit e nova validação.

## Instalar pela CLI da release

### Baixe o pacote certo

Na [release v1.0.0](https://github.com/elven-observability/stack-observability-k8s/releases/tag/v1.0.0), baixe `elven-observability-v1.0.0.tar.gz` e `SHA256SUMS` para uma pasta nova. O download automático **Source code** aponta para a revisão de build anterior à promoção dos digests; ele não é o pacote de instalação.

Com os dois arquivos na mesma pasta, verifique o checksum antes de extrair:

```sh
grep '  elven-observability-v1\.0\.0\.tar\.gz$' SHA256SUMS | shasum -a 256 -c - &&
  tar -xzf elven-observability-v1.0.0.tar.gz &&
  cd elven-observability-v1.0.0
```

Prossiga apenas se a verificação retornar `OK`. O pacote usa imagens Elven assinadas e fixadas por digest. O instalador confere se elas coincidem com os locks promovidos; veja como verificar as assinaturas na [cadeia de fornecimento](supply-chain.md#assinatura-identidade-e-promoção). Confirme também os limites de pull do registry no ambiente. O PAT de publicação da Elven não faz parte da instalação.

### Prepare os perfis e a identidade

Confirme a [matriz de suporte](support.md#matriz-declarada): Kubernetes 1.35–1.37, Python 3.11+, `kubectl` compatível, OpenSSL e Helm 4.3.1+ (preferido) ou 3.22.1+ (compatibilidade). Também são necessários acesso autorizado ao cluster, uma StorageClass adequada ao PVC e rede de saída para os destinos HTTPS da Elven.

1. Escolha o contexto explicitamente. Confira o UID do namespace `kube-system` com o registro do cluster aprovado:

   ```sh
   kubectl config get-contexts
   ELVEN_CONTEXT='CONTEXTO_APROVADO'
   kubectl --context "$ELVEN_CONTEXT" get namespace kube-system -o jsonpath='{.metadata.uid}'
   ```

2. Prepare o perfil do gateway a partir de [minimal.yaml](../examples/minimal.yaml). Defina a StorageClass, os CIDRs efetivos de egress e `collection.namespaces`. O exemplo vem com egress fechado. O gateway mínimo não ativa logs de containers, módulos de host/eBPF, profiles nem injeção de SDKs. Para coleta Kubernetes aprovada, use [kubernetes.yaml](../examples/kubernetes.yaml) como referência e revise acesso a nodes e namespaces.
3. Se o piloto usar o Operator Elven, prepare também [instrumentation.yaml](../examples/instrumentation.yaml): runtimes, namespaces, CIDRs reais do apiserver e identidade do gateway. O escopo deve estar autorizado no perfil do gateway. Veja os [runtimes suportados](../charts/elven-instrumentation/README.md#cobertura-e-limites).
4. Separe o tenant e o token em arquivos privados (`0600` ou `0400`), fora do Git. Nos comandos, passe apenas os caminhos. Para usar Secrets gerenciados pela plataforma em vez dos dois arquivos, siga o [procedimento de credenciais e PKI](security.md#credenciais-fora-dos-values-helm). Nunca grave o token nos values.

Substitua os valores e caminhos de exemplo pelos que foram aprovados. Se usar `--kubeconfig`, passe o mesmo arquivo a todos os comandos online, inclusive ao `kubectl` da conferência de UID.

```sh
ELVEN_CLUSTER_NAME='NOME_LOGICO_DO_CLUSTER'
ELVEN_CLUSTER_UID='UID_DO_CLUSTER_CONFERIDO'
ELVEN_VALUES='/caminho/privado/gateway.yaml'
ELVEN_INSTRUMENTATION_VALUES='/caminho/privado/instrumentation.yaml'
ELVEN_TENANT_FILE='/caminho/privado/tenant'
ELVEN_TOKEN_FILE='/caminho/privado/token'
```

### Revise e instale

Para revisar o gateway antes de qualquer escrita, renderize e rode o preflight de leitura. O render cria um arquivo novo sem os valores dos Secrets. Para revisar o manifesto do Operator separadamente, use o [render do módulo](../charts/elven-instrumentation/README.md#instalação-e-identidade). O render offline não é um manifesto pronto para aplicar.

```sh
./elven render --cluster-name "$ELVEN_CLUSTER_NAME" \
  --values "$ELVEN_VALUES" --output elven-reviewed.yaml

./elven preflight --context "$ELVEN_CONTEXT" \
  --cluster-name "$ELVEN_CLUSTER_NAME" --expect-cluster-uid "$ELVEN_CLUSTER_UID" \
  --values "$ELVEN_VALUES"
```

Quando a revisão estiver aprovada, o comando abaixo instala **gateway e Operator**. Para instalar só o gateway, remova a linha `--instrumentation-values`. A instalação já executa suas próprias validações. Não é necessário Helmfile nem modo de desenvolvimento.

```sh
./elven install --context "$ELVEN_CONTEXT" \
  --cluster-name "$ELVEN_CLUSTER_NAME" --expect-cluster-uid "$ELVEN_CLUSTER_UID" \
  --values "$ELVEN_VALUES" \
  --instrumentation-values "$ELVEN_INSTRUMENTATION_VALUES" \
  --tenant-file "$ELVEN_TENANT_FILE" --token-file "$ELVEN_TOKEN_FILE"
```

Os padrões são namespace `elven-observability`, release do gateway `elven` e release do Operator `elven-operator`. Se alterar a identidade, use os mesmos nomes nos perfis, na instalação e nas verificações. A CLI provisiona os Secrets separadamente do Helm; a aplicação usa mTLS até o gateway e não recebe o token da Elven.

As duas releases não formam uma transação. Se a instalação do Operator falhar depois do gateway, a CLI sinaliza estado parcial ou desconhecido e preserva dados. Consulte o estado das releases antes de repetir o comando. Não use a instalação para trocar tenant, rotacionar token ou migrar o legado.

## Valide o piloto

Confira o estado com `./elven status --context "$ELVEN_CONTEXT"` e, se instalou o Operator, com `python3 scripts/instrumentation.py status --context "$ELVEN_CONTEXT"`. Pods prontos não provam entrega.

A equipe de aplicações aplica o [opt-in no serviço piloto](../charts/elven-instrumentation/README.md#opt-in-explícito-sem-restart-automático) e conduz o rollout autorizado. Confira os [sinais esperados no tenant](operations.md#aceite-de-coleta-e-entrega) e a [proteção de dados](security.md#dados-sensíveis) antes de ampliar. Para incidentes, use o [diagnóstico e rollback](operations.md#atualização-e-rollback); para quem vem do Helmfile, siga a [migração do legado](migration.md).
