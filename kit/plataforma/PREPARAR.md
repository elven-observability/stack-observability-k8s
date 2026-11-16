# Preparar a configuração

O kit público é genérico: nenhum token, kubeconfig ou dado de cliente acompanha o download. Você prepara só a configuração do ambiente. O comando `./instalar` gera o plano e pede aprovação na primeira execução; não precisa gerar arquivos na máquina da Elven.

## 1. Prepare o terminal

Use Linux ou macOS, Python 3.11+, `kubectl` compatível, **OpenSSL 3.x** e Helm 4.3.1+ ou a ponte de compatibilidade 3.22.1+. O cluster deve estar na faixa Kubernetes 1.35–1.37. Confira `python3 --version` e `openssl version` no terminal: o LibreSSL padrão de alguns macOS não é compatível com a validação da PKI. Instale ferramentas pelo procedimento aprovado da plataforma; o kit não modifica sua máquina nem instala pré-requisitos automaticamente.

Confirme storage, CNI, regras de rede, permissões e admissão com a plataforma. Consulte a [matriz de suporte](https://github.com/elven-observability/stack-observability-k8s/blob/main/docs/support.md) e o [guia técnico](https://github.com/elven-observability/stack-observability-k8s/blob/main/docs/installation.md). O kit usa imagens Elven promovidas por digest, sem modo de desenvolvimento. Para conferir assinaturas, siga a [cadeia de fornecimento](https://github.com/elven-observability/stack-observability-k8s/blob/main/docs/supply-chain.md).

## 2. Preencha um arquivo, sem token

Na pasta `plataforma/`, copie o modelo sem sobrescrever uma configuração existente:

```sh
umask 077
cp -n cliente.exemplo.toml cliente.toml
```

Preencha os campos do modelo com dados reais aprovados:

- `alvo`: caminho do kubeconfig confiável, contexto, UID de `kube-system`, nome/domínio do cluster e identificador exato do tenant. O kubeconfig fica no terminal do cliente, não no ZIP público. Confira o UID com `kubectl --kubeconfig CAMINHO --context CONTEXTO get namespace kube-system -o jsonpath='{.metadata.uid}'` e o registro do cluster esperado; não adivinhe a identidade pelo nome.
- `storage`: StorageClass real e tamanho do PVC. Não use armazenamento efêmero para contornar falhas.
- `coleta`: namespaces de aplicações aprovados. Essa lista delimita o ingresso OTLP e, se habilitados, logs stdout/stderr e métricas de estado Kubernetes. Logs do host exigem aprovação e seletor de nodes piloto ou aprovação explícita de todos os nodes elegíveis. Incluem os containers dos namespaces selecionados, inclusive sidecars. Não relaxe a segurança global do cluster.
- `instrumentacao`: namespaces autorizados, dentro da lista de coleta, e runtimes necessários. Java 17/21; Node.js atual 22.15+; Node.js 20 só com aprovação EOL explícita; Python beta opcional. A instrumentação ainda exige opt-in no Pod template pelo time da aplicação.
- `rede`: CIDRs efetivos de exportação HTTPS e de origem do apiserver para o webhook; DNS conforme o CNI. Com Calico/NAT, o IP de origem pode ser o túnel do control plane, não seu InternalIP: a plataforma deve confirmar o endereço observado. Métricas de estado também exigem CIDRs da API. Não há fallback para rede irrestrita. Endpoints Elven vêm do pacote oficial, incluindo `loki.elvenobservability.com` para logs.

Use `selective` para mascarar padrões sensíveis suportados preservando texto útil; `strict` remove o corpo do log. Não há detecção universal de PII nem captura de todos os statements. O log original da aplicação não é reescrito. eBPF, kubelet e profiles ficam desativados neste kit; use a CLI e os perfis técnicos revisados se precisar desses módulos.

## 3. Rode um comando e confira o plano

Volte à pasta que contém `instalar` e execute `./instalar`. Os quatro arquivos de values/manifests e o recibo ficam em `plataforma/revisao-v1.0.0/`, com acesso local restrito. Confira o resumo e os manifests, incluindo rede e storage. Só depois digite a confirmação exata pedida no terminal. Cancelar não solicita o token nem escreve no Kubernetes; uma revisão não aprovada não é aceita automaticamente numa execução posterior.

O token é pedido sem eco somente se o Secret próprio não existir. Ele não vai nos values, argumentos, Git ou arquivo de configuração. No Linux pode usar descritores de memória; no fallback usa arquivos temporários privados removidos ao encerrar normalmente. Interrupção forçada pode deixar resíduos privados: proteja o terminal, o disco e o diretório temporário. O Secret `elven-observability/elven-ingest` guarda `tenant-id` e `api-token`; configure RBAC e criptografia em repouso na plataforma. Não faça dump do Secret para diagnóstico.

O modo manual opcional `python3 -I instalar.py plano --config cliente.toml` continua disponível na pasta `plataforma/` para revisão de leitura separada. O `./instalar` exige aprovação explícita desse plano antes da primeira escrita, mesmo se ele foi gerado manualmente.

## Mudanças e falhas

Alterar configuração depois da aprovação bloqueia a reexecução. Preserve a pasta de revisão anterior em arquivo privado, mantenha a configuração correspondente e gere/revise outro plano antes de aprovar. Não apague provas para contornar divergências. O kit não adota recursos alheios, rotaciona token, troca tenant nem migra instalações legadas.

Gateway e Operator são duas fases, não uma transação. Falha ou timeout pode deixar estado parcial; preserve Secrets/PVCs e consulte [operação e recuperação](https://github.com/elven-observability/stack-observability-k8s/blob/main/docs/operations.md). A aprovação local não impede mutações simultâneas por administradores: evite outros escritores durante a instalação.

Depois do sucesso, faça o [opt-in e rollout autorizado do piloto](https://github.com/elven-observability/stack-observability-k8s/blob/main/charts/elven-instrumentation/README.md#opt-in-explícito-sem-restart-automático). Confirme coleta, privacidade e chegada no tenant correto; Pods prontos não provam entrega. Combine alertas e responsáveis por expiração do token/TLS, CIDRs e capacidade. O kit não promete credenciais permanentes nem renovação automática da PKI.

## Verificação do download

Com o ZIP e o checksum baixados do GitHub na mesma pasta, execute `shasum -a 256 -c elven-instalacao-v1.0.0.zip.sha256` (macOS) ou `sha256sum -c elven-instalacao-v1.0.0.zip.sha256` (Linux). Extraia só se retornar `OK`. O ZIP traz `kit.manifest.json` com revisão da fonte e hashes dos arquivos; o pacote interno também tem SHA-256 fixado no bootstrap. O kit tem checksum/proveniência Git, não uma assinatura criptográfica própria; as imagens têm sua verificação separada.

Quem clonar a fonte pode usar `cd kit && ./instalar` após configurar o ambiente. Se o pacote interno não estiver presente, o bootstrap o baixa da release oficial por HTTPS e confere o hash fixado antes de extrair. No ZIP ele já está incluído.
