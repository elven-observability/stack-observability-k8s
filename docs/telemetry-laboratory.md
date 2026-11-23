# Contrato de evidência do laboratório de telemetria

Uma rodada nova exige engine Docker local e dedicada, sem containers em
execução. O harness usa seu próprio nome `elven-dist-*`, kubeconfig e contexto.
Antes de criar Kind ou baixar imagens, exige ao menos 8 GiB livres no volume
de saída para core ou 12 GiB para o lab com aplicações. Esses valores são um
piso conservador de admissão, não garantem espaço/CPU/memória suficientes na VM.
O operador precisa provisionar capacidade para o lab; ele não aumenta uma VM
nem apaga imagens, caches ou containers de outros trabalhos.

Em 23/11/2026, o volume local estava com menos de 4 GiB livres e o único
Docker ativo hospedava serviços de outro projeto. O lab foi recusado antes
de qualquer criação/pull; nenhum teste Kubernetes novo foi realizado.

## O que a fonte atual realmente testa

| Caminho | Exercício definido | Limite |
| --- | --- | --- |
| `scripts/test-kind.py` | OTLP sintético dos três sinais, privacidade, falha/replay, upgrade/rollback core, retenção de PVC | Não gera HTTP/SQL/Redis de SDK real |
| `scripts/test-instrumentation-kind.py` | Admission e aplicações reais Java 17/21, Node 22 e Node 20 explicitamente EOL; spans HTTP e JDBC/H2 em Java | Não cobre logs/métricas por runtime, Python, Redis, exceptions ou rollback de app |
| `processor/elvenprivacyprocessor` | OTLP Go real em memória: HTTP erro/exception, SQL/literais/binds, Redis e correlação, logs e métricas | Não prova imagem final, filas em disco, SDK, backend, assinatura ou cluster |

`report.json` da suíte SDK contém `runtime_coverage`: cada célula começa em
`NOT_TESTED` e muda para `PASS` apenas depois da asserção correspondente nos
sinais recebidos. Uma execução com `completed=true` concluiu os testes
definidos dessa suíte; não converte as demais células em aprovadas. O campo
`customer_acceptance` continua falso.

## Gates para o consumidor do template

Para promover uma combinação de runtime/sinais, executar uma aplicação real,
sem SDK dentro da fixture, com as imagens Elven promovidas e seus digests.
Registrar canário exclusivo para cada cenário: HTTP cliente/servidor, erro
com exception.type, SQL com placeholders e sem binds/literais, Redis com
comando e sem key/argument/value/script, e correlação logs/metrics/traces.
Ler os três sinais no sink/armazenamento independente e verificar que os
sentinels sintéticos privados não chegaram a export/queue. Adicionar casos
negativos de certificado/autorização, namespace e app não selecionados,
limite de recursos e coexistência de SDK/eBPF. Executar rollback da app e
da release, preservando identidades e conteúdo dos PVC/Secrets previstos.

O default CNI do Kind não aplica NetworkPolicy: instalação saudável nesse
ambiente não prova isolamento de rede. Usar CNI com enforcement num ensaio
próprio, com probes allow/deny de ambos os lados, antes de ampliar o aceite.

Os novos testes Redis do processor corrigem uma lacuna da fonte: comandos
e keys não eram SQL e escapavam pelos atributos/nome do span. Essa correção
exige novo build, scan, assinatura e promoção do Collector. Não reaplicar
valores de Helm nem reusar a imagem v1.0.1 para afirmar que a correção entrou.
