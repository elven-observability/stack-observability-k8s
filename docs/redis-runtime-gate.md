# Gate Redis do Collector candidato

O gate `tests/privacy-runtime.py` contém um corpus OTLP sintético Redis, enviado
por mTLS ao **binário candidato real**, pelo chart renderizado. Ele não inicia
Redis, não executa um SDK e não prova a auto-instrumentação de nenhuma biblioteca.
Também não acessa cluster, backend ou dados de cliente.

Casos: GET, SET, EVAL, AUTH, HGET com `redis.command` sem `db.system` e
representação RESP desconhecida. Chaves/valores/Lua/credenciais são sentinelas
sintéticos; incluem uma chave parecida com stack frame. Entram no nome do span,
query, campos Redis, erros/status/eventos, logs OTLP estruturados e JSON, ponto
de métrica e exemplar correlacionado.

O teste só chega a PASS após:

1. Exportação HTTPS autenticada dos seis casos, com logs/spans/métrica reais.
   Rejeita qualquer sentinela privada e exige operações finitas (ou marcador
   fail-closed para RESP), tipo RedisError, status ERROR, texto útil, IDs de
   trace/span/parent e exemplar, valor da métrica e índice numérico do banco.
2. Reenvio do conteúdo já sanitizado pelo mesmo processor: conteúdo semântico
   preservado, sem alegação de exactly-once.
3. Destino em HTTP 503; tentativa de exportação dos três sinais; Collector
   parado com as filas persistidas; leitura **somente leitura** dos arquivos
   WAL, como UID do runtime. Exige ausência de todos os sentinelas e presença
   de marcadores distintos de log, trace e métrica, além da redação.
4. Reinício do mesmo container/fila e recuperação dos três sinais. Conteúdo
   semântico sanitizado e correlação devem coincidir com o que foi tentado
   antes da parada. Retentativas são tratadas como entrega at-least-once.
5. Os demais gates existentes, inclusive strict, mTLS e limpeza, também passam.

Diagnósticos Redis podem ecoar chaves/scripts arbitrários: somente esses campos
sensíveis são mascarados integralmente. A mensagem operacional independente,
tipo do erro, operação e correlação são preservados. Não se promete preservar
stack frames Redis que poderiam ser a própria chave privada.

## Executar pelo CI existente

O workflow `images.yaml` já executa o teste após construir, escanear e carregar
o archive OCI exato, e novamente na qualificação nativa arm64. A construção
também executa os testes Go do processor. PRs/dispatch de branch não publicam;
não criar tag nem aprovar o environment de release como parte desse gate.

Depois de um build/scan candidato completo, é possível repetir a qualificação
com os mesmos archives nos runners amd64/arm64:

```sh
gh workflow run images.yaml --ref REVISAO_APROVADA \
  -f candidate_run=ID_DO_BUILD_SCAN_APROVADO
```

O workflow confere hashes de todas as entradas das imagens, archives, relatórios
e SBOM, além da idade do scan/DB. Se o processor mudar, um archive anterior
**não serve**: fazer novo build/scan no CI. Não baixar OCI nem executar Docker
no Mac sem capacidade. A execução direta `python3 tests/privacy-runtime.py`
exige `ELVEN_COLLECTOR_IMAGE` pinada no digest candidato, Docker descartável
autorizado e dependências pinadas; não usar o digest antigo como fallback.

Recibos: artifacts `elven-runtime-evidence` e
`elven-native-arm-runtime-evidence`, arquivo `.artifacts/privacy-*/report.json`.
O report deve identificar digest, arquitetura, config, dependências, os três
checks Redis, WAL/replay e limpeza concluída. Relatórios de falha não são aceite.

`tests/test_redis_runtime_contract.py` apenas testa o corpus e as próprias
asserções com um oracle manual, incluindo negativos. **Verde nele não comprova
sanitização, WAL ou execução do Collector.** O novo campo `redis.script` também
recebe guard de redação na fonte; exige Collector reconstruído, testado,
escaneado, assinado e promovido antes de qualquer alegação sobre a release.
