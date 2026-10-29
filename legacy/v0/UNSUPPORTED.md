# Legado v0 — histórico, não executar como nova instalação

Este diretório preserva o template anterior à refatoração, originalmente no commit `3978bcc`. Ele existe para comparação, análise de instalações antigas e preparação de uma migração manual. **Não é o caminho de instalação suportado da nova distribuição.**

Não execute seus scripts/Helmfile em um cluster para “testar” a migração. Há operações históricas que escrevem até durante `diff`, `template` ou `lint`, e rotinas de remoção que não verificam ownership. O bundle também inclui CRDs e webhooks de alcance global. Ver [diagnóstico](../../docs/audit-baseline.md).

Os entrypoints shell agora encerram com código 78 antes de qualquer ação, a menos que `ELVEN_ALLOW_UNSUPPORTED_LEGACY=1` seja fornecido explicitamente por quem revisou os riscos. Essa exceção permite uma recuperação histórica controlada; não torna o legado suportado, não é um comando de migração e não verifica ownership retroativamente. Não mantenha essa variável habilitada no ambiente de instalação normal.

Mover os arquivos para este diretório não altera uma instalação existente. Nenhum namespace, Secret, CRD, operador, aplicação ou release foi migrado, removido ou assumido automaticamente.

O Helmfile da raiz do repositório é apenas uma sentinela sem releases/hooks. Usar o comando antigo na raiz não instala a distribuição nova, não executa migração e não passa pelo gate de promoção de imagens. A nova CLI é o caminho de instalação; produção permanece bloqueada enquanto as imagens Elven não estiverem publicadas, assinadas e promovidas.

Use o [procedimento de migração](../../docs/migration.md): inventário de ownership, baseline de entrega, revisão de duplicação, piloto limitado, drenagem das filas e decisão explícita de cutover. Não use `helmfile destroy` do legado para remover indiscriminadamente componentes que possam pertencer ao cliente.
