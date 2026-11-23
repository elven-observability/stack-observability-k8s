# Dados sintéticos, não uma aprovação

`request.json`, `plan.json`, `materialized.json`, `baseline.json` e
`rollback.json` formam um round-trip determinístico em
`2026-11-23T12:00:00+00:00`. A ligação de catálogo `cccc…cccc` é deliberadamente
falsa: a CLI recusa esses exemplos contra o catálogo real. UIDs, tenant,
endereços TEST-NET, snapshots e revisões são sintéticos.

O teste injeta essa identidade apenas na API pura de teste. Uma engine real
admite o catálogo por canal confiável, observa o cluster e gera outro plano;
nunca promove uma fixture, hash ou status declarado a autorização.

Casos executados em `tests/test_template_contract.py`: catálogo/digests e
predicados, schemas fechados, determinismo, renders Helm reais sem Secrets,
entrada extra/segredos/comandos recusados, consentimento de host, UID/escopo,
instrumentação duplicada, tempo, adulteração de ações/gates com novo hash,
diff e remoção de app, troca de cluster/tenant, eBPF com loader desconhecido,
rollback com baseline recente e parsing hostil/oversized.

O adaptador não executa Kubernetes. O teste de contrato não comprova OAuth,
aprovação, admission, coleta SDK, filas, tenant ou rollback real da engine.
