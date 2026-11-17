# Elven Observability 1.0.1

Use o [kit completo](https://github.com/elven-observability/stack-observability-k8s/releases/download/v1.0.1/elven-instalacao-v1.0.1.zip), confira seu [.zip.sha256](https://github.com/elven-observability/stack-observability-k8s/releases/download/v1.0.1/elven-instalacao-v1.0.1.zip.sha256), preencha `plataforma/cliente.toml` e execute `./instalar`. O token é solicitado sem eco e fica no Secret próprio do Kubernetes; não vai no TOML. Não há modo de desenvolvimento nesse caminho.

O instalador valida e reconcilia gateway, módulos aprovados e Operator, sem depender do gateway/agentes do cliente. Não reinicia aplicações: SDKs exigem opt-in revisado por Pod template. Logs stdout/stderr ficam nos namespaces autorizados. eBPF exige deployments/nodes explícitos e aprovação de acesso ao host; exclui SDKs por padrão. Profiles continua opcional, sem backend presumido e sem sanitização OTLP de frames.

## Imagens imutáveis

Todas em `docker.io/elvenobservability`, tag `v1.0.1`, índices amd64/arm64:

| Imagem | Digest |
|---|---|
| `elven-collector` | `sha256:d6cb61db477227ed6b6bb673a43ba87dd2c893a61c6eb3febfeda3476ae398e4` |
| `elven-ebpf` | `sha256:68cd44f1aeafce7305a555e124f9687b1760db62bf7ea3e81e7d67af4f538f62` |
| `elven-profiler` | `sha256:f22e2e8099706ea1cec50d0fced8a7747598fe24956752df200dd5bff2eb3c1d` |
| `elven-instrumentation-operator` | `sha256:02bbd134aeb266b847acdcbce101b87f939d1dcfc0504644e658ad7ec169d9fb` |
| `elven-auto-java` | `sha256:d12eb4f89103253645a387728a882a6834b5a7f2016bd3809ab4987cff2be87d` |
| `elven-auto-nodejs` | `sha256:8b0d5f780b98346a4d2cfe3ae7f91fa40acb631465fcd0f855075c27b29a09c0` |
| `elven-auto-nodejs20` | `sha256:4181555e365edab084427d771025648ed58ba18744c6cb7c70b0dac6ca102aab` |
| `elven-auto-python` | `sha256:877ef1d6825eabe4911377a2103ede2024add278df504554de8789afeabf220b` |

O source das imagens é `7dea21b4391f5d0107bec8c280518fe097f9c494`, fixado pela tag protegida. A revisão de configuração instalável é posterior à promoção e consta em `INSTALL-MANIFEST.json`; a fonte do bootstrap consta em `kit.manifest.json`. **Não usar o Source code automático da tag como pacote de instalação.** A fonte de build recusa instalar silenciosamente um kit antigo.

## Evidências e segurança

- [Pipeline do núcleo](https://github.com/elven-observability/stack-observability-k8s/actions/runs/44100325545): seis scans High/Critical aprovados, Govuln/licenças, seis validações de runtime/configuração por arquitetura, seis grupos de testes de privacidade/WAL por arquitetura e 25 checks de ciclo de vida em cada arquitetura nativa.
- [Pipeline de SDKs](https://github.com/elven-observability/stack-observability-k8s/actions/runs/44100325488): dez scans aprovados e 20 checks de injeção/telemetria em cada arquitetura nativa, incluindo HTTP/JDBC e autenticação mTLS real dos exports.
- Publicação protegida por revisão; mesmos bytes escaneados enviados ao registry, assinados por OIDC e verificados com ambos SPDX e metadata exatos. Os locks contêm identidade do workflow/tag, source e hashes dos predicados aprovados. [Verificação independente](supply-chain.md).
- [Pacote permanente de evidências](https://github.com/elven-observability/stack-observability-k8s/releases/download/v1.0.1/elven-observability-v1.0.1-evidence.tar.gz): reports, SBOMs, metadata e recibos sanitizados do piloto. O ambiente-alvo e os limites do ensaio são parte da evidência, não uma certificação universal.

Collector 0.165.0 mantém a defesa contra recursão protobuf hostil. O teste separa rejeição HTTP 400 da sanitização de ramos acima do budget, sem aumentar limites. Beyla 3.42.0 é compilado de fontes imutáveis com x/net 0.62.0, preservando Java/JNI e licenças. Um patch Elven fixado por hash oferece validação pelo mesmo loader do startup sem iniciar captura. [Versões e decisões](versions.md).

## Limites e atualização

Kubernetes 1.35–1.37 é a faixa declarada; admissão, CNI/CSI, capacidade e kernels exigem qualificação no cliente. Java 17/21 e Node 22.15+ têm os perfis atuais; Node20 é exceção EOL explícita e Python permanece beta opt-in. Não há promessa de todos os métodos/statements, PII universal, profiling automático, SDK injection Go/.NET/PHP ou HA de gateway.

Os digests opcionais afetados da v1.0.0 continuam em `runtimeBlocks`. Assets, assinaturas e tags históricos não foram sobrescritos. A instalação v1 não migra nem adota releases legadas automaticamente. Preserve Secrets/PVC e consulte [operação/rollback](operations.md) antes de qualquer recuperação; falha entre gateway e Operator pode deixar estado parcial.
