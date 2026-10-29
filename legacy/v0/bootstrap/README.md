# Bootstrap

A stack e instalada pelo Helmfile. Na primeira instalacao, informe as credenciais do tenant por variaveis de ambiente:

```bash
export ELVEN_TENANT_ID="seu-tenant"
export ELVEN_API_TOKEN="<SEU_API_TOKEN>"
helmfile apply
```

O hook `prepare` do Helmfile cria ou atualiza as secrets Kubernetes, renderiza o values do Prometheus e deixa os charts prontos para instalacao. Nas proximas execucoes, `helmfile apply` reutiliza as secrets existentes sem receber o token novamente.

Nenhum token e escrito no repositorio. Arquivos gerados e `.env` locais sao ignorados pelo Git.

Componentes opcionais com credenciais proprias, como `elven-mysql`, seguem o mesmo principio: crie a Secret no cluster antes de habilitar a release. Para MySQL:

```bash
export ELVEN_MYSQL_PASSWORD="<MYSQL_EXPORTER_PASSWORD>"
./elven-mysql/create-secret.sh
```
