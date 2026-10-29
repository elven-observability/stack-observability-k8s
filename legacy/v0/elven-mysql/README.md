# elven-mysql

Monitoramento opcional de MySQL rodando dentro do Kubernetes.

O componente usa `prometheus-mysql-exporter`, cria um `ServiceMonitor` para o Prometheus da stack e envia as metricas para Mimir pelo `remoteWrite` ja configurado em `elven-prometheus`.

## Habilitar

1. Crie um usuario de leitura no MySQL:

```sql
CREATE USER 'exporter'@'%' IDENTIFIED BY '<MYSQL_EXPORTER_PASSWORD>' WITH MAX_USER_CONNECTIONS 3;
GRANT PROCESS, SELECT ON *.* TO 'exporter'@'%';
FLUSH PRIVILEGES;
```

O scraper de replication status fica desligado por padrao para nao exigir `REPLICATION CLIENT`.

2. Crie a Secret no namespace da stack:

```bash
export ELVEN_MYSQL_PASSWORD="<MYSQL_EXPORTER_PASSWORD>"
./elven-mysql/create-secret.sh
```

3. Ajuste o Service DNS do MySQL em `elven-mysql/values.yaml`:

```yaml
mysql:
  host: mysql.default.svc.cluster.local
  port: 3306
  user: exporter
```

4. Habilite a release no `helmfile.yaml`:

```yaml
- name: elven-mysql
  installed: true
```

5. Aplique:

```bash
helmfile apply
```

## Labels de scrape

O `ServiceMonitor` usa `jobLabel: elven_job`, entao as series chegam com:

- `job="elven-mysql"`
- `elven_component="mysql"`
- `elven_stack="observability"`
- `db_system="mysql"`
- `db_role="primary"`
- `scrape_source="serviceMonitor"`

O chart upstream vem com annotations `prometheus.io/*`, mas aqui `prometheus.io/scrape` fica `"false"` para evitar scrape duplicado pelo `elven-otel-collector`. O caminho oficial desta integracao e somente via `ServiceMonitor`.

Para coletar metricas de replica/replication, habilite `collectors.slave_status: true` em `elven-mysql/values.yaml` e conceda `REPLICATION CLIENT` ao usuario do exporter.

## Verificar

```bash
kubectl get deploy,svc,servicemonitor,prometheusrule -n monitoring | grep elven-mysql
kubectl logs -n monitoring deploy/elven-mysql --since=5m
kubectl port-forward -n monitoring svc/elven-mysql 9104:9104
curl -s http://localhost:9104/metrics | grep '^mysql_up'
```
