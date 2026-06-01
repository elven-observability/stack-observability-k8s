#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${ELVEN_NAMESPACE:-monitoring}"
SECRET_NAME="${ELVEN_MYSQL_PASSWORD_SECRET:-elven-mysql-exporter}"
SECRET_KEY="${ELVEN_MYSQL_PASSWORD_SECRET_KEY:-password}"
MYSQL_PASSWORD="${ELVEN_MYSQL_PASSWORD:-${MYSQL_EXPORTER_PASSWORD:-}}"

fail() {
  printf 'elven-mysql: %s\n' "$*" >&2
  exit 1
}

if [[ -z "${MYSQL_PASSWORD}" && -t 0 ]]; then
  printf 'MySQL exporter password: ' >&2
  IFS= read -r -s MYSQL_PASSWORD
  printf '\n' >&2
fi

[[ -n "${MYSQL_PASSWORD}" ]] || fail "set ELVEN_MYSQL_PASSWORD before running this script."

kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1 || kubectl create namespace "${NAMESPACE}" >/dev/null

kubectl -n "${NAMESPACE}" create secret generic "${SECRET_NAME}" \
  --from-literal="${SECRET_KEY}=${MYSQL_PASSWORD}" \
  --dry-run=client \
  -o yaml | kubectl apply -f - >/dev/null

printf 'elven-mysql: secret %s/%s is ready.\n' "${NAMESPACE}" "${SECRET_NAME}"
