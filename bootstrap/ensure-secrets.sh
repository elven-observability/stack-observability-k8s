#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_DIR}"

NAMESPACE="${ELVEN_NAMESPACE:-monitoring}"
CREDENTIALS_SECRET="${ELVEN_CREDENTIALS_SECRET:-elven-observability-credentials}"
COLLECTOR_FE_SECRET="${COLLECTOR_FE_SECRET_NAME:-elven-collector-fe-env-secret}"

log() {
  printf 'bootstrap: %s\n' "$*"
}

fail() {
  printf 'bootstrap: %s\n' "$*" >&2
  exit 1
}

base64_decode() {
  if ! base64 --decode >/dev/null 2>&1 <<<"dGVzdA=="; then
    base64 -D
  else
    base64 --decode
  fi
}

secret_key_value_or_empty() {
  local namespace="$1"
  local secret="$2"
  local key="$3"
  local encoded=""

  encoded="$(kubectl get secret "${secret}" -n "${namespace}" -o "jsonpath={.data.${key}}" 2>/dev/null || true)"
  [[ -n "${encoded}" ]] || return 0

  printf '%s' "${encoded}" | base64_decode
}

secret_has_key() {
  local namespace="$1"
  local secret="$2"
  local key="$3"
  local encoded=""

  encoded="$(kubectl get secret "${secret}" -n "${namespace}" -o "jsonpath={.data.${key}}" 2>/dev/null || true)"
  [[ -n "${encoded}" ]]
}

generate_secret_key() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 48
  else
    date +%s | shasum -a 256 | awk '{print $1}'
  fi
}

kubectl apply -f monitoring-namespace.yaml >/dev/null

if [[ -n "${ELVEN_TENANT_ID:-}" || -n "${ELVEN_API_TOKEN:-}" ]]; then
  [[ -n "${ELVEN_TENANT_ID:-}" ]] || fail "ELVEN_TENANT_ID is required when bootstrapping credentials."
  [[ -n "${ELVEN_API_TOKEN:-}" ]] || fail "ELVEN_API_TOKEN is required when bootstrapping credentials."

  kubectl -n "${NAMESPACE}" create secret generic "${CREDENTIALS_SECRET}" \
    --from-literal=tenantId="${ELVEN_TENANT_ID}" \
    --from-literal=apiToken="${ELVEN_API_TOKEN}" \
    --dry-run=client \
    -o yaml | kubectl apply -f - >/dev/null

  log "credentials secret ${NAMESPACE}/${CREDENTIALS_SECRET} is ready."
elif secret_has_key "${NAMESPACE}" "${CREDENTIALS_SECRET}" tenantId && secret_has_key "${NAMESPACE}" "${CREDENTIALS_SECRET}" apiToken; then
  log "using existing credentials secret ${NAMESPACE}/${CREDENTIALS_SECRET}."
else
  fail "missing ${NAMESPACE}/${CREDENTIALS_SECRET}. Run: ELVEN_TENANT_ID=<tenant> ELVEN_API_TOKEN=<token> helmfile apply"
fi

existing_secret_key="$(secret_key_value_or_empty "${NAMESPACE}" "${COLLECTOR_FE_SECRET}" SECRET_KEY)"
existing_loki_url="$(secret_key_value_or_empty "${NAMESPACE}" "${COLLECTOR_FE_SECRET}" LOKI_URL)"
existing_allow_origins="$(secret_key_value_or_empty "${NAMESPACE}" "${COLLECTOR_FE_SECRET}" ALLOW_ORIGINS)"
existing_jwt_issuer="$(secret_key_value_or_empty "${NAMESPACE}" "${COLLECTOR_FE_SECRET}" JWT_ISSUER)"

collector_fe_secret_key="${COLLECTOR_FE_SECRET_KEY:-${existing_secret_key:-$(generate_secret_key)}}"
collector_fe_loki_url="${COLLECTOR_FE_LOKI_URL:-${existing_loki_url:-https://logs.elvenobservability.com}}"
collector_fe_allow_origins="${COLLECTOR_FE_ALLOW_ORIGINS:-${existing_allow_origins:-https://*.elvenobservability.com}}"
collector_fe_jwt_issuer="${COLLECTOR_FE_JWT_ISSUER:-${existing_jwt_issuer:-elven-observability}}"

kubectl -n "${NAMESPACE}" create secret generic "${COLLECTOR_FE_SECRET}" \
  --from-literal=SECRET_KEY="${collector_fe_secret_key}" \
  --from-literal=LOKI_URL="${collector_fe_loki_url}" \
  --from-literal=ALLOW_ORIGINS="${collector_fe_allow_origins}" \
  --from-literal=JWT_ISSUER="${collector_fe_jwt_issuer}" \
  --dry-run=client \
  -o yaml | kubectl apply -f - >/dev/null

log "collector-fe secret ${NAMESPACE}/${COLLECTOR_FE_SECRET} is ready."
