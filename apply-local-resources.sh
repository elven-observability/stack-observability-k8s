#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

restart_if_present() {
  local resource="$1"
  local namespace="$2"

  if kubectl get "${resource}" -n "${namespace}" >/dev/null 2>&1; then
    kubectl rollout restart "${resource}" -n "${namespace}"
    kubectl rollout status "${resource}" -n "${namespace}" --timeout=300s
  fi
}

kubectl apply -f cert-manager/cluster-issuer.yaml
kubectl apply -k .
./apply-otel-operator.sh

restart_if_present deployment/opentelemetrycollector monitoring
restart_if_present deployment/elven-collector-fe monitoring
restart_if_present daemonset/elven-logs-collector monitoring
