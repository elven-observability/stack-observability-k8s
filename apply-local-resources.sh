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

delete_if_present() {
  local resource="$1"
  local namespace="$2"

  kubectl delete "${resource}" -n "${namespace}" --ignore-not-found=true >/dev/null 2>&1 || true
}

delete_cluster_if_present() {
  local resource="$1"
  kubectl delete "${resource}" --ignore-not-found=true >/dev/null 2>&1 || true
}

kubectl apply -f cert-manager/cluster-issuer.yaml
kubectl apply -k .
./apply-otel-operator.sh

delete_if_present deployment/opentelemetrycollector monitoring
delete_if_present service/opentelemetrycollector monitoring
delete_if_present serviceaccount/opentelemetrycollector monitoring
delete_cluster_if_present clusterrole/opentelemetrycollector-prometheus
delete_cluster_if_present clusterrolebinding/opentelemetrycollector-prometheus

restart_if_present deployment/elven-otel-collector monitoring
restart_if_present deployment/elven-collector-fe monitoring
restart_if_present daemonset/elven-logs-collector monitoring
