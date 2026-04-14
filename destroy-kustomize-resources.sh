#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

OPERATOR_NAMESPACE="${OPERATOR_NAMESPACE:-monitoring}"
INSTRUMENTATION_TARGET_NAMESPACES="${INSTRUMENTATION_TARGET_NAMESPACES:-}"
EXCLUDED_NAMESPACES_REGEX="${EXCLUDED_NAMESPACES_REGEX:-^(kube-system|kube-public|kube-node-lease|cert-manager|monitoring|ingress-nginx|kong|kong-system|cnpg-system|calico-apiserver|calico-system|tigera-operator|cattle-system|istio-system|linkerd|linkerd-viz|metallb-system|longhorn-system|velero|argocd|flux-system|kyverno|kyverno-system|gatekeeper-system|mgk-.*|sentinel)$}"
failed_namespaces=""

collect_target_namespaces() {
  if [[ -n "${INSTRUMENTATION_TARGET_NAMESPACES}" ]]; then
    tr ',' '\n' <<<"${INSTRUMENTATION_TARGET_NAMESPACES}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | awk 'NF'
  else
    kubectl get namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'
  fi
}

delete_instrumentations() {
  if ! kubectl get crd instrumentations.opentelemetry.io >/dev/null 2>&1; then
    echo "Instrumentation CRD not found, skipping Instrumentation cleanup."
    return
  fi

  while IFS= read -r ns; do
    [[ -z "${ns}" ]] && continue

    if [[ "${ns}" =~ ${EXCLUDED_NAMESPACES_REGEX} ]]; then
      continue
    fi

    echo "Deleting Instrumentation from namespace: ${ns}"
    if ! kubectl delete -n "${ns}" instrumentation instrumentation --ignore-not-found=true; then
      echo "Warning: failed to delete Instrumentation from namespace ${ns}. Skipping." >&2
      failed_namespaces+="${ns}"$'\n'
    fi
  done < <(collect_target_namespaces)

  if [[ -n "${failed_namespaces}" ]]; then
    echo "Instrumentation cleanup skipped for these namespaces:" >&2
    printf '%s' "${failed_namespaces}" >&2
  fi
}

echo "Deleting Instrumentation resources..."
delete_instrumentations

echo "Deleting ClusterIssuer..."
kubectl delete -f cert-manager/cluster-issuer.yaml --ignore-not-found=true || true

echo "Deleting collector config secret..."
kubectl delete -n "${OPERATOR_NAMESPACE}" secret secrets-collector-config --ignore-not-found=true || true

echo "Deleting collector-fe secret..."
kubectl delete -f collector-fe/collector-fe-env-secret.yaml --ignore-not-found=true || true

echo "Deleting OpenTelemetry Collector manifests..."
kubectl delete -f otel-collector/collector-service.yaml --ignore-not-found=true || true
kubectl delete -f otel-collector/collector-deploy.yaml --ignore-not-found=true || true
kubectl delete -f otel-collector/collector-rbac.yaml --ignore-not-found=true || true

echo "Deleting OpenTelemetry Operator manifests..."
kubectl delete -f opentelemetry-operator/opentelemetry-operator.yaml --ignore-not-found=true || true

echo "Done."
