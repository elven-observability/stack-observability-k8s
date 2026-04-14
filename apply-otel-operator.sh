#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

FILE="opentelemetry-operator/instrumentation.yaml"
OPERATOR_NAMESPACE="${OPERATOR_NAMESPACE:-monitoring}"
INSTRUMENTATION_TARGET_NAMESPACES="${INSTRUMENTATION_TARGET_NAMESPACES:-}"
EXCLUDED_NAMESPACES_REGEX="${EXCLUDED_NAMESPACES_REGEX:-^(kube-system|kube-public|kube-node-lease|cert-manager|monitoring|ingress-nginx|kong|kong-system|cnpg-system|calico-apiserver|calico-system|tigera-operator|cattle-system|istio-system|linkerd|linkerd-viz|metallb-system|longhorn-system|velero|argocd|flux-system|kyverno|kyverno-system|gatekeeper-system|mgk-.*|sentinel)$}"
failed_namespaces=""
DEPRECATED_VOLUME_WARNING_REGEX='^Warning: spec\.(java|nodejs|python|dotnet|go|apachehttpd|nginx)\.volumeSizeLimit is deprecated and will be removed in a future release; use spec\.[^.]+\.volume\.size instead$'

apply_instrumentation_manifest() {
  local namespace="$1"
  local output=""

  if ! output="$(kubectl apply -n "${namespace}" -f "${FILE}" 2>&1)"; then
    printf '%s\n' "${output}" | grep -Ev "${DEPRECATED_VOLUME_WARNING_REGEX}" >&2 || true
    return 1
  fi

  printf '%s\n' "${output}" | grep -Ev "${DEPRECATED_VOLUME_WARNING_REGEX}" || true
}

echo "Waiting for Instrumentation CRD..."
kubectl wait --for=condition=established crd/instrumentations.opentelemetry.io --timeout=60s

echo "Waiting for elven-instrumentation-operator controller..."
kubectl wait \
  -n "${OPERATOR_NAMESPACE}" \
  --for=condition=Available \
  deployment/elven-instrumentation-operator-controller-manager \
  --timeout=300s

if [[ -n "${INSTRUMENTATION_TARGET_NAMESPACES}" ]]; then
  namespace_stream="$(tr ',' '\n' <<<"${INSTRUMENTATION_TARGET_NAMESPACES}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | awk 'NF')"
else
  namespace_stream="$(kubectl get namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')"
fi

while IFS= read -r ns; do
  [[ -z "${ns}" ]] && continue

  if [[ "${ns}" =~ ${EXCLUDED_NAMESPACES_REGEX} ]]; then
    continue
  fi

  echo "Applying Instrumentation to namespace: ${ns}"
  if ! apply_instrumentation_manifest "${ns}"; then
    echo "Warning: failed to apply Instrumentation to namespace ${ns}. Skipping." >&2
    failed_namespaces+="${ns}"$'\n'
  fi
done <<< "${namespace_stream}"

if [[ -n "${failed_namespaces}" ]]; then
  echo "Instrumentation skipped for these namespaces:" >&2
  printf '%s' "${failed_namespaces}" >&2
fi
