#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

INSTRUMENTATION_NAMESPACE="${INSTRUMENTATION_NAMESPACE:-default}"
DEPRECATED_VOLUME_WARNING_REGEX='^Warning: spec\.(java|nodejs|python|dotnet|go|apachehttpd|nginx)\.volumeSizeLimit is deprecated and will be removed in a future release; use spec\.[^.]+\.volume\.size instead$'

apply_instrumentation_manifest() {
  local output=""

  if ! output="$(kubectl apply -n "$INSTRUMENTATION_NAMESPACE" -f instrumentation.yaml 2>&1)"; then
    printf '%s\n' "${output}" | grep -Ev "${DEPRECATED_VOLUME_WARNING_REGEX}" >&2 || true
    return 1
  fi

  printf '%s\n' "${output}" | grep -Ev "${DEPRECATED_VOLUME_WARNING_REGEX}" || true
}

echo "Applying elven-instrumentation-operator..."
kubectl apply -f opentelemetry-operator.yaml

echo "Waiting for CRD instrumentations.opentelemetry.io to be established..."
kubectl wait --for=condition=established crd/instrumentations.opentelemetry.io --timeout=60s

echo "Waiting for elven-instrumentation-operator controller to become available..."
kubectl wait \
  -n monitoring \
  --for=condition=Available \
  deployment/elven-instrumentation-operator-controller-manager \
  --timeout=180s

echo "Applying Instrumentation in namespace ${INSTRUMENTATION_NAMESPACE}..."
apply_instrumentation_manifest

echo "Done."
