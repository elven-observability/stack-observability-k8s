#!/usr/bin/env bash
set -euo pipefail

if [[ "${ELVEN_ALLOW_UNSUPPORTED_LEGACY:-}" != "1" ]]; then
  printf '%s\n' 'legacy/v0: deprecated and unsupported; execution blocked. Read UNSUPPORTED.md and review ownership risks before explicitly setting ELVEN_ALLOW_UNSUPPORTED_LEGACY=1.' >&2
  exit 78
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

SOURCE_FILE="elven-prometheus/values-prometheus.yaml"
TARGET_FILE="elven-prometheus/values-prometheus.rendered.yaml"
PLACEHOLDER="__PROMETHEUS_REMOTE_WRITE_TENANT__"

tenant_id="$(./get-secret-value.sh monitoring elven-observability-credentials tenantId)"

sed "s/${PLACEHOLDER}/${tenant_id}/g" "${SOURCE_FILE}" > "${TARGET_FILE}"
