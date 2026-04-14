#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

SOURCE_FILE="prometheus/values-prometheus.yaml"
TARGET_FILE="prometheus/values-prometheus.rendered.yaml"
PLACEHOLDER="__PROMETHEUS_REMOTE_WRITE_TENANT__"

tenant_id="$(./get-secret-value.sh monitoring elven-observability-credentials tenantId)"

sed "s/${PLACEHOLDER}/${tenant_id}/g" "${SOURCE_FILE}" > "${TARGET_FILE}"
