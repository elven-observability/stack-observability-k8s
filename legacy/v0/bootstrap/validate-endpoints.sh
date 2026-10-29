#!/usr/bin/env bash
set -euo pipefail

if [[ "${ELVEN_ALLOW_UNSUPPORTED_LEGACY:-}" != "1" ]]; then
  printf '%s\n' 'legacy/v0: deprecated and unsupported; execution blocked. Read UNSUPPORTED.md and review ownership risks before explicitly setting ELVEN_ALLOW_UNSUPPORTED_LEGACY=1.' >&2
  exit 78
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ALLOY_VALUES="${REPO_DIR}/elven-logs-collector/values-alloy.yaml"
CANONICAL_PUSH_URL="https://loki.elvenobservability.com/loki/api/v1/push"

grep -Fq "${CANONICAL_PUSH_URL}" "${ALLOY_VALUES}" || {
  echo "bootstrap: Alloy must use ${CANONICAL_PUSH_URL}." >&2
  exit 1
}

if grep -Fq 'logs.elvenobservability.com' "${ALLOY_VALUES}"; then
  echo "bootstrap: Alloy still uses the legacy logs.elvenobservability.com host." >&2
  exit 1
fi

if grep -Eq 'insecure_skip_verify[[:space:]]*=[[:space:]]*true' "${ALLOY_VALUES}"; then
  echo "bootstrap: disabling Loki TLS verification is forbidden." >&2
  exit 1
fi

echo "bootstrap: canonical Loki endpoint validation passed."
