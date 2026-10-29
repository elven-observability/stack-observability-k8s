#!/usr/bin/env bash
set -euo pipefail

if [[ "${ELVEN_ALLOW_UNSUPPORTED_LEGACY:-}" != "1" ]]; then
  printf '%s\n' 'legacy/v0: deprecated and unsupported; execution blocked. Read UNSUPPORTED.md and review ownership risks before explicitly setting ELVEN_ALLOW_UNSUPPORTED_LEGACY=1.' >&2
  exit 78
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_DIR}"

"${SCRIPT_DIR}/validate-endpoints.sh"
"${SCRIPT_DIR}/preflight.sh"
"${SCRIPT_DIR}/ensure-secrets.sh"
"${REPO_DIR}/render-prometheus-values.sh"
