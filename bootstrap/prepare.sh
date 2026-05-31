#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_DIR}"

"${SCRIPT_DIR}/preflight.sh"
"${SCRIPT_DIR}/ensure-secrets.sh"
"${REPO_DIR}/render-prometheus-values.sh"
