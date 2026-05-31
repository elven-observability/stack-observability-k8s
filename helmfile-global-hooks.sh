#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

HELMFILE_COMMAND="${1:-}"
HOOK_PHASE="${2:-}"

case "${HELMFILE_COMMAND}:${HOOK_PHASE}" in
  destroy:prepare|delete:prepare)
    echo "helmfile-global-hooks: command=${HELMFILE_COMMAND} phase=${HOOK_PHASE}"
    ./destroy-kustomize-resources.sh
    ;;
  apply:cleanup|sync:cleanup)
    echo "helmfile-global-hooks: command=${HELMFILE_COMMAND} phase=${HOOK_PHASE}"
    ./apply-local-resources.sh
    ;;
  apply:prepare|sync:prepare|diff:prepare|template:prepare|lint:prepare)
    echo "helmfile-global-hooks: command=${HELMFILE_COMMAND} phase=${HOOK_PHASE}"
    ./bootstrap/prepare.sh
    ;;
  *)
    exit 0
    ;;
esac
