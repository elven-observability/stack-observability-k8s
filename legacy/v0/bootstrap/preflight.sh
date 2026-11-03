#!/usr/bin/env bash
set -euo pipefail

if [[ "${ELVEN_ALLOW_UNSUPPORTED_LEGACY:-}" != "1" ]]; then
  printf '%s\n' 'legacy/v0: deprecated and unsupported; execution blocked. Read UNSUPPORTED.md and review ownership risks before explicitly setting ELVEN_ALLOW_UNSUPPORTED_LEGACY=1.' >&2
  exit 78
fi

fail() {
  printf 'bootstrap: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required in PATH."
}

require_cmd kubectl
require_cmd helm

kubectl version --client >/dev/null 2>&1 || fail "kubectl client is not working."
helm version --short >/dev/null 2>&1 || fail "helm client is not working."

if ! kubectl get namespace default >/dev/null 2>&1; then
  fail "kubectl cannot reach the target cluster. Check KUBECONFIG/current-context before running helmfile."
fi
