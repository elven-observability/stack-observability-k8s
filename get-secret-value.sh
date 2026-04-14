#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${1:?namespace is required}"
SECRET_NAME="${2:?secret name is required}"
KEY_NAME="${3:?secret key is required}"

if ! kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1; then
  echo "Namespace ${NAMESPACE} not found. Create it before running helmfile apply." >&2
  exit 1
fi

if ! kubectl get secret "${SECRET_NAME}" -n "${NAMESPACE}" >/dev/null 2>&1; then
  echo "Secret ${NAMESPACE}/${SECRET_NAME} not found. Create it before running helmfile apply." >&2
  exit 1
fi

encoded_value="$(
  kubectl get secret "${SECRET_NAME}" \
    -n "${NAMESPACE}" \
    -o "jsonpath={.data.${KEY_NAME}}"
)"

if [[ -z "${encoded_value}" ]]; then
  echo "Secret ${NAMESPACE}/${SECRET_NAME} is missing key ${KEY_NAME}." >&2
  exit 1
fi

if printf '%s' "${encoded_value}" | base64 --decode >/dev/null 2>&1; then
  printf '%s' "${encoded_value}" | base64 --decode
else
  printf '%s' "${encoded_value}" | base64 -D
fi
