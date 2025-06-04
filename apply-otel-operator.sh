#!/bin/bash

FILE="opentelemetry-operator/instrumentation.yaml"

for ns in $(kubectl get ns --no-headers -o custom-columns=":metadata.name"); do
  echo "Applying to namespace: $ns"
  kubectl apply -f "$FILE" -n "$ns"
done
