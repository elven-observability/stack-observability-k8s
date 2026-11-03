# Preserve the upstream SDK payload, copy utility, entrypoint and dependency licenses.
ARG UPSTREAM_IMAGE=ghcr.io/open-telemetry/opentelemetry-operator/autoinstrumentation-nodejs:0.82.0-3@sha256:609216a9e468279bd41b56829c1fd5e73cb29b5b1002ed95921bf59da854e09a
FROM ${UPSTREAM_IMAGE}
ARG VERSION=1.0.0-dev
ARG REVISION=unreleased
ARG CREATED
LABEL org.opencontainers.image.title="Elven Node.js Auto-Instrumentation" \
      org.opencontainers.image.description="Elven packaging of the unmodified pinned OpenTelemetry Node.js auto-instrumentation payload" \
      org.opencontainers.image.vendor="Elven Observability" \
      org.opencontainers.image.source="https://github.com/elven-observability/stack-observability-k8s" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="ghcr.io/open-telemetry/opentelemetry-operator/autoinstrumentation-nodejs:0.82.0-3" \
      org.opencontainers.image.base.digest="sha256:609216a9e468279bd41b56829c1fd5e73cb29b5b1002ed95921bf59da854e09a" \
      org.elvenobservability.instrumentation.version="0.82.0"
COPY images/licenses/APACHE-2.0.txt images/autoinstrumentation/nodejs/NOTICE /usr/share/licenses/elven-auto-nodejs/
