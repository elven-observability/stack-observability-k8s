# Explicit EOL Node.js 20 compatibility exception; never the default Node.js profile.
ARG UPSTREAM_IMAGE=ghcr.io/open-telemetry/opentelemetry-operator/autoinstrumentation-nodejs:0.81.2-1@sha256:7c5852f71d38ee12ba19df81aa8b7d866a254ce19fd3cf12966201de1efbc283
FROM ${UPSTREAM_IMAGE}
ARG VERSION=1.0.0-dev
ARG REVISION=unreleased
ARG CREATED
LABEL org.opencontainers.image.title="Elven Node.js 20 Legacy Auto-Instrumentation" \
      org.opencontainers.image.description="Explicit legacy compatibility wrapper; Node.js 20 is EOL, not the supported current Node.js profile" \
      org.opencontainers.image.vendor="Elven Observability" \
      org.opencontainers.image.source="https://github.com/elven-observability/stack-observability-k8s" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="ghcr.io/open-telemetry/opentelemetry-operator/autoinstrumentation-nodejs:0.81.2-1" \
      org.opencontainers.image.base.digest="sha256:7c5852f71d38ee12ba19df81aa8b7d866a254ce19fd3cf12966201de1efbc283" \
      org.elvenobservability.instrumentation.version="0.81.2" \
      org.elvenobservability.runtime.lifecycle="Node.js20-EOL-2026-04-30"
COPY images/licenses/APACHE-2.0.txt images/autoinstrumentation/nodejs20/NOTICE /usr/share/licenses/elven-auto-nodejs20/
