# Preserve the upstream SDK payload, copy utility, entrypoint and dependency licenses.
ARG UPSTREAM_IMAGE=ghcr.io/open-telemetry/opentelemetry-operator/autoinstrumentation-python:0.66b2-2@sha256:d3a1dae864158a561a99fd7bb8e4ac1c7c5f2f80a4d9d095b1813866da52693a
FROM ${UPSTREAM_IMAGE}
ARG VERSION=1.0.0-dev
ARG REVISION=unreleased
ARG CREATED
LABEL org.opencontainers.image.title="Elven Python Auto-Instrumentation" \
      org.opencontainers.image.description="Elven packaging of the unmodified pinned OpenTelemetry Python auto-instrumentation payload" \
      org.opencontainers.image.vendor="Elven Observability" \
      org.opencontainers.image.source="https://github.com/elven-observability/stack-observability-k8s" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="ghcr.io/open-telemetry/opentelemetry-operator/autoinstrumentation-python:0.66b2-2" \
      org.opencontainers.image.base.digest="sha256:d3a1dae864158a561a99fd7bb8e4ac1c7c5f2f80a4d9d095b1813866da52693a" \
      org.elvenobservability.instrumentation.version="0.66b2"
COPY images/licenses/APACHE-2.0.txt images/autoinstrumentation/python/NOTICE /usr/share/licenses/elven-auto-python/
