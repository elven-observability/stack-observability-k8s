# Preserve the upstream SDK payload, copy utility, entrypoint and dependency licenses.
ARG UPSTREAM_IMAGE=ghcr.io/open-telemetry/opentelemetry-operator/autoinstrumentation-java:2.33.1-2@sha256:6886169e41415eedcaa04d67485592022026eab5b33e2c83ce86561a72f15452
FROM ${UPSTREAM_IMAGE}
ARG VERSION=1.0.0-dev
ARG REVISION=unreleased
ARG CREATED
LABEL org.opencontainers.image.title="Elven Java Auto-Instrumentation" \
      org.opencontainers.image.description="Elven packaging of the unmodified pinned OpenTelemetry Java auto-instrumentation payload" \
      org.opencontainers.image.vendor="Elven Observability" \
      org.opencontainers.image.source="https://github.com/elven-observability/stack-observability-k8s" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="ghcr.io/open-telemetry/opentelemetry-operator/autoinstrumentation-java:2.33.1-2" \
      org.opencontainers.image.base.digest="sha256:6886169e41415eedcaa04d67485592022026eab5b33e2c83ce86561a72f15452" \
      org.elvenobservability.instrumentation.version="2.33.1"
COPY images/licenses/APACHE-2.0.txt images/autoinstrumentation/java/NOTICE /usr/share/licenses/elven-auto-java/
