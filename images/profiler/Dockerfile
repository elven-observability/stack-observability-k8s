# Alloy is the upstream profiling engine; Elven does not claim authorship of it.
ARG UPSTREAM_IMAGE=docker.io/grafana/alloy:v1.21.3@sha256:8ab871206bd2d8f89277f53abffee5f452a293980788d52f85fa183a87a505a4
FROM ${UPSTREAM_IMAGE}
ARG VERSION=1.0.0-dev
ARG REVISION=unreleased
ARG CREATED
LABEL org.opencontainers.image.title="Elven Profiler" \
      org.opencontainers.image.description="Elven distribution of the unmodified Grafana Alloy runtime for profiling" \
      org.opencontainers.image.vendor="Elven Observability" \
      org.opencontainers.image.source="https://github.com/elven-observability/stack-observability-k8s" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="docker.io/grafana/alloy:v1.21.3" \
      org.opencontainers.image.base.digest="sha256:8ab871206bd2d8f89277f53abffee5f452a293980788d52f85fa183a87a505a4"
COPY images/licenses/APACHE-2.0.txt images/profiler/NOTICE images/profiler/LICENSING.md /usr/share/licenses/elven-profiler/
