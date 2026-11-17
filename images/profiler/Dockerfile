# Alloy is the upstream profiling engine; Elven does not claim authorship of it.
ARG UPSTREAM_IMAGE=docker.io/grafana/alloy:v1.22.0@sha256:9acc2529bc1edb7f5b2bd801dd8334ebc80c158e3a9e5526ecd7c9a273d43189
FROM ${UPSTREAM_IMAGE}
ARG VERSION=1.0.1-dev
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
      org.opencontainers.image.base.name="docker.io/grafana/alloy:v1.22.0" \
      org.opencontainers.image.base.digest="sha256:9acc2529bc1edb7f5b2bd801dd8334ebc80c158e3a9e5526ecd7c9a273d43189"
COPY images/licenses/APACHE-2.0.txt images/profiler/NOTICE images/profiler/LICENSING.md /usr/share/licenses/elven-profiler/
