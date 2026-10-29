# Preserve the upstream binary, filesystem, entrypoint, and dependency licenses.
ARG UPSTREAM_IMAGE=docker.io/grafana/beyla:3.40.0@sha256:59e31947a79178f7228e3886d061e1261f792e84ea7365b8b54113232437a8b4
FROM ${UPSTREAM_IMAGE}
ARG VERSION=1.0.0-dev
ARG REVISION=unreleased
ARG CREATED
LABEL org.opencontainers.image.title="Elven eBPF" \
      org.opencontainers.image.description="Elven distribution of the unmodified Grafana Beyla runtime" \
      org.opencontainers.image.vendor="Elven Observability" \
      org.opencontainers.image.source="https://github.com/elven-observability/stack-observability-k8s" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="docker.io/grafana/beyla:3.40.0" \
      org.opencontainers.image.base.digest="sha256:59e31947a79178f7228e3886d061e1261f792e84ea7365b8b54113232437a8b4"
COPY images/licenses/APACHE-2.0.txt images/ebpf/NOTICE images/ebpf/UPSTREAM-NOTICE images/ebpf/third_party_licenses.csv /usr/share/licenses/elven-ebpf/
