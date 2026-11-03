# Elven admission-only Operator: no API client, shell, SDK or package manager.
ARG GO_IMAGE=docker.io/library/golang:1.27.3-bookworm@sha256:d9b6a1beb9474adc2a1ce842573639b44b2a0dd49b6669f51d3821baf9ec37c9
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS
ARG TARGETARCH
ARG SOURCE_DATE_EPOCH
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOMAXPROCS=2
WORKDIR /src
COPY operator/ /src/
RUN go test ./... && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /out/elven-operator .
FROM scratch
ARG VERSION=1.0.0-dev
ARG REVISION=unreleased
ARG CREATED
LABEL org.opencontainers.image.title="Elven Instrumentation Operator" \
      org.opencontainers.image.description="Scoped opt-in Elven SDK admission injector without CRDs or Kubernetes API access" \
      org.opencontainers.image.vendor="Elven Observability" \
      org.opencontainers.image.source="https://github.com/elven-observability/stack-observability-k8s" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="scratch"
COPY --from=build /out/elven-operator /elven-operator
COPY --from=build /usr/local/go/LICENSE /usr/share/licenses/elven-operator/GO-LICENSE
COPY images/licenses/APACHE-2.0.txt images/operator/NOTICE /usr/share/licenses/elven-operator/
USER 10001:10001
ENTRYPOINT ["/elven-operator"]
