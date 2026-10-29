# Minimal Elven Collector: explicit upstream components, no cloud/JWT receivers.
ARG GO_IMAGE=docker.io/library/golang:1.27.3-bookworm@sha256:d9b6a1beb9474adc2a1ce842573639b44b2a0dd49b6669f51d3821baf9ec37c9
ARG UPSTREAM_IMAGE=docker.io/otel/opentelemetry-collector-contrib:0.164.0@sha256:340c9ca6a36617084c6661bdc4f0fe92b7cda5a805d61673ec8db375fddc522b
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=1.0.0-dev
ARG SOURCE_DATE_EPOCH
ENV CGO_ENABLED=0 GOMAXPROCS=2 GOGC=50 GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GOTOOLCHAIN=local
WORKDIR /src
COPY images/collector/builder-config.yaml images/collector/license-bundle.go /src/
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go install go.opentelemetry.io/collector/cmd/builder@v0.164.0 && \
    sed "s/^  version:.*/  version: ${VERSION#v}/" builder-config.yaml > build.yaml && \
    /go/bin/builder --config=/src/build.yaml --skip-compilation && \
    cd /src/_build && go mod verify && \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /out/elven-collector . && \
    go version -m /out/elven-collector > /out/build-info.txt && \
    cp go.mod go.sum /out/ && \
    go list -m -json all > /out/modules.json && \
    go run /src/license-bundle.go /out/licenses < /out/modules.json
FROM ${UPSTREAM_IMAGE} AS certificates
FROM scratch
ARG VERSION=1.0.0-dev
ARG REVISION=unreleased
ARG CREATED
LABEL org.opencontainers.image.title="Elven Collector" \
      org.opencontainers.image.description="Minimal Elven OpenTelemetry Collector built from explicitly pinned upstream components" \
      org.opencontainers.image.vendor="Elven Observability" \
      org.opencontainers.image.source="https://github.com/elven-observability/stack-observability-k8s" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="scratch" \
      org.elvenobservability.collector.core="0.164.0" \
      org.elvenobservability.collector.contrib="0.164.1" \
      org.elvenobservability.ca-source.digest="sha256:340c9ca6a36617084c6661bdc4f0fe92b7cda5a805d61673ec8db375fddc522b"
COPY --from=certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/elven-collector /elven-collector
COPY --from=build /out/go.mod /out/go.sum /out/build-info.txt /usr/share/elven-collector/build/
COPY --from=build /out/licenses /usr/share/licenses/elven-collector/dependencies/
COPY images/licenses/APACHE-2.0.txt images/collector/NOTICE images/collector/builder-config.yaml /usr/share/licenses/elven-collector/
USER 10001:10001
ENTRYPOINT ["/elven-collector"]
