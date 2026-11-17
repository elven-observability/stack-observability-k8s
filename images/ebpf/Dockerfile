# Security-patched Beyla/OBI, built by Elven from immutable upstream revisions.
ARG GO_IMAGE=docker.io/library/golang:1.27.3-bookworm@sha256:d9b6a1beb9474adc2a1ce842573639b44b2a0dd49b6669f51d3821baf9ec37c9
ARG UPSTREAM_IMAGE=docker.io/grafana/beyla:3.42.0@sha256:4d3337af66a9ce65aa11fb423f19061d0b202e5e25e5a156ea04b913e47cbf4c
ARG GENERATOR_IMAGE=ghcr.io/open-telemetry/obi-generator:0.2.18@sha256:00da54aef610c9d8ed77757afab9c419079f17852bad0e02fe0102e5ce508be4
ARG JAVA_BUILD_IMAGE=docker.io/library/gradle:9.6.1-jdk21-noble@sha256:8074080ea0c9d663076211abc189ba1472474d3019a0da49c4216dce3184cf85

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS sources
COPY images/ebpf/build-source.sh /usr/local/bin/elven-ebpf-source
RUN /bin/sh /usr/local/bin/elven-ebpf-source /src/beyla

FROM --platform=$BUILDPLATFORM ${JAVA_BUILD_IMAGE} AS jdk
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS jni
ARG BUILDARCH
COPY --from=jdk /opt/java/openjdk/include /opt/java/include
COPY --from=sources /src/beyla/.obi-src/pkg/internal/java/agent/src/main/c/ /build/src/main/c/
COPY --from=sources /src/beyla/.obi-src/pkg/internal/java/agent/Makefile.jni /build/Makefile.jni
WORKDIR /build
RUN apt-get update && \
    case "$BUILDARCH" in \
      amd64) apt-get install --yes --no-install-recommends gcc-aarch64-linux-gnu libc6-dev-arm64-cross ;; \
      arm64) apt-get install --yes --no-install-recommends gcc-x86-64-linux-gnu libc6-dev-amd64-cross ;; \
      *) exit 1 ;; \
    esac && \
    case "$BUILDARCH" in amd64) native=amd64; cross=aarch64; cc=aarch64-linux-gnu-gcc ;; arm64) native=aarch64; cross=amd64; cc=x86_64-linux-gnu-gcc ;; esac && \
    make -f Makefile.jni CC=gcc JAVA_HOME=/opt/java JNI_HEADERS_DIR=src/main/c BUILD_DIR=build/jni/linux-$native TARGET_DIR=target/classes/native/linux-$native && \
    make -f Makefile.jni CC=$cc JAVA_HOME=/opt/java JNI_HEADERS_DIR=src/main/c BUILD_DIR=build/jni/linux-$cross TARGET_DIR=target/classes/native/linux-$cross

FROM --platform=$BUILDPLATFORM ${JAVA_BUILD_IMAGE} AS javaagent
WORKDIR /build
COPY --from=sources /src/beyla/.obi-src/pkg/internal/java/ ./
# Preserve the Beyla-specific agent overlay; do not silently substitute OBI's jar.
COPY --from=sources /src/beyla/internal/java/agent/ agent/
COPY --from=jni /build/target/classes/native/linux-amd64/libobijni.so agent/target/classes/native/linux-amd64/libobijni.so
COPY --from=jni /build/target/classes/native/linux-aarch64/libobijni.so agent/target/classes/native/linux-aarch64/libobijni.so
RUN gradle --no-daemon --max-workers=2 --console=plain build generateLicenseReport -x buildNativeLib-amd64 -x buildNativeLib-aarch64

FROM --platform=$BUILDPLATFORM ${GENERATOR_IMAGE} AS generated
# Generation runs natively; cross compilation starts only in the final build stage.
COPY --from=sources /usr/local/go /usr/local/go
ENV PATH=/usr/local/go/bin:/go/bin:/usr/lib/llvm22/bin:$PATH \
    GOTOOLCHAIN=local GOTELEMETRY=off GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GOMAXPROCS=2 GOGC=50
RUN apk add --no-cache ca-certificates curl git bash make
COPY --from=sources /src/beyla/ /src/beyla/
WORKDIR /src/beyla
RUN go version && \
    go mod edit -require=golang.org/x/net@v0.62.0 && \
    go mod download golang.org/x/net && \
    make -C .obi-src generate BPF2GO=/go/bin/bpf2go BPF_TARGETS=amd64,arm64 && \
    MISE_CONFIG_ROOT=/src/beyla BPF2GO=/go/bin/bpf2go BPF_CLANG=clang BPF_TARGETS=amd64,arm64 bash .mise/tasks/generate/beyla && \
    go mod vendor && go mod verify
COPY --from=javaagent /build/build/obi-java-agent.jar vendor/go.opentelemetry.io/obi/pkg/internal/java/embedded/obi-java-agent.jar

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOTELEMETRY=off GOPROXY=off GOSUMDB=sum.golang.org GOMAXPROCS=2 GOGC=50
COPY --from=generated /src/beyla/ /src/beyla/
COPY images/ebpf/license-bundle.go images/ebpf/license-bundle_test.go /src/
WORKDIR /src/beyla
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=1.0.1-dev
ARG REVISION=unreleased
RUN --mount=type=cache,target=/root/.cache/go-build \
    go test /src/license-bundle.go /src/license-bundle_test.go && \
    go test -mod=vendor ./pkg/buildinfo ./pkg/internal/ebpf/surveywatcher && \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -mod=vendor -trimpath -buildvcs=false \
      -ldflags="-s -w -buildid= -X github.com/grafana/beyla/v3/pkg/buildinfo.Version=3.42.0-elven.${VERSION} -X github.com/grafana/beyla/v3/pkg/buildinfo.Revision=${REVISION}" \
      -o /out/beyla ./cmd/beyla && \
    go version -m /out/beyla > /out/build-info.txt && \
    cp go.mod go.sum /out/ && \
    go run /src/license-bundle.go vendor /usr/local/go/LICENSE /out/licenses

FROM ${UPSTREAM_IMAGE} AS certificates
FROM scratch
ARG VERSION=1.0.1-dev
ARG REVISION=unreleased
ARG CREATED
LABEL org.opencontainers.image.title="Elven eBPF" \
      org.opencontainers.image.description="Elven security-patched build of pinned Beyla and OBI sources" \
      org.opencontainers.image.vendor="Elven Observability" \
      org.opencontainers.image.source="https://github.com/elven-observability/stack-observability-k8s" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="scratch" \
      org.elvenobservability.ca-source.digest="sha256:4d3337af66a9ce65aa11fb423f19061d0b202e5e25e5a156ea04b913e47cbf4c" \
      org.elvenobservability.ebpf.source-revision="70b1a981edd77257f96025bf9f16c1cf8c6f5f7a" \
      org.elvenobservability.ebpf.obi-revision="5abaf031651c103a31dfb67b129361917efaf969" \
      org.elvenobservability.ebpf.x-net="0.62.0"
COPY --from=build /out/beyla /beyla
COPY --from=build /out/build-info.txt /out/go.mod /out/go.sum /usr/share/elven-ebpf/build/
COPY --from=build /out/licenses /usr/share/licenses/elven-ebpf/dependencies/
# Keep the exact embedded jar visible to SBOM/SCA tools as well as in the binary.
COPY --from=javaagent /build/build/obi-java-agent.jar /usr/share/elven-ebpf/build/obi-java-agent.jar
COPY --from=javaagent /build/agent/build/reports/dependency-license/THIRD_PARTY_LICENSES.txt /usr/share/licenses/elven-ebpf/java/THIRD_PARTY_LICENSES.txt
COPY --from=certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY images/licenses/APACHE-2.0.txt images/ebpf/NOTICE images/ebpf/UPSTREAM-NOTICE images/ebpf/third_party_licenses.csv /usr/share/licenses/elven-ebpf/
ENTRYPOINT ["/beyla"]
