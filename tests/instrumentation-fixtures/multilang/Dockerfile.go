# Lab fixture only. The SDK-less source was exercised by eBPF on SaaS amd64.
FROM docker.io/library/golang:1.27.3-bookworm@sha256:d9b6a1beb9474adc2a1ce842573639b44b2a0dd49b6669f51d3821baf9ec37c9 AS build
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOTELEMETRY=off GOPROXY=off GOSUMDB=off GO111MODULE=off
WORKDIR /src
COPY app.go .
RUN go build -trimpath -o /server app.go
FROM docker.io/library/golang:1.27.3-bookworm@sha256:d9b6a1beb9474adc2a1ce842573639b44b2a0dd49b6669f51d3821baf9ec37c9
COPY --from=build /server /server
USER 10001:10001
ENTRYPOINT ["/server"]
