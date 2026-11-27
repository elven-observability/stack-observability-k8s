# Rebuild the pinned official agent with one reviewed synchronous Jedis4 fix.
# Build-only JDK/Gradle/git tools never enter the runtime payload image.
ARG UPSTREAM_IMAGE=ghcr.io/open-telemetry/opentelemetry-operator/autoinstrumentation-java:2.33.1-2@sha256:6886169e41415eedcaa04d67485592022026eab5b33e2c83ce86561a72f15452
FROM --platform=$BUILDPLATFORM gradle:9.8.2-jdk21@sha256:85f8f572045bfb31874d66d7d8a2bd0c17d8cb9ad34b6a4d02f5d552b4b92c04 AS builder
USER root
ADD --keep-git-dir=true https://github.com/open-telemetry/opentelemetry-java-instrumentation.git#d9045e02e0711837d54f0fd058cd55f77742506d /src
WORKDIR /src
COPY images/autoinstrumentation/java/jedis4-terminal-error.patch /tmp/jedis4-terminal-error.patch
RUN test "$(git rev-parse HEAD)" = d9045e02e0711837d54f0fd058cd55f77742506d \
    && echo '25dc0866daf97461bb4110d38d36225d8f336b90d1c4c1a9a00b949006b54be0  /tmp/jedis4-terminal-error.patch' | sha256sum -c - \
    && git apply --check /tmp/jedis4-terminal-error.patch \
    && git apply /tmp/jedis4-terminal-error.patch
# The wrapper itself comes from the exact source commit; do not replace it
# with the builder's global Gradle or bypass its distribution checksum.
RUN grep -Fx 'distributionUrl=https\://services.gradle.org/distributions/gradle-9.8.2-bin.zip' gradle/wrapper/gradle-wrapper.properties \
    && grep -Fx 'distributionSha256Sum=21bd5da2de49b642904077f38c0efdc7778e92b3ed0889392dca61b97e389607' gradle/wrapper/gradle-wrapper.properties \
    && ./gradlew --no-daemon --version | grep -Fx 'Gradle 9.8.2'
# This pure mocked unit suite has no Redis/Docker/Testcontainers dependency.
# Real SDK/Redis ERROR acceptance remains a separate disposable hosted CI gate.
RUN ./gradlew --no-daemon --max-workers=2 \
    '-Dorg.gradle.jvmargs=-Xmx3g -XX:MaxMetaspaceSize=768m' \
    -Potel.stable=true -PremoveJarVersionNumbers=true \
    :instrumentation:jedis:jedis-common-1.4:javaagent:unitTests :javaagent:assemble \
    && test -s /src/javaagent/build/libs/opentelemetry-javaagent.jar

# Preserve the upstream copy utility, entrypoint, user and dependency notices.
FROM ${UPSTREAM_IMAGE}
ARG VERSION=1.0.1-dev
ARG REVISION=unreleased
ARG CREATED
LABEL org.opencontainers.image.title="Elven Java Auto-Instrumentation" \
      org.opencontainers.image.description="Elven patched OpenTelemetry Java agent: synchronous Jedis4 terminal-error propagation" \
      org.opencontainers.image.vendor="Elven Observability" \
      org.opencontainers.image.source="https://github.com/elven-observability/stack-observability-k8s" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="ghcr.io/open-telemetry/opentelemetry-operator/autoinstrumentation-java:2.33.1-2" \
      org.opencontainers.image.base.digest="sha256:6886169e41415eedcaa04d67485592022026eab5b33e2c83ce86561a72f15452" \
      org.elvenobservability.instrumentation.version="2.33.1" \
      org.elvenobservability.instrumentation.patch="jedis4-terminal-error-v1" \
      org.elvenobservability.instrumentation.source.revision="d9045e02e0711837d54f0fd058cd55f77742506d" \
      org.elvenobservability.instrumentation.patch.sha256="25dc0866daf97461bb4110d38d36225d8f336b90d1c4c1a9a00b949006b54be0"
COPY --from=builder /src/javaagent/build/libs/opentelemetry-javaagent.jar /javaagent.jar
COPY images/licenses/APACHE-2.0.txt images/autoinstrumentation/java/NOTICE /usr/share/licenses/elven-auto-java/
