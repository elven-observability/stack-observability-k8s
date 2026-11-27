# Rebuild the pinned official agent with one reviewed synchronous Jedis4 fix.
# Build-only JDK/Gradle/git tools never enter the runtime payload image.
ARG UPSTREAM_IMAGE=ghcr.io/open-telemetry/opentelemetry-operator/autoinstrumentation-java:2.33.1-2@sha256:6886169e41415eedcaa04d67485592022026eab5b33e2c83ce86561a72f15452
FROM --platform=$BUILDPLATFORM docker.io/library/eclipse-temurin:17-jdk-jammy@sha256:81336a07f69ac361c7f278183b195e32037ebdb532684996806265a3b47ef516 AS build-jdk17
FROM --platform=$BUILDPLATFORM docker.io/library/eclipse-temurin:21-jdk-jammy@sha256:4b1a74fbffbe6b4e7b6f0171a472478282fb463790a51edf10e465d578f22b69 AS build-jdk21

FROM --platform=$BUILDPLATFORM gradle:9.8.2-jdk25@sha256:e46e15353757ef9c9be0197a243653e88d25ebcd4c3c841057cf839c11fcf898 AS builder
USER root
COPY --from=build-jdk17 /opt/java/openjdk /opt/elven-toolchains/jdk17
COPY --from=build-jdk21 /opt/java/openjdk /opt/elven-toolchains/jdk21
ADD --keep-git-dir=true https://github.com/open-telemetry/opentelemetry-java-instrumentation.git#d9045e02e0711837d54f0fd058cd55f77742506d /src
# Historical official release source subtrees only, not a Maven mirror or the
# entire SVN-tag tree. These dependencies remain build-only compile signatures.
ADD https://github.com/restlet/restlet-framework-java.git#93fab9888a9eded2c527e9eee8da46a30c403889:1.1.5 /opt/elven-restlet-sources/1.1.5
ADD https://github.com/restlet/restlet-framework-java.git#aec544eb2622f1959e9c905d435077dd7fec4092:2.0.2 /opt/elven-restlet-sources/2.0.2
WORKDIR /src
COPY images/autoinstrumentation/java/jedis4-terminal-error.patch /tmp/jedis4-terminal-error.patch
COPY images/autoinstrumentation/java/build-restlet-compile-only.sh /tmp/build-restlet-compile-only.sh
COPY images/autoinstrumentation/java/restlet-compile-only.init.gradle /tmp/restlet-compile-only.init.gradle
COPY images/autoinstrumentation/java/verify-restlet-payload.sh /tmp/verify-restlet-payload.sh
COPY images/autoinstrumentation/java/restlet-preflight.settings.gradle /opt/elven-restlet-preflight/settings.gradle
COPY images/autoinstrumentation/java/restlet-preflight.build.gradle /opt/elven-restlet-preflight/build.gradle
RUN echo 'a66a6b25647b88e187e8a0d1a6a609de00942aec9e88b45db3baa1e1c2b83b2b  /tmp/build-restlet-compile-only.sh' | sha256sum -c - \
    && echo '48308d22e57863f087fb68d08934f8969907cedc7e24d90c9fa227417be71357  /tmp/restlet-compile-only.init.gradle' | sha256sum -c - \
    && echo '9ed3071ce9b4fc915a19ca6ba3092a367bc91725c1b7e95971bbf8a54625c776  /tmp/verify-restlet-payload.sh' | sha256sum -c - \
    && echo '817233b8e3d57b2365a9bcbb9147db693a155a00cda9917e602d6e4ac4034732  /opt/elven-restlet-preflight/settings.gradle' | sha256sum -c - \
    && echo '6a65a01259808ae742c2ae9ffcae2a6160bef2e3e5a93ef04ef42fe608adabe0  /opt/elven-restlet-preflight/build.gradle' | sha256sum -c -
RUN test "$(git rev-parse HEAD)" = d9045e02e0711837d54f0fd058cd55f77742506d \
    && echo '25dc0866daf97461bb4110d38d36225d8f336b90d1c4c1a9a00b949006b54be0  /tmp/jedis4-terminal-error.patch' | sha256sum -c - \
    && git apply --check /tmp/jedis4-terminal-error.patch \
    && git apply /tmp/jedis4-terminal-error.patch
# The wrapper itself comes from the exact source commit; do not replace it
# with the builder's global Gradle or bypass its distribution checksum.
RUN java -XshowSettings:properties -version 2>&1 | grep -E '^[[:space:]]*java.specification.version = 25$'
RUN javac -version 2>&1 | grep -E '^javac 25([.]|$)'
RUN /opt/elven-toolchains/jdk17/bin/javac -version 2>&1 | grep -E '^javac 17([.]|$)'
RUN /opt/elven-toolchains/jdk21/bin/javac -version 2>&1 | grep -E '^javac 21([.]|$)'
RUN sh /tmp/build-restlet-compile-only.sh
RUN grep -Fx 'distributionUrl=https\://services.gradle.org/distributions/gradle-9.8.2-bin.zip' gradle/wrapper/gradle-wrapper.properties \
    && grep -Fx 'distributionSha256Sum=21bd5da2de49b642904077f38c0efdc7778e92b3ed0889392dca61b97e389607' gradle/wrapper/gradle-wrapper.properties \
    && ./gradlew --no-daemon --no-parallel --max-workers=2 \
       --init-script /tmp/restlet-compile-only.init.gradle \
       -Pkotlin.compiler.execution.strategy=in-process \
       -Porg.gradle.java.installations.auto-download=false \
       -Porg.gradle.java.installations.auto-detect=false \
       "-Porg.gradle.java.installations.paths=$JAVA_HOME,/opt/elven-toolchains/jdk17,/opt/elven-toolchains/jdk21" \
       --version | grep -Fx 'Gradle 9.8.2'
# Resolve only the three rebuilt API jars and the exact official Central BOM.
# Catch project-repository shadowing before configuring the full agent graph.
RUN ./gradlew --no-daemon --no-parallel --max-workers=2 \
    --init-script /tmp/restlet-compile-only.init.gradle \
    --project-dir /opt/elven-restlet-preflight \
    '-Dorg.gradle.jvmargs=-Xmx3g -XX:MaxMetaspaceSize=768m' \
    -Dorg.gradle.internal.http.connectionTimeout=30000 \
    -Dorg.gradle.internal.http.socketTimeout=30000 \
    -Dorg.gradle.internal.repository.max.retries=2 \
    -Pkotlin.compiler.execution.strategy=in-process \
    -Porg.gradle.java.installations.auto-download=false \
    -Porg.gradle.java.installations.auto-detect=false \
    "-Porg.gradle.java.installations.paths=$JAVA_HOME,/opt/elven-toolchains/jdk17,/opt/elven-toolchains/jdk21" \
    verifyRepositoryBoundaries
# This pure mocked unit suite has no Redis/Docker/Testcontainers dependency.
# Real SDK/Redis ERROR acceptance remains a separate disposable hosted CI gate.
# Upstream compilation defaults to Java25. Use only the JDK from the pinned
# builder plus the pinned JDK17 for gradle-plugins and JDK21 for Grails,
# never an implicit Foojay download or another detected installation.
# Keep Kotlin in-process instead of allowing a second inherited 3GiB heap.
RUN attempt=1; while true; do \
    if ./gradlew --no-daemon --no-parallel --max-workers=2 \
    --init-script /tmp/restlet-compile-only.init.gradle \
    '-Dorg.gradle.jvmargs=-Xmx3g -XX:MaxMetaspaceSize=768m' \
    -Pkotlin.compiler.execution.strategy=in-process \
    -Porg.gradle.java.installations.auto-download=false \
    -Porg.gradle.java.installations.auto-detect=false \
    "-Porg.gradle.java.installations.paths=$JAVA_HOME,/opt/elven-toolchains/jdk17,/opt/elven-toolchains/jdk21" \
    -Potel.stable=true -PremoveJarVersionNumbers=true \
    :instrumentation:jedis:jedis-common-1.4:javaagent:unitTests :javaagent:assemble \
    > /tmp/elven-gradle-build.log 2>&1; then \
      cat /tmp/elven-gradle-build.log; break; \
    else \
      result=$?; cat /tmp/elven-gradle-build.log; \
      if [ "$attempt" -ge 3 ] \
        || ! grep -Eq 'Received status code (429|5[0-9][0-9])' /tmp/elven-gradle-build.log \
        || grep -Eiq 'Compilation error|Compilation failed|There were failing tests|[0-9]+ tests completed, [1-9][0-9]* failed' /tmp/elven-gradle-build.log; then \
        exit "$result"; \
      fi; \
      attempt=$((attempt + 1)); sleep $((attempt * 10)); \
    fi; \
    done && test -s /src/javaagent/build/libs/opentelemetry-javaagent.jar \
    && sh /tmp/verify-restlet-payload.sh /src/javaagent/build/libs/opentelemetry-javaagent.jar

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
      org.elvenobservability.instrumentation.builder.java.version="25" \
      org.elvenobservability.instrumentation.source.revision="d9045e02e0711837d54f0fd058cd55f77742506d" \
      org.elvenobservability.instrumentation.patch.sha256="25dc0866daf97461bb4110d38d36225d8f336b90d1c4c1a9a00b949006b54be0"
COPY --from=builder /src/javaagent/build/libs/opentelemetry-javaagent.jar /javaagent.jar
COPY images/licenses/APACHE-2.0.txt images/autoinstrumentation/java/NOTICE /usr/share/licenses/elven-auto-java/
