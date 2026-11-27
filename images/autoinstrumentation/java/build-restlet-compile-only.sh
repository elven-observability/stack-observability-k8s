#!/bin/sh
# Build-time API jars only, rebuilt from the exact official historical sources.
# These are NOT the unavailable historical Maven binaries and are never shipped.
set -eu
export LC_ALL=C
repo=/opt/elven-restlet-maven
work=/opt/elven-restlet-work
jdk=/opt/elven-toolchains/jdk17
test ! -e "$repo"
test ! -e "$work"
mkdir -p "$repo" "$work"

check_source() {
    source_root=$1
    major=$2
    minor=$3
    release=$4
    test -d "$source_root/modules/org.restlet/src"
    test -f "$source_root/build/build.properties"
    tr -d '\r' < "$source_root/build/build.properties" > "$work/properties"
    grep -Fx "major-number: $major" "$work/properties"
    grep -Fx "minor-number: $minor" "$work/properties"
    grep -Fx "release-number: $release" "$work/properties"
    # The same official OSGi 4.0 input occurs in both pinned Restlet trees.
    echo "37a3bebd29d26e1d1e7ab2b1240435ba2f3cf610f718dbcfe4c05b628df6382b  $source_root/libraries/org.osgi_4.0/org.osgi.core.jar" | sha256sum -c -
    test -f "$source_root/libraries/org.osgi_4.0/license.txt"
    test -z "$(find "$source_root/modules/org.restlet/src" -type l -print)"
}

build_module() {
    source_root=$1
    module=$2
    group=$3
    version=$4
    revision=$5
    classpath=$6
    classes="$work/$version-$module"
    mkdir "$classes"
    find "$source_root/modules/$module/src" -type f -name '*.java' | sort > "$work/sources"
    count=$(wc -l < "$work/sources")
    test "$count" -gt 0
    test "$count" -le 1000
    test -z "$(find "$source_root/modules/$module/src" -type l -print)"
    # No resolver, package manager or remote mirror participates in this step.
    "$jdk/bin/javac" -J-Xmx512m --release 8 -proc:none -encoding UTF-8 -g \
        -classpath "$classpath" -d "$classes" @"$work/sources"
    artifact_dir="$repo/$(printf '%s' "$group" | tr . /)/$module/$version"
    mkdir -p "$artifact_dir"
    cat > "$classes/ELVEN-BUILD-ONLY-PROVENANCE.txt" <<EOF
SOURCE_REBUILD_NOT_UPSTREAM_MAVEN_BINARY
Repository: https://github.com/restlet/restlet-framework-java.git
Source revision: $revision
Source subdirectory: $version/modules/$module
Compiler: pinned Eclipse Temurin17, --release 8
Use: compile-only signatures for the complete OpenTelemetry Java agent build
Never install these API jars as a customer application dependency.
EOF
    cp "$source_root/libraries/org.osgi_4.0/license.txt" "$classes/BUILD-INPUT-OSGI-LICENSE.txt"
    "$jdk/bin/jar" --create --date=1980-01-01T00:00:02Z \
        --file "$artifact_dir/$module-$version.jar" -C "$classes" .
    # Deliberately minimal local build descriptor, not an upstream publication.
    cat > "$artifact_dir/$module-$version.pom" <<EOF
<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion><groupId>$group</groupId><artifactId>$module</artifactId><version>$version</version><description>Elven BUILD-ONLY source rebuild, official Git revision $revision; NOT the upstream Maven binary.</description></project>
EOF
    sha256sum "$artifact_dir/$module-$version.jar" "$artifact_dir/$module-$version.pom"
}

old=/opt/elven-restlet-sources/1.1.5
new=/opt/elven-restlet-sources/2.0.2
check_source "$old" 1 1 5
check_source "$new" 2 0 2
build_module "$old" org.restlet org.restlet 1.1.5 93fab9888a9eded2c527e9eee8da46a30c403889 "$old/libraries/org.osgi_4.0/org.osgi.core.jar"
build_module "$old" com.noelios.restlet com.noelios.restlet 1.1.5 93fab9888a9eded2c527e9eee8da46a30c403889 "$old/libraries/org.osgi_4.0/org.osgi.core.jar:$repo/org/restlet/org.restlet/1.1.5/org.restlet-1.1.5.jar"
build_module "$new" org.restlet org.restlet.jse 2.0.2 aec544eb2622f1959e9c905d435077dd7fec4092 "$new/libraries/org.osgi_4.0/org.osgi.core.jar"
test "$(find "$repo" -type f -name '*.jar' | wc -l)" -eq 3
