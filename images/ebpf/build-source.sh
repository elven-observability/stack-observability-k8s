#!/bin/sh
set -eu
test "$#" -eq 2
destination=$1
validation_patch=$2
revision=70b1a981edd77257f96025bf9f16c1cf8c6f5f7a
obi_revision=5abaf031651c103a31dfb67b129361917efaf969
git init "$destination"
git -C "$destination" remote add origin https://github.com/grafana/beyla.git
git -C "$destination" fetch --depth=1 origin "$revision"
git -C "$destination" checkout --detach FETCH_HEAD
test "$(git -C "$destination" rev-parse HEAD)" = "$revision"
test "$(git -C "$destination" config --file .gitmodules --get submodule.obi-src.url)" = https://github.com/grafana/opentelemetry-ebpf-instrumentation.git
git -C "$destination" submodule update --init --depth=1 .obi-src
test "$(git -C "$destination/.obi-src" rev-parse HEAD)" = "$obi_revision"
test -f "$validation_patch"
test "$(sha256sum "$validation_patch" | cut -d ' ' -f 1)" = 069dd3c038916f31bf840422246725165c9f55821184855b9a6f9a76443278e7
git -C "$destination" apply --check "$validation_patch"
git -C "$destination" apply "$validation_patch"
