#!/bin/sh
set -eu
destination=$1
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
