#!/bin/sh
# Offline oracle: dependencies used only to compile must not enter the agent.
set -eu
export LC_ALL=C
test "$#" -eq 1
test -f "$1"
scan_archive() (
    archive=$1
    depth=$2
    listing=$(mktemp /tmp/elven-restlet-payload.XXXXXXXX)
    nested_file=$(mktemp /tmp/elven-restlet-nested.XXXXXXXX)
    trap 'rm -f "$listing" "$nested_file"' EXIT HUP INT TERM
    test "$(wc -c < "$archive")" -le 100000000
    unzip -tqq "$archive"
    unzip -Z1 "$archive" > "$listing"
    if grep -Eq '(^|/)(org/restlet|com/noelios/restlet)/|(^|/)[^/]*[Rr][Ee][Ss][Tt][Ll][Ee][Tt][^/]*[.][Jj][Aa][Rr]$' "$listing"; then
        echo 'Build-only Restlet classes or nested jars escaped into the agent' >&2
        exit 1
    fi
    nested_count=0
    while IFS= read -r entry; do
        case "$entry" in
            *.[Jj][Aa][Rr])
                nested_count=$((nested_count + 1))
                test "$nested_count" -le 10
                test "$depth" -lt 2
                # Bound decompression even for renamed nested jars. The next
                # scan also rejects malformed/truncated ZIPs, not only names.
                unzip -p "$archive" "$entry" | head -c 30000001 > "$nested_file"
                test "$(wc -c < "$nested_file")" -le 30000000
                scan_archive "$nested_file" "$((depth + 1))"
                ;;
        esac
    done < "$listing"
)
scan_archive "$1" 0
listing=$(mktemp /tmp/elven-restlet-top.XXXXXXXX)
trap 'rm -f "$listing"' EXIT HUP INT TERM
unzip -Z1 "$1" > "$listing"
# The agent must retain both real instrumentations; absence is not a workaround.
grep -Eq '(^|/)io/opentelemetry/javaagent/instrumentation/restlet/v1_1/' "$listing"
grep -Eq '(^|/)io/opentelemetry/javaagent/instrumentation/restlet/v2_0/' "$listing"
echo 'Restlet 1.1/2.0 instrumentations retained; build-only library payload absent'
