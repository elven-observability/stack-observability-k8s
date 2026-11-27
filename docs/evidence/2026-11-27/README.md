# SDK privacy qualification — retained candidate

Status: **HOLD**, 27 November 2026. No new customer kit, image promotion or
release has been accepted. These failures are not covered by the older
26 November synthetic Collector corpus or HTTP/JDBC SDK receipts.

## Real application runs

All three runs used disposable hosted CI Kind clusters and actual injected
Java 17/21 and Node 22 applications. Neither customers nor shared EO/EIP were
accessed. Each failure report records `cluster_retained=false`.

| Run / source | Result and boundary | Evidence artifact / ZIP SHA-256 |
| --- | --- | --- |
| [46010050313](https://github.com/elven-observability/stack-observability-k8s/actions/runs/46010050313), `956afec97c1b4b10231f102de1a82b90ad96c4f4` | FAIL: first Java request timed out; no successful SDK privacy acceptance | `15203082606` / `f62ac272bbc72426dfce67b4c5d7a51147c464f428002791692ae0e4002d99df` |
| [46011239658](https://github.com/elven-observability/stack-observability-k8s/actions/runs/46011239658), `103c20fd0ceef686ef6aee649ca1dceb9edb018c` | FAIL: diagnostics established missing fixture transitive dependency `io.opentelemetry.common.ComponentLoader`; not a Collector diagnosis | `15203933390` / `859c3294958b8391013b8eac5e3c4f9d4215a4a2700378be6137228fb32b2b4d` |
| [46013176213](https://github.com/elven-observability/stack-observability-k8s/actions/runs/46013176213), `942fe504a9d6cc8e944b3bb4eeecc324f05b1b37` | FAIL: actual JDBC/Jedis/pg/Redis scopes observed, but Java Jedis HGET WRONGTYPE span lacked ERROR; raw positive control rejected it before post-Collector acceptance | `15205321329` / `926cf92fc6e0bbd74a67671a29a99ab9553c448f58ec847c1d24d05220a77f04` |

The original report entry hashes, in the same order, are:

```
8e2612544b064eccb3967b1960eb896c608d7c150d3131b02ef21a12e5806b3e
cb3014110e899b583e2850a29666e07ef4ae6ed7f3d6d35b9cee37da3077eb8e
555876f76cae06878a26d6518ed24ec3d112c690e2121338459d0cc97ad0110c
```

Archive digests and entries were independently read back through the GitHub
artifact API. No OCI archives or application runtimes were downloaded to the
developer machine. Diagnostic logs are not evidence that application logs
were exported and selectively sanitized by the Collector.

## Correction under review

[PR #16](https://github.com/elven-observability/stack-observability-k8s/pull/16)
adds the bounded synchronous Jedis4 terminal-error backport, strict SET/GET/
HGET cardinality assertions, native ARM SDK privacy qualification, and a
finite Redis error-code policy. The policy preserves only a recognized code
such as `[REDACTED:redis:WRONGTYPE]`; it never preserves opaque Redis operands
or Redis stack traces. Non-Redis business exceptions still require selective
message masking and preservation of the complete frame sequence.

At source `96087007775361378951af56551ef601b3e557f9`,
[source CI 46021919987](https://github.com/elven-observability/stack-observability-k8s/actions/runs/46021919987)
passed Python contracts and Go race tests. This is not compiled Collector
export/WAL proof or acceptance of a new Java image.

[SDK build 46021919983](https://github.com/elven-observability/stack-observability-k8s/actions/runs/46021919983)
failed resolving the upstream Restlet 1.1.5 repository
`maven.restlet.talend.com` (DNS). It produced no accepted SDK OCI artifact.
An unrelated dependency-resolution failure must not be hidden by excluding
instrumentations, disabling verification or declaring the patch tested.

[SDK build 46026043759](https://github.com/elven-observability/stack-observability-k8s/actions/runs/46026043759)
successfully rebuilt the three compile-only Restlet coordinates from official
sources, then failed during Gradle configuration. The first repository init
script created project repositories globally, causing Gradle to ignore the
Central repository in settings and fail resolving ordinary BOMs. This is a
recipe regression, not an accepted Java build or a new dependency outage.
The correction must preserve resolution outside the Restlet projects and prove
Central/local-repository coexistence before the expensive assembly task.

[SDK build 46028871872](https://github.com/elven-observability/stack-observability-k8s/actions/runs/46028871872)
stopped in the new six-second repository preflight: the BOM component was absent
from the lenient resolution result. The next preflight uses explicit JVM usage
attributes and strict resolution before inspecting component identities, so
an actual resolution failure cannot be hidden behind an empty component list.
Variant ambiguity is a hypothesis supported by the published BOM metadata,
not a confirmed cause from that run. No Java SDK artifact was accepted.

## Core milestone, not SDK acceptance

[Core run 46021919965](https://github.com/elven-observability/stack-observability-k8s/actions/runs/46021919965)
completed successfully for source `9608700`: both-architecture image scans and
Collector Govulncheck passed, followed by **native amd64 and arm64** actual-binary
selective privacy, three-signal WAL/replay, finite Redis error-code preservation
and **25 Kubernetes lifecycle checks per architecture**, including CLI rollback.
Both owned Kind clusters were removed. The actual SDK boundary is not covered.

Exact digests, independently verified small artifact ZIP/report hashes, and
the distinct GitHub synthetic build revision are in `core-candidate.json`.
This is not a signed/promoted image or a new combined SDK/Beyla kit. A newly
built Beyla archive alone does not prove its runtime or its disjoint selectors.

## Remaining gates

1. Complete the pinned Java source build and its actual terminal-error unit
   suite; scan all newly built images and validate both native architectures.
2. Keep the qualified core digests fixed. Run real SDK raw positive controls,
   post-Collector SQL/Redis/exceptions and rollback on both architectures with
   these exact images; the core corpus results above do not satisfy this gate.
3. Only then prepare the combined LAB candidate and record its exact source,
   build revisions, eight OCI digests and artifact hashes. Requalify the hybrid
   approved-node/disjoint-selector path for any changed payload.
4. Release signing/promotion, final immutable bundle, installer approved-node
   UID handling and a clean no-development ZIP installation remain separate
   gates in `docs/release-candidate-review-20261127.md`.

Python SDK exceptions, application log/metric privacy, other Redis client
families and customer/backend acceptance are not established by these runs.
