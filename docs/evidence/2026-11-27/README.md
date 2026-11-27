# Native SDK privacy and hybrid qualification — LAB PASS

27 November 2026: **LAB PASS; customer distribution remains HOLD**. No new
customer kit, image signature, promotion or release was published. The latest
public release remains `v1.0.1`. The failures retained below are historical
attempts, not the result of the newly qualified candidate.

## Current reproducible candidate

Source: `b79d3630a79393ad718d751b536a26a6347be72f`,
[PR #16](https://github.com/elven-observability/stack-observability-k8s/pull/16).
The source-only [LAB artifact](https://github.com/elven-observability/stack-observability-k8s/actions/runs/46033926214/artifacts/15215498124)
contains `elven-lab-candidate-b79d3630a793.zip` (272,265 bytes):

```
SHA-256: 442a5c3ee3023d4e324f686faf3f5086c2559ec225b4a097d58148fd58942817
```

Its `LAB-ONLY.txt`, `customerInstallable=false`, unsigned status and unchanged
immutable v1.0.1 production bootstrap are intentional. It is not a replacement
customer installer. All ZIP payload member hashes and its embedded manifest
were independently read back and verified without extraction/execution.

| Gate | Confirmed result |
| --- | --- |
| [Core 46021919965](https://github.com/elven-observability/stack-observability-k8s/actions/runs/46021919965) | Native amd64/arm64 compiled Collector privacy, three signals, WAL/replay and 25 Kubernetes lifecycle checks per architecture. |
| [SDK 46029749134](https://github.com/elven-observability/stack-observability-k8s/actions/runs/46029749134) | Complete patched Java source assembly, executed `unitTests` task, strict repository preflight and final-JAR payload oracle; five SDK/Operator images built/scanned; native HTTP injection/delivery in both architectures. Node20 is an explicit EOL exception, not the default. |
| [Real SDK privacy 46033921509](https://github.com/elven-observability/stack-observability-k8s/actions/runs/46033921509) | Native amd64 **and** arm64: Java17/21, Node22 and Python3.14 glibc. Actual H2/PostgreSQL/SQLite and Redis clients, real exceptions, raw positive controls, post-Collector selective masking and fresh captures after actual CLI rollback. |
| [ZIP/hybrid 46033926214](https://github.com/elven-observability/stack-observability-k8s/actions/runs/46033926214) | Native amd64: exact approved-node affinity/UID, SDK Node22 vs SDK-less Go/Beyla, real RED histogram, 4 SDK / 3 Beyla server spans and zero crossovers. Rollback removed the worker and preserved Secrets/PVCs/apps; fresh SDK=4, Beyla=0 during a 15-second observation. |

The exact eight image digests, distinct GitHub synthetic build revisions,
fresh scan/Govulncheck manifests, original report hashes, public error types,
diagnostic digests and teardown receipts are in [lab-candidate.json](lab-candidate.json).
Core-only receipts are in [core-candidate.json](core-candidate.json).
Both full OCI families were hashed/admitted in CI; they were **not** downloaded
or run on the developer machine. No Auth, shared EO/EIP or customer was changed.

### What the SDK evidence establishes

Each requested trace has one automatic HTTP server span with GET, integer 502
and ERROR, correlated with the business exception. SQL query shape and public
SQL/Redis error types are preserved. Node pg supplies its public type/SQLSTATE
in its official sanitized message, not an invented `exception.type` attribute.
The post-Collector diagnostic digests match the raw controls and the fresh
post-rollback captures for every case on both architectures.

Real business exception objects are explicitly passed to `recordException` /
`record_exception`, using only the external injected SDK provider/exporter.
This proves preservation, not automatic capture of every handled application
exception. Known private message/stack sentinels are absent after the Collector;
the complete business frame sequence and useful message context are retained.
Redis stacks remain masked; only the public type and finite error code survive.
SQL statements are diagnostic normalized shapes, not a promise to export bind
values or all original literals. Java payload readback measured 26,505,890 bytes
per JAR, below the 128 MiB SDK-volume limit; this is **not** a RAM/CPU benchmark.

Core three-signal tests and real CRI-log collection do not qualify application
SDK logs/metrics. Those remain `NOT_PROVEN`, as do Node20 SQL/Redis/exceptions,
other Python versions/musl/frameworks, other Redis clients and customer/backend
acceptance. Beyla was tested only on this amd64 host: kernel
`7.0.0-1020-azure`, BTF, containerd2.3.4 and Kind1.37/kindnet. NetworkPolicy
enforcement, other CNI/kernel/architecture combinations, production scale/HA
and kernel-probe/map purge after process exit remain unproven.

## Historical failed real application runs

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

## Correction and build history

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

## Separate core milestone

[Core run 46021919965](https://github.com/elven-observability/stack-observability-k8s/actions/runs/46021919965)
completed successfully for source `9608700`: both-architecture image scans and
Collector Govulncheck passed, followed by **native amd64 and arm64** actual-binary
selective privacy, three-signal WAL/replay, finite Redis error-code preservation
and **25 Kubernetes lifecycle checks per architecture**, including CLI rollback.
Both owned Kind clusters were removed. The core job alone does not cover the
SDK boundary; the separate native SDK privacy job above supplies that proof.

Exact digests, independently verified small artifact ZIP/report hashes, and
the distinct GitHub synthetic build revision are in `core-candidate.json`.
Core evidence alone is not a signed/promoted image or hybrid qualification.
The new hybrid receipt above separately qualifies the exact LAB ZIP/images.

## Remaining gates

1. Build all eight final images from one approved release revision, sign,
   promote and verify their anonymous registry/signature/predicate readback.
   The qualified LAB core/SDK build revisions differ; do not relabel them as
   a single promoted release or reuse immutable v1.0.1 tags/assets.
2. Bind the new immutable distribution, defaults, locks and template adapter
   to the real artifact hash. Preserve refusal of old/unknown bundles.
3. Finish client-kit exact approved-node UID handling and acceptance of the
   final ZIP in a clean directory, without any development flag/local file.
4. EIP-owner integration and customer/backend acceptance remain separate.
   Application SDK log/metric qualification needs its own measured gate.

See [the no-development release review](../../release-candidate-review-20261127.md).
No published lock/default/artifact pin was changed to manufacture acceptance.
