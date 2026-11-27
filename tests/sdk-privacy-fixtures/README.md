# Real-client SDK privacy fixture applications

Disposable synthetic laboratory only. These images contain HTTP applications,
database clients and the OpenTelemetry **API**. They contain no telemetry SDK,
provider, exporter, instrumentation or fabricated OTLP. The separately injected
Elven SDK must supply a valid span or `/exercise` fails.

The Java 17/21 apps execute real JDBC/H2 literal and parameterized SELECTs, verify
results, and observe a real division-by-zero SQL error. Java Jedis and Node
`@redis/client` execute real SET (120-second expiry) and GET and verify equality.
Both Redis clients then issue HGET against the string key and require the real
server's WRONGTYPE error; no synthetic Redis error span is constructed. Node
executes equivalent SQL through `pg` and the ephemeral PostgreSQL server.
The app then throws/catches a real Java `IllegalStateException` or Node `Error`,
calls the standard API's `recordException` on `elven.privacy.exception`, and marks
that span ERROR. Frames contain the actual `exercise` handler. Its parent comes
from the externally injected HTTP server instrumentation, not an app-generated
trace ID. A missing SDK is an infrastructure failure, not a passing fixture.

HTTP port is 8080 (`PORT` may override). `/ready` returns 200 `{ready:true}`.
`GET /exercise` deliberately returns **502**, with all of these JSON fields:

```json
{"ok":true,"sql":true,"sqlError":true,"redisSet":true,"redisGet":true,"redisError":true,"exception":true,"activeSpan":true,"runtime":"java17"}
```

`runtime` is `java17`, `java21`, or `node22`. Infrastructure/assertion failure
returns 500 `{ok:false}`. Responses never contain the synthetic private values.
The exception event and SDK status do contain known synthetic private values,
so a RAW SDK sink can prove their presence before the real Collector boundary.
SQL/Redis clients may already sanitize their operands in the SDK; observing a
query shape is not evidence that gateway redaction removed those operands.

Each handler also writes a real JSON **stdout** application log containing the
exception and the trace/span IDs obtained from the active injected SDK. This is
not an SDK-log-export claim. A node log collector can test this independent path;
the traces-only SDK tap cannot prove log ingestion. Synthetic PII in RAW payloads
and stdout must not be uploaded as CI artifacts.

Configuration: `REDIS_HOST` (default `redis`), `REDIS_PORT` (6379), optional
`REDIS_PASSWORD`; Node additionally reads `PGHOST`, `PGPORT`, `PGDATABASE`,
`PGUSER`, `PGPASSWORD`. The CI harness supplies ephemeral synthetic credentials.
No customer credential, cloud endpoint, SDK backend token or tenant enters these
applications. No persistent database volume is required.

`fixtures.json` records official Maven URLs with SHA-256, Docker Hub index
digests and sources. `package-lock.json` pins the entire Node closure with npm
registry SHA-512 integrity. Jedis 5.2.0 and the Redis 4.7-family client are explicit
compatibility fixtures inside the supported instrumentations, not a claim to
test latest clients or a production dependency recommendation. JS API 1.9.0
avoids requiring a newer global API than the injected provider supports.

The CI harness copies this directory, then calls:

```sh
python prepare.py --directory "$COPIED_FIXTURE_CONTEXT"
```

This only verifies/downloads bounded Maven dependencies in the copied context.
It never runs npm, Java, Docker or a compiler. `npm ci --ignore-scripts` and
`javac` run solely inside the disposable CI Docker build. Preparation is not
runtime acceptance. Only real injection, RAW positive controls and exports
through the compiled Collector can qualify the intended privacy boundary.
