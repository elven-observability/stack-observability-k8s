# Real auto-instrumentation application fixtures

These applications contain no OpenTelemetry API/SDK. HTTP/JDBC spans must come
from the separately injected SDK init container, not from a fake probe.

- `JavaFixture.java`: JDK17-compatible JDK HttpServer, HttpURLConnection client and
  H2 JDBC Statement. Run the same compiled fixture on Java17 and Java21.
- `main.js`: native Node HTTP server/client; run on Node22 and optionally Node20.
- Both listen on 8080 and expose `/ready`, `/downstream`, `/exercise`. The exercise
  makes a real HTTP request to `OUTBOUND_URL`, defaulting to its own downstream.
  `PORT` and `BIND_ADDRESS` can override the defaults for isolated loopback smoke
  checks; the Kind fixtures use port 8080 and the Pod network's default bind.
- Java also executes a real H2 SELECT containing only deliberately synthetic
  email/PAN values. The Operator enables the Java agent's JDBC literal sanitizer;
  do not override it. This verifies real JDBC statement spans with useful SQL and
  placeholders, not that only the gateway removed each original literal.

`fixtures.json` pins official runtime indices (amd64 and arm64) observed from
Docker Hub and H2 bytes fetched from Maven Central. The H2 SHA256 was computed
from the actual jar over verified HTTPS; Maven Central has no `.sha256` sidecar
for this artifact. The upstream release is 2.5.252.

Prepare the local Docker build context (downloads and verifies H2; does not build
or start any image):

```bash
python tests/instrumentation-fixtures/prepare.py
```

Use `Dockerfile.java17`, `Dockerfile.java21`, `Dockerfile.node22` or
`Dockerfile.node20`. Each pins the corresponding base from `fixtures.json`.
The E2E orchestrator builds only
local test images, loads them into its own disposable Kind cluster, and records
their image IDs. These fixtures are not shipped to customers or published.

Node20 is EOL and its fixture requires an explicit legacy opt-in. Passing this
compatibility test does not make an EOL runtime suitable for production.

The standalone SDK sink listens on HTTPS 8443, requires a client certificate
trusted by `/tls/ca.crt`, accepts `/v1/{traces,logs,metrics}` without backend
credentials and protects `/state` with a separate synthetic Bearer token. It
records decompressed OTLP bytes and client-certificate verification for the E2E
orchestrator. This is a test-only sink, not a production service.

Run fixture contracts and actual loopback mTLS positive/negative checks:

```bash
python tests/instrumentation-fixtures/test_fixtures.py
```

Those tests validate the sink and fixture contracts only. They do not claim SDK
loading, Kubernetes mutation or application-generated spans; the disposable
Kind E2E supplies those separate gates.
