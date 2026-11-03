# Elven Instrumentation Operator

Opt-in admission injector for the Elven distribution. This component creates no
CRDs, watches no cluster objects and calls no Kubernetes API. It needs no
ServiceAccount token or runtime RBAC. The distribution owns its Deployment,
Service and namespaced serving certificates; the installer separately manages
one uniquely named `MutatingWebhookConfiguration`.

## Scope and activation

The server independently checks an explicit namespace allow-list, `CREATE`
operation, core `v1` Pods and the Pod label
`elven.observability/inject=java|nodejs|python|nodejs20`. The webhook's namespace
and object selectors are an additional boundary, not the only boundary.

For a multi-container Pod, annotation
`elven.observability/container-name=<regular-container-name>` is mandatory. Only
that regular container receives the SDK loader, mTLS files and OTLP settings;
sidecars and original application security contexts are not changed. An
optional `elven.observability/service-name` sets a stable, bounded identity;
otherwise `app.kubernetes.io/name` or the stable container name is used. Pod
names/UIDs are never used as the service name.

Python defaults to glibc; musl-based images require the explicit annotation
`elven.observability/python-platform=musl`. Python remains a compatibility-gated
module. Node.js 20 uses a separate legacy image and requires
`legacyNode20Approved=true`; it must not use the current Node.js 22+ agent.

No existing Deployment, Namespace or running Pod is patched/restarted by this
process. Apply opt-in through the application's reviewed Pod template, canary
the rollout and remove opt-in/redeploy for rollback. Reinvocation must remain
`Never`; returning an error for existing injection markers prevents stacking a
second agent. Repeating the same original AdmissionReview produces the same
JSONPatch.

## Configuration

`ELVEN_INJECTION_CONFIG` contains non-secret JSON fields:

- `namespaces`: explicit application namespaces, never system/operator namespace.
- `operatorNamespace`: distribution namespace, default `elven-observability`.
- `endpoint`: HTTPS OTLP gateway base URL, without userinfo, path, query or fragment.
- `tlsSecretName`: separately provisioned client-TLS Secret in every target namespace.
- `images`: runtime-to-image map; only corresponding
  `docker.io/elvenobservability/elven-auto-<runtime>:<version>@sha256:<digest>`
  references are accepted. No latest/mutable references or annotation overrides.
- `samplingRatio`: decimal `0..1`; default `1` is intended for an approved canary.
- `sdkVolumeSizeMiB`: disk-backed SDK `emptyDir`, default 128Mi, allowed 64–512Mi.
- `legacyNode20Approved`: explicit EOL exception, default false.

Image/version signatures and publication are checked by the distribution's
release/installer gate. Passing a digest to this process alone is not proof of
publication, signing or compatibility.

Serving configuration: `ELVEN_WEBHOOK_ADDR` (default `:9443`),
`ELVEN_WEBHOOK_CERT` and `ELVEN_WEBHOOK_KEY` (default
`/etc/elven/webhook/tls.crt` and `tls.key`). Serving certificates reload on new
handshakes. TLS 1.2+ is required. The Kubernetes API server verifies this serving
identity using the webhook's `caBundle`. If a cluster explicitly configures an
API-server client certificate, `ELVEN_WEBHOOK_CLIENT_CA` additionally requires
and verifies that certificate; do not enable it without that API-server setup.

## SDK transport, depth and privacy

The agent payload is copied using a non-root, capability-dropped, read-only-root
init container into the SDK volume. That volume is mounted read-only by the
application. Client CA/certificate/key are mounted read-only only in the target
application container. Client keys must be PEM PKCS#8 for Java compatibility.
The Secret projection is mode 0444 inside that container so arbitrary
application UIDs can read it without changing the application's UID/fsGroup.
This credential authenticates telemetry to the scoped gateway; it is not the
backend tenant token and grants no Kubernetes API access.

OTLP uses HTTP/protobuf over verified HTTPS and mTLS. Backend credentials are
never injected into application environment variables. Propagation is
`tracecontext` only; baggage and capture of arbitrary HTTP headers are not
enabled. Attribute/queue counts are bounded. The Java common database query
sanitization uses its current canonical option; bind-parameter capture is not
enabled. Node SDKs use only explicit environment resource detection: cloud
metadata, host/process discovery and process arguments are not collected. The
gateway's selective privacy processor remains authoritative for statements,
logs, attributes, events and errors before its persistent queues/exporters.
Profiles are a separate opt-in policy, not covered by this injector.

Agent coverage depends on language/runtime/library versions and startup mode.
It does not imply automatic business spans, every SQL statement, every log
framework or arbitrary method-level tracing. Generic SQL/payload capture flags
are not invented for unsupported SDKs. Java, Node.js and Python use their
documented loader conventions. Validate each signal with a real application
and the exact selected digest before production acceptance.

## Conflicts and operational limits

Existing `OTEL_*`, loader variables, `envFrom`, upstream injection annotations,
agent startup arguments, agent init containers and reserved volumes/mounts are
rejected rather than overwritten. `envFrom` is rejected because it can hide an
existing instrumentation authority or loader setting. SDKs embedded in an
image or application code cannot be detected purely from admission JSON;
the application inventory and canary remain mandatory. Known active or ambiguous
admission-injection markers also reject the selection. Another mutating webhook
that runs later can still add an agent: inventory all admission authorities,
keep only one authority per process and validate the final admitted Pod.
Explicit non-Linux Pod OS/node selections are rejected, never rewritten.
Secret existence,
certificate compatibility and destination egress are installer/application
acceptance gates, not claims made by an admission response.

Requests are bounded to 1MiB and 16 concurrent admissions with bounded HTTP
timeouts. Objects, environment values, private keys and request bodies are never
logged. Generated SDK environment entries are appended without echoing the
original application environment values. Admission denials contain fixed
explanations and never reflect request data. Availability
policy is configured by the chart: a fail-open webhook can let an uninstrumented
Pod start during an Operator outage; that is a coverage gap, not proof of
collection. Do not use instrumentation readiness as application readiness.

## Tests

```sh
cd operator
go test -race ./...
go vet ./...
```

Tests cover real HTTPS AdmissionReviews/JSONPatch encoding, TLS certificate
verification, optional client-certificate authentication, namespace/Pod/runtime
boundaries, image pins, legacy/runtime approvals, explicit container targeting,
stable service identity, conflicts, malformed/oversized input, capacity bounds
and no-reflection of private sentinels. Cluster mutation and actual SDK loading
are separate integration gates; a generated patch is not a successfully
instrumented application.
