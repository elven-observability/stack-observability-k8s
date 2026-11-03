# Elven Privacy Processor

A bounded OTLP sanitization policy. It transforms the telemetry copy **before**
persistent queues and exporters; it does not rewrite the application's stdout,
files or in-process logging objects.

    elven_privacy:
      log_body_mode: selective
      preserve_span_links: true
      max_depth: 24
      max_string_bytes: 262144
      max_collection_items: 4096

Selective mode preserves useful text/JSON and redacts recognized credential and
PII values, not the entire log. Strict mode replaces all log bodies and still
applies the same envelope policy. Both modes sanitize resource, scope, log, span,
event, link, metric metadata and exemplar attribute values, including nested
maps, arrays and sensitive field names. Trace/span/link IDs, timestamps, status
codes and numeric metric observations retain their meaning. Opaque vendor
tracestate is removed, not mistaken for required trace identity.

Known sensitive fields are masked regardless of the value's scalar/container
type. Strings are inspected for common credentials, email, Brazilian documents,
payment-card patterns and labelled identifiers. Encoding layers are bounded.
JSON is parsed and reserialized recursively rather than editing escaped fragments
with regex. Bytes, malformed JSON-looking content and exceeded budgets produce
explicit redaction markers; they never fall back to the raw payload.

In free-form key/value logs, commas, semicolons and ampersands may be part of
a credential and are not trusted as value boundaries. Quoted/compound sensitive
values are consumed completely; malformed values mask the ambiguous remainder.
Unquoted raw Cookie/Authorization headers can contain internal key/value pairs,
so their whole remainder is treated as sensitive. Prefer structured logs or
properly quoted values to retain operational fields following such headers.

The configurable depth ceiling is 24. Nested AnyValue maps/slices consume more
than one protobuf message level each, in addition to the OTLP envelope; allowing
32 caused a real downstream decoder recursion-limit rejection. The lower bound
leaves interoperability headroom rather than increasing the receiver's recursion
limit to make a test pass. Deeper subtrees are masked before queueing/export.

SQL statement fields and recognized SQL within text retain a diagnostic query
shape while strings, numeric values, binds and comments are removed. This is a
conservative lexer, **not a universal database parser** or SQL execution engine.
Unsupported/malformed lexical forms are masked as a whole. Dialects and unquoted
identifiers still require review; do not use the output as executable SQL or
promise capture of every statement.

This is **not universal PII detection or anonymization**. Free-form personal names,
novel field names, secrets without recognizable syntax, application-specific
payloads, compressed/encrypted objects and numeric metric values cannot be
classified reliably by this policy. Avoid producing sensitive telemetry at the
source, keep payload/parameter collection disabled, review the policy with
synthetic fixtures, and use strict mode or disable a signal if required.
Profiles are a separate data path and are not sanitized by this processor.

Run Go unit/race tests in this module. The distribution additionally executes
the actual compiled Collector against OTLP inputs, HTTPS sinks and persistent
queue inspection; unit tests alone do not establish runtime wiring or tenant
acceptance.
