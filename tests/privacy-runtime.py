#!/usr/bin/env python3
"""Real OTLP -> rendered Elven gateway -> HTTPS sink privacy laboratory.

Uses only synthetic data, a local Unix Docker engine, an internal disposable
bridge and digest-pinned images. No kubeconfig, published ports, host networking,
host PID or eBPF are used. Checks selective and strict modes, mTLS verification,
correlation, recursively sanitized values and sanitized persistence/recovery.
This is a bounded regression corpus, never a universal PII detection guarantee.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import http.server
import importlib.metadata
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

PYTHON_FIXTURE = "python:3.14.0-slim@sha256:0aecac02dc3d4c5dbb024b753af084cafe41f5416e02193f1ce345d671ec966e"
TOKEN = "synthetic-privacy-ingest-token"
TENANT = "synthetic-privacy-tenant"
TRACE_ID = bytes.fromhex("00112233445566778899aabbccddeeff")
SPAN_ID = bytes.fromhex("0123456789abcdef")
PARENT_ID = bytes.fromhex("deadbeef12345678")
LINK_TRACE_ID = bytes.fromhex("ffeeddccbbaa99887766554433221100")
LINK_SPAN_ID = bytes.fromhex("fedcba9876543210")
FORBIDDEN = [
    TOKEN,
    "alice@example.invalid", "123.456.789-09", "529.982.247-25", "4111 1111 1111 1111", "5555 5555 5555 4444",
    "synthetic-log-token", "quoted synthetic password", "nested@example.invalid",
    "123456789", "nested-api-secret", "escaped@example.invalid", "escaped\\u0040example.invalid",
    "json-password-secret", "array-access-secret", "keyuser@example.invalid",
    "json-private-secret", "BYTES_SECRET_SENTINEL", "OVERSIZE_SECRET_SENTINEL",
    "DEPTH_SECRET_SENTINEL", "COLLECTION_SECRET_SENTINEL", "resource@example.invalid",
    "scope@example.invalid", "scope-api-secret", "schema-token-secret",
    "trace@example.invalid", "dbuser@example.invalid", "sql-comment-secret",
    "sql-name-secret",
    "parameter-secret", "status@example.invalid", "event@example.invalid",
    "eventattr@example.invalid", "link@example.invalid", "link-token-secret",
    "malformed-sql-secret", "metric@example.invalid", "metricsdesc@example.invalid",
    "operational@example.invalid",
    "ESCAPED_PASSWORD_PRIVATE_SUFFIX",
    "SYNTHETIC_URL_PRIVATE", "URL_PRIVATE_SUFFIX",
    "PUNCTUATION_SECRET_PRIVATE", "COMPOUND_SECRET_PRIVATE",
    "exemplar@example.invalid", "987654321", "wal@example.invalid", "wal-token-secret",
]


def run(*args, data=None, timeout=120, check=True):
    result = subprocess.run([str(arg) for arg in args], input=data, text=True,
                            capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError("Synthetic command failed: " + " ".join(str(a) for a in args[:6])
                           + "\n" + result.stdout + "\n" + result.stderr)
    return result.stdout


def assert_local_docker():
    configured = os.environ.get("DOCKER_HOST", "")
    endpoint = run("docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}").strip()
    if (configured and not configured.startswith("unix://")) or not endpoint.startswith("unix://"):
        raise ValueError("This laboratory requires a local Unix Docker socket, not a remote customer engine")
    if run("docker", "info", "--format", "{{.OSType}}").strip() != "linux":
        raise ValueError("This laboratory requires Linux containers")


def certificates(folder):
    paths = {name: folder / name for name in ("ca", "gateway", "fixture", "client")}
    for path in paths.values():
        path.mkdir()
        path.chmod(0o755)
    ca = paths["ca"]
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=Elven-Synthetic-Privacy-CA", "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash",
        "-keyout", ca / "ca.key", "-out", ca / "ca.crt")
    for name in ("gateway", "fixture", "client"):
        target = paths[name]
        prefix = "client" if name == "client" else "tls"
        run("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=privacy-" + name,
            "-keyout", target / (prefix + ".key"), "-out", target / "request.csr")
        purpose = "clientAuth" if name == "client" else "serverAuth"
        san = ""
        if name == "gateway":
            san = "subjectAltName=DNS:privacy-gateway,DNS:privacy-strict\n"
        elif name == "fixture":
            san = "subjectAltName=DNS:privacy-fixture\n"
        extensions = target / "extensions.cnf"
        extensions.write_text("basicConstraints=critical,CA:FALSE\nsubjectKeyIdentifier=hash\n"
                              "authorityKeyIdentifier=keyid,issuer\n"
                              "keyUsage=critical,digitalSignature,keyEncipherment\n"
                              "extendedKeyUsage=" + purpose + "\n" + san)
        run("openssl", "x509", "-req", "-in", target / "request.csr", "-CA", ca / "ca.crt",
            "-CAkey", ca / "ca.key", "-CAcreateserial", "-days", "1", "-extfile", extensions,
            "-out", target / (prefix + ".crt"))
        shutil.copyfile(ca / "ca.crt", target / "ca.crt")
        # Disposable synthetic files only. Production Secret permissions are
        # owned by Kubernetes; no real keys or CA private key enter containers.
        for path in target.iterdir():
            path.chmod(0o444)
    return paths


def serve():
    state = {"status": 200, "attempted": [], "accepted": [], "rejections": 0}
    lock = threading.Lock()

    class Sink(http.server.BaseHTTPRequestHandler):
        def reply(self, status, payload=b"{}"):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def authorized(self):
            return (self.headers.get("Authorization") == "Bearer " + TOKEN
                    and self.headers.get("X-Scope-OrgID") == TENANT)

        def do_GET(self):
            if not self.authorized():
                return self.reply(401)
            if self.path != "/state":
                return self.reply(404)
            with lock:
                payload = json.dumps(state).encode()
            self.reply(200, payload)

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if not self.authorized():
                with lock:
                    state["rejections"] += 1
                return self.reply(401)
            if self.path == "/control":
                status = json.loads(body)["status"]
                if status not in (200, 503):
                    return self.reply(400)
                with lock:
                    state["status"] = status
                return self.reply(200)
            if self.path not in ("/v1/logs", "/v1/metrics", "/v1/traces"):
                return self.reply(404)
            if self.headers.get("Content-Encoding") == "gzip":
                body = gzip.decompress(body)
            capture = {"path": self.path, "body": base64.b64encode(body).decode(),
                       "content_type": self.headers.get("Content-Type"),
                       "content_encoding": self.headers.get("Content-Encoding"), "authenticated": True}
            with lock:
                state["attempted"].append(capture)
                status = state["status"]
                if status == 200:
                    state["accepted"].append(capture)
            self.reply(status)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), Sink)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def action(request):
    """Stdlib-only operations executed inside the rootless synthetic fixture."""
    operation = request["op"]
    if operation == "wal":
        forbidden = [value.encode() for value in request["forbidden"]]
        matches, files, redacted, useful = [], [], 0, 0
        for path in sorted(Path("/wal/selective").rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            contents = path.read_bytes()
            files.append({"name": str(path.relative_to("/wal/selective")), "bytes": len(contents)})
            matches.extend(value.decode() for value in forbidden if value in contents)
            redacted += contents.count(b"[REDACTED")
            useful += contents.count(b"outage keep operation status=503")
        return {"files": files, "forbidden_matches": sorted(set(matches)),
                "redaction_markers": redacted, "useful_message_occurrences": useful}
    if operation == "cleanup":
        # Only these exact disposable fixture mounts may be cleared. They are
        # writable solely in a one-shot cleanup container, never the sink.
        for name in ("selective", "strict"):
            root = Path("/cleanup") / name
            for path in root.iterdir():
                if path.is_dir() and not path.is_symlink():
                    shutil.rmtree(path)
                else:
                    path.unlink()
        return {"cleaned": True}
    context = ssl.create_default_context(cafile="/client/ca.crt")
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if operation == "send":
        if request.get("client_certificate", True):
            context.load_cert_chain("/client/client.crt", "/client/client.key")
        host = request.get("host", "privacy-gateway")
        url = "https://" + host + ":4318/v1/" + request["signal"]
        body = base64.b64decode(request["body"])
        headers = {"Content-Type": "application/x-protobuf"}
    else:
        url = "https://privacy-fixture:8443/" + ("control" if operation == "control" else "state")
        body = json.dumps({"status": request["status"]}).encode() if operation == "control" else None
        headers = {"Authorization": "Bearer " + TOKEN, "X-Scope-OrgID": TENANT,
                   "Content-Type": "application/json"}
    outgoing = urllib.request.Request(url, data=body, headers=headers)
    try:
        with urllib.request.urlopen(outgoing, context=context, timeout=10) as response:
            payload = response.read()
            return {"status": response.status, "payload": payload.decode()}
    except urllib.error.HTTPError as error:
        # HTTP rejection proves the TLS connection completed. Never mistake
        # an application 4xx/5xx for the required no-client-certificate gate.
        return {"status": error.code, "payload": error.read().decode()}
    except (urllib.error.URLError, ssl.SSLError) as error:
        if operation == "send" and not request.get("client_certificate", True):
            return {"tls_rejected": True, "error_type": type(error).__name__}
        raise


def set_value(target, value):
    if isinstance(value, bool):
        target.bool_value = value
    elif isinstance(value, int):
        target.int_value = value
    elif isinstance(value, float):
        target.double_value = value
    elif isinstance(value, bytes):
        target.bytes_value = value
    elif isinstance(value, str):
        target.string_value = value
    elif isinstance(value, dict):
        attributes(target.kvlist_value.values, value)
    elif isinstance(value, list):
        for item in value:
            set_value(target.array_value.values.add(), item)
    elif value is not None:
        raise TypeError(type(value).__name__)


def attributes(target, values):
    for key, value in values.items():
        item = target.add()
        item.key = key
        set_value(item.value, value)


def shared(resource, scope):
    attributes(resource.attributes, {"service.name": "checkout", "k8s.namespace.name": "synthetic-app",
                                     "user.email": "resource@example.invalid"})
    scope.name = "runtime/scope@example.invalid"
    scope.version = "synthetic-1.0"
    attributes(scope.attributes, {"apiKey": "scope-api-secret"})


def corpus():
    from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
    from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

    logs = ExportLogsServiceRequest()
    resource_logs = logs.resource_logs.add()
    scope_logs = resource_logs.scope_logs.add()
    shared(resource_logs.resource, scope_logs.scope)
    resource_logs.schema_url = "https://schema.example.invalid/?token=schema-token-secret"
    nested = {"message": "worker retry status=503", "user": {"email": "nested@example.invalid", "password": 123456789},
              "items": [{"apiKey": "nested-api-secret"}, {"ok": True}],
              "accessToken": ["array-access-secret", {"password": True}],
              "keyuser@example.invalid": "operational map key value"}
    deep = {"message": "DEPTH_SECRET_SENTINEL"}
    for _ in range(40):
        deep = {"nested": deep}
    bodies = {
        "text": 'checkout failed status=502 latency_ms=17 email=alice@example.invalid cpf=123.456.789-09 '
                'card=4111 1111 1111 1111 token=synthetic-log-token password="quoted synthetic password"',
        "structured": nested,
        "json": r'{"message":"cache refresh complete","user":{"email":"escaped\u0040example.invalid",'
                r'"password":"json-password-secret"},"items":[{"ok":true}]}',
        "sql-text": "executing SELECT id FROM orders WHERE customer='sql-name-secret' AND total=42",
        "operational-verbs": "update cache complete status=200 DELETE /orders email=operational@example.invalid",
        "escaped-password": r'authentication failed password="prefix\"ESCAPED_PASSWORD_PRIVATE_SUFFIX" status=200',
        "adjacent-numbers": "identifier checks 529.982.247-25 123.456.789-09 cards "
                            "4111 1111 1111 1111 5555 5555 5555 4444 status=200",
        "encoded-relative-url": "request /orders?customer=SYNTHETIC_URL_PRIVATE%20URL_PRIVATE_SUFFIX&id=123 "
                                "completed status=200",
        "punctuation-secret": "authentication punctuation password=abc,PUNCTUATION_SECRET_PRIVATE status=200",
        "compound-secret": 'request compound payload={"safe":"one","other":"COMPOUND_SECRET_PRIVATE"} status=200',
        "malformed-json": '{"message":"broken", "password":"json-private-secret"',
        "bytes": b"BYTES_SECRET_SENTINEL",
        "oversize": "x" * 262145 + "OVERSIZE_SECRET_SENTINEL",
        "depth": deep,
        "collection": ["operational"] * 4100 + ["COLLECTION_SECRET_SENTINEL"],
    }
    now = time.time_ns()
    for name, body in bodies.items():
        record = scope_logs.log_records.add()
        record.time_unix_nano = now
        record.observed_time_unix_nano = now
        record.trace_id, record.span_id = TRACE_ID, SPAN_ID
        record.severity_number = 17
        record.severity_text = "ERROR"
        attributes(record.attributes, {"privacy.test.case": name, "http.response.status_code": 502})
        set_value(record.body, body)

    traces = ExportTraceServiceRequest()
    resource_spans = traces.resource_spans.add()
    scope_spans = resource_spans.scope_spans.add()
    shared(resource_spans.resource, scope_spans.scope)
    span = scope_spans.spans.add()
    span.trace_id, span.span_id, span.parent_span_id = TRACE_ID, SPAN_ID, PARENT_ID
    span.name = "checkout trace@example.invalid"
    span.start_time_unix_nano, span.end_time_unix_nano = now, now + 17_000_000
    span.kind = 2
    span.status.code = 2
    span.status.message = "upstream timeout email=status@example.invalid status=504"
    attributes(span.attributes, {"db.system": "postgresql", "db.operation.name": "SELECT",
        "db.query.text": "SELECT id, total FROM orders WHERE email='dbuser@example.invalid' AND total=42 /* sql-comment-secret */",
        "db.query.parameters": {"1": "parameter-secret", "2": 123456789}})
    event = span.events.add()
    event.name, event.time_unix_nano = "retry event event@example.invalid", now
    attributes(event.attributes, {"exception.message": "worker failed for eventattr@example.invalid"})
    link = span.links.add()
    link.trace_id, link.span_id = LINK_TRACE_ID, LINK_SPAN_ID
    attributes(link.attributes, {"user.email": "link@example.invalid", "accessToken": "link-token-secret"})
    malformed = scope_spans.spans.add()
    malformed.trace_id, malformed.span_id = TRACE_ID, bytes.fromhex("1122334455667788")
    malformed.name = "malformed SQL diagnostic"
    malformed.start_time_unix_nano, malformed.end_time_unix_nano = now, now + 1_000_000
    attributes(malformed.attributes, {"db.system": "postgresql", "db.statement": "SELECT 'malformed-sql-secret"})

    metrics = ExportMetricsServiceRequest()
    resource_metrics = metrics.resource_metrics.add()
    scope_metrics = resource_metrics.scope_metrics.add()
    shared(resource_metrics.resource, scope_metrics.scope)
    metric = scope_metrics.metrics.add()
    metric.name = "privacy.runtime.gauge"
    metric.description, metric.unit = "latency metric for metricsdesc@example.invalid", "1"
    point = metric.gauge.data_points.add()
    point.time_unix_nano, point.as_double = now, 42
    attributes(point.attributes, {"phase": "Running", "status": "metric@example.invalid"})
    exemplar = point.exemplars.add()
    exemplar.time_unix_nano, exemplar.as_double = now, 42
    exemplar.trace_id, exemplar.span_id = TRACE_ID, SPAN_ID
    attributes(exemplar.filtered_attributes, {"user.email": "exemplar@example.invalid", "password": 987654321})
    return {"logs": logs, "traces": traces, "metrics": metrics}


def outage_payload():
    from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
    payload = ExportLogsServiceRequest()
    resource = payload.resource_logs.add()
    attributes(resource.resource.attributes, {"service.name": "checkout"})
    record = resource.scope_logs.add().log_records.add()
    record.time_unix_nano = time.time_ns()
    record.trace_id, record.span_id = TRACE_ID, SPAN_ID
    attributes(record.attributes, {"privacy.test.case": "outage"})
    record.body.string_value = "outage keep operation status=503 email=wal@example.invalid token=wal-token-secret"
    return payload


def decode(captures):
    from google.protobuf.json_format import Parse
    from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
    from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
    types = {"logs": ExportLogsServiceRequest, "traces": ExportTraceServiceRequest,
             "metrics": ExportMetricsServiceRequest}
    decoded = {signal: [] for signal in types}
    for capture in captures:
        signal = capture["path"].rsplit("/", 1)[-1]
        payload = types[signal]()
        raw = base64.b64decode(capture["body"])
        try:
            if (capture.get("content_type") or "").split(";", 1)[0].strip() == "application/json":
                Parse(raw.decode("utf-8"), payload)
            else:
                payload.ParseFromString(raw)
        except Exception as error:
            # Only synthetic corpus bytes, never TLS keys or real tenant data.
            # Preserve the failing wire message for independent protobuf
            # diagnostics; CI uploads intentionally include reports only.
            diagnostic = Path(__file__).resolve().parents[1] / ".artifacts" / ("privacy-wire-" + uuid.uuid4().hex[:12])
            diagnostic.mkdir(parents=True, mode=0o700)
            wire = diagnostic / (signal + ".pb")
            wire.write_bytes(raw)
            raise AssertionError("Invalid synthetic OTLP capture: " + json.dumps({
                "signal": signal, "content_type": capture.get("content_type"),
                "content_encoding": capture.get("content_encoding"), "bytes": len(raw),
                "prefix_hex": raw[:16].hex(), "synthetic_wire_file": str(wire)})) from error
        decoded[signal].append(payload)
    return decoded


def records(decoded):
    return [record for payload in decoded["logs"] for resource in payload.resource_logs
            for scope in resource.scope_logs for record in scope.log_records]


def case_of(record):
    return next((item.value.string_value for item in record.attributes
                 if item.key == "privacy.test.case"), None)


def serialized(decoded):
    from google.protobuf.json_format import MessageToDict
    return json.dumps({signal: [MessageToDict(item, preserving_proto_field_name=True) for item in messages]
                       for signal, messages in decoded.items()}, sort_keys=True)


def semantic_items(decoded):
    """Ignore batching and attribute ordering, never ignore actual values."""
    from google.protobuf.json_format import MessageToDict

    def normalize(value):
        if isinstance(value, dict):
            return {key: normalize(item) for key, item in value.items()}
        if isinstance(value, list):
            result = [normalize(item) for item in value]
            if result and all(isinstance(item, dict) and set(item) == {"key", "value"} for item in result):
                result.sort(key=lambda item: item["key"])
            return result
        return value

    contracts = {"logs": ("resource_logs", "scope_logs", "log_records"),
                 "traces": ("resource_spans", "scope_spans", "spans"),
                 "metrics": ("resource_metrics", "scope_metrics", "metrics")}
    result = {signal: [] for signal in contracts}
    for signal, (resources_key, scopes_key, item_key) in contracts.items():
        for message in decoded[signal]:
            data = MessageToDict(message, preserving_proto_field_name=True)
            for resource in data.get(resources_key, []):
                for scope in resource.get(scopes_key, []):
                    for item in scope.get(item_key, []):
                        context = {"resource": resource.get("resource", {}),
                                   "resource_schema_url": resource.get("schema_url", ""),
                                   "scope": scope.get("scope", {}),
                                   "scope_schema_url": scope.get("schema_url", ""), "item": item}
                        result[signal].append(json.dumps(normalize(context), sort_keys=True))
        result[signal].sort()
    return result


def assert_corpus(decoded):
    text = serialized(decoded)
    leaked = [value for value in FORBIDDEN if value in text]
    if leaked:
        raise AssertionError("Synthetic privacy sentinel leaked: " + ", ".join(leaked))
    for useful in ("checkout failed status=502 latency_ms=17", "worker retry status=503",
                   "cache refresh complete", "executing SELECT", "update cache complete status=200 DELETE /orders",
                   "checkout", "orders", "SELECT", "Running"):
        if useful not in text:
            raise AssertionError("Selective mode lost expected useful information: " + useful)
    by_case = {case_of(record): record for record in records(decoded)}
    for case in ("text", "structured", "json", "sql-text", "operational-verbs", "escaped-password", "adjacent-numbers",
                 "encoded-relative-url",
                 "punctuation-secret", "compound-secret",
                 "malformed-json", "bytes", "oversize", "depth", "collection"):
        if case not in by_case:
            raise AssertionError("Missing synthetic log case " + case)
        record = by_case[case]
        if record.trace_id != TRACE_ID or record.span_id != SPAN_ID:
            raise AssertionError("Log correlation changed in case " + case)
    for case in ("malformed-json", "bytes", "oversize", "depth", "collection"):
        if "[REDACTED" not in str(by_case[case].body):
            raise AssertionError("Unsafe/over-budget case lacks fail-closed marker: " + case)
    if "[REDACTED" not in str(by_case["text"].body):
        raise AssertionError("Selective log text did not mask sensitive values")
    escaped_password = by_case["escaped-password"].body.string_value
    if ("authentication failed" not in escaped_password or "status=200" not in escaped_password
            or "prefix" in escaped_password or "[REDACTED" not in escaped_password):
        raise AssertionError("Escaped quoted password lost masking or adjacent operational fields")
    adjacent_numbers = by_case["adjacent-numbers"].body.string_value
    if ("identifier checks" not in adjacent_numbers or "status=200" not in adjacent_numbers
            or "[REDACTED" not in adjacent_numbers):
        raise AssertionError("Adjacent CPF/PAN values lost masking or adjacent operational fields")
    relative_url = by_case["encoded-relative-url"].body.string_value
    if "/orders?" not in relative_url or "completed" not in relative_url or "status=200" not in relative_url:
        raise AssertionError("Encoded relative URL sanitization lost path or adjacent operational fields")
    for case, prefix in (("punctuation-secret", "authentication punctuation"),
                         ("compound-secret", "request compound")):
        secret_body = by_case[case].body.string_value
        if prefix not in secret_body or "status=200" not in secret_body or "[REDACTED" not in secret_body:
            raise AssertionError("Compound/punctuated credential lost masking or adjacent fields: " + case)
    if by_case["malformed-json"].body.string_value != "[REDACTED:json]":
        raise AssertionError("Malformed JSON did not fail closed as one complete body")
    if by_case["bytes"].body.string_value != "[REDACTED:bytes]":
        raise AssertionError("Opaque bytes did not fail closed")
    spans = [span for payload in decoded["traces"] for resource in payload.resource_spans
             for scope in resource.scope_spans for span in scope.spans]
    main = next(span for span in spans if span.span_id == SPAN_ID)
    query = next(item.value.string_value for item in main.attributes if item.key == "db.query.text")
    if not all(fragment in query for fragment in ("SELECT", "orders", "WHERE")) or "42" in query:
        raise AssertionError("Supported SQL shape/literal sanitization is incorrect: " + query)
    malformed = next(span for span in spans if span.span_id != SPAN_ID)
    malformed_query = next(item.value.string_value for item in malformed.attributes if item.key == "db.statement")
    if malformed_query != "[REDACTED:sql]":
        raise AssertionError("Malformed SQL did not fail closed as one complete query")
    if (main.trace_id != TRACE_ID or main.parent_span_id != PARENT_ID or len(main.links) != 1
            or main.links[0].trace_id != LINK_TRACE_ID or main.links[0].span_id != LINK_SPAN_ID):
        raise AssertionError("Span/parent/link correlation was not preserved")
    if len(main.links[0].attributes) != 2 or not all("[REDACTED" in str(item.value) for item in main.links[0].attributes):
        raise AssertionError("Link attributes were not sanitized")
    points = [point for payload in decoded["metrics"] for resource in payload.resource_metrics
              for scope in resource.scope_metrics for metric in scope.metrics
              for point in metric.gauge.data_points]
    if len(points) != 1 or points[0].as_double != 42 or len(points[0].exemplars) != 1:
        raise AssertionError("Gauge numeric value/exemplar was lost")
    exemplar = points[0].exemplars[0]
    if exemplar.trace_id != TRACE_ID or exemplar.span_id != SPAN_ID:
        raise AssertionError("Metric exemplar correlation changed")
    if (len(exemplar.filtered_attributes) != 2
            or not all("[REDACTED" in str(item.value) for item in exemplar.filtered_attributes)):
        raise AssertionError("Exemplar attributes were not sanitized")
    return {"log_cases": len(by_case), "spans": len(spans), "metric_points": len(points),
            "span_links_preserved": len(main.links), "known_sensitive_values_absent": True,
            "useful_operational_text_preserved": True, "correlation_preserved": True}


def render_gateway(root, directory, mode):
    import yaml
    values = {"cluster": {"name": "synthetic-privacy"}, "networkPolicy": {"enabled": False},
              "selfMonitoring": {"enabled": False}, "exportTLS": {"existingCASecret": "synthetic-export-ca"},
              "privacy": {"logBodyMode": mode, "preserveSpanLinks": True},
              "endpoints": {signal: "https://privacy-fixture:8443/v1/" + signal
                            for signal in ("logs", "traces", "metrics")}}
    source = directory / (mode + "-values.yaml")
    source.write_text(yaml.safe_dump(values))
    rendered = run("helm", "template", "privacy", root / "charts/elven-observability", "--namespace",
                   "elven-synthetic", "--kube-version", "1.37.0", "-f", source)
    objects = [item for item in yaml.safe_load_all(rendered) if item]
    configuration = next(item["data"]["collector.yaml"] for item in objects
                         if item["kind"] == "ConfigMap" and "collector.yaml" in item.get("data", {}))
    parsed = yaml.safe_load(configuration)
    if parsed["processors"]["elven_privacy"]["log_body_mode"] != mode:
        raise AssertionError("Rendered gateway did not select requested privacy mode")
    for signal in ("logs", "metrics", "traces"):
        if "elven_privacy" not in parsed["service"]["pipelines"][signal]["processors"]:
            raise AssertionError("Privacy processor is missing before exporter for " + signal)
    path = directory / (mode + "-collector.yaml")
    path.write_text(configuration)
    path.chmod(0o444)
    return path


def smoke(image):
    import yaml

    if not re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", image):
        raise ValueError("--image must be an explicit sha256 digest-pinned Elven Collector image")
    assert_local_docker()
    root = Path(__file__).resolve().parents[1]
    identity = "elven-privacy-test-" + uuid.uuid4().hex[:12]
    report = root / ".artifacts" / ("privacy-" + identity.rsplit("-", 1)[-1]) / "report.json"
    network, fixture = identity, identity + "-fixture"
    containers, network_created = [], False
    evidence = {"result": "FAIL", "image": image, "fixture_image": PYTHON_FIXTURE,
                "runtime_platform": run("docker", "image", "inspect", image,
                                        "--format", "{{.Os}}/{{.Architecture}}").strip(),
                "test_dependencies": {name: importlib.metadata.version(name)
                                      for name in ("protobuf", "opentelemetry-proto", "PyYAML")},
                "customer_cluster_access": False, "checks": [],
                "network": "internal Docker bridge; no published ports or host networking",
                "not_proven": ["universal PII detection", "client data/tenant ingestion", "NetworkPolicy enforcement",
                               "production disk capacity/scale", "all SQL dialects"]}
    with tempfile.TemporaryDirectory(prefix="elven-privacy-runtime-") as temporary:
        folder = Path(temporary)
        pki = certificates(folder)
        runtime = folder / "runtime"
        runtime.mkdir(mode=0o755)
        script = runtime / "privacy-runtime.py"
        shutil.copyfile(Path(__file__), script)
        script.chmod(0o444)
        queues = folder / "queues"
        queues.mkdir(mode=0o755)
        for mode in ("selective", "strict"):
            # Synthetic writable bind directories allow UID10001 to create its
            # own private 0700 storage without a privileged init container.
            (queues / mode).mkdir(mode=0o777)
            (queues / mode).chmod(0o777)
        configs = {mode: render_gateway(root, runtime, mode) for mode in ("selective", "strict")}
        evidence["config_sha256"] = {mode: hashlib.sha256(path.read_bytes()).hexdigest()
                                     for mode, path in configs.items()}
        evidence["privacy"] = yaml.safe_load(configs["selective"].read_text())["processors"]["elven_privacy"]

        def fixture_action(payload):
            output = run("docker", "exec", "-i", fixture, "python", "/fixture/privacy-runtime.py", "--action",
                         data=json.dumps(payload), timeout=30)
            return json.loads(output)

        def state():
            return json.loads(fixture_action({"op": "state"})["payload"])

        def send(signal, payload, **options):
            response = fixture_action({"op": "send", "signal": signal,
                "body": base64.b64encode(payload.SerializeToString()).decode(), **options})
            if options.get("client_certificate", True) and response.get("status") != 200:
                raise AssertionError("OTLP mTLS receiver rejected synthetic " + signal + ": " + str(response))
            return response

        def wait_for(predicate, description, timeout=60):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if predicate():
                    return
                time.sleep(0.25)
            raise AssertionError("Timeout: " + description)

        def gateway(mode):
            name = identity + "-" + mode
            alias = "privacy-gateway" if mode == "selective" else "privacy-strict"
            run("docker", "run", "--detach", "--name", name, "--network", network,
                "--network-alias", alias, "--user", "10001:10001", "--cap-drop", "ALL", "--read-only",
                "--security-opt", "no-new-privileges", "--memory", "512m", "--cpus", "1",
                "--mount", f"type=bind,source={configs[mode]},target=/etc/elven/collector.yaml,readonly",
                "--mount", f"type=bind,source={pki['gateway']},target=/etc/elven/tls,readonly",
                "--mount", f"type=bind,source={pki['client'] / 'ca.crt'},target=/etc/elven/export-ca/ca.crt,readonly",
                "--mount", f"type=bind,source={queues / mode},target=/var/lib/elven",
                "--env", "ELVEN_API_TOKEN=" + TOKEN, "--env", "ELVEN_TENANT_ID=" + TENANT,
                "--env", "ELVEN_POD_NAME=synthetic-privacy-0", image, "--config=/etc/elven/collector.yaml")
            containers.append(name)
            def ready():
                state = json.loads(run("docker", "inspect", name))[0]["State"]
                if not state["Running"]:
                    raise AssertionError(mode + " Collector exited before receiver readiness; exit="
                                         + str(state.get("ExitCode")) + "; "
                                         + run("docker", "logs", "--tail", "20", name, check=False))
                try:
                    return fixture_action({"op": "send", "host": alias, "signal": "logs",
                                           "body": ""}).get("status") == 200
                except RuntimeError as error:
                    # Retry only a listener not yet bound. In particular, a
                    # TLS verification/authentication failure must not hide
                    # behind a readiness timeout or insecure retry path.
                    if "Connection refused" in str(error):
                        return False
                    raise
            wait_for(ready, mode + " receiver startup")
            return name

        try:
            run("docker", "network", "create", "--internal", network)
            network_created = True
            run("docker", "run", "--detach", "--name", fixture, "--network", network,
                "--network-alias", "privacy-fixture", "--user", "10001:10001", "--cap-drop", "ALL", "--read-only",
                "--security-opt", "no-new-privileges", "--memory", "192m", "--cpus", "0.5",
                "--mount", f"type=bind,source={runtime},target=/fixture,readonly",
                "--mount", f"type=bind,source={pki['fixture']},target=/tls,readonly",
                "--mount", f"type=bind,source={pki['client']},target=/client,readonly",
                "--mount", f"type=bind,source={queues / 'selective'},target=/wal/selective,readonly",
                PYTHON_FIXTURE, "python", "-u", "/fixture/privacy-runtime.py", "--serve")
            containers.append(fixture)
            # The initial listener race is expected, but any persistent failure
            # must abort rather than silently skipping runtime assertions.
            deadline = time.monotonic() + 30
            while True:
                try:
                    state()
                    break
                except (RuntimeError, json.JSONDecodeError):
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.25)
            selective = gateway("selective")
            payloads = corpus()
            expected_log_cases = len(payloads["logs"].resource_logs[0].scope_logs[0].log_records)
            rejected = send("logs", payloads["logs"], client_certificate=False)
            if not rejected.get("tls_rejected"):
                raise AssertionError("Gateway accepted a connection without a client certificate")
            evidence["checks"].append({"name": "verified server TLS and required client certificate", "result": "PASS"})
            for signal, payload in payloads.items():
                send(signal, payload)
            def all_signals_arrived():
                # Readiness uses an empty OTLP request. Only actual records
                # satisfy delivery, never merely an accepted empty batch.
                counts = semantic_items(decode(state()["accepted"]))
                return (len(counts["logs"]) >= expected_log_cases
                        and len(counts["traces"]) >= 2 and len(counts["metrics"]) >= 1)
            wait_for(all_signals_arrived, "all three OTLP signals exported")
            initial = assert_corpus(decode(state()["accepted"]))
            evidence["checks"].append({"name": "selective privacy and correlation", "result": "PASS", **initial})

            first_pass = decode(state()["accepted"])
            expected = semantic_items(first_pass)
            second_baseline = len(state()["accepted"])
            for signal, messages in first_pass.items():
                for message in messages:
                    send(signal, message)
            def second_pass_arrived():
                actual = semantic_items(decode(state()["accepted"][second_baseline:]))
                return all(len(actual[signal]) >= len(expected[signal]) for signal in expected)
            wait_for(second_pass_arrived, "all sanitized signals delivered through second privacy boundary")
            second_pass = decode(state()["accepted"][second_baseline:])
            if semantic_items(second_pass) != expected:
                raise AssertionError("Second privacy pass changed sanitized semantic content/correlation")
            assert_corpus(second_pass)
            evidence["checks"].append({"name": "idempotent second privacy boundary for node-to-gateway",
                                       "result": "PASS", "signals": sorted(first_pass)})

            fixture_action({"op": "control", "status": 503})
            outage = outage_payload()
            send("logs", outage)
            wait_for(lambda: any(case_of(record) == "outage" for record in records(decode(state()["attempted"]))),
                     "exporter attempts sanitized outage record")
            attempted = next(record for record in records(decode(state()["attempted"])) if case_of(record) == "outage")
            # Stop cleanly with exporter unavailable, inspect the actual storage
            # bytes RO as the runtime UID, and then restart the same container.
            run("docker", "stop", "--time", "5", selective, timeout=20)
            wal = fixture_action({"op": "wal", "forbidden": FORBIDDEN})
            if (not wal["files"] or wal["forbidden_matches"] or wal["redaction_markers"] < 1
                    or wal["useful_message_occurrences"] < 1):
                raise AssertionError("Persisted queue privacy assertion failed: " + json.dumps(wal))
            fixture_action({"op": "control", "status": 200})
            run("docker", "start", selective)
            wait_for(lambda: any(case_of(record) == "outage" for record in records(decode(state()["accepted"]))),
                     "sanitized persistent outage record recovered after restart", timeout=90)
            recovered = [record for record in records(decode(state()["accepted"])) if case_of(record) == "outage"]
            if not recovered or any(record.SerializeToString() != attempted.SerializeToString() for record in recovered):
                raise AssertionError("Recovered persistent log is not the original sanitized record")
            final_text = serialized(decode(state()["accepted"]))
            if any(value in final_text for value in FORBIDDEN):
                raise AssertionError("Sensitive value appeared after persistent-queue recovery")
            evidence["checks"].append({"name": "privacy before persistent WAL and restart recovery", "result": "PASS", **wal})

            gateway("strict")
            baseline = len(state()["accepted"])
            send("logs", payloads["logs"], host="privacy-strict")
            expected_strict = len(payloads["logs"].resource_logs[0].scope_logs[0].log_records)
            wait_for(lambda: len([record for record in records(decode(state()["accepted"][baseline:]))
                                  if case_of(record) != "outage"]) >= expected_strict, "strict log body delivery")
            strict_records = [record for record in records(decode(state()["accepted"][baseline:]))
                              if case_of(record) != "outage"]
            if len(strict_records) != expected_strict:
                raise AssertionError("Strict mode did not deliver all synthetic log cases")
            if any(record.body.string_value != "[REDACTED]" for record in strict_records):
                raise AssertionError("Strict mode did not replace every complete log body")
            if any(record.trace_id != TRACE_ID or record.span_id != SPAN_ID for record in strict_records):
                raise AssertionError("Strict mode changed log correlation")
            strict_text = serialized(decode(state()["accepted"][baseline:]))
            if any(value in strict_text for value in FORBIDDEN):
                raise AssertionError("Strict mode leaked sensitive attributes outside body")
            evidence["checks"].append({"name": "explicit strict mode", "result": "PASS", "log_cases": len(strict_records)})
            evidence["result"] = "PASS"
            print(json.dumps(evidence, sort_keys=True))
            return evidence
        except Exception:
            for name in containers:
                diagnostics = run("docker", "logs", "--tail", "30", name, check=False)
                if diagnostics:
                    print(name + ":\n" + diagnostics[-12000:], file=sys.stderr)
            raise
        finally:
            for name in reversed(containers):
                run("docker", "rm", "--force", name, check=False, timeout=30)
            # UID10001 removes its own private directories; the host then owns
            # the empty parent. Neither the CA key nor unrelated paths mount.
            if any(any((queues / mode).iterdir()) for mode in ("selective", "strict")):
                run("docker", "run", "--rm", "--network", "none", "--user", "10001:10001",
                    "--cap-drop", "ALL", "--read-only", "--security-opt", "no-new-privileges",
                    "--mount", f"type=bind,source={runtime},target=/fixture,readonly",
                    "--mount", f"type=bind,source={queues},target=/cleanup",
                    PYTHON_FIXTURE, "python", "/fixture/privacy-runtime.py", "--action",
                    data=json.dumps({"op": "cleanup"}), check=False, timeout=30)
            if network_created:
                run("docker", "network", "rm", network, check=False, timeout=30)
            report.parent.mkdir(parents=True, mode=0o700)
            report.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
            print("Evidence: " + str(report), file=sys.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default=os.environ.get("ELVEN_COLLECTOR_IMAGE"),
                        help="Sha256 digest-pinned Elven Collector image, or ELVEN_COLLECTOR_IMAGE; no upstream fallback")
    parser.add_argument("--serve", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--action", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.serve:
        serve()
    elif args.action:
        print(json.dumps(action(json.load(sys.stdin))))
    elif not args.image:
        parser.error("--image or ELVEN_COLLECTOR_IMAGE is required and must be digest-pinned")
    else:
        smoke(args.image)
