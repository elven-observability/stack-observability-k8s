#!/usr/bin/env python3
"""Send three synthetic OTLP signals through verified mTLS; never use client data."""
import argparse
import http.client
import ipaddress
import json
from pathlib import Path
import secrets
import socket
import ssl
import sys
import time
from urllib.parse import urlsplit


def payloads():
    trace_id, span_id = secrets.token_hex(16), secrets.token_hex(8)
    now = str(time.time_ns())
    resource = {"attributes": [{"key": "service.name", "value": {"stringValue": "elven-probe"}}]}
    return trace_id, {
        "logs": {"resourceLogs": [{"resource": resource, "scopeLogs": [{"logRecords": [{
            "timeUnixNano": now, "body": {"stringValue": "Elven synthetic verification; no customer payload"},
            "severityNumber": 9, "traceId": trace_id, "spanId": span_id}]}]}]},
        "metrics": {"resourceMetrics": [{"resource": resource, "scopeMetrics": [{"metrics": [{
            "name": "elven_probe_gauge", "gauge": {"dataPoints": [{"timeUnixNano": now, "asDouble": 1.0}]}}]}]}]},
        "traces": {"resourceSpans": [{"resource": resource, "scopeSpans": [{"spans": [{
            "traceId": trace_id, "spanId": span_id, "name": "elven-synthetic-probe", "kind": 2,
            "startTimeUnixNano": now, "endTimeUnixNano": str(int(now) + 1_000_000), "status": {"code": 1}}]}]}]},
    }


class VerifiedConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, context, connect_address=None):
        super().__init__(host, port=port, context=context, timeout=10)
        self.connect_address = connect_address

    def connect(self):
        # Port forwarding changes only the TCP route, NEVER the certificate
        # hostname/SNI. There is deliberately no insecure/skip-verify option.
        target = self.connect_address or (self.host, self.port)
        sock = socket.create_connection(target, timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise


def probe(endpoint, ca_file, cert_file, key_file, connect_address=None):
    parsed = urlsplit(endpoint)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in ("", "/")):
        raise ValueError("Use an HTTPS gateway base URL without credentials, query, fragment or path.")
    if Path(key_file).stat().st_mode & 0o077:
        raise ValueError("Client private key must have mode 0600 or 0400.")
    route = None
    if connect_address:
        # Only loopback TCP forwarding; this flag cannot redirect mTLS to an
        # arbitrary Internet host while hiding that route from the operator.
        address, port = connect_address.rsplit(":", 1)
        if not ipaddress.ip_address(address).is_loopback or not 1 <= int(port) <= 65535:
            raise ValueError("--connect-address must be a loopback address and port.")
        route = (address, int(port))
    context = ssl.create_default_context(cafile=str(ca_file))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(cert_file), str(key_file))
    trace_id, signals = payloads()
    accepted = []
    for signal, payload in signals.items():
        connection = VerifiedConnection(parsed.hostname, parsed.port or 443, context, route)
        try:
            connection.request("POST", f"/v1/{signal}", json.dumps(payload).encode(),
                               {"Content-Type": "application/json", "Accept": "application/json"})
            response = connection.getresponse()
            raw = response.read(65536)
            if not 200 <= response.status < 300:
                raise ValueError(f"Gateway rejected synthetic {signal} with HTTP {response.status}.")
            if raw:
                result = json.loads(raw)
                partial = result.get("partialSuccess", {})
                if any(int(partial.get(key, 0)) for key in ("rejectedLogRecords", "rejectedDataPoints", "rejectedSpans")):
                    raise ValueError(f"Gateway partially rejected synthetic {signal}; inspect local counters.")
            accepted.append(signal)
        finally:
            connection.close()
    return {"gateway_accepted": accepted, "service_name": "elven-probe", "trace_id": trace_id,
            "metric_name": "elven_probe_gauge", "backend_delivery": "NOT_VERIFIED",
            "next_step": "Confirm this trace ID and correlated log/metric in the correct Elven tenant."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--cert-file", required=True)
    parser.add_argument("--key-file", required=True)
    parser.add_argument("--connect-address", help="Optional loopback port-forward route, e.g. 127.0.0.1:14318")
    args = parser.parse_args()
    try:
        result = probe(args.endpoint, args.ca_file, args.cert_file, args.key_file, args.connect_address)
    except (OSError, ssl.SSLError, ValueError, http.client.HTTPException):
        print("Probe failed: check HTTPS/mTLS identity, key permissions, gateway response and connectivity locally. No response bodies or key material were printed.", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
