"""Offline negative oracle tests, never evidence that an SDK executed."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("sdk_privacy_lab_test", ROOT / "scripts/test-sdk-privacy-kind.py")
H = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(H)
PRIVATE = {"email": "person@example.invalid", "exceptionSecret": "SYNTHETIC_PRIVATE_VALUE",
           "forbidden": ["person@example.invalid", "SYNTHETIC_PRIVATE_VALUE"]}


def attrs(values):
    return [{"key": key, "value": {"int_value" if isinstance(value, int) else "string_value": value}}
            for key, value in values.items()]


def corpus(sanitized):
    result = {}
    for case in H.CASES:
        java = case.startswith("java")
        message = "checkout failed email=" + ("[REDACTED]" if sanitized else PRIVATE["email"]) + " password=" + (
            "[REDACTED]" if sanitized else PRIVATE["exceptionSecret"]) + " retry=false"
        exception = {"name": "elven.privacy.exception", "trace_id": "trace", "span_id": "exception", "parent_span_id": "server",
            "status": {"code": "STATUS_CODE_ERROR"}, "attributes": attrs({"http.route": "/exercise", "http.request.method": "GET", "http.response.status_code": 502}),
            "events": [{"name": "exception", "attributes": attrs({"exception.type": "java.lang.IllegalStateException" if java else "Error",
                "exception.message": message, "exception.stacktrace": message + "\n at fetchPrice (checkout:42)\n at exercise (checkout:55)"})}]}
        result[case] = [("io.opentelemetry.java-http-server" if java else "@opentelemetry/instrumentation-http",
                        {"kind": 2, "trace_id": "trace", "span_id": "server"}),
                       ("io.opentelemetry.jdbc" if java else "@opentelemetry/instrumentation-pg",
                        {"kind": 3, "trace_id": "trace", "status": {"code": 2}, "attributes": attrs({"db.query.text": "SELECT ? AS answer"})}),
                       ("io.opentelemetry.jedis-1.4" if java else "@opentelemetry/instrumentation-redis-4",
                        {"kind": 3, "trace_id": "trace", "status": {"code": 2}, "name": "SET"}),
                       ("io.opentelemetry.jedis-1.4" if java else "@opentelemetry/instrumentation-redis-4",
                        {"kind": 3, "trace_id": "trace", "name": "GET"}), ("fixture-api", exception)]
    return result


class ActualSdkPrivacyOracleTests(unittest.TestCase):
    def test_raw_control_requires_known_values_and_sanitized_requires_selective_diagnostics(self):
        H.check_capture(corpus(False), PRIVATE, sanitized=False)
        H.check_capture(corpus(True), PRIVATE, sanitized=True)
        with self.assertRaisesRegex(AssertionError, "positive control"):
            H.check_capture(corpus(True), PRIVATE, sanitized=False)
        with self.assertRaisesRegex(AssertionError, "private sentinel"):
            H.check_capture(corpus(False), PRIVATE, sanitized=True)

    def test_missing_auto_db_spans_type_frames_http_or_correlation_never_pass(self):
        for mutation in ("redis", "sql", "type", "frames", "http", "parent", "blanket"):
            with self.subTest(mutation=mutation):
                data = corpus(True)
                exception = data["node22"][-1][1]
                if mutation == "redis":
                    data["node22"] = [item for item in data["node22"] if "redis" not in item[0]]
                elif mutation == "sql":
                    data["node22"] = [item for item in data["node22"] if "instrumentation-pg" not in item[0]]
                elif mutation == "parent":
                    exception["parent_span_id"] = "unrelated"
                elif mutation == "http":
                    exception["attributes"] = []
                else:
                    event = exception["events"][0]
                    values = H.attributes(event["attributes"])
                    values[{"type": "exception.type", "frames": "exception.stacktrace", "blanket": "exception.message"}[mutation]] = "[REDACTED]"
                    event["attributes"] = attrs(values)
                with self.assertRaises(AssertionError):
                    H.check_capture(data, PRIVATE, sanitized=True)

    def test_lookalike_or_custom_db_scope_does_not_prove_auto_instrumentation(self):
        data = corpus(True)
        data["java17"][1] = ("io.opentelemetry.jdbc-NOT-REAL", data["java17"][1][1])
        with self.assertRaisesRegex(AssertionError, "Missing real"):
            H.check_capture(data, PRIVATE, sanitized=True)

    def test_stale_spans_cannot_prove_fresh_capture_after_rollback(self):
        with self.assertRaisesRegex(AssertionError, "Missing SDK"):
            H.check_capture(corpus(True), PRIVATE, sanitized=True,
                            required_traces={case: {"new-trace"} for case in H.CASES})

    def test_redis_lookalike_is_not_two_distinct_commands(self):
        for command in ("GETSET", "MGET", "SETEX"):
            data = corpus(True)
            data["node22"][3][1]["name"] = command
            with self.assertRaisesRegex(AssertionError, "SET/GET"):
                H.check_capture(data, PRIVATE, sanitized=True)

    def test_raw_and_post_diagnostic_hashes_match_only_selective_full_preservation(self):
        raw = H.check_capture(corpus(False), PRIVATE, sanitized=False)
        post = H.check_capture(corpus(True), PRIVATE, sanitized=True)
        for case in H.CASES:
            self.assertEqual(raw[case]["selectiveDiagnosticDigests"], post[case]["selectiveDiagnosticDigests"])


if __name__ == "__main__":
    unittest.main()
