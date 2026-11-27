"""Offline negative oracle tests, never evidence that an SDK executed."""
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

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
        runtime = {"java17": "java", "java21": "java", "node22": "node", "python314": "python"}[case]
        server_scope, sql_scope, redis_scope, api_type, redis_type = {
            "java": ("io.opentelemetry.java-http-server", "io.opentelemetry.jdbc", "io.opentelemetry.jedis-4.0",
                     "java.lang.IllegalStateException", "redis.clients.jedis.exceptions.JedisDataException"),
            "node": ("@opentelemetry/instrumentation-http", "@opentelemetry/instrumentation-pg", "@opentelemetry/instrumentation-redis-4", "Error", "Error"),
            "python": ("opentelemetry.instrumentation.flask", "opentelemetry.instrumentation.sqlite3", "opentelemetry.instrumentation.redis", "ValueError", "redis.exceptions.ResponseError"),
        }[runtime]
        message = "checkout failed email=" + ("[REDACTED]" if sanitized else PRIVATE["email"]) + " password=" + (
            "[REDACTED]" if sanitized else PRIVATE["exceptionSecret"]) + " retry=false"
        stack = ("Traceback (most recent call last):\n  File \"/fixture/main.py\", line 55, in exercise\n    fetchPrice()\n"
                 "  File \"/fixture/main.py\", line 42, in fetchPrice\n    raise ValueError(detail)\nValueError: " + message
                 if runtime == "python" else message + "\n at fetchPrice (checkout:42)\n at exercise (checkout:55)")
        exception = {"name": "elven.privacy.exception", "trace_id": "trace", "span_id": "exception", "parent_span_id": "server",
            "status": {"code": "STATUS_CODE_ERROR"}, "attributes": attrs({"http.route": "/exercise", "http.request.method": "GET", "http.response.status_code": 502}),
            "events": [{"name": "exception", "attributes": attrs({"exception.type": api_type,
                "exception.message": message, "exception.stacktrace": stack})}]}
        result[case] = [(server_scope,
                        {"kind": 2, "trace_id": "trace", "span_id": "server"}),
                       (sql_scope,
                        {"kind": 3, "trace_id": "trace", "status": {"code": 2}, "attributes": attrs({"db.query.text": "SELECT ? AS customer_email, ? AS answer"})}),
                       (redis_scope,
                        {"kind": 3, "trace_id": "trace", "name": "SET"}),
                       (redis_scope,
                        {"kind": 3, "trace_id": "trace", "name": "GET"}),
                       (redis_scope,
                        {"kind": 3, "trace_id": "trace", "name": "HGET", "status": {"code": 2, "message": "WRONGTYPE Operation against wrong kind of value"},
                         "events": [{"name": "exception", "attributes": attrs({"exception.type": redis_type,
                            "exception.message": "[REDACTED:redis:WRONGTYPE]" if sanitized else "WRONGTYPE Operation against wrong kind of value"})}]}),
                       ("elven.sdk.privacy.fixture", exception)]
    return result


class ActualSdkPrivacyOracleTests(unittest.TestCase):
    def test_python314_case_enables_only_explicit_python_profile(self):
        self.assertEqual(H.CASES, ("java17", "java21", "node22", "python314"))
        self.assertEqual(H.CASE_RUNTIMES["python314"], "python")
        lab = object.__new__(H.PrivacyLab)
        with mock.patch.object(H.SDK.InstrumentationLab, "operator_values", return_value={
                "runtimes": {"java": True, "nodejs": True, "python": False}}):
            settings = lab.operator_values("https://synthetic.invalid")
        self.assertTrue(settings["runtimes"]["python"])
        pod = {"metadata": {}, "spec": {"containers": [{"env": []}]}}
        with mock.patch.object(H.SDK.InstrumentationLab, "app", return_value=pod):
            self.assertEqual(lab.app("python314", "python314", "python")["metadata"]["annotations"],
                             {"elven.observability/python-platform": "glibc"})

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

    def test_exception_lookalike_scope_is_not_the_real_fixture_api(self):
        data = corpus(True)
        data["java17"][-1] = ("fixture-api", data["java17"][-1][1])
        with self.assertRaisesRegex(AssertionError, "Missing real"):
            H.check_capture(data, PRIVATE, sanitized=True)

    def test_stale_spans_cannot_prove_fresh_capture_after_rollback(self):
        with self.assertRaisesRegex(AssertionError, "Missing SDK"):
            H.check_capture(corpus(True), PRIVATE, sanitized=True,
                            required_traces={case: {"new-trace"} for case in H.CASES})

    def test_python_cannot_fall_back_to_node_or_lookalike_scopes(self):
        for index, wrong in ((0, "@opentelemetry/instrumentation-http"),
                             (1, "opentelemetry.instrumentation.sqlite3-NOT-REAL"),
                             (2, "@opentelemetry/instrumentation-redis-4")):
            data = corpus(True)
            if index == 2:
                for position in (2, 3, 4):
                    data["python314"][position] = (wrong, data["python314"][position][1])
            else:
                data["python314"][index] = (wrong, data["python314"][index][1])
            with self.subTest(scope=wrong), self.assertRaisesRegex(AssertionError, "Missing real"):
                H.check_capture(data, PRIVATE, sanitized=True)
        data = corpus(True)
        data.pop("python314")
        with self.assertRaisesRegex(AssertionError, "Missing SDK spans: python314"):
            H.check_capture(data, PRIVATE, sanitized=True)

    def test_python_exact_exception_types_and_full_traceback_are_required(self):
        for change in ("builtins_type", "header", "tail", "frames", "redis_type"):
            data = corpus(True)
            event = data["python314"][-1][1]["events"][0]
            values = H.attributes(event["attributes"])
            if change == "builtins_type":
                values["exception.type"] = "builtins.ValueError"
            elif change == "header":
                values["exception.stacktrace"] = values["exception.stacktrace"].replace("Traceback (most recent call last):\n", "")
            elif change == "tail":
                values["exception.stacktrace"] = values["exception.stacktrace"].replace("ValueError: ", "OtherError: ")
            elif change == "frames":
                values["exception.stacktrace"] = values["exception.stacktrace"].replace("fetchPrice", "removedFrame")
            else:
                data["python314"][4][1]["events"][0]["attributes"] = attrs({"exception.type": "ResponseError"})
            event["attributes"] = attrs(values)
            with self.subTest(change=change), self.assertRaises(AssertionError):
                H.check_capture(data, PRIVATE, sanitized=True)
        raw = H.check_capture(corpus(False), PRIVATE, sanitized=False)
        data = corpus(True)
        event = data["python314"][-1][1]["events"][0]
        values = H.attributes(event["attributes"])
        values["exception.stacktrace"] = values["exception.stacktrace"].replace("line 42", "line 99")
        event["attributes"] = attrs(values)
        changed = H.check_capture(data, PRIVATE, sanitized=True)
        self.assertNotEqual(raw["python314"]["selectiveDiagnosticDigests"], changed["python314"]["selectiveDiagnosticDigests"])

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
            self.assertTrue(raw[case]["redisExceptionClassDigests"])
            self.assertEqual(raw[case]["redisExceptionClassDigests"], post[case]["redisExceptionClassDigests"])

    def test_redis_exception_class_missing_masked_private_or_changed_cannot_qualify_preservation(self):
        for mutation in ("missing_event", "wrong_event", "missing_type", "masked_type", "private_type", "non_string_type"):
            data = corpus(True)
            span = data["java17"][4][1]
            if mutation == "missing_event":
                span.pop("events")
            elif mutation == "wrong_event":
                span["events"][0]["name"] = "not-exception"
            else:
                values = H.attributes(span["events"][0]["attributes"])
                if mutation == "missing_type":
                    values.pop("exception.type")
                else:
                    values["exception.type"] = {"masked_type": "[REDACTED]", "private_type": PRIVATE["exceptionSecret"], "non_string_type": 42}[mutation]
                span["events"][0]["attributes"] = attrs(values)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(AssertionError, "exception class|private sentinel"):
                H.check_capture(data, PRIVATE, sanitized=True)
        raw = H.check_capture(corpus(False), PRIVATE, sanitized=False)
        changed = corpus(True)
        changed["java17"][4][1]["events"][0]["attributes"] = attrs({"exception.type": "OtherPublicError"})
        post = H.check_capture(changed, PRIVATE, sanitized=True)
        self.assertNotEqual(raw["java17"]["selectiveDiagnosticDigests"], post["java17"]["selectiveDiagnosticDigests"])

    def test_blanket_sql_redaction_does_not_preserve_query_shape(self):
        data = corpus(True)
        data["java17"][1][1]["attributes"] = attrs({"db.query.text": "SELECT [REDACTED]"})
        with self.assertRaisesRegex(AssertionError, "SQL query shape"):
            H.check_capture(data, PRIVATE, sanitized=True)

    def test_redis_error_is_the_real_hget_reply_not_an_unrelated_error_or_duplicate(self):
        for mutation in ("missing_status", "unrelated_error", "lost_context", "duplicate"):
            data = corpus(True)
            if mutation == "missing_status":
                data["java17"][4][1]["status"] = {}
            elif mutation == "unrelated_error":
                data["java17"][4][1]["status"] = {}
                data["java17"].insert(0, ("io.opentelemetry.jedis-4.0", {"kind": 3, "trace_id": "trace", "name": "AUTH", "status": {"code": 2}}))
            elif mutation == "lost_context":
                data["java17"][4][1]["status"] = {"code": 2}
                data["java17"][4][1]["events"][0]["attributes"] = attrs({"exception.type": "redis.clients.jedis.exceptions.JedisDataException"})
            else:
                data["java17"].append(data["java17"][4])
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                H.check_capture(data, PRIVATE, sanitized=True)


if __name__ == "__main__":
    unittest.main()
