"""Assertion-oracle tests only: NOT compiled Collector or SDK acceptance."""
import base64
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("exception_runtime_contract", ROOT / "tests/privacy-runtime.py")
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


def capture(payloads):
    return P.decode([{"path": "/v1/" + signal, "content_type": "application/x-protobuf",
                      "body": base64.b64encode(message.SerializeToString()).decode()}
                     for signal, message in payloads.items()])


def oracle():
    """Manual expectations test the assertions, never count as sanitization."""
    from google.protobuf.json_format import MessageToJson, Parse
    payloads = P.exception_corpus()
    for payload in payloads.values():
        text = MessageToJson(payload).replace(P.EXCEPTION_EMAIL, "[REDACTED]").replace(P.EXCEPTION_SECRET, "[REDACTED]")
        Parse(text, payload)
    return capture(payloads)


def first_span(decoded):
    return decoded["traces"][0].resource_spans[0].scope_spans[0].spans[0]


def change_attr(items, name, value):
    next(item.value for item in items if item.key == name).string_value = value


class ExceptionRuntimeContract(unittest.TestCase):
    def test_raw_fixture_contains_private_values_and_cannot_pass(self):
        decoded = capture(P.exception_corpus())
        self.assertTrue(P.exception_complete(decoded))
        for value in (P.EXCEPTION_EMAIL, P.EXCEPTION_SECRET):
            self.assertIn(value, P.serialized(decoded))
        with self.assertRaisesRegex(AssertionError, "private"):
            P.assert_exception_corpus(decoded)

    def test_oracle_preserves_all_language_shapes_without_claiming_sdk_acceptance(self):
        decoded = oracle()
        result = P.assert_exception_corpus(decoded)
        self.assertEqual(result["cases"], ["java", "nodejs", "python"])
        self.assertFalse(result["sdk_runtime_execution_qualified"])
        self.assertEqual(len(P.records(decoded)), 3)

    def test_missing_case_leaks_blanket_redaction_and_context_loss_fail(self):
        mutations = (
            lambda d: change_attr(first_span(d).events[0].attributes, "exception.message", P.EXCEPTION_EMAIL),
            lambda d: change_attr(first_span(d).events[0].attributes, "exception.message", "[REDACTED]"),
            lambda d: change_attr(first_span(d).events[0].attributes, "exception.stacktrace", "[REDACTED]"),
            lambda d: change_attr(first_span(d).attributes, "exception.type", "[REDACTED]"),
            lambda d: change_attr(first_span(d).attributes, "http.request.method", "[REDACTED]"),
            lambda d: setattr(first_span(d).status, "code", 1),
            lambda d: setattr(first_span(d).status, "message", "[REDACTED]"),
            lambda d: setattr(first_span(d), "parent_span_id", b"BADID123"),
            lambda d: first_span(d).ClearField("events"),
            lambda d: setattr(P.records(d)[0], "trace_id", b"BADTRACE12345678"),
            lambda d: setattr(P.records(d)[0].body, "string_value", "[REDACTED]"),
            lambda d: setattr(P.records(d)[0], "severity_number", 9),
            lambda d: d.update(logs=[]),
            lambda d: d.update(traces=[]),
        )
        good = oracle()
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                decoded = copy.deepcopy(good)
                mutate(decoded)
                with self.assertRaises(AssertionError):
                    P.assert_exception_corpus(decoded)
        decoded = oracle()
        del decoded["logs"][0].resource_logs[0].scope_logs[0].log_records[-1]
        self.assertFalse(P.exception_complete(decoded))
        with self.assertRaisesRegex(AssertionError, "missing"):
            P.assert_exception_corpus(decoded)

    def test_runtime_gate_is_mandatory_and_not_using_manual_oracle(self):
        source = (ROOT / "tests/privacy-runtime.py").read_text()
        self.assertLess(source.index('evidence["checks"].extend(exception_runtime_checks('),
                        source.index('evidence["checks_passed"] = True'))
        self.assertNotIn("oracle(", source.split("def exception_runtime_checks", 1)[1].split("def redis_cases", 1)[0])
        self.assertIn('"evidence_boundary": "compiled_collector_https_export"', source)

    def test_runner_rejects_unsanitized_wire_instead_of_returning_pass(self):
        accepted = []
        def send(signal, message):
            accepted.append({"path": "/v1/" + signal, "content_type": "application/x-protobuf",
                             "body": base64.b64encode(message.SerializeToString()).decode()})
        def wait_for(predicate, description):
            self.assertTrue(predicate(), description)
        with self.assertRaisesRegex(AssertionError, "private"):
            P.exception_runtime_checks(send, lambda: {"accepted": accepted}, wait_for)


if __name__ == "__main__":
    unittest.main()
