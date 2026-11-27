"""Synthetic corpus/assertion regressions, NOT Collector/WAL acceptance.

The manually sanitized fixture is only an oracle for the assertion code. Real
sanitization and disk replay must pass tests/privacy-runtime.py in candidate CI.
"""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("redis_runtime_contract", ROOT / "tests/privacy-runtime.py")
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
PRIVATE_FIELDS = {"db.redis.key", "redis.values", "redis.script", "db.redis.command.args",
                  "exception.message", "exception.stacktrace", "status.description"}


def captured(payloads):
    return P.decode([{"path": "/v1/" + signal, "content_type": "application/x-protobuf",
                      "body": base64.b64encode(message.SerializeToString()).decode()}
                     for signal, message in payloads.items()])


def sanitized_oracle(phase):
    payloads = P.redis_corpus(phase)
    logs = payloads["logs"].resource_logs[0].scope_logs[0].log_records
    spans = payloads["traces"].resource_spans[0].scope_spans[0].spans
    def clean(attrs, operation, error_mask):
        for item in attrs:
            if item.key in PRIVATE_FIELDS:
                item.value.string_value = error_mask if item.key in ("exception.message", "status.description") else "[REDACTED]"
            elif item.key in {"db.query.text", "db.operation.name", "redis.command"}:
                item.value.string_value = operation
    for (case, (_, operation)), record, span in zip(P.redis_cases().items(), logs, spans):
        error_mask = "[REDACTED:redis:WRONGTYPE]" if case.startswith("wrongtype") else "[REDACTED]"
        clean(record.attributes, operation, error_mask)
        clean(span.attributes, operation, error_mask)
        clean(span.events[0].attributes, operation, error_mask)
        span.name, span.status.message = operation, error_mask
        if record.body.WhichOneof("value") == "string_value":
            body = json.loads(record.body.string_value)
            for key in PRIVATE_FIELDS:
                if key in body:
                    body[key] = error_mask if key in ("exception.message", "status.description") else "[REDACTED]"
            for key in ("db.query.text", "db.operation.name", "redis.command"):
                if key in body:
                    body[key] = operation
            record.body.string_value = json.dumps(body)
        else:
            clean(record.body.kvlist_value.values, operation, error_mask)
    point = payloads["metrics"].resource_metrics[0].scope_metrics[0].metrics[0].gauge.data_points[0]
    for item in [*point.attributes, *point.exemplars[0].filtered_attributes]:
        item.value.string_value = "[REDACTED]"
    return captured(payloads)


def span(decoded):
    return decoded["traces"][0].resource_spans[0].scope_spans[0].spans[0]


def log(decoded):
    return P.records(decoded)[0]


def point(decoded):
    return decoded["metrics"][0].resource_metrics[0].scope_metrics[0].metrics[0].gauge.data_points[0]


class RedisRuntimeContract(unittest.TestCase):
    def test_raw_inputs_really_contain_private_data_and_never_pass_assertions(self):
        for phase in ("export", "wal"):
            raw = captured(P.redis_corpus(phase))
            text = P.serialized(raw)
            for private in P.REDIS_PRIVATE.values():
                self.assertIn(private, text)
            self.assertTrue(P.redis_complete(raw, phase))
            with self.assertRaisesRegex(AssertionError, "sentinel"):
                P.assert_redis_corpus(raw, phase)
        with self.assertRaises(ValueError):
            P.redis_corpus("production")

    def test_assertion_oracle_roundtrip_preserves_every_case_and_three_signals(self):
        for phase in ("export", "wal"):
            decoded = sanitized_oracle(phase)
            self.assertTrue(P.redis_complete(decoded, phase))
            result = P.assert_redis_corpus(decoded, phase)
            self.assertEqual(result["logs"], 8)
            self.assertEqual(result["spans"], 8)
            self.assertEqual(result["metric_points"], 1)
        self.assertNotEqual(P.redis_identity("export"), P.redis_identity("wal"))

    def test_leaks_lossy_redaction_missing_records_and_broken_correlation_fail(self):
        good = sanitized_oracle("export")
        edits = (
            lambda d: setattr(span(d), "name", P.REDIS_PRIVATE["key"]),
            lambda d: setattr(span(d), "parent_span_id", b"BADID123"),
            lambda d: setattr(span(d).status, "code", 1),
            lambda d: setattr(log(d), "trace_id", b"BADTRACE12345678"),
            lambda d: setattr(log(d).body, "string_value", "[REDACTED]"),
            lambda d: setattr(log(d), "severity_number", 9),
            lambda d: span(d).ClearField("events"),
            lambda d: setattr(point(d).exemplars[0], "as_double", 999),
            lambda d: setattr(point(d).exemplars[0], "span_id", b"BADID123"),
            lambda d: span(d).attributes.__delitem__(next(i for i, a in enumerate(span(d).attributes)
                                                        if a.key == "db.operation.name")),
            lambda d: d.update(traces=[]),
            lambda d: d.update(metrics=[]),
            lambda d: d.update(logs=[]),
        )
        for edit in edits:
            with self.subTest(edit=edit):
                changed = copy.deepcopy(good); edit(changed)
                with self.assertRaises(AssertionError):
                    P.assert_redis_corpus(changed, "export")
        missing = copy.deepcopy(good)
        del missing["logs"][0].resource_logs[0].scope_logs[0].log_records[-1]
        self.assertFalse(P.redis_complete(missing, "export"))
        with self.assertRaises(AssertionError):
            P.assert_redis_corpus(missing, "export")

    def test_raw_wal_scan_requires_all_signal_markers_and_absence_of_secrets(self):
        markers = ["elven redis log wal cache operation failed status=503", "elven redis trace wal",
                   "elven.redis.synthetic.wal.duration", "[REDACTED:redis:WRONGTYPE]"]
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            queue = root / "synthetic-queue.bin"
            queue.write_bytes(("[REDACTED] " + " ".join(markers)).encode())
            with mock.patch.object(P, "Path", return_value=root):
                result = P.action({"op": "wal", "forbidden": P.FORBIDDEN, "required_markers": markers})
            P.assert_redis_wal(result)
            for edit in (lambda r: r.update(files=[]), lambda r: r.update(redaction_markers=0),
                         lambda r: r.update(required_markers={}),
                         lambda r: r.update(forbidden_matches=[P.REDIS_PRIVATE["key"]])):
                bad = copy.deepcopy(result); edit(bad)
                with self.assertRaises(AssertionError):
                    P.assert_redis_wal(bad)
            queue.write_bytes(P.REDIS_PRIVATE["script"].encode())
            with mock.patch.object(P, "Path", return_value=root):
                result = P.action({"op": "wal", "forbidden": P.FORBIDDEN, "required_markers": markers})
            self.assertIn(P.REDIS_PRIVATE["script"], result["forbidden_matches"])
            with self.assertRaises(AssertionError):
                P.assert_redis_wal(result)

    def test_finite_error_code_must_survive_without_the_echoed_operand(self):
        decoded = sanitized_oracle("export")
        spans = decoded["traces"][0].resource_spans[0].scope_spans[0].spans
        target = next(s for s in spans if P.case_of(s) == "redis-export-wrongtype")
        target.status.message = "[REDACTED]"
        with self.assertRaisesRegex(AssertionError, "operation/error"):
            P.assert_redis_corpus(decoded, "export")

    def test_real_runtime_gate_is_mandatory_before_overall_pass(self):
        source = (ROOT / "tests/privacy-runtime.py").read_text()
        self.assertLess(source.index('evidence["checks"].extend(redis_runtime_checks('),
                        source.index('evidence["checks_passed"] = True'))
        self.assertIn('run("docker", "stop", "--time", "5", selective', source)
        self.assertIn('assert_redis_wal(wal)', source)


if __name__ == "__main__":
    unittest.main()
