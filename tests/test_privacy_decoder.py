"""Receiver DoS rejection and processor redaction are separate contracts."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("elven_privacy_decoder_fixture", ROOT / "tests/privacy-runtime.py")
PRIVACY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PRIVACY)


def nested_maps(value):
    depth = 0
    while value.WhichOneof("value") == "kvlist_value":
        children = [item.value for item in value.kvlist_value.values if item.key == "nested"]
        if not children:
            break
        value = children[0]
        depth += 1
    return depth


class PrivacyDecoderTests(unittest.TestCase):
    def test_redaction_depth_still_exceeds_processor_budget_without_attacking_decoder(self):
        logs = PRIVACY.corpus()["logs"].resource_logs[0].scope_logs[0].log_records
        record = next(item for item in logs if any(attribute.key == "privacy.test.case" and attribute.value.string_value == "depth"
                                                  for attribute in item.attributes))
        self.assertEqual(nested_maps(record.body), 28)
        self.assertGreater(nested_maps(record.body), 24)
        self.assertLess(3 * nested_maps(record.body) + 10, 100)

    def test_hostile_depth_is_in_a_separate_request_and_its_sentinel_cannot_be_exported(self):
        attack = PRIVACY.recursion_attack_payload()
        records = attack.resource_logs[0].scope_logs[0].log_records
        self.assertEqual(len(records), 1)
        self.assertEqual(nested_maps(records[0].body), 40)
        self.assertIn("RECURSION_LIMIT_SECRET_SENTINEL", PRIVACY.FORBIDDEN)
        source = (ROOT / "tests/privacy-runtime.py").read_text()
        self.assertIn('recursion_attack_payload(), expected_status=400', source)
        self.assertIn('"recursion depth" not in excessive.get', source)


if __name__ == "__main__":
    unittest.main()
