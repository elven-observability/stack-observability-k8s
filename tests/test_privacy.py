"""Privacy chart contracts; real data-path checks live in privacy-runtime.py.

These tests inspect synthetic Helm output only. A render is not evidence that a
processor executes successfully or that an arbitrary source is free of PII.
"""
from __future__ import annotations

import unittest

import yaml

from test_chart import DEFAULTS, all_modules, objects, render


def gateway_config(values=None):
    config = next(obj for obj in objects(values)
                  if obj["kind"] == "ConfigMap"
                  and obj["metadata"]["name"].endswith("-gateway"))
    return yaml.safe_load(config["data"]["collector.yaml"])


class PrivacyChartTests(unittest.TestCase):
    def test_selective_masking_is_the_default_not_whole_body_redaction(self):
        self.assertEqual(DEFAULTS["privacy"]["logBodyMode"], "selective")
        privacy = gateway_config()["processors"]["elven_privacy"]
        self.assertEqual(privacy["log_body_mode"], "selective")
        self.assertEqual(privacy["max_depth"], 24)
        self.assertEqual(privacy["max_string_bytes"], 262144)
        self.assertEqual(privacy["max_collection_items"], 4096)

    def test_strict_body_redaction_remains_an_explicit_profile(self):
        privacy = gateway_config({"privacy": {"logBodyMode": "strict"}})["processors"]["elven_privacy"]
        self.assertEqual(privacy["log_body_mode"], "strict")

    def test_legacy_redact_mode_maps_to_recursive_selective_masking(self):
        privacy = gateway_config({"privacy": {"logBodyMode": "redact"}})["processors"]["elven_privacy"]
        self.assertEqual(privacy["log_body_mode"], "selective")

    def test_every_signal_is_sanitized_before_its_persistent_export_queue(self):
        config = gateway_config()
        for signal in ("logs", "metrics", "traces"):
            with self.subTest(signal=signal):
                pipeline = config["service"]["pipelines"][signal]
                self.assertEqual(pipeline["processors"][:3],
                                 ["memory_limiter", "resource/identity", "elven_privacy"])
                self.assertEqual(pipeline["processors"].count("elven_privacy"), 1)
                for exporter_name in pipeline["exporters"]:
                    exporter = config["exporters"][exporter_name]
                    self.assertEqual(exporter["sending_queue"]["storage"], "file_storage/exports")
                self.assertFalse(any(name.startswith("batch") for name in pipeline["processors"]))

    def test_link_ids_are_preserved_by_default_but_attributes_are_always_sanitized(self):
        for approved in (False, True):
            with self.subTest(legacy_approval=approved):
                privacy = gateway_config({"privacy": {"spanLinkAttributesApproved": approved}})["processors"]["elven_privacy"]
                self.assertTrue(privacy["preserve_span_links"])
                self.assertNotIn("span_link_attributes_approved", privacy)
        privacy = gateway_config({"privacy": {"preserveSpanLinks": False}})["processors"]["elven_privacy"]
        self.assertFalse(privacy["preserve_span_links"])

    def test_old_lossy_top_level_only_transform_is_not_a_fallback(self):
        config = gateway_config()
        self.assertNotIn("transform/privacy", config["processors"])
        rendered = render().stdout
        self.assertNotIn("set(name, \"operation\")", rendered)
        self.assertNotIn("set(body, \"[REDACTED]\")", rendered)
        self.assertNotIn("error_mode: ignore", rendered)

    def test_metric_label_cardinality_control_follows_sanitization(self):
        config = gateway_config()
        processors = config["service"]["pipelines"]["metrics"]["processors"]
        self.assertLess(processors.index("elven_privacy"), processors.index("transform/cardinality"))
        cardinality = config["processors"]["transform/cardinality"]
        self.assertEqual(cardinality["error_mode"], "propagate")
        statements = cardinality["metric_statements"]
        self.assertEqual(len(statements), 1)
        self.assertEqual(statements[0]["context"], "datapoint")
        self.assertTrue(all(statement.startswith("keep_keys(attributes,")
                            for statement in statements[0]["statements"]))
        for signal in ("logs", "traces"):
            self.assertNotIn("transform/cardinality", config["service"]["pipelines"][signal]["processors"])

    def test_source_log_collector_uses_the_same_recursive_policy_as_gateway(self):
        rendered = objects(all_modules())
        node = next(obj for obj in rendered if obj["kind"] == "ConfigMap"
                    and obj["metadata"]["name"].endswith("-node"))
        config = yaml.safe_load(node["data"]["collector.yaml"])
        self.assertEqual(config["processors"]["elven_privacy"],
                         gateway_config()["processors"]["elven_privacy"])
        self.assertNotIn("transform/log_privacy", config["processors"])
        self.assertEqual(config["service"]["pipelines"]["logs"]["processors"],
                         ["memory_limiter", "resource/identity", "elven_privacy"])
        self.assertFalse(config["exporters"]["otlp_http/gateway"]["sending_queue"]["enabled"])

    def test_json_severity_copy_is_removed_without_discarding_the_useful_body(self):
        node = next(obj for obj in objects(all_modules()) if obj["kind"] == "ConfigMap"
                    and obj["metadata"]["name"].endswith("-node"))
        config = yaml.safe_load(node["data"]["collector.yaml"])
        operators = config["receivers"]["file_log/containers"]["operators"]
        remove_index = next(index for index, operator in enumerate(operators)
                            if operator.get("id") == "remove_temporary_application")
        remove = operators[remove_index]
        self.assertEqual(remove["type"], "remove")
        self.assertEqual(remove["field"], "attributes.application")
        self.assertEqual(remove["if"], "attributes.application != nil")
        for index, operator in enumerate(operators):
            if operator["type"] == "severity_parser":
                self.assertLess(index, remove_index)
            self.assertFalse(operator["type"] == "remove" and operator.get("field") == "body")

    def test_invalid_privacy_budgets_are_rejected_before_installation(self):
        for settings in (
            {"logBodyMode": "off"},
            {"maxDepth": 0}, {"maxDepth": 25},
            {"maxStringBytes": 255}, {"maxStringBytes": 1048577},
            {"maxCollectionItems": 0}, {"maxCollectionItems": 16385},
            {"maxDepth": "32"}, {"allowRawFallback": True},
        ):
            with self.subTest(settings=settings):
                result = render({"privacy": settings}, check=False)
                self.assertNotEqual(result.returncode, 0)

    def test_reviewed_privacy_bounds_render_without_untrusted_ottl_injection(self):
        settings = {"maxDepth": 16, "maxStringBytes": 4096, "maxCollectionItems": 128}
        privacy = gateway_config({"privacy": settings})["processors"]["elven_privacy"]
        self.assertEqual(privacy["max_depth"], 16)
        self.assertEqual(privacy["max_string_bytes"], 4096)
        self.assertEqual(privacy["max_collection_items"], 128)
        self.assertEqual(set(privacy), {"log_body_mode", "preserve_span_links", "max_depth",
                                       "max_string_bytes", "max_collection_items"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
