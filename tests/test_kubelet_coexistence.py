"""Namespace separation does not isolate node-wide kubelet usage metrics."""
import argparse
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
LOADER = importlib.machinery.SourceFileLoader("elven_kubelet_claims_under_test", str(ROOT / "elven"))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
cli = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(cli)


class KubeletCoexistenceTests(unittest.TestCase):
    def setUp(self):
        self.args = argparse.Namespace(release="elven-new", namespace="elven-new",
                                       allow_overlapping_collection=False)
        self.existing = {"metadata": {"name": "elven-existing-node", "namespace": "elven-existing",
            "labels": {"app.kubernetes.io/instance": "elven-existing", "app.kubernetes.io/component": "node"},
            "annotations": {"elven.observability/source-signals": "logs,kubelet",
                            "elven.observability/collection-namespaces": "elven-app-a"}},
            "spec": {"template": {"spec": {"nodeSelector": {"kubernetes.io/hostname": "elven-node-a"}}}}}
        self.settings = {"modules": {"kubeletMetrics": {"enabled": True}},
            "collection": {"namespaces": ["elven-app-b"]},
            "nodeAgent": {"nodeSelector": {"kubernetes.io/hostname": "elven-node-a"}}}

    def test_kubelet_same_node_with_disjoint_namespaces_is_rejected(self):
        with mock.patch.object(cli, "kube", return_value=json.dumps({"items": [self.existing]})) as kube, \
             self.assertRaisesRegex(cli.Failure, "Kubelet node-wide metrics are not isolated by namespace"):
            cli.check_source_claims(self.args, self.settings)
        kube.assert_called_once()

    def test_logs_only_with_disjoint_namespaces_remain_allowed(self):
        self.settings["modules"] = {"logs": {"enabled": True}}
        with mock.patch.object(cli, "kube", return_value=json.dumps({"items": [self.existing]})) as kube:
            cli.check_source_claims(self.args, self.settings)
        kube.assert_called_once()

    def test_explicit_overlap_acknowledgement_allows_reviewed_node_collection(self):
        self.args.allow_overlapping_collection = True
        with mock.patch.object(cli, "kube") as kube:
            cli.check_source_claims(self.args, self.settings)
        kube.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
