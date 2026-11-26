"""Candidate ZIPs cannot silently become ordinary customer installers."""
import argparse
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load(name, file):
    loader = importlib.machinery.SourceFileLoader(name, str(file))
    spec = importlib.util.spec_from_loader(name, loader)
    result = importlib.util.module_from_spec(spec)
    loader.exec_module(result)
    return result


class CandidateRuntimePolicy(unittest.TestCase):
    def test_marker_blocks_online_before_programs_or_kube_even_with_client_context(self):
        for name, file, programs in (("core_policy", ROOT / "elven", "required_programs"),
                                     ("sdk_policy", ROOT / "scripts/instrumentation.py", "programs")):
            module = load(name, file)
            with self.subTest(cli=name), tempfile.TemporaryDirectory() as folder:
                path = Path(folder); (path / "LAB-ONLY.txt").write_text("ELVEN LAB ONLY")
                with mock.patch.object(module, "ROOT", path), mock.patch.dict(os.environ, {}, clear=True), \
                     mock.patch.object(module, programs) as external:
                    with self.assertRaisesRegex(module.Failure, "laboratory candidate"):
                        module.main(["install", "--context", "never-use-client"])
                    external.assert_not_called()
                    args = argparse.Namespace(command="install", development_images=True)
                    for env in ({}, {"GITHUB_ACTIONS": "true"}, {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"}):
                        with mock.patch.dict(os.environ, env, clear=True), self.assertRaises(module.Failure):
                            module.require_candidate_lab(args)
                    with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}, clear=True):
                        module.require_candidate_lab(args)
                    module.require_candidate_lab(argparse.Namespace(command="render", development_images=False))

    def test_normal_source_without_marker_keeps_existing_image_and_identity_gates(self):
        for name, file in (("normal_core", ROOT / "elven"), ("normal_sdk", ROOT / "scripts/instrumentation.py")):
            module = load(name, file)
            with tempfile.TemporaryDirectory() as folder, mock.patch.object(module, "ROOT", Path(folder)):
                module.require_candidate_lab(argparse.Namespace(command="install", development_images=False))
