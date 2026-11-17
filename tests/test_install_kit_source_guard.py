"""Build-tag source never downgrades a customer into an older public kit."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("elven_kit_source_guard", ROOT / "kit/plataforma/instalar.py")
B = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B)


class KitSourceGuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "elven").touch()
        self.bootstrap = self.root / "kit/plataforma/instalar.py"

    def source(self, status, version):
        (self.root / "versions.lock.json").write_text(json.dumps({"distribution": {"publicationStatus": status, "version": version}}))

    def test_unpromoted_source_refuses_before_any_old_release_download(self):
        self.source("not-published", B.VERSION)
        with patch.object(B, "__file__", str(self.bootstrap)), self.assertRaisesRegex(B.Refusa, "fonte de build"):
            B.conferir_fonte_checkout()

    def test_verified_but_different_version_cannot_silently_install_old_kit(self):
        self.source("verified", "1.999.999")
        with patch.object(B, "__file__", str(self.bootstrap)), self.assertRaises(B.Refusa):
            B.conferir_fonte_checkout()

    def test_matching_promoted_checkout_is_allowed(self):
        self.source("verified", B.VERSION)
        with patch.object(B, "__file__", str(self.bootstrap)):
            B.conferir_fonte_checkout()

    def test_public_zip_does_not_depend_on_any_adjacent_repository_lock(self):
        with patch.object(B, "__file__", str(self.root / "elven-instalacao-v1.0.1/plataforma/instalar.py")), patch.object(B, "ler_limite") as read:
            B.conferir_fonte_checkout()
        read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
