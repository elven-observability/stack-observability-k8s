"""Local Collector processor code and tests must bind source provenance."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


REPOSITORY = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("elven_images_local_inputs", REPOSITORY / "scripts/images-release.py")
IMAGES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMAGES)


class LocalModuleInputsTests(unittest.TestCase):
    def test_local_processor_source_tests_and_licenses_are_hashed(self):
        with tempfile.TemporaryDirectory(prefix="elven-source-inputs-") as folder:
            root = Path(folder).resolve()
            module = root / "processor/elvenprivacyprocessor"
            module.mkdir(parents=True)
            for name in ("processor.go", "processor_test.go", "go.mod", "go.sum", "LICENSE", "NOTICE", "README.md", "artifact.bin"):
                (module / name).write_text("synthetic input")
            image_dir = root / "images/collector"
            image_dir.mkdir(parents=True)
            (image_dir / "Dockerfile").write_text("FROM scratch")
            (root / "versions.lock.json").write_text("{}")
            image = {"dockerfile": "images/collector/Dockerfile", "sourceBuild": {"localModules": ["processor/elvenprivacyprocessor"]}}
            with mock.patch.object(IMAGES, "ROOT", root):
                files = {str(path.relative_to(root)) for path in IMAGES.build_input_files(image)}
                before = {str(path.relative_to(root)): IMAGES.sha256(path) for path in IMAGES.build_input_files(image)}
                (module / "additional_test.go").write_text("new synthetic input")
                after = {str(path.relative_to(root)): IMAGES.sha256(path) for path in IMAGES.build_input_files(image)}
                self.assertNotEqual(before, after)
                self.assertIn("processor/elvenprivacyprocessor/additional_test.go", after)
            for name in ("processor.go", "processor_test.go", "go.mod", "go.sum", "LICENSE", "NOTICE", "README.md"):
                self.assertIn("processor/elvenprivacyprocessor/" + name, files)
            self.assertNotIn("processor/elvenprivacyprocessor/artifact.bin", files)
            self.assertIn("versions.lock.json", files)

    def test_local_module_cannot_escape_repository(self):
        with tempfile.TemporaryDirectory(prefix="elven-source-boundary-") as folder:
            root = Path(folder).resolve()
            image = {"dockerfile": "images/collector/Dockerfile", "sourceBuild": {"localModules": ["../"]}}
            with mock.patch.object(IMAGES, "ROOT", root), self.assertRaises(ValueError):
                IMAGES.build_input_files(image)

    def test_license_inventory_requires_local_origin_and_all_source_notices(self):
        with tempfile.TemporaryDirectory(prefix="elven-license-origin-") as temporary:
            root = Path(temporary).resolve()
            folder = root / "processor/privacy"
            folder.mkdir(parents=True)
            (folder / "go.mod").write_text("module example.com/elven/privacy\n")
            (folder / "LICENSE").write_text("synthetic license")
            (folder / "NOTICE").write_text("synthetic notice")
            image = {"sourceBuild": {"localModules": ["processor/privacy"]}}
            records = [{"Module": "example.com/elven/privacy", "File": name, "Origin": "elven-source"}
                       for name in ("LICENSE", "NOTICE")]
            with mock.patch.object(IMAGES, "ROOT", root):
                self.assertEqual(IMAGES.verify_local_license_origins(records, image), ["example.com/elven/privacy"])
                with self.assertRaises(ValueError):
                    IMAGES.verify_local_license_origins(records[:1], image)
                records[0]["Origin"] = "checksum-verified-upstream"
                with self.assertRaises(ValueError):
                    IMAGES.verify_local_license_origins(records, image)


if __name__ == "__main__":
    unittest.main()
