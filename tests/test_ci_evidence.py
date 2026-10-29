"""Evidence must actually upload, without broadening uploads to private fixtures."""
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]


class EvidenceUploadTests(unittest.TestCase):
    def hidden_uploads(self):
        for file in (ROOT / ".github/workflows").glob("*.yaml"):
            workflow = yaml.safe_load(file.read_text())
            for job in workflow.get("jobs", {}).values():
                for step in job.get("steps", []):
                    if not step.get("uses", "").startswith("actions/upload-artifact@"):
                        continue
                    options = step.get("with", {})
                    paths = options.get("path", "")
                    if ".artifacts/" in paths:
                        yield file.name, options

    def test_hidden_report_directories_are_explicitly_included(self):
        uploads = list(self.hidden_uploads())
        self.assertGreaterEqual(len(uploads), 3)
        for file, options in uploads:
            with self.subTest(workflow=file, artifact=options.get("name")):
                self.assertIs(options.get("include-hidden-files"), True)

    def test_including_hidden_files_does_not_upload_keys_or_kubeconfigs(self):
        for file, options in self.hidden_uploads():
            for path in options["path"].splitlines():
                with self.subTest(workflow=file, path=path):
                    self.assertTrue(path.endswith(("/report.json", "/diagnostics.txt")))
                    self.assertNotIn("**", path)
                    self.assertNotIn("kubeconfig", path)
                    self.assertNotIn(".key", path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
