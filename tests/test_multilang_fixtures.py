"""Public source/recipe contracts, not builds or proofs of runtime coverage."""
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

SOURCE = Path(__file__).resolve().parent / "instrumentation-fixtures/multilang"


class MultilangFixtures(unittest.TestCase):
    def test_all_runtime_bases_are_immutable_and_final_users_are_nonroot(self):
        for runtime in ("go", "dotnet", "php"):
            recipe = (SOURCE / ("Dockerfile." + runtime)).read_text()
            bases = re.findall(r"^FROM (\S+)", recipe, re.M)
            self.assertTrue(bases)
            for base in bases:
                self.assertRegex(base, r"^[a-z0-9./:-]+@sha256:[a-f0-9]{64}$")
                self.assertNotIn(":latest", base)
            self.assertIn("USER 10001:10001", recipe)

    def test_sources_have_no_embedded_sdk_or_credential_and_expose_only_synthetic_paths(self):
        for file in ("app.go", "Program.cs", "app.php"):
            source = (SOURCE / file).read_text()
            self.assertIn("/ready", source)
            self.assertIn("/exercise", source)
            self.assertIn("synthetic-customer@example.invalid", source)
            self.assertNotIn("opentelemetry", source.lower())
            self.assertNotIn("api-token", source.lower())
            self.assertNotIn("Bearer ", source)

    def test_dotnet_is_lts_and_restore_has_no_remote_dependency_source(self):
        project = ET.parse(SOURCE / "dotnet.csproj").getroot()
        self.assertEqual(project.findtext("PropertyGroup/TargetFramework"), "net10.0")
        self.assertEqual(project.findall(".//PackageReference"), [])
        config = ET.parse(SOURCE / "NuGet.Config").getroot()
        self.assertIsNotNone(config.find("packageSources/clear"))
        self.assertEqual(config.findall("packageSources/add"), [])

    def test_php_refuses_the_unpatched_pre_october_security_floor(self):
        self.assertIn("PHP_VERSION_ID<80512", (SOURCE / "app.php").read_text())
        self.assertIn("PHP_VERSION_ID < 80512", (SOURCE / "Dockerfile.php").read_text())


if __name__ == "__main__":
    unittest.main()
