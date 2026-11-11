"""Unit tests for sensitive-path and parameter-name detection."""

import tempfile
import unittest
from pathlib import Path

from engines.sensitive_detection_engine import SensitiveDetectionEngine


class SensitiveDetectionTests(unittest.TestCase):
    def setUp(self):
        self.engine = SensitiveDetectionEngine()

    def categories(self, url):
        return {indicator.category for indicator in self.engine.analyze_url(url)}

    def test_environment_and_git_paths(self):
        self.assertIn("environment_configuration", self.categories("https://example.com/.env"))
        self.assertIn(
            "environment_configuration",
            self.categories("https://example.com/.env.production"),
        )
        self.assertIn("git_exposure", self.categories("https://example.com/.git/config"))
        self.assertIn("git_exposure", self.categories("https://example.com/.git/HEAD"))

    def test_admin_backup_database_logs(self):
        self.assertIn("administrative", self.categories("https://example.com/admin/login"))
        self.assertIn("backups", self.categories("https://example.com/backups/old.zip"))
        self.assertIn("databases", self.categories("https://example.com/dump.sql"))
        self.assertIn("logging", self.categories("https://example.com/debug.log"))

    def test_parameter_names_only(self):
        indicators = self.engine.analyze_url(
            "https://example.com/login?token=SUPERSECRETVALUE&user=bob"
        )
        kinds = {(i.kind, i.value) for i in indicators}
        self.assertIn(("parameter", "token"), kinds)
        self.assertIn(("parameter", "user"), kinds)
        for indicator in indicators:
            self.assertNotIn("SUPERSECRETVALUE", indicator.redacted_url)
            self.assertNotIn("bob", indicator.redacted_url)

    def test_no_substring_auth_false_positive(self):
        self.assertNotIn("authentication", self.categories("https://example.com/author?x=1"))
        self.assertNotIn("authentication", self.categories("https://example.com/oauth-docs"))

    def test_benign_url(self):
        self.assertEqual(self.engine.analyze_url("https://example.com/about-us"), [])

    def test_run_outputs_and_redaction(self):
        urls = [
            "https://example.com/.env",
            "https://example.com/api?api_key=deadbeefcafebabe&page=1",
            "https://example.com/about",
        ]
        result = self.engine.run(urls)
        self.assertGreaterEqual(len(result.interesting_urls), 1)
        self.assertTrue(result.suspicious_paths)
        flattened = " ".join(result.interesting_urls) + " ".join(result.suspicious_paths)
        self.assertNotIn("deadbeefcafebabe", flattened)
        self.assertIn("[REDACTED]", flattened)
        with tempfile.TemporaryDirectory() as tmp:
            self.engine.write_outputs(result, Path(tmp))
            self.assertTrue((Path(tmp) / "suspicious_paths.txt").exists())
            self.assertTrue((Path(tmp) / "sensitive_parameters.txt").exists())
            self.assertTrue((Path(tmp) / "interesting_urls.txt").exists())
            contents = (Path(tmp) / "sensitive_parameters.txt").read_text()
            self.assertNotIn("deadbeefcafebabe", contents)
            self.assertIn("api_key", contents)

    def test_secret_value_redacted_even_with_benign_name(self):
        result = self.engine.run(
            ["https://example.com/x?note=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"]
        )
        joined = " ".join(result.interesting_urls)
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", joined)


if __name__ == "__main__":
    unittest.main()
