"""Unit tests for the URL filtering / classification engine."""

import tempfile
import unittest
from pathlib import Path

from engines.url_filter_engine import REQUIRED_OUTPUTS, URLFilterEngine


class URLFilteringTests(unittest.TestCase):
    def setUp(self):
        self.engine = URLFilterEngine()

    def test_classification(self):
        cases = {
            "https://example.com/app.JS?x=1": "javascript",
            "https://example.com/module.mjs": "javascript",
            "https://example.com/data.json": "json",
            "https://example.com/report.PDF?download=1": "pdf",
            "https://example.com/archive.tar.gz": "archives",
            "https://example.com/page.xml": "xml",
            "https://example.com/notes.txt": "text",
            "https://example.com/photo.JPEG": "images",
            "https://example.com/index.php": "php",
            "https://example.com/app.jspx": "jspx",
            "https://example.com/server.log": "logs",
            "https://example.com/backup.bak": "backups",
            "https://example.com/db.sqlite3": "databases",
            "https://example.com/conf.yaml": "yaml",
            "https://example.com/app.config": "config",
            "https://example.com/doc.docx": "documents",
            "https://example.com/.env": "environment",
            "https://example.com/.env.production": "environment",
        }
        for url, category in cases.items():
            with self.subTest(url=url):
                self.assertIn(category, self.engine.classify(url))

    def test_no_substring_false_positives(self):
        # The extension must be the final path segment suffix.
        self.assertNotIn("javascript", self.engine.classify("https://example.com/notjs.js.txt"))
        self.assertEqual(self.engine.classify("https://example.com/page.html"), [])
        self.assertEqual(self.engine.classify("https://example.com/?file=x.js"), [])
        self.assertEqual(self.engine.classify("https://example.com/api/v1/users"), [])

    def test_case_insensitive(self):
        self.assertIn("javascript", self.engine.classify("https://example.com/A.JS"))
        self.assertIn("pdf", self.engine.classify("https://example.com/A.PdF"))

    def test_run_dedupes_and_counts(self):
        result = self.engine.run(
            [
                "https://example.com/a.js",
                "https://EXAMPLE.com/a.js#frag",
                "https://example.com/b.json",
                "https://example.com/noext",
            ]
        )
        self.assertEqual(result.total_urls, 4)
        self.assertEqual(len(result.categories["javascript"]), 1)
        self.assertEqual(result.stats["javascript"], 1)
        self.assertEqual(result.uncategorized, 1)

    def test_write_outputs_creates_all_required_files(self):
        result = self.engine.run(
            ["https://example.com/a.js", "https://example.com/db.sql"]
        )
        with tempfile.TemporaryDirectory() as tmp:
            self.engine.write_outputs(result, Path(tmp))
            for filename in REQUIRED_OUTPUTS:
                self.assertTrue((Path(tmp) / filename).exists(), filename)
            self.assertTrue((Path(tmp) / "documents.txt").exists())
            self.assertTrue((Path(tmp) / "filter_stats.json").exists())
            self.assertIn("a.js", (Path(tmp) / "js_files.txt").read_text())
            self.assertIn("db.sql", (Path(tmp) / "db_files.txt").read_text())


if __name__ == "__main__":
    unittest.main()
