"""Unit tests for passive takeover fingerprinting and scoring."""

import tempfile
import unittest
from pathlib import Path

from engines.takeover_engine import (
    TakeoverEngine,
    TakeoverResult,
    classification_for,
    load_fingerprints,
    match_providers,
    score_candidate,
)


class TakeoverDetectionTests(unittest.TestCase):
    def setUp(self):
        self.providers = load_fingerprints()

    def test_fingerprint_database_loads(self):
        self.assertTrue(self.providers)
        ids = {provider["id"] for provider in self.providers}
        self.assertIn("github-pages", ids)
        self.assertIn("heroku", ids)
        self.assertIn("aws-s3", ids)

    def test_match_github(self):
        matches = match_providers("user.github.io", self.providers)
        self.assertTrue(matches)
        self.assertEqual(matches[0]["id"], "github-pages")

    def test_match_heroku(self):
        matches = match_providers("myapp.herokuapp.com", self.providers)
        self.assertEqual(matches[0]["id"], "heroku")

    def test_no_match(self):
        self.assertEqual(match_providers("example.com", self.providers), [])

    def test_dangling_provider_candidate_is_likely(self):
        candidate = score_candidate(
            "dev.example.com",
            "user.github.io",
            target_resolves=False,
            target_rcode="NXDOMAIN",
            providers=self.providers,
            http_status=None,
        )
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.provider_id, "github-pages")
        self.assertGreaterEqual(candidate.confidence, 70)
        self.assertEqual(candidate.classification, "Likely")
        self.assertTrue(any("NXDOMAIN" in item for item in candidate.evidence))
        self.assertTrue(candidate.warnings)

    def test_resolving_target_without_indicator_is_not_reported(self):
        candidate = score_candidate(
            "www.example.com",
            "user.github.io",
            target_resolves=True,
            target_rcode="NOERROR",
            providers=self.providers,
            http_status=200,
            http_body="<html>a normal live page</html>",
        )
        self.assertIsNone(candidate)

    def test_error_page_indicator_raises_confidence(self):
        candidate = score_candidate(
            "dev.example.com",
            "user.github.io",
            target_resolves=True,
            target_rcode="NOERROR",
            providers=self.providers,
            http_status=404,
            http_body="There isn't a GitHub Pages site here",
        )
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.classification, "Likely")
        self.assertGreaterEqual(candidate.confidence, 70)

    def test_unknown_provider_dangling_is_manual_review(self):
        candidate = score_candidate(
            "old.example.com",
            "target.invalid-provider.example",
            target_resolves=False,
            target_rcode="NXDOMAIN",
            providers=self.providers,
            http_status=None,
        )
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.provider_id, "")
        self.assertLessEqual(candidate.confidence, 45)
        self.assertEqual(candidate.classification, "Needs Manual Review")

    def test_classification_thresholds(self):
        self.assertEqual(classification_for(85), "Likely")
        self.assertEqual(classification_for(70), "Likely")
        self.assertEqual(classification_for(60), "Potential")
        self.assertEqual(classification_for(50), "Potential")
        self.assertEqual(classification_for(49), "Needs Manual Review")

    def test_write_outputs(self):
        candidate = score_candidate(
            "dev.example.com",
            "user.github.io",
            target_resolves=False,
            target_rcode="NXDOMAIN",
            providers=self.providers,
        )
        result = TakeoverResult(candidates=[candidate])
        with tempfile.TemporaryDirectory() as tmp:
            TakeoverEngine(fingerprints=self.providers).write_outputs(result, Path(tmp))
            payload = (Path(tmp) / "takeover_candidates.txt").read_text()
            self.assertIn("dev.example.com", payload)
            self.assertIn("No resource was claimed", payload)
            self.assertTrue((Path(tmp) / "takeover_candidates.json").exists())


if __name__ == "__main__":
    unittest.main()
