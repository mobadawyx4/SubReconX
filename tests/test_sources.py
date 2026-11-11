"""Unit tests for passive-source response parsers (no network access)."""

import json
import unittest

from sources.certspotter import parse_certspotter
from sources.commoncrawl import _is_valid_cdx_api, parse_json_lines
from sources.crtsh import parse_crtsh
from sources.otx import parse_passive_dns, parse_url_list
from sources.wayback_cdx import parse_cdx_page
from utils.redaction import redact_payload, redact_url


class CrtshParserTests(unittest.TestCase):
    def test_parses_newline_and_wildcard_names(self):
        payload = json.dumps(
            [
                {
                    "name_value": "www.example.com\n*.example.com\\napi.example.com",
                    "issuer_name": "Test CA",
                    "not_before": "2025-01-01",
                    "not_after": "2026-01-01",
                }
            ]
        )
        records = parse_crtsh(payload, "example.com")
        hosts = {r["hostname"] for r in records}
        self.assertEqual(hosts, {"www.example.com", "example.com", "api.example.com"})

    def test_filters_out_of_scope_and_invalid_names(self):
        payload = json.dumps(
            [
                {"name_value": "evil-example.com"},
                {"name_value": "example.com.evil.net"},
                {"name_value": "bad host name"},
                {"name_value": "good.example.com"},
            ]
        )
        hosts = [r["hostname"] for r in parse_crtsh(payload, "example.com")]
        self.assertEqual(hosts, ["good.example.com"])

    def test_bad_payload(self):
        self.assertEqual(parse_crtsh("not-json", "example.com"), [])
        self.assertEqual(parse_crtsh("{}", "example.com"), [])


class CertSpotterParserTests(unittest.TestCase):
    def test_skips_revoked_and_dedupes(self):
        payload = json.dumps(
            [
                {"dns_names": ["a.example.com", "*.example.com"], "revoked": False},
                {"dns_names": ["a.example.com"], "revoked": False},
                {"dns_names": ["revoked.example.com"], "revoked": True},
            ]
        )
        hosts = [r["hostname"] for r in parse_certspotter(payload, "example.com")]
        self.assertEqual(hosts, ["a.example.com", "example.com"])


class WaybackParserTests(unittest.TestCase):
    def test_header_and_resume_key(self):
        payload = json.dumps(
            [
                ["urlkey", "timestamp", "original", "statuscode", "mimetype"],
                ["com,example)/a", "20200101000000", "https://example.com/a", "200", "text/html"],
                [],
                ["com,example)/a|resume-token"],
            ]
        )
        records, resume = parse_cdx_page(payload)
        self.assertEqual(resume, "com,example)/a|resume-token")
        self.assertEqual(records[0]["url"], "https://example.com/a")
        self.assertEqual(records[0]["timestamp"], "20200101000000")
        self.assertEqual(records[0]["status"], "200")

    def test_headerless_rows(self):
        payload = json.dumps(
            [["20210101000000", "https://example.com/b", "200", "text/html"]]
        )
        records, resume = parse_cdx_page(payload)
        self.assertEqual(resume, "")
        self.assertEqual(records[0]["url"], "https://example.com/b")

    def test_no_results(self):
        self.assertEqual(parse_cdx_page("[]"), ([], ""))


class CommonCrawlParserTests(unittest.TestCase):
    def test_json_lines(self):
        payload = "\n".join(
            [
                json.dumps({"url": "https://example.com/a", "timestamp": "1", "status": "200", "mime": "text/html"}),
                "not json",
                json.dumps({"original": "https://example.com/b", "mimetype": "application/javascript"}),
            ]
        )
        records = parse_json_lines(payload, "CC-MAIN-2026-01")
        self.assertEqual([r["url"] for r in records], ["https://example.com/a", "https://example.com/b"])
        self.assertEqual(records[1]["mimetype"], "application/javascript")
        self.assertEqual(records[0]["crawl"], "CC-MAIN-2026-01")

    def test_cdx_api_validation(self):
        self.assertTrue(_is_valid_cdx_api("https://index.commoncrawl.org/CC-MAIN-2026-43-index"))
        self.assertFalse(_is_valid_cdx_api("http://127.0.0.1:8080/index"))
        self.assertFalse(_is_valid_cdx_api("file:///etc/passwd"))
        self.assertFalse(_is_valid_cdx_api("https://evil-commoncrawl.org/index"))


class OtxParserTests(unittest.TestCase):
    def test_passive_dns_filters_scope(self):
        payload = json.dumps(
            {
                "passive_dns": [
                    {"hostname": "mail.example.com", "record_type": "A"},
                    {"hostname": "evil-example.com"},
                    {"hostname": "mail.example.com"},
                ]
            }
        )
        hosts = [r["hostname"] for r in parse_passive_dns(payload, "example.com")]
        self.assertEqual(hosts, ["mail.example.com"])

    def test_url_list(self):
        payload = json.dumps(
            {
                "url_list": [
                    {"url": "https://example.com/a?token=secret", "date": "2025-01-01"},
                    {"url": ""},
                ]
            }
        )
        records = parse_url_list(payload)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["timestamp"], "2025-01-01")


class RedactionTests(unittest.TestCase):
    def test_query_values_redacted(self):
        cases = {
            "https://example.com/a?api_key=abcdef1234567890": "[REDACTED]",
            "https://example.com/a?apikey=abcdef1234567890": "[REDACTED]",
            "https://example.com/a?access_token=abcdef1234567890": "[REDACTED]",
            "https://example.com/a?token=abc": "[REDACTED]",
            "https://example.com/a?user=bob&page=2": "page=2",
        }
        for url, expected in cases.items():
            with self.subTest(url=url):
                redacted = redact_url(url)
                self.assertNotIn("abcdef1234567890", redacted)
                self.assertIn(expected, redacted)

    def test_payload_redaction_json(self):
        payload = json.dumps(
            [
                {"url": "https://example.com/a?token=abcdef1234567890", "hostname": "example.com"},
                {"name_value": "www.example.com"},
            ]
        )
        redacted = redact_payload(payload)
        self.assertNotIn("abcdef1234567890", redacted)
        self.assertIn("[REDACTED]", redacted)
        self.assertIn("www.example.com", redacted)
        self.assertIsInstance(json.loads(redacted), list)

    def test_payload_redaction_json_lines(self):
        payload = "\n".join(
            [
                json.dumps({"url": "https://example.com/a?api_key=abcdef1234567890"}),
                json.dumps({"url": "https://example.com/b"}),
            ]
        )
        redacted = redact_payload(payload)
        self.assertNotIn("abcdef1234567890", redacted)
        self.assertIn("https://example.com/b", redacted)

    def test_userinfo_removed(self):
        redacted = redact_url("https://user:pass@example.com/x")
        self.assertNotIn("pass", redacted)
        self.assertTrue(redacted.startswith("https://[REDACTED]@example.com/"))


if __name__ == "__main__":
    unittest.main()
