"""Unit tests for HTML, JSON and TXT report generation."""

import json
import tempfile
import unittest
from pathlib import Path

from engines.report_engine import generate_reports


def sample_bundle():
    return {
        "meta": {
            "tool": "SubReconX",
            "version": "1.0.0",
            "domain": "example.com",
            "generated_at": "2026-01-01 00:00:00",
            "duration_seconds": 1.5,
            "duration_human": "1.5s",
        },
        "risk": {
            "overall_severity": "medium",
            "overall_score": 55,
            "summary": {"critical": 0, "high": 0, "medium": 1, "low": 0, "informational": 0},
            "asset_summary": {
                "subdomains": 2,
                "historical_urls": 1,
                "live_hosts": 1,
                "javascript_assets": 1,
                "sensitive_indicators": 1,
                "takeover_candidates": 0,
            },
            "notes": ["Indicators only."],
            "findings": [
                {
                    "title": "Sensitive-path indicators: environment configuration",
                    "severity": "medium",
                    "score": 55,
                    "rationale": "A path indicator matched; not proof of exposure.",
                    "evidence": [
                        "path: \\.env -> https://example.com/.env",
                        "https://example.com/a?api_key=SUPERSECRET123",
                    ],
                    "recommendation": "Manual review.",
                }
            ],
        },
        "subdomains": {
            "hosts": [
                {"hostname": "example.com", "sources": ["root"]},
                {"hostname": "www.example.com", "sources": ["crt.sh"]},
            ]
        },
        "dns": {
            "resolved": ["example.com", "www.example.com"],
            "records": [
                {
                    "hostname": "www.example.com",
                    "status": "resolved",
                    "a": ["93.184.216.34"],
                    "aaaa": [],
                    "cname": [],
                    "rcode": "NOERROR",
                    "dangling": False,
                }
            ],
        },
        "http": {
            "live_hosts": ["www.example.com"],
            "results": [
                {
                    "hostname": "www.example.com",
                    "scheme": "https",
                    "status": 200,
                    "server": "nginx",
                    "title": "Example",
                    "final_url": "https://www.example.com/",
                    "error": "",
                }
            ],
        },
        "tls": {"results": []},
        "historical": {
            "total": 1,
            "in_scope": 1,
            "out_of_scope": 0,
            "malformed": [],
            "source_stats": {"wayback": 1},
            "records": [
                {
                    "url": "https://example.com/api?token=SUPERSECRET123",
                    "normalized": "https://example.com/api?token=SUPERSECRET123",
                    "hostname": "example.com",
                    "sources": ["wayback"],
                }
            ],
            "out_of_scope_records": [],
        },
        "filter": {"stats": {"javascript": 1}},
        "sensitive": {
            "total_indicators": 1,
            "suspicious_paths": 1,
            "sensitive_parameters": 0,
            "categories": {"environment_configuration": 1},
            "indicators": [
                {
                    "category": "environment_configuration",
                    "kind": "path",
                    "value": "\\.env",
                    "severity": "high",
                    "url": "https://example.com/.env",
                }
            ],
        },
        "javascript": {
            "assets": [
                {
                    "url": "https://example.com/app.js",
                    "normalized": "https://example.com/app.js",
                    "hostname": "example.com",
                    "sources": ["wayback"],
                }
            ],
            "endpoints": ["/api/v1/users"],
        },
        "takeover": {"candidates": []},
        "sources": [
            {"source": "crt.sh", "count": 2, "cached": False, "error": ""}
        ],
        "tasks": [
            {"name": "passive", "status": "done", "duration_seconds": 0.1, "summary": "2", "error": ""}
        ],
        "errors": [],
    }


class ReportGenerationTests(unittest.TestCase):
    def test_generates_all_formats(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = generate_reports(sample_bundle(), Path(tmp))
            for key in ("html", "json", "txt"):
                self.assertTrue(paths[key].exists(), key)
            self.assertTrue(paths["html"].name == "report.html")
            self.assertTrue(paths["json"].name == "report.json")
            self.assertTrue(paths["txt"].name == "report.txt")

    def test_html_contents_and_redaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = generate_reports(sample_bundle(), Path(tmp))
            html = paths["html"].read_text()
            self.assertIn("example.com", html)
            self.assertIn("Risk assessment", html)
            self.assertIn("TLS certificates", html)
            self.assertIn("JavaScript inventory", html)
            self.assertIn("Takeover candidates", html)
            self.assertIn("Sensitive indicators", html)
            self.assertNotIn("SUPERSECRET123", html)
            self.assertIn("[REDACTED]", html)

    def test_json_is_valid_and_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = generate_reports(sample_bundle(), Path(tmp))
            payload = json.loads(paths["json"].read_text())
            self.assertEqual(payload["meta"]["domain"], "example.com")
            historical = json.dumps(payload["historical"])
            self.assertNotIn("SUPERSECRET123", historical)
            self.assertIn("[REDACTED]", historical)
            self.assertNotIn("SUPERSECRET123", json.dumps(payload["risk"]))

    def test_txt_report_sections(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = generate_reports(sample_bundle(), Path(tmp))
            text = paths["txt"].read_text()
            for section in (
                "RISK FINDINGS",
                "LIVE HOSTS",
                "TLS CERTIFICATES",
                "HISTORICAL URLS",
                "JAVASCRIPT INVENTORY",
                "SOURCES",
            ):
                self.assertIn(section, text)
            self.assertNotIn("SUPERSECRET123", text)


if __name__ == "__main__":
    unittest.main()
