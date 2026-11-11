"""Unit tests for explainable risk classification."""

import unittest

from engines.dns_engine import DNSRunResult
from engines.risk_engine import RiskEngine
from engines.sensitive_detection_engine import Indicator, SensitiveResult
from engines.takeover_engine import TakeoverCandidate, TakeoverResult
from engines.tls_engine import TLSResult, TLSRunResult
from engines.url_filter_engine import FilterResult


class RiskEngineTests(unittest.TestCase):
    def test_keyword_matches_not_critical(self):
        sensitive = SensitiveResult(
            indicators=[
                Indicator(
                    category="environment_configuration",
                    kind="path",
                    value="\\.env$",
                    severity="high",
                    url="https://example.com/.env",
                    redacted_url="https://example.com/.env",
                )
            ]
        )
        result = RiskEngine().run(sensitive=sensitive)
        self.assertFalse(any(f.severity == "critical" for f in result.findings))
        self.assertEqual(result.overall_severity, "medium")
        self.assertTrue(all(f.rationale for f in result.findings))

    def test_takeover_likely_is_high(self):
        takeover = TakeoverResult(
            candidates=[
                TakeoverCandidate(
                    hostname="dev.example.com",
                    cname_target="x.github.io",
                    provider_id="github-pages",
                    provider_name="GitHub Pages",
                    confidence=85,
                    classification="Likely",
                    evidence=["CNAME target x.github.io returns NXDOMAIN"],
                )
            ]
        )
        result = RiskEngine().run(takeover=takeover)
        finding = next(f for f in result.findings if f.category == "subdomain_takeover")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(result.overall_severity, "high")

    def test_tls_expired_and_mismatch(self):
        tls = TLSRunResult(
            results=[
                TLSResult(
                    hostname="www.example.com",
                    connected=True,
                    verified=True,
                    expired=True,
                    hostname_matches=False,
                    days_until_expiry=-2,
                )
            ]
        )
        result = RiskEngine().run(tls_result=tls)
        categories = {f.category for f in result.findings}
        self.assertIn("tls", categories)
        self.assertTrue(any("Expired" in f.title for f in result.findings))

    def test_dns_private_address_finding(self):
        dns = DNSRunResult(
            root="example.com",
            suspicious=[
                {"hostname": "internal.example.com", "reason": "private-ip-in-dns", "addresses": ["10.0.0.1"]}
            ],
        )
        result = RiskEngine().run(dns_result=dns)
        finding = next(f for f in result.findings if f.category == "dns_configuration")
        self.assertEqual(finding.severity, "medium")

    def test_historical_file_reference_is_indicator(self):
        filter_result = FilterResult(
            categories={"environment": ["https://example.com/.env"], "backups": []},
            stats={"environment": 1},
        )
        result = RiskEngine().run(filter_result=filter_result)
        finding = next(f for f in result.findings if f.category == "historical_file_reference")
        self.assertIn(finding.severity, {"low", "medium"})
        self.assertTrue(finding.rationale)


if __name__ == "__main__":
    unittest.main()
