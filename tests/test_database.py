"""Unit tests for the SQLite persistence layer."""

import tempfile
import unittest
from pathlib import Path

from core.database import Database


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "test.db")
        self.domain = "example.com"

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_scan_lifecycle(self):
        scan_id = self.db.start_scan(self.domain, {"a": 1})
        self.db.finish_scan(scan_id, "completed")
        scans = self.db.get_scans(self.domain)
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["status"], "completed")

    def test_subdomain_dedup_and_source_merge(self):
        self.db.upsert_subdomain(self.domain, "www.example.com", "crt.sh")
        self.db.upsert_subdomain(self.domain, "www.example.com", "otx")
        self.db.upsert_subdomain(self.domain, "www.example.com", "crt.sh")
        rows = self.db.get_subdomains(self.domain)
        self.assertEqual(len(rows), 1)
        self.assertIn("crt.sh", rows[0]["sources"])
        self.assertIn("otx", rows[0]["sources"])
        self.assertEqual(self.db.count_subdomains(self.domain), 1)

    def test_dns_records(self):
        self.db.add_dns_record(self.domain, "www.example.com", "A", "93.184.216.34")
        self.db.add_dns_record(self.domain, "www.example.com", "A", "93.184.216.34")
        self.db.add_dns_record(self.domain, "www.example.com", "CNAME", "edge.example.net")
        rows = self.db.get_dns_records(self.domain)
        self.assertEqual(len(rows), 2)

    def test_http_results_upsert(self):
        record = {
            "url": "https://www.example.com/",
            "hostname": "www.example.com",
            "scheme": "https",
            "status": 200,
            "title": "Example",
            "tls_verified": True,
        }
        self.db.add_http_result(self.domain, record)
        record["status"] = 301
        self.db.add_http_result(self.domain, record)
        rows = self.db.get_http_results(self.domain)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], 301)

    def test_historical_url_dedup(self):
        record = {
            "url": "https://example.com/a",
            "normalized": "https://example.com/a",
            "hostname": "example.com",
            "path": "/a",
            "extension": "",
            "source": "wayback",
            "timestamp": "20200101",
        }
        self.db.add_historical_url(self.domain, record)
        self.db.add_historical_url(self.domain, record)
        self.assertEqual(len(self.db.get_historical_urls(self.domain)), 1)

    def test_indicators_and_takeover(self):
        self.db.add_indicator(
            self.domain, "git_exposure", ".git/config", "https://example.com/.git/config", "high"
        )
        self.db.add_indicator(
            self.domain, "git_exposure", ".git/config", "https://example.com/.git/config", "high"
        )
        self.assertEqual(len(self.db.get_indicators(self.domain)), 1)
        self.db.add_takeover_finding(
            self.domain,
            {
                "hostname": "dev.example.com",
                "cname_target": "x.github.io",
                "provider": "GitHub Pages",
                "confidence": 85,
                "classification": "Likely",
                "evidence": ["NXDOMAIN"],
            },
        )
        rows = self.db.get_takeover_findings(self.domain)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["classification"], "Likely")

    def test_cache_ttl_and_clear(self):
        self.db.cache_set("crt.sh", "key", "payload", ttl=60)
        self.assertEqual(self.db.cache_get("crt.sh", "key"), "payload")
        self.db.cache_set("crt.sh", "expired", "payload", ttl=-1)
        self.assertIsNone(self.db.cache_get("crt.sh", "expired"))
        self.db.clear_cache()
        self.assertIsNone(self.db.cache_get("crt.sh", "key"))

    def test_meta_and_clear_domain(self):
        self.db.set_meta(self.domain, "phase", {"done": True})
        self.assertEqual(self.db.get_meta(self.domain, "phase"), {"done": True})
        self.db.upsert_subdomain(self.domain, "www.example.com", "crt.sh")
        self.db.add_tls_result(
            self.domain,
            {"hostname": "www.example.com", "port": 443, "connected": True, "verified": True},
        )
        self.db.add_js_asset(
            self.domain,
            {"normalized": "https://example.com/app.js", "url": "https://example.com/app.js"},
        )
        self.db.start_scan(self.domain, {"test": True})
        self.db.clear_domain(self.domain)
        self.assertEqual(self.db.count_subdomains(self.domain), 0)
        self.assertEqual(self.db.get_tls_results(self.domain), [])
        self.assertEqual(self.db.get_js_assets(self.domain), [])
        self.assertEqual(self.db.get_scans(self.domain), [])
        self.assertIsNone(self.db.get_meta(self.domain, "phase"))

    def test_reentrant_transaction_batching(self):
        items = [(f"sub{i}.example.com", "crt.sh") for i in range(25)]
        self.db.upsert_subdomains(self.domain, items)
        self.assertEqual(self.db.count_subdomains(self.domain), 25)


if __name__ == "__main__":
    unittest.main()
