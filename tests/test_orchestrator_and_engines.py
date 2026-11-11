"""Integration and engine tests using offline local fixtures."""

from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from config import ScanConfig
from core.database import Database
from core.event_logger import EventLogger
from core.orchestrator import Orchestrator
from core.scope_manager import ScopeManager
from engines.javascript_engine import JavaScriptEngine, extract_endpoints
from engines.tls_engine import TLSRunResult, write_tls_outputs
from protocols.http_protocol import HTTPResult
from protocols.tls_protocol import TLSResult


class JavaScriptEngineTests(unittest.TestCase):
    def test_extract_endpoints(self):
        sample_js = """
        const api = "/api/v1/users";
        const adminUrl = "https://api.example.com/admin/settings?token=secret1234567890";
        """
        endpoints = extract_endpoints(sample_js)
        self.assertIn("/api/v1/users", endpoints)
        self.assertTrue(any("api.example.com/admin/settings" in ep for ep in endpoints))
        self.assertFalse(any("secret1234567890" in ep for ep in endpoints))

    def test_max_files_limit_and_source_attribution(self):
        scope = ScopeManager("example.com")
        engine = JavaScriptEngine(scope, concurrency=4)
        urls = [f"https://example.com/static/app_{i}.js" for i in range(12)]
        source_map = {urls[0]: ["wayback", "otx"]}

        async def fake_fetch(url, _scope, **_kwargs):
            await asyncio.sleep(0.005)
            return HTTPResult(
                url=url,
                final_url=url,
                scheme="https",
                hostname="example.com",
                status=200,
                content_type="application/javascript",
                body=b'const route = "/api/v2/internal/debug";',
            )

        with patch("engines.javascript_engine.fetch", side_effect=fake_fetch):
            result = asyncio.run(
                engine.run(urls, analyze=True, max_files=3, source_map=source_map)
            )

        self.assertEqual(len(result.assets), 12)
        analyzed_assets = [a for a in result.assets if a.analyzed]
        self.assertEqual(len(analyzed_assets), 3)
        first = next(a for a in result.assets if a.normalized == urls[0])
        self.assertEqual(first.sources, ["wayback", "otx"])
        self.assertIn("/api/v2/internal/debug", first.endpoints)


class TLSEngineOutputTests(unittest.TestCase):
    def test_writes_json_and_txt(self):
        run = TLSRunResult(
            results=[
                TLSResult(
                    hostname="example.com",
                    port=443,
                    connected=True,
                    verified=True,
                    protocol="TLSv1.3",
                    cipher="TLS_AES_256_GCM_SHA384",
                    subject={"commonName": "example.com"},
                    issuer={"commonName": "Example CA"},
                    serial_number="01ABCD",
                    not_after="Dec 25 22:56:35 2026 GMT",
                    sans=["example.com", "*.example.com"],
                    expired=False,
                    days_until_expiry=45,
                    hostname_matches=True,
                )
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            write_tls_outputs(run, out)
            self.assertTrue((out / "tls_results.json").exists())
            self.assertTrue((out / "tls_results.txt").exists())
            data = json.loads((out / "tls_results.json").read_text())
            self.assertEqual(data["results"][0]["serial_number"], "01ABCD")
            txt = (out / "tls_results.txt").read_text()
            self.assertIn("VERIFIED", txt)
            self.assertIn("TLSv1.3", txt)


class OrchestratorResumeIntegrationTests(unittest.TestCase):
    def test_full_resume_pipeline_from_database_fixtures(self):
        with tempfile.TemporaryDirectory() as tmp:
            root_dir = Path(tmp)
            db_path = root_dir / "test.db"
            out_root = root_dir / "results"
            domain = "example.com"

            db = Database(db_path)
            try:
                db.upsert_subdomains(
                    domain,
                    [
                        ("example.com", "root"),
                        ("www.example.com", "crt.sh"),
                        ("dev.example.com", "otx"),
                    ],
                )
                db.add_dns_record(domain, "example.com", "A", "93.184.216.34")
                db.add_dns_record(domain, "www.example.com", "A", "93.184.216.34")
                db.add_dns_record(
                    domain, "dev.example.com", "CNAME", "unclaimed-app.github.io", status="dangling"
                )
                db.add_http_result(
                    domain,
                    {
                        "url": "https://example.com/",
                        "final_url": "https://example.com/",
                        "hostname": "example.com",
                        "scheme": "https",
                        "status": 200,
                        "title": "Example Domain",
                        "server": "cloudflare",
                        "tls_verified": True,
                        "technologies": ["Cloudflare"],
                    },
                )
                db.add_tls_result(
                    domain,
                    {
                        "hostname": "example.com",
                        "port": 443,
                        "connected": True,
                        "verified": True,
                        "protocol": "TLSv1.3",
                        "cipher": "TLS_AES_256_GCM_SHA384",
                        "subject": {"commonName": "example.com"},
                        "issuer": {"commonName": "Cloudflare CA"},
                        "serial_number": "AABBCC1122",
                        "not_after": "Dec 25 22:56:35 2026 GMT",
                        "sans": ["example.com", "*.example.com"],
                        "expired": False,
                        "days_until_expiry": 45,
                        "hostname_matches": True,
                    },
                )
                db.add_historical_url(
                    domain,
                    {
                        "url": "https://api.example.com/v1/bundle.js",
                        "normalized": "https://api.example.com/v1/bundle.js",
                        "hostname": "api.example.com",
                        "path": "/v1/bundle.js",
                        "extension": "js",
                        "source": "wayback",
                        "timestamp": "20260101000000",
                    },
                )
                db.add_historical_url(
                    domain,
                    {
                        "url": "https://example.com/.env",
                        "normalized": "https://example.com/.env",
                        "hostname": "example.com",
                        "path": "/.env",
                        "extension": "env",
                        "source": "otx",
                        "timestamp": "20260102000000",
                    },
                )

                config = ScanConfig(
                    domain=domain,
                    output_root=out_root,
                    db_path=db_path,
                    resume=True,
                    assume_authorized=True,
                    quiet=True,
                )
                scope = ScopeManager(domain)
                logger = EventLogger(quiet=True)
                orchestrator = Orchestrator(config, scope, logger, db)
                bundle = asyncio.run(orchestrator.run())
            finally:
                db.close()

            # Historical hostname api.example.com merged into subdomains
            sub_hosts = {h["hostname"] for h in bundle["subdomains"]["hosts"]}
            self.assertIn("api.example.com", sub_hosts)
            # Dangling CNAME reconstructed from DB and takeover candidate identified
            self.assertEqual(len(bundle["dns"]["dangling"]), 1)
            self.assertEqual(len(bundle["takeover"]["candidates"]), 1)
            self.assertEqual(
                bundle["takeover"]["candidates"][0]["hostname"], "dev.example.com"
            )
            # Reports written
            out_dir = out_root / domain
            for fname in (
                "report.html",
                "report.json",
                "report.txt",
                "scan_summary.json",
                "subdomains.txt",
                "dns_results.json",
                "tls_results.txt",
                "takeover_candidates.txt",
            ):
                self.assertTrue((out_dir / fname).exists(), fname)


if __name__ == "__main__":
    unittest.main()
