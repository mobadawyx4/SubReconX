"""Unit and integration tests for Phases 1–9 of Bug Bounty Optimization."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from config import ScanConfig
from core.database import Database
from core.event_logger import EventLogger
from core.orchestrator import Orchestrator
from core.scope_manager import ScopeManager
from engines.asset_intelligence_engine import (
    AssetIntelligenceEngine,
    detect_hostname_environment_labels,
    detect_legacy_indicators,
)
from engines.dns_engine import DNSRunResult, ResolvedHost
from engines.historical_url_engine import HistoricalURLEngine, write_historical_outputs
from engines.javascript_engine import JavaScriptEngine
from engines.live_host_engine import (
    LiveHostEngine,
    classify_host_liveness,
    summarize_host,
)
from engines.report_engine import generate_reports
from engines.results_engine import (
    ResultsProcessingEngine,
    clean_and_deduplicate_subdomains,
)
from engines.sensitive_detection_engine import SensitiveDetectionEngine
from engines.subdomain_engine import SubdomainResult
from engines.takeover_engine import TakeoverCandidate, TakeoverResult
from protocols.http_protocol import HTTPResult, fetch
from sources.base import SourceResult


class Phase1ResultsOrganizationTests(unittest.TestCase):
    def test_clean_deduplicate_boundary_and_attribution(self):
        scope = ScopeManager("example.com")
        raw_entries = [
            {"hostname": "  API.Example.com. ", "source": "crt.sh"},
            {"hostname": "api.example.com", "source": "wayback"},
            {"hostname": "staging.example.com", "sources": ["otx"]},
            {"hostname": "not_a_valid_host$$$", "source": "crt.sh"},
            {"hostname": "evil-example.com", "source": "crt.sh"},
            {"hostname": "   ", "source": "crt.sh"},
        ]
        deduped, raw_lines, malformed = clean_and_deduplicate_subdomains(
            raw_entries, scope
        )
        hosts = {item["hostname"]: item for item in deduped}
        self.assertEqual(set(hosts.keys()), {"api.example.com", "staging.example.com"})
        self.assertEqual(hosts["api.example.com"]["sources"], ["crt.sh", "wayback"])
        self.assertEqual(len(raw_lines), 5)
        self.assertEqual(len(malformed), 2)

    def test_migration_preserves_existing_results(self):
        scope = ScopeManager("example.com")
        engine = ResultsProcessingEngine(scope)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "subdomains.txt").write_text(
                "legacy1.example.com\nlegacy2.example.com\n", encoding="utf-8"
            )
            (out / "urls_all.txt").write_text(
                "https://legacy1.example.com/login?token=abcdef1234567890\n",
                encoding="utf-8",
            )
            migrated = engine.migrate_existing_results(out)
            self.assertEqual(migrated["subdomains"], 2)
            self.assertEqual(migrated["urls"], 1)
            raw_subs = (out / "raw" / "subdomains_raw.txt").read_text(encoding="utf-8")
            self.assertIn("legacy1.example.com", raw_subs)
            raw_urls = (out / "raw" / "urls_raw.txt").read_text(encoding="utf-8")
            self.assertIn("[REDACTED]", raw_urls)
            self.assertNotIn("abcdef1234567890", raw_urls)


class Phase2LiveHostClassificationTests(unittest.TestCase):
    def test_non_200_responses_classified_as_live(self):
        for status_code in (200, 301, 302, 401, 403, 404, 500, 503):
            with self.subTest(status=status_code):
                probe = HTTPResult(
                    url="https://api.example.com/",
                    hostname="api.example.com",
                    scheme="https",
                    status=status_code,
                )
                cls, reason = classify_host_liveness([probe])
                self.assertEqual(cls, "LIVE", reason)

    def test_timeouts_and_rate_limits_classified_as_unknown_not_dead(self):
        timeout_probe = HTTPResult(
            url="https://slow.example.com/",
            hostname="slow.example.com",
            scheme="https",
            error="timeout",
        )
        cls, _ = classify_host_liveness([timeout_probe])
        self.assertEqual(cls, "UNKNOWN")

        rate_limit_probe = HTTPResult(
            url="https://rl.example.com/",
            hostname="rl.example.com",
            scheme="https",
            status=429,
        )
        cls_rl, _ = classify_host_liveness([rate_limit_probe])
        self.assertEqual(cls_rl, "UNKNOWN")

        servfail_dns = ResolvedHost(hostname="temp.example.com", rcode="SERVFAIL")
        cls_sf, _ = classify_host_liveness([], servfail_dns)
        self.assertEqual(cls_sf, "UNKNOWN")

    def test_definitive_dns_and_connection_refused_classified_as_dead(self):
        refused_https = HTTPResult(
            url="https://dead.example.com/",
            hostname="dead.example.com",
            scheme="https",
            error="ConnectionRefusedError:[Errno 111] Connection refused",
        )
        refused_http = HTTPResult(
            url="http://dead.example.com/",
            hostname="dead.example.com",
            scheme="http",
            error="ConnectionRefusedError:[Errno 111] Connection refused",
        )
        cls, _ = classify_host_liveness([refused_https, refused_http])
        self.assertEqual(cls, "DEAD")

        nxdomain_dns = ResolvedHost(hostname="nx.example.com", rcode="NXDOMAIN")
        cls_nx, _ = classify_host_liveness([], nxdomain_dns)
        self.assertEqual(cls_nx, "DEAD")

    def test_summarize_host_captures_all_metadata(self):
        probe = HTTPResult(
            url="https://app.example.com/",
            final_url="https://app.example.com/home",
            hostname="app.example.com",
            scheme="https",
            status=403,
            title="Restricted Portal",
            content_type="text/html; charset=utf-8",
            server="nginx",
            elapsed=0.1234,
            redirect_chain=["https://app.example.com/home"],
            technologies=["nginx"],
            tls_metadata={"protocol": "TLSv1.3", "subject": {"commonName": "app.example.com"}},
        )
        summary = summarize_host("app.example.com", [probe])
        self.assertEqual(summary["classification"], "LIVE")
        self.assertEqual(summary["status"], 403)
        self.assertEqual(summary["final_url"], "https://app.example.com/home")
        self.assertEqual(summary["redirect_chain"], ["https://app.example.com/home"])
        self.assertEqual(summary["response_time"], 0.1234)
        self.assertEqual(summary["title"], "Restricted Portal")
        self.assertEqual(summary["content_type"], "text/html; charset=utf-8")
        self.assertEqual(summary["server"], "nginx")
        self.assertEqual(summary["tls_metadata"]["protocol"], "TLSv1.3")


class Phase3And4And5URLAndJSProcessingTests(unittest.TestCase):
    def test_historical_url_cleanup_and_outputs(self):
        class FakeSourceManager:
            async def collect_urls(self):
                return (
                    [
                        {
                            "url": "https://API.EXAMPLE.COM:443/v1/users?id=42&token=secret1234567890#frag",
                            "source": "wayback",
                            "timestamp": "20250101000000",
                        },
                        {
                            "url": "https://api.example.com/v1/users?id=42&token=secret1234567890",
                            "source": "commoncrawl",
                            "timestamp": "20260202000000",
                        },
                        {
                            "url": "https://dead.example.com/old.bak",
                            "source": "wayback",
                            "timestamp": "20240101000000",
                        },
                        {
                            "url": "https://cdn.other-domain.org/app.js",
                            "source": "otx",
                            "timestamp": "20260101000000",
                        },
                    ],
                    [SourceResult(source="wayback", records=[{}, {}, {}])],
                )

        scope = ScopeManager("example.com")
        engine = HistoricalURLEngine(scope, FakeSourceManager())
        host_cls = {
            "api.example.com": {"classification": "LIVE", "status": 200},
            "dead.example.com": {"classification": "DEAD", "status": None},
        }
        result = asyncio.run(engine.run(host_classifications=host_cls))
        self.assertEqual(len(result.in_scope), 2)
        self.assertEqual(len(result.out_of_scope), 1)
        self.assertEqual(len(result.with_parameters), 1)
        self.assertEqual(len(result.live_urls), 1)
        self.assertEqual(len(result.dead_urls), 1)
        api_rec = next(r for r in result.in_scope if r.hostname == "api.example.com")
        self.assertEqual(api_rec.sources, ["wayback", "commoncrawl"])
        self.assertEqual(api_rec.timestamp, "20260202000000")
        self.assertEqual(api_rec.params, ["id", "token"])

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            write_historical_outputs(result, out)
            for fname in (
                "urls_all.txt",
                "urls_unique.txt",
                "urls_in_scope.txt",
                "urls_out_of_scope.txt",
                "urls_live.txt",
                "urls_dead.txt",
                "urls_unknown.txt",
                "urls_with_parameters.txt",
                "urls.json",
            ):
                self.assertTrue((out / fname).exists(), fname)

    def test_intelligent_url_classification_categories_and_no_false_positives(self):
        engine = SensitiveDetectionEngine()
        urls = [
            "https://example.com/static/bundle.js",
            "https://api.example.com/api/v2/accounts?user_id=100",
            "https://example.com/oauth2/authorize?redirect_uri=https://example.com/cb",
            "https://example.com/admin/dashboard",
            "https://example.com/.env.staging",
            "https://example.com/backups/db.bak",
            "https://example.com/database/schema.sql",
            "https://example.com/actuator/health?debug=1",
            # Benign lookalikes that must NOT trigger false positives:
            "https://example.com/badminton/clubs",
            "https://example.com/therapist/directory",
            "https://example.com/author/profile",
        ]
        res = engine.run(urls)
        self.assertEqual(len(res.js_files), 1)
        self.assertEqual(len(res.api_endpoints), 1)
        self.assertEqual(len(res.authentication_paths), 1)
        self.assertEqual(len(res.admin_paths), 1)
        self.assertEqual(len(res.config_indicators), 1)
        self.assertEqual(len(res.backup_indicators), 1)
        self.assertEqual(len(res.database_indicators), 1)
        self.assertEqual(len(res.debug_paths), 1)
        self.assertGreaterEqual(len(res.interesting_parameters), 2)
        for benign in ("/badminton/", "/therapist/", "/author/"):
            self.assertFalse(any(benign in u for u in res.interesting_urls), benign)

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            engine.write_outputs(res, out)
            for fname in (
                "js_files.txt",
                "api_endpoints.txt",
                "authentication_paths.txt",
                "admin_paths.txt",
                "config_indicators.txt",
                "backup_indicators.txt",
                "database_indicators.txt",
                "debug_paths.txt",
                "interesting_parameters.txt",
                "suspicious_paths.txt",
            ):
                self.assertTrue((out / fname).exists(), fname)

    def test_javascript_inventory_metadata_and_files(self):
        scope = ScopeManager("example.com")
        js_engine = JavaScriptEngine(scope)
        urls = [
            "https://app.example.com/assets/main.js",
            "https://unknown.example.com/assets/vendor.mjs",
        ]
        source_map = {urls[0]: ["wayback"], urls[1]: ["commoncrawl"]}
        ts_map = {urls[0]: "20260115120000", urls[1]: "20251101000000"}
        host_cls = {
            "app.example.com": {"classification": "LIVE"},
            "unknown.example.com": {"classification": "UNKNOWN"},
        }
        res = asyncio.run(
            js_engine.run(
                urls,
                analyze=False,
                source_map=source_map,
                timestamp_map=ts_map,
                host_classifications=host_cls,
            )
        )
        self.assertEqual(len(res.assets), 2)
        self.assertEqual(len(res.live_urls), 1)
        self.assertEqual(len(res.unknown_urls), 1)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            js_engine.write_outputs(res, out)
            for fname in (
                "js_files.txt",
                "js_unique.txt",
                "js_live.txt",
                "js_unknown.txt",
                "js_inventory.json",
            ):
                self.assertTrue((out / fname).exists(), fname)


class Phase6And7ScopeAndIntelligenceTests(unittest.TestCase):
    def test_bug_bounty_json_scope_strict_mode_and_exclusions(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope_path = Path(tmp) / "bugcrowd_scope.json"
            scope_path.write_text(
                json.dumps(
                    {
                        "program_name": "Example Bug Bounty",
                        "root_domains": ["example.com"],
                        "in_scope_hosts": ["app.example.com", "portal.example.com"],
                        "wildcard_domains": ["api.example.com"],
                        "out_of_scope": [
                            "blog.example.com",
                            "*.corp.example.com",
                            "staging-payments.api.example.com",
                        ],
                        "strict_scope": True,
                        "allow_active_probing": True,
                        "rate_limit_rps": 10.0,
                        "restrictions": ["No brute force", "Authorized testing only"],
                    }
                ),
                encoding="utf-8",
            )
            scope = ScopeManager.from_scope_file("example.com", scope_path)
            self.assertTrue(scope.strict_scope)
            self.assertEqual(scope.rate_limit_rps, 10.0)
            # Root and explicit in-scope hosts allowed
            self.assertTrue(scope.is_in_scope("example.com"))
            self.assertTrue(scope.is_in_scope("app.example.com"))
            # Unlisted subdomain of root is NOT assumed in scope under strict_scope!
            self.assertFalse(scope.is_in_scope("random.example.com"))
            # Wildcard *.api.example.com IS in scope unless excluded
            self.assertTrue(scope.is_in_scope("v1.api.example.com"))
            self.assertFalse(scope.is_in_scope("staging-payments.api.example.com"))
            # Excluded hosts and wildcard domains are rejected
            self.assertFalse(scope.is_in_scope("blog.example.com"))
            self.assertFalse(scope.is_in_scope("hr.corp.example.com"))
            # Root-domain boundary check still recognizes subdomains of example.com
            self.assertTrue(scope.is_within_root_boundary("random.example.com"))

    def test_passive_only_blocks_active_http_probing(self):
        scope = ScopeManager("example.com", allow_active_probing=False)
        res = asyncio.run(fetch("https://example.com/", scope))
        self.assertIn("active probing is disabled", res.error)

    def test_asset_intelligence_indicators_and_explanations(self):
        env_hits = detect_hostname_environment_labels("staging-api.dev.example.com")
        self.assertTrue(any(h["indicator"] == "staging" for h in env_hits))
        self.assertTrue(all("explanation" in h for h in env_hits))

        leg_hits = detect_legacy_indicators(
            "legacy-portal.example.com",
            ["https://legacy-portal.example.com/login.jsp"],
            ["IIS"],
            "Microsoft-IIS/7.5",
        )
        self.assertGreaterEqual(len(leg_hits), 2)
        self.assertTrue(all("explanation" in h for h in leg_hits))


class Phase8And9FullPipelineStructureTests(unittest.TestCase):
    def test_orchestrator_produces_full_directory_hierarchy_and_dashboard(self):
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
                        ("staging-api.example.com", "crt.sh"),
                        ("dead.example.com", "otx"),
                    ],
                )
                db.add_dns_record(domain, "example.com", "A", "93.184.216.34")
                db.add_dns_record(domain, "staging-api.example.com", "A", "93.184.216.35")
                db.add_dns_record(
                    domain,
                    "dead.example.com",
                    "CNAME",
                    "unclaimed-bucket.s3.amazonaws.com",
                    status="dangling",
                )
                db.add_http_result(
                    domain,
                    {
                        "url": "https://staging-api.example.com/",
                        "final_url": "https://staging-api.example.com/",
                        "hostname": "staging-api.example.com",
                        "scheme": "https",
                        "status": 403,
                        "title": "Admin API Gateway",
                        "server": "nginx",
                        "tls_verified": True,
                        "technologies": ["nginx"],
                    },
                )
                db.add_historical_url(
                    domain,
                    {
                        "url": "https://staging-api.example.com/api/v1/admin/users?redirect=https://example.com&token=secret1234567890123456",
                        "normalized": "https://staging-api.example.com/api/v1/admin/users?redirect=https://example.com&token=secret1234567890123456",
                        "hostname": "staging-api.example.com",
                        "path": "/api/v1/admin/users",
                        "extension": "",
                        "source": "wayback",
                        "timestamp": "20260101000000",
                    },
                )
                db.add_historical_url(
                    domain,
                    {
                        "url": "https://staging-api.example.com/static/app.js",
                        "normalized": "https://staging-api.example.com/static/app.js",
                        "hostname": "staging-api.example.com",
                        "path": "/static/app.js",
                        "extension": "js",
                        "source": "wayback",
                        "timestamp": "20260101000000",
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

            out_dir = out_root / domain
            # Verify raw/
            for f in ("subdomains_raw.txt", "urls_raw.txt", "source_metadata.json"):
                self.assertTrue((out_dir / "raw" / f).exists(), f"raw/{f}")

            # Verify organized/
            for f in (
                "subdomains_all.txt",
                "subdomains_in_scope.txt",
                "subdomains_live.txt",
                "subdomains_dead.txt",
                "subdomains_unknown.txt",
                "subdomains.json",
                "urls_all.txt",
                "urls_unique.txt",
                "urls_in_scope.txt",
                "urls_out_of_scope.txt",
                "urls_live.txt",
                "urls_dead.txt",
                "urls_unknown.txt",
                "urls_with_parameters.txt",
                "urls.json",
                "js_files.txt",
                "js_unique.txt",
                "js_live.txt",
                "js_unknown.txt",
                "js_inventory.json",
                "api_endpoints.txt",
                "authentication_paths.txt",
                "admin_paths.txt",
                "config_indicators.txt",
                "backup_indicators.txt",
                "database_indicators.txt",
                "debug_paths.txt",
                "interesting_parameters.txt",
                "suspicious_paths.txt",
            ):
                self.assertTrue((out_dir / "organized" / f).exists(), f"organized/{f}")

            # Verify intelligence/
            for f in (
                "asset_inventory.json",
                "interesting_assets.json",
                "exposure_indicators.json",
                "takeover_candidates.json",
            ):
                self.assertTrue((out_dir / "intelligence" / f).exists(), f"intelligence/{f}")

            # Verify reports/
            for f in ("report.html", "report.json", "report.txt"):
                self.assertTrue((out_dir / "reports" / f).exists(), f"reports/{f}")

            # Verify HTML dashboard content (Phase 9)
            html_report = (out_dir / "reports" / "report.html").read_text(encoding="utf-8")
            for required_label in (
                "Total discovered subdomains",
                "Unique subdomains",
                "In-scope assets",
                "Live hosts",
                "Dead hosts",
                "Unknown hosts",
                "Bug Bounty asset intelligence",
            ):
                self.assertIn(required_label, html_report)

            # Verify staging-api.example.com (HTTP 403) is classified as LIVE
            live_subs = (
                (out_dir / "organized" / "subdomains_live.txt")
                .read_text(encoding="utf-8")
                .splitlines()
            )
            self.assertIn("staging-api.example.com", live_subs)
            self.assertGreaterEqual(len(bundle["intelligence"]["interesting_assets"]), 1)

    def test_offline_directory_organizer_and_post_redaction_dedup(self):
        with tempfile.TemporaryDirectory() as tmp:
            scan_dir = Path(tmp) / "ring.com"
            scan_dir.mkdir(parents=True, exist_ok=True)
            (scan_dir / "subdomains.json").write_text(
                json.dumps(
                    {
                        "root": "ring.com",
                        "hosts": [
                            {"hostname": "api.ring.com", "sources": ["crtsh"]},
                            {"hostname": "API.RING.COM.", "sources": ["otx"]},
                            {"hostname": "evilring.com", "sources": ["otx"]},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (scan_dir / "urls_all.json").write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "url": "https://api.ring.com/devices_api/v1?code=secret1",
                                "sources": ["wayback"],
                                "timestamp": "20250101000000",
                            },
                            {
                                "url": "https://api.ring.com/devices_api/v1?code=secret2",
                                "sources": ["commoncrawl"],
                                "timestamp": "20250201000000",
                            },
                            {
                                "url": "https://ring.com/builder/%3CbaseBackendBucketUrl%3E/rsb/js/heap.min.js",
                                "sources": ["wayback"],
                            },
                            {
                                "url": "http://www.ring.com/%20onmousedown=",
                                "sources": ["wayback"],
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            orig_sub_hash = (scan_dir / "subdomains.json").read_bytes()
            scope = ScopeManager("ring.com")
            engine = ResultsProcessingEngine(scope)
            bundle = engine.organize_existing_directory(
                scan_dir, preserve_top_level=True
            )
            # Top-level file preserved byte-for-byte
            self.assertEqual((scan_dir / "subdomains.json").read_bytes(), orig_sub_hash)
            # Post-redaction URL duplicates merged into 1 unique URL with both sources
            self.assertEqual(len(bundle["historical"]["records"]), 1)
            self.assertEqual(
                bundle["historical"]["records"][0]["sources"],
                ["wayback", "commoncrawl"],
            )
            # Malformed HTML/template artifacts rejected
            self.assertEqual(len(bundle["historical"]["malformed"]), 2)
            # API endpoint detected via api.ring.com and devices_api
            self.assertEqual(
                bundle["sensitive"]["classified_counts"]["api_endpoints"], 1
            )
            api_lines = (
                (scan_dir / "organized" / "api_endpoints.txt")
                .read_text(encoding="utf-8")
                .splitlines()
            )
            self.assertEqual(len(api_lines), 1)
            # Secret values redacted across all generated files
            for sub in ("raw", "organized", "intelligence", "reports"):
                for p in (scan_dir / sub).rglob("*"):
                    if p.is_file():
                        txt = p.read_text(encoding="utf-8")
                        self.assertNotIn("secret1", txt)
                        self.assertNotIn("secret2", txt)


if __name__ == "__main__":
    unittest.main()
