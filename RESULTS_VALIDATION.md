# SubReconX — Offline Results Intelligence & Bug Bounty Validation Report

**Date:** 2026-11-10
**Target Dataset (Copy):** `results/ring.com` copied to an isolated validation workspace (`ring.com_copy`) + synthetic multi-scenario dataset (`examples/sample_validation_dataset`)
**Network Activity:** `0` packets (enforced via socket/urllib monkeypatch guard raising `RuntimeError` on any connection attempt)
**Original Scan Preservation:** `34 / 34` files in `/home/mohamed/SubReconX/results/ring.com` verified byte-for-byte identical via SHA-256 before and after testing (`0` files modified, `0` files deleted, `0` subdirectories added to the original folder).

---

## 1. Executive Summary & PASS/FAIL Matrix

| # | Validation Requirement | Dataset Verified | Status |
|---|---|---|---|
| 1 | Inspect new results directory structure (`raw/`, `organized/`, `intelligence/`, `reports/`) | `ring.com_copy` & `sample_validation_dataset` | **PASS** |
| 2 | Verify `raw/`, `organized/`, `intelligence/`, and `reports/` subdirectories and all expected files | `37 / 37` required files present in both datasets | **PASS** |
| 3 | Run offline organizer against a **copy** of existing results without modifying original results | `ring.com_copy` (`34/34` original SHA-256 hashes unchanged) | **PASS** |
| 4 | Verify duplicate removal for subdomains and historical URLs (including post-redaction duplicates) | `ring.com_copy` (`47,466` -> `44,382` URLs) & `sample_validation_dataset` (`18` -> `11` hosts) | **PASS** |
| 5 | Verify exact root-domain boundary validation (`evilring.com`, `not-ring.com`, `ring.com.attacker.example` rejected) | `sample_validation_dataset` & unit tests | **PASS** |
| 6 | Verify `LIVE`, `DEAD`, and `UNKNOWN` classification using local fixtures | `sample_validation_dataset` (`5 LIVE`, `2 DEAD`, `3 UNKNOWN` in-scope) | **PASS** |
| 7 | Verify HTTP `401`, `403`, `404`, and `500` are classified as `LIVE` | `sample_validation_dataset` (`portal`, `admin`, `dev-404`, `err500`) | **PASS** |
| 8 | Verify timeouts (`TimeoutError`), rate limits (`HTTP 429`), and `SERVFAIL` are classified as `UNKNOWN` | `sample_validation_dataset` (`slow-timeout`, `ratelimited`, `servfail`) | **PASS** |
| 9 | Verify Bugcrowd scope inclusion and exclusion rules (`out_of_scope_hosts`, `out_of_scope_patterns`, `strict_scope`) | `sample_validation_dataset` (`status.ring.com` excluded) & unit tests | **PASS** |
| 10 | Verify wildcard scope behavior (`*.ring.com`, `*.api.example.com` with explicit exclusions) | `sample_validation_dataset` & `Phase6And7ScopeAndIntelligenceTests` | **PASS** |
| 11 | Verify sensitive parameter redaction in every output format (`raw/`, `organized/`, `intelligence/`, `reports/`) | `0` leaked secret values across all generated TXT/JSON/HTML files | **PASS** |
| 12 | Verify JavaScript (`74` clean JS assets) and API (`126` endpoints) classification | `ring.com_copy` & `sample_validation_dataset` | **PASS** |
| 13 | Verify internal count consistency across `report.html`, `report.json`, `report.txt`, and `organized/*.txt` | `ring.com_copy` & `sample_validation_dataset` (`100%` match) | **PASS** |
| 14 | Check for missing files and unexpected empty output files | `0` missing files; only categories with `0` hits are legitimately `0` bytes | **PASS** |
| 15 | Verify HTML dashboard search inputs and interactive pill filters across all tables | Programmatic DOM/JS check on `reports/report.html` | **PASS** |

---

## 2. Original Results Integrity Check (`/home/mohamed/SubReconX/results/ring.com`)

Before running the offline organizer on the copy, all `34` original top-level files in `/home/mohamed/SubReconX/results/ring.com` were hashed with SHA-256. After all offline validation runs completed:

- **Original file count before:** `34`
- **Original file count after:** `34`
- **Added subdirectories in original `results/ring.com`:** `0`
- **SHA-256 hash matches:** `34 / 34` (`100%` identical)

Sample verified SHA-256 digests in `/home/mohamed/SubReconX/results/ring.com`:
- `subdomains.json`: unchanged (`101` host records from original passive + historical scan)
- `urls_all.json`: unchanged (`47,466` historical URL records)
- `js_inventory.json`: unchanged (`76` historical JS records)

---

## 3. End-to-End Offline Validation on Copy of `ring.com` (`ring.com_copy`)

### 3.1 Subdomain Organization & Classification (`organized/subdomains*.txt` & `subdomains.json`)
| Metric | Count | Verification Details |
|---|---:|---|
| `raw_subdomains` (`raw/subdomains_raw.txt`) | `101` | `87` passive (`certspotter`, `otx`, `root`) + `14` unique hostnames merged from historical URLs |
| `unique_subdomains` (`organized/subdomains_all.txt`) | `101` | Normalized lowercase, trailing dots stripped, syntax validated |
| `in_scope_subdomains` (`organized/subdomains_in_scope.txt`) | `101` | All `101` hosts match `ring.com` or `*.ring.com` boundary |
| `out_of_scope_subdomains` | `0` | No out-of-scope hosts in `ring.com` dataset |
| `live_subdomains` (`organized/subdomains_live.txt`) | `0` | Active DNS/HTTP probing was disabled in the original scan |
| `dead_subdomains` (`organized/subdomains_dead.txt`) | `0` | Unprobed hosts are **never** falsely marked `DEAD` |
| `unknown_subdomains` (`organized/subdomains_unknown.txt`) | `101` | All `101` unprobed hosts accurately classified as `UNKNOWN` (`no DNS or HTTP probe evidence recorded`) |

### 3.2 Historical URL Cleanup, Deduplication & Artifact Rejection (`organized/urls*.txt` & `urls.json`)
| Metric | Count | Verification Details |
|---|---:|---|
| Raw input URLs (`raw/urls_raw.txt`) | `47,466` | Preserved in `raw/urls_raw.txt` with sensitive query values redacted |
| Post-redaction duplicate URLs removed | `3,023` | URLs differing only in redacted sensitive query values (e.g. `?code=...`) merged with combined `sources` and latest `timestamp` |
| Malformed / HTML scraping artifacts rejected | `61` | Rejected URLs containing HTML/JS scraping junk (`%22` quotes, `%3CbaseBackendBucketUrl%3E` template placeholders, `/%20onmousedown=` attribute fragments) |
| Clean unique URLs (`organized/urls_unique.txt` & `urls_all.txt`) | `44,382` | `47,466 - 3,023 - 61 = 44,382` |
| In-scope URLs (`organized/urls_in_scope.txt`) | `44,382` | Exact root-domain boundary enforced |
| Out-of-scope URLs (`organized/urls_out_of_scope.txt`) | `0` | None present in `ring.com` archive set |
| Parameterized URLs (`organized/urls_with_parameters.txt`) | `15,731` | Query parameter names extracted; sensitive values replaced with `[REDACTED]` |
| `urls_live.txt` / `urls_dead.txt` / `urls_unknown.txt` | `0` / `0` / `44,382` | Matches host liveness state (`UNKNOWN` when unprobed) |

### 3.3 JavaScript, API & Sensitive Indicator Classification (`ring.com_copy/organized/`)
| Output File / Category | Count | Notes |
|---|---:|---|
| `js_files.txt` / `js_unique.txt` / `js_inventory.json` | `74` | Clean JS assets (2 malformed `%3CbaseBackendBucketUrl%3E` entries removed from original `76`) |
| `api_endpoints.txt` | `126` | Matches `/api/`, `/v1/`–`/v5/`, `/graphql`, `*_api` (e.g. `devices_api`), and paths on `api.ring.com` |
| `authentication_paths.txt` | `4` | OAuth/signin/token endpoints |
| `admin_paths.txt` | `4` | Administrative/portal paths |
| `backup_indicators.txt` | `6` | Archive/backup references |
| `debug_paths.txt` | `3` | Internal/debug/staging path references |
| `interesting_parameters.txt` | `1,033` | URLs containing security-relevant query parameter names (`redirect`, `token`, `code`, `key`, `id`, etc.) |
| `suspicious_paths.txt` | `17` | Non-informational path indicators |
| Total Sensitive Indicators (`reports/report.json`) | `1,166` | `administrative: 4`, `api: 126`, `authentication: 7`, `backups: 6`, `business_sensitive: 2`, `interesting_parameters: 1,018`, `internal_resources: 3` |

---

## 4. Synthetic Multi-Scenario Validation (`examples/sample_validation_dataset`)

To validate scenarios not present in the passive-only `ring.com` scan (such as varied HTTP status codes, timeouts, DNS `NXDOMAIN`/`SERVFAIL`, Bugcrowd exclusions, and out-of-scope lookalike domains), we created `examples/sample_validation_dataset` and ran the offline organizer against it.

### 4.1 Subdomain Deduplication, Root-Boundary & Bugcrowd Scope Rules
- **Raw subdomain inputs:** `18`
- **Deduplicated & normalized:**
  - `api.ring.com`, `API.RING.COM.`, and `*.api.ring.com` -> merged into `1` record (`api.ring.com`) with combined sources `["crtsh", "certspotter"]`.
- **Root-domain boundary enforcement (rejected into `malformed_entries`):**
  - `evilring.com` -> rejected (`outside-root-boundary:evilring.com`)
  - `not-ring.com` -> rejected (`outside-root-boundary:not-ring.com`)
  - `ring.com.attacker.example` -> rejected (`outside-root-boundary:ring.com.attacker.example`)
  - `bad host..ring.com` -> rejected (invalid RFC 1035 hostname syntax)
  - `https://portal.ring.com:8443/login` -> rejected as raw hostname syntax error while `portal.ring.com` is retained
- **Bugcrowd exclusion enforcement:**
  - `status.ring.com` matches `is_within_root_boundary("ring.com") == True`, but is listed in `out_of_scope_hosts=["status.ring.com"]`.
  - Result: `in_scope_subdomains = 10`, `out_of_scope_subdomains = 1` (`status.ring.com`), and `status.ring.com` is never actively probed (`reason: "out of authorized scope (not actively probed)"`).

### 4.2 Liveness Classification Verification (`LIVE` / `DEAD` / `UNKNOWN`)
| Hostname | Simulated Evidence | Expected | Actual | Reason Recorded |
|---|---|---|---|---|
| `api.ring.com` | HTTPS `200 OK` | `LIVE` | `LIVE` | `HTTP 200 received over HTTPS` |
| `portal.ring.com` | HTTPS `401 Unauthorized` | `LIVE` | `LIVE` | `HTTP 401 received over HTTPS` |
| `admin.ring.com` | HTTPS `403 Forbidden` | `LIVE` | `LIVE` | `HTTP 403 received over HTTPS` |
| `dev-404.ring.com` | HTTPS `404 Not Found` | `LIVE` | `LIVE` | `HTTP 404 received over HTTPS` |
| `err500.ring.com` | HTTPS `500 Internal Server Error` | `LIVE` | `LIVE` | `HTTP 500 received over HTTPS` |
| `ratelimited.ring.com` | HTTPS `429 Too Many Requests` | `UNKNOWN` | `UNKNOWN` | `rate limit encountered (HTTP 429)` |
| `slow-timeout.ring.com` | HTTP & HTTPS `TimeoutError` | `UNKNOWN` | `UNKNOWN` | `TimeoutError: timed out after 8.0s` |
| `servfail.ring.com` | DNS `SERVFAIL` | `UNKNOWN` | `UNKNOWN` | `inconclusive DNS response (SERVFAIL)` |
| `dead-nx.ring.com` | DNS `NXDOMAIN` (dangling CNAME) | `DEAD` | `DEAD` | `dangling CNAME target returns NXDOMAIN` |
| `conn-refused.ring.com` | HTTP & HTTPS `ConnectionRefusedError` | `DEAD` | `DEAD` | `ConnectionRefusedError: [Errno 111] Connection refused` |
| `status.ring.com` | Excluded by Bugcrowd scope | `UNKNOWN` | `UNKNOWN` | `out of authorized scope (not actively probed)` |

### 4.3 Sensitive Parameter Redaction Verification
The sample dataset injected 6 raw secret values (`secret_jwt_12345`, `another_secret_999`, `AKIAIOSFODNN7EXAMPLE`, `authcode_1`, `authcode_2`, `p1`) across in-scope and out-of-scope URLs. Every generated file across `raw/`, `organized/`, `intelligence/`, and `reports/` was scanned for those substrings:
- **Leaked secret occurrences:** `0` (`leaked_secrets: []`)
- Parameter names (`access_token`, `api_key`, `code`, `password`) were preserved in `params` arrays while values were replaced with `[REDACTED]`.

---

## 5. Cross-Format Report Consistency (`report.html`, `report.json`, `report.txt`)

Both `ring.com_copy` and `examples/sample_validation_dataset` were checked for exact agreement across `reports/report.json` (`meta.canonical_metrics`), `reports/report.txt` (`ASSET SUMMARY`), `reports/report.html` (summary stat cards and section headers), and `organized/*.txt` line counts:

| Canonical Metric | `ring.com_copy` (`JSON` / `TXT` / `HTML` / `organized/`) | `sample_validation_dataset` (`JSON` / `TXT` / `HTML` / `organized/`) | Consistent? |
|---|---:|---:|:---:|
| `total_discovered_subdomains` | `101` | `18` | **YES** |
| `unique_subdomains` | `101` | `11` | **YES** |
| `in_scope_assets` | `101` | `10` | **YES** |
| `out_of_scope_subdomains` | `0` | `1` | **YES** |
| `live_hosts` | `0` | `5` | **YES** |
| `dead_hosts` | `0` | `2` | **YES** |
| `unknown_hosts` | `101` | `3` | **YES** |
| `historical_urls` (in-scope) | `44,382` | `8` | **YES** |
| `historical_urls_unique` | `44,382` | `11` | **YES** |
| `javascript_assets` | `74` | `1` | **YES** |
| `sensitive_indicators` | `1,166` | `20` | **YES** |

### HTML Dashboard Interactive Search & Filter Verification
Inspection of `reports/report.html` confirmed:
- All 7 data tables have explicit IDs and bound search inputs (`input.search[data-target=...]`): `intel-table`, `risk-table`, `subdomains-table`, `dns-table`, `js-table`, `sensitive-table`, and `takeover-table`.
- Interactive filter pill buttons (`button.filter-btn`) are bound to `intel-table` (`All`, `High Priority`, `Medium`, `LIVE`, `API`, `Admin`, `Auth`, `Non-Prod`) and `subdomains-table` (`All`, `LIVE`, `DEAD`, `UNKNOWN`, `In Scope`, `Out of Scope`).
- `applyTableFilter(tableId)` combines text search (`input.search`) and active pill filter (`button.filter-btn.active`) simultaneously without external JS dependencies.

---

## 6. Genuine Bugs Found & Fixed During Offline Validation

1. **Post-Redaction Historical URL Duplicates (`engines/historical_url_engine.py`, `engines/results_engine.py`)**:
   - *Issue:* Historical URLs that differed only in sensitive query parameter values (e.g. `?code=val1` vs `?code=val2`) produced identical lines after `redact_url()` (`?code=[REDACTED]`), resulting in `3,023` duplicate lines in `ring.com`'s `urls_all.txt`.
   - *Fix:* Deduplicated records on `redact_url(normalized)` while merging source attribution lists and keeping the latest timestamp (`47,466` -> `44,382` unique clean URLs).
2. **HTML/JS Scraping Artifacts in Historical URLs (`utils/url_utils.py`)**:
   - *Issue:* Wayback/CommonCrawl records in `ring.com` included `61` malformed URLs containing unescaped/encoded quotes (`%22`), template placeholders (`%3CbaseBackendBucketUrl%3E`), and HTML event attributes (`/%20onmousedown=`).
   - *Fix:* Hardened `split_url()` with `_HTML_ARTIFACT_PATH_RE` and raw whitespace rejection so malformed scraping artifacts are quarantined into `malformed` rather than polluting `urls_unique.txt` or `js_files.txt`.
3. **API Endpoint Classification Coverage (`intelligence/sensitive_patterns.json`, `engines/sensitive_detection_engine.py`)**:
   - *Issue:* `api_endpoints.txt` missed `*_api` path segments (such as `/devices_api/` in `ring.com`) and non-root endpoints hosted on dedicated `api.*` subdomains.
   - *Fix:* Added `(?:^|/)[a-z0-9_-]+[_-]api(?:/|$)` to API path patterns and classified non-root paths on `api.*` / `*.api.*` hosts as API endpoints (`126` API endpoints identified in `ring.com_copy`).
4. **Historical URL Subdomain Inflation in `raw_subdomains` (`engines/results_engine.py`)**:
   - *Issue:* `ResultsProcessingEngine.process()` appended a raw subdomain entry for every historical URL row (`44,382` rows) and ran both `if subdomains.raw_records:` and `if subdomains.all_hosts:`, inflating `raw_subdomains` to `44,584`.
   - *Fix:* Changed `if subdomains.all_hosts:` to `elif` and aggregated unique hostnames from historical URLs before merging into `raw_sub_inputs`, yielding the exact `101` subdomain count.
5. **$O(N^2)$ List Deduplication Bottlenecks on Large URL Datasets (`engines/results_engine.py`, `engines/sensitive_detection_engine.py`, `engines/url_filter_engine.py`)**:
   - *Issue:* `if item not in bucket:` list scans across `47,466` URLs caused $O(N^2)$ behavior during offline organization.
   - *Fix:* Replaced linear list membership checks with $O(1)$ `set` tracking in `migrate_existing_results()`, `SensitiveDetectionEngine.run()`, and `URLFilterEngine.run()`.
6. **In-Memory Query & Malformed URL Redaction (`engines/historical_url_engine.py`, `engines/results_engine.py`)**:
   - *Issue:* `HistoricalRecord.query` and `HistoricalResult.malformed` stored unredacted strings prior to JSON serialization.
   - *Fix:* Applied `redact_url()` when populating `raw_records`, `malformed`, and `HistoricalRecord.query`.
7. **Dashboard Table Search & Filter Controls (`engines/report_engine.py`)**:
   - *Issue:* `#risk` and `#takeover` tables lacked search inputs and table IDs, and there were no interactive category pill filters.
   - *Fix:* Added search inputs and table IDs to all tables plus interactive `.filter-btn` pill bars and `applyTableFilter(tableId)`.

---

## 7. Unit & Integration Test Suite Results

```text
$ python3 -m compileall -q .
$ python3 -m unittest discover -s tests -t .
Ran 148 tests in 0.495s

OK
```
