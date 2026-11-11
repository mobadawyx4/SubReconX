# SubReconX — Technical & Security Audit Report

**Audit Date:** 2026-11-10
**Target Directory:** `/home/mohamed/SubReconX`
**Version Audited:** `1.0.0`
**Python Environment:** Python 3.12 (Standard Library Only)

---

## Executive Summary

SubReconX is a well-structured, standard-library-only Python reconnaissance and exposure-intelligence framework designed for authorized security assessments. The codebase compiles cleanly, has **zero third-party package dependencies**, makes **zero calls to external security tools or subprocesses**, and passes all **125 offline unit tests** (`0.156s`).

All 11 core functional areas specified for the framework are implemented and operational. During the initial audit, several bugs, concurrency flaws, incomplete `--resume` / database lifecycle behaviors, report omissions, and subtle security/resilience edge cases were identified and **have now been fully remediated and verified across 134 passing unit and integration tests**.

---

## 1. Verification Results & Independent QA Matrix

| # | Verification Item | Status | Details |
| :--- | :--- | :--- | :--- |
| 1 | Unit & Integration Test Suite | **PASS** | **134 tests** across 15 test modules executed via `python3 -m unittest discover -s tests -t . -v` (`0.20s`, `OK`). |
| 2 | Python Bytecode Compilation | **PASS** | `python3 -m compileall -q .` exited `0` with zero syntax errors or warnings across all 60 Python files. |
| 3 | CLI `--version` and `--help` | **PASS** | `python3 main.py --version` (`SubReconX 1.0.0`) and `python3 main.py --help` verified. |
| 4 | Engine Placeholder / Stub Inspection | **PASS** | AST static analysis of all 60 `.py` files confirmed zero `pass`-only stubs, zero `NotImplementedError`, and zero `TODO`/`FIXME` markers. |
| 5 | Wayback CDX & Common Crawl Integration | **PASS** | Verified multi-page `resumeKey` pagination in `wayback_cdx.py`, `collinfo.json` discovery + `*.{domain}/*` JSON-lines parsing in `commoncrawl.py`, and `url_list` pagination in `otx.py`. |
| 6 | URL Filtering vs. Local Fixtures | **PASS** | Verified all 16 file-extension categories (`extension_categories.json`), `.env*` prefix matching, deduplication, and generation of all 15+ category output files plus `filter_stats.json`/`.txt`. |
| 7 | Sensitive Parameter & Secret Redaction | **PASS** | Verified redaction of sensitive parameter values, userinfo, HTTP auth/cookie headers, JWTs, AWS keys, GitHub tokens, Slack tokens, private keys, and hex/base64 secrets across DB, cache, and reports. |
| 8 | Native DNS & HTTP Integration | **PASS** | Verified RFC 1035 wire encoding/decoding, compression loop guard, multi-hop CNAME chains, dangling CNAME classification, HTTP chunked transfer limits, title/tech extraction, and redirect guards. |
| 9 | Passive Takeover Fingerprint Matching | **PASS** | Verified all **36** provider fingerprints (`takeover_fingerprints.json`), NXDOMAIN dangling scoring, HTTP error-indicator scoring, and false-positive suppression on live resolving targets. |
| 10 | HTML, JSON & TXT Report Generation | **PASS** | Verified `report.html`, `report.json`, and `report.txt` generation, client-side filtering tables, TLS/JS sections, and end-to-end recursive secret redaction. |
| 11 | Zero External Security Tool Dependencies | **PASS** | Verified zero third-party packages (`requirements.txt`) and zero `subprocess`, `os.system`, or external binary calls (`subfinder`, `amass`, `httpx`, `dnsx`, `nuclei`, etc.). |
| 12 | Scope Enforcement & SSRF Protections | **PASS** | Verified label-aware domain boundary enforcement, wildcard connection rejection, port allow-listing, per-hop redirect validation, and blocking of loopback/private/link-local/CGNAT/multicast/IPv4-mapped IPv6 addresses. |

---

## 2. Feature Implementation Audit

### Completed Features

1. **Subdomain Enumeration (`engines/subdomain_engine.py`, `sources/`)**
   - Passive enumeration implemented via Certificate Transparency (`crt.sh`, `certspotter`) and AlienVault OTX (`otx`) in `sources/source_manager.py`.
   - Per-source failure isolation (`_guard`), SQLite TTL caching (`utils/cache.py`), wildcard stripping, label-aware scope validation (`is_within_domain`), and source attribution merging.
   - Optional bounded DNS wordlist brute-forcing (`--wordlist`, `wordlists/subdomains.txt`).
   - Writes `subdomains.txt` and `subdomains.json`.

2. **DNS Resolution (`protocols/dns_protocol.py`, `engines/dns_engine.py`)**
   - Native RFC 1035 UDP/TCP wire-protocol encoder and decoder supporting `A`, `AAAA`, `CNAME`, `NS`, `MX`, `TXT`, and `SOA` records, including DNS name compression pointer decoding and loop protection (`max_depth=32`).
   - Automatic TCP fallback on truncated (`TC` flag) UDP responses and OS stub resolver fallback (`safe_getaddrinfo`) if all raw queries fail.
   - CNAME chain construction, single-hop dangling CNAME follow-up, and private/reserved IP flagging (`suspicious`).
   - Writes `dns_results.json`, `resolved.txt`, `unresolved.txt`, and `cname_records.txt`.

3. **HTTP/HTTPS Live Detection (`protocols/http_protocol.py`, `engines/live_host_engine.py`)**
   - Custom `asyncio` HTTP/1.1 client with `HTTPS` and `HTTP` probing, chunked transfer decoding, hard body size caps (`MAX_HTTP_BODY = 256 KB`), HTML `<title>` extraction, and passive header/cookie/meta-generator technology fingerprinting (`detect_technologies`).
   - Per-hop redirect resolution and scope/SSRF validation up to `MAX_REDIRECTS = 5`.
   - Verified TLS handshake first, with an explicitly flagged unverified fallback (`tls_verified=False`) for asset inventory.
   - Writes `live_hosts.txt`, `http_results.txt`, and `http_results.json`.

4. **TLS Certificate Inspection (`protocols/tls_protocol.py`, `engines/tls_engine.py`)**
   - Inspects certificate subject, issuer, SANs (`DNS` and `IP Address`), validity timestamps, days until expiry, expiration status, and wildcard/hostname matching.
   - Falls back to unverified DER extraction (`_decode_der`) when chain verification fails, recording `verified=False` and `verification_error`.
   - Writes `tls_results.json`.

5. **Historical URL Collection (`sources/wayback_cdx.py`, `sources/commoncrawl.py`, `sources/otx.py`, `engines/historical_url_engine.py`)**
   - Collects historical URLs concurrently from Wayback Machine CDX (with `resumeKey` pagination), Common Crawl index API (`collinfo.json` discovery + JSON-lines parsing), and AlienVault OTX (`url_list` pagination).
   - Separates in-scope (`urls_in_scope.txt`), out-of-scope, and malformed URLs (`urls_all.txt`, `urls_all.json`).

6. **URL Normalization and Deduplication (`utils/url_utils.py`, `engines/url_normalizer.py`)**
   - Lowercases scheme and hostname, converts IDN to punycode, strips credentials/userinfo and fragments, removes default ports (`:80` for HTTP, `:443` for HTTPS), uppercases percent-encoding triples, collapses redundant `/./` and `/../` segments, and preserves query parameter order.

7. **File Extension Filtering (`engines/url_filter_engine.py`, `intelligence/extension_categories.json`)**
   - Classifies URLs across 16 categories (`javascript`, `xml`, `archives`, `json`, `text`, `pdf`, `documents`, `jspx`, `images`, `php`, `environment`, `logs`, `backups`, `databases`, `yaml`, `config`), including `.env*` basename prefix matching.
   - Guarantees creation of all 15+ category files plus `filter_stats.txt` and `filter_stats.json`.

8. **Sensitive Path & Parameter-Name Detection (`engines/sensitive_detection_engine.py`, `utils/redaction.py`, `intelligence/sensitive_patterns.json`)**
   - Matches URL paths and query parameter names against 9 exposure categories (`environment_configuration`, `git_exposure`, `backups`, `databases`, `administrative`, `internal_resources`, `authentication`, `business_sensitive`, `logging`).
   - Redacts sensitive parameter values, userinfo, and secret-like tokens (JWTs, AWS keys, GitHub tokens, Slack tokens, private keys, hex/base64 secrets) with `[REDACTED]`.
   - Writes `suspicious_paths.txt`, `sensitive_parameters.txt`, `interesting_urls.txt`, and `sensitive_indicators.json`.

9. **JavaScript Inventory (`engines/javascript_engine.py`)**
   - Inventories `.js`, `.mjs`, and `.cjs` assets from historical and live URLs.
   - Supports optional `--js-analysis` to fetch in-scope JS files and statically extract relative/absolute endpoints.
   - Writes `js_files.txt`, `js_inventory.json`, and `js_endpoints.txt`.

10. **Passive Subdomain Takeover Analysis (`engines/takeover_engine.py`, `intelligence/takeover_fingerprints.json`)**
    - Evaluates CNAME records against 36 cloud/SaaS provider fingerprints (GitHub Pages, Heroku, AWS S3, Azure, Netlify, Vercel, Shopify, Fastly, CloudFront, etc.), DNS resolution status (`NXDOMAIN`/unresolvable), and passive HTTP error body indicators.
    - Computes confidence scores (`0–95`) and classifications (`Likely`, `Potential`, `Needs Manual Review`) without attempting resource claiming.
    - Writes `takeover_candidates.txt` and `takeover_candidates.json`.

11. **Explainable Risk Scoring (`engines/risk_engine.py`)**
    - Generates structured findings with severity, numeric score, rationale, evidence, and remediation advice across takeover, sensitive paths, TLS issues, private DNS records, HTTP-only hosts, and historical file exposures.
    - Enforces a safety cap so automated indicators are never marked `critical`.
    - Writes `risk_assessment.txt` and `risk_assessment.json`.

12. **HTML, JSON, and TXT Reporting (`engines/report_engine.py`)**
    - Generates self-contained dark-mode `report.html` (with client-side table search filters), redacted `report.json`, and formatted `report.txt`, plus `scan_summary.json`.

---

## 3. Incomplete Features

1. **Incomplete `--resume` Behavior in `core/orchestrator.py`**
   - When `--resume` is passed alongside enabled phases (e.g., `python3 main.py example.com --resume`), the orchestrator still executes live network scans for `passive`, `dns`, `live`, `tls`, and `historical` instead of hydrating from the SQLite database when prior data exists. DB hydration is currently only triggered when a phase is *disabled* or raises an unhandled exception.
   - Conversely, when `passive`, `dns`, `live`, or `historical` are disabled without `--resume`, `_load_subdomains()`, `_dns_from_db()`, `_http_from_db()`, and `_historical_from_db()` are called unconditionally, whereas `_tls_from_db()`, `_filter_from_db()`, `_javascript_from_db()`, `_sensitive_from_db()`, and `_takeover_from_db()` are gated behind `if cfg.resume:`.
   - `_dns_from_db()` (`core/orchestrator.py:608-639`) does not reconstruct `dangling` or `suspicious` DNS entries when loading from SQLite.
   - `_sensitive_from_db()` (`core/orchestrator.py:804-823`) only populates `result.indicators` and leaves `suspicious_paths`, `sensitive_parameters`, and `interesting_urls` empty (`[]`), causing resumed reports to display `0` for those metrics.

2. **Missing Report Sections for TLS and JavaScript (`engines/report_engine.py`)**
   - Although `tls` and `javascript` are full scan phases stored in `bundle["tls"]` and `bundle["javascript"]`, `build_html()` and `build_text()` have no section or table for **TLS certificate inventory** or **JavaScript assets / extracted endpoints**.
   - `engines/tls_engine.py` only writes `tls_results.json` and does not write a human-readable `tls_results.txt`.

3. **Unpopulated TLS `serial_number` Field (`protocols/tls_protocol.py`)**
   - `TLSResult.serial_number` (`protocols/tls_protocol.py:34`) and the `serial_number` column in `tls_results` (`core/database.py:83`) are defined, but `inspect()` (`protocols/tls_protocol.py:248-257`) never extracts `cert.get("serialNumber")` into `result.serial_number`, leaving it permanently `""`.

4. **Unused JS Secret Indicator Pattern & Missing JS Source Attribution (`engines/javascript_engine.py`)**
   - `_SECRET_ASSIGN_RE` is defined at `engines/javascript_engine.py:22-25` to detect hardcoded secret assignments in JS files, but is never referenced anywhere.
   - `collect_js_urls()` (`engines/javascript_engine.py:78`) receives bare URL strings (`hist_urls`) rather than `HistoricalRecord` objects, so `JSAsset.sources` is always `[]`.
   - Relative endpoints extracted from JS files (e.g., `"/api/v1/admin"`) are appended to `sensitive_urls` in `core/orchestrator.py:350`, but `SensitiveDetectionEngine.run()` calls `normalize_url()`, which rejects relative paths without a scheme/host — silently dropping all relative JS endpoints from sensitive path analysis.

5. **Historical Subdomains Not Merged into Subdomain Inventory**
   - Historical URL sources (`wayback`, `commoncrawl`, `otx`) frequently uncover additional in-scope subdomains (as seen in `examples/example-report.json`, where OTX URLs contained `api.example.com`, `git.example.com`, `cdn.example.com`, etc. that were absent from CT logs). Because `historical` runs after `passive`/`dns`/`live`, hostnames discovered in historical URLs are never added to the subdomain inventory or resolved.

---

## 4. Missing Features

1. **Git Repository Initialization**
   - The workspace has a `.gitignore` but is not a Git repository (`git init` has not been run).
2. **Batch Database Transactions (`core/database.py`, `core/orchestrator.py`)**
   - All `_persist_*` methods in `core/orchestrator.py` insert records one by one in a loop, where each call opens and commits a separate SQLite transaction (`BEGIN` ... `COMMIT`). For large scans (up to `100,000` historical URLs), performing 100,000 individual disk syncs blocks the event loop and degrades performance. Bulk/batch upsert methods (`executemany` inside a single transaction) are needed.
3. **End-to-End Orchestrator & Async Engine Unit Tests (`tests/`)**
   - While unit tests cover individual parsers and helpers, there are no unit tests covering `Orchestrator` execution, `--resume` hydration, `JavaScriptEngine` analysis, `LiveHostEngine`, `DNSEngine.resolve()`, or `protocols/http_protocol.py` socket/stream handling (`_read_chunked`, redirect chains).

---

## 5. Bugs and Security Issues

### High Severity

1. **Chunked Encoding Memory/Bandwidth DoS (`protocols/http_protocol.py:253-276`)**
   - **Location:** `_read_chunked()` in `protocols/http_protocol.py:271-275`:
     ```python
     take = min(size, limit - len(data))
     if take > 0:
         data.extend(await reader.readexactly(take))
     if take < size:
         await reader.readexactly(size - take)
     ```
   - **Issue:** If a target server responds with `Transfer-Encoding: chunked` and declares a huge chunk size (e.g., `FFFFFFFF\r\n`), `take` is bounded by `limit`, but `await reader.readexactly(size - take)` then attempts to read and allocate the remaining gigabytes in memory before the `while len(data) < limit:` loop can exit.
   - **Fix:** When `take < size` (meaning `len(data)` has reached `limit`), break out of the loop immediately without reading `size - take`, as the connection uses `Connection: close` and is closed in `finally`.

2. **JavaScript Analysis Concurrency & `max_files` Bypass (`engines/javascript_engine.py:156-183`)**
   - **Location:** `JavaScriptEngine.run()` in `engines/javascript_engine.py:156-165`:
     ```python
     async def _analyse(asset: JSAsset) -> None:
         nonlocal analyzed
         if analyzed >= max_files:
             return
         ...
         async with semaphore:
             analyzed += 1
     ```
   - **Issue:** `asyncio.gather(*[_analyse(asset) for asset in ordered])` starts all coroutines simultaneously. Every coroutine evaluates `if analyzed >= max_files:` *before* awaiting `semaphore` (when `analyzed == 0`), so all coroutines pass the guard and queue on the semaphore. If 5,000 JS URLs are discovered, all 5,000 will be downloaded and analyzed despite `max_files: int = 50`.
   - **Fix:** Slice the candidate list before scheduling or re-check `if analyzed >= max_files:` inside `async with semaphore:`.

### Medium Severity

3. **Dangling CNAMEs Misclassified as `resolved = True` (`engines/dns_engine.py:42-44`, `386-399`)**
   - **Location:** `ResolvedHost.resolved` in `engines/dns_engine.py:43-44`:
     ```python
     @property
     def resolved(self) -> bool:
         return bool(self.a or self.aaaa or self.cname)
     ```
   - **Issue:** A hostname with a dangling CNAME (`self.cname` is non-empty, `self.a` and `self.aaaa` are empty, and `self.dangling` is `True` because the target returned `NXDOMAIN`) still evaluates `outcome.resolved == True`. Consequently:
     - Dangling hosts are written to `resolved.txt` instead of `unresolved.txt`.
     - Dangling hosts are passed into `probe_hosts` for HTTP/TLS probing.
     - In `TakeoverEngine.run()` (`engines/takeover_engine.py:207`), if a CNAME target itself has a second CNAME hop that is dangling, `resolved.resolved` returns `True`, masking the dangling state.
   - **Fix:** Define `resolved` as `bool(self.a or self.aaaa or (self.cname and not self.dangling))`.

4. **`Database.clear_domain()` Leaves Orphaned Data (`core/database.py:554-568`)**
   - **Location:** `Database.clear_domain()` in `core/database.py:554-568`.
   - **Issue:** The `tables` tuple omits `tls_results`, `js_assets`, and `scans`. Running `python3 main.py example.com --clear-domain` fails to delete stored TLS certificates, JS asset records, and scan metadata for that domain.

5. **`js_files.txt` Overwritten Between Phases (`engines/url_filter_engine.py:109` vs `engines/javascript_engine.py:194`)**
   - **Issue:** Phase 6 (`filter`) writes `js_files.txt` from classified historical URLs, and Phase 7 (`javascript`) immediately overwrites `js_files.txt`. If `javascript` includes live URLs or normalizes differently, or if only one phase is run, the file contents can diverge or clobber without coordination.

6. **Thread-Unsafe `socket.setdefaulttimeout()` Mutation (`utils/network.py:103-113`)**
   - **Location:** `safe_getaddrinfo()` in `utils/network.py:105-112`.
   - **Issue:** `safe_getaddrinfo()` is executed concurrently across worker threads via `asyncio.to_thread(scope.resolve, ...)`. Mutating process-global `socket.setdefaulttimeout(timeout)` across threads creates a race condition where overlapping calls save and restore another thread's timeout value instead of `None`. Furthermore, `DNSEngine.resolve()` (`engines/dns_engine.py:176`) calls `safe_getaddrinfo()` synchronously on the event loop thread instead of via `asyncio.to_thread()`.

7. **Common Crawl Query Misses Subdomains (`sources/commoncrawl.py:102`)**
   - **Location:** `fetch_urls()` in `sources/commoncrawl.py:101-103`:
     ```python
     query = urllib.parse.urlencode(
         {"url": f"{domain}/*", "output": "json", "limit": str(max(1, limit))}
     )
     ```
   - **Issue:** Passing `url=example.com/*` to the Common Crawl CDX API only matches URLs on the apex domain `example.com`, omitting subdomains (`*.example.com`). Using `url=*.{domain}/*` (or `url={domain}&matchType=domain`) is required to capture subdomain URLs.

### Low Severity

8. **IPv6 Nameserver Incompatibility in `DNSEngine._udp_query()` (`engines/dns_engine.py:85`)**
   - `_udp_query()` hardcodes `socket.socket(socket.AF_INET, socket.SOCK_DGRAM)`. If `/etc/resolv.conf` contains a public IPv6 nameserver (which `parse_resolv_conf()` accepts), `sock_connect` raises an `OSError`. Socket family should be selected via `ipaddress.ip_address(server).version` (`AF_INET6` vs `AF_INET`).
9. **`LiveHostEngine` Ignores CLI `--retries` (`core/orchestrator.py:204-209`, `engines/live_host_engine.py:56`)**
   - `Orchestrator` does not pass `retries=cfg.retries` when instantiating `LiveHostEngine`, leaving it hardcoded to `1`.
10. **Passive Source URL Validation in `CommonCrawl` (`sources/commoncrawl.py:45-47`)**
    - `discover_indexes()` trusts the `cdx-api` URL returned by `collinfo.json` without verifying that the scheme is `https` and the hostname is under `commoncrawl.org`.

---

## 6. Remediation & Implementation Status

All items identified in Sections 3, 4, and 5 have been implemented and verified:

1. **Phase 1 — Security & Stability Fixes (COMPLETED)**
   - Fixed `_read_chunked()` in `protocols/http_protocol.py` so oversized chunk headers stop immediately at `limit` without reading the remaining chunk bytes into memory.
   - Removed thread-unsafe global `socket.setdefaulttimeout()` mutation in `utils/network.py`, added `_SafeRedirectHandler` to `http_request()`, and moved fallback `safe_getaddrinfo()` calls to `asyncio.to_thread()` in `engines/dns_engine.py`.
   - Added `_is_valid_cdx_api()` validation in `sources/commoncrawl.py` and unified `USER_AGENT` in `protocols/http_protocol.py`.
   - Added IPv6 nameserver socket family selection (`AF_INET6` vs `AF_INET`) in `DNSEngine._udp_query()`.

2. **Phase 2 — Core Engine & Data Accuracy Fixes (COMPLETED)**
   - Updated `ResolvedHost.resolved` in `engines/dns_engine.py` (`bool(self.a or self.aaaa or (self.cname and not self.dangling))`) and added multi-hop CNAME resolution for both `A` and `AAAA` records.
   - Fixed `JavaScriptEngine.run()` concurrency guard so `max_files` is checked inside the `asyncio.Semaphore`, preserved `sources` attribution via `source_map`, and resolved relative JS endpoints against the asset origin in `core/orchestrator.py` before running `SensitiveDetectionEngine`.
   - Populated `TLSResult.serial_number` in `protocols/tls_protocol.py` and added `tls_results.txt` output in `engines/tls_engine.py`.
   - Updated `sources/commoncrawl.py` query to `*.{domain}/*` to capture subdomain URLs, and merged historical in-scope subdomains into the subdomain inventory (`_merge_historical_subdomains`).
   - Passed `retries=cfg.retries` to `LiveHostEngine` in `core/orchestrator.py`.

3. **Phase 3 — Database, `--resume`, and Reporting Completeness (COMPLETED)**
   - Added `tls_results`, `js_assets`, and `scans` to `Database.clear_domain()` in `core/database.py`.
   - Made `Database.transaction()` re-entrant and wrapped all `Orchestrator._persist_*` methods in batch transactions.
   - Completed `--resume` hydration across all phases in `core/orchestrator.py`, including full reconstruction of `dangling`/`suspicious` DNS entries in `_dns_from_db()` and `suspicious_paths`/`sensitive_parameters`/`interesting_urls` in `_sensitive_from_db()`.
   - Added **TLS Certificates** and **JavaScript Inventory** sections to `report.html` and `report.txt` in `engines/report_engine.py`, and generated `examples/example-report.html` and `examples/example-report.txt`.

4. **Phase 4 — Test Suite Expansion & Git Initialization (COMPLETED)**
   - Added unit and integration tests in `tests/test_orchestrator_and_engines.py`, `tests/test_http_protocol.py`, `tests/test_database.py`, `tests/test_dns_protocol.py`, `tests/test_reports.py`, and `tests/test_sources.py` (134 total tests passing).
   - Initialized the Git repository on `main`.

5. **Results Intelligence & Bug Bounty Optimization — Phases 1–9 (COMPLETED)**
   - **Phase 1 (Results Organization)**: Implemented `ResultsProcessingEngine` (`engines/results_engine.py`) with deduplication, hostname normalization, syntax validation, root-domain boundary enforcement, source attribution merging, immutable raw data preservation (`raw/`), and non-destructive migration of existing result files.
   - **Phase 2 (Live Subdomain Classification)**: Upgraded `LiveHostEngine` (`engines/live_host_engine.py`) and `protocols/http_protocol.py` to classify hosts into `LIVE` (any valid HTTP/HTTPS status including 200/301/302/401/403/404/500), `DEAD` (definitive DNS NXDOMAIN/no_records or ConnectionRefusedError), and `UNKNOWN` (timeouts, HTTP 429 rate limits, SERVFAIL, resets, or unprobed), with TLS metadata extraction and configurable RPS rate limiting.
   - **Phase 3 (Historical URL Cleanup)**: Upgraded `HistoricalURLEngine` (`engines/historical_url_engine.py`) with deduplication, source/timestamp merging, root-domain boundary checks, extension classification, host-correlated and optional bounded URL liveness checks, and generation of `urls_all.txt`, `urls_unique.txt`, `urls_in_scope.txt`, `urls_out_of_scope.txt`, `urls_live.txt`, `urls_dead.txt`, `urls_unknown.txt`, `urls_with_parameters.txt`, and `urls.json`.
   - **Phase 4 (Intelligent URL Classification)**: Expanded `SensitiveDetectionEngine` (`engines/sensitive_detection_engine.py`) and `intelligence/sensitive_patterns.json` to produce `js_files.txt`, `api_endpoints.txt`, `authentication_paths.txt`, `admin_paths.txt`, `config_indicators.txt`, `backup_indicators.txt`, `database_indicators.txt`, `debug_paths.txt`, `interesting_parameters.txt`, and `suspicious_paths.txt` without substring false positives and with full parameter value redaction.
   - **Phase 5 (JavaScript Inventory Improvements)**: Upgraded `JavaScriptEngine` (`engines/javascript_engine.py`) to track `content_type`, `timestamp`, and `liveness`, generating `js_files.txt`, `js_unique.txt`, `js_live.txt`, `js_unknown.txt`, and `js_inventory.json`.
   - **Phase 6 (Bug Bounty Asset Intelligence)**: Implemented `AssetIntelligenceEngine` (`engines/asset_intelligence_engine.py`) to prioritize interesting assets and generate explainable indicators in `intelligence/asset_inventory.json`, `interesting_assets.json`, `exposure_indicators.json`, and `takeover_candidates.json`.
   - **Phase 7 (Authorized Scope Management)**: Upgraded `ScopeManager` (`core/scope_manager.py`) and CLI (`main.py`) to support Bugcrowd/Bug Bounty JSON and text scope files, `strict_scope` (no implicit `*.root` assumption unless wildcard rule is present), explicit `out_of_scope` exclusions overriding inclusions, `allow_active_probing` (`--passive-only`), and `--rate-limit`.
   - **Phase 8 & 9 (Improved Output Structure & HTML Dashboard)**: Organized output into `raw/`, `organized/`, `intelligence/`, and `reports/` while preserving top-level outputs, and upgraded `engines/report_engine.py` with Bug Bounty summary cards and the prioritized asset intelligence table. Verified with **147 passing unit and integration tests** (`tests/test_bug_bounty_optimization.py`).
