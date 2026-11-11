# SubReconX

**Standalone, standard-library-only reconnaissance and exposure-intelligence framework for authorized security testing.**

SubReconX performs passive subdomain discovery, native DNS analysis, safe HTTP/HTTPS probing, TLS certificate inspection, historical URL collection, file-extension filtering, sensitive path/parameter indicators, JavaScript inventory, passive takeover checks, risk scoring, and HTML/JSON/TXT reporting — without calling `subfinder`, `amass`, `nmap`, `nuclei`, `curl`, or any other external tool.

> **Authorization required.** Only use SubReconX against domains you own or have explicit written permission to test. The CLI refuses to start active phases until you confirm authorization or pass `--yes`.

---

## Highlights

- **Zero third-party dependencies** — Python standard library only.
- **No subprocess calls** to security tooling; protocol clients are implemented in Python.
- **Scope-aware by construction** — label-aware domain matching, extra scope files, and wildcard entries that are never treated as connectable hosts.
- **SSRF-resistant** — every connection resolves the host, rejects loopback/private/link-local/reserved/multicast addresses, pins the approved IP, and validates every redirect hop.
- **Read-only** — GET/HEAD-style probing only; no exploitation, brute force beyond an optional DNS wordlist, or file-content retrieval.
- **Secrets stay out of outputs** — sensitive query values and userinfo are redacted in files, reports, and the database.
- **Resumable** — SQLite storage lets `--resume` and report-only runs reuse previous results.
- **Explainable risk** — every finding carries a severity, score, evidence, and a note describing what it does *not* prove.
- **Self-contained reports** — a single HTML file, plus machine-readable JSON and plain text.

---

## Requirements

- Python **3.10+** (tested on 3.12).
- Outbound HTTPS and DNS access for passive sources and probing.
- No `pip install` step. `requirements.txt` intentionally contains no packages.

---

## Quick start

```bash
cd SubReconX

# Verify the install
python3 main.py --version

# Run every phase against an authorized target
python3 main.py example.com

# Passive + DNS + live probing + TLS + report
python3 main.py example.com --passive --dns --live --tls --report -y

# Historical URLs, file filtering, sensitive indicators, JS inventory
python3 main.py example.com --historical --filter --sensitive --javascript --report

# Sub-commands & Bug Bounty examples
python3 main.py example.com --scope-file examples/bugcrowd-scope.json --strict-scope --rate-limit 5 -y

# Passive-only reconnaissance (zero active DNS/HTTP/TLS packets)
python3 main.py example.com --passive-only

# Reuse stored results and regenerate the report
python3 main.py example.com --report --resume
```

If you do not pass any phase flag, **all phases are enabled**. Explicit phase flags automatically pull in their dependencies:

| Phase | Depends on |
| --- | --- |
| `dns`, `live`, `tls` | `passive` |
| `takeover` | `passive`, `dns` |
| `filter`, `sensitive`, `javascript` | `historical` |

Active phases (`dns`, `live`, `tls`, `takeover`, wordlist brute force) require authorization confirmation. Use `--yes` for non-interactive runs.

---

## CLI reference

```
python3 main.py DOMAIN [options]
```

| Option | Meaning |
| --- | --- |
| `--passive` | Certificate Transparency + passive DNS sources |
| `--dns` | Native DNS resolution, CNAME chains, dangling detection |
| `--live` | Safe HTTP/HTTPS probing with bounded concurrency and header/meta technology hints |
| `--tls` / `--no-tls` | Enable or disable TLS certificate inspection |
| `--historical` | Internet Archive, Common Crawl, and OTX URL collection |
| `--filter` | Classify URLs by file extension (15+ output files) |
| `--sensitive` | Path and parameter-name indicators (redacted) |
| `--javascript` | Inventory JS assets; `--js-analysis` extracts static endpoints |
| `--takeover` | Passive dangling-DNS / fingerprint analysis |
| `--report` | Write HTML, JSON, and TXT reports |
| `--output DIR` | Results root (default `results/`) |
| `--db PATH` | SQLite database (default `subreconx.db`) |
| `--timeout SECONDS` | Per-request timeout (default `10`) |
| `--concurrency N` | Bounded concurrency (default `20`) |
| `--retries N` | Transient HTTP retries (default `2`) |
| `--scope-file PATH` | Scope configuration file (plain-text rules or Bugcrowd/Bug Bounty JSON) |
| `--strict-scope` | Do not assume `*.domain` is authorized unless explicitly listed in wildcard scope |
| `--rate-limit RPS` | Maximum HTTP requests per second (`0` = bounded by concurrency) |
| `--passive-only` | Disable active HTTP/TLS/DNS probing (passive intelligence only) |
| `--check-historical-urls` | Perform bounded, rate-limited HTTP checks on authorized historical URLs |
| `--max-url-checks N` | Cap on optional historical URL HTTP checks (default `50`) |
| `--resume` | Reuse prior results from the database (subdomains, DNS, HTTP, TLS, historical, filtering, indicators, JS, takeover) |
| `--no-cache` | Disable the passive-source cache |
| `--max-urls N` | Historical URL cap |
| `--cdx-limit N` | CDX page size |
| `--commoncrawl-crawls N` | Number of Common Crawl indexes to query |
| `--wordlist` | Enable bounded DNS wordlist discovery |
| `--wordlist-path PATH` | Custom wordlist |
| `--js-analysis` | Download and statically inspect in-scope JS |
| `--config FILE` | JSON defaults; explicit CLI flags override |
| `--quiet` / `--verbose` | Reduce or increase console output |
| `-y`, `--yes` | Confirm authorization non-interactively |
| `--clear-cache` | Clear the passive-source cache and exit |
| `--clear-domain` | Clear stored data for `DOMAIN` and exit |
| `--no-banner` | Suppress the ASCII banner |

Exit codes: `0` success, `1` runtime failure, `2` usage/validation error, `3` authorization not confirmed, `130` interrupted.

---

## Configuration file

`--config` accepts a JSON object. Only allow-listed keys are accepted, and explicit CLI flags take precedence.

```json
{
  "phases": ["passive", "dns", "live", "tls", "report"],
  "timeout": 10.0,
  "concurrency": 20,
  "retries": 2,
  "max_urls": 5000,
  "cdx_limit": 500,
  "commoncrawl_crawls": 1,
  "js_analysis": false,
  "resume": false,
  "no_cache": false,
  "quiet": false
}
```

See `examples/config.example.json`. `phases` must be a non-empty list drawn from `passive`, `dns`, `live`, `tls`, `historical`, `filter`, `sensitive`, `javascript`, `takeover`, `report`.

---

## Outputs & Bug Bounty Directory Structure

Results are organized under `results/<domain>/` into four structured directories alongside legacy top-level files:

```
results/<domain>/
├── raw/
│   ├── subdomains_raw.txt
│   ├── urls_raw.txt
│   └── source_metadata.json
├── organized/
│   ├── subdomains_all.txt
│   ├── subdomains_in_scope.txt
│   ├── subdomains_live.txt
│   ├── subdomains_dead.txt
│   ├── subdomains_unknown.txt
│   ├── subdomains.json
│   ├── urls_all.txt
│   ├── urls_unique.txt
│   ├── urls_in_scope.txt
│   ├── urls_out_of_scope.txt
│   ├── urls_live.txt
│   ├── urls_dead.txt
│   ├── urls_unknown.txt
│   ├── urls_with_parameters.txt
│   ├── urls.json
│   ├── js_files.txt
│   ├── js_unique.txt
│   ├── js_live.txt
│   ├── js_unknown.txt
│   ├── js_inventory.json
│   ├── api_endpoints.txt
│   ├── authentication_paths.txt
│   ├── admin_paths.txt
│   ├── config_indicators.txt
│   ├── backup_indicators.txt
│   ├── database_indicators.txt
│   ├── debug_paths.txt
│   ├── interesting_parameters.txt
│   └── suspicious_paths.txt
├── intelligence/
│   ├── asset_inventory.json
│   ├── interesting_assets.json
│   ├── exposure_indicators.json
│   └── takeover_candidates.json
└── reports/
    ├── report.html
    ├── report.json
    └── report.txt
```

Representative HTML, JSON, and TXT reports and a Bugcrowd scope configuration are included at `examples/example-report.html`, `examples/example-report.json`, `examples/example-report.txt`, and `examples/bugcrowd-scope.json`.

---

## Security model

1. **Authorization gate** — active phases require typed confirmation or `--yes`.
2. **Scope enforcement** — `example.com` matches `example.com` and `*.example.com`, never `evil-example.com` or `example.com.evil.net`. Wildcards are never connectable.
3. **IP safety** — connections are rejected when any resolved address is loopback, private, link-local, reserved, multicast, unspecified, or an IPv4-mapped private address. The approved IP is supplied directly to the TLS/HTTP connector to prevent DNS rebinding.
4. **Redirect validation** — every hop is re-parsed, re-scoped, re-resolved, and re-checked; overlong redirect chains are stopped.
5. **Read-only probing** — no POST bodies, no credential use, no exploitation. HTTP bodies are capped and only parsed for titles/metadata.
6. **Redaction** — sensitive query parameter values, userinfo, and secret-looking tokens are replaced with `[REDACTED]` in every persisted artifact.
7. **Bounded work** — concurrency limits, timeouts, retry backoff, body caps, URL caps, and page caps.

> Passive data can contain stale or third-party references. A sensitive-path match is an **indicator**, not proof of exposed data; referenced content is never downloaded.

---

## Testing

```bash
python3 -m unittest discover -s tests -t . -v
```

The suite covers domain validation, scope/SSRF rules, DNS wire encoding, URL normalization, file filtering, sensitive detection/redaction, takeover scoring, database persistence, risk scoring, report generation, passive-source parsers, and configuration parsing. All tests are offline — no live hosts are contacted.

---

## Project layout

```
SubReconX/
├── main.py                     CLI entry point
├── config.py                   Constants and ScanConfig
├── core/                       Scope, database, logging, orchestration
├── engines/                    Passive/DNS/HTTP/TLS/historical/filter/JS/takeover/risk/report
├── protocols/                  Native DNS, HTTP, and TLS clients
├── sources/                    crt.sh, Cert Spotter, Wayback CDX, Common Crawl, OTX
├── intelligence/               Sensitive patterns, extension map, takeover fingerprints
├── utils/                      Validation, network safety, redaction, cache, config loader
├── wordlists/subdomains.txt    Optional DNS wordlist
├── examples/                   Example config and report
└── tests/                      Offline unit tests
```

---

## Limitations

- Passive sources may be rate-limited, unavailable, or incomplete; errors are reported per source and do not abort the scan.
- The bundled public-suffix guard is intentionally small; it prevents obvious mistakes, not every possible suffix.
- Takeover detection is passive and fingerprint-based; candidates require manual verification.
- TLS inspection reports certificate facts; it does not grade protocol configuration.
- The database and passive-source cache are local files. Cached payloads are redacted before storage; clear them with `--clear-cache` / `--clear-domain`.

---

## License

MIT — see `LICENSE`.
