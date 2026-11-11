"""Results Processing Engine for Bug Bounty organization and migration.

Responsibilities (Phase 1, Phase 3, Phase 4, Phase 5, Phase 8):
1. Remove duplicate subdomains while merging source attribution.
2. Normalize hostnames and strip whitespace/malformed entries.
3. Validate hostname syntax and enforce exact root-domain boundaries.
4. Keep original scan results as immutable raw data under ``raw/``.
5. Classify subdomains into ``all``, ``in_scope``, ``live``, ``dead``, and
   ``unknown`` under ``organized/``.
6. Organize historical URLs, classified URL categories, and JavaScript
   inventories under ``organized/``.
7. Support non-destructive migration of existing flat result directories.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path

from core.scope_manager import ScopeManager
from engines.dns_engine import DNSRunResult
from engines.historical_url_engine import HistoricalResult, write_historical_outputs
from engines.javascript_engine import JSResult
from engines.live_host_engine import HTTPRunResult, summarize_host
from engines.sensitive_detection_engine import SensitiveResult
from engines.subdomain_engine import SubdomainResult
from engines.tls_engine import TLSRunResult
from utils.redaction import redact_url
from utils.url_utils import normalize_url
from utils.validators import is_valid_hostname, is_within_domain, normalize_hostname


@dataclass
class OrganizedSubdomain:
    hostname: str
    in_scope: bool
    within_root_boundary: bool
    classification: str  # "LIVE", "DEAD", "UNKNOWN"
    reason: str = ""
    sources: list[str] = field(default_factory=list)
    http_status: int | None = None
    https_status: int | None = None
    final_url: str = ""
    title: str = ""
    server: str = ""
    content_type: str = ""
    response_time: float = 0.0
    redirect_chain: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    tls_metadata: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "in_scope": self.in_scope,
            "within_root_boundary": self.within_root_boundary,
            "classification": self.classification,
            "reason": self.reason,
            "source": self.sources[0] if self.sources else "unknown",
            "sources": self.sources,
            "http_status": self.http_status,
            "https_status": self.https_status,
            "final_url": self.final_url,
            "title": self.title,
            "server": self.server,
            "content_type": self.content_type,
            "response_time": self.response_time,
            "redirect_chain": self.redirect_chain,
            "technologies": self.technologies,
            "tls_metadata": self.tls_metadata,
        }


@dataclass
class OrganizedResults:
    root: str
    subdomains_raw: list[str] = field(default_factory=list)
    subdomains_all: list[str] = field(default_factory=list)
    subdomains_in_scope: list[str] = field(default_factory=list)
    subdomains_out_of_scope: list[str] = field(default_factory=list)
    subdomains_live: list[str] = field(default_factory=list)
    subdomains_dead: list[str] = field(default_factory=list)
    subdomains_unknown: list[str] = field(default_factory=list)
    subdomains_malformed: list[str] = field(default_factory=list)
    subdomain_records: list[OrganizedSubdomain] = field(default_factory=list)
    urls_raw: list[str] = field(default_factory=list)
    source_metadata: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "root": self.root,
            "counts": {
                "raw_subdomains": len(self.subdomains_raw),
                "unique_subdomains": len(self.subdomains_all),
                "in_scope_subdomains": len(self.subdomains_in_scope),
                "out_of_scope_subdomains": len(self.subdomains_out_of_scope),
                "live_subdomains": len(self.subdomains_live),
                "dead_subdomains": len(self.subdomains_dead),
                "unknown_subdomains": len(self.subdomains_unknown),
                "malformed_entries": len(self.subdomains_malformed),
                "raw_urls": len(self.urls_raw),
            },
            "subdomains_all": self.subdomains_all,
            "subdomains_in_scope": self.subdomains_in_scope,
            "subdomains_out_of_scope": self.subdomains_out_of_scope,
            "subdomains_live": self.subdomains_live,
            "subdomains_dead": self.subdomains_dead,
            "subdomains_unknown": self.subdomains_unknown,
            "malformed_entries": self.subdomains_malformed[:500],
            "hosts": [rec.as_dict() for rec in self.subdomain_records],
        }


def clean_and_deduplicate_subdomains(
    entries: list[dict | str],
    scope: ScopeManager,
) -> tuple[list[dict], list[str], list[str]]:
    """Clean, validate, enforce root-domain boundary, and deduplicate subdomains.

    Returns ``(deduped_records, raw_lines, malformed_entries)``.
    """
    by_host: dict[str, dict] = {}
    raw_lines: list[str] = []
    malformed: list[str] = []

    for item in entries:
        if isinstance(item, str):
            raw_host = item
            sources = ["raw"]
        elif isinstance(item, dict):
            raw_host = str(item.get("hostname", "") or "")
            raw_srcs = item.get("sources")
            if isinstance(raw_srcs, list) and raw_srcs:
                sources = [str(s).strip() for s in raw_srcs if str(s).strip()]
            else:
                src = str(item.get("source", "") or "passive").strip()
                sources = [src] if src else ["passive"]
        else:
            continue

        stripped = raw_host.strip()
        if stripped:
            raw_lines.append(stripped)

        normalized = normalize_hostname(stripped)
        if not normalized:
            if stripped:
                malformed.append(stripped[:255])
            continue
        if not is_valid_hostname(normalized):
            malformed.append(stripped[:255])
            continue

        within_boundary = scope.is_within_root_boundary(normalized)
        in_scope = scope.is_in_scope(normalized)
        if not within_boundary and not in_scope:
            malformed.append(f"outside-root-boundary:{normalized}")
            continue

        if normalized in by_host:
            existing_sources = by_host[normalized]["sources"]
            for s in sources:
                if s not in existing_sources:
                    existing_sources.append(s)
        else:
            by_host[normalized] = {
                "hostname": normalized,
                "sources": list(sources),
                "source": sources[0] if sources else "passive",
                "in_scope": in_scope,
                "within_root_boundary": within_boundary,
            }

    deduped = sorted(by_host.values(), key=lambda r: r["hostname"])
    return deduped, raw_lines, malformed


class ResultsProcessingEngine:
    def __init__(self, scope: ScopeManager):
        self.scope = scope

    def process(
        self,
        *,
        subdomains: SubdomainResult | None = None,
        dns: DNSRunResult | None = None,
        http: HTTPRunResult | None = None,
        tls: TLSRunResult | None = None,
        historical: HistoricalResult | None = None,
    ) -> OrganizedResults:
        organized = OrganizedResults(root=self.scope.root)

        raw_sub_inputs: list[dict | str] = []
        if subdomains is not None:
            if subdomains.raw_records:
                raw_sub_inputs.extend(subdomains.raw_records)
            elif subdomains.all_hosts:
                raw_sub_inputs.extend(subdomains.all_hosts)
            elif subdomains.hosts:
                raw_sub_inputs.extend(subdomains.hosts)
            for m in subdomains.malformed:
                if m not in organized.subdomains_malformed:
                    organized.subdomains_malformed.append(m)

        if historical is not None:
            hist_hosts: dict[str, list[str]] = {}
            for rec in historical.records + historical.out_of_scope:
                if rec.hostname and self.scope.is_within_root_boundary(rec.hostname):
                    bucket = hist_hosts.setdefault(rec.hostname, [])
                    for s in (rec.sources if rec.sources else ["historical"]):
                        if s not in bucket:
                            bucket.append(s)
            existing_raw_hosts = {
                normalize_hostname(
                    item.get("hostname", "") if isinstance(item, dict) else str(item)
                )
                for item in raw_sub_inputs
            }
            for hname, hsources in sorted(hist_hosts.items()):
                if hname not in existing_raw_hosts:
                    raw_sub_inputs.append({"hostname": hname, "sources": hsources})
                else:
                    # Merge historical source attribution without inflating raw subdomain count
                    for item in raw_sub_inputs:
                        if isinstance(item, dict) and normalize_hostname(item.get("hostname", "")) == hname:
                            srcs = list(item.get("sources") or ([item["source"]] if item.get("source") else []))
                            for s in hsources:
                                if s not in srcs:
                                    srcs.append(s)
                            item["sources"] = srcs
                            break

        deduped, raw_lines, malformed = clean_and_deduplicate_subdomains(
            raw_sub_inputs, self.scope
        )
        organized.subdomains_raw = raw_lines
        for m in malformed:
            if m not in organized.subdomains_malformed:
                organized.subdomains_malformed.append(m)

        dns_map = {}
        if dns is not None:
            for drec in dns.records:
                dns_map[drec.hostname] = drec

        http_by_host = http.by_host() if http is not None else {}
        http_cls_map = http.host_classifications if http is not None else {}

        tls_map = {}
        if tls is not None:
            for trec in tls.results:
                tls_map[trec.hostname] = trec

        for item in deduped:
            host = item["hostname"]
            in_scope = bool(item["in_scope"])
            within_boundary = bool(item["within_root_boundary"])
            organized.subdomains_all.append(host)

            if in_scope:
                organized.subdomains_in_scope.append(host)
            else:
                organized.subdomains_out_of_scope.append(host)

            probes = http_by_host.get(host, [])
            dns_rec = dns_map.get(host)
            tls_rec = tls_map.get(host)

            if not in_scope:
                summary = {
                    "classification": "UNKNOWN",
                    "reason": "out of authorized scope (not actively probed)",
                    "http_status": None,
                    "https_status": None,
                    "final_url": "",
                    "title": "",
                    "server": "",
                    "content_type": "",
                    "response_time": 0.0,
                    "redirect_chain": [],
                    "technologies": [],
                    "tls_metadata": {},
                }
            elif host in http_cls_map and not tls_rec:
                summary = dict(http_cls_map[host])
            else:
                summary = summarize_host(host, probes, dns_rec, tls_rec)
                if http is not None:
                    http.host_classifications[host] = summary

            cls = str(summary.get("classification", "UNKNOWN")).upper()
            if in_scope:
                if cls == "LIVE":
                    organized.subdomains_live.append(host)
                elif cls == "DEAD":
                    organized.subdomains_dead.append(host)
                else:
                    organized.subdomains_unknown.append(host)

            organized.subdomain_records.append(
                OrganizedSubdomain(
                    hostname=host,
                    in_scope=in_scope,
                    within_root_boundary=within_boundary,
                    classification=cls,
                    reason=str(summary.get("reason", "")),
                    sources=list(item.get("sources", [])),
                    http_status=summary.get("http_status"),
                    https_status=summary.get("https_status"),
                    final_url=str(summary.get("final_url", "")),
                    title=str(summary.get("title", "")),
                    server=str(summary.get("server", "")),
                    content_type=str(summary.get("content_type", "")),
                    response_time=float(summary.get("response_time", 0.0) or 0.0),
                    redirect_chain=list(summary.get("redirect_chain", [])),
                    technologies=list(summary.get("technologies", [])),
                    tls_metadata=dict(summary.get("tls_metadata", {})),
                )
            )

        if http is not None:
            http.live_hosts = sorted(set(organized.subdomains_live))
            http.dead_hosts = sorted(set(organized.subdomains_dead))
            http.unknown_hosts = sorted(set(organized.subdomains_unknown))

        if historical is not None:
            if historical.raw_records:
                organized.urls_raw = [
                    redact_url(str(r.get("url") or ""))
                    for r in historical.raw_records
                    if r.get("url")
                ]
            else:
                organized.urls_raw = [
                    redact_url(r.url)
                    for r in (historical.records + historical.out_of_scope)
                ]
            direct_status: dict[str, tuple[str, int | None]] = {}
            if http is not None:
                for hrec in http.records:
                    norm = normalize_url(hrec.final_url or hrec.url)
                    if norm and hrec.status is not None and hrec.status != 429:
                        direct_status[norm] = ("LIVE", hrec.status)
            host_cls = {rec.hostname: rec.as_dict() for rec in organized.subdomain_records}
            for rec in historical.records:
                if rec.liveness_basis != "direct_probe":
                    if rec.normalized in direct_status:
                        rec.liveness, rec.http_status = direct_status[rec.normalized]
                        rec.liveness_basis = "direct_probe"
                    elif rec.hostname in host_cls:
                        h_cls = host_cls[rec.hostname]["classification"]
                        rec.liveness = h_cls
                        rec.liveness_basis = f"host_{h_cls.lower()}"

        sub_sources = [s.as_dict() for s in (subdomains.sources if subdomains else [])]
        hist_sources = [s.as_dict() for s in (historical.sources if historical else [])]
        organized.source_metadata = {
            "domain": self.scope.root,
            "scope": self.scope.as_dict(),
            "subdomain_sources": sub_sources,
            "historical_sources": hist_sources,
            "counts": {
                "raw_subdomains": len(organized.subdomains_raw),
                "unique_subdomains": len(organized.subdomains_all),
                "in_scope_subdomains": len(organized.subdomains_in_scope),
                "out_of_scope_subdomains": len(organized.subdomains_out_of_scope),
                "live_subdomains": len(organized.subdomains_live),
                "dead_subdomains": len(organized.subdomains_dead),
                "unknown_subdomains": len(organized.subdomains_unknown),
                "malformed_subdomains": len(organized.subdomains_malformed),
                "raw_urls": len(organized.urls_raw),
            },
        }
        return organized

    def migrate_existing_results(self, output_dir: Path) -> dict[str, int]:
        """Non-destructively migrate flat legacy files into raw/ and organized/."""
        output_dir = Path(output_dir)
        raw_dir = output_dir / "raw"
        org_dir = output_dir / "organized"
        raw_dir.mkdir(parents=True, exist_ok=True)
        org_dir.mkdir(parents=True, exist_ok=True)
        migrated = {"subdomains": 0, "urls": 0}

        legacy_subs = output_dir / "subdomains.txt"
        raw_subs_file = raw_dir / "subdomains_raw.txt"
        if legacy_subs.exists():
            lines = [
                line.strip()
                for line in legacy_subs.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            existing = []
            if raw_subs_file.exists():
                existing = [
                    line.strip()
                    for line in raw_subs_file.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
            merged = list(existing)
            seen_subs = set(existing)
            for item in lines:
                if item not in seen_subs:
                    seen_subs.add(item)
                    merged.append(item)
            raw_subs_file.write_text(
                "\n".join(merged) + ("\n" if merged else ""), encoding="utf-8"
            )
            migrated["subdomains"] = len(merged)

        legacy_urls = output_dir / "urls_all.txt"
        raw_urls_file = raw_dir / "urls_raw.txt"
        if legacy_urls.exists():
            lines = [
                redact_url(line.strip())
                for line in legacy_urls.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            existing = []
            if raw_urls_file.exists():
                existing = [
                    line.strip()
                    for line in raw_urls_file.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
            merged = list(existing)
            seen_urls = set(existing)
            for item in lines:
                if item not in seen_urls:
                    seen_urls.add(item)
                    merged.append(item)
            raw_urls_file.write_text(
                "\n".join(merged) + ("\n" if merged else ""), encoding="utf-8"
            )
            migrated["urls"] = len(merged)

        return migrated

    def write_outputs(
        self,
        organized: OrganizedResults,
        output_dir: Path,
        *,
        historical: HistoricalResult | None = None,
        sensitive: SensitiveResult | None = None,
        javascript: JSResult | None = None,
        preserve_top_level: bool = False,
    ) -> None:
        output_dir = Path(output_dir)
        raw_dir = output_dir / "raw"
        org_dir = output_dir / "organized"
        raw_dir.mkdir(parents=True, exist_ok=True)
        org_dir.mkdir(parents=True, exist_ok=True)

        self.migrate_existing_results(output_dir)

        def _write_immutable_raw(target: Path, new_lines: list[str]) -> None:
            existing: list[str] = []
            if target.exists():
                existing = [
                    line.strip()
                    for line in target.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
            combined = list(existing)
            seen = set(existing)
            for line in new_lines:
                cleaned = line.strip()
                if cleaned and cleaned not in seen:
                    seen.add(cleaned)
                    combined.append(cleaned)
            target.write_text(
                "\n".join(combined) + ("\n" if combined else ""), encoding="utf-8"
            )

        _write_immutable_raw(raw_dir / "subdomains_raw.txt", organized.subdomains_raw)
        _write_immutable_raw(raw_dir / "urls_raw.txt", organized.urls_raw)
        (raw_dir / "source_metadata.json").write_text(
            json.dumps(organized.source_metadata, indent=2, default=str),
            encoding="utf-8",
        )

        def _write_lines(directory: Path, filename: str, lines: list[str]) -> None:
            (directory / filename).write_text(
                "\n".join(lines) + ("\n" if lines else ""), encoding="utf-8"
            )

        target_dirs = (org_dir,) if preserve_top_level else (org_dir, output_dir)
        for target_dir in target_dirs:
            _write_lines(target_dir, "subdomains_all.txt", organized.subdomains_all)
            _write_lines(target_dir, "subdomains_in_scope.txt", organized.subdomains_in_scope)
            _write_lines(target_dir, "subdomains_live.txt", organized.subdomains_live)
            _write_lines(target_dir, "subdomains_dead.txt", organized.subdomains_dead)
            _write_lines(target_dir, "subdomains_unknown.txt", organized.subdomains_unknown)

        (org_dir / "subdomains.json").write_text(
            json.dumps(organized.as_dict(), indent=2, default=str), encoding="utf-8"
        )

        if historical is not None:
            write_historical_outputs(historical, org_dir)
            if not preserve_top_level:
                write_historical_outputs(historical, output_dir)
        else:
            for fname in (
                "urls_all.txt",
                "urls_unique.txt",
                "urls_in_scope.txt",
                "urls_out_of_scope.txt",
                "urls_live.txt",
                "urls_dead.txt",
                "urls_unknown.txt",
                "urls_with_parameters.txt",
            ):
                if not (org_dir / fname).exists():
                    (org_dir / fname).write_text("", encoding="utf-8")
            if not (org_dir / "urls.json").exists():
                (org_dir / "urls.json").write_text("{}", encoding="utf-8")

        if sensitive is not None:
            from engines.sensitive_detection_engine import SensitiveDetectionEngine

            s_engine = SensitiveDetectionEngine()
            s_engine.write_outputs(sensitive, org_dir)
            if not preserve_top_level:
                s_engine.write_outputs(sensitive, output_dir)
        else:
            for fname in (
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
                if not (org_dir / fname).exists():
                    (org_dir / fname).write_text("", encoding="utf-8")

        if javascript is not None:
            from engines.javascript_engine import JavaScriptEngine

            j_engine = JavaScriptEngine(self.scope)
            j_engine.write_outputs(javascript, org_dir)
            if not preserve_top_level:
                j_engine.write_outputs(javascript, output_dir)
        else:
            for fname in (
                "js_files.txt",
                "js_unique.txt",
                "js_live.txt",
                "js_unknown.txt",
            ):
                if not (org_dir / fname).exists():
                    (org_dir / fname).write_text("", encoding="utf-8")
            if not (org_dir / "js_inventory.json").exists():
                (org_dir / "js_inventory.json").write_text("{}", encoding="utf-8")

    def organize_existing_directory(
        self, directory: Path, *, preserve_top_level: bool = False
    ) -> dict:
        """Load an existing scan directory offline and generate all structured outputs.

        Performs zero network requests and preserves original top-level raw files.
        """
        from config import TOOL_NAME, VERSION
        from engines.asset_intelligence_engine import AssetIntelligenceEngine
        from engines.dns_engine import ResolvedHost
        from engines.historical_url_engine import HistoricalRecord
        from engines.javascript_engine import JSResult, collect_js_urls
        from engines.report_engine import generate_reports
        from engines.risk_engine import RiskEngine, write_risk_outputs
        from engines.sensitive_detection_engine import SensitiveDetectionEngine
        from engines.takeover_engine import TakeoverCandidate, TakeoverResult
        from engines.tls_engine import TLSResult
        from engines.url_filter_engine import URLFilterEngine
        from protocols.http_protocol import HTTPResult
        from sources.base import SourceResult
        from utils.url_utils import extract_param_names, get_extension, get_path, split_url

        directory = Path(directory)
        self.migrate_existing_results(directory)

        # 1) Load subdomains
        sub_result = SubdomainResult(root=self.scope.root)
        sub_json_path = directory / "subdomains.json"
        sub_txt_path = directory / "subdomains.txt"
        raw_sub_entries: list[dict | str] = []
        if sub_json_path.exists():
            sub_data = json.loads(sub_json_path.read_text(encoding="utf-8"))
            raw_sub_entries.extend(sub_data.get("hosts", []))
            for src in sub_data.get("sources", []):
                sub_result.sources.append(
                    SourceResult(
                        source=str(src.get("source", "passive")),
                        records=[{}] * int(src.get("count", 0)),
                        cached=bool(src.get("cached", False)),
                        error=str(src.get("error", "")),
                    )
                )
        elif sub_txt_path.exists():
            raw_sub_entries.extend(
                line.strip()
                for line in sub_txt_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            )
        deduped_subs, raw_sub_lines, malformed_subs = clean_and_deduplicate_subdomains(
            raw_sub_entries, self.scope
        )
        sub_result.raw_records = [
            item if isinstance(item, dict) else {"hostname": str(item), "source": "raw"}
            for item in raw_sub_entries
        ]
        sub_result.all_hosts = deduped_subs
        sub_result.hosts = [h for h in deduped_subs if h.get("in_scope", True)]
        sub_result.out_of_scope_hosts = [
            h for h in deduped_subs if not h.get("in_scope", True)
        ]
        sub_result.malformed = malformed_subs

        # 2) Load DNS if present
        dns_result: DNSRunResult | None = None
        dns_json_path = directory / "dns_results.json"
        if dns_json_path.exists():
            dns_data = json.loads(dns_json_path.read_text(encoding="utf-8"))
            dns_result = DNSRunResult(root=self.scope.root)
            for rec in dns_data.get("records", []):
                rh = ResolvedHost(
                    hostname=rec.get("hostname", ""),
                    a=list(rec.get("a", [])),
                    aaaa=list(rec.get("aaaa", [])),
                    cname=list(rec.get("cname", [])),
                    mx=list(rec.get("mx", [])),
                    ns=list(rec.get("ns", [])),
                    txt=list(rec.get("txt", [])),
                    soa=list(rec.get("soa", [])),
                    status=rec.get("status", "unresolved"),
                    rcode=rec.get("rcode", ""),
                    dangling=bool(rec.get("dangling", False)),
                    private_ips=list(rec.get("private_ips", [])),
                    errors=list(rec.get("errors", [])),
                )
                dns_result.records.append(rh)
                if rh.resolved:
                    dns_result.resolved.append(rh.hostname)
                else:
                    dns_result.unresolved.append(rh.hostname)
            dns_result.cname_records = list(dns_data.get("cname_records", []))
            dns_result.dangling = list(dns_data.get("dangling", []))
            dns_result.suspicious = list(dns_data.get("suspicious", []))

        # 3) Load HTTP if present
        http_result: HTTPRunResult | None = None
        http_json_path = directory / "http_results.json"
        if http_json_path.exists():
            http_data = json.loads(http_json_path.read_text(encoding="utf-8"))
            http_result = HTTPRunResult()
            for r in http_data.get("results", []):
                http_result.records.append(
                    HTTPResult(
                        url=r.get("url", ""),
                        final_url=r.get("final_url", ""),
                        scheme=r.get("scheme", "https"),
                        hostname=r.get("hostname", ""),
                        status=r.get("status"),
                        reason=r.get("reason", ""),
                        headers=dict(r.get("headers", {})),
                        title=r.get("title", ""),
                        server=r.get("server", ""),
                        content_type=r.get("content_type", ""),
                        content_length=r.get("content_length"),
                        elapsed=float(r.get("elapsed", 0.0) or 0.0),
                        redirect_chain=list(r.get("redirect_chain", [])),
                        redirect_rejected=r.get("redirect_rejected", ""),
                        tls_verified=r.get("tls_verified"),
                        tls_error=r.get("tls_error", ""),
                        tls_metadata=dict(r.get("tls_metadata", {})),
                        ip_used=r.get("ip_used", ""),
                        technologies=list(r.get("technologies", [])),
                        error=r.get("error", ""),
                    )
                )

        # 4) Load TLS if present
        tls_result: TLSRunResult | None = None
        tls_json_path = directory / "tls_results.json"
        if tls_json_path.exists():
            tls_data = json.loads(tls_json_path.read_text(encoding="utf-8"))
            tls_result = TLSRunResult()
            for r in tls_data.get("results", []):
                tls_result.results.append(
                    TLSResult(
                        hostname=r.get("hostname", ""),
                        port=int(r.get("port", 443)),
                        connected=bool(r.get("connected", False)),
                        verified=bool(r.get("verified", False)),
                        verification_error=r.get("verification_error", ""),
                        protocol=r.get("protocol", ""),
                        cipher=r.get("cipher", ""),
                        subject=dict(r.get("subject", {})),
                        issuer=dict(r.get("issuer", {})),
                        serial_number=r.get("serial_number", ""),
                        not_before=r.get("not_before", ""),
                        not_after=r.get("not_after", ""),
                        sans=list(r.get("sans", [])),
                        expired=r.get("expired"),
                        days_until_expiry=r.get("days_until_expiry"),
                        hostname_matches=r.get("hostname_matches"),
                        error=r.get("error", ""),
                    )
                )

        # 5) Load Historical URLs if present
        hist_result = HistoricalResult()
        urls_json_path = directory / "urls_all.json"
        urls_txt_path = directory / "urls_all.txt"
        raw_url_items: list[dict] = []
        if urls_json_path.exists():
            urls_data = json.loads(urls_json_path.read_text(encoding="utf-8"))
            for src in urls_data.get("sources", []):
                hist_result.sources.append(
                    SourceResult(
                        source=str(src.get("source", "historical")),
                        records=[{}] * int(src.get("count", 0)),
                        cached=bool(src.get("cached", False)),
                        error=str(src.get("error", "")),
                    )
                )
            for m in urls_data.get("malformed", []):
                hist_result.malformed.append(str(m))
            raw_url_items.extend(urls_data.get("records", []))
            raw_url_items.extend(urls_data.get("out_of_scope_records", []))
        elif urls_txt_path.exists():
            for line in urls_txt_path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    raw_url_items.append({"url": line.strip(), "sources": ["historical"]})

        filter_engine = URLFilterEngine()
        by_redacted: dict[str, HistoricalRecord] = {}
        for raw in raw_url_items:
            raw_copy = dict(raw)
            if raw_copy.get("url"):
                raw_copy["url"] = redact_url(str(raw_copy["url"]))
            if raw_copy.get("normalized"):
                raw_copy["normalized"] = redact_url(str(raw_copy["normalized"]))
            hist_result.raw_records.append(raw_copy)
            orig = str(raw.get("url") or raw.get("normalized") or "").strip()
            norm = normalize_url(orig)
            if norm is None:
                if orig and len(hist_result.malformed) < 500:
                    hist_result.malformed.append(redact_url(orig[:2048]))
                continue
            parsed = split_url(norm)
            host = normalize_hostname(parsed.host)
            if not host or not is_valid_hostname(host):
                if orig and len(hist_result.malformed) < 500:
                    hist_result.malformed.append(redact_url(orig[:2048]))
                continue
            redacted_norm = redact_url(norm)
            redacted_parsed = split_url(redacted_norm)
            raw_srcs = raw.get("sources")
            if isinstance(raw_srcs, list) and raw_srcs:
                srcs = [str(s) for s in raw_srcs if s]
            else:
                s = raw.get("source", "")
                srcs = [str(s)] if s else ["historical"]
            ts = str(raw.get("timestamp", "") or "")
            if redacted_norm in by_redacted:
                ex = by_redacted[redacted_norm]
                for s in srcs:
                    if s not in ex.sources:
                        ex.sources.append(s)
                if ts and (not ex.timestamp or ts > ex.timestamp):
                    ex.timestamp = ts
                continue
            in_scope = self.scope.is_in_scope(host)
            rec = HistoricalRecord(
                url=redact_url(orig),
                normalized=redacted_norm,
                hostname=host,
                path=get_path(norm),
                query=redacted_parsed.query,
                extension=get_extension(norm),
                params=extract_param_names(parsed.query),
                sources=srcs,
                timestamp=ts,
                in_scope=in_scope,
                within_root_boundary=self.scope.is_within_root_boundary(host),
                categories=filter_engine.classify(norm),
            )
            by_redacted[redacted_norm] = rec
            if in_scope:
                hist_result.records.append(rec)
            else:
                hist_result.out_of_scope.append(rec)

        # 6) Run ResultsProcessingEngine.process()
        organized = self.process(
            subdomains=sub_result,
            dns=dns_result,
            http=http_result,
            tls=tls_result,
            historical=hist_result,
        )

        # Keep sub_result synced with merged historical in-scope subdomains
        existing_sub_names = {h["hostname"] for h in sub_result.hosts}
        for orec in organized.subdomain_records:
            if orec.in_scope and orec.hostname not in existing_sub_names:
                sub_result.hosts.append(
                    {
                        "hostname": orec.hostname,
                        "sources": list(orec.sources),
                        "source": orec.sources[0] if orec.sources else "historical",
                        "in_scope": True,
                    }
                )
                existing_sub_names.add(orec.hostname)

        # 7) Run URLFilterEngine, JavaScript inventory, SensitiveDetectionEngine
        in_scope_urls = [r.normalized for r in hist_result.in_scope]
        filter_result = filter_engine.run(in_scope_urls)
        filter_engine.write_outputs(filter_result, directory / "organized")

        source_map = {r.normalized: list(r.sources) for r in hist_result.in_scope}
        ts_map = {r.normalized: r.timestamp for r in hist_result.in_scope if r.timestamp}
        host_cls = {rec.hostname: rec.as_dict() for rec in organized.subdomain_records}
        js_assets_map = collect_js_urls(
            in_scope_urls,
            source_map=source_map,
            timestamp_map=ts_map,
            host_classifications=host_cls,
        )
        js_result = JSResult(
            assets=sorted(js_assets_map.values(), key=lambda a: a.normalized)
        )

        sensitive_engine = SensitiveDetectionEngine()
        sensitive_result = sensitive_engine.run(in_scope_urls + js_result.urls)

        # 8) Load takeover candidates if present
        takeover_result = TakeoverResult()
        takeover_json_path = directory / "takeover_candidates.json"
        if takeover_json_path.exists():
            tdata = json.loads(takeover_json_path.read_text(encoding="utf-8"))
            for c in tdata.get("candidates", []):
                takeover_result.candidates.append(
                    TakeoverCandidate(
                        hostname=c.get("hostname", ""),
                        cname_target=c.get("cname_target", ""),
                        provider_id=c.get("provider_id", ""),
                        provider_name=c.get("provider", ""),
                        confidence=int(c.get("confidence", 0)),
                        classification=c.get("classification", "Needs Manual Review"),
                        evidence=list(c.get("evidence", [])),
                        warnings=list(c.get("false_positive_warnings", [])),
                        reference=c.get("reference", ""),
                        http_status=c.get("http_status"),
                    )
                )

        # 9) Write organized outputs, intelligence outputs, risk, and reports
        self.write_outputs(
            organized,
            directory,
            historical=hist_result,
            sensitive=sensitive_result,
            javascript=js_result,
            preserve_top_level=preserve_top_level,
        )

        intel_engine = AssetIntelligenceEngine()
        intel_result = intel_engine.run(
            domain=self.scope.root,
            organized=organized,
            dns=dns_result,
            http=http_result,
            tls=tls_result,
            historical=hist_result,
            sensitive=sensitive_result,
            javascript=js_result,
            takeover=takeover_result,
        )
        intel_engine.write_outputs(intel_result, directory)

        risk_engine = RiskEngine()
        risk_result = risk_engine.run(
            dns_result=dns_result,
            http_result=http_result,
            tls_result=tls_result,
            historical=hist_result,
            sensitive=sensitive_result,
            filter_result=filter_result,
            takeover=takeover_result,
            js_count=len(js_result.assets),
            subdomain_count=len(organized.subdomains_in_scope),
        )
        write_risk_outputs(risk_result, directory / "reports")

        bundle = {
            "meta": {
                "tool": TOOL_NAME,
                "version": VERSION,
                "domain": self.scope.root,
                "output_dir": str(directory),
                "phases_enabled": ["offline-organization"],
            },
            "subdomains": sub_result.as_dict(),
            "dns": dns_result.as_dict() if dns_result else {},
            "http": http_result.as_dict() if http_result else {},
            "tls": tls_result.as_dict() if tls_result else {},
            "historical": hist_result.as_dict(),
            "filter": filter_result.as_dict(),
            "sensitive": sensitive_result.as_dict(),
            "javascript": js_result.as_dict(),
            "takeover": takeover_result.as_dict(),
            "organized": organized.as_dict(),
            "intelligence": intel_result.as_dict(),
            "scope": self.scope.as_dict(),
            "risk": risk_result.as_dict(),
            "sources": [
                s.as_dict() for s in (sub_result.sources + hist_result.sources)
            ],
            "tasks": [],
            "errors": [],
        }
        generate_reports(bundle, directory, preserve_top_level=preserve_top_level)
        return bundle
