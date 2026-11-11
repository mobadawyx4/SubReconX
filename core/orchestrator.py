"""Scan orchestrator: wires every engine together in a safe order."""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from config import VERSION, TOOL_NAME, ScanConfig, ensure_directories
from core.database import Database
from core.event_logger import EventLogger
from core.scope_manager import ScopeManager
from core.task_manager import TaskManager
from engines.dns_engine import (
    DNSRunResult,
    DNSEngine,
    ResolvedHost,
    run_dns,
    write_dns_outputs,
)
from engines.asset_intelligence_engine import AssetIntelligenceEngine, AssetIntelligenceResult
from engines.historical_url_engine import (
    HistoricalRecord,
    HistoricalResult,
    HistoricalURLEngine,
    write_historical_outputs,
)
from engines.javascript_engine import JSAsset, JavaScriptEngine, JSResult
from engines.live_host_engine import (
    HTTPRunResult,
    LiveHostEngine,
    summarize_host,
    write_http_outputs,
)
from engines.report_engine import generate_reports
from engines.results_engine import OrganizedResults, ResultsProcessingEngine
from engines.risk_engine import RiskEngine, write_risk_outputs
from engines.sensitive_detection_engine import (
    Indicator,
    SensitiveDetectionEngine,
    SensitiveResult,
)
from engines.subdomain_engine import SubdomainEngine, SubdomainResult, write_subdomain_outputs
from engines.takeover_engine import TakeoverCandidate, TakeoverEngine, TakeoverResult
from engines.tls_engine import TLSEngine, TLSRunResult, write_tls_outputs
from engines.url_filter_engine import FilterResult, URLFilterEngine
from protocols.http_protocol import HTTPResult
from protocols.tls_protocol import TLSResult
from sources.source_manager import SourceManager
from utils.cache import SourceCache
from utils.formatting import human_duration
from utils.redaction import redact_structure, redact_url
from utils.url_utils import (
    extract_param_names,
    get_extension,
    get_path,
    normalize_url,
    resolve_redirect,
    split_url,
)
from utils.validators import normalize_hostname


@dataclass
class ScanState:
    subdomains: SubdomainResult | None = None
    dns: DNSRunResult | None = None
    http: HTTPRunResult | None = None
    tls: TLSRunResult | None = None
    historical: HistoricalResult | None = None
    filter_result: object | None = None
    sensitive: object | None = None
    javascript: object | None = None
    takeover: object | None = None
    organized: OrganizedResults | None = None
    intelligence: AssetIntelligenceResult | None = None
    risk: object | None = None
    extra_sources: list = field(default_factory=list)


class Orchestrator:
    def __init__(
        self,
        config: ScanConfig,
        scope: ScopeManager,
        logger: EventLogger,
        db: Database,
    ):
        self.config = config
        self.scope = scope
        self.logger = logger
        self.db = db
        self.state = ScanState()
        self.tasks = TaskManager()
        self.cache = SourceCache(db, enabled=config.use_cache)
        self.sources = SourceManager(
            config.domain,
            self.cache,
            timeout=config.timeout,
            retries=config.retries,
            cdx_limit=config.cdx_limit,
            max_urls=config.max_urls,
            commoncrawl_crawls=config.commoncrawl_crawls,
        )
        self.dns = DNSEngine(
            timeout=config.timeout,
            concurrency=max(config.concurrency, 20),
        )
        self.started_at = 0.0
        self.scan_id = 0

    # ------------------------------------------------------------------
    async def run(self) -> dict:
        ensure_directories(self.config)
        self.started_at = time.monotonic()
        self.scan_id = self.db.start_scan(
            self.config.domain,
            {
                "timeout": self.config.timeout,
                "concurrency": self.config.concurrency,
                "phases": self.config.enabled_phases(),
                "resume": self.config.resume,
                "use_cache": self.config.use_cache,
            },
        )
        status = "completed"
        failure: Exception | None = None
        try:
            await self._run_phases()
        except asyncio.CancelledError:
            status = "cancelled"
            self.logger.warn("scan cancelled - writing partial results")
            self.db.finish_scan(self.scan_id, status)
            try:
                self._finalize()
            except Exception as exc:  # noqa: BLE001 - never mask cancellation
                self.logger.error(f"partial report generation failed: {exc}")
            raise
        except Exception as exc:  # noqa: BLE001 - persist partial work
            status = "failed"
            failure = exc
            self.logger.error(f"fatal orchestrator error: {exc}")
        finally:
            self.db.finish_scan(self.scan_id, status)
        bundle = self._finalize()
        if failure is not None:
            raise failure
        return bundle

    async def _run_phases(self) -> None:
        cfg = self.config
        out = cfg.output_dir

        # 1) Passive subdomain discovery ---------------------------------
        if cfg.passive:
            self.logger.start_phase("passive", "certificate transparency & passive DNS")
            self.tasks.start("passive")
            cached_subs = self._load_subdomains() if (cfg.resume and not cfg.wordlist_bruteforce) else None
            if cached_subs is not None and cached_subs.hosts:
                self.state.subdomains = cached_subs
                write_subdomain_outputs(self.state.subdomains, out)
                self.tasks.finish("passive", f"{len(self.state.subdomains.hosts)} hosts (resumed)")
                self.logger.info(f"reused {len(self.state.subdomains.hosts)} subdomains from database")
                self.logger.set_count("subdomains", len(self.state.subdomains.hosts))
            else:
                engine = SubdomainEngine(
                    self.scope, self.sources, dns_engine=self.dns, logger=self.logger
                )
                words = self._load_wordlist() if cfg.wordlist_bruteforce else None
                try:
                    self.state.subdomains = await engine.run(brute_words=words)
                    write_subdomain_outputs(self.state.subdomains, out)
                    self._persist_subdomains(self.state.subdomains)
                    self.tasks.finish("passive", f"{len(self.state.subdomains.hosts)} hosts")
                    self.logger.set_count("subdomains", len(self.state.subdomains.hosts))
                except Exception as exc:  # noqa: BLE001
                    self.tasks.fail("passive", str(exc))
                    self.logger.error(f"passive phase failed: {exc}")
                    self.state.subdomains = self._load_subdomains()
        else:
            self.tasks.skip("passive", "disabled")
            self.state.subdomains = self._load_subdomains()
            if self.state.subdomains is None:
                self.state.subdomains = SubdomainResult(root=self.scope.root)
                self.state.subdomains.hosts = [
                    {"hostname": self.scope.root, "sources": ["root"], "source": "root"}
                ]

        hostnames = self.state.subdomains.hostnames if self.state.subdomains else [self.scope.root]

        # 2) DNS ----------------------------------------------------------
        if cfg.dns:
            self.logger.start_phase("dns", "native DNS resolution")
            self.tasks.start("dns")
            cached_dns = self._dns_from_db() if cfg.resume else None
            if cached_dns is not None and cached_dns.records:
                self.state.dns = cached_dns
                write_dns_outputs(self.state.dns, out)
                self.tasks.finish("dns", f"{len(self.state.dns.resolved)} resolved (resumed)")
                self.logger.info(f"reused {len(self.state.dns.records)} DNS records from database")
                self.logger.set_count("dns_resolved", len(self.state.dns.resolved))
                self.logger.set_count("dns_unresolved", len(self.state.dns.unresolved))
                self.logger.set_count("dangling_cnames", len(self.state.dns.dangling))
            else:
                try:
                    self.state.dns = await run_dns(
                        self.dns, hostnames, self.scope.root, self.logger
                    )
                    write_dns_outputs(self.state.dns, out)
                    self._persist_dns(self.state.dns)
                    self.tasks.finish("dns", f"{len(self.state.dns.resolved)} resolved")
                    self.logger.set_count("dns_resolved", len(self.state.dns.resolved))
                    self.logger.set_count("dns_unresolved", len(self.state.dns.unresolved))
                    self.logger.set_count("dangling_cnames", len(self.state.dns.dangling))
                except Exception as exc:  # noqa: BLE001
                    self.tasks.fail("dns", str(exc))
                    self.logger.error(f"dns phase failed: {exc}")
                    self.state.dns = self._dns_from_db()
        else:
            self.tasks.skip("dns", "disabled")
            self.state.dns = self._dns_from_db()

        probe_hosts = hostnames
        if self.state.dns is not None and self.state.dns.resolved:
            probe_hosts = self.state.dns.resolved

        # 3) Live hosts / HTTP -------------------------------------------
        if cfg.live:
            self.logger.start_phase("live", "safe HTTP/HTTPS probing")
            self.tasks.start("live")
            cached_http = self._http_from_db() if cfg.resume else None
            if cached_http is not None and cached_http.records:
                self.state.http = cached_http
                write_http_outputs(self.state.http, out)
                self.tasks.finish("live", f"{len(self.state.http.live_hosts)} live (resumed)")
                self.logger.info(f"reused {len(self.state.http.records)} HTTP records from database")
                self.logger.set_count("live_hosts", len(self.state.http.live_hosts))
            else:
                try:
                    live_engine = LiveHostEngine(
                        self.scope,
                        timeout=cfg.timeout,
                        concurrency=cfg.concurrency,
                        retries=cfg.retries,
                        rate_limit_rps=cfg.rate_limit_rps or self.scope.rate_limit_rps,
                        logger=self.logger,
                    )
                    self.state.http = await live_engine.run(
                        probe_hosts,
                        all_hosts=hostnames,
                        dns_result=self.state.dns,
                    )
                    write_http_outputs(self.state.http, out)
                    self._persist_http(self.state.http)
                    self.tasks.finish("live", f"{len(self.state.http.live_hosts)} live")
                    self.logger.set_count("live_hosts", len(self.state.http.live_hosts))
                except Exception as exc:  # noqa: BLE001
                    self.tasks.fail("live", str(exc))
                    self.logger.error(f"live phase failed: {exc}")
                    self.state.http = self._http_from_db()
        else:
            self.tasks.skip("live", "disabled")
            self.state.http = self._http_from_db()

        # 4) TLS ----------------------------------------------------------
        if cfg.tls:
            self.logger.start_phase("tls", "certificate inspection")
            self.tasks.start("tls")
            cached_tls = self._tls_from_db() if cfg.resume else None
            if cached_tls is not None and cached_tls.results:
                self.state.tls = cached_tls
                write_tls_outputs(self.state.tls, out)
                self.tasks.finish(
                    "tls",
                    f"{sum(1 for r in self.state.tls.results if r.connected)} connected (resumed)",
                )
                self.logger.info(f"reused {len(self.state.tls.results)} TLS records from database")
            else:
                try:
                    tls_hosts = probe_hosts
                    if self.state.http is not None and self.state.http.best_https():
                        tls_hosts = sorted(self.state.http.best_https().keys())
                    tls_engine = TLSEngine(
                        self.scope,
                        timeout=cfg.timeout,
                        concurrency=cfg.concurrency,
                        logger=self.logger,
                    )
                    self.state.tls = await tls_engine.run(tls_hosts)
                    write_tls_outputs(self.state.tls, out)
                    self._persist_tls(self.state.tls)
                    self.tasks.finish(
                        "tls", f"{sum(1 for r in self.state.tls.results if r.connected)} connected"
                    )
                except Exception as exc:  # noqa: BLE001
                    self.tasks.fail("tls", str(exc))
                    self.logger.error(f"tls phase failed: {exc}")
        else:
            self.tasks.skip("tls", "disabled")
            if cfg.resume:
                self.state.tls = self._tls_from_db()

        # 5) Historical URLs ---------------------------------------------
        if cfg.historical:
            self.logger.start_phase("historical", "Internet Archive, Common Crawl, OTX")
            self.tasks.start("historical")
            cached_hist = self._historical_from_db() if cfg.resume else None
            if cached_hist is not None and cached_hist.records:
                self.state.historical = cached_hist
                write_historical_outputs(self.state.historical, out)
                self._merge_historical_subdomains(self.state.historical, out)
                self.tasks.finish(
                    "historical", f"{len(self.state.historical.records)} in-scope URLs (resumed)"
                )
                self.logger.info(
                    f"reused {len(self.state.historical.records)} historical URLs from database"
                )
                self.logger.set_count(
                    "historical_urls", len(self.state.historical.records)
                )
            else:
                try:
                    hist_engine = HistoricalURLEngine(
                        self.scope,
                        self.sources,
                        max_urls=cfg.max_urls,
                        logger=self.logger,
                    )
                    self.state.historical = await hist_engine.run(
                        host_classifications=(
                            self.state.http.host_classifications
                            if self.state.http is not None
                            else None
                        ),
                        check_urls=cfg.check_historical_urls,
                        max_checks=cfg.max_url_checks,
                        timeout=cfg.timeout,
                        rate_limit_rps=cfg.rate_limit_rps or self.scope.rate_limit_rps,
                    )
                    write_historical_outputs(self.state.historical, out)
                    self._persist_historical(self.state.historical)
                    self._merge_historical_subdomains(self.state.historical, out)
                    self.tasks.finish(
                        "historical", f"{len(self.state.historical.records)} in-scope URLs"
                    )
                    self.logger.set_count(
                        "historical_urls", len(self.state.historical.records)
                    )
                except Exception as exc:  # noqa: BLE001
                    self.tasks.fail("historical", str(exc))
                    self.logger.error(f"historical phase failed: {exc}")
                    self.state.historical = self._historical_from_db()
        else:
            self.tasks.skip("historical", "disabled")
            self.state.historical = self._historical_from_db()

        hist_urls = (
            [record.normalized for record in self.state.historical.in_scope]
            if self.state.historical is not None
            else []
        )
        live_urls = (
            [record.final_url or record.url for record in self.state.http.records]
            if self.state.http is not None
            else []
        )

        # 6) File extension filtering ------------------------------------
        if cfg.filter and hist_urls:
            self.logger.start_phase("filter", "file-extension classification")
            self.tasks.start("filter")
            try:
                filter_engine = URLFilterEngine()
                self.state.filter_result = filter_engine.run(hist_urls)
                filter_engine.write_outputs(self.state.filter_result, out)
                self._persist_filter(self.state.filter_result)
                self.tasks.finish(
                    "filter",
                    f"{sum(self.state.filter_result.stats.values())} classified",
                )
            except Exception as exc:  # noqa: BLE001
                self.tasks.fail("filter", str(exc))
                self.logger.error(f"filter phase failed: {exc}")
        else:
            self.tasks.skip("filter", "disabled or no historical URLs")
            if cfg.resume:
                self.state.filter_result = self._filter_from_db()

        # 7) JavaScript inventory ----------------------------------------
        if cfg.javascript:
            self.logger.start_phase("javascript", "asset inventory")
            self.tasks.start("javascript")
            cached_js = self._javascript_from_db() if (cfg.resume and not cfg.js_analysis) else None
            if cached_js is not None and cached_js.assets:
                self.state.javascript = cached_js
                JavaScriptEngine(self.scope).write_outputs(self.state.javascript, out)
                self.tasks.finish("javascript", f"{len(self.state.javascript.assets)} assets (resumed)")
                self.logger.set_count("javascript_assets", len(self.state.javascript.assets))
            else:
                try:
                    source_map: dict[str, list[str]] = {}
                    timestamp_map: dict[str, str] = {}
                    if self.state.historical is not None:
                        for rec in self.state.historical.in_scope:
                            source_map[rec.normalized] = list(rec.sources)
                            if rec.timestamp:
                                timestamp_map[rec.normalized] = rec.timestamp
                    js_engine = JavaScriptEngine(
                        self.scope,
                        timeout=cfg.timeout,
                        concurrency=min(cfg.concurrency, 10),
                        logger=self.logger,
                    )
                    self.state.javascript = await js_engine.run(
                        hist_urls,
                        live_urls,
                        analyze=cfg.js_analysis,
                        source_map=source_map,
                        timestamp_map=timestamp_map,
                        host_classifications=(
                            self.state.http.host_classifications
                            if self.state.http is not None
                            else None
                        ),
                    )
                    js_engine.write_outputs(self.state.javascript, out)
                    self._persist_javascript(self.state.javascript)
                    self.tasks.finish("javascript", f"{len(self.state.javascript.assets)} assets")
                    self.logger.set_count(
                        "javascript_assets", len(self.state.javascript.assets)
                    )
                except Exception as exc:  # noqa: BLE001
                    self.tasks.fail("javascript", str(exc))
                    self.logger.error(f"javascript phase failed: {exc}")
        else:
            self.tasks.skip("javascript", "disabled")
            if cfg.resume:
                self.state.javascript = self._javascript_from_db()

        # 8) Sensitive indicators ----------------------------------------
        if cfg.sensitive:
            self.logger.start_phase("sensitive", "path & parameter-name indicators")
            self.tasks.start("sensitive")
            try:
                sensitive_urls = list(hist_urls)
                if self.state.javascript is not None:
                    sensitive_urls.extend(self.state.javascript.urls)
                    for asset in self.state.javascript.assets:
                        for ep in asset.endpoints:
                            if ep.startswith("/"):
                                resolved_ep = resolve_redirect(asset.normalized, ep)
                                if resolved_ep:
                                    sensitive_urls.append(resolved_ep)
                            else:
                                sensitive_urls.append(ep)
                sensitive_urls.extend(live_urls)
                sensitive_engine = SensitiveDetectionEngine()
                self.state.sensitive = sensitive_engine.run(sensitive_urls)
                sensitive_engine.write_outputs(self.state.sensitive, out)
                self._persist_sensitive(self.state.sensitive)
                self.tasks.finish(
                    "sensitive", f"{len(self.state.sensitive.indicators)} indicators"
                )
                self.logger.set_count(
                    "sensitive_indicators", len(self.state.sensitive.indicators)
                )
            except Exception as exc:  # noqa: BLE001
                self.tasks.fail("sensitive", str(exc))
                self.logger.error(f"sensitive phase failed: {exc}")
        else:
            self.tasks.skip("sensitive", "disabled")
            if cfg.resume:
                self.state.sensitive = self._sensitive_from_db()

        # 9) Takeover analysis -------------------------------------------
        if cfg.takeover and self.state.dns is not None:
            self.logger.start_phase("takeover", "passive dangling-DNS analysis")
            self.tasks.start("takeover")
            cached_takeover = self._takeover_from_db() if cfg.resume else None
            if cached_takeover is not None and cached_takeover.candidates:
                self.state.takeover = cached_takeover
                TakeoverEngine().write_outputs(self.state.takeover, out)
                self.tasks.finish(
                    "takeover", f"{len(self.state.takeover.candidates)} candidates (resumed)"
                )
                self.logger.set_count(
                    "takeover_candidates", len(self.state.takeover.candidates)
                )
            else:
                try:
                    http_map: dict[str, object] = {}
                    if self.state.http is not None:
                        http_map = self.state.http.best_https()
                        # Include HTTP responses when no HTTPS result exists.
                        for host, records in self.state.http.by_host().items():
                            if host not in http_map and records:
                                http_map[host] = records[0]
                    takeover_engine = TakeoverEngine(
                        dns_engine=(None if cfg.resume else self.dns), logger=self.logger
                    )
                    self.state.takeover = await takeover_engine.run(
                        self.state.dns, http_map
                    )
                    takeover_engine.write_outputs(self.state.takeover, out)
                    self._persist_takeover(self.state.takeover)
                    self.tasks.finish(
                        "takeover", f"{len(self.state.takeover.candidates)} candidates"
                    )
                    self.logger.set_count(
                        "takeover_candidates", len(self.state.takeover.candidates)
                    )
                except Exception as exc:  # noqa: BLE001
                    self.tasks.fail("takeover", str(exc))
                    self.logger.error(f"takeover phase failed: {exc}")
        else:
            self.tasks.skip("takeover", "disabled or no DNS data")
            if cfg.resume:
                self.state.takeover = self._takeover_from_db()

        # 10) Results Organization & Bug Bounty Asset Intelligence -------
        try:
            results_engine = ResultsProcessingEngine(self.scope)
            self.state.organized = results_engine.process(
                subdomains=self.state.subdomains,
                dns=self.state.dns,
                http=self.state.http,
                tls=self.state.tls,
                historical=self.state.historical,
            )
            results_engine.write_outputs(
                self.state.organized,
                out,
                historical=self.state.historical,
                sensitive=self.state.sensitive,
                javascript=self.state.javascript,
            )
            intel_engine = AssetIntelligenceEngine()
            self.state.intelligence = intel_engine.run(
                domain=cfg.domain,
                organized=self.state.organized,
                dns=self.state.dns,
                http=self.state.http,
                tls=self.state.tls,
                historical=self.state.historical,
                sensitive=self.state.sensitive,
                javascript=self.state.javascript,
                takeover=self.state.takeover,
            )
            intel_engine.write_outputs(self.state.intelligence, out)
        except Exception as exc:  # noqa: BLE001
            self.logger.error(f"results/intelligence organization failed: {exc}")

        # 11) Risk --------------------------------------------------------
        self.logger.start_phase("risk", "explainable risk classification")
        self.tasks.start("risk")
        try:
            risk_engine = RiskEngine()
            self.state.risk = risk_engine.run(
                dns_result=self.state.dns,
                http_result=self.state.http,
                tls_result=self.state.tls,
                historical=self.state.historical,
                sensitive=self.state.sensitive,
                filter_result=self.state.filter_result,
                takeover=self.state.takeover,
                js_count=len(self.state.javascript.assets) if self.state.javascript else 0,
                subdomain_count=(
                    len(self.state.subdomains.hosts) if self.state.subdomains else 0
                ),
            )
            write_risk_outputs(self.state.risk, out)
            self.tasks.finish(
                "risk", f"overall {self.state.risk.overall_severity}"
            )
        except Exception as exc:  # noqa: BLE001
            self.tasks.fail("risk", str(exc))
            self.logger.error(f"risk phase failed: {exc}")

    # ------------------------------------------------------------------
    def _finalize(self) -> dict:
        cfg = self.config
        self._refresh_counts()
        duration = time.monotonic() - self.started_at
        bundle = self._bundle(duration)
        if cfg.report and cfg.is_phase_enabled("report"):
            self.logger.start_phase("report", "HTML / JSON / TXT")
            self.tasks.start("report")
            try:
                paths = generate_reports(bundle, cfg.output_dir)
                self.tasks.finish("report", ", ".join(p.name for p in paths.values()))
                self.logger.success(
                    "reports written: " + ", ".join(str(p) for p in paths.values())
                )
            except Exception as exc:  # noqa: BLE001
                self.tasks.fail("report", str(exc))
                self.logger.error(f"report generation failed: {exc}")
        else:
            self.tasks.skip("report", "disabled")

        summary = redact_structure({
            "domain": cfg.domain,
            "duration_seconds": round(duration, 3),
            "duration_human": human_duration(duration),
            "phases": [t.as_dict() for t in self.tasks.tasks.values()],
            "counts": dict(self.logger.counters),
            "errors": self.logger.errors,
            "output_dir": str(cfg.output_dir),
        })
        (cfg.output_dir / "scan_summary.json").write_text(
            json.dumps(summary, indent=2, default=str), encoding="utf-8"
        )
        self.db.set_meta(cfg.domain, "last_summary", summary)
        return bundle

    def _refresh_counts(self) -> None:
        if self.state.subdomains is not None:
            self.logger.set_count("subdomains", len(self.state.subdomains.hosts))
        if self.state.dns is not None:
            self.logger.set_count("dns_resolved", len(self.state.dns.resolved))
            self.logger.set_count("dns_unresolved", len(self.state.dns.unresolved))
            self.logger.set_count("dangling_cnames", len(self.state.dns.dangling))
        if self.state.http is not None:
            self.logger.set_count("live_hosts", len(self.state.http.live_hosts))
        if self.state.historical is not None:
            self.logger.set_count("historical_urls", len(self.state.historical.records))
        if self.state.sensitive is not None:
            self.logger.set_count("sensitive_indicators", len(self.state.sensitive.indicators))
        if self.state.javascript is not None:
            self.logger.set_count("javascript_assets", len(self.state.javascript.assets))
        if self.state.takeover is not None:
            self.logger.set_count("takeover_candidates", len(self.state.takeover.candidates))

    def _bundle(self, duration: float) -> dict:
        sources = []
        if self.state.subdomains:
            sources.extend(s.as_dict() for s in self.state.subdomains.sources)
        if self.state.historical:
            sources.extend(s.as_dict() for s in self.state.historical.sources)
        return {
            "meta": {
                "tool": TOOL_NAME,
                "version": VERSION,
                "domain": self.config.domain,
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "duration_seconds": round(duration, 3),
                "duration_human": human_duration(duration),
                "output_dir": str(self.config.output_dir),
                "phases_enabled": self.config.enabled_phases(),
            },
            "subdomains": self.state.subdomains.as_dict() if self.state.subdomains else {},
            "dns": self.state.dns.as_dict() if self.state.dns else {},
            "http": self.state.http.as_dict() if self.state.http else {},
            "tls": self.state.tls.as_dict() if self.state.tls else {},
            "historical": self.state.historical.as_dict() if self.state.historical else {},
            "filter": self.state.filter_result.as_dict() if self.state.filter_result else {},
            "sensitive": self.state.sensitive.as_dict() if self.state.sensitive else {},
            "javascript": self.state.javascript.as_dict() if self.state.javascript else {},
            "takeover": self.state.takeover.as_dict() if self.state.takeover else {},
            "organized": self.state.organized.as_dict() if self.state.organized else {},
            "intelligence": self.state.intelligence.as_dict() if self.state.intelligence else {},
            "scope": self.scope.as_dict(),
            "risk": self.state.risk.as_dict() if self.state.risk else {},
            "sources": _dedupe_sources(sources),
            "tasks": self.tasks.as_list(),
            "errors": self.logger.errors,
        }

    # -- persistence ---------------------------------------------------
    def _merge_historical_subdomains(self, historical: HistoricalResult, out: Path) -> None:
        if self.state.subdomains is None:
            return
        existing = {item["hostname"]: item for item in self.state.subdomains.hosts}
        added = 0
        new_items: list[tuple[str, str]] = []
        for record in historical.in_scope:
            host = normalize_hostname(record.hostname)
            if not host or not self.scope.is_in_scope(host):
                continue
            if host not in existing:
                srcs = list(record.sources) if record.sources else ["historical"]
                entry = {"hostname": host, "sources": srcs, "source": srcs[0]}
                existing[host] = entry
                self.state.subdomains.hosts.append(entry)
                for s in srcs:
                    new_items.append((host, s))
                added += 1
        if added:
            self.state.subdomains.hosts.sort(key=lambda item: item["hostname"])
            write_subdomain_outputs(self.state.subdomains, out)
            self.db.upsert_subdomains(self.config.domain, new_items)
            self.logger.set_count("subdomains", len(self.state.subdomains.hosts))

    def _persist_subdomains(self, result: SubdomainResult) -> None:
        with self.db.transaction():
            for item in result.hosts:
                for source in item.get("sources", [item.get("source", "unknown")]):
                    self.db.upsert_subdomain(self.config.domain, item["hostname"], source)

    def _persist_dns(self, result: DNSRunResult) -> None:
        domain = self.config.domain
        with self.db.transaction():
            for record in result.records:
                cname_status = "dangling" if record.dangling else "ok"
                for value in record.a:
                    self.db.add_dns_record(domain, record.hostname, "A", value)
                for value in record.aaaa:
                    self.db.add_dns_record(domain, record.hostname, "AAAA", value)
                for value in record.cname:
                    self.db.add_dns_record(
                        domain, record.hostname, "CNAME", value, status=cname_status
                    )
                for value in record.ns:
                    self.db.add_dns_record(domain, record.hostname, "NS", value)
                for value in record.mx:
                    self.db.add_dns_record(domain, record.hostname, "MX", value)
                for value in record.txt:
                    self.db.add_dns_record(domain, record.hostname, "TXT", value[:4000])
                for value in record.soa:
                    self.db.add_dns_record(domain, record.hostname, "SOA", value)

    def _persist_http(self, result: HTTPRunResult) -> None:
        with self.db.transaction():
            for record in result.records:
                self.db.add_http_result(self.config.domain, record.as_dict())

    def _persist_historical(self, result: HistoricalResult) -> None:
        with self.db.transaction():
            for record in result.records + result.out_of_scope:
                self.db.add_historical_url(
                    self.config.domain,
                    {
                        "url": redact_url(record.url),
                        "normalized": redact_url(record.normalized),
                        "hostname": record.hostname,
                        "path": record.path,
                        "extension": record.extension,
                        "source": ",".join(record.sources),
                        "timestamp": record.timestamp,
                    },
                )

    def _persist_filter(self, result) -> None:
        with self.db.transaction():
            for category, urls in result.categories.items():
                for url in urls:
                    normalized = normalize_url(url) or url
                    self.db.add_file_classification(
                        self.config.domain,
                        category,
                        redact_url(url),
                        redact_url(normalized),
                    )

    def _persist_sensitive(self, result) -> None:
        with self.db.transaction():
            for indicator in result.indicators:
                self.db.add_indicator(
                    self.config.domain,
                    indicator.category,
                    indicator.value,
                    indicator.redacted_url,
                    indicator.severity,
                )

    def _persist_javascript(self, result) -> None:
        with self.db.transaction():
            for asset in result.assets:
                self.db.add_js_asset(self.config.domain, asset.as_dict())

    def _persist_tls(self, result: TLSRunResult) -> None:
        with self.db.transaction():
            for record in result.results:
                self.db.add_tls_result(self.config.domain, record.as_dict())

    def _persist_takeover(self, result) -> None:
        with self.db.transaction():
            for candidate in result.candidates:
                self.db.add_takeover_finding(self.config.domain, candidate.as_dict())

    # -- DB hydration (resume / report-only) ---------------------------
    def _load_subdomains(self) -> SubdomainResult | None:
        rows = self.db.get_subdomains(self.config.domain)
        if not rows:
            return None
        result = SubdomainResult(root=self.scope.root)
        for row in rows:
            try:
                sources = json.loads(row.get("sources") or "[]")
            except (json.JSONDecodeError, TypeError):
                sources = ["previous"]
            result.hosts.append(
                {"hostname": row["hostname"], "sources": sources, "source": sources[0] if sources else "previous"}
            )
        return result

    def _dns_from_db(self) -> DNSRunResult | None:
        from utils.network import assess_ip

        rows = self.db.get_dns_records(self.config.domain)
        if not rows:
            return None
        grouped: dict[str, ResolvedHost] = {}
        for row in rows:
            host = row["hostname"]
            record = grouped.setdefault(host, ResolvedHost(hostname=host))
            rtype = row["rtype"]
            value = row["value"]
            if rtype == "A":
                record.a.append(value)
            elif rtype == "AAAA":
                record.aaaa.append(value)
            elif rtype == "CNAME":
                record.cname.append(value)
                if row.get("status") == "dangling":
                    record.dangling = True
            elif rtype == "NS":
                record.ns.append(value)
            elif rtype == "MX":
                record.mx.append(value)
            elif rtype == "TXT":
                record.txt.append(value)
            elif rtype == "SOA":
                record.soa.append(value)
        result = DNSRunResult(root=self.scope.root)
        for host, record in sorted(grouped.items()):
            for ip in record.a + record.aaaa:
                if not assess_ip(ip).safe:
                    record.private_ips.append(ip)
            record.status = "resolved" if record.resolved else "unresolved"
            result.records.append(record)
            (result.resolved if record.resolved else result.unresolved).append(host)
            for target in record.cname:
                result.cname_records.append({"hostname": host, "target": target})
            if record.dangling:
                result.dangling.append(
                    {
                        "hostname": host,
                        "cname_target": record.cname[-1] if record.cname else "",
                        "records": record.cname,
                    }
                )
            if record.private_ips:
                result.suspicious.append(
                    {
                        "hostname": host,
                        "reason": "private-ip-in-dns",
                        "addresses": record.private_ips,
                    }
                )
        return result

    def _http_from_db(self) -> HTTPRunResult | None:
        rows = self.db.get_http_results(self.config.domain)
        if not rows:
            return None
        run = HTTPRunResult()
        live: set[str] = set()
        for row in rows:
            try:
                chain = json.loads(row.get("redirect_chain") or "[]")
            except (json.JSONDecodeError, TypeError):
                chain = []
            try:
                technologies = json.loads(row.get("technologies") or "[]")
            except (json.JSONDecodeError, TypeError):
                technologies = []
            result = HTTPResult(
                url=row["url"],
                final_url=row.get("final_url") or "",
                scheme=row.get("scheme") or "",
                hostname=row.get("hostname") or "",
                status=row.get("status"),
                headers={},
                title=row.get("title") or "",
                server=row.get("server") or "",
                content_type=row.get("content_type") or "",
                content_length=row.get("content_length"),
                elapsed=row.get("elapsed") or 0.0,
                redirect_chain=chain,
                technologies=technologies if isinstance(technologies, list) else [],
                tls_verified=(
                    bool(row["tls_verified"]) if row.get("tls_verified") is not None else None
                ),
                error=row.get("error") or "",
            )
            run.records.append(result)
            if result.status is not None and result.status != 429:
                live.add(result.hostname)
        for host, probes in run.by_host().items():
            run.host_classifications[host] = summarize_host(host, probes)
        run.live_hosts = sorted(live)
        return run

    def _historical_from_db(self) -> HistoricalResult | None:
        rows = self.db.get_historical_urls(self.config.domain)
        if not rows:
            return None
        result = HistoricalResult()
        for row in rows:
            normalized = row.get("normalized") or ""
            parsed = split_url(normalized)
            record = HistoricalRecord(
                url=row.get("url") or normalized,
                normalized=normalized,
                hostname=row.get("hostname") or parsed.host,
                path=row.get("path") or get_path(normalized),
                query=parsed.query,
                extension=row.get("extension") or get_extension(normalized),
                params=extract_param_names(parsed.query),
                sources=(row.get("source") or "previous").split(","),
                timestamp=row.get("timestamp") or "",
                in_scope=self.scope.is_in_scope(row.get("hostname") or parsed.host),
            )
            if record.in_scope:
                result.records.append(record)
            else:
                result.out_of_scope.append(record)
        return result

    def _javascript_from_db(self) -> JSResult | None:
        rows = self.db.get_js_assets(self.config.domain)
        if not rows:
            return None
        result = JSResult()
        for row in rows:
            try:
                sources = json.loads(row.get("sources") or "[]")
                params = json.loads(row.get("params") or "[]")
                endpoints = json.loads(row.get("endpoints") or "[]")
            except (json.JSONDecodeError, TypeError):
                sources, params, endpoints = [], [], []
            result.assets.append(
                JSAsset(
                    url=row.get("url") or "",
                    normalized=row.get("normalized") or "",
                    hostname=row.get("hostname") or "",
                    sources=sources if isinstance(sources, list) else [],
                    extension=row.get("extension") or "",
                    params=params if isinstance(params, list) else [],
                    live_status=row.get("live_status"),
                    content_length=row.get("content_length"),
                    endpoints=endpoints if isinstance(endpoints, list) else [],
                    analyzed=bool(row.get("analyzed")),
                    error=row.get("error") or "",
                )
            )
        return result

    def _tls_from_db(self) -> TLSRunResult | None:
        rows = self.db.get_tls_results(self.config.domain)
        if not rows:
            return None
        run = TLSRunResult()
        for row in rows:
            try:
                subject = json.loads(row.get("subject") or "{}")
                issuer = json.loads(row.get("issuer") or "{}")
                sans = json.loads(row.get("sans") or "[]")
            except (json.JSONDecodeError, TypeError):
                subject, issuer, sans = {}, {}, []
            run.results.append(
                TLSResult(
                    hostname=row["hostname"],
                    port=int(row.get("port") or 443),
                    connected=bool(row.get("connected")),
                    verified=bool(row.get("verified")),
                    verification_error=row.get("verification_error") or "",
                    protocol=row.get("protocol") or "",
                    cipher=row.get("cipher") or "",
                    subject=subject if isinstance(subject, dict) else {},
                    issuer=issuer if isinstance(issuer, dict) else {},
                    serial_number=row.get("serial_number") or "",
                    not_before=row.get("not_before") or "",
                    not_after=row.get("not_after") or "",
                    sans=sans if isinstance(sans, list) else [],
                    expired=(
                        None if row.get("expired") is None else bool(row.get("expired"))
                    ),
                    days_until_expiry=row.get("days_until_expiry"),
                    hostname_matches=(
                        None
                        if row.get("hostname_matches") is None
                        else bool(row.get("hostname_matches"))
                    ),
                    error=row.get("error") or "",
                )
            )
        return run

    def _filter_from_db(self) -> FilterResult | None:
        rows = self.db.get_file_classifications(self.config.domain)
        if not rows:
            return None
        categories: dict[str, list[str]] = {}
        classified: set[str] = set()
        for row in rows:
            normalized = row.get("normalized") or row.get("url") or ""
            if not normalized:
                continue
            categories.setdefault(row.get("category") or "uncategorized", []).append(
                normalized
            )
            classified.add(normalized)
        total = (
            len(self.state.historical.records)
            if self.state.historical is not None
            else len(classified)
        )
        stats = {name: len(urls) for name, urls in categories.items()}
        return FilterResult(
            categories=categories,
            stats=stats,
            total_urls=total,
            uncategorized=max(0, total - len(classified)),
        )

    def _sensitive_from_db(self) -> SensitiveResult | None:
        rows = self.db.get_indicators(self.config.domain)
        if not rows:
            return None
        urls = []
        seen = set()
        for row in rows:
            u = row.get("url") or ""
            if u and u not in seen:
                seen.add(u)
                urls.append(u)
        if urls:
            return SensitiveDetectionEngine().run(urls)
        return None

    def _takeover_from_db(self) -> TakeoverResult | None:
        rows = self.db.get_takeover_findings(self.config.domain)
        if not rows:
            return None
        result = TakeoverResult(analyzed_targets=len(rows))
        for row in rows:
            try:
                evidence = json.loads(row.get("evidence") or "[]")
            except (json.JSONDecodeError, TypeError):
                evidence = []
            result.candidates.append(
                TakeoverCandidate(
                    hostname=row.get("hostname") or "",
                    cname_target=row.get("cname_target") or "",
                    provider_name=row.get("provider") or "",
                    confidence=int(row.get("confidence") or 0),
                    classification=row.get("classification") or "Needs Manual Review",
                    evidence=evidence if isinstance(evidence, list) else [],
                )
            )
        return result

    def _load_wordlist(self) -> list[str]:
        path = Path(self.config.wordlist_path)
        try:
            return [
                line.strip()
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")
            ]
        except OSError:
            self.logger.warn(f"wordlist not found: {path}")
            return []


def _dedupe_sources(items: list[dict]) -> list[dict]:
    merged: dict[str, dict] = {}
    for item in items:
        name = item.get("source", "unknown")
        if name in merged:
            merged[name]["count"] = int(merged[name].get("count", 0)) + int(
                item.get("count", 0)
            )
            if item.get("error") and not merged[name].get("error"):
                merged[name]["error"] = item["error"]
            merged[name]["cached"] = bool(
                merged[name].get("cached") or item.get("cached")
            )
        else:
            merged[name] = dict(item)
    return list(merged.values())
