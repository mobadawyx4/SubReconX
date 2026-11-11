"""Historical URL collection, normalization and dataset assembly."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import json
from pathlib import Path
import time

from config import MAX_HTTP_BODY
from core.event_logger import EventLogger
from core.scope_manager import ScopeManager
from engines.live_host_engine import classify_host_liveness
from engines.url_filter_engine import URLFilterEngine
from protocols.http_protocol import fetch
from sources.base import SourceResult
from sources.source_manager import SourceManager
from utils.redaction import redact_url
from utils.url_utils import (
    extract_param_names,
    get_extension,
    get_path,
    normalize_url,
    split_url,
)
from utils.validators import is_valid_hostname, normalize_hostname


@dataclass
class HistoricalRecord:
    url: str
    normalized: str
    hostname: str
    path: str
    query: str
    extension: str
    params: list[str]
    sources: list[str]
    timestamp: str
    in_scope: bool
    within_root_boundary: bool = True
    categories: list[str] = field(default_factory=list)
    liveness: str = "UNKNOWN"
    liveness_basis: str = "unprobed"
    http_status: int | None = None

    def as_dict(self) -> dict:
        return {
            "url": redact_url(self.url),
            "normalized": redact_url(self.normalized),
            "hostname": self.hostname,
            "path": self.path,
            "extension": self.extension,
            "categories": self.categories,
            "params": self.params,
            "sources": self.sources,
            "timestamp": self.timestamp,
            "in_scope": self.in_scope,
            "within_root_boundary": self.within_root_boundary,
            "liveness": self.liveness,
            "liveness_basis": self.liveness_basis,
            "http_status": self.http_status,
        }


@dataclass
class HistoricalResult:
    records: list[HistoricalRecord] = field(default_factory=list)
    out_of_scope: list[HistoricalRecord] = field(default_factory=list)
    raw_records: list[dict] = field(default_factory=list)
    malformed: list[str] = field(default_factory=list)
    sources: list[SourceResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def in_scope(self) -> list[HistoricalRecord]:
        return [record for record in self.records if record.in_scope]

    @property
    def all_unique(self) -> list[HistoricalRecord]:
        return list(self.records) + list(self.out_of_scope)

    @property
    def with_parameters(self) -> list[HistoricalRecord]:
        return [record for record in self.in_scope if record.params]

    @property
    def live_urls(self) -> list[HistoricalRecord]:
        return [record for record in self.in_scope if record.liveness == "LIVE"]

    @property
    def dead_urls(self) -> list[HistoricalRecord]:
        return [record for record in self.in_scope if record.liveness == "DEAD"]

    @property
    def unknown_urls(self) -> list[HistoricalRecord]:
        return [record for record in self.in_scope if record.liveness == "UNKNOWN"]

    def source_stats(self) -> dict[str, int]:
        stats: dict[str, int] = {}
        for record in self.records:
            for source in record.sources:
                if source:
                    stats[source] = stats.get(source, 0) + 1
        return stats

    def as_dict(self) -> dict:
        return {
            "total": len(self.records),
            "total_raw": len(self.raw_records) if self.raw_records else (len(self.records) + len(self.out_of_scope)),
            "unique_count": len(self.records) + len(self.out_of_scope),
            "in_scope": len(self.in_scope),
            "out_of_scope": len(self.out_of_scope),
            "with_parameters": len(self.with_parameters),
            "live_count": len(self.live_urls),
            "dead_count": len(self.dead_urls),
            "unknown_count": len(self.unknown_urls),
            "malformed": self.malformed[:500],
            "source_stats": self.source_stats(),
            "sources": [s.as_dict() for s in self.sources],
            "errors": self.errors,
            "records": [record.as_dict() for record in self.records],
            "out_of_scope_records": [record.as_dict() for record in self.out_of_scope],
        }


class HistoricalURLEngine:
    def __init__(
        self,
        scope: ScopeManager,
        source_manager: SourceManager,
        *,
        max_urls: int = 100_000,
        logger: EventLogger | None = None,
    ):
        self.scope = scope
        self.sources = source_manager
        self.max_urls = max_urls
        self.logger = logger
        self._classifier = URLFilterEngine()

    async def run(
        self,
        *,
        host_classifications: dict[str, dict] | None = None,
        check_urls: bool = False,
        max_checks: int = 50,
        timeout: float = 10.0,
        concurrency: int = 5,
        rate_limit_rps: float = 0.0,
    ) -> HistoricalResult:
        result = HistoricalResult()
        raw_records, source_results = await self.sources.collect_urls()
        result.sources = source_results
        for source in source_results:
            if source.error and self.logger:
                self.logger.warn(f"source {source.source}: {source.error}")
            elif self.logger:
                self.logger.debug(f"source {source.source}: {source.count} URLs")

        by_redacted: dict[str, HistoricalRecord] = {}
        for raw in raw_records:
            raw_copy = dict(raw)
            if raw_copy.get("url"):
                raw_copy["url"] = redact_url(str(raw_copy["url"]))
            if raw_copy.get("normalized"):
                raw_copy["normalized"] = redact_url(str(raw_copy["normalized"]))
            result.raw_records.append(raw_copy)
            if len(by_redacted) >= self.max_urls:
                if self.logger:
                    self.logger.warn(f"historical URL cap reached ({self.max_urls})")
                break
            original = str(raw.get("url", "") or raw.get("normalized", "") or "").strip()
            normalized = normalize_url(original)
            if normalized is None:
                if original and len(result.malformed) < 500:
                    result.malformed.append(redact_url(original[:2048]))
                continue

            parsed = split_url(normalized)
            host = normalize_hostname(parsed.host)
            if not host or not is_valid_hostname(host):
                if original and len(result.malformed) < 500:
                    result.malformed.append(redact_url(original[:2048]))
                continue

            redacted_norm = redact_url(normalized)
            redacted_parsed = split_url(redacted_norm)
            raw_sources = raw.get("sources")
            if isinstance(raw_sources, list):
                sources = [str(s) for s in raw_sources if s]
            else:
                source = raw.get("source", "")
                sources = [str(source)] if source else []
            if not sources:
                sources = ["unknown"]
            timestamp = str(raw.get("timestamp", "") or "")

            if redacted_norm in by_redacted:
                existing = by_redacted[redacted_norm]
                for s in sources:
                    if s and s not in existing.sources:
                        existing.sources.append(s)
                if timestamp and (not existing.timestamp or timestamp > existing.timestamp):
                    existing.timestamp = timestamp
                continue

            in_scope = self.scope.is_in_scope(host)
            within_boundary = self.scope.is_within_root_boundary(host)
            record = HistoricalRecord(
                url=redact_url(original),
                normalized=redacted_norm,
                hostname=host,
                path=get_path(normalized),
                query=redacted_parsed.query,
                extension=get_extension(normalized),
                params=extract_param_names(parsed.query),
                sources=sources,
                timestamp=timestamp,
                in_scope=in_scope,
                within_root_boundary=within_boundary,
                categories=self._classifier.classify(normalized),
            )
            by_redacted[redacted_norm] = record
            if record.in_scope:
                result.records.append(record)
            else:
                result.out_of_scope.append(record)

        self.apply_liveness(result, host_classifications=host_classifications)
        if check_urls and self.scope.allow_active_probing and result.in_scope:
            await self.probe_authorized_urls(
                result,
                max_checks=max_checks,
                timeout=timeout,
                concurrency=concurrency,
                rate_limit_rps=rate_limit_rps or self.scope.rate_limit_rps,
            )

        if self.logger:
            self.logger.success(
                f"historical URLs: {len(result.records)} in-scope, "
                f"{len(result.out_of_scope)} out-of-scope, "
                f"{len(result.malformed)} malformed"
            )
        return result

    def apply_liveness(
        self,
        result: HistoricalResult,
        *,
        host_classifications: dict[str, dict] | None = None,
        direct_url_status: dict[str, tuple[str, int | None]] | None = None,
    ) -> None:
        host_classifications = host_classifications or {}
        direct_url_status = direct_url_status or {}
        for record in result.records:
            if not record.in_scope:
                record.liveness = "UNKNOWN"
                record.liveness_basis = "out_of_scope"
                continue
            if record.normalized in direct_url_status:
                cls, status = direct_url_status[record.normalized]
                record.liveness = cls
                record.http_status = status
                record.liveness_basis = "direct_probe"
                continue
            host_info = host_classifications.get(record.hostname)
            if host_info:
                host_cls = str(host_info.get("classification", "UNKNOWN")).upper()
                if host_cls in ("LIVE", "DEAD", "UNKNOWN"):
                    record.liveness = host_cls
                    record.liveness_basis = f"host_{host_cls.lower()}"
                    if host_cls == "LIVE" and record.path in ("", "/"):
                        record.http_status = host_info.get("status")
                    continue
            record.liveness = "UNKNOWN"
            record.liveness_basis = "unprobed"

    async def probe_authorized_urls(
        self,
        result: HistoricalResult,
        *,
        max_checks: int = 50,
        timeout: float = 10.0,
        concurrency: int = 5,
        rate_limit_rps: float = 0.0,
    ) -> None:
        if not self.scope.allow_active_probing:
            return
        candidates = [
            rec
            for rec in result.in_scope
            if self.scope.check_url(rec.normalized).allowed
            and rec.liveness != "DEAD"
        ][: max(0, int(max_checks))]
        if not candidates:
            return
        sem = asyncio.Semaphore(max(1, min(concurrency, 10)))
        rate_lock = asyncio.Lock()
        last_req = 0.0
        effective_rps = rate_limit_rps if rate_limit_rps > 0 else 5.0

        async def _check_one(rec: HistoricalRecord) -> None:
            nonlocal last_req
            async with sem:
                min_interval = 1.0 / effective_rps
                async with rate_lock:
                    now = time.monotonic()
                    wait_for = (last_req + min_interval) - now
                    if wait_for > 0:
                        await asyncio.sleep(wait_for)
                    last_req = time.monotonic()
                resp = await fetch(
                    rec.normalized,
                    self.scope,
                    timeout=timeout,
                    max_body=min(MAX_HTTP_BODY, 32 * 1024),
                )
                cls, _reason = classify_host_liveness([resp])
                rec.liveness = cls
                rec.liveness_basis = "direct_probe"
                rec.http_status = resp.status

        await asyncio.gather(*[_check_one(rec) for rec in candidates])


def write_historical_outputs(result: HistoricalResult, output_dir: Path) -> None:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    def _dedupe(items: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for item in items:
            if item and item not in seen:
                seen.add(item)
                out.append(item)
        return out

    unique_urls = _dedupe(
        [
            redact_url(record.normalized)
            for record in result.records + result.out_of_scope
        ]
    )
    in_scope = _dedupe([redact_url(record.normalized) for record in result.in_scope])
    out_of_scope = _dedupe(
        [redact_url(record.normalized) for record in result.out_of_scope]
    )
    live_urls = _dedupe([redact_url(record.normalized) for record in result.live_urls])
    dead_urls = _dedupe([redact_url(record.normalized) for record in result.dead_urls])
    unknown_urls = _dedupe(
        [redact_url(record.normalized) for record in result.unknown_urls]
    )
    param_urls = _dedupe(
        [redact_url(record.normalized) for record in result.with_parameters]
    )

    def _write_list(path: Path, items: list[str]) -> None:
        path.write_text("\n".join(items) + ("\n" if items else ""), encoding="utf-8")

    _write_list(output_dir / "urls_all.txt", unique_urls)
    _write_list(output_dir / "urls_unique.txt", unique_urls)
    _write_list(output_dir / "urls_in_scope.txt", in_scope)
    _write_list(output_dir / "urls_out_of_scope.txt", out_of_scope)
    _write_list(output_dir / "urls_live.txt", live_urls)
    _write_list(output_dir / "urls_dead.txt", dead_urls)
    _write_list(output_dir / "urls_unknown.txt", unknown_urls)
    _write_list(output_dir / "urls_with_parameters.txt", param_urls)

    payload = result.as_dict()
    (output_dir / "urls_all.json").write_text(
        json.dumps(payload, indent=2, default=str), encoding="utf-8"
    )
    (output_dir / "urls.json").write_text(
        json.dumps(payload, indent=2, default=str), encoding="utf-8"
    )
