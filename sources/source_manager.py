"""Passive-source orchestration with per-source failure isolation."""

from __future__ import annotations

import asyncio

from sources import certspotter, commoncrawl, crtsh, otx, wayback_cdx
from sources.base import SourceResult
from utils.cache import SourceCache
from utils.validators import is_within_domain, normalize_hostname


class SourceManager:
    def __init__(
        self,
        domain: str,
        cache: SourceCache | None = None,
        *,
        timeout: float = 30.0,
        retries: int = 2,
        cdx_limit: int = 5_000,
        max_urls: int = 100_000,
        commoncrawl_crawls: int = 1,
    ):
        self.domain = normalize_hostname(domain)
        self.cache = cache
        self.timeout = timeout
        self.retries = retries
        self.cdx_limit = cdx_limit
        self.max_urls = max_urls
        self.commoncrawl_crawls = commoncrawl_crawls

    async def collect_subdomains(self) -> tuple[list[dict], list[SourceResult]]:
        tasks = [
            _guard("crt.sh", crtsh.fetch_subdomains(
                self.domain, self.cache, timeout=self.timeout, retries=self.retries
            )),
            _guard("certspotter", certspotter.fetch_subdomains(
                self.domain, self.cache, timeout=self.timeout, retries=self.retries
            )),
            _guard("otx", otx.fetch_subdomains(
                self.domain, self.cache, timeout=self.timeout, retries=self.retries
            )),
        ]
        outcomes = await asyncio.gather(*tasks)
        merged: dict[str, dict] = {}
        sources: list[SourceResult] = []
        for outcome in outcomes:
            if isinstance(outcome, Exception):
                sources.append(SourceResult(source="unknown", error=str(outcome)))
                continue
            sources.append(outcome)
            for record in outcome.records:
                host = normalize_hostname(record.get("hostname", ""))
                if not host or not is_within_domain(host, self.domain):
                    continue
                if host not in merged:
                    merged[host] = dict(record)
                    merged[host]["sources"] = [record.get("source", outcome.source)]
                else:
                    src = record.get("source", outcome.source)
                    if src not in merged[host]["sources"]:
                        merged[host]["sources"].append(src)
        return list(merged.values()), sources

    async def collect_urls(self) -> tuple[list[dict], list[SourceResult]]:
        tasks = [
            _guard("wayback", wayback_cdx.fetch_urls(
                self.domain,
                self.cache,
                limit=self.cdx_limit,
                max_urls=self.max_urls,
                timeout=max(self.timeout, 60.0),
                retries=self.retries,
            )),
            _guard("commoncrawl", commoncrawl.fetch_urls(
                self.domain,
                self.cache,
                crawls=self.commoncrawl_crawls,
                limit=self.cdx_limit,
                max_urls=self.max_urls,
                timeout=max(self.timeout, 60.0),
                retries=self.retries,
            )),
            _guard("otx", otx.fetch_urls(
                self.domain,
                self.cache,
                max_urls=self.max_urls,
                timeout=self.timeout,
                retries=self.retries,
            )),
        ]
        outcomes = await asyncio.gather(*tasks)
        merged: dict[str, dict] = {}
        sources: list[SourceResult] = []
        for outcome in outcomes:
            if isinstance(outcome, Exception):
                sources.append(SourceResult(source="unknown", error=str(outcome)))
                continue
            sources.append(outcome)
            for record in outcome.records:
                url = record.get("url", "")
                if not isinstance(url, str) or not url:
                    continue
                key = url
                if key not in merged:
                    merged[key] = dict(record)
                else:
                    existing = merged[key].get("sources")
                    src = record.get("source", outcome.source)
                    if existing is None:
                        merged[key]["sources"] = [merged[key].get("source", ""), src]
                    elif src not in existing:
                        existing.append(src)
        return list(merged.values()), sources


async def _guard(name: str, coro) -> SourceResult | Exception:
    try:
        return await coro
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - isolate a broken source
        return SourceResult(source=name, error=f"{type(exc).__name__}:{exc}")
