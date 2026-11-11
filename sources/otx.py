"""AlienVault OTX passive DNS and URL source (no API key required)."""

from __future__ import annotations

import asyncio
import json

from config import DEFAULT_RETRIES, MAX_HISTORICAL_URLS
from sources.base import SourceResult
from utils.cache import SourceCache, cache_key
from utils.network import http_request
from utils.validators import is_valid_hostname, is_within_domain, normalize_hostname

SOURCE = "otx"
BASE = "https://otx.alienvault.com/api/v1/indicators/domain"


def parse_passive_dns(payload: str, domain: str) -> list[dict]:
    try:
        data = json.loads(payload)
    except (json.JSONDecodeError, TypeError):
        return []
    entries = data.get("passive_dns", []) if isinstance(data, dict) else []
    seen: set[str] = set()
    out: list[dict] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        host = normalize_hostname(entry.get("hostname", ""))
        if not host or not is_valid_hostname(host):
            continue
        if not is_within_domain(host, domain):
            continue
        if host in seen:
            continue
        seen.add(host)
        out.append(
            {
                "hostname": host,
                "source": SOURCE,
                "record_type": entry.get("record_type", ""),
                "first": entry.get("first", ""),
                "last": entry.get("last", ""),
            }
        )
    return out


def parse_url_list(payload: str) -> list[dict]:
    try:
        data = json.loads(payload)
    except (json.JSONDecodeError, TypeError):
        return []
    entries = data.get("url_list", []) if isinstance(data, dict) else []
    out: list[dict] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        url = entry.get("url")
        if not isinstance(url, str) or not url:
            continue
        out.append(
            {
                "url": url,
                "timestamp": str(entry.get("date", "")),
                "status": "",
                "mimetype": "",
                "source": SOURCE,
            }
        )
    return out


async def fetch_subdomains(
    domain: str,
    cache: SourceCache | None = None,
    *,
    timeout: float = 30.0,
    retries: int = DEFAULT_RETRIES,
) -> SourceResult:
    result = SourceResult(source=SOURCE)
    url = f"{BASE}/{domain}/passive_dns"
    key = cache_key(domain, "passive_dns")
    payload = cache.get(SOURCE, key) if cache else None
    if payload is not None:
        result.cached = True
    else:
        response = await asyncio.to_thread(
            http_request, url, timeout=timeout, retries=retries
        )
        if response.error or response.status != 200:
            result.error = response.error or f"http-{response.status}"
            return result
        payload = response.text()
        if cache is not None:
            cache.set(SOURCE, key, payload)
    result.records = parse_passive_dns(payload, domain)
    return result


async def fetch_urls(
    domain: str,
    cache: SourceCache | None = None,
    *,
    max_urls: int = MAX_HISTORICAL_URLS,
    timeout: float = 30.0,
    retries: int = DEFAULT_RETRIES,
    max_pages: int = 5,
) -> SourceResult:
    result = SourceResult(source=SOURCE)
    collected: list[dict] = []
    seen: set[str] = set()
    for page in range(1, max_pages + 1):
        url = f"{BASE}/{domain}/url_list?limit=500&page={page}"
        key = cache_key(domain, "url_list", str(page))
        payload = cache.get(SOURCE, key) if cache else None
        if payload is None:
            response = await asyncio.to_thread(
                http_request, url, timeout=timeout, retries=retries
            )
            if response.error or response.status != 200:
                if not collected:
                    result.error = response.error or f"http-{response.status}"
                break
            payload = response.text()
            if cache is not None:
                cache.set(SOURCE, key, payload)
        else:
            result.cached = True
        page_records = parse_url_list(payload)
        if not page_records:
            break
        for record in page_records:
            if record["url"] in seen:
                continue
            seen.add(record["url"])
            collected.append(record)
            if len(collected) >= max_urls:
                break
        if len(collected) >= max_urls:
            break
        try:
            has_next = bool(json.loads(payload).get("has_next"))
        except (json.JSONDecodeError, TypeError, AttributeError):
            has_next = False
        if not has_next:
            break
    result.records = collected
    return result
