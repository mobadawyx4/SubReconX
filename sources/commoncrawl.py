"""Common Crawl index collector (JSON-lines CDX API)."""

from __future__ import annotations

import asyncio
import json
import urllib.parse

from config import DEFAULT_CDX_LIMIT, DEFAULT_RETRIES
from sources.base import SourceResult
from utils.cache import SourceCache, cache_key
from utils.network import http_request
from utils.validators import is_within_domain, normalize_hostname

SOURCE = "commoncrawl"
COLLINFO_URL = "https://index.commoncrawl.org/collinfo.json"


def _is_valid_cdx_api(api_url: str) -> bool:
    try:
        parsed = urllib.parse.urlsplit(api_url)
    except ValueError:
        return False
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        return False
    host = normalize_hostname(parsed.hostname)
    return is_within_domain(host, "commoncrawl.org")


async def discover_indexes(
    cache: SourceCache | None = None,
    *,
    timeout: float = 30.0,
    retries: int = DEFAULT_RETRIES,
) -> list[dict]:
    key = cache_key("collinfo")
    payload = cache.get("commoncrawl-index", key) if cache else None
    if payload is None:
        response = await asyncio.to_thread(
            http_request, COLLINFO_URL, timeout=timeout, retries=retries
        )
        if response.error or response.status != 200:
            return []
        payload = response.text()
        if cache is not None:
            cache.set("commoncrawl-index", key, payload)
    try:
        data = json.loads(payload)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(data, list):
        return []
    indexes: list[dict] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        api = entry.get("cdx-api") or entry.get("cdx_api")
        if isinstance(api, str) and _is_valid_cdx_api(api):
            indexes.append({"id": entry.get("id", ""), "api": api})
    return indexes


def parse_json_lines(payload: str, crawl_id: str) -> list[dict]:
    records: list[dict] = []
    for line in payload.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        url = item.get("url") or item.get("original")
        if not isinstance(url, str) or not url:
            continue
        records.append(
            {
                "url": url,
                "timestamp": str(item.get("timestamp", "")),
                "status": str(item.get("status", "")),
                "mimetype": str(item.get("mime", item.get("mimetype", ""))),
                "source": SOURCE,
                "crawl": crawl_id,
            }
        )
    return records


async def fetch_urls(
    domain: str,
    cache: SourceCache | None = None,
    *,
    crawls: int = 1,
    limit: int = DEFAULT_CDX_LIMIT,
    max_urls: int = 100_000,
    timeout: float = 60.0,
    retries: int = DEFAULT_RETRIES,
) -> SourceResult:
    result = SourceResult(source=SOURCE)
    indexes = await discover_indexes(cache, timeout=timeout, retries=retries)
    if not indexes:
        result.error = "index discovery failed"
        return result
    selected = indexes[: max(1, crawls)]
    collected: list[dict] = []
    seen: set[str] = set()
    errors: list[str] = []

    for index in selected:
        crawl_id = index["id"]
        query = urllib.parse.urlencode(
            {"url": f"*.{domain}/*", "output": "json", "limit": str(max(1, limit))}
        )
        url = f"{index['api']}?{query}"
        key = cache_key(domain, crawl_id)
        payload: str | None = cache.get(SOURCE, key) if cache else None
        if payload is None:
            response = await asyncio.to_thread(
                http_request, url, timeout=timeout, retries=retries
            )
            if response.status == 404:
                # No captures for this crawl.
                continue
            if response.error or response.status not in (200, 204):
                errors.append(f"{crawl_id}:{response.error or response.status}")
                continue
            payload = response.text()
            if cache is not None:
                cache.set(SOURCE, key, payload)
        else:
            result.cached = True

        for record in parse_json_lines(payload, crawl_id):
            if record["url"] in seen:
                continue
            seen.add(record["url"])
            collected.append(record)
            if len(collected) >= max_urls:
                break
        if len(collected) >= max_urls:
            break

    result.records = collected
    if errors and not collected:
        result.error = "; ".join(errors)
    return result
