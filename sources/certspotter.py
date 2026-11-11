"""SSLMate Cert Spotter CT source (no API key for limited use)."""

from __future__ import annotations

import asyncio
import json
import urllib.parse

from config import DEFAULT_RETRIES
from sources.base import SourceResult
from utils.cache import SourceCache, cache_key
from utils.network import http_request
from utils.validators import (
    is_valid_hostname,
    is_within_domain,
    normalize_hostname,
    strip_wildcard,
)

SOURCE = "certspotter"


def parse_certspotter(payload: str, domain: str) -> list[dict]:
    try:
        data = json.loads(payload)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(data, list):
        return []
    seen: set[str] = set()
    records: list[dict] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        if entry.get("revoked"):
            continue
        for raw in entry.get("dns_names", []) or []:
            host = normalize_hostname(strip_wildcard(str(raw)))
            if not host or not is_valid_hostname(host) or host in seen:
                continue
            if not is_within_domain(host, domain):
                continue
            seen.add(host)
            records.append(
                {
                    "hostname": host,
                    "source": SOURCE,
                    "not_before": entry.get("not_before", ""),
                    "not_after": entry.get("not_after", ""),
                }
            )
    return records


async def fetch_subdomains(
    domain: str,
    cache: SourceCache | None = None,
    *,
    timeout: float = 30.0,
    retries: int = DEFAULT_RETRIES,
) -> SourceResult:
    result = SourceResult(source=SOURCE)
    query = urllib.parse.urlencode(
        {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}
    )
    url = f"https://api.certspotter.com/v1/issuances?{query}"
    key = cache_key(domain)
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
    result.records = parse_certspotter(payload, domain)
    return result
