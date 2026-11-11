"""crt.sh Certificate Transparency source."""

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

SOURCE = "crt.sh"


def _extract_hosts(entry: dict) -> list[str]:
    hosts: list[str] = []
    for field in ("name_value", "common_name"):
        raw = entry.get(field) or ""
        if not isinstance(raw, str):
            continue
        for line in raw.replace("\\n", "\n").splitlines():
            candidate = normalize_hostname(strip_wildcard(line))
            if candidate and is_valid_hostname(candidate):
                hosts.append(candidate)
    return hosts


def parse_crtsh(payload: str, domain: str) -> list[dict]:
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
        issuer = (entry.get("issuer_name") or "")[:200]
        not_before = entry.get("not_before") or ""
        not_after = entry.get("not_after") or ""
        for host in _extract_hosts(entry):
            if host in seen:
                continue
            if not is_within_domain(host, domain):
                continue
            seen.add(host)
            records.append(
                {
                    "hostname": host,
                    "source": SOURCE,
                    "issuer": issuer,
                    "not_before": not_before,
                    "not_after": not_after,
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
    url = (
        "https://crt.sh/?q="
        + urllib.parse.quote(f"%.{domain}", safe="")
        + "&output=json"
    )
    key = cache_key(domain)
    payload: str | None = cache.get(SOURCE, key) if cache else None
    if payload is not None:
        result.cached = True
    else:
        response = await asyncio.to_thread(
            http_request,
            url,
            timeout=timeout,
            retries=retries,
            headers={"Accept": "application/json"},
        )
        if response.error or response.status != 200:
            result.error = response.error or f"http-{response.status}"
            return result
        payload = response.text()
        if cache is not None:
            cache.set(SOURCE, key, payload)
    result.records = parse_crtsh(payload, domain)
    if not result.records and not result.cached:
        result.error = "no cert records parsed"
    return result
