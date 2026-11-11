"""Internet Archive CDX API client with resume-key pagination."""

from __future__ import annotations

import asyncio
import json
import urllib.parse

from config import DEFAULT_CDX_LIMIT, DEFAULT_RETRIES
from sources.base import SourceResult
from utils.cache import SourceCache, cache_key
from utils.network import http_request

SOURCE = "wayback"
CDX_ENDPOINT = "https://web.archive.org/cdx/search/cdx"


def parse_cdx_page(payload: str) -> tuple[list[dict], str]:
    """Return (records, resume_key) from one CDX JSON page."""
    try:
        rows = json.loads(payload)
    except (json.JSONDecodeError, TypeError):
        return [], ""
    if not isinstance(rows, list) or not rows:
        return [], ""

    # A page may end with an empty row and a resume-key row when
    # showResumeKey=true is used.
    resume_key = ""
    while rows and isinstance(rows[-1], list) and len(rows[-1]) <= 1:
        last = rows.pop()
        if len(last) == 1 and isinstance(last[0], str) and last[0]:
            resume_key = last[0]
        if not rows:
            break

    header = rows[0]
    if not isinstance(header, list):
        return [], resume_key
    known_columns = {"urlkey", "timestamp", "original", "url", "statuscode", "mimetype"}
    if known_columns.intersection(str(c) for c in header):
        data_rows = rows[1:]
    else:
        header = ["timestamp", "original", "statuscode", "mimetype"]
        data_rows = rows

    records: list[dict] = []
    for row in data_rows:
        if not isinstance(row, list):
            continue
        item: dict = {}
        for idx, column in enumerate(header):
            if idx < len(row):
                item[column] = row[idx]
        url = item.get("original") or item.get("url")
        if not isinstance(url, str) or not url:
            continue
        records.append(
            {
                "url": url,
                "timestamp": str(item.get("timestamp", "")),
                "status": str(item.get("statuscode", "")),
                "mimetype": str(item.get("mimetype", "")),
                "source": SOURCE,
            }
        )
    return records, resume_key


async def fetch_urls(
    domain: str,
    cache: SourceCache | None = None,
    *,
    limit: int = DEFAULT_CDX_LIMIT,
    max_urls: int = 100_000,
    max_pages: int = 20,
    timeout: float = 60.0,
    retries: int = DEFAULT_RETRIES,
) -> SourceResult:
    result = SourceResult(source=SOURCE)
    base_params = {
        "url": domain,
        "matchType": "domain",
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype",
        "collapse": "urlkey",
        "limit": str(max(1, limit)),
        "showResumeKey": "true",
    }
    resume_key = ""
    collected: list[dict] = []
    seen: set[str] = set()
    any_success = False

    for page in range(max_pages):
        params = dict(base_params)
        if resume_key:
            params["resumeKey"] = resume_key
        url = CDX_ENDPOINT + "?" + urllib.parse.urlencode(params)
        key = cache_key(domain, str(page), resume_key)
        payload: str | None = cache.get(SOURCE, key) if cache else None
        if payload is None:
            response = await asyncio.to_thread(
                http_request,
                url,
                timeout=timeout,
                retries=retries,
                headers={"Accept": "application/json"},
            )
            if response.status == 429:
                result.error = "rate-limited"
                break
            if response.error or response.status not in (200, 204):
                if not any_success:
                    result.error = response.error or f"http-{response.status}"
                break
            payload = response.text()
            if cache is not None and payload:
                cache.set(SOURCE, key, payload)
        else:
            result.cached = True
        any_success = True

        records, next_key = parse_cdx_page(payload)
        for record in records:
            if record["url"] in seen:
                continue
            seen.add(record["url"])
            collected.append(record)
            if len(collected) >= max_urls:
                break
        if len(collected) >= max_urls or not next_key or not records:
            break
        resume_key = next_key

    result.records = collected
    return result
