"""JavaScript asset inventory and optional static endpoint extraction."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from core.event_logger import EventLogger
from core.scope_manager import ScopeManager
from protocols.http_protocol import fetch
from utils.redaction import redact_text, redact_url
from utils.url_utils import get_extension, get_hostname, extract_param_names, normalize_url, split_url

JS_EXTENSIONS = {"js", "mjs", "cjs"}

_ENDPOINT_RE = re.compile(
    r"""(?:"|'|`)((?:https?://[^\s"'`<>]+)|(?:/[\w\-./{}$:]+))(?:"|'|`)"""
)
_ABS_URL_RE = re.compile(r"""https?://[^\s"'`<>()]+""")
_SECRET_ASSIGN_RE = re.compile(
    r"""(?:api[_-]?key|token|secret|password|passwd|authorization)\s*[:=]\s*["'][^"']{6,}["']""",
    re.IGNORECASE,
)


@dataclass
class JSAsset:
    url: str
    normalized: str
    hostname: str
    sources: list[str] = field(default_factory=list)
    extension: str = ""
    params: list[str] = field(default_factory=list)
    live_status: int | None = None
    content_type: str = ""
    content_length: int | None = None
    timestamp: str = ""
    liveness: str = "UNKNOWN"
    endpoints: list[str] = field(default_factory=list)
    analyzed: bool = False
    error: str = ""

    def as_dict(self) -> dict:
        return {
            "url": redact_url(self.url),
            "normalized": redact_url(self.normalized),
            "hostname": self.hostname,
            "source": self.sources[0] if self.sources else "unknown",
            "sources": self.sources,
            "extension": self.extension,
            "params": self.params,
            "live_status": self.live_status,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "timestamp": self.timestamp,
            "liveness": self.liveness,
            "endpoints": self.endpoints,
            "analyzed": self.analyzed,
            "error": self.error,
        }


@dataclass
class JSResult:
    assets: list[JSAsset] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def urls(self) -> list[str]:
        return [asset.normalized for asset in self.assets]

    @property
    def live_urls(self) -> list[str]:
        return [
            asset.normalized
            for asset in self.assets
            if asset.liveness == "LIVE"
            or (asset.live_status is not None and asset.live_status != 429)
        ]

    @property
    def unknown_urls(self) -> list[str]:
        return [
            asset.normalized
            for asset in self.assets
            if asset.liveness == "UNKNOWN"
            and not (asset.live_status is not None and asset.live_status != 429)
        ]

    def as_dict(self) -> dict:
        endpoints = sorted({e for asset in self.assets for e in asset.endpoints})
        return {
            "count": len(self.assets),
            "unique_count": len(self.assets),
            "live_count": len(self.live_urls),
            "unknown_count": len(self.unknown_urls),
            "analyzed": sum(1 for asset in self.assets if asset.analyzed),
            "endpoints": endpoints,
            "assets": [asset.as_dict() for asset in self.assets],
            "errors": self.errors,
        }


def collect_js_urls(
    urls: list[str],
    live_urls: list[str] | None = None,
    source_map: dict[str, list[str]] | None = None,
    timestamp_map: dict[str, str] | None = None,
    host_classifications: dict[str, dict] | None = None,
) -> dict[str, JSAsset]:
    assets: dict[str, JSAsset] = {}
    source_map = source_map or {}
    timestamp_map = timestamp_map or {}
    host_classifications = host_classifications or {}
    live_set = {normalize_url(u) or u for u in (live_urls or [])}
    for url in list(urls) + list(live_urls or []):
        normalized = normalize_url(url)
        if normalized is None:
            continue
        parsed = split_url(normalized)
        ext = get_extension(normalized)
        if ext not in JS_EXTENSIONS:
            continue
        if normalized in assets:
            if normalized in live_set and "live" not in assets[normalized].sources:
                assets[normalized].sources.append("live")
                assets[normalized].liveness = "LIVE"
            continue
        srcs = list(source_map.get(normalized, []))
        if normalized in live_set and "live" not in srcs:
            srcs.append("live")
        if not srcs:
            srcs = ["historical"] if normalized not in live_set else ["live"]
        liveness = "UNKNOWN"
        if normalized in live_set:
            liveness = "LIVE"
        elif parsed.host in host_classifications:
            host_cls = str(host_classifications[parsed.host].get("classification", "UNKNOWN")).upper()
            if host_cls in ("LIVE", "DEAD", "UNKNOWN"):
                liveness = host_cls
        assets[normalized] = JSAsset(
            url=url,
            normalized=normalized,
            hostname=parsed.host,
            sources=srcs,
            extension=ext,
            params=extract_param_names(parsed.query),
            timestamp=timestamp_map.get(normalized, ""),
            liveness=liveness,
        )
    return assets


def extract_endpoints(text: str, limit: int = 500) -> list[str]:
    """Extract endpoint-like references without persisting file contents."""
    found: list[str] = []
    seen: set[str] = set()
    for match in _ENDPOINT_RE.finditer(text):
        candidate = match.group(1)
        if len(candidate) > 2048:
            continue
        if candidate.startswith("/") and candidate.count("/") < 2:
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        found.append(redact_url(candidate) if candidate.startswith("http") else candidate)
        if len(found) >= limit:
            break
    for match in _ABS_URL_RE.finditer(text):
        candidate = match.group(0)
        if candidate in seen:
            continue
        seen.add(candidate)
        found.append(redact_url(candidate))
        if len(found) >= limit:
            break
    return found


class JavaScriptEngine:
    def __init__(
        self,
        scope: ScopeManager,
        *,
        timeout: float = 10.0,
        concurrency: int = 10,
        logger: EventLogger | None = None,
    ):
        self.scope = scope
        self.timeout = timeout
        self.concurrency = concurrency
        self.logger = logger

    async def run(
        self,
        urls: list[str],
        live_urls: list[str] | None = None,
        *,
        analyze: bool = False,
        max_files: int = 50,
        source_map: dict[str, list[str]] | None = None,
        timestamp_map: dict[str, str] | None = None,
        host_classifications: dict[str, dict] | None = None,
    ) -> JSResult:
        import asyncio

        result = JSResult()
        assets = collect_js_urls(
            urls,
            live_urls,
            source_map=source_map,
            timestamp_map=timestamp_map,
            host_classifications=host_classifications,
        )
        semaphore = asyncio.Semaphore(max(1, self.concurrency))
        analyzed = 0

        async def _analyse(asset: JSAsset) -> None:
            nonlocal analyzed
            if not self.scope.is_in_scope(asset.hostname):
                asset.error = "out-of-scope asset"
                return
            if not self.scope.allow_active_probing:
                asset.error = "active probing disabled"
                return
            async with semaphore:
                if analyzed >= max_files:
                    return
                analyzed += 1
                response = await fetch(
                    asset.normalized,
                    self.scope,
                    timeout=self.timeout,
                    max_body=512 * 1024,
                )
                asset.live_status = response.status
                asset.content_type = response.content_type
                asset.content_length = response.content_length
                if response.status is not None and response.status != 429:
                    asset.liveness = "LIVE"
                elif response.status == 429 or (
                    response.error and "timeout" in response.error.lower()
                ):
                    asset.liveness = "UNKNOWN"
                if response.error:
                    asset.error = response.error
                    return
                text = response.text()
                asset.endpoints = extract_endpoints(text)
                asset.analyzed = True

        ordered = sorted(assets.values(), key=lambda a: a.normalized)
        if analyze and self.scope.allow_active_probing:
            await asyncio.gather(*[_analyse(asset) for asset in ordered])
        result.assets = ordered
        if self.logger:
            self.logger.success(
                f"JavaScript assets: {len(result.assets)}"
                + (f" ({analyzed} analysed)" if analyze else "")
            )
        return result

    def write_outputs(self, result: JSResult, output_dir: Path) -> None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        unique_lines = [redact_url(u) for u in result.urls]
        live_lines = [redact_url(u) for u in result.live_urls]
        unknown_lines = [redact_url(u) for u in result.unknown_urls]

        def _write(name: str, items: list[str]) -> None:
            (output_dir / name).write_text(
                "\n".join(items) + ("\n" if items else ""), encoding="utf-8"
            )

        _write("js_files.txt", unique_lines)
        _write("js_unique.txt", unique_lines)
        _write("js_live.txt", live_lines)
        _write("js_unknown.txt", unknown_lines)
        (output_dir / "js_inventory.json").write_text(
            json.dumps(result.as_dict(), indent=2, default=str), encoding="utf-8"
        )
        endpoints = sorted({e for asset in result.assets for e in asset.endpoints})
        if endpoints:
            (output_dir / "js_endpoints.txt").write_text(
                "\n".join(endpoints) + "\n", encoding="utf-8"
            )
