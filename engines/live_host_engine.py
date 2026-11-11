"""Live-host detection and HTTP/HTTPS analysis."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import json
from pathlib import Path
import time

from config import MAX_HTTP_BODY
from core.event_logger import EventLogger
from core.scope_manager import ScopeManager
from protocols.http_protocol import HTTPResult, fetch, origin_url
from utils.concurrency import bounded_map
from utils.redaction import redact_url
from utils.validators import normalize_hostname

_DEFINITIVE_DEAD_MARKERS = (
    "dns:resolution failed",
    "nxdomain",
    "no_records",
    "connectionrefusederror",
    "connection refused",
    "errno 111",
    "econnrefused",
    "no route to host",
    "network is unreachable",
    "name or service not known",
    "nodename nor servname provided",
)

_UNKNOWN_MARKERS = (
    "timeout",
    "timed out",
    "rate-limit",
    "rate_limit",
    "ratelimit",
    "too many requests",
    "servfail",
    "temporary failure",
    "connectionreseterror",
    "connection reset",
    "incompletereaderror",
    "sslerror",
    "active probing is disabled",
    "ssrf-guard",
)


def classify_host_liveness(
    probes: list[HTTPResult],
    dns_record: object | None = None,
) -> tuple[str, str]:
    """Classify a host as LIVE, DEAD, or UNKNOWN.

    Rules:
    - LIVE: A valid HTTP or HTTPS response was received (including 200, 301,
      302, 401, 403, 404, 500, etc.).
    - DEAD: A definitive DNS failure or connection failure was observed.
    - UNKNOWN: Timeout, rate limit (HTTP 429 or throttle), temporary network
      failure, or inconclusive response.
    """
    valid_responses = [
        r for r in probes if r.status is not None and r.status != 429
    ]
    if valid_responses:
        best = next(
            (r for r in valid_responses if r.scheme == "https"),
            valid_responses[0],
        )
        return ("LIVE", f"HTTP {best.status} received over {best.scheme.upper()}")

    rate_limited = [r for r in probes if r.status == 429]
    if rate_limited:
        return ("UNKNOWN", "rate limit encountered (HTTP 429)")

    if probes:
        errors = [str(r.error or "").strip() for r in probes if r.error]
        lower_errors = [e.lower() for e in errors]
        for err, low in zip(errors, lower_errors):
            if any(marker in low for marker in _UNKNOWN_MARKERS):
                return ("UNKNOWN", err)
        if lower_errors and all(
            any(marker in low for marker in _DEFINITIVE_DEAD_MARKERS)
            for low in lower_errors
        ):
            if dns_record is not None:
                rcode = str(getattr(dns_record, "rcode", "") or "").upper()
                if rcode in ("SERVFAIL", "REFUSED"):
                    return ("UNKNOWN", f"temporary DNS failure ({rcode})")
            return ("DEAD", errors[0])
        if errors:
            return ("UNKNOWN", errors[0])

    if dns_record is not None:
        resolved = bool(getattr(dns_record, "resolved", False))
        dangling = bool(getattr(dns_record, "dangling", False))
        rcode = str(getattr(dns_record, "rcode", "") or "")
        dns_errors = [str(e).lower() for e in (getattr(dns_record, "errors", []) or [])]
        if not resolved:
            if rcode.upper() in ("SERVFAIL", "REFUSED") or any(
                "timeout" in e for e in dns_errors
            ):
                return ("UNKNOWN", f"inconclusive DNS response ({rcode or 'timeout'})")
            if rcode in ("NXDOMAIN", "no_records", "NOERROR") and not dangling:
                return ("DEAD", f"definitive DNS failure ({rcode})")
            if dangling and rcode == "NXDOMAIN":
                return ("DEAD", "dangling CNAME target returns NXDOMAIN")

    return ("UNKNOWN", "not actively probed or inconclusive response")


def summarize_host(
    hostname: str,
    probes: list[HTTPResult],
    dns_record: object | None = None,
    tls_record: object | None = None,
) -> dict:
    """Build a structured Bug Bounty host classification summary."""
    classification, reason = classify_host_liveness(probes, dns_record)
    https_probe = next(
        (r for r in probes if r.scheme == "https" and r.status is not None),
        next((r for r in probes if r.scheme == "https"), None),
    )
    http_probe = next(
        (r for r in probes if r.scheme == "http" and r.status is not None),
        next((r for r in probes if r.scheme == "http"), None),
    )
    best = None
    if https_probe and https_probe.status is not None:
        best = https_probe
    elif http_probe and http_probe.status is not None:
        best = http_probe
    elif https_probe is not None:
        best = https_probe
    elif http_probe is not None:
        best = http_probe

    tls_meta: dict = {}
    if tls_record is not None and hasattr(tls_record, "as_dict"):
        tls_meta = tls_record.as_dict()
    elif https_probe is not None and getattr(https_probe, "tls_metadata", None):
        tls_meta = dict(https_probe.tls_metadata)

    technologies: list[str] = []
    for p in probes:
        for tech in p.technologies:
            if tech not in technologies:
                technologies.append(tech)

    return {
        "hostname": hostname,
        "classification": classification,
        "reason": reason,
        "http_available": bool(http_probe and http_probe.status is not None and http_probe.status != 429),
        "https_available": bool(https_probe and https_probe.status is not None and https_probe.status != 429),
        "status": best.status if best else None,
        "http_status": http_probe.status if http_probe else None,
        "https_status": https_probe.status if https_probe else None,
        "final_url": redact_url(best.final_url or best.url) if best else "",
        "redirect_chain": [redact_url(u) for u in (best.redirect_chain if best else [])],
        "response_time": round(best.elapsed, 4) if best else 0.0,
        "title": best.title if best else "",
        "content_type": best.content_type if best else "",
        "server": best.server if best else "",
        "technologies": technologies,
        "tls_metadata": tls_meta,
    }


@dataclass
class HTTPRunResult:
    records: list[HTTPResult] = field(default_factory=list)
    live_hosts: list[str] = field(default_factory=list)
    dead_hosts: list[str] = field(default_factory=list)
    unknown_hosts: list[str] = field(default_factory=list)
    host_classifications: dict[str, dict] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def by_host(self) -> dict[str, list[HTTPResult]]:
        mapping: dict[str, list[HTTPResult]] = {}
        for record in self.records:
            mapping.setdefault(record.hostname, []).append(record)
        return mapping

    def best_https(self) -> dict[str, HTTPResult]:
        out: dict[str, HTTPResult] = {}
        for record in self.records:
            if record.scheme != "https" or record.status is None:
                continue
            current = out.get(record.hostname)
            if current is None or (record.status or 0) < (current.status or 999):
                out[record.hostname] = record
        return out

    def as_dict(self) -> dict:
        return {
            "count": len(self.records),
            "live_hosts": self.live_hosts,
            "dead_hosts": self.dead_hosts,
            "unknown_hosts": self.unknown_hosts,
            "host_classifications": self.host_classifications,
            "errors": self.errors,
            "results": [record.as_dict() for record in self.records],
        }


class LiveHostEngine:
    def __init__(
        self,
        scope: ScopeManager,
        *,
        timeout: float = 10.0,
        concurrency: int = 20,
        retries: int = 1,
        rate_limit_rps: float = 0.0,
        logger: EventLogger | None = None,
    ):
        self.scope = scope
        self.timeout = timeout
        self.concurrency = max(1, concurrency)
        self.retries = retries
        self.rate_limit_rps = max(
            0.0, float(rate_limit_rps or getattr(scope, "rate_limit_rps", 0.0) or 0.0)
        )
        self.logger = logger
        self._rate_lock = asyncio.Lock()
        self._last_request_at = 0.0

    async def _throttle(self) -> None:
        if self.rate_limit_rps <= 0:
            return
        min_interval = 1.0 / self.rate_limit_rps
        async with self._rate_lock:
            now = time.monotonic()
            wait_time = (self._last_request_at + min_interval) - now
            if wait_time > 0:
                await asyncio.sleep(wait_time)
            self._last_request_at = time.monotonic()

    async def _probe_host(self, hostname: str) -> list[HTTPResult]:
        results: list[HTTPResult] = []
        for scheme in ("https", "http"):
            url = origin_url(hostname, scheme)
            attempt = 0
            await self._throttle()
            result = await fetch(
                url,
                self.scope,
                timeout=self.timeout,
                max_body=MAX_HTTP_BODY,
            )
            while (
                (result.error and result.error.startswith("timeout"))
                or result.status == 429
            ) and attempt < self.retries:
                attempt += 1
                await asyncio.sleep(0.4 * attempt)
                await self._throttle()
                result = await fetch(
                    url, self.scope, timeout=self.timeout, max_body=MAX_HTTP_BODY
                )
            results.append(result)
        return results

    async def run(
        self,
        hostnames: list[str],
        *,
        all_hosts: list[str] | None = None,
        dns_result: object | None = None,
    ) -> HTTPRunResult:
        run = HTTPRunResult()
        unique: list[str] = []
        seen: set[str] = set()
        for host in hostnames:
            host = normalize_hostname(host)
            if host and host not in seen and self.scope.is_in_scope(host):
                seen.add(host)
                unique.append(host)

        dns_map: dict[str, object] = {}
        if dns_result is not None and hasattr(dns_result, "records"):
            for rec in getattr(dns_result, "records", []):
                dns_map[rec.hostname] = rec

        if self.scope.allow_active_probing:
            outcomes = await bounded_map(self._probe_host, unique, self.concurrency)
        else:
            outcomes = [[] for _ in unique]

        live: set[str] = set()
        dead: set[str] = set()
        unknown: set[str] = set()

        for host, outcome in zip(unique, outcomes):
            if isinstance(outcome, Exception):
                run.errors.append(f"{host}: {outcome}")
                unknown.add(host)
                run.host_classifications[host] = summarize_host(
                    host, [], dns_map.get(host)
                )
                continue
            for result in outcome:
                run.records.append(result)
                if result.error:
                    run.errors.append(f"{result.url}: {result.error}")
            summary = summarize_host(host, outcome, dns_map.get(host))
            run.host_classifications[host] = summary
            cls = summary["classification"]
            if cls == "LIVE":
                live.add(host)
            elif cls == "DEAD":
                dead.add(host)
            else:
                unknown.add(host)

        if all_hosts:
            for raw_host in all_hosts:
                host = normalize_hostname(raw_host)
                if not host or host in run.host_classifications:
                    continue
                if not self.scope.is_in_scope(host):
                    continue
                summary = summarize_host(host, [], dns_map.get(host))
                run.host_classifications[host] = summary
                cls = summary["classification"]
                if cls == "LIVE":
                    live.add(host)
                elif cls == "DEAD":
                    dead.add(host)
                else:
                    unknown.add(host)

        run.live_hosts = sorted(live)
        run.dead_hosts = sorted(dead)
        run.unknown_hosts = sorted(unknown)
        run.records.sort(key=lambda r: (r.hostname, r.scheme))
        if self.logger:
            self.logger.success(
                f"live hosts: {len(run.live_hosts)} "
                f"(dead: {len(run.dead_hosts)}, unknown: {len(run.unknown_hosts)})"
            )
        return run


def write_http_outputs(run: HTTPRunResult, output_dir: Path) -> None:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "live_hosts.txt").write_text(
        "\n".join(run.live_hosts) + ("\n" if run.live_hosts else ""), encoding="utf-8"
    )
    (output_dir / "http_results.json").write_text(
        json.dumps(run.as_dict(), indent=2, default=str), encoding="utf-8"
    )
    lines: list[str] = []
    for record in run.records:
        status = record.status if record.status is not None else "ERR"
        title = (record.title or "")[:80]
        lines.append(
            f"{record.scheme.upper():5} {status!s:4} {record.hostname:40} "
            f"{(record.server or '-')[:24]:24} {title}"
        )
    (output_dir / "http_results.txt").write_text(
        "\n".join(lines) + ("\n" if lines else ""), encoding="utf-8"
    )
