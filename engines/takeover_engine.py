"""Passive subdomain-takeover analysis.

The engine never claims, registers, or provisions anything.  It combines DNS
state, provider CNAME fingerprints and safe HTTP error-page indicators, then
assigns a confidence score and an explicit manual-review classification.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from config import INTELLIGENCE_DIR
from core.event_logger import EventLogger
from engines.dns_engine import DNSRunResult, DNSEngine
from utils.validators import normalize_hostname

FINGERPRINT_FILE = INTELLIGENCE_DIR / "takeover_fingerprints.json"

CONFIDENCE_BASE = {"high": 45, "medium": 30, "low": 15}


def load_fingerprints(path: Path = FINGERPRINT_FILE) -> list[dict]:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    providers = data.get("providers", [])
    for provider in providers:
        provider["_compiled"] = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in provider.get("cname_patterns", [])
        ]
    return providers


def match_providers(cname_target: str, providers: list[dict]) -> list[dict]:
    target = normalize_hostname(cname_target)
    if not target:
        return []
    matches: list[dict] = []
    for provider in providers:
        for regex in provider.get("_compiled", []):
            if regex.search(target):
                matches.append(provider)
                break
    return matches


@dataclass
class TakeoverCandidate:
    hostname: str
    cname_target: str
    provider_id: str = ""
    provider_name: str = ""
    confidence: int = 0
    classification: str = "Needs Manual Review"
    evidence: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    reference: str = ""
    http_status: int | None = None

    def as_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "cname_target": self.cname_target,
            "provider": self.provider_name,
            "provider_id": self.provider_id,
            "confidence": self.confidence,
            "classification": self.classification,
            "evidence": self.evidence,
            "false_positive_warnings": self.warnings,
            "reference": self.reference,
            "http_status": self.http_status,
            "note": "Indicator only. Authorized manual verification required; no claim was attempted.",
        }


@dataclass
class TakeoverResult:
    candidates: list[TakeoverCandidate] = field(default_factory=list)
    analyzed_targets: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "count": len(self.candidates),
            "analyzed_targets": self.analyzed_targets,
            "candidates": [candidate.as_dict() for candidate in self.candidates],
            "errors": self.errors,
        }


def classification_for(score: int) -> str:
    if score >= 70:
        return "Likely"
    if score >= 50:
        return "Potential"
    return "Needs Manual Review"


def score_candidate(
    hostname: str,
    cname_target: str,
    *,
    target_resolves: bool,
    target_rcode: str = "",
    providers: list[dict] | None = None,
    http_status: int | None = None,
    http_body: str = "",
) -> TakeoverCandidate | None:
    """Pure scoring function (also used by the unit tests)."""
    providers = providers or []
    matches = match_providers(cname_target, providers)
    provider = matches[0] if matches else None
    evidence: list[str] = []
    warnings: list[str] = []

    body_lower = (http_body or "").lower()
    indicator_hit = ""
    if provider:
        for indicator in provider.get("http_indicators", []):
            if indicator.lower() in body_lower:
                indicator_hit = indicator
                break

    dangling = not target_resolves or target_rcode == "NXDOMAIN"
    if not dangling and not indicator_hit:
        # Nothing suspicious: a resolving target with a normal page is not a
        # takeover candidate.
        return None

    score = 0
    if provider:
        score += CONFIDENCE_BASE.get(provider.get("confidence", "low"), 10)
        score += 10
        evidence.append(f"CNAME matches {provider.get('name', provider.get('id'))} fingerprint")
        warnings.extend(provider.get("false_positive_warnings", []))
    else:
        evidence.append("No provider fingerprint matched the CNAME target")

    if dangling:
        score += 30
        if target_rcode == "NXDOMAIN":
            evidence.append(f"CNAME target {cname_target} returns NXDOMAIN")
        else:
            evidence.append(f"CNAME target {cname_target} does not resolve")
    if indicator_hit:
        score += 30
        evidence.append(f"HTTP response contains provider error indicator: {indicator_hit!r}")
    if http_status in (404, 410):
        score += 5
        evidence.append(f"HTTP status {http_status} recorded on the in-scope host")
    if provider is None and dangling:
        score = min(score, 45)
    if not provider and not dangling and not indicator_hit:
        return None

    score = max(0, min(95, score))
    return TakeoverCandidate(
        hostname=hostname,
        cname_target=cname_target,
        provider_id=provider.get("id", "") if provider else "",
        provider_name=provider.get("name", "") if provider else "",
        confidence=score,
        classification=classification_for(score),
        evidence=evidence,
        warnings=warnings,
        reference=provider.get("reference", "") if provider else "",
        http_status=http_status,
    )


class TakeoverEngine:
    def __init__(
        self,
        *,
        fingerprints: list[dict] | None = None,
        dns_engine: DNSEngine | None = None,
        logger: EventLogger | None = None,
    ):
        self.providers = fingerprints if fingerprints is not None else load_fingerprints()
        self.dns = dns_engine
        self.logger = logger

    async def run(
        self,
        dns_result: DNSRunResult,
        http_results: dict[str, object] | None = None,
    ) -> TakeoverResult:
        result = TakeoverResult()
        http_results = http_results or {}

        cname_map: dict[str, str] = {}
        for item in dns_result.cname_records:
            host = normalize_hostname(item.get("hostname", ""))
            target = normalize_hostname(item.get("target", ""))
            if host and target:
                cname_map.setdefault(host, target)

        targets = sorted(set(cname_map.values()))
        result.analyzed_targets = len(targets)
        resolution: dict[str, tuple[bool, str]] = {}
        if self.dns is not None:
            for target in targets:
                resolved = await self.dns.resolve(target)
                resolution[target] = (resolved.resolved, resolved.rcode)
        else:
            for item in dns_result.records:
                if item.hostname in cname_map:
                    resolution[cname_map[item.hostname]] = (
                        item.resolved,
                        item.rcode,
                    )

        for host, target in sorted(cname_map.items()):
            resolves, rcode = resolution.get(target, (False, ""))
            http = http_results.get(host)
            status = getattr(http, "status", None) if http is not None else None
            body = ""
            if http is not None:
                try:
                    body = http.text()  # type: ignore[attr-defined]
                except Exception:  # noqa: BLE001
                    body = ""
            candidate = score_candidate(
                host,
                target,
                target_resolves=resolves,
                target_rcode=rcode,
                providers=self.providers,
                http_status=status,
                http_body=body,
            )
            if candidate is not None:
                result.candidates.append(candidate)
        result.candidates.sort(key=lambda c: (-c.confidence, c.hostname))
        if self.logger:
            self.logger.success(
                f"takeover candidates: {len(result.candidates)} "
                f"(analysed {result.analyzed_targets} CNAME targets)"
            )
        return result

    def write_outputs(self, result: TakeoverResult, output_dir: Path) -> None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "takeover_candidates.json").write_text(
            json.dumps(result.as_dict(), indent=2, default=str), encoding="utf-8"
        )
        lines = [
            f"{c.hostname} -> {c.cname_target} | {c.provider_name or 'unknown provider'} "
            f"| confidence={c.confidence} | {c.classification}"
            + (f" | {c.evidence[-1]}" if c.evidence else "")
            for c in result.candidates
        ]
        header = (
            "# Indicator-only output. Authorized manual verification required.\n"
            "# No resource was claimed, registered, or provisioned.\n"
        )
        (output_dir / "takeover_candidates.txt").write_text(
            header + "\n".join(lines) + ("\n" if lines else ""), encoding="utf-8"
        )
