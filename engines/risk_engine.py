"""Explainable risk classification.

Every finding carries a rationale string.  Keyword matches are capped so that
an indicator can never be auto-promoted to Critical; Critical is reserved for
corroborated, manually validated impact and is never emitted automatically.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from engines.dns_engine import DNSRunResult
from engines.historical_url_engine import HistoricalResult
from engines.live_host_engine import HTTPRunResult
from engines.sensitive_detection_engine import SensitiveResult
from engines.takeover_engine import TakeoverResult
from engines.tls_engine import TLSResult, TLSRunResult
from engines.url_filter_engine import FilterResult
from utils.redaction import redact_url

SEVERITY_SCORE = {
    "informational": 10,
    "low": 30,
    "medium": 55,
    "high": 78,
    "critical": 92,
}
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}

SENSITIVE_CATEGORY_RISK = {
    "environment_configuration": ("medium", 55),
    "git_exposure": ("medium", 55),
    "databases": ("medium", 50),
    "backups": ("low", 35),
    "administrative": ("low", 30),
    "internal_resources": ("low", 30),
    "authentication": ("low", 25),
    "business_sensitive": ("low", 25),
    "logging": ("informational", 12),
}


@dataclass
class RiskFinding:
    title: str
    category: str
    severity: str
    score: int
    rationale: str
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""
    hostname: str = ""
    url: str = ""

    def as_dict(self) -> dict:
        return {
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "score": self.score,
            "rationale": self.rationale,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "hostname": self.hostname,
            "url": self.url,
        }


@dataclass
class RiskResult:
    findings: list[RiskFinding] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    overall_severity: str = "informational"
    overall_score: int = 0
    asset_summary: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "overall_severity": self.overall_severity,
            "overall_score": self.overall_score,
            "summary": self.summary,
            "asset_summary": self.asset_summary,
            "notes": self.notes,
            "findings": [finding.as_dict() for finding in self.findings],
        }

    def add(self, finding: RiskFinding) -> None:
        self.findings.append(finding)


class RiskEngine:
    def run(
        self,
        *,
        dns_result: DNSRunResult | None = None,
        http_result: HTTPRunResult | None = None,
        tls_result: TLSRunResult | None = None,
        historical: HistoricalResult | None = None,
        sensitive: SensitiveResult | None = None,
        filter_result: FilterResult | None = None,
        takeover: TakeoverResult | None = None,
        js_count: int = 0,
        subdomain_count: int = 0,
    ) -> RiskResult:
        result = RiskResult()

        if takeover:
            for candidate in takeover.candidates:
                severity = {
                    "Likely": "high",
                    "Potential": "medium",
                    "Needs Manual Review": "low",
                }.get(candidate.classification, "low")
                result.add(
                    RiskFinding(
                        title=f"Possible subdomain takeover: {candidate.hostname}",
                        category="subdomain_takeover",
                        severity=severity,
                        score=candidate.confidence,
                        rationale=(
                            f"CNAME points to {candidate.cname_target}; provider="
                            f"{candidate.provider_name or 'unknown'}; confidence="
                            f"{candidate.confidence}/100. Classified "
                            f"{candidate.classification}. This is an indicator, not proof."
                        ),
                        evidence=candidate.evidence,
                        recommendation=(
                            "Authorized reviewer should verify the provider dashboard and "
                            "DNS ownership before any remediation. Do not attempt to claim."
                        ),
                        hostname=candidate.hostname,
                    )
                )

        if sensitive:
            grouped = sensitive.by_category()
            for category, indicators in grouped.items():
                severity, base = SENSITIVE_CATEGORY_RISK.get(
                    category, ("informational", 10)
                )
                count = len(indicators)
                score = min(base + min(count, 10), 65)
                result.add(
                    RiskFinding(
                        title=f"Sensitive-path indicators: {category.replace('_', ' ')}",
                        category="sensitive_path",
                        severity=severity if count else "informational",
                        score=score,
                        rationale=(
                            f"{count} URL path/parameter-name indicator(s) matched the "
                            f"'{category}' patterns. Matches are not evidence of exposed "
                            f"data; no referenced file was downloaded and query values "
                            f"were redacted."
                        ),
                        evidence=[
                            f"{indicator.kind}: {indicator.value} -> {indicator.redacted_url}"
                            for indicator in indicators[:10]
                        ],
                        recommendation=(
                            "Manually review the referenced paths with authorization; do not "
                            "download secrets, database dumps or configuration files."
                        ),
                    )
                )

        if tls_result:
            self._tls_findings(tls_result, result)

        if dns_result:
            if dns_result.suspicious:
                result.add(
                    RiskFinding(
                        title="DNS records referencing private/reserved addresses",
                        category="dns_configuration",
                        severity="medium",
                        score=50,
                        rationale=(
                            "One or more in-scope names resolve to non-public IP space. "
                            "This can indicate split-horizon DNS or a misconfiguration; it "
                            "is not by itself a vulnerability."
                        ),
                        evidence=[
                            f"{item['hostname']}: {', '.join(item['addresses'])}"
                            for item in dns_result.suspicious[:20]
                        ],
                        recommendation="Confirm the DNS design with the asset owner.",
                    )
                )

        if http_result:
            self._http_findings(http_result, result)

        if filter_result:
            risky_categories = {
                "environment": "Environment files",
                "backups": "Backup artefacts",
                "databases": "Database files",
                "config": "Configuration files",
                "yaml": "YAML configuration",
                "logs": "Log files",
            }
            for name, label in risky_categories.items():
                urls = filter_result.categories.get(name, [])
                if not urls:
                    continue
                result.add(
                    RiskFinding(
                        title=f"Historical references to {label.lower()}",
                        category="historical_file_reference",
                        severity="low" if name in {"backups", "logs"} else "medium",
                        score=32 if name in {"backups", "logs"} else 48,
                        rationale=(
                            f"{len(urls)} historical URL(s) end in a {name} extension. "
                            "Historical references do not prove current exposure and the "
                            "content was not downloaded."
                        ),
                        evidence=[redact_url(url) for url in urls[:10]],
                        recommendation=(
                            "Verify current status manually; avoid downloading sensitive files."
                        ),
                    )
                )

        if js_count:
            result.add(
                RiskFinding(
                    title="JavaScript asset inventory collected",
                    category="asset_inventory",
                    severity="informational",
                    score=10,
                    rationale=(
                        f"{js_count} JavaScript asset URL(s) were inventoried. This is "
                        "attack-surface context, not a vulnerability."
                    ),
                    recommendation="Review JavaScript assets for exposed API routes (authorized).",
                )
            )

        result.notes.append(
            "Critical is never auto-assigned. All findings are indicators requiring "
            "authorized manual validation."
        )
        result.asset_summary = {
            "subdomains": subdomain_count,
            "historical_urls": len(historical.records) if historical else 0,
            "live_hosts": len(http_result.live_hosts) if http_result else 0,
            "javascript_assets": js_count,
            "sensitive_indicators": len(sensitive.indicators) if sensitive else 0,
            "takeover_candidates": len(takeover.candidates) if takeover else 0,
        }
        self._finalize(result)
        return result

    # ------------------------------------------------------------------
    def _tls_findings(self, tls_result: TLSRunResult, result: RiskResult) -> None:
        expired: list[str] = []
        mismatched: list[str] = []
        unverified: list[str] = []
        expiring: list[str] = []
        for item in tls_result.results:
            if not item.connected:
                continue
            if item.expired:
                expired.append(item.hostname)
            if item.hostname_matches is False:
                mismatched.append(item.hostname)
            if item.connected and not item.verified:
                unverified.append(item.hostname)
            if (
                item.days_until_expiry is not None
                and 0 <= item.days_until_expiry <= 14
                and not item.expired
            ):
                expiring.append(f"{item.hostname} ({item.days_until_expiry}d)")

        if expired:
            result.add(
                RiskFinding(
                    title="Expired TLS certificates",
                    category="tls",
                    severity="medium",
                    score=50,
                    rationale=(
                        f"{len(expired)} host(s) presented an expired certificate. This can "
                        "enable interception and break trust."
                    ),
                    evidence=expired[:20],
                    recommendation="Renew certificates and automate expiry monitoring.",
                )
            )
        if mismatched:
            result.add(
                RiskFinding(
                    title="TLS certificate hostname mismatches",
                    category="tls",
                    severity="medium",
                    score=48,
                    rationale=(
                        f"{len(mismatched)} host(s) presented a certificate that does not "
                        "cover the requested hostname."
                    ),
                    evidence=mismatched[:20],
                    recommendation="Deploy a certificate matching the served hostname.",
                )
            )
        if unverified:
            result.add(
                RiskFinding(
                    title="TLS chain could not be verified",
                    category="tls",
                    severity="low",
                    score=35,
                    rationale=(
                        f"{len(unverified)} host(s) had an invalid or untrusted chain. "
                        "Certificate inventory was collected with an explicitly unverified "
                        "handshake; the connection was not trusted."
                    ),
                    evidence=unverified[:20],
                    recommendation="Install a publicly trusted certificate chain.",
                )
            )
        if expiring:
            result.add(
                RiskFinding(
                    title="TLS certificates expiring soon",
                    category="tls",
                    severity="low",
                    score=28,
                    rationale=f"{len(expiring)} certificate(s) expire within 14 days.",
                    evidence=expiring[:20],
                    recommendation="Renew certificates before expiry.",
                )
            )

    def _http_findings(self, http_result: HTTPRunResult, result: RiskResult) -> None:
        https_hosts = {
            record.hostname
            for record in http_result.records
            if record.scheme == "https" and record.status is not None
        }
        http_only: list[str] = []
        for record in http_result.records:
            if (
                record.scheme == "http"
                and record.status is not None
                and record.hostname not in https_hosts
            ):
                http_only.append(record.hostname)
        if http_only:
            result.add(
                RiskFinding(
                    title="Hosts serving HTTP without HTTPS",
                    category="http",
                    severity="low",
                    score=25,
                    rationale=(
                        f"{len(http_only)} live host(s) responded over HTTP while no HTTPS "
                        "response was observed. Traffic may be plaintext."
                    ),
                    evidence=sorted(set(http_only))[:20],
                    recommendation="Redirect HTTP to HTTPS and deploy valid certificates.",
                )
            )
        rejected = [
            record
            for record in http_result.records
            if record.redirect_rejected
        ]
        if rejected:
            result.add(
                RiskFinding(
                    title="Redirects rejected by scope guard",
                    category="http",
                    severity="informational",
                    score=10,
                    rationale=(
                        f"{len(rejected)} response(s) attempted to redirect outside the "
                        "authorized scope or to an unsafe address; the redirect was not followed."
                    ),
                    evidence=[
                        f"{record.hostname}: {record.redirect_rejected}" for record in rejected[:20]
                    ],
                    recommendation="Review redirect configuration if this is unexpected.",
                )
            )

    def _finalize(self, result: RiskResult) -> None:
        summary = {name: 0 for name in SEVERITY_ORDER}
        overall_score = 0
        overall_severity = "informational"
        for finding in result.findings:
            summary[finding.severity] = summary.get(finding.severity, 0) + 1
            if finding.score > overall_score:
                overall_score = finding.score
                overall_severity = finding.severity
        result.summary = summary
        result.overall_score = overall_score
        result.overall_severity = overall_severity
        result.findings.sort(
            key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), -f.score, f.title)
        )


def write_risk_outputs(result: RiskResult, output_dir: Path) -> None:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "risk_assessment.json").write_text(
        json.dumps(result.as_dict(), indent=2, default=str), encoding="utf-8"
    )
    lines = [
        f"[{finding.severity.upper():13}] {finding.score:>3}  {finding.title}"
        for finding in result.findings
    ]
    (output_dir / "risk_assessment.txt").write_text(
        "\n".join(lines) + ("\n" if lines else ""), encoding="utf-8"
    )
