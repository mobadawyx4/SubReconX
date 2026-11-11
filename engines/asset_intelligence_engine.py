"""Bug Bounty Asset Intelligence Engine (Phase 6 & Phase 8).

Correlates passive and safe active reconnaissance signals to help security
assessors prioritize interesting assets for manual review.

Safety guarantees:
- Indicators are never automatically classified as confirmed vulnerabilities.
- Every indicator carries a clear human-readable explanation.
- No exploitation, authentication, brute force, file download, or resource
  claiming is ever performed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import re

from engines.dns_engine import DNSRunResult
from engines.historical_url_engine import HistoricalResult
from engines.javascript_engine import JSResult
from engines.live_host_engine import HTTPRunResult
from engines.results_engine import OrganizedResults
from engines.sensitive_detection_engine import SensitiveResult
from engines.takeover_engine import TakeoverResult
from engines.tls_engine import TLSRunResult
from utils.redaction import redact_url

_ENV_LABELS = {
    "dev": "Development environment hostname label",
    "development": "Development environment hostname label",
    "staging": "Staging environment hostname label",
    "stage": "Staging environment hostname label",
    "stg": "Staging environment hostname label",
    "uat": "User Acceptance Testing (UAT) hostname label",
    "qa": "Quality Assurance (QA) hostname label",
    "test": "Test environment hostname label",
    "testing": "Test environment hostname label",
    "sandbox": "Sandbox environment hostname label",
    "preprod": "Pre-production environment hostname label",
    "beta": "Beta environment hostname label",
    "internal": "Internal-facing hostname label",
    "intranet": "Intranet hostname label",
    "corp": "Corporate network hostname label",
}

_LEGACY_LABELS = {"legacy", "old", "v0", "v1", "deprecated", "archive"}
_LEGACY_EXTENSIONS = {
    "asp", "aspx", "ashx", "asmx", "jsp", "jspx", "do", "action",
    "cfm", "cfc", "cgi", "pl", "php3", "php4", "php5",
}

_UNUSUAL_STATUS_EXPLANATIONS = {
    401: "HTTP 401 Unauthorized indicates an active authentication boundary suitable for authorized access-control review.",
    403: "HTTP 403 Forbidden indicates a live server enforcing access restrictions; useful context when reviewing authorized routes.",
    405: "HTTP 405 Method Not Allowed indicates an active endpoint that rejects GET but may accept other HTTP verbs.",
    500: "HTTP 500 Internal Server Error indicates server-side exception handling on a live application.",
    502: "HTTP 502 Bad Gateway indicates a reverse proxy or load balancer unable to reach an upstream backend.",
    503: "HTTP 503 Service Unavailable indicates a maintenance state or upstream capacity constraint on a live host.",
}

_TOKEN_SPLIT_RE = re.compile(r"[-_.]")


def detect_hostname_environment_labels(hostname: str) -> list[dict]:
    """Identify non-production or internal tokens in a hostname."""
    findings: list[dict] = []
    seen: set[str] = set()
    labels = hostname.lower().split(".")
    for label in labels[:-2] if len(labels) > 2 else labels[:1]:
        tokens = [label] + _TOKEN_SPLIT_RE.split(label)
        for token in tokens:
            if token in _ENV_LABELS and token not in seen:
                seen.add(token)
                findings.append(
                    {
                        "type": "environment_label",
                        "indicator": token,
                        "hostname": hostname,
                        "explanation": (
                            f"{_ENV_LABELS[token]} ('{token}' in {hostname}). "
                            "Non-production hosts often expose debug features or newer API routes for manual review."
                        ),
                    }
                )
    return findings


def detect_legacy_indicators(
    hostname: str,
    urls: list[str],
    technologies: list[str] | None = None,
    server: str = "",
) -> list[dict]:
    """Identify legacy application indicators from host labels, URL extensions, and headers."""
    findings: list[dict] = []
    labels = hostname.lower().split(".")
    for label in labels[:-2] if len(labels) > 2 else labels[:1]:
        for token in [label] + _TOKEN_SPLIT_RE.split(label):
            if token in _LEGACY_LABELS:
                findings.append(
                    {
                        "type": "legacy_hostname",
                        "indicator": token,
                        "hostname": hostname,
                        "explanation": (
                            f"Hostname contains legacy indicator '{token}' ({hostname}). "
                            "Legacy services may run older application stacks warranting manual assessment."
                        ),
                    }
                )
                break

    ext_hits: dict[str, str] = {}
    for u in urls:
        path = u.split("?", 1)[0].lower()
        if "." in path.rsplit("/", 1)[-1]:
            ext = path.rsplit(".", 1)[-1]
            if ext in _LEGACY_EXTENSIONS and ext not in ext_hits:
                ext_hits[ext] = redact_url(u)
    for ext, sample_url in sorted(ext_hits.items()):
        findings.append(
            {
                "type": "legacy_extension",
                "indicator": f".{ext}",
                "hostname": hostname,
                "sample_url": sample_url,
                "explanation": (
                    f"Historical or live URL uses classic server extension '.{ext}' ({sample_url}). "
                    "This is technology context for manual testing, not a vulnerability."
                ),
            }
        )

    banner = f"{server} {' '.join(technologies or [])}".lower()
    for marker in ("iis/6", "iis/7", "iis/8", "php/5", "php/7.0", "apache/2.2"):
        if marker in banner:
            findings.append(
                {
                    "type": "legacy_stack_banner",
                    "indicator": marker,
                    "hostname": hostname,
                    "explanation": (
                        f"Server/technology metadata mentions '{marker}' on {hostname}. "
                        "Banner strings are passive indicators and require manual verification."
                    ),
                }
            )
    return findings


@dataclass
class AssetIntelligenceResult:
    domain: str
    asset_inventory: list[dict] = field(default_factory=list)
    interesting_assets: list[dict] = field(default_factory=list)
    exposure_indicators: dict = field(default_factory=dict)
    takeover_candidates: list[dict] = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "domain": self.domain,
            "summary": self.summary,
            "interesting_assets": self.interesting_assets,
            "asset_inventory": self.asset_inventory,
            "exposure_indicators": self.exposure_indicators,
            "takeover_candidates": self.takeover_candidates,
            "disclaimer": (
                "Reconnaissance intelligence for authorized manual security assessment only. "
                "Indicators are not confirmed vulnerabilities."
            ),
        }


class AssetIntelligenceEngine:
    def run(
        self,
        *,
        domain: str,
        organized: OrganizedResults | None = None,
        dns: DNSRunResult | None = None,
        http: HTTPRunResult | None = None,
        tls: TLSRunResult | None = None,
        historical: HistoricalResult | None = None,
        sensitive: SensitiveResult | None = None,
        javascript: JSResult | None = None,
        takeover: TakeoverResult | None = None,
    ) -> AssetIntelligenceResult:
        result = AssetIntelligenceResult(domain=domain)

        urls_by_host: dict[str, list[str]] = {}
        params_by_host: dict[str, set[str]] = {}
        if historical is not None:
            for rec in historical.in_scope:
                urls_by_host.setdefault(rec.hostname, []).append(rec.normalized)
                for p in rec.params:
                    params_by_host.setdefault(rec.hostname, set()).add(p)

        js_by_host: dict[str, list[dict]] = {}
        js_endpoints_by_host: dict[str, list[str]] = {}
        if javascript is not None:
            for asset in javascript.assets:
                js_by_host.setdefault(asset.hostname, []).append(asset.as_dict())
                if asset.endpoints:
                    js_endpoints_by_host.setdefault(asset.hostname, []).extend(
                        asset.endpoints
                    )

        dns_map = {r.hostname: r for r in (dns.records if dns else [])}
        takeover_by_host = {
            c.hostname: c for c in (takeover.candidates if takeover else [])
        }

        api_routes = list(sensitive.api_endpoints) if sensitive else []
        auth_paths = list(sensitive.authentication_paths) if sensitive else []
        admin_paths = list(sensitive.admin_paths) if sensitive else []
        config_ind = list(sensitive.config_indicators) if sensitive else []
        backup_ind = list(sensitive.backup_indicators) if sensitive else []
        db_ind = list(sensitive.database_indicators) if sensitive else []
        debug_ind = list(sensitive.debug_paths) if sensitive else []
        interesting_params = list(sensitive.interesting_parameters) if sensitive else []

        env_indicators: list[dict] = []
        legacy_indicators: list[dict] = []
        unusual_status_indicators: list[dict] = []
        technology_summary: dict[str, list[str]] = {}
        dangling_dns_indicators: list[dict] = []

        sub_records = organized.subdomain_records if organized else []
        for sub in sub_records:
            host = sub.hostname
            host_urls = urls_by_host.get(host, [])
            host_js = js_by_host.get(host, [])
            host_js_eps = sorted(set(js_endpoints_by_host.get(host, [])))
            host_params = sorted(params_by_host.get(host, set()))
            dns_rec = dns_map.get(host)

            host_indicators: list[dict] = []
            tags: list[str] = []
            priority_score = 0

            if sub.classification == "LIVE":
                priority_score += 20
                tags.append("live")

            env_hits = detect_hostname_environment_labels(host)
            if env_hits:
                env_indicators.extend(env_hits)
                host_indicators.extend(env_hits)
                tags.append("non-prod-label")
                priority_score += 18

            leg_hits = detect_legacy_indicators(
                host, host_urls, sub.technologies, sub.server
            )
            if leg_hits:
                legacy_indicators.extend(leg_hits)
                host_indicators.extend(leg_hits)
                tags.append("legacy-indicator")
                priority_score += 12

            for scheme_label, code in (("HTTPS", sub.https_status), ("HTTP", sub.http_status)):
                if code in _UNUSUAL_STATUS_EXPLANATIONS:
                    entry = {
                        "type": "unusual_http_status",
                        "hostname": host,
                        "scheme": scheme_label,
                        "status": code,
                        "explanation": _UNUSUAL_STATUS_EXPLANATIONS[code],
                    }
                    unusual_status_indicators.append(entry)
                    host_indicators.append(entry)
                    if f"http-{code}" not in tags:
                        tags.append(f"http-{code}")
                    priority_score += 15

            host_api = [u for u in api_routes if f"://{host}/" in u or u.endswith(f"://{host}")]
            if host_api or host_js_eps:
                tags.append("api-surface")
                priority_score += 15
                host_indicators.append(
                    {
                        "type": "api_routes",
                        "hostname": host,
                        "count": len(host_api) + len(host_js_eps),
                        "samples": (host_api + host_js_eps)[:10],
                        "explanation": (
                            f"{len(host_api)} historical API URL(s) and {len(host_js_eps)} JS endpoint reference(s) "
                            "associated with this host. Useful for authorized API authorization and schema review."
                        ),
                    }
                )

            host_auth = [u for u in auth_paths if f"://{host}/" in u]
            if host_auth:
                tags.append("authentication-surface")
                priority_score += 15
                host_indicators.append(
                    {
                        "type": "authentication_paths",
                        "hostname": host,
                        "count": len(host_auth),
                        "samples": host_auth[:10],
                        "explanation": (
                            f"{len(host_auth)} authentication/session-related path(s) observed on {host}. "
                            "Candidate for authorized manual authentication workflow assessment."
                        ),
                    }
                )

            host_admin = [u for u in admin_paths if f"://{host}/" in u]
            title_lower = (sub.title or "").lower()
            title_admin = any(
                w in title_lower for w in ("admin", "dashboard", "console", "portal", "manager")
            )
            if host_admin or title_admin:
                tags.append("admin-interface")
                priority_score += 20
                host_indicators.append(
                    {
                        "type": "admin_interface",
                        "hostname": host,
                        "count": len(host_admin),
                        "title": sub.title,
                        "samples": host_admin[:10],
                        "explanation": (
                            f"Administrative path or page title indicator observed on {host}. "
                            "Verify access controls manually within program rules; do not brute-force credentials."
                        ),
                    }
                )

            if host_params:
                tags.append("parameterized-endpoints")
                priority_score += 10
                host_indicators.append(
                    {
                        "type": "historical_parameters",
                        "hostname": host,
                        "parameters": host_params[:25],
                        "explanation": (
                            f"{len(host_params)} unique query parameter name(s) observed in historical URLs for {host}. "
                            "Parameter values are redacted."
                        ),
                    }
                )

            if sub.technologies or sub.server:
                techs = list(sub.technologies)
                if sub.server and sub.server not in techs:
                    techs.append(sub.server)
                technology_summary[host] = techs

            if dns_rec and dns_rec.dangling:
                cname_target = dns_rec.cname[-1] if dns_rec.cname else ""
                dangling_entry = {
                    "type": "dangling_dns",
                    "hostname": host,
                    "cname_target": cname_target,
                    "rcode": dns_rec.rcode,
                    "explanation": (
                        f"Hostname {host} has a CNAME pointing to {cname_target} which did not resolve ({dns_rec.rcode}). "
                        "Inspect manually for potential dangling DNS; never attempt to claim external resources."
                    ),
                }
                dangling_dns_indicators.append(dangling_entry)
                host_indicators.append(dangling_entry)
                tags.append("dangling-dns")
                priority_score += 25

            if host in takeover_by_host:
                cand = takeover_by_host[host]
                tags.append("takeover-candidate")
                priority_score += 25
                host_indicators.append(
                    {
                        "type": "takeover_candidate",
                        "hostname": host,
                        "cname_target": cand.cname_target,
                        "provider": cand.provider_name,
                        "confidence": cand.confidence,
                        "classification": cand.classification,
                        "explanation": (
                            f"Passive takeover indicator ({cand.classification}, {cand.confidence}/100) "
                            f"for CNAME {cand.cname_target}. Manual verification required."
                        ),
                    }
                )

            priority_score = min(100, priority_score)
            if priority_score >= 60:
                priority_level = "high"
            elif priority_score >= 35:
                priority_level = "medium"
            elif priority_score > 0:
                priority_level = "low"
            else:
                priority_level = "informational"

            asset_entry = {
                "hostname": host,
                "in_scope": sub.in_scope,
                "classification": sub.classification,
                "reason": sub.reason,
                "priority_score": priority_score,
                "priority_level": priority_level,
                "tags": tags,
                "sources": sub.sources,
                "http_status": sub.http_status,
                "https_status": sub.https_status,
                "final_url": sub.final_url,
                "title": sub.title,
                "server": sub.server,
                "content_type": sub.content_type,
                "response_time": sub.response_time,
                "technologies": sub.technologies,
                "tls_metadata": sub.tls_metadata,
                "dns": dns_rec.as_dict() if dns_rec else {},
                "historical_url_count": len(host_urls),
                "javascript_asset_count": len(host_js),
                "parameter_names": host_params[:50],
                "indicators": host_indicators,
            }
            result.asset_inventory.append(asset_entry)
            if sub.in_scope and (host_indicators or sub.classification == "LIVE"):
                result.interesting_assets.append(asset_entry)

        result.interesting_assets.sort(
            key=lambda a: (-a["priority_score"], a["hostname"])
        )

        if takeover is not None:
            for cand in takeover.candidates:
                entry = cand.as_dict()
                entry["explanation"] = (
                    f"{cand.hostname} aliases {cand.cname_target} "
                    f"(provider: {cand.provider_name or 'unmatched'}, "
                    f"classification: {cand.classification}, confidence: {cand.confidence}/100). "
                    "This is a passive indicator only; do not register or claim any third-party resource."
                )
                result.takeover_candidates.append(entry)

        result.exposure_indicators = {
            "api_routes": {
                "count": len(api_routes),
                "explanation": "API, GraphQL, Swagger/OpenAPI, and versioned service paths identified for manual authorization and input validation review.",
                "urls": api_routes[:500],
            },
            "authentication_paths": {
                "count": len(auth_paths),
                "explanation": "Authentication, SSO, OAuth, SAML, and session management endpoints identified for manual workflow review.",
                "urls": auth_paths[:500],
            },
            "admin_interfaces": {
                "count": len(admin_paths),
                "explanation": "Administrative, console, dashboard, or management portal paths identified for manual access-control verification.",
                "urls": admin_paths[:500],
            },
            "config_indicators": {
                "count": len(config_ind),
                "explanation": "Environment, configuration, or repository metadata path indicators (never downloaded by SubReconX).",
                "urls": config_ind[:500],
            },
            "backup_indicators": {
                "count": len(backup_ind),
                "explanation": "Historical or live path references matching backup, archive, or export naming conventions.",
                "urls": backup_ind[:500],
            },
            "database_indicators": {
                "count": len(db_ind),
                "explanation": "Path or parameter-name indicators referencing database dumps or database administration paths.",
                "urls": db_ind[:500],
            },
            "debug_indicators": {
                "count": len(debug_ind),
                "explanation": "Debug, actuator, profiler, trace, or diagnostic log indicators.",
                "urls": debug_ind[:500],
            },
            "interesting_parameters": {
                "count": len(interesting_params),
                "explanation": "URLs containing query parameter names often relevant to manual redirect, SSRF, IDOR, or file-inclusion testing (parameter values redacted).",
                "urls": interesting_params[:500],
            },
            "environment_hostname_labels": {
                "count": len(env_indicators),
                "explanation": "Subdomains containing development, staging, UAT, QA, test, sandbox, or internal labels.",
                "items": env_indicators,
            },
            "legacy_application_indicators": {
                "count": len(legacy_indicators),
                "explanation": "Subdomains or endpoints exhibiting legacy naming or classic server file extensions.",
                "items": legacy_indicators,
            },
            "unusual_status_codes": {
                "count": len(unusual_status_indicators),
                "explanation": "Live hosts returning HTTP 401, 403, 405, 500, 502, or 503 responses.",
                "items": unusual_status_indicators,
            },
            "technology_metadata": {
                "count": len(technology_summary),
                "explanation": "Passively fingerprinted server headers and web technologies per live host.",
                "by_host": technology_summary,
            },
            "dangling_dns_references": {
                "count": len(dangling_dns_indicators),
                "explanation": "In-scope hostnames with CNAME records pointing to unresolved targets.",
                "items": dangling_dns_indicators,
            },
        }

        result.summary = {
            "total_assets": len(result.asset_inventory),
            "interesting_assets": len(result.interesting_assets),
            "high_priority_assets": sum(
                1 for a in result.interesting_assets if a["priority_level"] == "high"
            ),
            "api_routes": len(api_routes),
            "authentication_paths": len(auth_paths),
            "admin_interfaces": len(admin_paths),
            "environment_labels": len(env_indicators),
            "legacy_indicators": len(legacy_indicators),
            "unusual_status_codes": len(unusual_status_indicators),
            "dangling_dns_references": len(dangling_dns_indicators),
            "takeover_candidates": len(result.takeover_candidates),
        }
        return result

    def write_outputs(self, result: AssetIntelligenceResult, output_dir: Path) -> None:
        output_dir = Path(output_dir)
        intel_dir = output_dir / "intelligence"
        intel_dir.mkdir(parents=True, exist_ok=True)

        (intel_dir / "asset_inventory.json").write_text(
            json.dumps(
                {
                    "domain": result.domain,
                    "count": len(result.asset_inventory),
                    "summary": result.summary,
                    "assets": result.asset_inventory,
                },
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )
        (intel_dir / "interesting_assets.json").write_text(
            json.dumps(
                {
                    "domain": result.domain,
                    "count": len(result.interesting_assets),
                    "assets": result.interesting_assets,
                },
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )
        (intel_dir / "exposure_indicators.json").write_text(
            json.dumps(
                {
                    "domain": result.domain,
                    "summary": result.summary,
                    "indicators": result.exposure_indicators,
                },
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )
        (intel_dir / "takeover_candidates.json").write_text(
            json.dumps(
                {
                    "domain": result.domain,
                    "count": len(result.takeover_candidates),
                    "candidates": result.takeover_candidates,
                    "note": "Indicator only. Authorized manual verification required; no claim was attempted.",
                },
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )
