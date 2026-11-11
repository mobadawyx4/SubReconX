"""Standalone HTML / JSON / TXT reporting."""

from __future__ import annotations

import html
import json
import time
from pathlib import Path
from typing import Any

from utils.redaction import redact_text, redact_url

SEVERITY_CLASS = {
    "critical": "sev-critical",
    "high": "sev-high",
    "medium": "sev-medium",
    "low": "sev-low",
    "informational": "sev-info",
}


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def _badge(severity: str) -> str:
    css = SEVERITY_CLASS.get(severity, "sev-info")
    return f'<span class="badge {css}">{_esc(severity.upper())}</span>'


def _redact_record(record: dict) -> dict:
    out = dict(record)
    for key in ("url", "normalized"):
        if isinstance(out.get(key), str):
            out[key] = redact_url(out[key])
    for key in ("sources", "params", "endpoints"):
        if isinstance(out.get(key), list):
            out[key] = [redact_url(str(v)) if isinstance(v, str) and "://" in v else v for v in out[key]]
    return out


def _redact_tree(value):
    if isinstance(value, dict):
        return {key: _redact_tree(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_tree(item) for item in value]
    if isinstance(value, str):
        if "://" in value:
            return redact_url(value)
        return redact_text(value)
    return value


def _prepare_json(bundle: dict) -> dict:
    payload = _redact_tree(json.loads(json.dumps(bundle, default=str)))
    historical = payload.get("historical") or {}
    for key in ("records", "out_of_scope_records"):
        if isinstance(historical.get(key), list):
            historical[key] = [_redact_record(item) for item in historical[key]]
    js = payload.get("javascript") or {}
    if isinstance(js.get("assets"), list):
        js["assets"] = [_redact_record(item) for item in js["assets"]]
    if isinstance(js.get("endpoints"), list):
        js["endpoints"] = [redact_url(str(x)) for x in js["endpoints"]]
    return payload


def _extract_canonical_metrics(bundle: dict) -> dict:
    assets = bundle.get("risk", {}).get("asset_summary", {})
    dns = bundle.get("dns") or {}
    subdomains = bundle.get("subdomains") or {}
    organized = bundle.get("organized") or {}
    org_counts = organized.get("counts") or {}
    http = bundle.get("http") or {}
    historical = bundle.get("historical") or {}
    js = bundle.get("javascript") or {}
    sensitive = bundle.get("sensitive") or {}
    takeover = bundle.get("takeover") or {}
    risk = bundle.get("risk") or {}

    unique_subs = (
        org_counts.get("unique_subdomains")
        if "unique_subdomains" in org_counts
        else (subdomains.get("count") or assets.get("subdomains", 0))
    )
    total_discovered = (
        org_counts.get("raw_subdomains")
        if "raw_subdomains" in org_counts
        else (subdomains.get("total_discovered") or unique_subs)
    )
    in_scope_subs = (
        org_counts.get("in_scope_subdomains")
        if "in_scope_subdomains" in org_counts
        else (subdomains.get("in_scope_count") or unique_subs)
    )
    out_of_scope_subs = org_counts.get(
        "out_of_scope_subdomains", subdomains.get("out_of_scope_count", 0)
    )
    live_hosts = (
        org_counts.get("live_subdomains")
        if "live_subdomains" in org_counts
        else (len(http.get("live_hosts", [])) or assets.get("live_hosts", 0))
    )
    dead_hosts = (
        org_counts.get("dead_subdomains")
        if "dead_subdomains" in org_counts
        else len(http.get("dead_hosts", []))
    )
    unknown_hosts = (
        org_counts.get("unknown_subdomains")
        if "unknown_subdomains" in org_counts
        else len(http.get("unknown_hosts", []))
    )
    hist_in_scope = (
        historical.get("in_scope")
        if "in_scope" in historical
        else assets.get("historical_urls", 0)
    )
    hist_unique = (
        historical.get("unique_count")
        if "unique_count" in historical
        else hist_in_scope + int(historical.get("out_of_scope", 0))
    )
    js_count = (
        js.get("count")
        if "count" in js
        else assets.get("javascript_assets", 0)
    )
    sens_count = (
        sensitive.get("total_indicators")
        if "total_indicators" in sensitive
        else assets.get("sensitive_indicators", 0)
    )
    takeover_count = (
        takeover.get("count")
        if "count" in takeover
        else assets.get("takeover_candidates", 0)
    )

    return {
        "total_discovered_subdomains": int(total_discovered or 0),
        "unique_subdomains": int(unique_subs or 0),
        "in_scope_assets": int(in_scope_subs or 0),
        "out_of_scope_subdomains": int(out_of_scope_subs or 0),
        "live_hosts": int(live_hosts or 0),
        "dead_hosts": int(dead_hosts or 0),
        "unknown_hosts": int(unknown_hosts or 0),
        "resolved_dns": len(dns.get("resolved", [])),
        "historical_urls": int(hist_in_scope or 0),
        "historical_urls_unique": int(hist_unique or 0),
        "javascript_assets": int(js_count or 0),
        "sensitive_indicators": int(sens_count or 0),
        "takeover_candidates": int(takeover_count or 0),
        "overall_severity": str(risk.get("overall_severity", "informational")),
        "overall_score": int(risk.get("overall_score", 0) or 0),
    }


def _stat_cards(bundle: dict) -> str:
    m = _extract_canonical_metrics(bundle)
    cards = [
        ("Total discovered subdomains", m["total_discovered_subdomains"], "total-subs"),
        ("Unique subdomains", m["unique_subdomains"], "subdomains"),
        ("In-scope assets", m["in_scope_assets"], "in-scope"),
        ("Live hosts", m["live_hosts"], "live"),
        ("Dead hosts", m["dead_hosts"], "dead"),
        ("Unknown hosts", m["unknown_hosts"], "unknown"),
        ("Resolved DNS", m["resolved_dns"], "dns"),
        ("Historical URLs", m["historical_urls"], "historical"),
        ("JavaScript", m["javascript_assets"], "js"),
        ("Sensitive indicators", m["sensitive_indicators"], "sensitive"),
        ("Takeover candidates", m["takeover_candidates"], "takeover"),
    ]
    parts = []
    for label, value, _key in cards:
        parts.append(
            f'<div class="card" data-metric="{_esc(_key)}"><div class="card-value">{_esc(value)}</div>'
            f'<div class="card-label">{_esc(label)}</div></div>'
        )
    return "\n".join(parts)


def _liveness_badge(state: str) -> str:
    st = (state or "UNKNOWN").upper()
    if st == "LIVE":
        return '<span class="badge sev-low">LIVE</span>'
    if st == "DEAD":
        return '<span class="badge sev-critical">DEAD</span>'
    return '<span class="badge sev-medium">UNKNOWN</span>'


def _intelligence_section(bundle: dict) -> str:
    intel = bundle.get("intelligence") or {}
    interesting = intel.get("interesting_assets", [])
    summary = intel.get("summary", {})
    rows = []
    for item in interesting[:500]:
        prio = item.get("priority_level", "informational")
        tags = " ".join(
            f'<span class="badge sev-info">{_esc(t)}</span>'
            for t in (item.get("tags") or [])
        )
        explanations = "<br>".join(
            f"• <strong>{_esc(ind.get('type'))}</strong>: {_esc(ind.get('explanation'))}"
            for ind in (item.get("indicators") or [])[:6]
        )
        status_str = (
            f"HTTPS:{item.get('https_status') or '-'} / HTTP:{item.get('http_status') or '-'}"
        )
        rows.append(
            "<tr>"
            f"<td>{_badge(prio)} <span class='score'>{_esc(item.get('priority_score', 0))}</span></td>"
            f"<td><strong>{_esc(item.get('hostname'))}</strong><br><span class='muted'>{_esc(item.get('title') or '')}</span></td>"
            f"<td>{_liveness_badge(item.get('classification', 'UNKNOWN'))}<br><span class='muted'>{_esc(status_str)}</span></td>"
            f"<td>{tags}</td>"
            f"<td class='evidence'>{explanations or _esc(item.get('reason') or 'Live in-scope asset')}</td>"
            "</tr>"
        )
    empty = "<tr><td colspan='5' class='muted'>No prioritized assets identified.</td></tr>"
    return f"""
    <section id="intelligence"><h2>Bug Bounty asset intelligence <span class="muted">({len(interesting)} prioritized)</span></h2>
    <div class="metrics">
      <div class="metric"><strong>{_esc(summary.get('high_priority_assets', 0))}</strong><span>high priority</span></div>
      <div class="metric"><strong>{_esc(summary.get('api_routes', 0))}</strong><span>API routes</span></div>
      <div class="metric"><strong>{_esc(summary.get('authentication_paths', 0))}</strong><span>auth paths</span></div>
      <div class="metric"><strong>{_esc(summary.get('admin_interfaces', 0))}</strong><span>admin paths</span></div>
      <div class="metric"><strong>{_esc(summary.get('environment_labels', 0))}</strong><span>dev/stage hosts</span></div>
      <div class="metric"><strong>{_esc(summary.get('legacy_indicators', 0))}</strong><span>legacy indicators</span></div>
      <div class="metric"><strong>{_esc(summary.get('unusual_status_codes', 0))}</strong><span>unusual HTTP codes</span></div>
    </div>
    <div class="controls-row">
      <input class="search" data-target="intel-table" placeholder="Filter prioritized assets…">
      <div class="filter-bar" data-target="intel-table">
        <button type="button" class="filter-btn active" data-target="intel-table" data-filter="">All</button>
        <button type="button" class="filter-btn" data-target="intel-table" data-filter="HIGH">High</button>
        <button type="button" class="filter-btn" data-target="intel-table" data-filter="MEDIUM">Medium</button>
        <button type="button" class="filter-btn" data-target="intel-table" data-filter="LOW">Low</button>
        <button type="button" class="filter-btn" data-target="intel-table" data-filter="LIVE">LIVE</button>
        <button type="button" class="filter-btn" data-target="intel-table" data-filter="DEAD">DEAD</button>
        <button type="button" class="filter-btn" data-target="intel-table" data-filter="UNKNOWN">UNKNOWN</button>
      </div>
    </div>
    <div class="table-wrap"><table id="intel-table" class="filterable"><thead><tr><th>Priority</th><th>Asset</th><th>State &amp; Status</th><th>Tags</th><th>Indicator Explanations (Manual Review)</th></tr></thead>
    <tbody>{''.join(rows) or empty}</tbody></table></div>
    <p class="muted">Prioritized indicators for authorized manual Bug Bounty assessment. Keyword and metadata matches are not automatically classified as vulnerabilities.</p>
    </section>"""


def _risk_section(risk: dict) -> str:
    findings = risk.get("findings", [])
    overall = risk.get("overall_severity", "informational")
    summary = risk.get("summary", {})
    summary_html = " ".join(
        f'{_badge(sev)} <span class="muted">{count}</span>' for sev, count in summary.items()
    )
    rows = []
    for finding in findings:
        evidence = "<br>".join(_esc(item) for item in finding.get("evidence", [])[:8])
        rows.append(
            "<tr>"
            f"<td>{_badge(finding.get('severity', 'informational'))}</td>"
            f"<td class='score'>{_esc(finding.get('score'))}</td>"
            f"<td><strong>{_esc(finding.get('title'))}</strong><br>"
            f"<span class='muted'>{_esc(finding.get('rationale'))}</span></td>"
            f"<td class='evidence'>{evidence}</td>"
            "</tr>"
        )
    empty = "<tr><td colspan='4' class='muted'>No findings.</td></tr>"
    return f"""
    <section id="risk"><h2>Risk assessment</h2>
    <div class="overall">{_badge(overall)} <span class="muted">overall severity · score {_esc(risk.get("overall_score", 0))}/100</span></div>
    <p>{summary_html}</p>
    <input class="search" data-target="risk-table" placeholder="Filter risk findings…">
    <div class="table-wrap"><table id="risk-table" class="filterable"><thead><tr><th>Severity</th><th>Score</th><th>Finding</th><th>Evidence</th></tr></thead>
    <tbody>{''.join(rows) or empty}</tbody></table></div>
    <p class="muted">{_esc(" ".join(risk.get("notes", [])))}</p>
    </section>"""


def _subdomains_section(bundle: dict) -> str:
    organized = bundle.get("organized") or {}
    org_hosts = organized.get("hosts", [])
    hosts = org_hosts if org_hosts else (bundle.get("subdomains") or {}).get("hosts", [])
    rows = []
    for item in hosts:
        sources = ", ".join(item.get("sources", []) or [])
        cls = item.get("classification", "")
        in_scope = "yes" if item.get("in_scope", True) else "no"
        state_html = _liveness_badge(cls) if cls else '<span class="muted">-</span>'
        rows.append(
            f"<tr data-classification='{_esc(cls)}' data-scope='{_esc(in_scope)}'>"
            f"<td>{_esc(item.get('hostname'))}</td>"
            f"<td>{_esc(in_scope)}</td>"
            f"<td>{state_html}</td>"
            f"<td class='muted'>{_esc(item.get('reason') or '')}</td>"
            f"<td class='muted'>{_esc(sources)}</td>"
            "</tr>"
        )
    return f"""
    <section id="subdomains"><h2>Subdomains &amp; liveness classification <span class="muted">({len(hosts)})</span></h2>
    <div class="controls-row">
      <input class="search" data-target="subdomains-table" placeholder="Filter subdomains…">
      <div class="filter-bar" data-target="subdomains-table">
        <button type="button" class="filter-btn active" data-target="subdomains-table" data-filter="">All</button>
        <button type="button" class="filter-btn" data-target="subdomains-table" data-filter="LIVE">LIVE</button>
        <button type="button" class="filter-btn" data-target="subdomains-table" data-filter="DEAD">DEAD</button>
        <button type="button" class="filter-btn" data-target="subdomains-table" data-filter="UNKNOWN">UNKNOWN</button>
      </div>
    </div>
    <div class="table-wrap"><table id="subdomains-table" class="filterable"><thead><tr><th>Hostname</th><th>In Scope</th><th>Classification</th><th>Reason</th><th>Sources</th></tr></thead>
    <tbody>{''.join(rows) or "<tr><td colspan='5' class='muted'>None.</td></tr>"}</tbody></table></div>
    </section>"""


def _http_section(bundle: dict) -> str:
    records = (bundle.get("http") or {}).get("results", [])
    rows = []
    for item in records:
        rows.append(
            "<tr>"
            f"<td>{_esc(item.get('hostname'))}</td>"
            f"<td>{_esc(item.get('scheme'))}</td>"
            f"<td class='status'>{_esc(item.get('status') if item.get('status') is not None else 'ERR')}</td>"
            f"<td>{_esc(item.get('server'))}</td>"
            f"<td>{_esc(', '.join(item.get('technologies', []) or []))}</td>"
            f"<td>{_esc(item.get('title'))}</td>"
            f"<td>{_esc(item.get('final_url'))}</td>"
            f"<td>{_esc(item.get('error'))}</td>"
            "</tr>"
        )
    return f"""
    <section id="live"><h2>Live hosts &amp; HTTP <span class="muted">({len(records)})</span></h2>
    <input class="search" data-target="http-table" placeholder="Filter HTTP results…">
    <div class="table-wrap"><table id="http-table" class="filterable"><thead><tr><th>Host</th><th>Scheme</th><th>Status</th><th>Server</th><th>Tech</th><th>Title</th><th>Final URL</th><th>Error</th></tr></thead>
    <tbody>{''.join(rows) or "<tr><td colspan='8' class='muted'>None.</td></tr>"}</tbody></table></div>
    </section>"""


def _tls_section(bundle: dict) -> str:
    records = (bundle.get("tls") or {}).get("results", [])
    rows = []
    for item in records:
        subject = item.get("subject") or {}
        issuer = item.get("issuer") or {}
        cn = subject.get("commonName", "")
        issuer_cn = issuer.get("commonName") or issuer.get("organizationName", "")
        sans = ", ".join((item.get("sans") or [])[:6])
        status = (
            "verified"
            if item.get("verified")
            else ("unverified" if item.get("connected") else "error")
        )
        rows.append(
            "<tr>"
            f"<td>{_esc(item.get('hostname'))}</td>"
            f"<td>{_esc(status)}</td>"
            f"<td>{_esc(item.get('protocol'))}</td>"
            f"<td>{_esc(cn)}</td>"
            f"<td>{_esc(issuer_cn)}</td>"
            f"<td>{_esc(sans)}</td>"
            f"<td>{_esc(item.get('not_after'))}</td>"
            f"<td>{_esc(item.get('days_until_expiry') if item.get('days_until_expiry') is not None else '')}</td>"
            "</tr>"
        )
    return f"""
    <section id="tls"><h2>TLS certificates <span class="muted">({len(records)})</span></h2>
    <input class="search" data-target="tls-table" placeholder="Filter TLS certificates…">
    <div class="table-wrap"><table id="tls-table" class="filterable"><thead><tr><th>Host</th><th>Chain</th><th>Protocol</th><th>Subject CN</th><th>Issuer</th><th>SANs</th><th>Expires</th><th>Days left</th></tr></thead>
    <tbody>{''.join(rows) or "<tr><td colspan='8' class='muted'>None.</td></tr>"}</tbody></table></div>
    </section>"""


def _javascript_section(bundle: dict) -> str:
    js = bundle.get("javascript") or {}
    assets = js.get("assets", [])
    endpoints = js.get("endpoints", [])
    rows = []
    for item in assets[:1000]:
        sources = ", ".join(item.get("sources") or [])
        rows.append(
            "<tr>"
            f"<td>{_esc(item.get('hostname'))}</td>"
            f"<td class='url'>{_esc(item.get('normalized') or item.get('url'))}</td>"
            f"<td class='muted'>{_esc(sources)}</td>"
            f"<td>{_esc(item.get('live_status') if item.get('live_status') is not None else '')}</td>"
            f"<td>{_esc(len(item.get('endpoints') or []))}</td>"
            "</tr>"
        )
    ep_html = ""
    if endpoints:
        ep_items = "".join(f"<li><code>{_esc(ep)}</code></li>" for ep in endpoints[:200])
        ep_html = f"<h3>Extracted endpoints ({len(endpoints)})</h3><ul>{ep_items}</ul>"
    return f"""
    <section id="javascript"><h2>JavaScript inventory <span class="muted">({len(assets)})</span></h2>
    <input class="search" data-target="js-table" placeholder="Filter JavaScript assets…">
    <div class="table-wrap"><table id="js-table" class="filterable"><thead><tr><th>Host</th><th>Asset URL</th><th>Sources</th><th>HTTP Status</th><th>Endpoints</th></tr></thead>
    <tbody>{''.join(rows) or "<tr><td colspan='5' class='muted'>None.</td></tr>"}</tbody></table></div>
    {ep_html}
    </section>"""


def _dns_section(bundle: dict) -> str:
    records = (bundle.get("dns") or {}).get("records", [])
    rows = []
    for item in records:
        cname = ", ".join(item.get("cname", []) or [])
        a = ", ".join(item.get("a", []) or [])
        aaaa = ", ".join(item.get("aaaa", []) or [])
        rows.append(
            "<tr>"
            f"<td>{_esc(item.get('hostname'))}</td>"
            f"<td>{_esc(item.get('status'))}</td>"
            f"<td>{_esc(a)}</td><td>{_esc(aaaa)}</td>"
            f"<td>{_esc(cname)}</td>"
            f"<td>{_esc(item.get('rcode'))}</td>"
            f"<td>{'yes' if item.get('dangling') else ''}</td>"
            "</tr>"
        )
    return f"""
    <section id="dns"><h2>DNS analysis <span class="muted">({len(records)})</span></h2>
    <input class="search" data-target="dns-table" placeholder="Filter DNS records…">
    <div class="table-wrap"><table id="dns-table" class="filterable"><thead><tr><th>Host</th><th>Status</th><th>A</th><th>AAAA</th><th>CNAME</th><th>RCODE</th><th>Dangling</th></tr></thead>
    <tbody>{''.join(rows) or "<tr><td colspan='7' class='muted'>None.</td></tr>"}</tbody></table></div>
    </section>"""


def _historical_section(bundle: dict) -> str:
    historical = bundle.get("historical") or {}
    stats = historical.get("source_stats", {})
    filter_stats = (bundle.get("filter") or {}).get("stats", {})
    source_rows = "".join(
        f"<tr><td>{_esc(name)}</td><td>{_esc(count)}</td></tr>" for name, count in sorted(stats.items())
    )
    ext_rows = "".join(
        f"<tr><td>{_esc(name)}</td><td>{_esc(count)}</td></tr>" for name, count in sorted(filter_stats.items())
    )
    return f"""
    <section id="historical"><h2>Historical URLs</h2>
    <div class="metrics">
      <div class="metric"><strong>{_esc(historical.get('total', 0))}</strong><span>total</span></div>
      <div class="metric"><strong>{_esc(historical.get('in_scope', 0))}</strong><span>in scope</span></div>
      <div class="metric"><strong>{_esc(historical.get('out_of_scope', 0))}</strong><span>out of scope</span></div>
      <div class="metric"><strong>{_esc(len(historical.get('malformed', [])))}</strong><span>malformed</span></div>
    </div>
    <div class="two-col">
      <div><h3>By source</h3><table><thead><tr><th>Source</th><th>URLs</th></tr></thead><tbody>{source_rows or "<tr><td colspan='2' class='muted'>None.</td></tr>"}</tbody></table></div>
      <div><h3>By file category</h3><table><thead><tr><th>Category</th><th>URLs</th></tr></thead><tbody>{ext_rows or "<tr><td colspan='2' class='muted'>None.</td></tr>"}</tbody></table></div>
    </div>
    <p class="muted">Out-of-scope references are recorded only and were never probed. Sensitive query values are redacted.</p>
    </section>"""


def _sensitive_section(bundle: dict) -> str:
    sensitive = bundle.get("sensitive") or {}
    indicators = sensitive.get("indicators", [])
    rows = []
    for item in indicators[:2000]:
        rows.append(
            "<tr>"
            f"<td>{_badge(item.get('severity', 'informational'))}</td>"
            f"<td>{_esc(item.get('category'))}</td>"
            f"<td>{_esc(item.get('kind'))}</td>"
            f"<td>{_esc(item.get('value'))}</td>"
            f"<td class='url'>{_esc(item.get('url'))}</td>"
            "</tr>"
        )
    return f"""
    <section id="sensitive"><h2>Sensitive indicators <span class="muted">({len(indicators)})</span></h2>
    <input class="search" data-target="sensitive-table" placeholder="Filter indicators…">
    <div class="table-wrap"><table id="sensitive-table" class="filterable"><thead><tr><th>Severity</th><th>Category</th><th>Kind</th><th>Indicator</th><th>Redacted URL</th></tr></thead>
    <tbody>{''.join(rows) or "<tr><td colspan='5' class='muted'>None.</td></tr>"}</tbody></table></div>
    <p class="muted">Path and parameter-NAME matches only. Values are redacted; no referenced file was downloaded.</p>
    </section>"""


def _takeover_section(bundle: dict) -> str:
    candidates = (bundle.get("takeover") or {}).get("candidates", [])
    rows = []
    for item in candidates:
        evidence = "<br>".join(_esc(x) for x in item.get("evidence", []))
        rows.append(
            "<tr>"
            f"<td>{_badge('high' if item.get('classification') == 'Likely' else ('medium' if item.get('classification') == 'Potential' else 'low'))}</td>"
            f"<td>{_esc(item.get('hostname'))}</td>"
            f"<td>{_esc(item.get('cname_target'))}</td>"
            f"<td>{_esc(item.get('provider'))}</td>"
            f"<td class='score'>{_esc(item.get('confidence'))}</td>"
            f"<td>{_esc(item.get('classification'))}</td>"
            f"<td class='evidence'>{evidence}</td>"
            "</tr>"
        )
    return f"""
    <section id="takeover"><h2>Takeover candidates <span class="muted">({len(candidates)})</span></h2>
    <input class="search" data-target="takeover-table" placeholder="Filter takeover candidates…">
    <div class="table-wrap"><table id="takeover-table" class="filterable"><thead><tr><th>Severity</th><th>Host</th><th>CNAME target</th><th>Provider</th><th>Confidence</th><th>Classification</th><th>Evidence</th></tr></thead>
    <tbody>{''.join(rows) or "<tr><td colspan='7' class='muted'>None.</td></tr>"}</tbody></table></div>
    <p class="muted">Indicators only. No resource was claimed, registered or provisioned. Authorized manual verification required.</p>
    </section>"""


def _sources_section(bundle: dict) -> str:
    sources = bundle.get("sources", [])
    rows = "".join(
        f"<tr><td>{_esc(item.get('source'))}</td><td>{_esc(item.get('count'))}</td>"
        f"<td>{'yes' if item.get('cached') else 'no'}</td><td>{_esc(item.get('error'))}</td></tr>"
        for item in sources
    )
    return f"""
    <section id="sources"><h2>Source attribution</h2>
    <table><thead><tr><th>Source</th><th>Records</th><th>Cached</th><th>Error</th></tr></thead>
    <tbody>{rows or "<tr><td colspan='4' class='muted'>None.</td></tr>"}</tbody></table>
    </section>"""


def _tasks_section(bundle: dict) -> str:
    tasks = bundle.get("tasks", [])
    rows = "".join(
        f"<tr><td>{_esc(t.get('name'))}</td><td>{_esc(t.get('status'))}</td>"
        f"<td>{_esc(t.get('duration_seconds'))}s</td><td>{_esc(t.get('summary'))}</td>"
        f"<td>{_esc(t.get('error'))}</td></tr>"
        for t in tasks
    )
    return f"""
    <section id="tasks"><h2>Scan phases</h2>
    <table><thead><tr><th>Phase</th><th>Status</th><th>Duration</th><th>Summary</th><th>Error</th></tr></thead>
    <tbody>{rows or "<tr><td colspan='5' class='muted'>None.</td></tr>"}</tbody></table>
    </section>"""


def _errors_section(bundle: dict) -> str:
    errors = bundle.get("errors", [])
    rows = "".join(
        f"<tr><td>{_esc(item.get('phase'))}</td><td>{_esc(item.get('message'))}</td>"
        f"<td class='muted'>{_esc(item.get('time'))}</td></tr>"
        for item in errors
    )
    return f"""
    <section id="errors"><h2>Errors <span class="muted">({len(errors)})</span></h2>
    <table><thead><tr><th>Phase</th><th>Message</th><th>Time</th></tr></thead>
    <tbody>{rows or "<tr><td colspan='3' class='muted'>None.</td></tr>"}</tbody></table>
    </section>"""


CSS = """
:root{--bg:#0b1220;--panel:#121b2e;--panel2:#0f1728;--text:#e6edf7;--muted:#8aa0bd;--line:#22304a;--accent:#38bdf8;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
header{padding:28px 32px;background:linear-gradient(135deg,#0f2740,#141b34);border-bottom:1px solid var(--line)}
h1{margin:0;font-size:26px;letter-spacing:.3px}h2{margin:0 0 14px;font-size:19px}h3{margin:0 0 10px;font-size:15px;color:var(--muted)}
a{color:var(--accent)}.muted{color:var(--muted)}nav{padding:12px 32px;background:var(--panel2);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5;display:flex;gap:16px;flex-wrap:wrap}
nav a{text-decoration:none;color:var(--muted);font-weight:600}nav a:hover{color:var(--accent)}
main{padding:24px 32px 64px;max-width:1500px;margin:0 auto}section{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px;margin:18px 0}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:18px}
.card{background:rgba(255,255,255,.03);border:1px solid var(--line);border-radius:10px;padding:14px}
.card-value{font-size:26px;font-weight:700}.card-label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}
.metrics{display:flex;gap:24px;flex-wrap:wrap;margin:8px 0 16px}.metric{background:var(--panel2);padding:10px 16px;border-radius:8px;border:1px solid var(--line)}.metric strong{display:block;font-size:20px}.metric span{color:var(--muted);font-size:12px}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);text-transform:uppercase;font-size:11px;letter-spacing:.07em}
.table-wrap{max-height:420px;overflow:auto;border:1px solid var(--line);border-radius:8px}
td.url{word-break:break-all;max-width:520px}td.evidence{max-width:420px;color:var(--muted)}td.score{font-weight:700}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:10px;font-weight:800;letter-spacing:.06em}
.sev-critical{background:#4c0519;color:#fecdd3}.sev-high{background:#4a1d05;color:#fed7aa}.sev-medium{background:#422006;color:#fde68a}.sev-low{background:#052e2b;color:#99f6e4}.sev-info{background:#172554;color:#bfdbfe}
.overall{margin-bottom:10px}.two-col{display:grid;grid-template-columns:1fr 1fr;gap:18px}@media(max-width:800px){.two-col{grid-template-columns:1fr}}
.controls-row{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
.controls-row .search{margin-bottom:0}
.search{width:100%;max-width:420px;margin-bottom:12px;padding:9px 12px;border-radius:8px;border:1px solid var(--line);background:var(--panel2);color:var(--text)}
.filter-bar{display:flex;gap:6px;flex-wrap:wrap}
.filter-btn{background:var(--panel2);color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:6px 12px;font-size:12px;font-weight:600;cursor:pointer}
.filter-btn.active,.filter-btn:hover{border-color:var(--accent);color:var(--accent)}
footer{padding:24px 32px;color:var(--muted);border-top:1px solid var(--line);font-size:12px}
.status{font-weight:700}
"""

JS = """
function applyTableFilter(tableId){
  var target = document.getElementById(tableId);
  if(!target) return;
  var searchInput = document.querySelector('input.search[data-target="' + tableId + '"]');
  var activeBtn = document.querySelector('button.filter-btn.active[data-target="' + tableId + '"]');
  var q = searchInput ? searchInput.value.toLowerCase().trim() : '';
  var pill = activeBtn ? (activeBtn.dataset.filter || '').toLowerCase().trim() : '';
  target.querySelectorAll('tbody tr').forEach(function(row){
    var text = row.textContent.toLowerCase();
    var matchSearch = !q || text.indexOf(q) !== -1;
    var matchPill = !pill || text.indexOf(pill) !== -1;
    row.style.display = (matchSearch && matchPill) ? '' : 'none';
  });
}
document.querySelectorAll('input.search').forEach(function(input){
  input.addEventListener('input', function(){
    applyTableFilter(input.dataset.target);
  });
});
document.querySelectorAll('button.filter-btn').forEach(function(btn){
  btn.addEventListener('click', function(){
    var tableId = btn.dataset.target;
    document.querySelectorAll('button.filter-btn[data-target="' + tableId + '"]').forEach(function(b){
      b.classList.remove('active');
    });
    btn.classList.add('active');
    applyTableFilter(tableId);
  });
});
"""


def build_html(bundle: dict) -> str:
    meta = bundle.get("meta", {})
    risk = bundle.get("risk", {})
    domain = meta.get("domain", "unknown")
    generated = meta.get("generated_at", "")
    duration = meta.get("duration_human", "")
    tool = meta.get("tool", "SubReconX")
    version = meta.get("version", "")
    overall = risk.get("overall_severity", "informational")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(tool)} report · {_esc(domain)}</title>
<style>{CSS}</style></head>
<body>
<header>
  <h1>{_esc(tool)} <span class="muted">v{_esc(version)}</span></h1>
  <div class="muted">Reconnaissance report for <strong>{_esc(domain)}</strong> · generated {_esc(generated)} · duration {_esc(duration)} {_badge(overall)}</div>
  <div class="cards">{_stat_cards(bundle)}</div>
</header>
<nav>
  <a href="#intelligence">Bug Bounty Intel</a><a href="#risk">Risk</a><a href="#subdomains">Subdomains</a><a href="#live">Live/HTTP</a>
  <a href="#tls">TLS</a><a href="#dns">DNS</a><a href="#historical">Historical</a>
  <a href="#javascript">JavaScript</a><a href="#sensitive">Sensitive</a>
  <a href="#takeover">Takeover</a><a href="#sources">Sources</a><a href="#tasks">Phases</a><a href="#errors">Errors</a>
</nav>
<main>
{_intelligence_section(bundle)}
{_risk_section(risk)}
{_subdomains_section(bundle)}
{_http_section(bundle)}
{_tls_section(bundle)}
{_dns_section(bundle)}
{_historical_section(bundle)}
{_javascript_section(bundle)}
{_sensitive_section(bundle)}
{_takeover_section(bundle)}
{_sources_section(bundle)}
{_tasks_section(bundle)}
{_errors_section(bundle)}
</main>
<footer>
  {_esc(tool)} v{_esc(version)} · Passive and safe active reconnaissance for AUTHORIZED targets only.
  Findings are indicators, not confirmed vulnerabilities. No exploitation, authentication, file download or resource claiming was performed.
</footer>
<script>{JS}</script>
</body></html>"""


def build_text(bundle: dict) -> str:
    meta = bundle.get("meta", {})
    risk = bundle.get("risk", {})
    dns = bundle.get("dns") or {}
    http = bundle.get("http") or {}
    historical = bundle.get("historical") or {}
    sensitive = bundle.get("sensitive") or {}
    takeover = bundle.get("takeover") or {}
    filter_result = bundle.get("filter") or {}
    lines: list[str] = []
    add = lines.append
    add(f"{meta.get('tool', 'SubReconX')} v{meta.get('version', '')} - Reconnaissance report")
    add("=" * 72)
    add(f"Domain          : {meta.get('domain', '')}")
    add(f"Generated       : {meta.get('generated_at', '')}")
    add(f"Duration        : {meta.get('duration_human', '')}")
    add(f"Overall risk    : {risk.get('overall_severity', 'informational').upper()} "
        f"({risk.get('overall_score', 0)}/100)")
    add("")
    canonical = _extract_canonical_metrics(bundle)
    intel = bundle.get("intelligence") or {}
    add("ASSET SUMMARY")
    add("-" * 72)
    for key, value in canonical.items():
        if key in ("overall_severity", "overall_score"):
            continue
        add(f"  {key.replace('_', ' ').title():28} {value}")
    add("")
    if intel.get("interesting_assets"):
        add("PRIORITIZED BUG BOUNTY ASSETS")
        add("-" * 72)
        for item in intel.get("interesting_assets", [])[:30]:
            tags = ", ".join(item.get("tags") or [])
            add(
                f"  [{item.get('priority_level', 'info').upper():13}] {item.get('priority_score', 0):>3}  "
                f"{item.get('hostname')} ({item.get('classification')}) [{tags}]"
            )
            for ind in (item.get("indicators") or [])[:3]:
                add(f"      - {ind.get('type')}: {ind.get('explanation')}")
        add("")
    add("RISK FINDINGS")
    add("-" * 72)
    findings = risk.get("findings", [])
    if not findings:
        add("  None.")
    for finding in findings:
        add(f"  [{finding.get('severity', 'info').upper():13}] {finding.get('score'):>3}  {finding.get('title')}")
        add(f"      {finding.get('rationale')}")
    add("")
    add("LIVE HOSTS")
    add("-" * 72)
    for record in http.get("results", []):
        status = record.get("status") if record.get("status") is not None else "ERR"
        add(f"  {record.get('scheme', '').upper():5} {status!s:4} {record.get('hostname', '')} "
            f"{record.get('title') or ''}")
    if not http.get("results"):
        add("  None.")
    add("")
    tls = bundle.get("tls") or {}
    add("TLS CERTIFICATES")
    add("-" * 72)
    for item in tls.get("results", []):
        state = "VERIFIED" if item.get("verified") else ("UNVERIFIED" if item.get("connected") else "ERR")
        cn = (item.get("subject") or {}).get("commonName", "-")
        add(f"  {item.get('hostname', ''):32} {state:10} {(item.get('protocol') or '-'):8} CN={cn} "
            f"notAfter={item.get('not_after') or '-'}")
    if not tls.get("results"):
        add("  None.")
    add("")
    add("HISTORICAL URLS")
    add("-" * 72)
    add(f"  total={historical.get('total', 0)} in_scope={historical.get('in_scope', 0)} "
        f"out_of_scope={historical.get('out_of_scope', 0)}")
    for name, count in sorted(historical.get("source_stats", {}).items()):
        add(f"    {name:20} {count}")
    add("  file categories:")
    for name, count in sorted(filter_result.get("stats", {}).items()):
        add(f"    {name:20} {count}")
    add("")
    js = bundle.get("javascript") or {}
    add("JAVASCRIPT INVENTORY")
    add("-" * 72)
    add(f"  assets={len(js.get('assets', []))} endpoints={len(js.get('endpoints', []))}")
    for item in js.get("assets", [])[:50]:
        add(f"    {item.get('normalized') or item.get('url')}")
    add("")
    add("SENSITIVE INDICATORS")
    add("-" * 72)
    add(f"  total={sensitive.get('total_indicators', 0)} "
        f"suspicious_paths={sensitive.get('suspicious_paths', 0)} "
        f"sensitive_parameters={sensitive.get('sensitive_parameters', 0)}")
    for name, count in sorted((sensitive.get("categories") or {}).items()):
        add(f"    {name:28} {count}")
    add("")
    add("TAKEOVER CANDIDATES")
    add("-" * 72)
    for candidate in takeover.get("candidates", []):
        add(f"  {candidate.get('hostname')} -> {candidate.get('cname_target')} "
            f"[{candidate.get('classification')}, {candidate.get('confidence')}/100]")
    if not takeover.get("candidates"):
        add("  None.")
    add("")
    add("SOURCES")
    add("-" * 72)
    for source in bundle.get("sources", []):
        add(f"  {source.get('source'):20} records={source.get('count')} "
            f"cached={'yes' if source.get('cached') else 'no'} {source.get('error') or ''}")
    add("")
    errors = bundle.get("errors", [])
    add(f"ERRORS ({len(errors)})")
    add("-" * 72)
    for item in errors[:100]:
        add(f"  [{item.get('phase')}] {item.get('message')}")
    if not errors:
        add("  None.")
    add("")
    add("Indicators only. Authorized manual verification required. No exploitation or resource claiming performed.")
    return "\n".join(lines) + "\n"


def generate_reports(
    bundle: dict,
    output_dir: Path,
    *,
    preserve_top_level: bool = False,
) -> dict[str, Path]:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    reports_dir = output_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    payload = _prepare_json(bundle)
    payload.setdefault("meta", {})
    payload["meta"]["generated_at"] = payload["meta"].get("generated_at") or time.strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    payload["meta"]["canonical_metrics"] = _extract_canonical_metrics(payload)
    json_text = json.dumps(payload, indent=2, default=str)
    html_text = build_html(payload)
    txt_text = build_text(payload)

    rep_json = reports_dir / "report.json"
    rep_html = reports_dir / "report.html"
    rep_txt = reports_dir / "report.txt"
    rep_json.write_text(json_text, encoding="utf-8")
    rep_html.write_text(html_text, encoding="utf-8")
    rep_txt.write_text(txt_text, encoding="utf-8")

    json_path = output_dir / "report.json"
    html_path = output_dir / "report.html"
    txt_path = output_dir / "report.txt"
    if not preserve_top_level:
        json_path.write_text(json_text, encoding="utf-8")
        html_path.write_text(html_text, encoding="utf-8")
        txt_path.write_text(txt_text, encoding="utf-8")
        return {"json": json_path, "html": html_path, "txt": txt_path}
    return {"json": rep_json, "html": rep_html, "txt": rep_txt}
