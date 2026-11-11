"""Authorized-scope enforcement.

Every network operation performed by SubReconX first passes through this
manager.  The rules are intentionally strict:

* only the root domain and its subdomains are in scope;
* optional extra hosts from a scope file are honoured;
* resolved IPs must be public (no loopback/private/link-local/reserved);
* redirect destinations are re-validated at every hop;
* non-standard ports are rejected unless explicitly permitted by the caller.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
import json
from pathlib import Path

from utils.network import assess_ip, safe_getaddrinfo
from utils.url_utils import split_url
from utils.validators import (
    is_within_domain,
    normalize_hostname,
    strip_wildcard,
)

DEFAULT_WEB_PORTS = {80, 443, 8080, 8443}


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str = ""
    host: str = ""

    def __bool__(self) -> bool:
        return self.allowed


def _clean_host_list(items: list[str]) -> list[str]:
    out: list[str] = []
    for entry in items:
        host = normalize_hostname(strip_wildcard(entry))
        if host and host not in out:
            out.append(host)
    return out


@dataclass
class ScopeManager:
    root: str
    extra_hosts: list[str] = field(default_factory=list)
    allow_private: bool = False
    allowed_ports: set[int] = field(default_factory=lambda: set(DEFAULT_WEB_PORTS))
    root_domains: list[str] = field(default_factory=list)
    in_scope_hosts: list[str] = field(default_factory=list)
    wildcard_domains: list[str] = field(default_factory=list)
    out_of_scope_hosts: list[str] = field(default_factory=list)
    out_of_scope_domains: list[str] = field(default_factory=list)
    out_of_scope_patterns: list[str] = field(default_factory=list)
    strict_scope: bool = False
    allow_active_probing: bool = True
    rate_limit_rps: float = 0.0
    program_name: str = ""
    restrictions: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.root = normalize_hostname(self.root)
        self.extra_hosts = _clean_host_list(self.extra_hosts)
        self.root_domains = _clean_host_list([self.root] + list(self.root_domains))
        self.in_scope_hosts = _clean_host_list(self.in_scope_hosts)
        self.wildcard_domains = _clean_host_list(self.wildcard_domains)
        self.out_of_scope_hosts = _clean_host_list(self.out_of_scope_hosts)
        self.out_of_scope_domains = _clean_host_list(self.out_of_scope_domains)
        self.out_of_scope_patterns = [
            p.strip().lower() for p in self.out_of_scope_patterns if p and p.strip()
        ]
        self.rate_limit_rps = max(0.0, float(self.rate_limit_rps or 0.0))

    # ------------------------------------------------------------------
    @classmethod
    def from_scope_file(
        cls,
        root: str,
        path: Path | None,
        *,
        strict_scope: bool = False,
        rate_limit_rps: float = 0.0,
        allow_active_probing: bool = True,
    ) -> "ScopeManager":
        if path is None:
            return cls(
                root=root,
                strict_scope=strict_scope,
                rate_limit_rps=rate_limit_rps,
                allow_active_probing=allow_active_probing,
            )
        try:
            content = Path(path).read_text(encoding="utf-8")
        except OSError:
            return cls(
                root=root,
                strict_scope=strict_scope,
                rate_limit_rps=rate_limit_rps,
                allow_active_probing=allow_active_probing,
            )

        stripped = content.strip()
        if stripped.startswith("{"):
            try:
                data = json.loads(stripped)
                if isinstance(data, dict):
                    return cls._from_json_dict(
                        root,
                        data,
                        strict_scope=strict_scope,
                        rate_limit_rps=rate_limit_rps,
                        allow_active_probing=allow_active_probing,
                    )
            except json.JSONDecodeError:
                pass

        extra: list[str] = []
        in_scope_hosts: list[str] = []
        wildcard_domains: list[str] = []
        out_hosts: list[str] = []
        out_domains: list[str] = []
        out_patterns: list[str] = []

        for raw in content.splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            lower = line.lower()
            is_exclusion = False
            if lower.startswith(("exclude:", "out_of_scope:", "out-of-scope:")):
                is_exclusion = True
                line = line.split(":", 1)[1].strip()
            elif line.startswith(("-", "!")):
                is_exclusion = True
                line = line[1:].strip()
            elif lower.startswith(("host:", "exact:")):
                target = line.split(":", 1)[1].strip()
                if "://" in target:
                    target = split_url(target).host
                host = normalize_hostname(strip_wildcard(target))
                if host:
                    in_scope_hosts.append(host)
                continue

            if "://" in line:
                line = split_url(line).host

            if is_exclusion:
                if line.startswith("*."):
                    host = normalize_hostname(strip_wildcard(line))
                    if host:
                        out_domains.append(host)
                elif "*" in line:
                    out_patterns.append(line.lower())
                else:
                    host = normalize_hostname(line)
                    if host:
                        out_hosts.append(host)
                        out_domains.append(host)
                continue

            if line.startswith("*."):
                host = normalize_hostname(strip_wildcard(line))
                if host:
                    wildcard_domains.append(host)
                    extra.append(host)
            else:
                host = normalize_hostname(strip_wildcard(line))
                if host:
                    in_scope_hosts.append(host)
                    extra.append(host)

        return cls(
            root=root,
            extra_hosts=extra,
            in_scope_hosts=in_scope_hosts,
            wildcard_domains=wildcard_domains,
            out_of_scope_hosts=out_hosts,
            out_of_scope_domains=out_domains,
            out_of_scope_patterns=out_patterns,
            strict_scope=strict_scope,
            rate_limit_rps=rate_limit_rps,
            allow_active_probing=allow_active_probing,
        )

    @classmethod
    def _from_json_dict(
        cls,
        root: str,
        data: dict,
        *,
        strict_scope: bool = False,
        rate_limit_rps: float = 0.0,
        allow_active_probing: bool = True,
    ) -> "ScopeManager":
        root_domains = list(data.get("root_domains") or [])
        in_scope_hosts = list(data.get("in_scope_hosts") or [])
        wildcard_domains = list(data.get("wildcard_domains") or [])
        extra_hosts = list(data.get("extra_hosts") or [])
        out_hosts = list(data.get("out_of_scope_hosts") or [])
        out_domains = list(data.get("out_of_scope_domains") or [])
        out_patterns = list(data.get("out_of_scope_patterns") or [])

        for item in data.get("in_scope") or []:
            entry = str(item).strip()
            if "://" in entry:
                entry = split_url(entry).host
            if entry.startswith("*."):
                wildcard_domains.append(strip_wildcard(entry))
            else:
                in_scope_hosts.append(entry)

        for item in data.get("out_of_scope") or []:
            entry = str(item).strip()
            if "://" in entry:
                entry = split_url(entry).host
            if entry.startswith("*."):
                out_domains.append(strip_wildcard(entry))
            elif "*" in entry:
                out_patterns.append(entry.lower())
            else:
                out_hosts.append(entry)
                out_domains.append(entry)

        file_strict = bool(data.get("strict_scope", False))
        if "wildcard_subdomains" in data and not bool(data.get("wildcard_subdomains")):
            file_strict = True
        file_active = bool(data.get("allow_active_probing", True))
        file_rps = float(data.get("rate_limit_rps") or 0.0)

        return cls(
            root=root,
            extra_hosts=extra_hosts,
            root_domains=root_domains,
            in_scope_hosts=in_scope_hosts,
            wildcard_domains=wildcard_domains,
            out_of_scope_hosts=out_hosts,
            out_of_scope_domains=out_domains,
            out_of_scope_patterns=out_patterns,
            strict_scope=strict_scope or file_strict,
            allow_active_probing=allow_active_probing and file_active,
            rate_limit_rps=rate_limit_rps if rate_limit_rps > 0 else file_rps,
            program_name=str(data.get("program_name") or ""),
            restrictions=[str(r) for r in (data.get("restrictions") or [])],
        )

    # ------------------------------------------------------------------
    def is_root(self, host: str) -> bool:
        return normalize_hostname(host) == self.root

    def is_within_root_boundary(self, host: str) -> bool:
        """Check whether *host* belongs to the target root domain boundary."""
        host = normalize_hostname(host)
        if not host:
            return False
        for root_dom in self.root_domains:
            if is_within_domain(host, root_dom):
                return True
        return False

    def is_excluded(self, host: str) -> bool:
        """Check whether *host* matches any explicit out-of-scope exclusion rule."""
        host = normalize_hostname(host)
        if not host:
            return False
        if host in self.out_of_scope_hosts:
            return True
        for dom in self.out_of_scope_domains:
            if is_within_domain(host, dom):
                return True
        for pattern in self.out_of_scope_patterns:
            if fnmatchcase(host, pattern):
                return True
        return False

    def is_in_scope(self, host: str) -> bool:
        host = normalize_hostname(host)
        if not host:
            return False
        if self.is_excluded(host):
            return False
        if host in self.in_scope_hosts:
            return True
        for wildcard_dom in self.wildcard_domains:
            if is_within_domain(host, wildcard_dom):
                return True
        if self.strict_scope:
            if host in self.root_domains or host in self.extra_hosts:
                return True
            return False
        if is_within_domain(host, self.root):
            return True
        for root_dom in self.root_domains:
            if is_within_domain(host, root_dom):
                return True
        for extra in self.extra_hosts:
            if is_within_domain(host, extra):
                return True
        return False

    def check_host(self, host: str) -> ScopeDecision:
        raw = (host or "").strip()
        if "*" in raw:
            return ScopeDecision(False, "wildcard host is not connectable", raw)
        host = normalize_hostname(raw)
        if not host:
            return ScopeDecision(False, "empty host", host)
        if self.is_excluded(host):
            return ScopeDecision(False, "host is explicitly excluded from scope", host)
        if not self.is_in_scope(host):
            return ScopeDecision(False, "host is outside the authorized scope", host)
        return ScopeDecision(True, "", host)

    def check_active_probe(self, host: str) -> ScopeDecision:
        if not self.allow_active_probing:
            return ScopeDecision(
                False,
                "active probing is disabled by program scope restrictions",
                normalize_hostname(host),
            )
        return self.check_host(host)

    def as_dict(self) -> dict:
        return {
            "root": self.root,
            "root_domains": list(self.root_domains),
            "in_scope_hosts": list(self.in_scope_hosts),
            "wildcard_domains": list(self.wildcard_domains),
            "extra_hosts": list(self.extra_hosts),
            "out_of_scope_hosts": list(self.out_of_scope_hosts),
            "out_of_scope_domains": list(self.out_of_scope_domains),
            "out_of_scope_patterns": list(self.out_of_scope_patterns),
            "strict_scope": self.strict_scope,
            "allow_active_probing": self.allow_active_probing,
            "rate_limit_rps": self.rate_limit_rps,
            "program_name": self.program_name,
            "restrictions": list(self.restrictions),
        }

    def check_url(self, url: str, *, allow_any_port: bool = False) -> ScopeDecision:
        parsed = split_url(url)
        if not parsed.valid:
            return ScopeDecision(False, f"malformed URL: {parsed.malformed_reason}", parsed.host)
        host_decision = self.check_host(parsed.host)
        if not host_decision:
            return ScopeDecision(
                False,
                host_decision.reason or "host is outside the authorized scope",
                parsed.host,
            )
        if not allow_any_port and parsed.port is not None:
            if parsed.port not in self.allowed_ports:
                return ScopeDecision(False, f"port {parsed.port} is not permitted", parsed.host)
        return ScopeDecision(True, "", parsed.host)

    # ------------------------------------------------------------------
    def resolve(self, host: str, port: int = 443, timeout: float = 5.0) -> tuple[list[str], str]:
        """Resolve *host* and return public IPs only.

        The caller must connect to one of the returned IPs directly; this is
        what prevents DNS-rebinding SSRF between validation and connection.
        """
        if not self.check_host(host):
            return [], "out-of-scope host"
        ips = safe_getaddrinfo(host, port, timeout=timeout)
        if not ips:
            return [], "resolution failed"
        safe: list[str] = []
        for ip in ips:
            assessment = assess_ip(ip)
            if assessment.safe or self.allow_private:
                safe.append(ip)
        if not safe:
            return [], "all resolved addresses are private/reserved"
        return safe, ""

    def verify_connect_ip(self, host: str, ip: str) -> ScopeDecision:
        if not self.check_host(host):
            return ScopeDecision(False, "host out of scope", host)
        assessment = assess_ip(ip)
        if not assessment.safe and not self.allow_private:
            return ScopeDecision(False, f"unsafe target address: {assessment.reason}", host)
        return ScopeDecision(True, "", host)

    def is_out_of_scope_reference(self, url: str) -> bool:
        parsed = split_url(url)
        return not parsed.valid or not self.is_in_scope(parsed.host)
