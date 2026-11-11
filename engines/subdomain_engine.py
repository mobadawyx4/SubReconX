"""Passive subdomain enumeration engine."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from core.event_logger import EventLogger
from core.scope_manager import ScopeManager
from engines.dns_engine import DNSEngine
from sources.base import SourceResult
from sources.source_manager import SourceManager
from utils.validators import (
    is_valid_hostname,
    is_within_domain,
    normalize_hostname,
)


@dataclass
class SubdomainResult:
    root: str
    hosts: list[dict] = field(default_factory=list)
    all_hosts: list[dict] = field(default_factory=list)
    out_of_scope_hosts: list[dict] = field(default_factory=list)
    raw_records: list[dict] = field(default_factory=list)
    malformed: list[str] = field(default_factory=list)
    sources: list[SourceResult] = field(default_factory=list)
    bruteforce_resolved: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def hostnames(self) -> list[str]:
        return [item["hostname"] for item in self.hosts]

    @property
    def all_hostnames(self) -> list[str]:
        if self.all_hosts:
            return [item["hostname"] for item in self.all_hosts]
        return [item["hostname"] for item in self.hosts]

    def as_dict(self) -> dict:
        return {
            "root": self.root,
            "count": len(self.hosts),
            "total_discovered": len(self.all_hosts) if self.all_hosts else len(self.hosts),
            "in_scope_count": len(self.hosts),
            "out_of_scope_count": len(self.out_of_scope_hosts),
            "malformed_count": len(self.malformed),
            "hosts": self.hosts,
            "all_hosts": self.all_hosts if self.all_hosts else self.hosts,
            "out_of_scope_hosts": self.out_of_scope_hosts,
            "malformed": self.malformed[:500],
            "sources": [s.as_dict() for s in self.sources],
            "bruteforce_resolved": self.bruteforce_resolved,
            "errors": self.errors,
        }


class SubdomainEngine:
    def __init__(
        self,
        scope: ScopeManager,
        source_manager: SourceManager,
        *,
        dns_engine: DNSEngine | None = None,
        logger: EventLogger | None = None,
    ):
        self.scope = scope
        self.sources = source_manager
        self.dns = dns_engine
        self.logger = logger

    async def run(self, *, brute_words: list[str] | None = None) -> SubdomainResult:
        result = SubdomainResult(root=self.scope.root)
        root_in_scope = self.scope.is_in_scope(self.scope.root)
        root_entry = {
            "hostname": self.scope.root,
            "sources": ["root"],
            "source": "root",
            "in_scope": root_in_scope,
        }
        result.raw_records.append(dict(root_entry))
        result.all_hosts.append(dict(root_entry))
        if root_in_scope:
            result.hosts.append(dict(root_entry))
        else:
            result.out_of_scope_hosts.append(dict(root_entry))

        records, source_results = await self.sources.collect_subdomains()
        result.sources = source_results
        for source in source_results:
            if source.error and self.logger:
                self.logger.warn(f"source {source.source}: {source.error}")
            elif self.logger:
                self.logger.debug(f"source {source.source}: {source.count} records")

        by_host: dict[str, dict] = {self.scope.root: result.all_hosts[0]}
        for record in records:
            result.raw_records.append(dict(record))
            raw_name = str(record.get("hostname", "") or "")
            host = normalize_hostname(raw_name)
            if not host:
                if raw_name.strip() and len(result.malformed) < 500:
                    result.malformed.append(raw_name.strip()[:255])
                continue
            if not is_valid_hostname(host):
                if len(result.malformed) < 500:
                    result.malformed.append(raw_name.strip()[:255])
                continue
            if not (
                self.scope.is_within_root_boundary(host)
                or self.scope.is_in_scope(host)
            ):
                if len(result.malformed) < 500:
                    result.malformed.append(f"outside-root-boundary:{host}")
                continue

            rec_sources = list(record.get("sources") or [])
            if not rec_sources:
                src = record.get("source", "passive")
                rec_sources = [str(src)] if src else ["passive"]

            if host in by_host:
                existing_sources = by_host[host].setdefault("sources", [])
                for s in rec_sources:
                    if s and s not in existing_sources:
                        existing_sources.append(s)
                continue

            in_scope = self.scope.is_in_scope(host)
            entry = dict(record)
            entry["hostname"] = host
            entry["sources"] = rec_sources
            entry["source"] = rec_sources[0]
            entry["in_scope"] = in_scope
            by_host[host] = entry
            result.all_hosts.append(entry)
            if in_scope:
                result.hosts.append(entry)
            else:
                result.out_of_scope_hosts.append(entry)

        if brute_words and self.dns is not None and self.scope.allow_active_probing:
            seen_in_scope = {h["hostname"] for h in result.hosts}
            result.bruteforce_resolved = await self._bruteforce(brute_words, seen_in_scope)
            for host in result.bruteforce_resolved:
                entry = {
                    "hostname": host,
                    "sources": ["wordlist"],
                    "source": "wordlist",
                    "in_scope": True,
                }
                result.raw_records.append(dict(entry))
                if host not in by_host:
                    by_host[host] = entry
                    result.all_hosts.append(entry)
                    result.hosts.append(entry)

        result.hosts.sort(key=lambda item: item["hostname"])
        result.all_hosts.sort(key=lambda item: item["hostname"])
        result.out_of_scope_hosts.sort(key=lambda item: item["hostname"])
        if self.logger:
            self.logger.success(
                f"discovered {len(result.hosts)} in-scope hostnames "
                f"({len(result.all_hosts)} total within boundary)"
            )
        return result

    async def _bruteforce(self, words: list[str], seen: set[str]) -> list[str]:
        if self.dns is None:
            return []
        candidates = await self.dns.wordlist_candidates(self.scope.root, words)
        candidates = [c for c in candidates if c not in seen and self.scope.is_in_scope(c)]
        if self.logger:
            self.logger.info(f"wordlist: resolving {len(candidates)} in-scope candidates")
        resolved = await self.dns.resolve_many(candidates)
        out: list[str] = []
        for item in resolved:
            if item.resolved:
                out.append(item.hostname)
        return sorted(out)


def write_subdomain_outputs(result: SubdomainResult, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "subdomains.txt").write_text(
        "\n".join(result.hostnames) + ("\n" if result.hostnames else ""),
        encoding="utf-8",
    )
    (output_dir / "subdomains.json").write_text(
        json.dumps(result.as_dict(), indent=2, default=str), encoding="utf-8"
    )
