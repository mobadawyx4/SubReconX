"""TLS certificate inventory engine."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from core.event_logger import EventLogger
from core.scope_manager import ScopeManager
from protocols.tls_protocol import TLSResult, inspect
from utils.concurrency import bounded_map
from utils.validators import normalize_hostname


@dataclass
class TLSRunResult:
    results: list[TLSResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "count": len(self.results),
            "results": [item.as_dict() for item in self.results],
            "errors": self.errors,
        }


class TLSEngine:
    def __init__(
        self,
        scope: ScopeManager,
        *,
        timeout: float = 10.0,
        concurrency: int = 20,
        logger: EventLogger | None = None,
    ):
        self.scope = scope
        self.timeout = timeout
        self.concurrency = max(1, concurrency)
        self.logger = logger

    async def run(self, hostnames: list[str]) -> TLSRunResult:
        run = TLSRunResult()
        unique: list[str] = []
        seen: set[str] = set()
        for host in hostnames:
            host = normalize_hostname(host)
            if host and host not in seen and self.scope.is_in_scope(host):
                seen.add(host)
                unique.append(host)

        async def _one(host: str) -> TLSResult:
            return await inspect(host, self.scope, port=443, timeout=self.timeout)

        outcomes = await bounded_map(_one, unique, self.concurrency)
        for host, outcome in zip(unique, outcomes):
            if isinstance(outcome, Exception):
                failed = TLSResult(hostname=host, error=str(outcome))
                run.results.append(failed)
                run.errors.append(f"{host}: {outcome}")
            else:
                run.results.append(outcome)
                if outcome.error:
                    run.errors.append(f"{host}: {outcome.error}")
        run.results.sort(key=lambda r: r.hostname)
        connected = sum(1 for r in run.results if r.connected)
        if self.logger:
            self.logger.success(f"TLS: inspected {connected}/{len(unique)} hosts")
        return run


def write_tls_outputs(run: TLSRunResult, output_dir: Path) -> None:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "tls_results.json").write_text(
        json.dumps(run.as_dict(), indent=2, default=str), encoding="utf-8"
    )
    lines: list[str] = []
    for item in run.results:
        status = "VERIFIED" if item.verified else ("UNVERIFIED" if item.connected else "ERR")
        cn = item.subject.get("commonName", "-") if item.subject else "-"
        issuer_cn = item.issuer.get("commonName", item.issuer.get("organizationName", "-")) if item.issuer else "-"
        expiry = item.not_after or "-"
        lines.append(
            f"{item.hostname:40} {status:10} {(item.protocol or '-'):8} "
            f"CN={cn} Issuer={issuer_cn} Expires={expiry}"
        )
    (output_dir / "tls_results.txt").write_text(
        "\n".join(lines) + ("\n" if lines else ""), encoding="utf-8"
    )
