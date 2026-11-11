"""Shared passive-source result container."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SourceResult:
    source: str
    records: list[dict] = field(default_factory=list)
    error: str = ""
    cached: bool = False

    @property
    def ok(self) -> bool:
        return not self.error

    @property
    def count(self) -> int:
        return len(self.records)

    def as_dict(self) -> dict:
        return {
            "source": self.source,
            "count": self.count,
            "cached": self.cached,
            "error": self.error,
        }
