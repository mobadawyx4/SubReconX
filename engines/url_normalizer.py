"""URL normalization engine (thin, testable layer over utils.url_utils)."""

from __future__ import annotations

from dataclasses import dataclass, field

from utils.url_utils import normalize_url, split_url


@dataclass
class NormalizationResult:
    pairs: list[tuple[str, str]] = field(default_factory=list)
    duplicates: list[str] = field(default_factory=list)
    malformed: list[str] = field(default_factory=list)

    @property
    def normalized(self) -> list[str]:
        return [norm for _orig, norm in self.pairs]

    def as_dict(self) -> dict:
        return {
            "input": len(self.pairs) + len(self.duplicates) + len(self.malformed),
            "unique": len(self.pairs),
            "duplicates": len(self.duplicates),
            "malformed": len(self.malformed),
        }


def normalize_urls(urls: list[str]) -> NormalizationResult:
    result = NormalizationResult()
    seen: set[str] = set()
    for url in urls:
        normalized = normalize_url(url)
        if normalized is None:
            result.malformed.append(url)
            continue
        if normalized in seen:
            result.duplicates.append(normalized)
            continue
        seen.add(normalized)
        result.pairs.append((url, normalized))
    return result


__all__ = ["NormalizationResult", "normalize_url", "normalize_urls", "split_url"]
