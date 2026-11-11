"""File-extension classification and grep-style URL filtering (pure Python)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from config import INTELLIGENCE_DIR
from utils.redaction import redact_url
from utils.url_utils import get_extension, get_path, normalize_url

CATEGORY_FILE = INTELLIGENCE_DIR / "extension_categories.json"

# Guaranteed output files required by the specification.
REQUIRED_OUTPUTS = [
    "js_files.txt",
    "xml_files.txt",
    "archives.txt",
    "json_files.txt",
    "txt_files.txt",
    "pdf_files.txt",
    "jspx.txt",
    "photofiles.txt",
    "php.txt",
    "env_files.txt",
    "log_files.txt",
    "backup_files.txt",
    "db_files.txt",
    "yaml_files.txt",
    "config_files.txt",
]


def load_categories(path: Path = CATEGORY_FILE) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return data.get("categories", {})


@dataclass
class FilterResult:
    categories: dict[str, list[str]] = field(default_factory=dict)
    stats: dict[str, int] = field(default_factory=dict)
    total_urls: int = 0
    uncategorized: int = 0

    def as_dict(self) -> dict:
        return {
            "total_urls": self.total_urls,
            "uncategorized": self.uncategorized,
            "stats": self.stats,
            "categories": {name: len(urls) for name, urls in self.categories.items()},
        }


class URLFilterEngine:
    def __init__(self, categories: dict | None = None):
        self.categories = categories or load_categories()
        self._ext_map: dict[str, list[str]] = {}
        self._prefix_map: dict[str, list[str]] = {}
        for name, meta in self.categories.items():
            for ext in meta.get("extensions", []):
                self._ext_map.setdefault(ext.lower().lstrip("."), []).append(name)
            for prefix in meta.get("basename_prefixes", []):
                self._prefix_map.setdefault(prefix.lower(), []).append(name)

    def classify(self, url: str) -> list[str]:
        basename = get_path(url).rsplit("/", 1)[-1].lower()
        matches: list[str] = []
        for prefix, names in self._prefix_map.items():
            if basename == prefix or basename.startswith(prefix + "."):
                for name in names:
                    if name not in matches:
                        matches.append(name)
        ext = get_extension(url)
        if ext and ext in self._ext_map:
            for name in self._ext_map[ext]:
                if name not in matches:
                    matches.append(name)
        return matches

    def run(self, urls: list[str]) -> FilterResult:
        result = FilterResult(total_urls=len(urls))
        seen_per_cat: dict[str, set[str]] = {}
        for url in urls:
            normalized = normalize_url(url)
            if normalized is None:
                continue
            matched = self.classify(normalized)
            if not matched:
                result.uncategorized += 1
                continue
            for category in matched:
                bucket = result.categories.setdefault(category, [])
                cat_seen = seen_per_cat.setdefault(category, set())
                if normalized not in cat_seen:
                    cat_seen.add(normalized)
                    bucket.append(normalized)
        for name in self.categories:
            bucket = result.categories.setdefault(name, [])
            result.stats[name] = len(bucket)
        return result

    def write_outputs(self, result: FilterResult, output_dir: Path) -> None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        written: set[str] = set()
        for name, meta in self.categories.items():
            filename = meta.get("output") or f"{name}.txt"
            urls = [redact_url(url) for url in result.categories.get(name, [])]
            (output_dir / filename).write_text(
                "\n".join(urls) + ("\n" if urls else ""), encoding="utf-8"
            )
            written.add(filename)
        for filename in REQUIRED_OUTPUTS:
            if filename not in written:
                (output_dir / filename).write_text("", encoding="utf-8")
        payload = {
            "total_urls": result.total_urls,
            "uncategorized": result.uncategorized,
            "stats": result.stats,
        }
        (output_dir / "filter_stats.json").write_text(
            json.dumps(payload, indent=2), encoding="utf-8"
        )
        lines = [f"{name:14} {count}" for name, count in sorted(result.stats.items())]
        lines.append(f"{'uncategorized':14} {result.uncategorized}")
        (output_dir / "filter_stats.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
