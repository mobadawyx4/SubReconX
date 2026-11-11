"""Sensitive path and parameter-NAME intelligence.

Only URL paths and query parameter names are analysed.  Values are never
extracted and are redacted in every output.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from config import INTELLIGENCE_DIR
from utils.redaction import redact_url
from utils.url_utils import extract_param_names, get_extension, get_path, normalize_url, split_url

PATTERNS_FILE = INTELLIGENCE_DIR / "sensitive_patterns.json"
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
JS_EXTENSIONS = {"js", "mjs", "cjs"}


@dataclass
class Indicator:
    category: str
    kind: str  # "path" or "parameter"
    value: str
    severity: str
    url: str
    redacted_url: str

    def as_dict(self) -> dict:
        return {
            "category": self.category,
            "kind": self.kind,
            "value": self.value,
            "severity": self.severity,
            "url": self.redacted_url,
        }


@dataclass
class SensitiveResult:
    indicators: list[Indicator] = field(default_factory=list)
    suspicious_paths: list[str] = field(default_factory=list)
    sensitive_parameters: list[dict] = field(default_factory=list)
    interesting_urls: list[str] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    authentication_paths: list[str] = field(default_factory=list)
    admin_paths: list[str] = field(default_factory=list)
    config_indicators: list[str] = field(default_factory=list)
    backup_indicators: list[str] = field(default_factory=list)
    database_indicators: list[str] = field(default_factory=list)
    debug_paths: list[str] = field(default_factory=list)
    interesting_parameters: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def by_category(self) -> dict[str, list[Indicator]]:
        out: dict[str, list[Indicator]] = {}
        for indicator in self.indicators:
            out.setdefault(indicator.category, []).append(indicator)
        return out

    def as_dict(self) -> dict:
        return {
            "total_indicators": len(self.indicators),
            "categories": {
                name: len(items) for name, items in sorted(self.by_category().items())
            },
            "suspicious_paths": len(self.suspicious_paths),
            "sensitive_parameters": len(self.sensitive_parameters),
            "interesting_urls": len(self.interesting_urls),
            "classified_counts": {
                "js_files": len(self.js_files),
                "api_endpoints": len(self.api_endpoints),
                "authentication_paths": len(self.authentication_paths),
                "admin_paths": len(self.admin_paths),
                "config_indicators": len(self.config_indicators),
                "backup_indicators": len(self.backup_indicators),
                "database_indicators": len(self.database_indicators),
                "debug_paths": len(self.debug_paths),
                "interesting_parameters": len(self.interesting_parameters),
                "suspicious_paths": len(self.suspicious_paths),
            },
            "indicators": [indicator.as_dict() for indicator in self.indicators],
        }


def _param_regex(pattern: str) -> re.Pattern:
    escaped = re.escape(pattern.lower())
    return re.compile(rf"(?:^|[^a-z0-9])({escaped})(?:$|[^a-z0-9])")


class SensitiveDetectionEngine:
    def __init__(self, patterns: dict | None = None):
        if patterns is None:
            with open(PATTERNS_FILE, "r", encoding="utf-8") as handle:
                patterns = json.load(handle)
        self.patterns = patterns
        self.categories: dict[str, dict] = patterns.get("categories", {})
        self.global_sensitive = {
            name.lower() for name in patterns.get("sensitive_parameter_names", [])
        }
        self._path_regexes: dict[str, list[re.Pattern]] = {}
        self._param_regexes: dict[str, list[re.Pattern]] = {}
        for name, meta in self.categories.items():
            try:
                self._path_regexes[name] = [
                    re.compile(p, re.IGNORECASE)
                    for p in meta.get("path_patterns", [])
                ]
            except re.error:
                self._path_regexes[name] = []
            self._param_regexes[name] = [
                _param_regex(p) for p in meta.get("parameter_patterns", [])
            ]

    def analyze_url(self, url: str) -> list[Indicator]:
        normalized = normalize_url(url)
        if normalized is None:
            return []
        parsed = split_url(normalized)
        path = get_path(normalized)
        indicators: list[Indicator] = []
        redacted = redact_url(normalized)
        seen: set[tuple[str, str, str]] = set()

        for category, regexes in self._path_regexes.items():
            severity = self.categories[category].get("severity", "informational")
            for regex in regexes:
                if regex.search(path):
                    key = (category, "path", regex.pattern)
                    if key not in seen:
                        seen.add(key)
                        indicators.append(
                            Indicator(
                                category=category,
                                kind="path",
                                value=regex.pattern,
                                severity=severity,
                                url=normalized,
                                redacted_url=redacted,
                            )
                        )
                    break

        param_names = extract_param_names(parsed.query)
        for name in param_names:
            lowered = name.lower()
            matched_categories: set[str] = set()
            for category, regexes in self._param_regexes.items():
                if any(regex.search(lowered) for regex in regexes):
                    matched_categories.add(category)
            if lowered in self.global_sensitive:
                matched_categories.add("authentication")
            for category in matched_categories:
                severity = self.categories.get(category, {}).get("severity", "medium")
                key = (category, "parameter", lowered)
                if key not in seen:
                    seen.add(key)
                    indicators.append(
                        Indicator(
                            category=category,
                            kind="parameter",
                            value=lowered,
                            severity=severity,
                            url=normalized,
                            redacted_url=redacted,
                        )
                    )
        return indicators

    def run(self, urls: list[str]) -> SensitiveResult:
        result = SensitiveResult()
        seen_urls: set[str] = set()
        bucket_seen: dict[int, set[str]] = {}

        def _append_unique(bucket: list[str], item: str) -> None:
            if not item:
                return
            bset = bucket_seen.setdefault(id(bucket), set())
            if item not in bset:
                bset.add(item)
                bucket.append(item)

        for url in urls:
            normalized = normalize_url(url)
            if normalized is None or normalized in seen_urls:
                continue
            seen_urls.add(normalized)
            redacted = redact_url(normalized)
            ext = get_extension(normalized)
            if ext in JS_EXTENSIONS:
                _append_unique(result.js_files, redacted)

            parsed_norm = split_url(normalized)
            host_lower = (parsed_norm.host or "").lower()
            is_api_host = (
                host_lower.startswith(("api.", "api-"))
                or ".api." in host_lower
                or "-api." in host_lower
            )
            if is_api_host and get_path(normalized) not in ("", "/"):
                _append_unique(result.api_endpoints, redacted)

            indicators = self.analyze_url(normalized)
            if not indicators:
                continue
            result.indicators.extend(indicators)

            categories_hit = {item.category for item in indicators}
            path_categories = {item.category for item in indicators if item.kind == "path"}

            if "api" in categories_hit or is_api_host:
                _append_unique(result.api_endpoints, redacted)
            if "authentication" in path_categories or (
                "authentication" in categories_hit
                and any(
                    seg in get_path(normalized).lower().split("/")
                    for seg in ("auth", "login", "signin", "sso", "oauth", "oauth2", "token", "session", "saml")
                )
            ):
                _append_unique(result.authentication_paths, redacted)
            if "administrative" in categories_hit:
                _append_unique(result.admin_paths, redacted)
            if "environment_configuration" in categories_hit or "git_exposure" in categories_hit:
                _append_unique(result.config_indicators, redacted)
            if "backups" in categories_hit:
                _append_unique(result.backup_indicators, redacted)
            if "databases" in categories_hit:
                _append_unique(result.database_indicators, redacted)
            if "debug" in categories_hit or "logging" in categories_hit or (
                "internal_resources" in path_categories
                and any(
                    seg in get_path(normalized).lower().split("/")
                    for seg in ("debug", "test", "testing", "staging", "dev")
                )
            ):
                _append_unique(result.debug_paths, redacted)

            non_info_path = [
                item for item in indicators if item.kind == "path" and item.category != "api"
            ]
            if non_info_path:
                _append_unique(result.suspicious_paths, redacted)

            if any(item.kind == "parameter" for item in indicators):
                params = sorted({item.value for item in indicators if item.kind == "parameter"})
                result.sensitive_parameters.append(
                    {"url": redacted, "parameters": params}
                )
                _append_unique(result.interesting_parameters, redacted)
            _append_unique(result.interesting_urls, redacted)
        return result

    def write_outputs(self, result: SensitiveResult, output_dir: Path) -> None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        def _write_lines(filename: str, lines: list[str]) -> None:
            (output_dir / filename).write_text(
                "\n".join(lines) + ("\n" if lines else ""),
                encoding="utf-8",
            )

        _write_lines("suspicious_paths.txt", result.suspicious_paths)
        _write_lines("api_endpoints.txt", result.api_endpoints)
        _write_lines("authentication_paths.txt", result.authentication_paths)
        _write_lines("admin_paths.txt", result.admin_paths)
        _write_lines("config_indicators.txt", result.config_indicators)
        _write_lines("backup_indicators.txt", result.backup_indicators)
        _write_lines("database_indicators.txt", result.database_indicators)
        _write_lines("debug_paths.txt", result.debug_paths)
        _write_lines("interesting_parameters.txt", result.interesting_parameters)

        js_target = output_dir / "js_files.txt"
        if result.js_files or not js_target.exists():
            existing_js: list[str] = []
            if js_target.exists():
                existing_js = [
                    line.strip()
                    for line in js_target.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
            merged_js = list(existing_js)
            for item in result.js_files:
                if item not in merged_js:
                    merged_js.append(item)
            _write_lines("js_files.txt", merged_js)

        param_lines = [
            f"{item['url']}  [{', '.join(item['parameters'])}]"
            for item in result.sensitive_parameters
        ]
        _write_lines("sensitive_parameters.txt", param_lines)
        _write_lines("interesting_urls.txt", result.interesting_urls)
        (output_dir / "sensitive_indicators.json").write_text(
            json.dumps(result.as_dict(), indent=2, default=str), encoding="utf-8"
        )
