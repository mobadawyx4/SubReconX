"""Optional JSON configuration-file loader.

The CLI remains the primary interface; ``--config file.json`` merely supplies
defaults that explicit command-line flags can still override.  Only a small,
typed allow-list of keys is accepted so a malformed file cannot inject
unexpected phase switches or path types.
"""

from __future__ import annotations

import json
from pathlib import Path

PHASE_NAMES = (
    "passive",
    "dns",
    "live",
    "tls",
    "historical",
    "filter",
    "sensitive",
    "javascript",
    "takeover",
    "report",
)

_BOOL_KEYS = {
    "wordlist",
    "js_analysis",
    "resume",
    "no_cache",
    "quiet",
    "verbose",
    "strict_scope",
    "passive_only",
    "check_historical_urls",
}
_INT_KEYS = {"concurrency", "retries", "max_urls", "cdx_limit", "commoncrawl_crawls", "max_url_checks"}
_FLOAT_KEYS = {"timeout", "rate_limit"}
_PATH_KEYS = {"output", "db", "scope_file", "wordlist_path"}


class ConfigFileError(ValueError):
    pass


def load_scan_config(path: Path) -> dict:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigFileError(f"cannot read config file: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigFileError(f"invalid JSON in config file: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigFileError("config file must contain a JSON object")

    unknown = set(data) - set(_BOOL_KEYS) - set(_INT_KEYS) - set(_FLOAT_KEYS) - set(_PATH_KEYS) - {"phases"}
    if unknown:
        raise ConfigFileError(f"unknown config key(s): {', '.join(sorted(unknown))}")

    out: dict = {}
    phases = data.get("phases")
    if phases is not None:
        if not isinstance(phases, list) or not phases:
            raise ConfigFileError("'phases' must be a non-empty list")
        for name in phases:
            if name not in PHASE_NAMES:
                raise ConfigFileError(f"unknown phase in config: {name!r}")
        for name in PHASE_NAMES:
            out[name] = name in phases

    for key in _BOOL_KEYS:
        if key in data:
            if not isinstance(data[key], bool):
                raise ConfigFileError(f"'{key}' must be a boolean")
            out[key] = data[key]
    for key in _INT_KEYS:
        if key in data:
            value = data[key]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ConfigFileError(f"'{key}' must be a non-negative integer")
            out[key] = value
    for key in _FLOAT_KEYS:
        if key in data:
            value = data[key]
            if not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0:
                raise ConfigFileError(f"'{key}' must be a positive number")
            out[key] = float(value)
    for key in _PATH_KEYS:
        if key in data:
            if not isinstance(data[key], str) or not data[key].strip():
                raise ConfigFileError(f"'{key}' must be a non-empty string")
            out[key] = data[key]
    return out
