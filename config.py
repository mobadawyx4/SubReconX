"""Central configuration for SubReconX.

All tunables live here so that engines stay free of magic numbers.  The
project intentionally depends only on the Python standard library.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

VERSION = "1.0.0"
TOOL_NAME = "SubReconX"
USER_AGENT = (
    f"{TOOL_NAME}/{VERSION} (authorized reconnaissance; "
    "+https://github.com/subreconx/subreconx)"
)

PROJECT_ROOT = Path(__file__).resolve().parent

def _find_data_dir(name: str) -> Path:
    candidates = (
        PROJECT_ROOT / name,
        Path(sys.prefix) / name,
    )
    return next((path for path in candidates if path.is_dir()), candidates[0])

INTELLIGENCE_DIR = _find_data_dir("intelligence")
WORDLIST_DIR = _find_data_dir("wordlists")
if "site-packages" in PROJECT_ROOT.parts:
    if os.name == "nt":
        DATA_HOME = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "SubReconX"
    else:
        DATA_HOME = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "SubReconX"
else:
    DATA_HOME = PROJECT_ROOT

DEFAULT_RESULTS_DIR = DATA_HOME / "results"
DEFAULT_DB_PATH = DATA_HOME / "subreconx.db"
DEFAULT_WORDLIST = WORDLIST_DIR / "subdomains.txt"

# Network defaults -----------------------------------------------------------
DEFAULT_TIMEOUT = 10.0
DEFAULT_CONCURRENCY = 20
DEFAULT_DNS_CONCURRENCY = 40
DEFAULT_RETRIES = 2
DEFAULT_RETRY_BACKOFF = 0.6
MAX_REDIRECTS = 5
MAX_HTTP_BODY = 256 * 1024          # bytes read for title / fingerprinting
MAX_SOURCE_BYTES = 32 * 1024 * 1024  # hard cap for passive API payloads
MAX_HISTORICAL_URLS = 100_000
DEFAULT_CDX_LIMIT = 5_000

# DNS -----------------------------------------------------------------------
DNS_TIMEOUT = 5.0
DNS_TCP_FALLBACK = True
DNS_CACHE_TTL = 300.0
DNS_DEFAULT_SERVERS = ("1.1.1.1", "8.8.8.8")

# Cache ---------------------------------------------------------------------
SOURCE_CACHE_TTL = 24 * 60 * 60  # 24h

# Well known public suffix-ish guard.  We do not ship the full PSL, but we
# refuse to treat a bare public suffix as a scan target.
KNOWN_PUBLIC_SUFFIXES = {
    "com", "net", "org", "io", "dev", "app", "co", "ai", "me", "info",
    "biz", "edu", "gov", "mil", "int", "xyz", "site", "online", "tech",
    "cloud", "org.uk", "co.uk", "com.au", "co.jp", "com.br", "co.za",
}

PHASE_ORDER = (
    "passive",
    "dns",
    "live",
    "tls",
    "historical",
    "filter",
    "sensitive",
    "javascript",
    "takeover",
    "risk",
    "report",
)


@dataclass
class ScanConfig:
    """Runtime configuration produced by the CLI layer."""

    domain: str
    output_root: Path = DEFAULT_RESULTS_DIR
    db_path: Path = DEFAULT_DB_PATH
    timeout: float = DEFAULT_TIMEOUT
    concurrency: int = DEFAULT_CONCURRENCY
    retries: int = DEFAULT_RETRIES

    # Phase switches
    passive: bool = True
    dns: bool = True
    live: bool = True
    tls: bool = True
    historical: bool = True
    filter: bool = True
    sensitive: bool = True
    javascript: bool = True
    takeover: bool = True
    report: bool = True

    # Options
    scope_file: Path | None = None
    strict_scope: bool = False
    rate_limit_rps: float = 0.0
    allow_active_probing: bool = True
    check_historical_urls: bool = False
    max_url_checks: int = 50
    resume: bool = False
    use_cache: bool = True
    wordlist_bruteforce: bool = False
    wordlist_path: Path = DEFAULT_WORDLIST
    js_analysis: bool = False
    max_urls: int = MAX_HISTORICAL_URLS
    cdx_limit: int = DEFAULT_CDX_LIMIT
    commoncrawl_crawls: int = 1
    allowed_extra_hosts: list[str] = field(default_factory=list)
    assume_authorized: bool = False
    quiet: bool = False

    def __post_init__(self) -> None:
        self.output_root = Path(self.output_root).expanduser()
        self.db_path = Path(self.db_path).expanduser()

    @property
    def output_dir(self) -> Path:
        return self.output_root / self.domain

    @property
    def raw_dir(self) -> Path:
        return self.output_dir / "raw"

    @property
    def organized_dir(self) -> Path:
        return self.output_dir / "organized"

    @property
    def intelligence_out_dir(self) -> Path:
        return self.output_dir / "intelligence"

    @property
    def reports_dir(self) -> Path:
        return self.output_dir / "reports"

    def enabled_phases(self) -> list[str]:
        return [p for p in PHASE_ORDER if getattr(self, p, False)]

    def is_phase_enabled(self, phase: str) -> bool:
        return bool(getattr(self, phase, False))


def env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def ensure_directories(config: ScanConfig) -> None:
    config.output_root.mkdir(parents=True, exist_ok=True)
    config.output_dir.mkdir(parents=True, exist_ok=True)
    config.raw_dir.mkdir(parents=True, exist_ok=True)
    config.organized_dir.mkdir(parents=True, exist_ok=True)
    config.intelligence_out_dir.mkdir(parents=True, exist_ok=True)
    config.reports_dir.mkdir(parents=True, exist_ok=True)
    config.db_path.parent.mkdir(parents=True, exist_ok=True)
