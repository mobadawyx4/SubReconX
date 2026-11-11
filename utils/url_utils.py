"""URL parsing, normalization and classification primitives."""

from __future__ import annotations

import posixpath
import re
import urllib.parse
from dataclasses import dataclass, field

from utils.validators import is_valid_hostname, normalize_hostname

_PCT_RE = re.compile(r"%([0-9a-fA-F]{2})")
_SAFE_PATHS = ("http", "https")
_HTML_ARTIFACT_PATH_RE = re.compile(
    r"""(?:["'<>`\\]|%22|%3[ce]|%5ct|%0[9ad]|/\s|\+\s*listings\[)""",
    re.IGNORECASE,
)


@dataclass
class ParsedURL:
    original: str
    scheme: str = ""
    host: str = ""
    port: int | None = None
    path: str = ""
    query: str = ""
    fragment: str = ""
    valid: bool = False
    malformed_reason: str = ""
    params: list[str] = field(default_factory=list)


def _normalize_percent(value: str) -> str:
    """Upper-case existing percent escapes without decoding them."""
    return _PCT_RE.sub(lambda m: "%" + m.group(1).upper(), value)


def split_url(url: str) -> ParsedURL:
    result = ParsedURL(original=url or "")
    raw = (url or "").strip()
    if not raw:
        result.malformed_reason = "empty"
        return result
    if any(ch.isspace() for ch in raw):
        result.malformed_reason = "whitespace-in-url"
        return result
    if raw.startswith("//"):
        raw = "http:" + raw
    try:
        parts = urllib.parse.urlsplit(raw)
    except ValueError as exc:
        result.malformed_reason = f"urlsplit:{exc}"
        return result

    scheme = (parts.scheme or "").lower()
    raw_host = parts.hostname or ""
    if "*" in raw_host:
        result.malformed_reason = "wildcard-host"
        return result
    host = normalize_hostname(raw_host)
    try:
        port = parts.port
    except ValueError:
        result.malformed_reason = "invalid-port"
        return result

    result.scheme = scheme
    result.host = host
    result.port = port
    result.path = parts.path or ""
    result.query = parts.query or ""
    result.fragment = parts.fragment or ""

    if scheme not in _SAFE_PATHS:
        result.malformed_reason = f"unsupported-scheme:{scheme or 'none'}"
        return result
    if not host or not is_valid_hostname(host, allow_single_label=False):
        result.malformed_reason = "invalid-host"
        return result
    if port is not None and not (0 < port < 65536):
        result.malformed_reason = "invalid-port"
        return result
    if result.path and (
        _HTML_ARTIFACT_PATH_RE.search(result.path)
        or result.path.lower().startswith(("/%20", "/+%20"))
    ):
        result.malformed_reason = "html-artifact-in-path"
        return result

    result.params = extract_param_names(result.query)
    result.valid = True
    return result


def normalize_url(url: str) -> str | None:
    """Return a canonical form used for de-duplication, or None if invalid.

    The transformation is deliberately conservative: it lower-cases the
    scheme/host, drops userinfo (credentials must never be persisted) and the
    fragment, removes default ports, upper-cases percent escapes and ensures a
    path.  It never rewrites the path or reorders query parameters.
    """
    parsed = split_url(url)
    if not parsed.valid:
        return None

    host = parsed.host
    try:
        host_ascii = host.encode("idna").decode("ascii") if not host.isascii() else host
    except UnicodeError:
        host_ascii = host

    netloc = host_ascii
    if host_ascii.startswith("[") or ":" in host_ascii:
        netloc = f"[{host_ascii}]" if ":" in host_ascii and not host_ascii.startswith("[") else host_ascii
    if parsed.port is not None and not (
        (parsed.scheme == "http" and parsed.port == 80)
        or (parsed.scheme == "https" and parsed.port == 443)
    ):
        netloc = f"{netloc}:{parsed.port}"

    path = _normalize_percent(parsed.path)
    if not path:
        path = "/"
    else:
        # Collapse only redundant "./" and "../" segments; never touch the
        # semantic path content itself.
        if path.startswith("/") and ("/./" in path or "/../" in path):
            trailing = path.endswith("/")
            collapsed = posixpath.normpath(path)
            if path.startswith("//") and not collapsed.startswith("//"):
                collapsed = "/" + collapsed.lstrip("/")
            path = collapsed + ("/" if trailing and not collapsed.endswith("/") else "")
    query = _normalize_percent(parsed.query)
    return urllib.parse.urlunsplit((parsed.scheme, netloc, path, query, ""))


def extract_param_names(query: str) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    if not query:
        return names
    for pair in query.split("&"):
        if not pair:
            continue
        name = pair.split("=", 1)[0]
        name = urllib.parse.unquote_plus(name).strip().lower()
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    return names


def get_path(url: str) -> str:
    try:
        return urllib.parse.urlsplit(url).path or "/"
    except ValueError:
        return "/"


def get_hostname(url: str) -> str:
    parsed = split_url(url)
    return parsed.host if parsed.valid else ""


def get_extension(url: str) -> str:
    """Return the lower-case file extension of a URL path (no query string).

    ``/foo/app.JS?x=1`` -> ``js``.  ``/foo/.env`` is reported as ``env`` only
    when the whole basename is ``.env``; ``.env.production`` reports
    ``production`` and is handled separately by the environment-file filter.
    """
    path = get_path(url)
    basename = path.rsplit("/", 1)[-1]
    if not basename:
        return ""
    if basename.lower() == ".env":
        return "env"
    if "." not in basename:
        return ""
    candidate = basename.rsplit(".", 1)[1].lower()
    if not candidate or len(candidate) > 15:
        return ""
    if not re.fullmatch(r"[a-z0-9]+", candidate):
        return ""
    return candidate


def basename(url: str) -> str:
    path = get_path(url)
    return path.rsplit("/", 1)[-1]


def resolve_redirect(base_url: str, location: str) -> str | None:
    """Resolve a Location header against the request URL and normalize it."""
    if not location:
        return None
    try:
        joined = urllib.parse.urljoin(base_url, location.strip())
    except ValueError:
        return None
    return normalize_url(joined)


def is_same_host(url_a: str, url_b: str) -> bool:
    return get_hostname(url_a) == get_hostname(url_b)


def dedupe_urls(urls: list[str]) -> list[str]:
    """De-duplicate on the normalized form while preserving first-seen order."""
    seen: set[str] = set()
    out: list[str] = []
    for url in urls:
        key = normalize_url(url)
        if key is None:
            continue
        if key in seen:
            continue
        seen.add(key)
        out.append(url)
    return out
