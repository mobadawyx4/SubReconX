"""Redaction helpers.

Reconnaissance data frequently contains tokens in query strings.  Every
output produced by SubReconX passes through these helpers so that indicator
evidence can be shared without leaking live credentials.
"""

from __future__ import annotations

import json
import re
import urllib.parse

REDACTED = "[REDACTED]"

_SENSITIVE_PARAM_RE = re.compile(
    r"(?:^|[_-])(?:"
    r"pass(?:word|wd)?|pwd|secret|token|access[_-]?token|refresh[_-]?token|"
    r"api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|"
    r"auth(?:orization)?|session(?:id)?|sid|jwt|credential(?:s)?|bearer|"
    r"otp|totp|signature|sig|hash|key"
    r")(?:$|[_-])",
    re.IGNORECASE,
)

_SECRET_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
]

_HEX_RE = re.compile(r"^[0-9a-fA-F]{24,}$")
_B64ISH_RE = re.compile(r"^[A-Za-z0-9+/=_-]{32,}$")


def is_sensitive_param(name: str) -> bool:
    name = (name or "").strip()
    if not name:
        return False
    if _SENSITIVE_PARAM_RE.search(name):
        return True
    lowered = name.lower()
    return lowered in {
        "key", "code", "ticket", "assertion", "samlresponse", "state",
        "redirect_uri", "email", "user", "username", "account",
        "apikey", "api-key", "api_key", "accesstoken", "access-token",
        "access_token", "refreshtoken", "refresh-token", "refresh_token",
        "accesstoken", "clientsecret", "client-secret", "client_secret",
        "privatekey", "private-key", "private_key", "sessionid",
        "session-id", "session_id", "phpsessid", "jsessionid", "bearer",
        "authorization", "auth", "password", "passwd", "pwd", "secret",
        "token", "otp", "totp", "jwt", "credential", "credentials",
    }


def looks_like_secret(value: str) -> bool:
    if not value or len(value) < 16:
        return False
    stripped = value.strip()
    if _HEX_RE.match(stripped):
        return True
    if _B64ISH_RE.match(stripped) and (
        any(c.isdigit() for c in stripped) and any(c.isalpha() for c in stripped)
    ):
        return True
    for pattern in _SECRET_PATTERNS:
        if pattern.search(stripped):
            return True
    if stripped.count(".") == 2 and stripped.startswith("eyJ"):
        return True
    return False


def redact_value(value: str) -> str:
    return REDACTED if looks_like_secret(value) else value


def redact_url(url: str) -> str:
    """Redact sensitive parameter values, leaving names visible.

    Only the query string and any userinfo are touched; the path is kept
    intact because it is the actual indicator under review.
    """
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return url
    netloc = parts.netloc
    if "@" in netloc:
        hostpart = netloc.rsplit("@", 1)[1]
        netloc = f"{REDACTED}@{hostpart}"
    redacted_pairs: list[str] = []
    if parts.query:
        for pair in parts.query.split("&"):
            if not pair:
                continue
            if "=" in pair:
                name, value = pair.split("=", 1)
            else:
                name, value = pair, ""
            decoded_name = urllib.parse.unquote_plus(name)
            if is_sensitive_param(decoded_name) or looks_like_secret(value):
                redacted_pairs.append(f"{name}={REDACTED}")
            else:
                redacted_pairs.append(pair)
    query = "&".join(redacted_pairs)
    return urllib.parse.urlunsplit((parts.scheme, netloc, parts.path, query, ""))


def redact_text(text: str) -> str:
    """Mask secret-looking tokens inside free-form text."""
    if not text:
        return text
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(REDACTED, text)
    return text


def redact_mapping(mapping: dict) -> dict:
    out: dict = {}
    for key, value in mapping.items():
        if is_sensitive_param(str(key)):
            out[key] = REDACTED
        elif isinstance(value, str):
            out[key] = redact_text(value)
        else:
            out[key] = value
    return out


def _redact_object(value):
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if is_sensitive_param(str(key)):
                out[key] = REDACTED
            else:
                out[key] = _redact_object(item)
        return out
    if isinstance(value, list):
        return [_redact_object(item) for item in value]
    if isinstance(value, str):
        if "://" in value:
            return redact_url(value)
        return redact_text(value)
    return value


def redact_structure(value):
    """Recursively redact a JSON-like Python structure."""
    return _redact_object(value)


def redact_payload(payload: str) -> str:
    """Redact URLs/secrets inside a cached JSON (or JSON-lines) payload."""
    if not payload:
        return payload
    stripped = payload.strip()
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            data = json.loads(stripped)
        except (json.JSONDecodeError, TypeError):
            pass
        else:
            return json.dumps(_redact_object(data), separators=(",", ":"))
    lines = payload.splitlines()
    if len(lines) > 1:
        rewritten = []
        parsed_any = False
        for line in lines:
            if not line.strip():
                rewritten.append(line)
                continue
            try:
                item = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                rewritten.append(redact_text(line))
                continue
            parsed_any = True
            rewritten.append(json.dumps(_redact_object(item), separators=(",", ":")))
        if parsed_any:
            return "\n".join(rewritten)
    return redact_text(payload)
