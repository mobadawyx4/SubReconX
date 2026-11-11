"""Root-domain validation with actionable error messages."""

from __future__ import annotations

from dataclasses import dataclass

from utils.validators import (
    is_ip_literal,
    is_valid_domain,
    is_valid_hostname,
    normalize_hostname,
)


class DomainValidationError(ValueError):
    """Raised when the operator-supplied domain is unusable."""


@dataclass
class ValidationResult:
    ok: bool
    domain: str = ""
    reason: str = ""


def validate_domain(raw: str) -> ValidationResult:
    if raw is None or not str(raw).strip():
        return ValidationResult(False, "", "empty input")
    candidate = str(raw).strip()
    if "://" in candidate:
        return ValidationResult(
            False,
            "",
            "provide a bare domain (example.com), not a URL",
        )
    if "/" in candidate or " " in candidate or "\t" in candidate:
        return ValidationResult(False, "", "domain must not contain paths or whitespace")
    if "*" in candidate:
        return ValidationResult(False, "", "wildcards are not valid root domains")
    if is_ip_literal(candidate.strip("[]")):
        return ValidationResult(False, "", "IP addresses are not valid root domains")
    host = normalize_hostname(candidate)
    if not is_valid_hostname(host):
        return ValidationResult(False, "", "syntax is not a valid DNS hostname")
    if not is_valid_domain(host):
        return ValidationResult(
            False,
            "",
            "a registrable domain with at least two labels is required",
        )
    return ValidationResult(True, host, "")


def require_valid_domain(raw: str) -> str:
    result = validate_domain(raw)
    if not result.ok:
        raise DomainValidationError(f"invalid domain {raw!r}: {result.reason}")
    return result.domain
