"""Hostname / domain / IP validation helpers."""

from __future__ import annotations

import ipaddress
import re

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
_HOST_RE = re.compile(r"^[a-z0-9._-]+$", re.IGNORECASE)


def normalize_hostname(host: str) -> str:
    """Lower-case, trim trailing dot and convert IDN labels to punycode."""
    if host is None:
        return ""
    host = host.strip().strip("\u200b").lower()
    if host.startswith("*."):
        host = host[2:]
    if host.endswith("."):
        host = host[:-1]
    if not host:
        return ""
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return host
    return host


def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def is_valid_hostname(host: str, allow_single_label: bool = False) -> bool:
    """Validate a DNS hostname using RFC 1035 / 1123 label rules."""
    if not host or len(host) > 253:
        return False
    if host.endswith("."):
        host = host[:-1]
    if not host or not _HOST_RE.match(host):
        return False
    labels = host.split(".")
    if len(labels) < 2 and not allow_single_label:
        return False
    if any(not label for label in labels):
        return False
    if any(len(label) > 63 for label in labels):
        return False
    for label in labels:
        if not _LABEL_RE.match(label):
            return False
    # A TLD consisting only of digits is not a hostname (it is usually an IP).
    if labels[-1].isdigit():
        return False
    return True


def is_valid_domain(domain: str) -> bool:
    """Validate a registrable/root domain supplied by the operator.

    The input must be a DNS name with at least two labels and a non-numeric
    TLD.  IP addresses and bare public suffixes are rejected.
    """
    from config import KNOWN_PUBLIC_SUFFIXES

    host = normalize_hostname(domain)
    if not host or is_ip_literal(host):
        return False
    if not is_valid_hostname(host):
        return False
    if host in KNOWN_PUBLIC_SUFFIXES:
        return False
    return True


def is_wildcard_entry(value: str) -> bool:
    value = value.strip()
    return value.startswith("*.") or value.startswith(".")


def strip_wildcard(value: str) -> str:
    value = value.strip()
    if value.startswith("*."):
        value = value[2:]
    return value.lstrip(".")


def is_within_domain(host: str, root: str) -> bool:
    """Return True when *host* equals or is a subdomain of *root*.

    The comparison is label-aware: ``evil-example.com`` is NOT inside
    ``example.com``.
    """
    host = normalize_hostname(host)
    root = normalize_hostname(root)
    if not host or not root:
        return False
    return host == root or host.endswith("." + root)
