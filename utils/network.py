"""Low-level network helpers (IP safety, resolver config, source HTTP)."""

from __future__ import annotations

import gzip
import ipaddress
import json
import random
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass
from typing import Any

from config import (
    DNS_DEFAULT_SERVERS,
    MAX_SOURCE_BYTES,
    USER_AGENT,
)


@dataclass
class IPAssessment:
    ip: str
    safe: bool
    reason: str = ""
    version: int = 0


def assess_ip(value: str) -> IPAssessment:
    """Classify an IP as safe-to-connect (public) or not.

    Everything that is loopback, private, link-local, multicast, reserved,
    unspecified, or otherwise non-global is rejected.  IPv4-mapped IPv6
    addresses are unwrapped first so ``::ffff:127.0.0.1`` cannot slip through.
    """
    raw = value.strip().strip("[]")
    # Strip a possible zone id, e.g. fe80::1%eth0
    if "%" in raw:
        raw = raw.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return IPAssessment(ip=value, safe=False, reason="not-an-ip")

    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if ip.is_loopback:
        return IPAssessment(str(ip), False, "loopback", ip.version)
    if ip.is_private:
        return IPAssessment(str(ip), False, "private", ip.version)
    if ip.is_link_local:
        return IPAssessment(str(ip), False, "link-local", ip.version)
    if ip.is_multicast:
        return IPAssessment(str(ip), False, "multicast", ip.version)
    if ip.is_reserved:
        return IPAssessment(str(ip), False, "reserved", ip.version)
    if ip.is_unspecified:
        return IPAssessment(str(ip), False, "unspecified", ip.version)
    # ``is_global`` is the final guard for shared/CGNAT style ranges.
    if not ip.is_global:
        return IPAssessment(str(ip), False, "non-global", ip.version)
    return IPAssessment(str(ip), True, "", ip.version)


def is_public_ip(value: str) -> bool:
    return assess_ip(value).safe


def filter_safe_ips(ips: list[str]) -> list[str]:
    out: list[str] = []
    for ip in ips:
        if assess_ip(ip).safe:
            out.append(ip)
    return out


def parse_resolv_conf(path: str = "/etc/resolv.conf") -> list[str]:
    servers: list[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith(";"):
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    candidate = parts[1]
                    if is_public_ip(candidate):
                        servers.append(candidate)
    except OSError:
        pass
    if not servers:
        servers = list(DNS_DEFAULT_SERVERS)
    return servers


def safe_getaddrinfo(host: str, port: int, timeout: float = 5.0) -> list[str]:
    """Resolve *host* using the OS stub resolver and return unique IPs.

    Does not mutate global socket default timeout so concurrent worker threads
    cannot race on process-wide socket state.
    """
    _ = timeout
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError, UnicodeError):
        return []
    seen: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.append(addr)
    return seen


def build_ssl_context(verify: bool = True) -> ssl.SSLContext:
    if verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Still negotiate modern TLS; we simply do not validate the chain.
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except (AttributeError, ValueError):
        pass
    return ctx


def _decode_body(raw: bytes, encoding: str) -> bytes:
    encoding = (encoding or "").lower()
    if "gzip" in encoding:
        try:
            return gzip.decompress(raw)
        except OSError:
            return raw
    if "deflate" in encoding:
        try:
            return zlib.decompress(raw)
        except zlib.error:
            try:
                return zlib.decompress(raw, -zlib.MAX_WBITS)
            except zlib.error:
                return raw
    return raw


@dataclass
class ApiResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    url: str
    error: str = ""

    def text(self, encoding: str = "utf-8") -> str:
        charset = encoding
        content_type = self.headers.get("content-type", "")
        if "charset=" in content_type:
            candidate = content_type.split("charset=", 1)[1].split(";")[0].strip()
            if candidate:
                charset = candidate
        return self.body.decode(charset, errors="replace")

    def json(self) -> Any:
        return json.loads(self.text())


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirects to non-HTTP schemes or non-public IP addresses."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise urllib.error.URLError(f"unsafe redirect scheme/host: {newurl}")
        ips = safe_getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
        if not ips or not all(assess_ip(ip).safe for ip in ips):
            raise urllib.error.URLError(f"unsafe redirect address for {parsed.hostname}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def http_request(
    url: str,
    *,
    timeout: float = 20.0,
    retries: int = 2,
    backoff: float = 0.6,
    headers: dict[str, str] | None = None,
    max_bytes: int = MAX_SOURCE_BYTES,
) -> ApiResponse:
    """Fetch a passive data-source URL using urllib with safe retries.

    Only used for public intelligence APIs, never for target probing.  The
    caller is responsible for treating the payload as untrusted.
    """
    parsed_init = urllib.parse.urlsplit(url)
    if parsed_init.scheme not in {"http", "https"} or not parsed_init.hostname:
        return ApiResponse(0, {}, b"", url, "invalid-source-url")

    request_headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, identity",
    }
    if headers:
        request_headers.update(headers)

    opener = urllib.request.build_opener(_SafeRedirectHandler())
    last_error = ""
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=request_headers, method="GET")
            with opener.open(req, timeout=timeout) as resp:
                raw = resp.read(max_bytes + 1)[:max_bytes]
                raw = _decode_body(raw, resp.headers.get("Content-Encoding", ""))
                parsed = urllib.parse.urlsplit(resp.geturl())
                # Reject absurd redirects to non-HTTP schemes.
                if parsed.scheme not in {"http", "https"}:
                    return ApiResponse(0, {}, b"", url, "non-http-response")
                merged = {k.lower(): v for k, v in resp.headers.items()}
                return ApiResponse(resp.status, merged, raw, resp.geturl())
        except urllib.error.HTTPError as exc:
            last_error = f"http-{exc.code}"
            # 4xx (except 429) are not worth retrying.
            if 400 <= exc.code < 500 and exc.code != 429:
                try:
                    body = exc.read(max_bytes)
                except Exception:  # noqa: BLE001 - defensive
                    body = b""
                return ApiResponse(exc.code, {}, body, url, last_error)
        except (urllib.error.URLError, TimeoutError, socket.timeout, OSError) as exc:
            last_error = str(exc)
        except Exception as exc:  # noqa: BLE001 - never let a source crash a scan
            last_error = str(exc)
        if attempt < retries:
            sleep_for = backoff * (2 ** attempt) + random.uniform(0, 0.25)
            time.sleep(sleep_for)
    return ApiResponse(0, {}, b"", url, last_error or "request-failed")
