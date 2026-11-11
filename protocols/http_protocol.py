"""Native asyncio HTTP/1.1 client.

Features used by SubReconX: bounded redirects with per-hop scope validation,
TLS-verification tracking with a clearly-labelled unverified fallback for
inventory, title extraction, chunked decoding and hard body limits.
"""

from __future__ import annotations

import asyncio
import html
import re
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from config import USER_AGENT
from core.scope_manager import ScopeManager
from utils.network import build_ssl_context
from utils.redaction import redact_text, redact_url
from utils.url_utils import resolve_redirect, split_url

_STATUS_RE = re.compile(r"^HTTP/(\d\.\d)\s+(\d{3})\s*(.*)$")
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_CHARSET_RE = re.compile(r"charset\s*=\s*[\"']?([\w-]+)", re.IGNORECASE)
WHITESPACE_RE = re.compile(r"\s+")


class HTTPFetchError(Exception):
    pass


@dataclass
class HTTPResult:
    url: str
    final_url: str = ""
    scheme: str = ""
    hostname: str = ""
    status: int | None = None
    reason: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    title: str = ""
    server: str = ""
    content_type: str = ""
    content_length: int | None = None
    elapsed: float = 0.0
    redirect_chain: list[str] = field(default_factory=list)
    redirect_rejected: str = ""
    tls_verified: bool | None = None
    tls_error: str = ""
    tls_metadata: dict = field(default_factory=dict)
    ip_used: str = ""
    technologies: list[str] = field(default_factory=list)
    error: str = ""

    def text(self) -> str:
        return decode_body(self.body, self.content_type)

    def as_dict(self) -> dict:
        sensitive_headers = {
            "set-cookie", "cookie", "authorization", "proxy-authorization",
            "x-api-key", "x-auth-token", "authentication",
        }
        safe_headers = {
            key: (
                "[REDACTED]"
                if key.lower() in sensitive_headers
                else redact_text(value)
            )
            for key, value in self.headers.items()
        }
        return {
            "url": redact_url(self.url),
            "final_url": redact_url(self.final_url),
            "scheme": self.scheme,
            "hostname": self.hostname,
            "status": self.status,
            "reason": self.reason,
            "server": self.server,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "title": self.title,
            "elapsed": round(self.elapsed, 4),
            "redirect_chain": [redact_url(item) for item in self.redirect_chain],
            "redirect_rejected": self.redirect_rejected,
            "tls_verified": self.tls_verified,
            "tls_error": self.tls_error,
            "tls_metadata": self.tls_metadata,
            "ip_used": self.ip_used,
            "technologies": self.technologies,
            "error": redact_text(self.error),
            "headers": safe_headers,
        }


def decode_body(body: bytes, content_type: str = "") -> str:
    charset = "utf-8"
    match = _CHARSET_RE.search(content_type or "")
    if match:
        charset = match.group(1)
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def extract_title(body: bytes, content_type: str = "") -> str:
    if not body:
        return ""
    text = decode_body(body[:200_000], content_type)
    match = _TITLE_RE.search(text)
    if not match:
        return ""
    title = html.unescape(match.group(1))
    title = WHITESPACE_RE.sub(" ", title).strip()
    return title[:300]


_GENERATOR_RE = re.compile(
    r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']{1,120})["']""",
    re.IGNORECASE,
)
_COOKIE_TECH = {
    "phpsessid": "PHP",
    "jsessionid": "Java",
    "asp.net_sessionid": "ASP.NET",
    "laravel_session": "Laravel",
    "connect.sid": "Express",
    "csrftoken": "Django",
    "wp-settings": "WordPress",
    "wordpress_logged_in": "WordPress",
    "_shopify_s": "Shopify",
}
_SERVER_TECH = {
    "cloudflare": "Cloudflare",
    "nginx": "nginx",
    "apache": "Apache",
    "microsoft-iis": "IIS",
    "openresty": "OpenResty",
    "litespeed": "LiteSpeed",
    "caddy": "Caddy",
    "gunicorn": "Gunicorn",
    "uvicorn": "Uvicorn",
    "envoy": "Envoy",
    "awselb": "AWS ELB",
    "cloudfront": "Amazon CloudFront",
    "akamaighost": "Akamai",
    "fastly": "Fastly",
    "varnish": "Varnish",
    "istio-envoy": "Istio",
}
_POWERED_BY = {
    "php": "PHP",
    "express": "Express",
    "asp.net": "ASP.NET",
    "servlet": "Java Servlet",
    "next.js": "Next.js",
    "nuxt": "Nuxt",
    "django": "Django",
    "rails": "Ruby on Rails",
}


def detect_technologies(
    headers: dict[str, str], body: bytes, content_type: str = ""
) -> list[str]:
    """Best-effort, header/metadata-only technology hints (no active probing)."""
    found: list[str] = []

    def add(name: str) -> None:
        if name and name not in found:
            found.append(name)

    server = headers.get("server", "").lower()
    for signature, name in _SERVER_TECH.items():
        if signature in server:
            add(name)

    powered = headers.get("x-powered-by", "").lower()
    for signature, name in _POWERED_BY.items():
        if signature in powered:
            add(name)

    cookie = headers.get("set-cookie", "").lower()
    for signature, name in _COOKIE_TECH.items():
        if signature in cookie:
            add(name)

    header_markers = {
        "x-aspnet-version": "ASP.NET",
        "x-drupal-cache": "Drupal",
        "x-shopify-stage": "Shopify",
        "x-vercel-id": "Vercel",
        "x-nf-request-id": "Netlify",
        "x-amz-cf-id": "Amazon CloudFront",
        "x-azure-ref": "Azure Front Door",
        "x-github-request-id": "GitHub Pages",
    }
    for header, name in header_markers.items():
        if header in headers:
            add(name)

    via = headers.get("via", "").lower()
    if "varnish" in via:
        add("Varnish")

    if body and "html" in (content_type or "").lower():
        text = decode_body(body[:100_000], content_type)
        match = _GENERATOR_RE.search(text)
        if match:
            add(match.group(1).strip()[:60])
    return found[:20]


def _build_request(url: str, host_header: str) -> bytes:
    parts = urlsplit(url)
    target = parts.path or "/"
    if parts.query:
        target = f"{target}?{parts.query}"
    lines = [
        f"GET {target} HTTP/1.1",
        f"Host: {host_header}",
        f"User-Agent: {USER_AGENT}",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding: identity",
        "Connection: close",
        "",
        "",
    ]
    return "\r\n".join(lines).encode("latin-1", errors="replace")


async def _read_headers(reader: asyncio.StreamReader, limit: int = 64 * 1024) -> tuple[str, dict[str, str]]:
    raw = await reader.readuntil(b"\r\n\r\n")
    if len(raw) > limit:
        raise HTTPFetchError("response headers too large")
    text = raw.decode("latin-1", errors="replace")
    lines = text.split("\r\n")
    status_line = lines[0] if lines else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip().lower()
        value = value.strip()
        if name in headers:
            headers[name] = f"{headers[name]}, {value}"
        else:
            headers[name] = value
    return status_line, headers


async def _read_chunked(reader: asyncio.StreamReader, limit: int) -> bytes:
    data = bytearray()
    while len(data) < limit:
        line = await reader.readline()
        if not line:
            break
        try:
            size = int(line.split(b";", 1)[0].strip() or b"0", 16)
        except ValueError:
            break
        if size == 0:
            # Consume trailers.
            while True:
                trailer = await reader.readline()
                if trailer in (b"\r\n", b"\n", b""):
                    break
            break
        take = min(size, limit - len(data))
        if take > 0:
            try:
                data.extend(await reader.readexactly(take))
            except asyncio.IncompleteReadError as exc:
                data.extend(exc.partial)
                break
        if take < size or len(data) >= limit:
            # Hard body cap reached; do not read the rest of an oversized chunk.
            break
        await reader.readline()
    return bytes(data)


async def _read_body(
    reader: asyncio.StreamReader, headers: dict[str, str], limit: int, status: int
) -> bytes:
    if status in (204, 304) or 100 <= status < 200:
        return b""
    if "chunked" in headers.get("transfer-encoding", "").lower():
        return await _read_chunked(reader, limit)
    length_header = headers.get("content-length")
    if length_header:
        try:
            length = min(int(length_header), limit)
        except ValueError:
            length = limit
        try:
            return await reader.readexactly(length)
        except asyncio.IncompleteReadError as exc:
            return exc.partial
    chunks = bytearray()
    while len(chunks) < limit:
        try:
            chunk = await reader.read(min(65536, limit - len(chunks)))
        except (OSError, asyncio.IncompleteReadError):
            break
        if not chunk:
            break
        chunks.extend(chunk)
    return bytes(chunks)


async def _connect(
    host: str, port: int, ip: str, use_tls: bool
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, bool | None, str]:
    tls_verified: bool | None = None
    tls_error = ""
    if not use_tls:
        reader, writer = await asyncio.open_connection(ip, port)
        return reader, writer, tls_verified, tls_error

    verify_ctx = build_ssl_context(True)
    try:
        reader, writer = await asyncio.open_connection(
            ip, port, ssl=verify_ctx, server_hostname=host
        )
        tls_verified = True
        return reader, writer, tls_verified, tls_error
    except ssl.SSLCertVerificationError as exc:
        tls_verified = False
        tls_error = str(exc)
    except ssl.SSLError as exc:
        tls_verified = False
        tls_error = str(exc)
    # Inventory fallback: re-connect without chain verification purely so the
    # host can still be fingerprinted.  Reported as tls_verified=False.
    fallback_ctx = build_ssl_context(False)
    reader, writer = await asyncio.open_connection(
        ip, port, ssl=fallback_ctx, server_hostname=host
    )
    return reader, writer, tls_verified, tls_error


async def _single_request(
    url: str,
    scope: ScopeManager,
    *,
    timeout: float,
    max_body: int,
    want_body: bool,
) -> HTTPResult:
    parsed = split_url(url)
    result = HTTPResult(url=url, scheme=parsed.scheme, hostname=parsed.host)
    if not parsed.valid:
        result.error = f"invalid-url:{parsed.malformed_reason}"
        return result

    if not scope.allow_active_probing:
        result.error = "scope:active probing is disabled by program scope restrictions"
        return result

    decision = scope.check_url(url)
    if not decision:
        result.error = f"scope:{decision.reason}"
        return result

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        ips, reason = await asyncio.to_thread(scope.resolve, parsed.host, port, timeout)
    except Exception as exc:  # noqa: BLE001
        result.error = f"dns:{exc}"
        return result
    if not ips:
        result.error = f"dns:{reason}"
        return result
    ip = ips[0]

    ip_decision = scope.verify_connect_ip(parsed.host, ip)
    if not ip_decision:
        result.error = f"ssrf-guard:{ip_decision.reason}"
        return result

    host_header = parsed.host
    default_port = 443 if parsed.scheme == "https" else 80
    if port != default_port:
        host_header = f"{parsed.host}:{port}"

    start = time.monotonic()
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer, tls_verified, tls_error = await asyncio.wait_for(
            _connect(parsed.host, port, ip, parsed.scheme == "https"), timeout=timeout
        )
        result.tls_verified = tls_verified
        result.tls_error = tls_error
        result.ip_used = ip
        if parsed.scheme == "https" and writer is not None:
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj is not None:
                try:
                    cert = ssl_obj.getpeercert() or {}
                    cipher_info = ssl_obj.cipher() or ("", "", 0)
                    subject = {
                        k: v for rdn in cert.get("subject", ()) for k, v in rdn
                    }
                    issuer = {
                        k: v for rdn in cert.get("issuer", ()) for k, v in rdn
                    }
                    sans = [
                        val
                        for kind, val in cert.get("subjectAltName", ())
                        if kind.lower() == "dns"
                    ]
                    result.tls_metadata = {
                        "protocol": ssl_obj.version() or "",
                        "cipher": cipher_info[0] if cipher_info else "",
                        "subject": subject,
                        "issuer": issuer,
                        "not_before": cert.get("notBefore", ""),
                        "not_after": cert.get("notAfter", ""),
                        "serial_number": cert.get("serialNumber", ""),
                        "sans": sans,
                        "verified": bool(tls_verified),
                    }
                except Exception:  # noqa: BLE001
                    pass
        writer.write(_build_request(url, host_header))
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        status_line, headers = await asyncio.wait_for(
            _read_headers(reader), timeout=timeout
        )
        match = _STATUS_RE.match(status_line)
        if not match:
            result.error = "bad-status-line"
            return result
        status = int(match.group(2))
        result.status = status
        result.reason = match.group(3).strip()
        result.headers = headers
        result.server = headers.get("server", "")
        result.content_type = headers.get("content-type", "")
        result.final_url = url
        try:
            result.content_length = int(headers.get("content-length", ""))
        except ValueError:
            result.content_length = None
        if want_body and status not in (301, 302, 303, 307, 308):
            result.body = await asyncio.wait_for(
                _read_body(reader, headers, max_body, status), timeout=timeout
            )
            result.title = extract_title(result.body, result.content_type)
            result.technologies = detect_technologies(
                headers, result.body, result.content_type
            )
        else:
            result.technologies = detect_technologies(headers, b"", result.content_type)
        return result
    except asyncio.TimeoutError:
        result.error = "timeout"
        return result
    except (OSError, ssl.SSLError, HTTPFetchError, asyncio.IncompleteReadError,
            asyncio.LimitOverrunError) as exc:
        result.error = f"{type(exc).__name__}:{exc}"
        return result
    finally:
        result.elapsed = time.monotonic() - start
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # noqa: BLE001 - closing a broken stream is best-effort
                pass


async def fetch(
    url: str,
    scope: ScopeManager,
    *,
    timeout: float = 10.0,
    max_body: int = 256 * 1024,
    max_redirects: int = 5,
) -> HTTPResult:
    """Fetch *url*, validating scope and IP safety at every redirect hop."""
    chain: list[str] = []
    current = url
    last: HTTPResult | None = None
    for _hop in range(max_redirects + 1):
        result = await _single_request(
            current, scope, timeout=timeout, max_body=max_body, want_body=True
        )
        result.redirect_chain = list(chain)
        last = result
        if result.error or result.status not in (301, 302, 303, 307, 308):
            return result
        location = result.headers.get("location", "")
        if not location:
            return result
        target = resolve_redirect(current, location)
        if target is None:
            result.redirect_rejected = f"invalid location: {location}"
            return result
        scoped = scope.check_url(target)
        if not scoped:
            result.redirect_rejected = f"redirect to out-of-scope target: {target}"
            return result
        chain.append(target)
        current = target
    if last is not None:
        last.redirect_rejected = "maximum redirects exceeded"
        return last
    return HTTPResult(url=url, error="redirect-loop")


def origin_url(hostname: str, scheme: str = "https", port: int | None = None) -> str:
    netloc = hostname
    if port is not None:
        default = 443 if scheme == "https" else 80
        if port != default:
            netloc = f"{hostname}:{port}"
    return urlunsplit((scheme, netloc, "/", "", ""))
