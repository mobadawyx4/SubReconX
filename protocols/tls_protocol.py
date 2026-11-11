"""TLS certificate inspection using the standard-library ``ssl`` module.

A verified handshake is always attempted first and its result recorded.  When
the chain is invalid, a second, explicitly unverified handshake is used *only*
to inventory the presented certificate; that connection is never used to
trust data and the result is marked ``verified=False``.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import ssl
import tempfile
import time
from dataclasses import dataclass, field

from core.scope_manager import ScopeManager
from utils.network import build_ssl_context


@dataclass
class TLSResult:
    hostname: str
    port: int = 443
    connected: bool = False
    verified: bool = False
    verification_error: str = ""
    protocol: str = ""
    cipher: str = ""
    subject: dict = field(default_factory=dict)
    issuer: dict = field(default_factory=dict)
    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""
    sans: list[str] = field(default_factory=list)
    expired: bool | None = None
    days_until_expiry: int | None = None
    hostname_matches: bool | None = None
    error: str = ""

    def as_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "port": self.port,
            "connected": self.connected,
            "verified": self.verified,
            "verification_error": self.verification_error,
            "protocol": self.protocol,
            "cipher": self.cipher,
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "sans": self.sans,
            "expired": self.expired,
            "days_until_expiry": self.days_until_expiry,
            "hostname_matches": self.hostname_matches,
            "error": self.error,
        }


def _decode_der(der: bytes) -> dict:
    """Decode a DER certificate to the same dict shape as getpeercert().

    Uses CPython's private helper because the public API only parses a
    certificate from a verified handshake.  A failure here degrades to an
    empty dict rather than aborting the scan.
    """
    if not der:
        return {}
    path = ""
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        fd, path = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(pem)
        decoder = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
        if decoder is None:
            return {}
        return decoder(path)
    except Exception:  # noqa: BLE001 - best-effort inventory
        return {}
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def _name_dict(subject) -> dict:
    out: dict = {}
    if not subject:
        return out
    for rdn in subject:
        for key, value in rdn:
            out.setdefault(key, value)
    return out


def _extract_sans(cert: dict) -> list[str]:
    sans: list[str] = []
    for kind, value in cert.get("subjectAltName", ()) if cert else ():
        if kind in ("DNS", "IP Address") and value not in sans:
            sans.append(value)
    return sans


def hostname_matches(hostname: str, cert: dict) -> bool:
    hostname = hostname.lower().rstrip(".")
    candidates = list(_extract_sans(cert))
    cn = _name_dict(cert.get("subject", ())).get("commonName", "")
    if cn:
        candidates.append(cn)
    if not candidates:
        return False
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None
    for candidate in candidates:
        cand = candidate.strip().lower().rstrip(".")
        if ip is not None:
            try:
                if ipaddress.ip_address(cand) == ip:
                    return True
            except ValueError:
                continue
            continue
        if cand.startswith("*."):
            suffix = cand[1:]  # ".example.com"
            if hostname.endswith(suffix) and hostname.count(".") == cand.count("."):
                return True
        elif cand == hostname:
            return True
    return False


def _validity(cert: dict) -> tuple[str, str, bool | None, int | None]:
    not_before = cert.get("notBefore", "") if cert else ""
    not_after = cert.get("notAfter", "") if cert else ""
    expired: bool | None = None
    days: int | None = None
    if not_after:
        try:
            end_seconds = ssl.cert_time_to_seconds(not_after)
            remaining = end_seconds - time.time()
            days = int(remaining // 86400)
            expired = remaining < 0
        except (ValueError, OverflowError):
            pass
    return not_before, not_after, expired, days


async def inspect(
    hostname: str,
    scope: ScopeManager,
    *,
    port: int = 443,
    timeout: float = 10.0,
) -> TLSResult:
    result = TLSResult(hostname=hostname, port=port)
    if not scope.check_host(hostname):
        result.error = "out-of-scope host"
        return result
    try:
        ips, reason = await asyncio.to_thread(scope.resolve, hostname, port, timeout)
    except Exception as exc:  # noqa: BLE001
        result.error = f"dns:{exc}"
        return result
    if not ips:
        result.error = f"dns:{reason}"
        return result
    ip = ips[0]
    if not scope.verify_connect_ip(hostname, ip):
        result.error = "unsafe-resolved-address"
        return result

    cert: dict = {}
    der = b""
    tls_sock: ssl.SSLSocket | None = None
    writer = None
    verified = False
    verification_error = ""

    # 1) Verified handshake.
    try:
        verify_ctx = build_ssl_context(True)
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=verify_ctx, server_hostname=hostname),
            timeout=timeout,
        )
        tls_sock = writer.get_extra_info("ssl_object")
        verified = True
        if tls_sock is not None:
            cert = tls_sock.getpeercert() or {}
            der = tls_sock.getpeercert(binary_form=True) or b""
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        writer = None
    except ssl.SSLCertVerificationError as exc:
        verification_error = str(exc)
    except (asyncio.TimeoutError, TimeoutError):
        result.error = "timeout"
        return result
    except (OSError, ssl.SSLError) as exc:
        result.error = f"{type(exc).__name__}:{exc}"
        return result

    # 2) Unverified inventory handshake (only when verification failed).
    if not verified:
        try:
            fallback_ctx = build_ssl_context(False)
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=fallback_ctx, server_hostname=hostname),
                timeout=timeout,
            )
            tls_sock = writer.get_extra_info("ssl_object")
            if tls_sock is not None:
                der = tls_sock.getpeercert(binary_form=True) or b""
                cert = _decode_der(der)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            writer = None
        except (asyncio.TimeoutError, TimeoutError):
            result.error = "timeout"
            return result
        except (OSError, ssl.SSLError) as exc:
            result.error = f"{type(exc).__name__}:{exc}"
            return result

    result.connected = True
    result.verified = verified
    result.verification_error = verification_error
    if tls_sock is not None:
        result.protocol = tls_sock.version() or ""
        cipher = tls_sock.cipher()
        result.cipher = cipher[0] if cipher else ""
    result.subject = _name_dict(cert.get("subject", ())) if cert else {}
    result.issuer = _name_dict(cert.get("issuer", ())) if cert else {}
    result.serial_number = str(cert.get("serialNumber", "")) if cert else ""
    result.sans = _extract_sans(cert)
    (
        result.not_before,
        result.not_after,
        result.expired,
        result.days_until_expiry,
    ) = _validity(cert)
    result.hostname_matches = hostname_matches(hostname, cert) if cert else None
    return result
