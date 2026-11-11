"""Native DNS resolution engine."""

from __future__ import annotations

import asyncio
import socket
import struct
import time
from dataclasses import dataclass, field

from config import DNS_CACHE_TTL, DNS_DEFAULT_SERVERS, DNS_TIMEOUT
from protocols.dns_protocol import (
    DNSFormatError,
    DNSResponse,
    build_query,
    parse_response,
)
from utils.network import parse_resolv_conf, safe_getaddrinfo
from utils.validators import normalize_hostname

ROOT_RECORD_TYPES = ("A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA")
HOST_RECORD_TYPES = ("A", "AAAA", "CNAME")


@dataclass
class ResolvedHost:
    hostname: str
    status: str = "error"
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    cname: list[str] = field(default_factory=list)
    cname_chain: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    soa: list[str] = field(default_factory=list)
    rcode: str = ""
    dangling: bool = False
    private_ips: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def resolved(self) -> bool:
        return bool(self.a or self.aaaa or (self.cname and not self.dangling))

    def as_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "status": self.status,
            "resolved": self.resolved,
            "a": self.a,
            "aaaa": self.aaaa,
            "cname": self.cname,
            "cname_chain": self.cname_chain,
            "ns": self.ns,
            "mx": self.mx,
            "txt": self.txt,
            "soa": self.soa,
            "rcode": self.rcode,
            "dangling": self.dangling,
            "private_ips": self.private_ips,
            "errors": self.errors,
        }


class DNSEngine:
    def __init__(
        self,
        servers: list[str] | None = None,
        *,
        timeout: float = DNS_TIMEOUT,
        concurrency: int = 40,
        cache_ttl: float = DNS_CACHE_TTL,
    ):
        self.servers = servers or parse_resolv_conf() or list(DNS_DEFAULT_SERVERS)
        self.timeout = timeout
        self.concurrency = max(1, concurrency)
        self.cache_ttl = cache_ttl
        self._cache: dict[tuple[str, str], tuple[float, DNSResponse]] = {}
        self._semaphore = asyncio.Semaphore(self.concurrency)

    # -- low-level transport ------------------------------------------
    async def _udp_query(self, server: str, packet: bytes, query_id: int) -> DNSResponse | None:
        loop = asyncio.get_running_loop()
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            await loop.sock_connect(sock, (server, 53))
            await loop.sock_sendall(sock, packet)
            deadline = loop.time() + self.timeout
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    return None
                data = await asyncio.wait_for(loop.sock_recv(sock, 4096), timeout=remaining)
                try:
                    response = parse_response(data)
                except DNSFormatError:
                    continue
                if response.query_id != query_id:
                    continue
                return response
        except (asyncio.TimeoutError, TimeoutError, OSError):
            return None
        finally:
            sock.close()

    async def _tcp_query(self, server: str, packet: bytes, query_id: int) -> DNSResponse | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(server, 53), timeout=self.timeout
            )
        except (asyncio.TimeoutError, OSError):
            return None
        try:
            writer.write(struct.pack("!H", len(packet)) + packet)
            await asyncio.wait_for(writer.drain(), timeout=self.timeout)
            length_data = await asyncio.wait_for(reader.readexactly(2), timeout=self.timeout)
            length = struct.unpack("!H", length_data)[0]
            data = await asyncio.wait_for(reader.readexactly(length), timeout=self.timeout)
            response = parse_response(data)
            if response.query_id != query_id:
                return None
            return response
        except (asyncio.TimeoutError, OSError, DNSFormatError, struct.error):
            return None
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, Exception):  # noqa: BLE001
                pass

    async def query(self, name: str, qtype: str = "A") -> DNSResponse | None:
        name = normalize_hostname(name)
        if not name:
            return None
        cache_key = (name, qtype)
        cached = self._cache.get(cache_key)
        if cached and time.time() - cached[0] < self.cache_ttl:
            return cached[1]

        packet = build_query(name, qtype)
        query_id = struct.unpack("!H", packet[:2])[0]
        async with self._semaphore:
            for server in self.servers:
                response = await self._udp_query(server, packet, query_id)
                if response is None:
                    continue
                if response.truncated:
                    tcp = await self._tcp_query(server, packet, query_id)
                    if tcp is not None:
                        response = tcp
                if response.rcode in (0, 3):
                    self._cache[cache_key] = (time.time(), response)
                    return response
                # SERVFAIL/REFUSED -> try next resolver.
            return None

    # -- high-level resolution ---------------------------------------
    async def resolve(self, hostname: str, *, full: bool = False) -> ResolvedHost:
        hostname = normalize_hostname(hostname)
        result = ResolvedHost(hostname=hostname)
        if not hostname:
            result.status = "invalid"
            return result

        record_types = ROOT_RECORD_TYPES if full else HOST_RECORD_TYPES
        responses: dict[str, DNSResponse | None] = {}
        for rtype in record_types:
            responses[rtype] = await self.query(hostname, rtype)

        if all(resp is None for resp in responses.values()):
            # Our wire queries failed; fall back to the system resolver so a
            # broken/blocked resolver does not produce false "unresolved" data.
            ips = await asyncio.to_thread(
                safe_getaddrinfo, hostname, 443, self.timeout
            )
            if ips:
                for ip in ips:
                    if ":" in ip:
                        result.aaaa.append(ip)
                    else:
                        result.a.append(ip)
                result.status = "resolved"
                result.rcode = "SYSTEM"
            else:
                result.status = "error"
                result.errors.append("all DNS queries failed")
            self._postprocess(result)
            return result

        a_resp = responses.get("A")
        aaaa_resp = responses.get("AAAA")
        cname_resp = responses.get("CNAME")

        for record in (a_resp.answers if a_resp else []):
            if record.rtype == "A":
                result.a.append(record.value)
            elif record.rtype == "CNAME":
                result.cname.append(record.value)
        for record in (aaaa_resp.answers if aaaa_resp else []):
            if record.rtype == "AAAA":
                result.aaaa.append(record.value)
        for record in (cname_resp.answers if cname_resp else []):
            if record.rtype == "CNAME":
                result.cname.append(record.value)

        result.a = _dedupe(result.a)
        result.aaaa = _dedupe(result.aaaa)
        result.cname = _dedupe(result.cname)
        result.cname_chain = _build_chain(hostname, result.cname)

        result.rcode = (
            a_resp.rcode_name if a_resp else (aaaa_resp.rcode_name if aaaa_resp else "")
        )

        # Follow CNAME hops (up to 4) when the initial lookup returned a CNAME
        # target without A/AAAA records.
        if not result.a and not result.aaaa and result.cname:
            visited = {hostname, *result.cname}
            target = result.cname[-1]
            for _hop in range(4):
                follow_a = await self.query(target, "A")
                follow_aaaa = await self.query(target, "AAAA")
                next_target = ""
                if follow_a is not None:
                    for record in follow_a.answers:
                        if record.rtype == "A":
                            result.a.append(record.value)
                        elif record.rtype == "CNAME" and record.value not in visited:
                            result.cname.append(record.value)
                            visited.add(record.value)
                            next_target = record.value
                if follow_aaaa is not None:
                    for record in follow_aaaa.answers:
                        if record.rtype == "AAAA":
                            result.aaaa.append(record.value)
                        elif record.rtype == "CNAME" and record.value not in visited:
                            result.cname.append(record.value)
                            visited.add(record.value)
                            next_target = next_target or record.value
                if result.a or result.aaaa:
                    break
                if next_target:
                    target = next_target
                    continue
                if follow_a is not None and follow_a.rcode == 3:
                    result.dangling = True
                elif follow_a is None and follow_aaaa is None:
                    result.dangling = True
                else:
                    result.dangling = not (result.a or result.aaaa)
                break
            result.a = _dedupe(result.a)
            result.aaaa = _dedupe(result.aaaa)
            result.cname = _dedupe(result.cname)
            result.cname_chain = _build_chain(hostname, result.cname)

        if full:
            for rtype in ("NS", "MX", "TXT", "SOA"):
                resp = responses.get(rtype)
                if not resp:
                    continue
                for record in resp.answers:
                    if record.rtype == rtype:
                        getattr(result, rtype.lower()).append(record.value)

        if result.resolved:
            result.status = "resolved"
        elif result.rcode == "NXDOMAIN":
            result.status = "nxdomain"
        elif result.rcode:
            result.status = "no_records"
        else:
            result.status = "error"

        self._postprocess(result)
        return result

    def _postprocess(self, result: ResolvedHost) -> None:
        from utils.network import assess_ip

        for ip in result.a + result.aaaa:
            if not assess_ip(ip).safe:
                result.private_ips.append(ip)
        if result.private_ips:
            result.errors.append("resolved address is private/reserved")

    async def resolve_many(
        self, hostnames: list[str], *, full: bool = False
    ) -> list[ResolvedHost]:
        from utils.concurrency import bounded_map

        unique: list[str] = []
        seen: set[str] = set()
        for host in hostnames:
            host = normalize_hostname(host)
            if host and host not in seen:
                seen.add(host)
                unique.append(host)

        async def _one(host: str) -> ResolvedHost:
            return await self.resolve(host, full=full)

        results = await bounded_map(_one, unique, self.concurrency)
        output: list[ResolvedHost] = []
        for host, item in zip(unique, results):
            if isinstance(item, Exception):
                failed = ResolvedHost(hostname=host, status="error")
                failed.errors.append(str(item))
                output.append(failed)
            else:
                output.append(item)
        return output

    async def wordlist_candidates(self, root: str, words: list[str]) -> list[str]:
        from utils.validators import is_valid_hostname

        candidates: list[str] = []
        for word in words:
            word = word.strip().lower()
            if not word or word.startswith("#"):
                continue
            if word.endswith("." + root):
                candidate = word
            else:
                candidate = f"{word}.{root}"
            if is_valid_hostname(candidate) and candidate not in candidates:
                candidates.append(candidate)
        return candidates


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _build_chain(start: str, cnames: list[str]) -> list[str]:
    chain: list[str] = []
    current = normalize_hostname(start)
    remaining = list(cnames)
    while remaining:
        # Prefer the target that is not the current hop.
        match = None
        for target in remaining:
            if target != current:
                match = target
                break
        if match is None:
            break
        chain.append(match)
        remaining.remove(match)
        current = match
    return chain


@dataclass
class DNSRunResult:
    root: str
    records: list[ResolvedHost] = field(default_factory=list)
    resolved: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)
    cname_records: list[dict] = field(default_factory=list)
    dangling: list[dict] = field(default_factory=list)
    suspicious: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "root": self.root,
            "count": len(self.records),
            "resolved": self.resolved,
            "unresolved": self.unresolved,
            "cname_records": self.cname_records,
            "dangling": self.dangling,
            "suspicious": self.suspicious,
            "records": [record.as_dict() for record in self.records],
        }


async def run_dns(
    engine: DNSEngine,
    hostnames: list[str],
    root: str,
    logger: EventLogger | None = None,
) -> DNSRunResult:
    result = DNSRunResult(root=root)
    unique: list[str] = []
    seen: set[str] = set()
    for host in hostnames:
        host = normalize_hostname(host)
        if host and host not in seen:
            seen.add(host)
            unique.append(host)

    async def _one(host: str) -> ResolvedHost:
        return await engine.resolve(host, full=(host == root))

    from utils.concurrency import bounded_map

    outcomes = await bounded_map(_one, unique, engine.concurrency)
    for host, outcome in zip(unique, outcomes):
        if isinstance(outcome, Exception):
            failed = ResolvedHost(hostname=host, status="error")
            failed.errors.append(str(outcome))
            outcome = failed
        result.records.append(outcome)
        if outcome.resolved:
            result.resolved.append(host)
        else:
            result.unresolved.append(host)
        for target in outcome.cname:
            result.cname_records.append({"hostname": host, "target": target})
        if outcome.dangling:
            result.dangling.append(
                {
                    "hostname": host,
                    "cname_target": outcome.cname[-1] if outcome.cname else "",
                    "records": outcome.cname,
                }
            )
        if outcome.private_ips:
            result.suspicious.append(
                {
                    "hostname": host,
                    "reason": "private-ip-in-dns",
                    "addresses": outcome.private_ips,
                }
            )
    result.records.sort(key=lambda r: r.hostname)
    result.resolved.sort()
    result.unresolved.sort()
    if logger:
        logger.success(
            f"DNS: {len(result.resolved)} resolved, "
            f"{len(result.unresolved)} unresolved, "
            f"{len(result.dangling)} dangling CNAME(s)"
        )
    return result


def write_dns_outputs(result: DNSRunResult, output_dir) -> None:
    import json
    from pathlib import Path

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "dns_results.json").write_text(
        json.dumps(result.as_dict(), indent=2, default=str), encoding="utf-8"
    )
    (output_dir / "resolved.txt").write_text(
        "\n".join(result.resolved) + ("\n" if result.resolved else ""), encoding="utf-8"
    )
    (output_dir / "unresolved.txt").write_text(
        "\n".join(result.unresolved) + ("\n" if result.unresolved else ""),
        encoding="utf-8",
    )
    lines = [f"{item['hostname']} -> {item['target']}" for item in result.cname_records]
    (output_dir / "cname_records.txt").write_text(
        "\n".join(lines) + ("\n" if lines else ""), encoding="utf-8"
    )
