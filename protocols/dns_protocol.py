"""Native DNS wire-protocol encoder/decoder.

Implements RFC 1035 message parsing: name compression pointers, the record
types required by SubReconX, and response-code interpretation.  No external
DNS library is used.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import Iterable

QTYPES: dict[str, int] = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
}
RTYPES: dict[int, str] = {v: k for k, v in QTYPES.items()}

RCODES: dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
}


class DNSFormatError(ValueError):
    pass


@dataclass
class DNSRecord:
    name: str
    rtype: str
    rtype_code: int
    ttl: int
    value: str

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.rtype,
            "ttl": self.ttl,
            "value": self.value,
        }


@dataclass
class DNSResponse:
    query_id: int
    flags: int
    rcode: int
    rcode_name: str
    truncated: bool
    question: list[tuple[str, str]] = field(default_factory=list)
    answers: list[DNSRecord] = field(default_factory=list)
    authority: list[DNSRecord] = field(default_factory=list)
    additional: list[DNSRecord] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return self.rcode == 0

    def of_type(self, rtype: str) -> list[DNSRecord]:
        return [record for record in self.answers if record.rtype == rtype]

    def as_dict(self) -> dict:
        return {
            "query_id": self.query_id,
            "rcode": self.rcode_name,
            "truncated": self.truncated,
            "question": self.question,
            "answers": [r.as_dict() for r in self.answers],
            "authority": [r.as_dict() for r in self.authority],
            "additional": [r.as_dict() for r in self.additional],
        }


def encode_name(name: str) -> bytes:
    name = name.strip().rstrip(".")
    out = bytearray()
    if name:
        for label in name.split("."):
            encoded = label.encode("ascii", errors="ignore")
            if not encoded or len(encoded) > 63:
                raise DNSFormatError(f"invalid label {label!r}")
            out.append(len(encoded))
            out.extend(encoded)
    out.append(0)
    return bytes(out)


def build_query(name: str, qtype: str = "A", query_id: int | None = None) -> bytes:
    if qtype not in QTYPES:
        raise DNSFormatError(f"unsupported query type {qtype}")
    if query_id is None:
        import random

        query_id = random.randint(0, 0xFFFF)
    flags = 0x0100  # recursion desired
    header = struct.pack("!HHHHHH", query_id, flags, 1, 0, 0, 0)
    question = encode_name(name) + struct.pack("!HH", QTYPES[qtype], 1)
    return header + question


def decode_name(data: bytes, offset: int, max_depth: int = 32) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    next_offset = offset
    depth = 0
    while True:
        if depth > max_depth:
            raise DNSFormatError("compression pointer loop")
        depth += 1
        if offset >= len(data):
            raise DNSFormatError("name runs past end of packet")
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                next_offset = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise DNSFormatError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                next_offset = offset + 2
            if pointer >= len(data):
                raise DNSFormatError("compression pointer out of range")
            offset = pointer
            jumped = True
            continue
        offset += 1
        if offset + length > len(data):
            raise DNSFormatError("label runs past end of packet")
        labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
        if not jumped:
            next_offset = offset
    return ".".join(labels).lower(), next_offset


def _decode_rdata(
    data: bytes, rtype_code: int, rdata_offset: int, rdata_len: int, ttl: int
) -> str:
    rdata = data[rdata_offset : rdata_offset + rdata_len]
    if rtype_code == 1 and len(rdata) >= 4:
        return socket.inet_ntoa(rdata[:4])
    if rtype_code == 28 and len(rdata) >= 16:
        return socket.inet_ntop(socket.AF_INET6, rdata[:16])
    if rtype_code in (2, 5):  # NS, CNAME
        name, _ = decode_name(data, rdata_offset)
        return name
    if rtype_code == 15 and len(rdata) >= 3:  # MX
        preference = struct.unpack("!H", rdata[:2])[0]
        exchange, _ = decode_name(data, rdata_offset + 2)
        return f"{preference} {exchange}"
    if rtype_code == 16:  # TXT
        parts: list[str] = []
        cursor = 0
        while cursor < len(rdata):
            seg_len = rdata[cursor]
            cursor += 1
            parts.append(
                rdata[cursor : cursor + seg_len].decode("utf-8", errors="replace")
            )
            cursor += seg_len
        return "".join(parts)
    if rtype_code == 6:  # SOA
        mname, cursor = decode_name(data, rdata_offset)
        rname, cursor = decode_name(data, cursor)
        if cursor + 20 <= len(data):
            serial, refresh, retry, expire, minimum = struct.unpack(
                "!IIIII", data[cursor : cursor + 20]
            )
            return (
                f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
            )
        return f"{mname} {rname}"
    return rdata.hex()


def parse_response(data: bytes) -> DNSResponse:
    if len(data) < 12:
        raise DNSFormatError("packet shorter than header")
    query_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        "!HHHHHH", data[:12]
    )
    rcode = flags & 0x000F
    truncated = bool(flags & 0x0200)
    response = DNSResponse(
        query_id=query_id,
        flags=flags,
        rcode=rcode,
        rcode_name=RCODES.get(rcode, f"RCODE{rcode}"),
        truncated=truncated,
    )
    offset = 12
    for _ in range(qdcount):
        name, offset = decode_name(data, offset)
        if offset + 4 > len(data):
            raise DNSFormatError("truncated question")
        qtype, _qclass = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        response.question.append((name, RTYPES.get(qtype, str(qtype))))

    def _read_records(count: int, target: list[DNSRecord]) -> None:
        nonlocal offset
        for _ in range(count):
            name, offset = decode_name(data, offset)
            if offset + 10 > len(data):
                raise DNSFormatError("truncated resource record")
            rtype_code, _rclass, ttl, rdlength = struct.unpack(
                "!HHIH", data[offset : offset + 10]
            )
            offset += 10
            if offset + rdlength > len(data):
                raise DNSFormatError("rdata runs past end of packet")
            value = _decode_rdata(data, rtype_code, offset, rdlength, ttl)
            offset += rdlength
            target.append(
                DNSRecord(
                    name=name,
                    rtype=RTYPES.get(rtype_code, f"TYPE{rtype_code}"),
                    rtype_code=rtype_code,
                    ttl=ttl,
                    value=value,
                )
            )

    _read_records(ancount, response.answers)
    _read_records(nscount, response.authority)
    _read_records(arcount, response.additional)
    return response


def cname_chain(records: Iterable[DNSRecord]) -> list[str]:
    return [record.value for record in records if record.rtype == "CNAME"]
