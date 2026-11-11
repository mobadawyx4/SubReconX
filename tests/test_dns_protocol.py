"""Unit tests for the native DNS wire protocol."""

import socket
import struct
import unittest

from protocols.dns_protocol import (
    DNSFormatError,
    build_query,
    decode_name,
    encode_name,
    parse_response,
)


def _header(query_id, flags, qd=1, an=0, ns=0, ar=0):
    return struct.pack("!HHHHHH", query_id, flags, qd, an, ns, ar)


def _question(name, qtype=1):
    return encode_name(name) + struct.pack("!HH", qtype, 1)


def _rr_pointer(qtype, rdata, ttl=300):
    return b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, ttl, len(rdata)) + rdata


class DNSEncodingTests(unittest.TestCase):
    def test_encode_name(self):
        self.assertEqual(encode_name("www.example.com"), b"\x03www\x07example\x03com\x00")

    def test_build_query_header_and_question(self):
        packet = build_query("example.com", "A", query_id=0x1234)
        qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", packet[:12])
        self.assertEqual(qid, 0x1234)
        self.assertEqual(flags & 0x0100, 0x0100)  # recursion desired
        self.assertEqual((qd, an, ns, ar), (1, 0, 0, 0))
        self.assertEqual(packet[12:], _question("example.com", 1))

    def test_build_query_rejects_unknown_type(self):
        with self.assertRaises(DNSFormatError):
            build_query("example.com", "HINFO")

    def test_decode_name_plain(self):
        data = encode_name("a.example.com")
        name, offset = decode_name(data, 0)
        self.assertEqual(name, "a.example.com")
        self.assertEqual(offset, len(data))

    def test_decode_name_compression_pointer(self):
        first = encode_name("www.example.com")
        data = first + b"\xc0\x00"
        name, offset = decode_name(data, len(first))
        self.assertEqual(name, "www.example.com")
        self.assertEqual(offset, len(first) + 2)

    def test_decode_name_rejects_pointer_loop(self):
        with self.assertRaises(DNSFormatError):
            decode_name(b"\xc0\x00", 0)


class DNSResponseParsingTests(unittest.TestCase):
    def test_a_record(self):
        packet = (
            _header(0x1234, 0x8180, an=1)
            + _question("www.example.com", 1)
            + _rr_pointer(1, socket.inet_aton("93.184.216.34"))
        )
        response = parse_response(packet)
        self.assertTrue(response.success)
        self.assertEqual(response.rcode_name, "NOERROR")
        self.assertEqual(response.question[0], ("www.example.com", "A"))
        self.assertEqual(len(response.answers), 1)
        self.assertEqual(response.answers[0].rtype, "A")
        self.assertEqual(response.answers[0].value, "93.184.216.34")
        self.assertEqual(response.answers[0].ttl, 300)

    def test_cname_record(self):
        target = encode_name("edge.example.net")
        packet = (
            _header(0x2222, 0x8180, an=1)
            + _question("www.example.com", 5)
            + _rr_pointer(5, target)
        )
        response = parse_response(packet)
        self.assertEqual(response.of_type("CNAME")[0].value, "edge.example.net")

    def test_aaaa_record(self):
        addr = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        packet = (
            _header(0x3333, 0x8180, an=1)
            + _question("v6.example.com", 28)
            + _rr_pointer(28, addr)
        )
        response = parse_response(packet)
        self.assertEqual(response.answers[0].rtype, "AAAA")
        self.assertEqual(response.answers[0].value, "2001:db8::1")

    def test_mx_record(self):
        rdata = struct.pack("!H", 10) + encode_name("mail.example.com")
        packet = (
            _header(0x4444, 0x8180, an=1)
            + _question("example.com", 15)
            + _rr_pointer(15, rdata)
        )
        response = parse_response(packet)
        self.assertEqual(response.answers[0].rtype, "MX")
        self.assertEqual(response.answers[0].value, "10 mail.example.com")

    def test_txt_record(self):
        rdata = b"\x0bhello world"
        packet = (
            _header(0x5555, 0x8180, an=1)
            + _question("example.com", 16)
            + _rr_pointer(16, rdata)
        )
        response = parse_response(packet)
        self.assertEqual(response.answers[0].value, "hello world")

    def test_soa_record(self):
        rdata = (
            encode_name("ns1.example.com")
            + encode_name("hostmaster.example.com")
            + struct.pack("!IIIII", 2024010101, 7200, 3600, 1209600, 300)
        )
        packet = (
            _header(0x6666, 0x8180, an=1)
            + _question("example.com", 6)
            + _rr_pointer(6, rdata)
        )
        response = parse_response(packet)
        self.assertEqual(response.answers[0].rtype, "SOA")
        self.assertIn("ns1.example.com", response.answers[0].value)
        self.assertIn("2024010101", response.answers[0].value)

    def test_nxdomain(self):
        packet = _header(0x7777, 0x8183) + _question("missing.example.com", 1)
        response = parse_response(packet)
        self.assertFalse(response.success)
        self.assertEqual(response.rcode, 3)
        self.assertEqual(response.rcode_name, "NXDOMAIN")

    def test_truncated_flag(self):
        packet = _header(0x8888, 0x8380) + _question("example.com", 1)
        response = parse_response(packet)
        self.assertTrue(response.truncated)

    def test_short_packet_raises(self):
        with self.assertRaises(DNSFormatError):
            parse_response(b"\x00\x01")

    def test_unknown_rtype_preserved_as_hex(self):
        packet = (
            _header(0x9999, 0x8180, an=1)
            + _question("example.com", 99)
            + _rr_pointer(99, b"\xde\xad\xbe\xef")
        )
        response = parse_response(packet)
        self.assertEqual(response.answers[0].rtype, "TYPE99")
        self.assertEqual(response.answers[0].value, "deadbeef")

    def test_dangling_cname_not_marked_resolved(self):
        from engines.dns_engine import ResolvedHost

        dangling_host = ResolvedHost(
            hostname="old.example.com",
            cname=["missing.github.io"],
            dangling=True,
        )
        self.assertFalse(dangling_host.resolved)

        valid_cname_host = ResolvedHost(
            hostname="www.example.com",
            cname=["edge.example.com"],
            a=["93.184.216.34"],
            dangling=False,
        )
        self.assertTrue(valid_cname_host.resolved)


if __name__ == "__main__":
    unittest.main()
