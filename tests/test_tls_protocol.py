"""Offline tests for TLS certificate helpers."""

import re
import ssl
import unittest
from pathlib import Path

from protocols.tls_protocol import _decode_der, _extract_sans, hostname_matches

SYSTEM_BUNDLE = Path("/etc/ssl/certs/ca-certificates.crt")


def _first_system_cert() -> bytes | None:
    if not SYSTEM_BUNDLE.exists():
        return None
    text = SYSTEM_BUNDLE.read_text(encoding="utf-8", errors="ignore")
    match = re.search(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, re.S
    )
    if not match:
        return None
    return ssl.PEM_cert_to_DER_cert(match.group(0))


class TlsHelperTests(unittest.TestCase):
    def test_sans_extraction(self):
        cert = {
            "subjectAltName": (
                ("DNS", "example.com"),
                ("DNS", "www.example.com"),
                ("IP Address", "192.0.2.1"),
            )
        }
        self.assertEqual(
            _extract_sans(cert), ["example.com", "www.example.com", "192.0.2.1"]
        )

    def test_hostname_matching_wildcard_and_ip(self):
        cert = {"subjectAltName": (("DNS", "*.example.com"), ("IP Address", "192.0.2.1"))}
        self.assertTrue(hostname_matches("api.example.com", cert))
        self.assertFalse(hostname_matches("example.com", cert))
        self.assertTrue(hostname_matches("192.0.2.1", cert))
        self.assertFalse(hostname_matches("198.51.100.1", cert))

    def test_decode_der_with_system_certificate(self):
        der = _first_system_cert()
        if der is None:
            self.skipTest("no system CA bundle available")
        decoded = _decode_der(der)
        self.assertIsInstance(decoded, dict)
        self.assertIn("subject", decoded)
        self.assertIn("issuer", decoded)

    def test_decode_der_empty(self):
        self.assertEqual(_decode_der(b""), {})


if __name__ == "__main__":
    unittest.main()
