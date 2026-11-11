"""Unit tests for authorized-scope and SSRF enforcement."""

import tempfile
import unittest
from pathlib import Path

from core.scope_manager import ScopeManager
from utils.network import assess_ip, filter_safe_ips, is_public_ip
from utils.url_utils import resolve_redirect


class IPSafetyTests(unittest.TestCase):
    def test_private_and_reserved_rejected(self):
        blocked = [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:127.0.0.1",
        ]
        for value in blocked:
            with self.subTest(value=value):
                self.assertFalse(assess_ip(value).safe, assess_ip(value).reason)
                self.assertFalse(is_public_ip(value))

    def test_public_addresses_allowed(self):
        for value in ("93.184.216.34", "8.8.8.8", "2001:4860:4860::8888"):
            with self.subTest(value=value):
                self.assertTrue(assess_ip(value).safe)

    def test_filter_safe_ips(self):
        self.assertEqual(
            filter_safe_ips(["127.0.0.1", "8.8.8.8", "10.0.0.1"]), ["8.8.8.8"]
        )


class ScopeEnforcementTests(unittest.TestCase):
    def setUp(self):
        self.scope = ScopeManager("example.com")

    def test_in_scope(self):
        self.assertTrue(self.scope.is_in_scope("example.com"))
        self.assertTrue(self.scope.is_in_scope("www.example.com"))
        self.assertTrue(self.scope.is_in_scope("deep.api.example.com"))

    def test_out_of_scope_boundaries(self):
        self.assertFalse(self.scope.is_in_scope("evil-example.com"))
        self.assertFalse(self.scope.is_in_scope("example.com.evil.net"))
        self.assertFalse(self.scope.is_in_scope("other.com"))
        self.assertFalse(self.scope.is_in_scope(""))

    def test_check_url(self):
        self.assertTrue(self.scope.check_url("https://api.example.com/x"))
        self.assertFalse(self.scope.check_url("https://evil.com/x"))
        self.assertFalse(self.scope.check_url("ftp://example.com/x"))
        self.assertFalse(self.scope.check_url("https://example.com:22/x"))
        self.assertTrue(self.scope.check_url("https://example.com:8443/x"))
        self.assertTrue(self.scope.check_url("https://example.com:22/x", allow_any_port=True))
        self.assertFalse(self.scope.check_url("https://*.example.com/x"))

    def test_redirect_validation(self):
        target = resolve_redirect("https://example.com/a", "https://evil.com/steal")
        self.assertEqual(target, "https://evil.com/steal")
        self.assertFalse(self.scope.check_url(target))

        okay = resolve_redirect("https://example.com/a", "/safe")
        self.assertEqual(okay, "https://example.com/safe")
        self.assertTrue(self.scope.check_url(okay))

    def test_connect_ip_guard(self):
        self.assertTrue(self.scope.verify_connect_ip("example.com", "8.8.8.8"))
        self.assertFalse(self.scope.verify_connect_ip("example.com", "127.0.0.1"))
        self.assertFalse(self.scope.verify_connect_ip("evil.com", "8.8.8.8"))

    def test_extra_scope_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.txt"
            path.write_text("# comment\npartner.test\n*.cdn.example.net\n", encoding="utf-8")
            scope = ScopeManager.from_scope_file("example.com", path)
            self.assertTrue(scope.is_in_scope("partner.test"))
            self.assertTrue(scope.is_in_scope("x.cdn.example.net"))
            self.assertFalse(scope.is_in_scope("unrelated.test"))

    def test_wildcard_not_connectable(self):
        decision = self.scope.check_host("*.example.com")
        self.assertFalse(decision)
        self.assertIn("wildcard", decision.reason)


if __name__ == "__main__":
    unittest.main()
