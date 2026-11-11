"""Unit tests for domain validation and root-domain boundaries."""

import unittest

from core.domain_validator import DomainValidationError, require_valid_domain, validate_domain
from utils.validators import (
    is_valid_domain,
    is_valid_hostname,
    is_within_domain,
    normalize_hostname,
)


class DomainValidationTests(unittest.TestCase):
    def test_valid_domains(self):
        for value in ("example.com", "sub.example.co.uk", "xn--bcher-kva.example"):
            with self.subTest(value=value):
                result = validate_domain(value)
                self.assertTrue(result.ok, result.reason)

    def test_normalizes_case_and_trailing_dot(self):
        self.assertEqual(require_valid_domain("Example.COM."), "example.com")
        self.assertEqual(normalize_hostname("WWW.Example.com."), "www.example.com")

    def test_rejects_urls(self):
        result = validate_domain("https://example.com/path")
        self.assertFalse(result.ok)
        self.assertIn("bare domain", result.reason)

    def test_rejects_ip_literals(self):
        self.assertFalse(validate_domain("127.0.0.1").ok)
        self.assertFalse(validate_domain("192.168.1.1").ok)
        self.assertFalse(validate_domain("::1").ok)

    def test_rejects_single_label_and_public_suffix(self):
        self.assertFalse(validate_domain("localhost").ok)
        self.assertFalse(validate_domain("com").ok)
        self.assertFalse(validate_domain("co.uk").ok)

    def test_rejects_wildcards_and_paths(self):
        self.assertFalse(validate_domain("*.example.com").ok)
        self.assertFalse(validate_domain("example.com/admin").ok)
        self.assertFalse(validate_domain("exa mple.com").ok)

    def test_rejects_bad_labels(self):
        self.assertFalse(validate_domain("-example.com").ok)
        self.assertFalse(validate_domain("example-.com").ok)
        self.assertFalse(validate_domain("a" * 64 + ".com").ok)

    def test_require_raises(self):
        with self.assertRaises(DomainValidationError):
            require_valid_domain("not a domain")

    def test_hostname_rules(self):
        self.assertTrue(is_valid_hostname("a.b.example.com"))
        self.assertFalse(is_valid_hostname("a..b.com"))
        self.assertFalse(is_valid_hostname("-a.com"))
        self.assertFalse(is_valid_hostname("example.123"))

    def test_root_boundary_is_label_aware(self):
        self.assertTrue(is_within_domain("www.example.com", "example.com"))
        self.assertTrue(is_within_domain("example.com", "example.com"))
        self.assertFalse(is_within_domain("evil-example.com", "example.com"))
        self.assertFalse(is_within_domain("example.com.evil.net", "example.com"))
        self.assertFalse(is_within_domain("sub.example.co", "example.com"))


if __name__ == "__main__":
    unittest.main()
