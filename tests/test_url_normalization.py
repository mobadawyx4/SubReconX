"""Unit tests for URL normalization, parsing and de-duplication."""

import unittest

from engines.url_normalizer import normalize_urls
from utils.url_utils import (
    dedupe_urls,
    extract_param_names,
    get_extension,
    get_path,
    normalize_url,
    resolve_redirect,
    split_url,
)


class URLNormalizationTests(unittest.TestCase):
    def test_lowercases_scheme_and_host(self):
        self.assertEqual(normalize_url("HTTP://WWW.Example.COM/Path"), "http://www.example.com/Path")

    def test_removes_default_ports(self):
        self.assertEqual(normalize_url("http://example.com:80/a"), "http://example.com/a")
        self.assertEqual(normalize_url("https://example.com:443/a"), "https://example.com/a")

    def test_keeps_non_default_port(self):
        self.assertEqual(normalize_url("https://example.com:8443/a"), "https://example.com:8443/a")

    def test_removes_fragment(self):
        self.assertEqual(normalize_url("https://example.com/a#section"), "https://example.com/a")

    def test_empty_path_becomes_slash(self):
        self.assertEqual(normalize_url("https://example.com"), "https://example.com/")
        self.assertEqual(normalize_url("https://example.com?x=1"), "https://example.com/?x=1")

    def test_strips_userinfo(self):
        self.assertEqual(
            normalize_url("https://user:pass@example.com/a"), "https://example.com/a"
        )

    def test_preserves_query_order_and_values(self):
        self.assertEqual(
            normalize_url("https://example.com/a?b=2&a=1"),
            "https://example.com/a?b=2&a=1",
        )

    def test_uppercases_percent_escapes(self):
        self.assertEqual(normalize_url("https://example.com/a%2fb"), "https://example.com/a%2Fb")

    def test_scheme_relative(self):
        self.assertEqual(normalize_url("//Example.com/a"), "http://example.com/a")

    def test_trailing_dot_host(self):
        self.assertEqual(normalize_url("https://example.com./a"), "https://example.com/a")

    def test_rejects_malformed(self):
        self.assertIsNone(normalize_url(""))
        self.assertIsNone(normalize_url("javascript:alert(1)"))
        self.assertIsNone(normalize_url("https:///nohost"))
        self.assertIsNone(normalize_url("http://exa mple.com/"))
        self.assertIsNone(normalize_url("ftp://example.com/a"))

    def test_distinct_queries_not_merged(self):
        self.assertNotEqual(
            normalize_url("https://example.com/a?id=1"),
            normalize_url("https://example.com/a?id=2"),
        )
        self.assertNotEqual(
            normalize_url("https://example.com/a"), normalize_url("https://example.com/b")
        )

    def test_dedupe_urls(self):
        urls = [
            "https://example.com/a",
            "https://EXAMPLE.com/a#frag",
            "https://example.com/a?x=1",
            "https://example.com/a",
        ]
        self.assertEqual(
            dedupe_urls(urls),
            ["https://example.com/a", "https://example.com/a?x=1"],
        )

    def test_normalize_urls_result(self):
        result = normalize_urls(
            ["https://example.com/a", "https://example.com/a#x", "not a url"]
        )
        self.assertEqual(len(result.pairs), 1)
        self.assertEqual(len(result.duplicates), 1)
        self.assertEqual(len(result.malformed), 1)

    def test_extract_param_names(self):
        self.assertEqual(
            extract_param_names("A=1&b=2&a=3&flag"), ["a", "b", "flag"]
        )

    def test_get_extension(self):
        self.assertEqual(get_extension("https://example.com/app.JS?x=1"), "js")
        self.assertEqual(get_extension("https://example.com/archive.tar.gz"), "gz")
        self.assertEqual(get_extension("https://example.com/.env"), "env")
        self.assertEqual(get_extension("https://example.com/.env.production"), "production")
        self.assertEqual(get_extension("https://example.com/path/"), "")
        self.assertEqual(get_extension("https://example.com/?file=x.js"), "")

    def test_get_path(self):
        self.assertEqual(get_path("https://example.com/a/b?x=1"), "/a/b")

    def test_split_url_valid(self):
        parsed = split_url("https://example.com:8443/a?x=1")
        self.assertTrue(parsed.valid)
        self.assertEqual(parsed.host, "example.com")
        self.assertEqual(parsed.port, 8443)
        self.assertEqual(parsed.params, ["x"])

    def test_resolve_redirect(self):
        self.assertEqual(
            resolve_redirect("https://example.com/a/b", "/c"),
            "https://example.com/c",
        )
        self.assertEqual(
            resolve_redirect("https://example.com/a/b", "https://example.com/d"),
            "https://example.com/d",
        )
        self.assertIsNone(resolve_redirect("https://example.com/a", "javascript:alert(1)"))


if __name__ == "__main__":
    unittest.main()
