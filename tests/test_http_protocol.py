"""Offline tests for HTTP fingerprint helpers and stream decoders (no sockets)."""

import asyncio
import json
import unittest
from unittest.mock import patch

from core.scope_manager import ScopeManager
from protocols.http_protocol import (
    HTTPResult,
    _read_chunked,
    detect_technologies,
    extract_title,
    fetch,
)


class HttpHelperTests(unittest.TestCase):
    def test_extract_title(self):
        body = b"<html><head><title>  Hello &amp; World  </title></head></html>"
        self.assertEqual(extract_title(body, "text/html"), "Hello & World")

    def test_detect_from_headers_and_meta(self):
        headers = {
            "server": "cloudflare",
            "x-powered-by": "PHP/8.2.1",
            "set-cookie": "PHPSESSID=abc; path=/",
            "x-vercel-id": "iad1::abc",
        }
        body = b'<meta name="generator" content="WordPress 6.5">'
        tech = detect_technologies(headers, body, "text/html; charset=utf-8")
        for expected in ("Cloudflare", "PHP", "Vercel", "WordPress 6.5"):
            self.assertIn(expected, tech)

    def test_no_false_positive_on_empty_headers(self):
        self.assertEqual(detect_technologies({}, b"", ""), [])

    def test_result_serialization_includes_technologies(self):
        result = HTTPResult(url="https://example.com", technologies=["nginx"])
        payload = result.as_dict()
        self.assertEqual(payload["technologies"], ["nginx"])

    def test_sensitive_headers_and_urls_redacted(self):
        result = HTTPResult(
            url="https://example.com/a?token=abcdef1234567890",
            final_url="https://example.com/a?token=abcdef1234567890",
            headers={
                "set-cookie": "session=supersecretvalue",
                "x-api-key": "abcdef1234567890",
                "server": "nginx",
            },
            redirect_chain=["https://example.com/a?api_key=abcdef1234567890"],
        )
        payload = result.as_dict()
        self.assertEqual(payload["headers"]["set-cookie"], "[REDACTED]")
        self.assertEqual(payload["headers"]["x-api-key"], "[REDACTED]")
        self.assertEqual(payload["headers"]["server"], "nginx")
        self.assertNotIn("abcdef1234567890", json.dumps(payload))

    def test_read_chunked_respects_hard_limit_on_oversized_chunk(self):
        async def _run():
            reader = asyncio.StreamReader()
            # Declare a 16 MB chunk ("1000000\r\n") but only feed 64 bytes
            # with a 16-byte limit; _read_chunked must stop at 16 bytes
            # without waiting for the remaining 16 MB.
            reader.feed_data(b"1000000\r\n" + b"A" * 64)
            reader.feed_eof()
            return await _read_chunked(reader, limit=16)

        body = asyncio.run(_run())
        self.assertEqual(body, b"A" * 16)

    def test_fetch_blocks_out_of_scope_redirect_and_private_ip(self):
        scope = ScopeManager("example.com")

        # 1) Redirect to out-of-scope domain is rejected
        async def fake_single_request(url, _scope, **_kwargs):
            return HTTPResult(
                url=url,
                final_url=url,
                scheme="https",
                hostname="example.com",
                status=302,
                headers={"location": "https://evil.org/phish"},
            )

        with patch("protocols.http_protocol._single_request", side_effect=fake_single_request):
            res = asyncio.run(fetch("https://example.com/", scope))
        self.assertIn("out-of-scope", res.redirect_rejected)

        # 2) Private IP resolved by DNS is blocked by ScopeManager
        with patch("core.scope_manager.safe_getaddrinfo", return_value=["127.0.0.1"]):
            res_ssrf = asyncio.run(fetch("https://example.com/", scope))
        self.assertIn("private/reserved", res_ssrf.error)


if __name__ == "__main__":
    unittest.main()
