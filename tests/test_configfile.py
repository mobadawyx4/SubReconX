"""Unit tests for the optional JSON configuration loader and phase resolver."""

import json
import tempfile
import unittest
from pathlib import Path

from main import build_parser, resolve_phases
from utils.configfile import ConfigFileError, load_scan_config


class ConfigFileTests(unittest.TestCase):
    def _write(self, directory: str, payload) -> Path:
        path = Path(directory) / "config.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_valid_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(
                tmp,
                {
                    "phases": ["passive", "dns", "report"],
                    "timeout": 3.5,
                    "concurrency": 7,
                    "retries": 1,
                    "resume": True,
                },
            )
            data = load_scan_config(path)
        self.assertTrue(data["passive"])
        self.assertTrue(data["dns"])
        self.assertTrue(data["report"])
        self.assertFalse(data["live"])
        self.assertEqual(data["timeout"], 3.5)
        self.assertEqual(data["retries"], 1)

    def test_unknown_key_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, {"evil": True})
            with self.assertRaises(ConfigFileError):
                load_scan_config(path)

    def test_empty_or_unknown_phase_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            for payload in ({"phases": []}, {"phases": ["sqlmap"]}):
                with self.subTest(payload=payload):
                    path = self._write(tmp, payload)
                    with self.assertRaises(ConfigFileError):
                        load_scan_config(path)

    def test_config_defaults_and_cli_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(
                tmp,
                {"phases": ["passive"], "timeout": 4.0, "concurrency": 5},
            )
            parser = build_parser()
            parser.set_defaults(**load_scan_config(path))
            args = parser.parse_args(["example.com", "--timeout", "9"])
            args._cli_phase_flags = set()
            args._config_phases = ["passive"]
            phases = resolve_phases(args)
        self.assertEqual(args.timeout, 9.0)
        self.assertEqual(args.concurrency, 5)
        self.assertTrue(phases["passive"])
        self.assertFalse(phases["live"])
        self.assertFalse(phases["report"])

    def test_cli_phase_flags_override_config_phases(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, {"phases": ["passive", "dns"]})
            parser = build_parser()
            parser.set_defaults(**load_scan_config(path))
            args = parser.parse_args(["example.com", "--report"])
            args._cli_phase_flags = {"report"}
            args._config_phases = ["passive", "dns"]
            phases = resolve_phases(args)
        self.assertTrue(phases["report"])
        self.assertFalse(phases["passive"])
        self.assertFalse(phases["dns"])

    def test_no_tls_only_keeps_defaults(self):
        args = build_parser().parse_args(["example.com", "--no-tls"])
        args._cli_phase_flags = set()
        args._config_phases = None
        phases = resolve_phases(args)
        self.assertFalse(phases["tls"])
        self.assertTrue(phases["passive"])
        self.assertTrue(phases["historical"])
        self.assertTrue(phases["report"])

    def test_sensitive_pulls_historical_dependency(self):
        args = build_parser().parse_args(["example.com", "--sensitive"])
        args._cli_phase_flags = {"sensitive"}
        args._config_phases = None
        phases = resolve_phases(args)
        self.assertTrue(phases["sensitive"])
        self.assertTrue(phases["historical"])
        self.assertFalse(phases["passive"])

    def test_config_tls_phase_and_no_tls_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, {"phases": ["tls"]})
            parser = build_parser()
            parser.set_defaults(**load_scan_config(path))
            args = parser.parse_args(["example.com", "--no-tls"])
            args._cli_phase_flags = set()
            args._config_phases = ["tls"]
            phases = resolve_phases(args)
        self.assertFalse(phases["tls"])
        self.assertTrue(phases["passive"])


if __name__ == "__main__":
    unittest.main()
