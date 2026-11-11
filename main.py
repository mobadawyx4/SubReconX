#!/usr/bin/env python3
"""SubReconX command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from config import (
    DEFAULT_CDX_LIMIT,
    DEFAULT_CONCURRENCY,
    DEFAULT_DB_PATH,
    DEFAULT_RESULTS_DIR,
    DEFAULT_TIMEOUT,
    DEFAULT_WORDLIST,
    MAX_HISTORICAL_URLS,
    TOOL_NAME,
    VERSION,
    ScanConfig,
    ensure_directories,
)
from core.database import Database
from core.domain_validator import DomainValidationError, require_valid_domain
from core.event_logger import EventLogger
from core.orchestrator import Orchestrator
from core.scope_manager import ScopeManager
from utils.configfile import PHASE_NAMES as CONFIG_PHASE_NAMES, ConfigFileError, load_scan_config
from utils.formatting import colorize

PHASE_FLAGS = ("passive", "dns", "live", "historical", "filter", "javascript", "takeover", "report")
CLI_PHASE_FLAGS = {
    "--passive": "passive",
    "--dns": "dns",
    "--live": "live",
    "--tls": "tls",
    "--historical": "historical",
    "--filter": "filter",
    "--sensitive": "sensitive",
    "--javascript": "javascript",
    "--takeover": "takeover",
    "--report": "report",
}


def _cli_phase_flags(argv: list[str] | None) -> set[str]:
    tokens = list(sys.argv[1:] if argv is None else argv)
    found: set[str] = set()
    for token in tokens:
        if token == "--":
            break
        name = token.split("=", 1)[0]
        if name in CLI_PHASE_FLAGS:
            found.add(CLI_PHASE_FLAGS[name])
    return found
DEPENDENCIES = {
    "dns": ("passive",),
    "live": ("passive",),
    "tls": ("passive",),
    "takeover": ("passive", "dns"),
    "filter": ("historical",),
    "sensitive": ("historical",),
    "javascript": ("historical",),
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="subreconx",
        description=(
            f"{TOOL_NAME} - standalone reconnaissance and exposure-intelligence "
            "framework for AUTHORIZED targets only."
        ),
        epilog=(
            "Examples:\n"
            "  python main.py example.com\n"
            "  python main.py example.com --passive --historical\n"
            "  python main.py example.com --dns --live\n"
            "  python main.py example.com --historical --filter\n"
            "  python main.py example.com --takeover\n"
            "  python main.py example.com --resume\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("domain", nargs="?", help="authorized root domain, e.g. example.com")
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {VERSION}")

    parser.add_argument("--passive", action="store_true", help="passive subdomain enumeration")
    parser.add_argument("--dns", action="store_true", help="native DNS analysis")
    parser.add_argument("--live", action="store_true", help="safe HTTP/HTTPS probing")
    parser.add_argument("--tls", action="store_true", help="TLS certificate inspection")
    parser.add_argument("--no-tls", action="store_true", help="disable TLS inspection")
    parser.add_argument("--historical", action="store_true", help="historical URL collection")
    parser.add_argument("--filter", action="store_true", help="file-extension classification")
    parser.add_argument("--sensitive", action="store_true", help="sensitive path/parameter indicators")
    parser.add_argument("--javascript", action="store_true", help="JavaScript asset inventory")
    parser.add_argument("--takeover", action="store_true", help="passive takeover analysis")
    parser.add_argument("--report", action="store_true", help="generate HTML/JSON/TXT reports")

    parser.add_argument("--output", default=str(DEFAULT_RESULTS_DIR), help="results root directory")
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH), help="SQLite database path")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="network timeout (s)")
    parser.add_argument(
        "--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="bounded concurrency"
    )
    parser.add_argument("--scope-file", help="scope configuration file (text or Bug Bounty JSON)")
    parser.add_argument(
        "--strict-scope",
        action="store_true",
        help="do not assume *.domain is authorized unless explicitly listed in wildcard scope",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.0,
        help="maximum HTTP requests per second (0 = bounded by concurrency)",
    )
    parser.add_argument(
        "--passive-only",
        action="store_true",
        help="disable active HTTP/TLS/DNS probing (passive intelligence only)",
    )
    parser.add_argument(
        "--check-historical-urls",
        action="store_true",
        help="perform bounded, rate-limited HTTP checks on authorized historical URLs",
    )
    parser.add_argument(
        "--max-url-checks",
        type=int,
        default=50,
        help="cap on optional historical URL HTTP checks (default: 50)",
    )
    parser.add_argument("--resume", action="store_true", help="reuse previous results from the database")
    parser.add_argument("--no-cache", action="store_true", help="disable passive-source cache")
    parser.add_argument("--retries", type=int, default=2, help="retries for transient HTTP failures")
    parser.add_argument(
        "--config", help="optional JSON file with default settings (CLI flags override)"
    )
    parser.add_argument("--max-urls", type=int, default=MAX_HISTORICAL_URLS, help="historical URL cap")
    parser.add_argument("--cdx-limit", type=int, default=DEFAULT_CDX_LIMIT, help="CDX page limit")
    parser.add_argument(
        "--commoncrawl-crawls", type=int, default=1, help="number of Common Crawl indexes"
    )
    parser.add_argument(
        "--wordlist", action="store_true", help="enable rate-limited DNS wordlist discovery"
    )
    parser.add_argument("--wordlist-path", help="custom subdomain wordlist")
    parser.add_argument("--js-analysis", action="store_true", help="statically analyse in-scope JS")
    parser.add_argument("--quiet", action="store_true", help="suppress console output")
    parser.add_argument("--verbose", action="store_true", help="debug logging")
    parser.add_argument("-y", "--yes", action="store_true", help="confirm authorization non-interactively")
    parser.add_argument("--clear-cache", action="store_true", help="clear the passive-source cache and exit")
    parser.add_argument("--clear-domain", action="store_true", help="clear stored data for DOMAIN and exit")
    parser.add_argument("--no-banner", action="store_true", help="suppress the ASCII banner")
    return parser


def resolve_phases(args: argparse.Namespace) -> dict[str, bool]:
    cli_phases = set(getattr(args, "_cli_phase_flags", ()) or ())
    config_phases = getattr(args, "_config_phases", None)

    if cli_phases:
        phases = {name: name in cli_phases for name in PHASE_FLAGS}
        phases["tls"] = "tls" in cli_phases
        phases["sensitive"] = "sensitive" in cli_phases
    elif config_phases is not None:
        selected = set(config_phases)
        phases = {name: name in selected for name in PHASE_FLAGS}
        phases["tls"] = "tls" in selected
        phases["sensitive"] = "sensitive" in selected
    else:
        phases = {name: True for name in PHASE_FLAGS}
        phases["tls"] = True
        phases["sensitive"] = True
        phases["report"] = True

    changed = True
    while changed:
        changed = False
        for phase, deps in DEPENDENCIES.items():
            if phases.get(phase):
                for dep in deps:
                    if not phases.get(dep):
                        phases[dep] = True
                        changed = True
    if getattr(args, "no_tls", False):
        phases["tls"] = False
    if getattr(args, "passive_only", False):
        phases["dns"] = False
        phases["live"] = False
        phases["tls"] = False
        phases["takeover"] = False
    return phases


def confirm_authorization(args: argparse.Namespace, phases: dict[str, bool]) -> bool:
    requires_confirmation = any(
        phases.get(name) for name in ("dns", "live", "tls", "takeover")
    ) or bool(args.wordlist)
    if not requires_confirmation:
        return True
    if args.yes:
        return True
    message = (
        "SubReconX will perform active DNS/HTTP/TLS queries against the supplied domain. "
        "Only continue if you have explicit written authorization for this target."
    )
    if not sys.stdin.isatty():
        print(f"[-] {message}\n[-] Non-interactive session: re-run with --yes to confirm.", file=sys.stderr)
        return False
    print(colorize(message, "yellow"))
    try:
        answer = input("Type 'yes' to confirm authorization: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer == "yes"


def build_config(args: argparse.Namespace, domain: str, phases: dict[str, bool]) -> ScanConfig:
    wordlist_path = Path(args.wordlist_path) if args.wordlist_path else DEFAULT_WORDLIST
    return ScanConfig(
        domain=domain,
        output_root=Path(args.output),
        db_path=Path(args.db),
        timeout=args.timeout,
        concurrency=args.concurrency,
        retries=args.retries,
        passive=phases["passive"],
        dns=phases["dns"],
        live=phases["live"],
        tls=phases["tls"],
        historical=phases["historical"],
        filter=phases["filter"],
        sensitive=phases["sensitive"],
        javascript=phases["javascript"],
        takeover=phases["takeover"],
        report=phases["report"],
        scope_file=Path(args.scope_file) if args.scope_file else None,
        strict_scope=bool(getattr(args, "strict_scope", False)),
        rate_limit_rps=float(getattr(args, "rate_limit", 0.0) or 0.0),
        allow_active_probing=not bool(getattr(args, "passive_only", False)),
        check_historical_urls=bool(getattr(args, "check_historical_urls", False)),
        max_url_checks=int(getattr(args, "max_url_checks", 50) or 50),
        resume=args.resume,
        use_cache=not args.no_cache,
        wordlist_bruteforce=args.wordlist,
        wordlist_path=wordlist_path,
        js_analysis=args.js_analysis,
        max_urls=args.max_urls,
        cdx_limit=args.cdx_limit,
        commoncrawl_crawls=max(1, args.commoncrawl_crawls),
        assume_authorized=args.yes,
        quiet=args.quiet,
    )


def main(argv: list[str] | None = None) -> int:
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--config")
    pre_args, _ = pre_parser.parse_known_args(argv)
    parser = build_parser()
    config_phases = None
    if pre_args.config:
        try:
            file_defaults = load_scan_config(Path(pre_args.config))
        except ConfigFileError as exc:
            print(f"[-] {exc}", file=sys.stderr)
            return 2
        if any(name in file_defaults for name in CONFIG_PHASE_NAMES):
            config_phases = [
                name for name in CONFIG_PHASE_NAMES if file_defaults.get(name)
            ]
        parser.set_defaults(**file_defaults)
    args = parser.parse_args(argv)
    args._cli_phase_flags = _cli_phase_flags(argv)
    args._config_phases = config_phases
    logger = EventLogger(quiet=args.quiet, verbose=args.verbose)

    if not args.no_banner and not args.quiet:
        logger.banner(TOOL_NAME, VERSION)

    if args.clear_cache:
        db = Database(args.db)
        try:
            count = db.clear_cache()
            logger.success(f"cache cleared ({count} entries)")
        finally:
            db.close()
        if not args.domain:
            return 0

    if not args.domain:
        parser.print_help()
        return 2

    try:
        domain = require_valid_domain(args.domain)
    except DomainValidationError as exc:
        logger.error(str(exc))
        return 2

    phases = resolve_phases(args)

    if args.clear_domain:
        db = Database(args.db)
        try:
            db.clear_domain(domain)
            logger.success(f"stored data cleared for {domain}")
        finally:
            db.close()
        return 0

    if not confirm_authorization(args, phases):
        logger.error("authorization not confirmed; aborting")
        return 3

    config = build_config(args, domain, phases)
    try:
        ensure_directories(config)
    except OSError as exc:
        logger.error(f"cannot create output directory: {exc}")
        return 2

    scope = ScopeManager.from_scope_file(
        domain,
        config.scope_file,
        strict_scope=config.strict_scope,
        rate_limit_rps=config.rate_limit_rps,
        allow_active_probing=config.allow_active_probing,
    )
    if config.scope_file and not config.scope_file.exists():
        logger.warn(f"scope file not found: {config.scope_file}")

    db = Database(config.db_path)
    logger.info(f"target: {domain}")
    logger.info(f"output: {config.output_dir}")
    logger.info(f"phases: {', '.join(config.enabled_phases())}")
    if config.resume:
        previous = db.get_scans(domain, limit=1)
        if previous:
            logger.info("resume: previous scan history found")

    orchestrator = Orchestrator(config, scope, logger, db)
    exit_code = 0
    try:
        asyncio.run(orchestrator.run())
    except KeyboardInterrupt:
        logger.warn("interrupted by user")
        exit_code = 130
    except Exception as exc:  # noqa: BLE001 - top-level safety net
        logger.error(f"scan failed: {exc}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        exit_code = 1
    finally:
        db.close()

    if not args.quiet:
        logger.summary()
        logger.info(f"results directory: {config.output_dir}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
