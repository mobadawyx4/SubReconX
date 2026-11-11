"""SQLite persistence layer.

All writes are wrapped in transactions.  The schema is designed for
incremental scans: re-running a domain updates existing rows instead of
duplicating them, and previous scan history is preserved in the ``scans``
table.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    started_at REAL NOT NULL,
    finished_at REAL,
    status TEXT NOT NULL DEFAULT 'running',
    config_json TEXT
);

CREATE TABLE IF NOT EXISTS subdomains (
    domain TEXT NOT NULL,
    hostname TEXT NOT NULL,
    sources TEXT NOT NULL DEFAULT '[]',
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    PRIMARY KEY (domain, hostname)
);

CREATE TABLE IF NOT EXISTS dns_records (
    domain TEXT NOT NULL,
    hostname TEXT NOT NULL,
    rtype TEXT NOT NULL,
    value TEXT NOT NULL,
    ttl INTEGER,
    status TEXT NOT NULL DEFAULT 'ok',
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    PRIMARY KEY (domain, hostname, rtype, value)
);

CREATE TABLE IF NOT EXISTS http_results (
    domain TEXT NOT NULL,
    url TEXT NOT NULL,
    hostname TEXT NOT NULL,
    scheme TEXT,
    status INTEGER,
    final_url TEXT,
    title TEXT,
    server TEXT,
    content_type TEXT,
    content_length INTEGER,
    elapsed REAL,
    tls_verified INTEGER,
    redirect_chain TEXT,
    technologies TEXT,
    error TEXT,
    last_seen REAL NOT NULL,
    PRIMARY KEY (domain, url)
);

CREATE TABLE IF NOT EXISTS tls_results (
    domain TEXT NOT NULL,
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 443,
    connected INTEGER NOT NULL DEFAULT 0,
    verified INTEGER NOT NULL DEFAULT 0,
    verification_error TEXT,
    protocol TEXT,
    cipher TEXT,
    subject TEXT,
    issuer TEXT,
    serial_number TEXT,
    not_before TEXT,
    not_after TEXT,
    sans TEXT,
    expired INTEGER,
    days_until_expiry INTEGER,
    hostname_matches INTEGER,
    error TEXT,
    last_seen REAL NOT NULL,
    PRIMARY KEY (domain, hostname, port)
);

CREATE TABLE IF NOT EXISTS historical_urls (
    domain TEXT NOT NULL,
    url TEXT NOT NULL,
    normalized TEXT NOT NULL,
    hostname TEXT NOT NULL,
    path TEXT,
    extension TEXT,
    source TEXT NOT NULL,
    timestamp TEXT,
    last_seen REAL NOT NULL,
    PRIMARY KEY (domain, normalized)
);

CREATE TABLE IF NOT EXISTS js_assets (
    domain TEXT NOT NULL,
    normalized TEXT NOT NULL,
    url TEXT,
    hostname TEXT,
    sources TEXT,
    extension TEXT,
    params TEXT,
    live_status INTEGER,
    content_length INTEGER,
    endpoints TEXT,
    analyzed INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    last_seen REAL NOT NULL,
    PRIMARY KEY (domain, normalized)
);

CREATE TABLE IF NOT EXISTS file_classifications (
    domain TEXT NOT NULL,
    category TEXT NOT NULL,
    url TEXT NOT NULL,
    normalized TEXT NOT NULL,
    last_seen REAL NOT NULL,
    PRIMARY KEY (domain, category, normalized)
);

CREATE TABLE IF NOT EXISTS exposure_indicators (
    domain TEXT NOT NULL,
    category TEXT NOT NULL,
    indicator TEXT NOT NULL,
    url TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'informational',
    last_seen REAL NOT NULL,
    PRIMARY KEY (domain, category, indicator, url)
);

CREATE TABLE IF NOT EXISTS takeover_findings (
    domain TEXT NOT NULL,
    hostname TEXT NOT NULL,
    cname_target TEXT,
    provider TEXT,
    confidence REAL,
    classification TEXT,
    evidence TEXT,
    last_seen REAL NOT NULL,
    PRIMARY KEY (domain, hostname)
);

CREATE TABLE IF NOT EXISTS source_cache (
    source TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    PRIMARY KEY (source, cache_key)
);

CREATE TABLE IF NOT EXISTS scan_meta (
    domain TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT,
    updated_at REAL NOT NULL,
    PRIMARY KEY (domain, key)
);

CREATE INDEX IF NOT EXISTS idx_subdomains_domain ON subdomains(domain);
CREATE INDEX IF NOT EXISTS idx_dns_domain_host ON dns_records(domain, hostname);
CREATE INDEX IF NOT EXISTS idx_http_domain ON http_results(domain);
CREATE INDEX IF NOT EXISTS idx_hist_domain ON historical_urls(domain);
"""


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=30.0)
        self.conn.row_factory = sqlite3.Row
        self._in_tx = False
        self._init_schema()

    def _init_schema(self) -> None:
        with self.transaction() as cur:
            cur.executescript(SCHEMA)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Cursor]:
        if self._in_tx:
            cur = self.conn.cursor()
            try:
                yield cur
            finally:
                cur.close()
            return
        self._in_tx = True
        cur = self.conn.cursor()
        try:
            cur.execute("BEGIN")
            yield cur
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        finally:
            self._in_tx = False
            cur.close()

    def close(self) -> None:
        try:
            self.conn.close()
        except sqlite3.Error:
            pass

    # -- scans ---------------------------------------------------------
    def start_scan(self, domain: str, config: dict | None = None) -> int:
        with self.transaction() as cur:
            cur.execute(
                "INSERT INTO scans(domain, started_at, status, config_json) VALUES(?,?,?,?)",
                (domain, time.time(), "running", json.dumps(config or {}, default=str)),
            )
            return int(cur.lastrowid)

    def finish_scan(self, scan_id: int, status: str = "completed") -> None:
        with self.transaction() as cur:
            cur.execute(
                "UPDATE scans SET finished_at=?, status=? WHERE id=?",
                (time.time(), status, scan_id),
            )

    # -- subdomains ----------------------------------------------------
    def upsert_subdomain(self, domain: str, hostname: str, source: str) -> None:
        now = time.time()
        with self.transaction() as cur:
            row = cur.execute(
                "SELECT sources FROM subdomains WHERE domain=? AND hostname=?",
                (domain, hostname),
            ).fetchone()
            if row is None:
                cur.execute(
                    "INSERT INTO subdomains(domain, hostname, sources, first_seen, last_seen)"
                    " VALUES(?,?,?,?,?)",
                    (domain, hostname, json.dumps([source]), now, now),
                )
            else:
                try:
                    sources = json.loads(row["sources"])
                except (json.JSONDecodeError, TypeError):
                    sources = []
                if source not in sources:
                    sources.append(source)
                cur.execute(
                    "UPDATE subdomains SET sources=?, last_seen=? WHERE domain=? AND hostname=?",
                    (json.dumps(sources), now, domain, hostname),
                )

    def upsert_subdomains(self, domain: str, items: Iterable[tuple[str, str]]) -> None:
        with self.transaction():
            for hostname, source in items:
                self.upsert_subdomain(domain, hostname, source)

    def get_subdomains(self, domain: str) -> list[dict]:
        cur = self.conn.execute(
            "SELECT * FROM subdomains WHERE domain=? ORDER BY hostname", (domain,)
        )
        return [dict(row) for row in cur.fetchall()]

    def count_subdomains(self, domain: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS c FROM subdomains WHERE domain=?", (domain,)
        ).fetchone()
        return int(row["c"]) if row else 0

    # -- dns -----------------------------------------------------------
    def add_dns_record(
        self,
        domain: str,
        hostname: str,
        rtype: str,
        value: str,
        ttl: int | None = None,
        status: str = "ok",
    ) -> None:
        now = time.time()
        with self.transaction() as cur:
            cur.execute(
                "INSERT INTO dns_records(domain, hostname, rtype, value, ttl, status,"
                " first_seen, last_seen) VALUES(?,?,?,?,?,?,?,?)"
                " ON CONFLICT(domain, hostname, rtype, value) DO UPDATE SET"
                " last_seen=excluded.last_seen, status=excluded.status, ttl=excluded.ttl",
                (domain, hostname, rtype, value, ttl, status, now, now),
            )

    def get_dns_records(self, domain: str) -> list[dict]:
        cur = self.conn.execute(
            "SELECT * FROM dns_records WHERE domain=? ORDER BY hostname, rtype", (domain,)
        )
        return [dict(row) for row in cur.fetchall()]

    # -- http ----------------------------------------------------------
    def add_http_result(self, domain: str, record: dict) -> None:
        now = time.time()
        with self.transaction() as cur:
            cur.execute(
                "INSERT INTO http_results(domain, url, hostname, scheme, status, final_url,"
                " title, server, content_type, content_length, elapsed, tls_verified,"
                " redirect_chain, technologies, error, last_seen)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(domain, url) DO UPDATE SET"
                " status=excluded.status, final_url=excluded.final_url,"
                " title=excluded.title, server=excluded.server,"
                " content_type=excluded.content_type, elapsed=excluded.elapsed,"
                " tls_verified=excluded.tls_verified, redirect_chain=excluded.redirect_chain,"
                " technologies=excluded.technologies,"
                " error=excluded.error, last_seen=excluded.last_seen",
                (
                    domain,
                    record.get("url", ""),
                    record.get("hostname", ""),
                    record.get("scheme", ""),
                    record.get("status"),
                    record.get("final_url", ""),
                    record.get("title", ""),
                    record.get("server", ""),
                    record.get("content_type", ""),
                    record.get("content_length"),
                    record.get("elapsed"),
                    int(bool(record.get("tls_verified"))) if record.get("tls_verified") is not None else None,
                    json.dumps(record.get("redirect_chain", [])),
                    json.dumps(record.get("technologies", [])),
                    record.get("error", ""),
                    now,
                ),
            )

    def get_http_results(self, domain: str) -> list[dict]:
        cur = self.conn.execute(
            "SELECT * FROM http_results WHERE domain=? ORDER BY hostname, scheme", (domain,)
        )
        return [dict(row) for row in cur.fetchall()]

    # -- tls -----------------------------------------------------------
    def add_tls_result(self, domain: str, record: dict) -> None:
        now = time.time()
        with self.transaction() as cur:
            cur.execute(
                "INSERT INTO tls_results(domain, hostname, port, connected, verified,"
                " verification_error, protocol, cipher, subject, issuer, serial_number,"
                " not_before, not_after, sans, expired, days_until_expiry,"
                " hostname_matches, error, last_seen)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(domain, hostname, port) DO UPDATE SET"
                " connected=excluded.connected, verified=excluded.verified,"
                " verification_error=excluded.verification_error,"
                " protocol=excluded.protocol, cipher=excluded.cipher,"
                " subject=excluded.subject, issuer=excluded.issuer,"
                " serial_number=excluded.serial_number, not_before=excluded.not_before,"
                " not_after=excluded.not_after, sans=excluded.sans,"
                " expired=excluded.expired, days_until_expiry=excluded.days_until_expiry,"
                " hostname_matches=excluded.hostname_matches, error=excluded.error,"
                " last_seen=excluded.last_seen",
                (
                    domain,
                    record.get("hostname", ""),
                    int(record.get("port", 443)),
                    1 if record.get("connected") else 0,
                    1 if record.get("verified") else 0,
                    record.get("verification_error", ""),
                    record.get("protocol", ""),
                    record.get("cipher", ""),
                    json.dumps(record.get("subject", {})),
                    json.dumps(record.get("issuer", {})),
                    record.get("serial_number", ""),
                    record.get("not_before", ""),
                    record.get("not_after", ""),
                    json.dumps(record.get("sans", [])),
                    None if record.get("expired") is None else (1 if record["expired"] else 0),
                    record.get("days_until_expiry"),
                    None if record.get("hostname_matches") is None else (1 if record["hostname_matches"] else 0),
                    record.get("error", ""),
                    now,
                ),
            )

    def get_tls_results(self, domain: str) -> list[dict]:
        cur = self.conn.execute(
            "SELECT * FROM tls_results WHERE domain=? ORDER BY hostname, port", (domain,)
        )
        return [dict(row) for row in cur.fetchall()]

    # -- historical ----------------------------------------------------
    def add_historical_url(self, domain: str, record: dict) -> None:
        now = time.time()
        with self.transaction() as cur:
            cur.execute(
                "INSERT INTO historical_urls(domain, url, normalized, hostname, path,"
                " extension, source, timestamp, last_seen)"
                " VALUES(?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(domain, normalized) DO UPDATE SET last_seen=excluded.last_seen",
                (
                    domain,
                    record.get("url", ""),
                    record.get("normalized", ""),
                    record.get("hostname", ""),
                    record.get("path", ""),
                    record.get("extension", ""),
                    record.get("source", ""),
                    record.get("timestamp", ""),
                    now,
                ),
            )

    def get_historical_urls(self, domain: str) -> list[dict]:
        cur = self.conn.execute(
            "SELECT * FROM historical_urls WHERE domain=? ORDER BY normalized", (domain,)
        )
        return [dict(row) for row in cur.fetchall()]

    # -- classifications / indicators ---------------------------------
    def add_file_classification(
        self, domain: str, category: str, url: str, normalized: str
    ) -> None:
        with self.transaction() as cur:
            cur.execute(
                "INSERT INTO file_classifications(domain, category, url, normalized, last_seen)"
                " VALUES(?,?,?,?,?) ON CONFLICT(domain, category, normalized)"
                " DO UPDATE SET last_seen=excluded.last_seen",
                (domain, category, url, normalized, time.time()),
            )

    def add_indicator(
        self, domain: str, category: str, indicator: str, url: str, severity: str
    ) -> None:
        with self.transaction() as cur:
            cur.execute(
                "INSERT INTO exposure_indicators(domain, category, indicator, url, severity,"
                " last_seen) VALUES(?,?,?,?,?,?)"
                " ON CONFLICT(domain, category, indicator, url) DO UPDATE SET"
                " last_seen=excluded.last_seen, severity=excluded.severity",
                (domain, category, indicator, url, severity, time.time()),
            )

    def add_js_asset(self, domain: str, record: dict) -> None:
        now = time.time()
        with self.transaction() as cur:
            cur.execute(
                "INSERT INTO js_assets(domain, normalized, url, hostname, sources,"
                " extension, params, live_status, content_length, endpoints, analyzed,"
                " error, last_seen)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(domain, normalized) DO UPDATE SET"
                " url=excluded.url, hostname=excluded.hostname, sources=excluded.sources,"
                " extension=excluded.extension, params=excluded.params,"
                " live_status=excluded.live_status, content_length=excluded.content_length,"
                " endpoints=excluded.endpoints, analyzed=excluded.analyzed,"
                " error=excluded.error, last_seen=excluded.last_seen",
                (
                    domain,
                    record.get("normalized", ""),
                    record.get("url", ""),
                    record.get("hostname", ""),
                    json.dumps(record.get("sources", [])),
                    record.get("extension", ""),
                    json.dumps(record.get("params", [])),
                    record.get("live_status"),
                    record.get("content_length"),
                    json.dumps(record.get("endpoints", [])),
                    1 if record.get("analyzed") else 0,
                    record.get("error", ""),
                    now,
                ),
            )

    def get_js_assets(self, domain: str) -> list[dict]:
        cur = self.conn.execute(
            "SELECT * FROM js_assets WHERE domain=? ORDER BY normalized", (domain,)
        )
        return [dict(row) for row in cur.fetchall()]

    def get_file_classifications(self, domain: str) -> list[dict]:
        cur = self.conn.execute(
            "SELECT * FROM file_classifications WHERE domain=? ORDER BY category, normalized",
            (domain,),
        )
        return [dict(row) for row in cur.fetchall()]

    def get_indicators(self, domain: str) -> list[dict]:
        cur = self.conn.execute(
            "SELECT * FROM exposure_indicators WHERE domain=? ORDER BY category, indicator",
            (domain,),
        )
        return [dict(row) for row in cur.fetchall()]

    def add_takeover_finding(self, domain: str, record: dict) -> None:
        with self.transaction() as cur:
            cur.execute(
                "INSERT INTO takeover_findings(domain, hostname, cname_target, provider,"
                " confidence, classification, evidence, last_seen)"
                " VALUES(?,?,?,?,?,?,?,?)"
                " ON CONFLICT(domain, hostname) DO UPDATE SET"
                " cname_target=excluded.cname_target, provider=excluded.provider,"
                " confidence=excluded.confidence, classification=excluded.classification,"
                " evidence=excluded.evidence, last_seen=excluded.last_seen",
                (
                    domain,
                    record.get("hostname", ""),
                    record.get("cname_target", ""),
                    record.get("provider", ""),
                    float(record.get("confidence", 0.0)),
                    record.get("classification", ""),
                    json.dumps(record.get("evidence", [])),
                    time.time(),
                ),
            )

    def get_takeover_findings(self, domain: str) -> list[dict]:
        cur = self.conn.execute(
            "SELECT * FROM takeover_findings WHERE domain=? ORDER BY confidence DESC",
            (domain,),
        )
        return [dict(row) for row in cur.fetchall()]

    # -- cache ---------------------------------------------------------
    def cache_get(self, source: str, key: str) -> str | None:
        now = time.time()
        row = self.conn.execute(
            "SELECT payload, expires_at FROM source_cache WHERE source=? AND cache_key=?",
            (source, key),
        ).fetchone()
        if row is None:
            return None
        if row["expires_at"] < now:
            self.cache_delete(source, key)
            return None
        return str(row["payload"])

    def cache_set(self, source: str, key: str, payload: str, ttl: float) -> None:
        now = time.time()
        with self.transaction() as cur:
            cur.execute(
                "INSERT INTO source_cache(source, cache_key, payload, created_at, expires_at)"
                " VALUES(?,?,?,?,?) ON CONFLICT(source, cache_key) DO UPDATE SET"
                " payload=excluded.payload, created_at=excluded.created_at,"
                " expires_at=excluded.expires_at",
                (source, key, payload, now, now + ttl),
            )

    def cache_delete(self, source: str, key: str) -> None:
        with self.transaction() as cur:
            cur.execute(
                "DELETE FROM source_cache WHERE source=? AND cache_key=?", (source, key)
            )

    def clear_cache(self) -> int:
        with self.transaction() as cur:
            cur.execute("DELETE FROM source_cache")
            return cur.rowcount

    def clear_domain(self, domain: str) -> None:
        tables = (
            "scans",
            "subdomains",
            "dns_records",
            "http_results",
            "tls_results",
            "historical_urls",
            "js_assets",
            "file_classifications",
            "exposure_indicators",
            "takeover_findings",
            "scan_meta",
        )
        with self.transaction() as cur:
            for table in tables:
                cur.execute(f"DELETE FROM {table} WHERE domain=?", (domain,))

    # -- meta ----------------------------------------------------------
    def set_meta(self, domain: str, key: str, value: Any) -> None:
        with self.transaction() as cur:
            cur.execute(
                "INSERT INTO scan_meta(domain, key, value, updated_at) VALUES(?,?,?,?)"
                " ON CONFLICT(domain, key) DO UPDATE SET"
                " value=excluded.value, updated_at=excluded.updated_at",
                (domain, key, json.dumps(value, default=str), time.time()),
            )

    def get_meta(self, domain: str, key: str) -> Any:
        row = self.conn.execute(
            "SELECT value FROM scan_meta WHERE domain=? AND key=?", (domain, key)
        ).fetchone()
        if row is None:
            return None
        try:
            return json.loads(row["value"])
        except (json.JSONDecodeError, TypeError):
            return row["value"]

    def get_scans(self, domain: str, limit: int = 20) -> list[dict]:
        cur = self.conn.execute(
            "SELECT * FROM scans WHERE domain=? ORDER BY id DESC LIMIT ?", (domain, limit)
        )
        return [dict(row) for row in cur.fetchall()]
