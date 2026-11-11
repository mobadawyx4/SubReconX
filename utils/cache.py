"""TTL cache backed by the SQLite ``source_cache`` table."""

from __future__ import annotations

import hashlib

from config import SOURCE_CACHE_TTL
from core.database import Database
from utils.redaction import redact_payload


def cache_key(*parts: str) -> str:
    joined = "\x1f".join(str(p) for p in parts)
    return hashlib.sha256(joined.encode("utf-8", errors="replace")).hexdigest()


class SourceCache:
    def __init__(self, db: Database, enabled: bool = True, ttl: float = SOURCE_CACHE_TTL):
        self.db = db
        self.enabled = enabled
        self.ttl = ttl

    def get(self, source: str, key: str) -> str | None:
        if not self.enabled:
            return None
        return self.db.cache_get(source, key)

    def set(self, source: str, key: str, payload: str) -> None:
        if not self.enabled:
            return
        self.db.cache_set(source, key, redact_payload(payload), self.ttl)

    def clear(self) -> int:
        return self.db.clear_cache()
