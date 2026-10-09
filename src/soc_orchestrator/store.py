"""SQLite persistence: incidents, idempotent tickets, and the hash-chained audit trail.

Idempotency: the ticket id is derived from the incident's correlation key and inserted with
INSERT OR IGNORE, so replaying the same telemetry (a retry, a duplicate webhook, a re-run)
updates the existing ticket instead of opening a second one.

Audit: every record stores the SHA-256 of the previous record. Editing or deleting any row
breaks the chain from that row onward, and `verify_audit()` reports where.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Incident

GENESIS = "0" * 64
_SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)\b(\s*[:=]\s*|\s+)['\"]?[^\s'\"]{4,}"),
    re.compile(r"(?i)(?<=\s-p\s)[^\s]{4,}"),  # "-p hunter2" style CLI passwords
]


def redact(text: str) -> str:
    for pat in _SECRET_PATTERNS:
        text = pat.sub("[REDACTED]", text)
    return text


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _digest(payload: str, prev: str) -> str:
    return hashlib.sha256((prev + payload).encode()).hexdigest()


class Store:
    def __init__(self, path: str | Path = ":memory:") -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock, self.db:
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, key TEXT UNIQUE, data TEXT, updated TEXT);
                CREATE TABLE IF NOT EXISTS tickets (key TEXT PRIMARY KEY, ticket_id TEXT UNIQUE, title TEXT,
                    risk_score INTEGER, created TEXT, updated TEXT, updates INTEGER DEFAULT 0);
                CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, record TEXT, prev TEXT, hash TEXT);
            """)

    # --- incidents -----------------------------------------------------------------------
    def save_incident(self, inc: Incident) -> None:
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO incidents (id, key, data, updated) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET data=excluded.data, updated=excluded.updated",
                (inc.id, inc.key, inc.model_dump_json(), _now()))

    def get_incident(self, incident_id: str) -> Incident | None:
        row = self.db.execute("SELECT data FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        return Incident.model_validate_json(row["data"]) if row else None

    def list_incidents(self) -> list[Incident]:
        rows = self.db.execute("SELECT data FROM incidents ORDER BY updated DESC").fetchall()
        return [Incident.model_validate_json(r["data"]) for r in rows]

    # --- idempotent ticketing --------------------------------------------------------------
    def upsert_ticket(self, key: str, title: str, risk_score: int, ticket_id: str | None = None) -> tuple[str, bool]:
        """Return (ticket_id, created). Same key => same ticket, however many times it's called."""
        existing = self.get_ticket(key)
        ticket_id = existing or ticket_id or "INC-" + key[:8].upper()
        with self.lock, self.db:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO tickets (key, ticket_id, title, risk_score, created, updated) VALUES (?, ?, ?, ?, ?, ?)",
                (key, ticket_id, title, risk_score, _now(), _now()))
            created = cur.rowcount == 1
            if not created:
                self.db.execute("UPDATE tickets SET risk_score = MAX(risk_score, ?), updated = ?, updates = updates + 1 "
                                "WHERE key = ?", (risk_score, _now(), key))
        return ticket_id, created

    def get_ticket(self, key: str) -> str | None:
        row = self.db.execute("SELECT ticket_id FROM tickets WHERE key = ?", (key,)).fetchone()
        return row["ticket_id"] if row else None

    def ticket_count(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM tickets").fetchone()[0]

    # --- audit trail -------------------------------------------------------------------------
    def audit(self, event: str, **data: Any) -> str:
        payload = redact(json.dumps({"ts": _now(), "event": event, **data}, sort_keys=True, default=str))
        with self.lock, self.db:
            row = self.db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            prev = row["hash"] if row else GENESIS
            h = _digest(payload, prev)
            self.db.execute("INSERT INTO audit (record, prev, hash) VALUES (?, ?, ?)", (payload, prev, h))
        return h

    def audit_records(self) -> list[dict]:
        return [json.loads(r["record"]) for r in self.db.execute("SELECT record FROM audit ORDER BY seq")]

    def verify_audit(self) -> tuple[bool, int | None]:
        prev = GENESIS
        for r in self.db.execute("SELECT seq, record, prev, hash FROM audit ORDER BY seq"):
            if r["prev"] != prev or _digest(r["record"], prev) != r["hash"]:
                return False, r["seq"]
            prev = r["hash"]
        return True, None
