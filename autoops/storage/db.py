"""
AutoSecOps — Storage Layer
SQLite-based persistence for scan records and results.
Can be swapped for PostgreSQL in production via AUTOOPS_DB_URL.
"""

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Generator

DEFAULT_DB_PATH = Path(__file__).parent.parent.parent / "autoops.db"


class Database:
    """
    SQLite database for persisting scan metadata and results.
    Schema:
      scans(id, scan_type, target, status, options, summary,
            created_at, started_at, finished_at)
    """

    def __init__(self, db_path: str | Path | None = None):
        self.db_path = Path(
            os.environ.get("AUTOOPS_DB_URL", "")
        ) or (db_path or DEFAULT_DB_PATH)
        self._init_db()

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self):
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id          TEXT PRIMARY KEY,
                    scan_type   TEXT NOT NULL DEFAULT 'full',
                    target      TEXT NOT NULL,
                    status      TEXT NOT NULL DEFAULT 'pending',
                    options     TEXT,       -- JSON
                    summary     TEXT,       -- JSON
                    created_at  TEXT,
                    started_at  TEXT,
                    finished_at TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC)
            """)

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def create_scan(self, scan_id: str, scan_type: str, target: str, options: dict | None = None) -> dict:
        now = datetime.now().isoformat()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO scans (id, scan_type, target, status, options, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (scan_id, scan_type, target, "pending", json.dumps(options or {}), now),
            )
        return self.get_scan(scan_id)

    def get_scan(self, scan_id: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if row is None:
                return None
            return self._row_to_dict(row)

    def update_scan(
        self,
        scan_id: str,
        status: str | None = None,
        summary: dict | None = None,
        started_at: str | None = None,
        finished_at: str | None = None,
    ) -> dict | None:
        updates, args = [], []
        if status is not None:
            updates.append("status = ?")
            args.append(status)
        if summary is not None:
            updates.append("summary = ?")
            args.append(json.dumps(summary))
        if started_at is not None:
            updates.append("started_at = ?")
            args.append(started_at)
        if finished_at is not None:
            updates.append("finished_at = ?")
            args.append(finished_at)
        if not updates:
            return self.get_scan(scan_id)
        args.append(scan_id)
        with self._conn() as conn:
            conn.execute(f"UPDATE scans SET {', '.join(updates)} WHERE id = ?", args)
        return self.get_scan(scan_id)

    def list_scans(
        self,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        with self._conn() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM scans WHERE status = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (status, limit, offset),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
            return [self._row_to_dict(r) for r in rows]

    def delete_scan(self, scan_id: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            return cur.rowcount > 0

    def _row_to_dict(self, row: sqlite3.Row) -> dict:
        d = dict(row)
        for key in ("options", "summary"):
            if d.get(key) and isinstance(d[key], str):
                try:
                    d[key] = json.loads(d[key])
                except Exception:
                    pass
        return d


# ── Global singleton ────────────────────────────────────────────────────────────

_db: Database | None = None

def get_db() -> Database:
    global _db
    if _db is None:
        _db = Database()
    return _db
