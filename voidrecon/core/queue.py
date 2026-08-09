"""Distributed work queue over shared SQLite.

For large engagements you want several workers — processes on one box, or
machines pointing at the same shared DB file — chewing through a list of targets
in parallel, all writing results into one datastore. This is a small SQLite-backed
job queue with atomic claiming (``BEGIN IMMEDIATE`` + guarded update), safe for
concurrent workers via WAL mode and a busy timeout.

    voidrecon queue add a.com b.com c.com --active
    voidrecon worker            # run on each machine/terminal; drains the queue
"""

from __future__ import annotations

import json
import socket
import sqlite3
import time
from pathlib import Path

_SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    options TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    worker TEXT,
    created REAL, started REAL, finished REAL,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
"""


class JobQueue:
    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def _init(self) -> None:
        conn = self._conn()
        try:
            conn.executescript(_SCHEMA)
        finally:
            conn.close()

    def add(self, target: str, options: dict | None = None) -> int:
        conn = self._conn()
        try:
            cur = conn.execute(
                "INSERT INTO jobs (target, options, status, created) VALUES (?,?, 'pending', ?)",
                (target, json.dumps(options or {}), time.time()),
            )
            return cur.lastrowid
        finally:
            conn.close()

    def add_many(self, targets, options: dict | None = None) -> int:
        n = 0
        for t in targets:
            t = t.strip()
            if t:
                self.add(t, options)
                n += 1
        return n

    def claim(self, worker_id: str | None = None) -> dict | None:
        worker_id = worker_id or f"{socket.gethostname()}:{time.time():.0f}"
        conn = self._conn()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT id, target, options FROM jobs WHERE status='pending' ORDER BY created LIMIT 1"
            ).fetchone()
            if not row:
                conn.execute("COMMIT")
                return None
            conn.execute(
                "UPDATE jobs SET status='running', worker=?, started=? WHERE id=? AND status='pending'",
                (worker_id, time.time(), row["id"]),
            )
            conn.execute("COMMIT")
            return {"id": row["id"], "target": row["target"],
                    "options": json.loads(row["options"] or "{}")}
        except sqlite3.OperationalError:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            return None
        finally:
            conn.close()

    def complete(self, job_id: int, status: str = "done", error: str | None = None) -> None:
        conn = self._conn()
        try:
            conn.execute("UPDATE jobs SET status=?, finished=?, error=? WHERE id=?",
                         (status, time.time(), error, job_id))
        finally:
            conn.close()

    def list(self) -> list[dict]:
        conn = self._conn()
        try:
            return [dict(r) for r in conn.execute(
                "SELECT id, target, status, worker, created, finished, error FROM jobs ORDER BY id").fetchall()]
        finally:
            conn.close()

    def stats(self) -> dict:
        conn = self._conn()
        try:
            rows = conn.execute("SELECT status, COUNT(*) c FROM jobs GROUP BY status").fetchall()
            return {r["status"]: r["c"] for r in rows}
        finally:
            conn.close()

    def clear(self) -> int:
        conn = self._conn()
        try:
            cur = conn.execute("DELETE FROM jobs")
            return cur.rowcount
        finally:
            conn.close()
