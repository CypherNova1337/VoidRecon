"""Optional SQLite persistence.

For recurring or large engagements a central database beats a pile of JSON files:
it makes trend queries and cross-run diffs cheap. Each run appends its assets and
findings to a shared SQLite DB (``<output_base>/voidrecon.db`` by default). This
is additive and best-effort — a DB error never fails the run.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from voidrecon.core.logging import get_logger

log = get_logger("db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    target TEXT,
    generated TEXT,
    ts REAL,
    elapsed REAL,
    asset_count INTEGER,
    finding_count INTEGER,
    counts_json TEXT
);
CREATE TABLE IF NOT EXISTS assets (
    run_id TEXT, kind TEXT, value TEXT, score REAL, scope TEXT, tags TEXT, sources TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    run_id TEXT, severity TEXT, title TEXT, module TEXT, asset TEXT
);
CREATE INDEX IF NOT EXISTS idx_assets_run ON assets(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_runs_target ON runs(target);
"""


def persist_run(db_path: str | Path, ctx, summary: dict) -> Path | None:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        conn = sqlite3.connect(str(path))
        try:
            conn.executescript(_SCHEMA)
            target = (ctx.scope.seeds[0] if ctx.scope.seeds else "target")
            counts = ctx.store.counts()
            conn.execute("DELETE FROM runs WHERE run_id=?", (ctx.run_id,))
            conn.execute("DELETE FROM assets WHERE run_id=?", (ctx.run_id,))
            conn.execute("DELETE FROM findings WHERE run_id=?", (ctx.run_id,))
            conn.execute(
                "INSERT INTO runs VALUES (?,?,?,?,?,?,?,?)",
                (ctx.run_id, target, time.strftime("%Y-%m-%d %H:%M:%S"), time.time(),
                 summary.get("elapsed"), len(ctx.store), counts.get("findings", 0),
                 json.dumps(counts)),
            )
            conn.executemany(
                "INSERT INTO assets VALUES (?,?,?,?,?,?,?)",
                [(ctx.run_id, a.kind.value, a.value, a.score, a.scope_state.value,
                  ",".join(sorted(a.tags)), ",".join(sorted(a.sources)))
                 for a in ctx.store.iter_assets()],
            )
            conn.executemany(
                "INSERT INTO findings VALUES (?,?,?,?,?)",
                [(ctx.run_id, f.severity.value, f.title, f.module, f.asset or "")
                 for f in ctx.store.findings()],
            )
            conn.commit()
        finally:
            conn.close()
        return path
    except Exception as exc:  # noqa: BLE001
        log.warning("SQLite persistence failed: %s", exc)
        return None
