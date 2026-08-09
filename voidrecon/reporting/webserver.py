"""Local web UI over the SQLite datastore.

``voidrecon serve`` starts a small, read-only, standard-library HTTP server that
browses ``voidrecon.db``: a list of runs, and per-run findings and top assets.
No external dependencies, binds to localhost by default, and uses parameterised
SQL only. It never modifies the database.
"""

from __future__ import annotations

import html
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

_SEV_COLOR = {"critical": "#b00020", "high": "#e65100", "medium": "#f9a825",
              "low": "#2e7d32", "info": "#546e7a"}
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_STYLE = """
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#e6edf3;--muted:#8b949e;--accent:#58a6ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
header{padding:20px 24px;border-bottom:1px solid var(--border)}h1{margin:0;font-size:20px}
h1 span{color:var(--accent)}a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
main{padding:24px;max-width:1100px;margin:0 auto}h2{font-size:16px;border-bottom:1px solid var(--border);padding-bottom:6px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--border);border-radius:8px;overflow:hidden;margin-bottom:24px}
th,td{padding:8px 10px;border-bottom:1px solid var(--border);font-size:13px;text-align:left;vertical-align:top}
th{background:#1c2128;color:var(--muted);text-transform:uppercase;font-size:11px}
.badge{color:#fff;padding:2px 8px;border-radius:6px;font-size:11px;font-weight:700}
code{background:#1c2128;padding:1px 5px;border-radius:4px;font-size:12px}
"""


def _page(title: str, body: str) -> bytes:
    return (f"<!doctype html><html><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)}</title><style>{_STYLE}</style></head><body>"
            f"<header><h1><span>Void</span>Recon</h1></header><main>{body}</main></body></html>"
            ).encode("utf-8")


def _esc(x) -> str:
    return html.escape(str(x if x is not None else ""))


class _Handler(BaseHTTPRequestHandler):
    db_path = "voidrecon.db"

    def log_message(self, *args):  # silence default logging
        pass

    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/":
                body = self._index()
            elif parsed.path == "/run":
                run_id = parse_qs(parsed.query).get("id", [""])[0]
                body = self._run(run_id)
            else:
                self.send_error(404)
                return
        except Exception as exc:  # noqa: BLE001
            self.send_error(500, str(exc))
            return
        payload = _page("VoidRecon", body)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _index(self) -> str:
        conn = self._conn()
        rows = conn.execute(
            "SELECT run_id, target, generated, asset_count, finding_count "
            "FROM runs ORDER BY ts DESC"
        ).fetchall()
        conn.close()
        if not rows:
            return "<h2>No runs</h2><p>Run <code>voidrecon run &lt;target&gt;</code> first.</p>"
        trs = "".join(
            f"<tr><td><a href='/run?id={_esc(r['run_id'])}'>{_esc(r['run_id'])}</a></td>"
            f"<td>{_esc(r['target'])}</td><td>{_esc(r['generated'])}</td>"
            f"<td>{_esc(r['asset_count'])}</td><td>{_esc(r['finding_count'])}</td></tr>"
            for r in rows
        )
        return ("<h2>Runs</h2><table><thead><tr><th>Run</th><th>Target</th><th>When</th>"
                f"<th>Assets</th><th>Findings</th></tr></thead><tbody>{trs}</tbody></table>")

    def _run(self, run_id: str) -> str:
        conn = self._conn()
        findings = conn.execute(
            "SELECT severity, title, module, asset FROM findings WHERE run_id=?", (run_id,)
        ).fetchall()
        assets = conn.execute(
            "SELECT kind, value, score, scope FROM assets WHERE run_id=? ORDER BY score DESC LIMIT 100",
            (run_id,),
        ).fetchall()
        conn.close()
        findings = sorted(findings, key=lambda r: -_SEV_RANK.get(r["severity"], 0))
        f_rows = "".join(
            f"<tr><td><span class='badge' style='background:{_SEV_COLOR.get(r['severity'],'#546e7a')}'>"
            f"{_esc(r['severity'].upper())}</span></td><td>{_esc(r['title'])}</td>"
            f"<td>{_esc(r['module'])}</td><td><code>{_esc(r['asset'])}</code></td></tr>"
            for r in findings
        ) or "<tr><td colspan=4>No findings.</td></tr>"
        a_rows = "".join(
            f"<tr><td>{_esc(r['score'])}</td><td>{_esc(r['kind'])}</td>"
            f"<td>{_esc(r['value'])}</td><td>{_esc(r['scope'])}</td></tr>"
            for r in assets
        ) or "<tr><td colspan=4>No assets.</td></tr>"
        return (f"<p><a href='/'>&larr; all runs</a></p><h2>Findings — {_esc(run_id)}</h2>"
                f"<table><thead><tr><th>Sev</th><th>Title</th><th>Module</th><th>Asset</th></tr></thead>"
                f"<tbody>{f_rows}</tbody></table>"
                f"<h2>Top assets</h2><table><thead><tr><th>Score</th><th>Kind</th><th>Value</th>"
                f"<th>Scope</th></tr></thead><tbody>{a_rows}</tbody></table>")


def serve(db_path: str | Path, host: str = "127.0.0.1", port: int = 8787) -> None:
    db_path = str(db_path)
    if not Path(db_path).exists():
        raise FileNotFoundError(f"database not found: {db_path} (run a scan first)")
    _Handler.db_path = db_path
    server = ThreadingHTTPServer((host, port), _Handler)
    print(f"VoidRecon UI serving {db_path} at http://{host}:{port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()
