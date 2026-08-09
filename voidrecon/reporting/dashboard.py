"""Historical trend dashboard.

Renders a self-contained HTML view across many runs of a target: how the attack
surface (subdomains, live hosts, services) and findings have moved over time, and
which assets appeared most recently. Built from the saved ``voidrecon.json`` run
files — no recon is performed.
"""

from __future__ import annotations

import html
import time
from pathlib import Path

from voidrecon.core import history

_SEV_COLOR = {"critical": "#b00020", "high": "#e65100", "medium": "#f9a825",
              "low": "#2e7d32", "info": "#546e7a"}


def _bars(series: list[tuple[str, int]], color: str = "#58a6ff") -> str:
    if not series:
        return "<p><em>No data.</em></p>"
    peak = max(v for _, v in series) or 1
    rows = ""
    for label, value in series:
        pct = int(value / peak * 100)
        rows += (
            f'<div class="bar-row"><span class="bar-label">{html.escape(label)}</span>'
            f'<span class="bar-track"><span class="bar-fill" style="width:{pct}%;background:{color}"></span></span>'
            f'<span class="bar-val">{value}</span></div>'
        )
    return f'<div class="bars">{rows}</div>'


def build_dashboard(run_paths: list[Path], target: str | None = None) -> str:
    runs = []
    for p in run_paths:
        try:
            data = history.load_run(p)
        except Exception:
            continue
        counts = data.get("store", {}).get("counts", {})
        findings = data.get("store", {}).get("findings", [])
        sev_counts: dict[str, int] = {}
        for f in findings:
            sev_counts[f.get("severity", "info")] = sev_counts.get(f.get("severity", "info"), 0) + 1
        runs.append({
            "label": p.parent.name,
            "generated": data.get("generated", ""),
            "counts": counts,
            "sev": sev_counts,
            "data": data,
        })

    title = target or (runs[-1]["data"].get("scope", {}).get("seeds", ["target"])[0] if runs else "target")
    generated = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    def esc(x):
        return html.escape(str(x if x is not None else ""))

    subs_series = [(r["label"][-20:], r["counts"].get("subdomain", 0)) for r in runs]
    find_series = [(r["label"][-20:], r["counts"].get("findings", 0)) for r in runs]

    # Latest run detail.
    latest = runs[-1] if runs else None
    sev_html = ""
    if latest:
        sev_html = "".join(
            f'<span class="chip" style="background:{_SEV_COLOR.get(s,"#546e7a")}">{esc(s.upper())}: {n}</span>'
            for s, n in sorted(latest["sev"].items(), key=lambda kv: -_sev_rank(kv[0]))
        ) or "<em>none</em>"

    table_rows = ""
    for r in runs:
        c = r["counts"]
        table_rows += (
            f"<tr><td>{esc(r['generated'])}</td><td>{c.get('subdomain',0)}</td>"
            f"<td>{c.get('ip',0)}</td><td>{c.get('service',0)}</td>"
            f"<td>{c.get('url',0)}</td><td>{c.get('findings',0)}</td></tr>"
        )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VoidRecon Trends — {esc(title)}</title>
<style>
  :root {{ --bg:#0d1117; --panel:#161b22; --border:#30363d; --fg:#e6edf3; --muted:#8b949e; --accent:#58a6ff; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }}
  header {{ padding:26px 24px; border-bottom:1px solid var(--border); }}
  h1 {{ margin:0; font-size:22px; }} h1 span {{ color:var(--accent); }}
  .sub {{ color:var(--muted); font-size:13px; margin-top:4px; }}
  main {{ padding:24px; max-width:1000px; margin:0 auto; }}
  section {{ margin-bottom:34px; }}
  h2 {{ font-size:17px; border-bottom:1px solid var(--border); padding-bottom:6px; }}
  .bars {{ display:flex; flex-direction:column; gap:6px; }}
  .bar-row {{ display:flex; align-items:center; gap:10px; font-size:12px; }}
  .bar-label {{ width:180px; color:var(--muted); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
  .bar-track {{ flex:1; background:#1c2128; border-radius:4px; height:16px; overflow:hidden; }}
  .bar-fill {{ display:block; height:100%; border-radius:4px; }}
  .bar-val {{ width:44px; text-align:right; }}
  table {{ width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--border); border-radius:8px; overflow:hidden; }}
  th,td {{ padding:8px 10px; border-bottom:1px solid var(--border); font-size:13px; text-align:left; }}
  th {{ background:#1c2128; color:var(--muted); text-transform:uppercase; font-size:11px; }}
  .chip {{ color:#fff; padding:3px 9px; border-radius:6px; font-size:12px; font-weight:700; margin-right:6px; display:inline-block; }}
  footer {{ padding:18px 24px; color:var(--muted); font-size:12px; border-top:1px solid var(--border); text-align:center; }}
</style></head>
<body>
<header><h1><span>Void</span>Recon Trends</h1>
<div class="sub">{esc(title)} · {len(runs)} runs · generated {esc(generated)} · VoidSec-Hub</div></header>
<main>
  <section><h2>Latest findings by severity</h2>{sev_html}</section>
  <section><h2>Subdomains over time</h2>{_bars(subs_series)}</section>
  <section><h2>Findings over time</h2>{_bars(find_series, color="#e65100")}</section>
  <section><h2>All runs</h2>
    <table><thead><tr><th>Generated</th><th>Subdomains</th><th>IPs</th><th>Services</th><th>URLs</th><th>Findings</th></tr></thead>
    <tbody>{table_rows or '<tr><td colspan=6>No runs.</td></tr>'}</tbody></table>
  </section>
</main>
<footer>VoidRecon — authorized security testing only.</footer>
</body></html>"""


def _sev_rank(sev: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(sev, 0)
