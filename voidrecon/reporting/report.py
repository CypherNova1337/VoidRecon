"""Report generation.

Renders an engagement's results to three formats:

* **JSON** — the complete, machine-readable datastore (for piping into other
  tooling or diffing runs over time).
* **Markdown** — a readable operator report: scope, headline findings, and the
  prioritised target list.
* **HTML** — a self-contained page (no external assets) for sharing.

The prioritised target list is the payoff: assets sorted by the heuristic score,
so the reader's eye lands on the most promising surface first.
"""

from __future__ import annotations

import html
import json
import time
from pathlib import Path

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Severity
from voidrecon.intel.scoring import top_assets
from voidrecon.version import __version__

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_SEV_COLOR = {
    "critical": "#b00020", "high": "#e65100", "medium": "#f9a825",
    "low": "#2e7d32", "info": "#546e7a",
}


class Reporter:
    def __init__(self, ctx: RunContext, summary: dict | None = None):
        self.ctx = ctx
        self.summary = summary or {}
        self.store = ctx.store
        self.generated = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    # ---- public API -------------------------------------------------------
    def write_all(self, formats: list[str] | None = None) -> dict[str, Path]:
        formats = formats or ["json", "markdown", "html"]
        outdir = self.ctx.output_dir
        outdir.mkdir(parents=True, exist_ok=True)
        written: dict[str, Path] = {}
        if "json" in formats:
            written["json"] = self._write_json(outdir / "voidrecon.json")
        if "markdown" in formats or "md" in formats:
            written["markdown"] = self._write(outdir / "report.md", self.render_markdown())
        if "html" in formats:
            written["html"] = self._write(outdir / "report.html", self.render_html())
        return written

    # ---- data helpers -----------------------------------------------------
    def _findings_sorted(self):
        return sorted(
            self.store.findings(),
            key=lambda f: (-f.severity.rank, f.module, f.title),
        )

    def _llm(self) -> dict | None:
        return getattr(self.store, "llm_analysis", None)

    # ---- JSON -------------------------------------------------------------
    def _write_json(self, path: Path) -> Path:
        payload = {
            "tool": "VoidRecon",
            "version": __version__,
            "generated": self.generated,
            "summary": self.summary,
            "scope": self.ctx.scope.summary(),
            "store": self.store.to_dict(),
            "llm_analysis": self._llm(),
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        return path

    def _write(self, path: Path, content: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    # ---- Markdown ---------------------------------------------------------
    def render_markdown(self) -> str:
        counts = self.store.counts()
        scope = self.ctx.scope.summary()
        lines: list[str] = []
        lines.append(f"# VoidRecon Report — {', '.join(scope['seeds']) or 'target'}")
        lines.append("")
        lines.append(f"*Generated {self.generated} · VoidRecon v{__version__} · maintained by VoidSec-Hub*")
        lines.append("")
        lines.append("## Scope")
        lines.append(f"- **In scope:** {', '.join(scope['include']) or '—'}")
        lines.append(f"- **Out of scope:** {', '.join(scope['exclude']) or '—'}")
        if scope.get("program_url"):
            lines.append(f"- **Program:** {scope['program_url']}")
        lines.append("")
        lines.append("## Surface summary")
        for k in ("domain", "subdomain", "ip", "cidr", "asn", "service", "url", "endpoint", "code_repo"):
            if counts.get(k):
                lines.append(f"- {k}: **{counts[k]}**")
        lines.append(f"- findings: **{counts.get('findings', 0)}**")
        lines.append("")

        llm = self._llm()
        if llm:
            lines.append("## Analyst summary")
            lines.append(str(llm.get("summary", "")).strip() or "_(no summary)_")
            lines.append("")
            targets = llm.get("priority_targets") or []
            if targets:
                lines.append("### Model-nominated priority targets")
                for t in targets[:15]:
                    checks = ", ".join(t.get("suggested_checks", []) or [])
                    lines.append(f"- **{t.get('asset','?')}** — {t.get('why','')}" + (f" _(checks: {checks})_" if checks else ""))
                lines.append("")

        lines.append("## Findings")
        findings = self._findings_sorted()
        if not findings:
            lines.append("_No findings recorded._")
        else:
            for f in findings:
                lines.append(f"### [{f.severity.value.upper()}] {f.title}")
                if f.asset:
                    lines.append(f"- **Asset:** `{f.asset}`")
                lines.append(f"- **Module:** {f.module} · **Confidence:** {f.confidence.value}")
                if f.description:
                    lines.append(f"- {f.description}")
                if f.references:
                    lines.append(f"- Refs: {', '.join(f.references)}")
                lines.append("")

        lines.append("## Prioritised targets")
        top = top_assets(self.store, limit=40, kinds={AssetKind.SUBDOMAIN, AssetKind.DOMAIN})
        if not top:
            lines.append("_No scored hosts._")
        else:
            lines.append("| Score | Host | Scope | Status | Title | Signals |")
            lines.append("|------:|------|-------|:------:|-------|---------|")
            for a in top:
                sig = ", ".join((a.attrs.get("score_reasons") or [])[:3])
                title = (a.attrs.get("http_title") or "")[:40].replace("|", "/")
                status = a.attrs.get("http_status") or ""
                lines.append(
                    f"| {a.score:.0f} | {a.value} | {a.scope_state.value} | {status} | {title} | {sig} |"
                )
        lines.append("")
        lines.append("---")
        lines.append(
            "_VoidRecon is for authorized security testing only. Verify all leads before acting; "
            "respect program scope and the law._"
        )
        return "\n".join(lines)

    # ---- HTML -------------------------------------------------------------
    def render_html(self) -> str:
        counts = self.store.counts()
        scope = self.ctx.scope.summary()
        findings = self._findings_sorted()
        top = top_assets(self.store, limit=50, kinds={AssetKind.SUBDOMAIN, AssetKind.DOMAIN})
        llm = self._llm()

        def esc(x) -> str:
            return html.escape(str(x if x is not None else ""))

        cards = "".join(
            f'<div class="card"><div class="n">{counts.get(k,0)}</div><div class="l">{k}</div></div>'
            for k in ("domain", "subdomain", "ip", "cidr", "asn", "service", "url", "endpoint")
            if counts.get(k)
        )
        cards += f'<div class="card"><div class="n">{counts.get("findings",0)}</div><div class="l">findings</div></div>'

        findings_html = ""
        for f in findings:
            color = _SEV_COLOR.get(f.severity.value, "#546e7a")
            refs = "".join(f'<a href="{esc(r)}">{esc(r)}</a> ' for r in f.references)
            findings_html += (
                f'<div class="finding"><span class="badge" style="background:{color}">'
                f'{esc(f.severity.value.upper())}</span> <strong>{esc(f.title)}</strong>'
                f'<div class="meta">{esc(f.module)} · {esc(f.confidence.value)}'
                + (f' · <code>{esc(f.asset)}</code>' if f.asset else "")
                + f'</div><p>{esc(f.description)}</p>{("<p class=refs>"+refs+"</p>") if refs else ""}</div>'
            )
        if not findings_html:
            findings_html = "<p><em>No findings recorded.</em></p>"

        rows = ""
        for a in top:
            sig = ", ".join((a.attrs.get("score_reasons") or [])[:4])
            rows += (
                f"<tr><td class=score>{a.score:.0f}</td><td>{esc(a.value)}</td>"
                f"<td>{esc(a.scope_state.value)}</td><td>{esc(a.attrs.get('http_status',''))}</td>"
                f"<td>{esc((a.attrs.get('http_title') or '')[:60])}</td><td class=sig>{esc(sig)}</td></tr>"
            )

        shots = [a for a in self.store.assets() if a.attrs.get("screenshot")]
        shots.sort(key=lambda a: -a.score)
        gallery_html = ""
        if shots:
            cells = "".join(
                f'<figure><a href="{esc(a.attrs["screenshot"])}" target="_blank">'
                f'<img loading="lazy" src="{esc(a.attrs["screenshot"])}" alt="{esc(a.value)}"></a>'
                f'<figcaption>{esc(a.value)} '
                f'<span class="sc">{esc(a.attrs.get("http_status",""))}</span></figcaption></figure>'
                for a in shots[:120]
            )
            gallery_html = f'<section><h2>Visual triage ({len(shots)})</h2><div class="gallery">{cells}</div></section>'

        llm_html = ""
        if llm:
            targets = "".join(
                f"<li><strong>{esc(t.get('asset','?'))}</strong> — {esc(t.get('why',''))}</li>"
                for t in (llm.get("priority_targets") or [])[:15]
            )
            llm_html = (
                f'<section><h2>Analyst summary</h2><p>{esc(llm.get("summary",""))}</p>'
                + (f"<ul>{targets}</ul>" if targets else "")
                + "</section>"
            )

        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VoidRecon — {esc(', '.join(scope['seeds']) or 'target')}</title>
<style>
  :root {{ --bg:#0d1117; --panel:#161b22; --border:#30363d; --fg:#e6edf3; --muted:#8b949e; --accent:#58a6ff; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--fg); font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }}
  header {{ padding:28px 24px; border-bottom:1px solid var(--border); background:linear-gradient(180deg,#161b22,#0d1117); }}
  h1 {{ margin:0 0 4px; font-size:24px; letter-spacing:.5px; }}
  h1 span {{ color:var(--accent); }}
  .sub {{ color:var(--muted); font-size:13px; }}
  main {{ padding:24px; max-width:1100px; margin:0 auto; }}
  section {{ margin-bottom:32px; }}
  h2 {{ font-size:18px; border-bottom:1px solid var(--border); padding-bottom:6px; }}
  .cards {{ display:flex; flex-wrap:wrap; gap:12px; }}
  .card {{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:14px 18px; min-width:96px; text-align:center; }}
  .card .n {{ font-size:26px; font-weight:700; color:var(--accent); }}
  .card .l {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.5px; }}
  .finding {{ background:var(--panel); border:1px solid var(--border); border-left:4px solid var(--border); border-radius:8px; padding:12px 16px; margin-bottom:12px; }}
  .finding p {{ margin:8px 0 0; color:#c9d1d9; }}
  .badge {{ color:#fff; padding:2px 8px; border-radius:6px; font-size:11px; font-weight:700; }}
  .meta {{ color:var(--muted); font-size:12px; margin-top:6px; }}
  .refs a {{ color:var(--accent); font-size:12px; display:inline-block; margin-right:8px; }}
  table {{ width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--border); border-radius:8px; overflow:hidden; }}
  th,td {{ text-align:left; padding:8px 10px; border-bottom:1px solid var(--border); font-size:13px; vertical-align:top; }}
  th {{ background:#1c2128; color:var(--muted); text-transform:uppercase; font-size:11px; letter-spacing:.5px; }}
  td.score {{ font-weight:700; color:var(--accent); }}
  td.sig {{ color:var(--muted); font-size:12px; }}
  code {{ background:#1c2128; padding:1px 5px; border-radius:4px; font-size:12px; }}
  .gallery {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(220px,1fr)); gap:14px; }}
  figure {{ margin:0; background:var(--panel); border:1px solid var(--border); border-radius:8px; overflow:hidden; }}
  figure img {{ width:100%; height:150px; object-fit:cover; object-position:top; display:block; background:#000; }}
  figcaption {{ padding:6px 8px; font-size:12px; color:var(--muted); word-break:break-all; }}
  figcaption .sc {{ color:var(--accent); }}
  footer {{ padding:20px 24px; color:var(--muted); font-size:12px; border-top:1px solid var(--border); text-align:center; }}
</style></head>
<body>
<header>
  <h1><span>Void</span>Recon <span style="font-size:14px;color:var(--muted)">v{__version__}</span></h1>
  <div class="sub">{esc(', '.join(scope['seeds']) or 'target')} · generated {esc(self.generated)} · maintained by VoidSec-Hub</div>
</header>
<main>
  <section><h2>Attack surface</h2><div class="cards">{cards}</div></section>
  {llm_html}
  <section><h2>Findings</h2>{findings_html}</section>
  {gallery_html}
  <section><h2>Prioritised targets</h2>
    <table><thead><tr><th>Score</th><th>Host</th><th>Scope</th><th>Status</th><th>Title</th><th>Signals</th></tr></thead>
    <tbody>{rows or '<tr><td colspan=6>No scored hosts.</td></tr>'}</tbody></table>
  </section>
</main>
<footer>VoidRecon — for authorized security testing only. Verify every lead; respect scope and the law.</footer>
</body></html>"""
