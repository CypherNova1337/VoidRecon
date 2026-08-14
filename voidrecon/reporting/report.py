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
        self._candidate_files: dict[str, Path] = {}

    # ---- public API -------------------------------------------------------
    def write_all(self, formats: list[str] | None = None) -> dict[str, Path]:
        formats = formats or ["json", "markdown", "html"]
        outdir = self.ctx.output_dir
        outdir.mkdir(parents=True, exist_ok=True)
        # Per-category candidate lists (xss.txt, lfi.txt, …) — computed first so
        # the reports can reference them.
        self._write_candidates(outdir)
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

    def _advice(self) -> list:
        return getattr(self.store, "advice", []) or []

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

    # ---- candidate lists (where to actually test) -------------------------
    _CANDIDATE_TAGS = ("xss", "sqli", "ssrf", "lfi", "rce", "ssti", "crlf",
                       "open-redirect", "idor", "redirect", "debug", "prototype-pollution")

    @staticmethod
    def _injection_key(url: str) -> tuple:
        """Collapse a URL to its injection point: (scheme, host, path, param-names).

        A vulnerability class lives at an *injection point*, not at a specific
        value. ``/flows?id=1``, ``/flows?id=2`` … ``/flows?id=999`` are the same
        SQLi/XSS test target — the ``id`` parameter on ``/flows`` — so they map to
        one key and become one line. A different parameter (``/flows?sort=name``)
        is a distinct injection point and stays separate. This is exactly how
        dalfox/sqlmap/nuclei treat them, so the candidate files pipe in clean.
        """
        from urllib.parse import parse_qsl, urlsplit

        try:
            p = urlsplit(url)
        except Exception:
            return ("", "", url, ())
        names = tuple(sorted({k for k, _ in parse_qsl(p.query, keep_blank_values=True)}))
        return (p.scheme, p.netloc, p.path, names)

    @staticmethod
    def _better_representative(current: str, candidate: str) -> str:
        """Pick the more tool-ready of two URLs for the same injection point.

        Prefer the one whose parameters carry non-empty values (tools error on
        ``?id=`` with nothing to mutate), then the shorter/cleaner URL.
        """
        from urllib.parse import parse_qsl, urlsplit

        def filled(u: str) -> int:
            try:
                q = urlsplit(u).query
            except Exception:
                return 0
            return sum(1 for _, v in parse_qsl(q, keep_blank_values=True) if v)

        if current is None:
            return candidate
        cf, nf = filled(current), filled(candidate)
        if nf != cf:
            return candidate if nf > cf else current
        return candidate if len(candidate) < len(current) else current

    def _write_candidates(self, outdir: Path) -> dict[str, Path]:
        # One representative URL per (category, injection point). See _injection_key.
        buckets: dict[str, dict[tuple, str]] = {}

        def add(cat: str, url: str) -> None:
            if not url:
                return
            point = buckets.setdefault(cat, {})
            key = self._injection_key(url)
            point[key] = self._better_representative(point.get(key), url)

        # Full lists from classified endpoints (each carries its matching params).
        for a in self.store.assets(AssetKind.URL) + self.store.assets(AssetKind.ENDPOINT):
            for cat in a.attrs.get("vuln_hints", []) or []:
                add(cat, a.value)
        # Plus any confirmed/candidate finding that names a URL.
        for f in self.store.findings():
            url = (f.evidence or {}).get("url")
            if not url:
                continue
            for tag in f.tags:
                if tag in self._CANDIDATE_TAGS:
                    add(tag, url)

        written: dict[str, Path] = {}
        if buckets:
            cdir = outdir / "candidates"
            cdir.mkdir(parents=True, exist_ok=True)
            for cat, points in buckets.items():
                urls = sorted(points.values())
                p = cdir / f"{cat}.txt"
                p.write_text("\n".join(urls) + "\n", encoding="utf-8")
                written[cat] = p
        self._candidate_files = written
        return written

    # ---- recon coverage (why a source is empty) ---------------------------
    _HEALTH_LABEL = {
        "ok": "ok", "empty": "nothing found", "no_key": "needs API key",
        "rate_limited": "RATE-LIMITED", "forbidden": "BLOCKED (403/401)",
        "not_found": "nothing found", "server_error": "source error (5xx)",
        "http_error": "source error", "unreachable": "TIMED OUT / unreachable",
    }
    # Worst-first so the representative status of a source surfaces real trouble.
    _HEALTH_RANK = ["rate_limited", "forbidden", "unreachable", "server_error",
                    "http_error", "no_key", "empty", "not_found", "ok"]

    def _source_health(self) -> list[dict]:
        """Aggregate per-seed source rows into one row per source.

        A source that returned data anywhere is ``ok`` (with the summed count);
        otherwise its worst status wins, so 'rate-limited' or 'timed out' is what
        the reader sees instead of a bare, unexplained zero."""
        rows = []
        getter = getattr(self.store, "source_health", None)
        if callable(getter):
            rows = getter() or []
        if not rows:
            return []
        agg: dict[str, dict] = {}
        for r in rows:
            src = r.get("source", "?")
            cur = agg.setdefault(src, {"source": src, "count": 0, "statuses": set()})
            cur["count"] += int(r.get("count", 0) or 0)
            cur["statuses"].add(r.get("status", "ok"))
        out = []
        for src, cur in agg.items():
            if cur["count"] > 0:
                status = "ok"
            else:
                status = next((s for s in self._HEALTH_RANK if s in cur["statuses"]), "empty")
            out.append({"source": src, "count": cur["count"], "status": status})
        # data-bearing sources first (by count), then problems, then the rest
        out.sort(key=lambda d: (-d["count"], self._HEALTH_RANK.index(d["status"])
                                if d["status"] in self._HEALTH_RANK else 99, d["source"]))
        return out

    @staticmethod
    def _evidence_urls(finding) -> list[str]:
        ev = finding.evidence or {}
        urls: list[str] = []
        if ev.get("url"):
            urls.append(str(ev["url"]))
        for key in ("urls", "sample_keys", "matched"):
            v = ev.get(key)
            if isinstance(v, list):
                urls.extend(str(x) for x in v)
            elif isinstance(v, str):
                urls.append(v)
        # de-dup preserve order
        seen, out = set(), []
        for u in urls:
            if u not in seen:
                seen.add(u)
                out.append(u)
        return out[:8]

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

        health = self._source_health()
        if health:
            problems = [h for h in health if h["status"] in
                        ("rate_limited", "forbidden", "unreachable", "server_error", "http_error")]
            lines.append("## Recon coverage")
            if problems:
                lines.append(f"> ⚠️ {len(problems)} source(s) did not return data "
                             "(rate-limited / blocked / timed out) — an empty section below may "
                             "mean the source failed, not that nothing exists. Add API keys or "
                             "re-run to fill the gaps.")
                lines.append("")
            lines.append("| Source | Result | Count |")
            lines.append("| --- | --- | --- |")
            for h in health:
                label = self._HEALTH_LABEL.get(h["status"], h["status"])
                cnt = h["count"] if h["count"] else "—"
                lines.append(f"| {h['source']} | {label} | {cnt} |")
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

        summary_txt = getattr(self.store, "advice_summary", "")
        if summary_txt:
            lines.append("## Analyst read")
            lines.append(summary_txt)
            lines.append("")

        advice = self._advice()
        if advice:
            lines.append("## Recommended next steps")
            for i, rec in enumerate(advice, 1):
                lines.append(f"{i}. **{rec['action']}** — {rec['why']}")
                if rec.get("targets"):
                    lines.append(f"   - Targets: {', '.join(str(t) for t in rec['targets'][:8])}")
                if rec.get("command"):
                    lines.append(f"   - `{rec['command']}`")
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
                ev_urls = self._evidence_urls(f)
                if ev_urls:
                    lines.append("- **Where to test:**")
                    for u in ev_urls:
                        lines.append(f"    - `{u}`")
                refs_extra = [r for r in f.references if r not in ev_urls]
                if refs_extra:
                    lines.append(f"- Refs: {', '.join(refs_extra)}")
                lines.append("")

        if self._candidate_files:
            lines.append("## Candidate lists (ready to feed your tools)")
            for cat, path in sorted(self._candidate_files.items()):
                n = sum(1 for _ in path.open())
                lines.append(f"- **{cat.upper()}** — {n} endpoint(s): `candidates/{path.name}`")
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

        # Clickable stat cards: each expands to the list of assets of that kind.
        cards = ""
        for k in ("domain", "subdomain", "ip", "cidr", "asn", "service", "url", "endpoint",
                  "email", "cloud_resource"):
            c = counts.get(k, 0)
            if not c:
                continue
            try:
                vals = sorted(a.value for a in self.store.assets(AssetKind(k)))
            except Exception:
                vals = []
            items = "".join(f"<li>{esc(v)}</li>" for v in vals[:2000])
            cards += (f'<details class="card"><summary><span class="n">{c}</span>'
                      f'<span class="l">{esc(k)}</span></summary>'
                      f'<ul class="asset-list">{items}</ul></details>')
        cards += (f'<a class="card static" href="#findings"><span class="n">'
                  f'{counts.get("findings",0)}</span><span class="l">findings</span></a>')

        def _link(u):
            u = esc(u)
            href = u if u.lower().startswith(("http://", "https://")) else ""
            return f'<a href="{href}" target="_blank" rel="noreferrer">{u}</a>' if href else f"<code>{u}</code>"

        findings_html = ""
        for f in findings:
            color = _SEV_COLOR.get(f.severity.value, "#546e7a")
            ev_urls = self._evidence_urls(f)
            refs = "".join(f'<a href="{esc(r)}" target="_blank">{esc(r)}</a> '
                           for r in f.references if r not in ev_urls)
            where = ("<div class='where'><b>Where to test:</b><ul>"
                     + "".join(f"<li>{_link(u)}</li>" for u in ev_urls) + "</ul></div>") if ev_urls else ""
            findings_html += (
                f'<div class="finding" style="border-left-color:{color}">'
                f'<span class="badge" style="background:{color}">{esc(f.severity.value.upper())}</span> '
                f'<strong>{esc(f.title)}</strong>'
                f'<div class="meta">{esc(f.module)} · {esc(f.confidence.value)}'
                + (f' · <code>{esc(f.asset)}</code>' if f.asset else "")
                + f'</div><p>{esc(f.description)}</p>{where}'
                + (f'<p class="refs">{refs}</p>' if refs else "") + "</div>"
            )
        if not findings_html:
            findings_html = "<p><em>No findings recorded.</em></p>"

        cand_html = ""
        if self._candidate_files:
            rows_c = "".join(
                f"<li><b>{esc(cat.upper())}</b> — {sum(1 for _ in p.open())} endpoints "
                f"→ <code>candidates/{esc(p.name)}</code></li>"
                for cat, p in sorted(self._candidate_files.items()))
            cand_html = f'<section><h2>Candidate lists</h2><ul class="cand">{rows_c}</ul></section>'

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

        health = self._source_health()
        coverage_html = ""
        if health:
            bad = {"rate_limited", "forbidden", "unreachable", "server_error", "http_error"}
            problems = [h for h in health if h["status"] in bad]
            rows = ""
            for h in health:
                label = self._HEALTH_LABEL.get(h["status"], h["status"])
                cls = "bad" if h["status"] in bad else ("warn" if h["status"] == "no_key" else "good")
                cnt = h["count"] if h["count"] else "—"
                rows += (f'<tr><td>{esc(h["source"])}</td>'
                         f'<td class="{cls}">{esc(label)}</td><td>{cnt}</td></tr>')
            warn = ""
            if problems:
                warn = (f'<p class="cov-warn">⚠️ {len(problems)} source(s) did not return data '
                        "(rate-limited / blocked / timed out). An empty section may mean a source "
                        "failed, not that nothing exists — add API keys or re-run to fill gaps.</p>")
            coverage_html = (
                '<section><h2>Recon coverage</h2>' + warn +
                '<table><thead><tr><th>Source</th><th>Result</th><th>Count</th></tr></thead>'
                f'<tbody>{rows}</tbody></table></section>'
            )

        summary_txt = getattr(self.store, "advice_summary", "")
        summary_html = (f'<section><h2>Analyst read</h2><p>{esc(summary_txt)}</p></section>'
                        if summary_txt else "")
        advice = self._advice()
        advice_html = ""
        if advice:
            items = ""
            for rec in advice:
                tgt = (f'<div class="meta">Targets: {esc(", ".join(str(t) for t in rec["targets"][:8]))}</div>'
                       if rec.get("targets") else "")
                cmd = f'<div class="refs"><code>{esc(rec["command"])}</code></div>' if rec.get("command") else ""
                items += (f'<div class="finding"><strong>{esc(rec["action"])}</strong>'
                          f'<p>{esc(rec["why"])}</p>{tgt}{cmd}</div>')
            advice_html = f'<section><h2>Recommended next steps</h2>{items}</section>'

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
  .card {{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:14px 18px; min-width:110px; text-align:center; cursor:pointer; }}
  .card.static {{ text-decoration:none; display:block; }}
  .card summary {{ list-style:none; }}
  .card summary::-webkit-details-marker {{ display:none; }}
  .card .n {{ font-size:26px; font-weight:700; color:var(--accent); display:block; }}
  .card .l {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.5px; }}
  details.card[open] {{ text-align:left; min-width:280px; }}
  .asset-list {{ list-style:none; margin:10px 0 0; padding:0; max-height:320px; overflow:auto; font-size:12px; }}
  .asset-list li {{ padding:2px 0; border-bottom:1px solid var(--border); word-break:break-all; font-family:monospace; }}
  .where {{ margin-top:8px; font-size:13px; }} .where ul {{ margin:4px 0 0; padding-left:18px; }}
  .where a {{ color:var(--accent); word-break:break-all; }}
  .cand li {{ margin:3px 0; }}
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
  td.good {{ color:#3fb950; }} td.warn {{ color:#d29922; }} td.bad {{ color:#f85149; font-weight:700; }}
  .cov-warn {{ background:#2d2212; border:1px solid #9e6a03; border-radius:8px; padding:10px 14px; color:#e3b341; font-size:13px; }}
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
  {coverage_html}
  {summary_html}
  {advice_html}
  {llm_html}
  <section id="findings"><h2>Findings</h2>{findings_html}</section>
  {cand_html}
  {gallery_html}
  <section><h2>Prioritised targets</h2>
    <table><thead><tr><th>Score</th><th>Host</th><th>Scope</th><th>Status</th><th>Title</th><th>Signals</th></tr></thead>
    <tbody>{rows or '<tr><td colspan=6>No scored hosts.</td></tr>'}</tbody></table>
  </section>
</main>
<footer>VoidRecon — for authorized security testing only. Verify every lead; respect scope and the law.</footer>
</body></html>"""
