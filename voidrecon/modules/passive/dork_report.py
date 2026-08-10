"""Search-engine dork generation.

Rather than scrape search engines (against their terms and easily blocked),
VoidRecon generates the high-value dork queries an operator runs by hand — Google/
Bing for exposed files, panels and index listings, GitHub for leaked code, and
Shodan/Censys for infrastructure — pre-built as ready-to-click URLs for each seed.
Fully passive: it produces leads, it doesn't execute them.
"""

from __future__ import annotations

import html
from urllib.parse import quote_plus

from voidrecon.core.context import RunContext
from voidrecon.core.models import Severity
from voidrecon.core.module import Module, Phase, register
from voidrecon.utils.text import slugify

_GOOGLE_DORKS = [
    'site:{d}',
    'site:{d} -www',
    'site:{d} ext:php | ext:asp | ext:aspx | ext:jsp',
    'site:{d} ext:sql | ext:db | ext:log | ext:bak | ext:env | ext:yml | ext:json | ext:xml',
    'site:{d} inurl:admin | inurl:login | inurl:dashboard | inurl:portal',
    'site:{d} intitle:"index of"',
    'site:{d} inurl:api | inurl:graphql | inurl:swagger',
    'site:{d} "access_key" | "api_key" | "secret" | "password"',
    'site:pastebin.com "{d}"',
    'site:trello.com "{d}"',
    'site:s3.amazonaws.com "{d}"',
    'site:github.com "{d}"',
]
_GITHUB_DORKS = ['"{d}" password', '"{d}" api_key', '"{d}" secret', '"{d}" filename:.env']


@register
class DorkReport(Module):
    name = "dork_report"
    phase = Phase.PASSIVE
    active = False
    description = "Generate ready-to-run Google/GitHub/Shodan dork URLs for the target"

    async def run(self, ctx: RunContext) -> None:
        for apex in ctx.scope.seeds:
            google = [{"dork": d.format(d=apex),
                       "url": "https://www.google.com/search?q=" + quote_plus(d.format(d=apex))}
                      for d in _GOOGLE_DORKS]
            github = [{"dork": d.format(d=apex),
                       "url": "https://github.com/search?type=code&q=" + quote_plus(d.format(d=apex))}
                      for d in _GITHUB_DORKS]
            infra = {
                "shodan": f'https://www.shodan.io/search?query={quote_plus("hostname:" + apex)}',
                "censys": f'https://search.censys.io/search?resource=hosts&q={quote_plus(apex)}',
                "fofa": f'https://fofa.info/result?qbase64={quote_plus("domain=" + apex)}',
            }
            page = self._write_page(ctx, apex, google, github, infra)
            ctx.add_finding(
                f"OSINT dork pack for {apex}",
                module=self.name, severity=Severity.INFO, asset=apex,
                description=("Ready-to-run search queries for manual OSINT — exposed files, panels, "
                             "index listings, leaked code, and infrastructure. Open the clickable "
                             f"page: {page.name}"),
                evidence={"dork_page": page.name, "google": google, "github": github, "infra": infra},
                tags={"osint", "dorks"},
            )
        self.log.info("generated dork packs for %d seed(s)", len(ctx.scope.seeds))

    def _write_page(self, ctx: RunContext, apex: str, google, github, infra):
        def esc(x):
            return html.escape(str(x))

        def links(items):
            return "".join(
                f'<li><a href="{esc(i["url"])}" target="_blank" rel="noreferrer">{esc(i["dork"])}</a></li>'
                for i in items)
        infra_links = "".join(
            f'<li><a href="{esc(u)}" target="_blank" rel="noreferrer">{esc(name)}</a></li>'
            for name, u in infra.items())
        body = f"""<!doctype html><html><head><meta charset="utf-8">
<title>VoidRecon dorks — {esc(apex)}</title>
<style>body{{background:#0d1117;color:#e6edf3;font:15px/1.6 -apple-system,Segoe UI,Roboto,sans-serif;
margin:0;padding:24px;max-width:900px;margin:0 auto}}h1{{font-size:20px}}h2{{font-size:15px;color:#8b949e;
border-bottom:1px solid #30363d;padding-bottom:4px;margin-top:26px}}a{{color:#58a6ff;text-decoration:none}}
a:hover{{text-decoration:underline}}li{{margin:4px 0;word-break:break-all}}ul{{padding-left:18px}}</style>
</head><body><h1>OSINT dork pack — {esc(apex)}</h1>
<p style="color:#8b949e">Click to run each query. Manual OSINT leads — nothing is auto-executed.</p>
<h2>Google</h2><ul>{links(google)}</ul>
<h2>GitHub code search</h2><ul>{links(github)}</ul>
<h2>Infrastructure</h2><ul>{infra_links}</ul>
</body></html>"""
        path = ctx.output_dir / f"dorks-{slugify(apex)}.html"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        return path
