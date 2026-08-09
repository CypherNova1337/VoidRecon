"""Search-engine dork generation.

Rather than scrape search engines (against their terms and easily blocked),
VoidRecon generates the high-value dork queries an operator runs by hand — Google/
Bing for exposed files, panels and index listings, GitHub for leaked code, and
Shodan/Censys for infrastructure — pre-built as ready-to-click URLs for each seed.
Fully passive: it produces leads, it doesn't execute them.
"""

from __future__ import annotations

from urllib.parse import quote_plus

from voidrecon.core.context import RunContext
from voidrecon.core.models import Severity
from voidrecon.core.module import Module, Phase, register

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
            ctx.add_finding(
                f"OSINT dork pack for {apex}",
                module=self.name, severity=Severity.INFO, asset=apex,
                description=("Ready-to-run search queries for manual OSINT — exposed files, panels, "
                             "index listings, leaked code, and infrastructure. Not auto-executed."),
                evidence={"google": google, "github": github, "infra": infra},
                tags={"osint", "dorks"},
            )
        self.log.info("generated dork packs for %d seed(s)", len(ctx.scope.seeds))
