"""Email harvesting.

Email addresses are both a phishing/pretext surface and an attribution signal
(they confirm which hosts belong to the org). This module scrapes a handful of
likely pages on each in-scope web origin — home, contact, about, team, careers —
and extracts addresses under the target's domains. Active and scope-gated.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence
from voidrecon.core.module import Module, Phase, register
from voidrecon.utils import net

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_PAGES = ["", "/contact", "/contact-us", "/about", "/about-us", "/team", "/careers",
          "/support", "/legal", "/privacy", "/.well-known/security.txt"]
# Obvious non-personal / vendor noise to drop.
_NOISE = ("example.com", "sentry.io", "wixpress.com", "@2x", ".png", ".jpg", ".gif", ".svg", ".webp")


@register
class EmailHarvest(Module):
    name = "email_harvest"
    phase = Phase.CONTENT
    active = True
    description = "Harvest organisation email addresses from web pages"
    depends_on = ("http_probe",)
    enabled_by_default = False  # opt-in: fetches several extra pages per origin

    async def run(self, ctx: RunContext) -> None:
        origins = self._origins(ctx)
        if not origins:
            self.log.info("no in-scope web origins for email harvesting")
            return
        sem = asyncio.Semaphore(int(ctx.config.get("opsec.max_concurrency", 20)))
        found: set[str] = set()

        async def harvest(origin):
            async with sem:
                found.update(await self._scrape(ctx, origin))

        await asyncio.gather(*(harvest(o) for o in origins))
        for email in found:
            ctx.add_asset(AssetKind.EMAIL, email, source=self.name, confidence=Confidence.LIKELY)
        self.log.info("harvested %d organisation email address(es)", len(found))

    def _origins(self, ctx: RunContext) -> list[str]:
        seen, out = set(), []
        for a in ctx.store.assets():
            url = a.attrs.get("http_url")
            if not url or "web" not in a.tags or not ctx.can_touch(a.value):
                continue
            p = urlparse(url)
            origin = f"{p.scheme}://{p.netloc}"
            if origin not in seen:
                seen.add(origin)
                out.append(origin)
        return out

    async def _scrape(self, ctx: RunContext, origin: str) -> set[str]:
        emails: set[str] = set()
        for path in _PAGES:
            html = await ctx.http.get_text(urljoin(origin, path))
            if not html:
                continue
            for match in _EMAIL_RE.findall(html):
                email = match.lower()
                if any(n in email for n in _NOISE):
                    continue
                domain = email.rsplit("@", 1)[-1]
                # Keep addresses that belong to the target's domains.
                if ctx.scope.is_related(domain) or any(
                    net.registrable_domain(domain) == net.registrable_domain(s) for s in ctx.scope.seeds
                ):
                    emails.add(email)
        return emails
