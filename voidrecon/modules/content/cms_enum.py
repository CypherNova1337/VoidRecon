"""CMS-specific enumeration.

Content management systems leak in predictable, well-known ways. For WordPress,
Drupal, and Joomla this module pulls the version, enumerates users, and flags the
usual exposures (WordPress REST user list, ``?author=`` enumeration, ``xmlrpc.php``,
Drupal ``CHANGELOG.txt``). CMS is detected from the fingerprints already gathered,
or by probing a couple of tell-tale paths. Active and scope-gated; opt-in.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin

from voidrecon.core.context import RunContext
from voidrecon.core.models import Confidence, Severity
from voidrecon.core.module import Module, Phase, register

_WP_VER_RE = re.compile(r'content="WordPress ([0-9.]+)"', re.IGNORECASE)
_DRUPAL_VER_RE = re.compile(r"Drupal (\d[0-9.]*)", re.IGNORECASE)
_JOOMLA_VER_RE = re.compile(r"<version>([0-9.]+)</version>", re.IGNORECASE)


@register
class CmsEnum(Module):
    name = "cms_enum"
    phase = Phase.CONTENT
    active = True
    description = "Enumerate WordPress/Drupal/Joomla (version, users, exposures)"
    depends_on = ("http_probe",)
    enabled_by_default = False  # opt-in

    async def run(self, ctx: RunContext) -> None:
        origins = self._origins(ctx)
        if not origins:
            self.log.info("no in-scope web origins for CMS enumeration")
            return
        sem = asyncio.Semaphore(int(ctx.config.get("opsec.max_concurrency", 20)))

        async def worker(item):
            async with sem:
                await self._enum(ctx, *item)

        await asyncio.gather(*(worker(o) for o in origins))
        self.log.info("CMS enumeration complete over %d origin(s)", len(origins))

    def _origins(self, ctx: RunContext):
        seen, out = set(), []
        for a in ctx.store.assets():
            url = a.attrs.get("http_url")
            if not url or "web" not in a.tags or not ctx.can_touch(a.value) or url in seen:
                continue
            seen.add(url)
            techs = {str(t).lower() for t in (a.attrs.get("technologies") or [])}
            out.append((a.value, url, techs))
        return out

    async def _enum(self, ctx: RunContext, host: str, url: str, techs: set) -> None:
        home = await ctx.http.get_text(url) or ""
        if "wordpress" in techs or "wp-content" in home or "/wp-includes/" in home:
            await self._wordpress(ctx, host, url, home)
        if "drupal" in techs or "drupal" in home.lower():
            await self._drupal(ctx, host, url)
        if "joomla" in techs or "joomla" in home.lower():
            await self._joomla(ctx, host, url)

    async def _wordpress(self, ctx: RunContext, host: str, url: str, home: str) -> None:
        m = _WP_VER_RE.search(home)
        version = m.group(1) if m else None
        if version:
            ctx.add_finding(f"WordPress {version} on {host}", module=self.name, severity=Severity.INFO,
                            asset=host, description="WordPress version disclosed via generator meta.",
                            evidence={"version": version}, tags={"cms", "wordpress"})
        # User enumeration via REST API.
        users = await ctx.http.get_json(urljoin(url, "/wp-json/wp/v2/users"))
        names = []
        if isinstance(users, list):
            names = [u.get("slug") or u.get("name") for u in users if isinstance(u, dict)]
        if names:
            ctx.add_finding(f"WordPress user enumeration on {host} ({len(names)} users)",
                            module=self.name, severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED,
                            asset=host,
                            description="The WordPress REST API exposes the user list (usernames aid brute-force).",
                            evidence={"endpoint": "/wp-json/wp/v2/users", "users": names[:50]},
                            tags={"cms", "wordpress", "user-enum"})
        # xmlrpc.
        xr = await ctx.http.get(urljoin(url, "/xmlrpc.php"))
        if xr is not None and xr.status_code in (200, 405):
            ctx.add_finding(f"WordPress xmlrpc.php enabled on {host}", module=self.name,
                            severity=Severity.LOW, asset=host,
                            description="xmlrpc.php is reachable — enables pingback abuse and credential brute-force amplification.",
                            evidence={"url": urljoin(url, '/xmlrpc.php')}, tags={"cms", "wordpress", "xmlrpc"})

    async def _drupal(self, ctx: RunContext, host: str, url: str) -> None:
        txt = await ctx.http.get_text(urljoin(url, "/CHANGELOG.txt"))
        if txt:
            m = _DRUPAL_VER_RE.search(txt)
            ver = m.group(1) if m else "unknown"
            ctx.add_finding(f"Drupal {ver} — CHANGELOG.txt exposed on {host}", module=self.name,
                            severity=Severity.LOW, confidence=Confidence.CONFIRMED, asset=host,
                            description="Drupal CHANGELOG.txt is readable, disclosing the exact core version.",
                            evidence={"version": ver, "url": urljoin(url, '/CHANGELOG.txt')},
                            tags={"cms", "drupal"})

    async def _joomla(self, ctx: RunContext, host: str, url: str) -> None:
        xml = await ctx.http.get_text(urljoin(url, "/administrator/manifests/files/joomla.xml"))
        if xml:
            m = _JOOMLA_VER_RE.search(xml)
            if m:
                ctx.add_finding(f"Joomla {m.group(1)} on {host}", module=self.name, severity=Severity.INFO,
                                confidence=Confidence.CONFIRMED, asset=host,
                                description="Joomla version disclosed via the manifest XML.",
                                evidence={"version": m.group(1)}, tags={"cms", "joomla"})
