"""HTTP(S) probing and lightweight fingerprinting.

The first active step: for every resolving, in-scope host, find out whether it
speaks HTTP/HTTPS, what it returns, and what it is built with. Status codes,
titles, server headers, redirects, and cheap technology hints feed directly into
the scoring engine (an ``admin`` title or a ``401`` gate raises an asset's
priority).

This module is **active** — it contacts the target directly — so it runs only
when ``opsec.allow_active`` is enabled AND the specific host is positively in
scope. Everything is throttled through the shared rate limiter.
"""

from __future__ import annotations

import asyncio
import re

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence, Severity
from voidrecon.core.module import Module, Phase, register
from voidrecon.core.tools import run_tool

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Very cheap header/body -> technology hints. The heavy lifting is left to
# dedicated tools (httpx/wappalyzer) when available; this is the native fallback.
_TECH_HINTS = {
    "x-powered-by": None,             # value is the tech
    "server": None,
    "x-generator": None,
    "x-drupal-cache": "Drupal",
    "x-aspnet-version": "ASP.NET",
}
_BODY_HINTS = [
    ("wp-content", "WordPress"),
    ("/sites/default/files", "Drupal"),
    ("Joomla!", "Joomla"),
    ("__NEXT_DATA__", "Next.js"),
    ("ng-version", "Angular"),
    ("data-reactroot", "React"),
    ("csrfmiddlewaretoken", "Django"),
    ("Laravel", "Laravel"),
    ("swagger-ui", "Swagger UI"),
    ("grafana", "Grafana"),
    ("kibana", "Kibana"),
]


@register
class HttpProbe(Module):
    name = "http_probe"
    phase = Phase.ACTIVE
    active = True
    description = "Probe live hosts over HTTP/HTTPS and fingerprint them"
    depends_on = ("dns_resolve",)

    async def run(self, ctx: RunContext) -> None:
        targets = [
            a for a in ctx.store.assets(kind=AssetKind.SUBDOMAIN) + ctx.store.assets(kind=AssetKind.DOMAIN)
            if a.attrs.get("resolved_ips") and ctx.can_touch(a.value)
        ]
        if not targets:
            self.log.info("no in-scope resolving hosts to probe")
            return

        # Prefer httpx binary if present — it's faster and richer.
        if ctx.tools.has("httpx"):
            await self._probe_with_httpx(ctx, targets)
            return

        sem = asyncio.Semaphore(int(ctx.config.get("opsec.max_concurrency", 20)))

        async def worker(asset):
            async with sem:
                await self._probe_one(ctx, asset)

        await asyncio.gather(*(worker(a) for a in targets))
        alive = sum(1 for a in targets if a.attrs.get("http_status"))
        self.log.info("probed %d hosts; %d responded over HTTP(S)", len(targets), alive)

    async def _probe_one(self, ctx: RunContext, asset) -> None:
        for scheme in ("https", "http"):
            url = f"{scheme}://{asset.value}"
            resp = await ctx.http.get(url)
            if resp is None:
                continue
            body = resp.text[:200_000]
            title = self._title(body)
            techs = self._fingerprint(dict(resp.headers), body)
            asset.attrs.update(
                {
                    "http_url": str(resp.url),
                    "http_status": resp.status_code,
                    "http_title": title,
                    "http_server": resp.headers.get("server"),
                    "technologies": techs,
                    "content_length": len(resp.content),
                }
            )
            asset.tags.add("web")
            ctx.add_asset(
                AssetKind.URL, str(resp.url), source=self.name,
                confidence=Confidence.CONFIRMED, status=resp.status_code, title=title,
            )
            if resp.status_code in (401, 403):
                ctx.add_finding(
                    f"Access-gated endpoint: {url} ({resp.status_code})",
                    module=self.name, severity=Severity.INFO, asset=asset.value,
                    description="Authentication or authorization gate — a candidate for access-control testing.",
                    tags={"auth-gate"},
                )
            return  # first responding scheme wins

    def _title(self, body: str) -> str | None:
        m = _TITLE_RE.search(body)
        if m:
            return re.sub(r"\s+", " ", m.group(1)).strip()[:200]
        return None

    def _fingerprint(self, headers: dict, body: str) -> list[str]:
        techs: set[str] = set()
        lowered = {k.lower(): v for k, v in headers.items()}
        for header, static in _TECH_HINTS.items():
            if header in lowered and lowered[header]:
                techs.add(static or lowered[header])
        for needle, tech in _BODY_HINTS:
            if needle.lower() in body.lower():
                techs.add(tech)
        return sorted(techs)

    async def _probe_with_httpx(self, ctx: RunContext, targets) -> None:
        hosts = "\n".join(a.value for a in targets)
        result = await run_tool(
            "httpx",
            ["-silent", "-json", "-title", "-tech-detect", "-status-code", "-server", "-no-color"],
            stdin=hosts,
            timeout=600,
        )
        if not result.ok:
            self.log.warning("httpx invocation failed; falling back to native probe")
            return
        import json

        by_host = {a.value: a for a in targets}
        alive = 0
        for line in result.lines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = row.get("input") or row.get("host")
            asset = by_host.get(host)
            if not asset:
                continue
            alive += 1
            asset.attrs.update(
                {
                    "http_url": row.get("url"),
                    "http_status": row.get("status_code") or row.get("status-code"),
                    "http_title": row.get("title"),
                    "http_server": row.get("webserver") or row.get("server"),
                    "technologies": row.get("tech") or row.get("technologies") or [],
                }
            )
            asset.tags.add("web")
            if row.get("url"):
                ctx.add_asset(AssetKind.URL, row["url"], source=self.name, confidence=Confidence.CONFIRMED)
        self.log.info("httpx probed %d hosts; %d responded", len(targets), alive)
