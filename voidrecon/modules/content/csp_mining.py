"""Content-Security-Policy and header host mining.

Defensive headers are an unintentional map of an app's dependencies: a CSP lists
every origin the page is allowed to talk to (APIs, CDNs, auth providers, sibling
apps), and headers like Access-Control-Allow-Origin, Report-To, and Link name
more. Harvesting those hostnames routinely turns up related infrastructure no
subdomain source listed. This module reads them from each in-scope web origin.

Active and scope-gated.
"""

from __future__ import annotations

import asyncio
import re

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence
from voidrecon.core.module import Module, Phase, register
from voidrecon.utils import net

_HOST_RE = re.compile(r"(?:https?:)?//([A-Za-z0-9.\-]+\.[A-Za-z]{2,})")
_BARE_HOST_RE = re.compile(r"\b([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+\.[A-Za-z]{2,})\b")
_META_CSP_RE = re.compile(
    r"""<meta[^>]+http-equiv=["']content-security-policy["'][^>]+content=["']([^"']+)""",
    re.IGNORECASE)


def extract_hosts_from_csp(csp: str) -> set[str]:
    hosts: set[str] = set()
    for token in re.split(r"[;\s]+", csp):
        token = token.strip().strip("'\"")
        if not token or token == "*" or token.startswith(("data:", "blob:", "filesystem:", "mediastream:")):
            continue
        # Keep wildcard hosts like *.example.com by stripping the leading '*.'.
        cand = token[2:] if token.startswith("*.") else token
        m = _HOST_RE.search(cand)
        if m:
            hosts.add(m.group(1).lower())
        elif "/" not in cand:
            bm = _BARE_HOST_RE.search(cand)
            if bm:
                hosts.add(bm.group(1).lower())
    return {h.lstrip("*.") for h in hosts}


def extract_hosts_from_headers(headers: dict) -> set[str]:
    hosts: set[str] = set()
    blob = " ".join(f"{k}: {v}" for k, v in headers.items()
                    if k.lower() in ("access-control-allow-origin", "report-to", "link",
                                     "content-security-policy", "content-security-policy-report-only",
                                     "x-frame-options", "access-control-expose-headers"))
    for m in _HOST_RE.finditer(blob):
        hosts.add(m.group(1).lower())
    return {h.lstrip("*.") for h in hosts}


@register
class CspMining(Module):
    name = "csp_mining"
    phase = Phase.CONTENT
    active = True
    description = "Mine CSP and security headers for related hostnames"
    depends_on = ("http_probe",)

    async def run(self, ctx: RunContext) -> None:
        origins = []
        seen = set()
        for a in ctx.store.assets():
            url = a.attrs.get("http_url")
            if url and "web" in a.tags and ctx.can_touch(a.value) and url not in seen:
                seen.add(url)
                origins.append(url)
        if not origins:
            self.log.info("no in-scope web assets for CSP mining")
            return
        sem = asyncio.Semaphore(int(ctx.config.get("opsec.max_concurrency", 20)))
        found = 0

        async def worker(url):
            nonlocal found
            async with sem:
                found += await self._mine(ctx, url)

        await asyncio.gather(*(worker(u) for u in origins))
        self.log.info("CSP/header mining surfaced %d related hostname(s)", found)

    async def _mine(self, ctx: RunContext, url: str) -> int:
        resp = await ctx.http.get(url)
        if resp is None:
            return 0
        headers = dict(resp.headers)
        hosts = extract_hosts_from_headers(headers)
        csp = headers.get("content-security-policy") or headers.get("content-security-policy-report-only")
        if csp:
            hosts |= extract_hosts_from_csp(csp)
        m = _META_CSP_RE.search(resp.text)
        if m:
            hosts |= extract_hosts_from_csp(m.group(1))
        added = 0
        for host in hosts:
            host = net.normalize_host(host)
            if not net.is_domain(host):
                continue
            related = ctx.scope.is_related(host)
            kind = AssetKind.SUBDOMAIN if related else AssetKind.DOMAIN
            a = ctx.add_asset(kind, host, source=self.name, confidence=Confidence.TENTATIVE, via="csp")
            if a:
                a.tags.add("csp")
                if related:
                    added += 1
        return added
