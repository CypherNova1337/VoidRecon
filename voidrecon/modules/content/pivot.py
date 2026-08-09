"""Fingerprint pivoting — favicon hashes and tracking IDs.

Two of the highest-yield attacker pivots, in one module:

* **Favicon hashing.** Compute the Shodan-style MurmurHash3 of each site's
  favicon. Identical icons across the internet betray sibling infrastructure —
  staging clones, shadow copies, and forgotten deployments that reuse the org's
  branding. With a Shodan API key, VoidRecon queries ``http.favicon.hash`` to
  surface those other hosts directly.

* **Tracking-ID correlation.** Google Analytics, GTM, AdSense, Facebook Pixel,
  and Hotjar IDs are frequently shared across an organisation's properties.
  Extracting them lets the correlation engine cluster hosts that belong together
  even when their names give nothing away.

Active and scope-gated: favicons/pages are fetched only from in-scope hosts and
only when active mode is on. The Shodan lookup itself is passive (third-party).
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence
from voidrecon.core.module import Module, Phase, register
from voidrecon.utils import net
from voidrecon.utils.hashing import favicon_hash

_ICON_RE = re.compile(
    r"""<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]*href=["']([^"']+)["']""",
    re.IGNORECASE,
)
_TRACKERS = [
    ("google_analytics", re.compile(r"\bUA-\d{4,10}-\d{1,4}\b")),
    ("ga4", re.compile(r"\bG-[A-Z0-9]{8,12}\b")),
    ("gtm", re.compile(r"\bGTM-[A-Z0-9]{5,8}\b")),
    ("adsense", re.compile(r"\bca-pub-\d{10,20}\b")),
    ("facebook_pixel", re.compile(r"""fbq\(\s*['"]init['"]\s*,\s*['"](\d{10,20})['"]""")),
    ("hotjar", re.compile(r"""hjid\s*[:=]\s*['\"]?(\d{5,10})""")),
    ("yandex_metrika", re.compile(r"\bym\(\s*(\d{5,10})")),
]


@register
class FingerprintPivot(Module):
    name = "pivot"
    phase = Phase.CONTENT
    active = True
    description = "Favicon-hash + tracking-ID pivoting (with optional Shodan expansion)"
    depends_on = ("http_probe",)

    async def run(self, ctx: RunContext) -> None:
        targets = [
            a for a in ctx.store.assets()
            if a.attrs.get("http_url") and "web" in a.tags and ctx.can_touch(a.value)
        ]
        if not targets:
            self.log.info("no in-scope web assets to pivot on")
            return

        sem = asyncio.Semaphore(int(ctx.config.get("opsec.max_concurrency", 20)))

        async def worker(asset):
            async with sem:
                await self._fingerprint(ctx, asset)

        await asyncio.gather(*(worker(a) for a in targets))

        hashes = {a.attrs["favicon_hash"] for a in targets if a.attrs.get("favicon_hash")}
        self.log.info("collected %d unique favicon hash(es) across %d hosts", len(hashes), len(targets))

        shodan_key = ctx.source_key("shodan_api_key")
        if shodan_key:
            for fh in hashes:
                await self._shodan_pivot(ctx, shodan_key, fh)
        elif hashes:
            self.log.info("set VOIDRECON_SOURCES_SHODAN_API_KEY to pivot favicon hashes across the internet")

    async def _fingerprint(self, ctx: RunContext, asset) -> None:
        page = asset.attrs["http_url"]
        html = await ctx.http.get_text(page)
        # Tracking IDs
        if html:
            trackers: list[str] = []
            for label, pattern in _TRACKERS:
                for m in pattern.finditer(html):
                    val = m.group(1) if m.groups() else m.group(0)
                    trackers.append(f"{label}:{val}")
            if trackers:
                asset.attrs["trackers"] = sorted(set(trackers))
        # Favicon
        icon_url = urljoin(page, "/favicon.ico")
        if html:
            m = _ICON_RE.search(html)
            if m:
                icon_url = urljoin(page, m.group(1))
        resp = await ctx.http.get(icon_url)
        if resp is not None and resp.status_code == 200 and resp.content:
            ctype = resp.headers.get("content-type", "")
            if "image" in ctype or icon_url.endswith(".ico") or len(resp.content) > 60:
                asset.attrs["favicon_hash"] = favicon_hash(resp.content)
                asset.attrs["favicon_url"] = icon_url

    async def _shodan_pivot(self, ctx: RunContext, key: str, fh: int) -> None:
        data = await ctx.http.get_json(
            "https://api.shodan.io/shodan/host/search",
            params={"key": key, "query": f"http.favicon.hash:{fh}"},
        )
        if not data:
            return
        matches = data.get("matches", []) or []
        added = 0
        for m in matches:
            ip = m.get("ip_str")
            hostnames = m.get("hostnames") or []
            if ip:
                a = ctx.add_asset(
                    AssetKind.IP, ip, source=self.name, confidence=Confidence.TENTATIVE,
                    via="favicon_pivot", favicon_hash=fh,
                )
                if a:
                    a.tags.add("favicon-pivot")
                    added += 1
            for host in hostnames:
                host = net.normalize_host(host)
                if host and net.is_domain(host):
                    a = ctx.add_asset(
                        AssetKind.SUBDOMAIN, host, source=self.name,
                        confidence=Confidence.TENTATIVE, via="favicon_pivot",
                    )
                    if a:
                        a.tags.add("favicon-pivot")
        if added:
            self.log.info("favicon hash %s -> %d hosts via Shodan", fh, added)
