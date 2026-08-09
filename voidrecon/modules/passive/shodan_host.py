"""Shodan host enrichment.

Shodan has already scanned most of the internet, so for every IP VoidRecon
discovers it can pull open ports, service banners, product/version data,
hostnames, and known-CVE tags — without sending a single packet to the target.
This turns a bare IP into a rich profile and often reveals services and
vulnerabilities before any active scanning. Passive; requires a Shodan API key.
"""

from __future__ import annotations

import asyncio

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence, Severity
from voidrecon.core.module import Module, Phase, register
from voidrecon.utils import net


@register
class ShodanHost(Module):
    name = "shodan_host"
    phase = Phase.PASSIVE
    active = False
    description = "Enrich discovered IPs with Shodan (ports, banners, CVEs) — no packets to target"
    depends_on = ("dns_resolve",)

    async def run(self, ctx: RunContext) -> None:
        key = ctx.source_key("shodan_api_key")
        if not key:
            self.log.info("no Shodan key — skipping (set VOIDRECON_SOURCES_SHODAN_API_KEY)")
            return
        ips = [a for a in ctx.store.assets(kind=AssetKind.IP)
               if ctx.scope.classify_ip(a.value).value != "out_of_scope"]
        if not ips:
            return
        sem = asyncio.Semaphore(min(int(ctx.config.get("opsec.max_concurrency", 20)), 5))

        async def worker(asset):
            async with sem:
                await self._enrich(ctx, key, asset)

        await asyncio.gather(*(worker(a) for a in ips))
        self.log.info("Shodan-enriched %d IP(s)", len(ips))

    async def _enrich(self, ctx: RunContext, key: str, asset) -> None:
        data = await ctx.http.get_json(f"https://api.shodan.io/shodan/host/{asset.value}",
                                       params={"key": key})
        if not isinstance(data, dict):
            return
        ports = data.get("ports") or []
        if ports:
            asset.attrs["open_ports"] = sorted(set((asset.attrs.get("open_ports") or []) + list(ports)))
        products = sorted({s.get("product") for s in data.get("data", []) or [] if s.get("product")})
        if products:
            asset.attrs["shodan_products"] = products
        asset.attrs["shodan_org"] = data.get("org")
        for host in data.get("hostnames", []) or []:
            host = net.normalize_host(host)
            if host and net.is_domain(host):
                kind = AssetKind.SUBDOMAIN if ctx.scope.is_related(host) else AssetKind.DOMAIN
                ctx.add_asset(kind, host, source=self.name, confidence=Confidence.LIKELY, via="shodan")
        vulns = list((data.get("vulns") or []))
        if vulns:
            asset.attrs["shodan_vulns"] = vulns[:50]
            ctx.add_finding(
                f"Shodan reports {len(vulns)} known CVE(s) on {asset.value}",
                module=self.name, severity=Severity.HIGH, confidence=Confidence.TENTATIVE,
                asset=asset.value,
                description=("Shodan associates known-vulnerability tags with this host based on its "
                             "banners. Verify each against the actual running versions before reporting."),
                evidence={"ip": asset.value, "cves": sorted(vulns)[:40], "products": products,
                          "org": data.get("org")},
                tags={"shodan", "cve"},
            )
