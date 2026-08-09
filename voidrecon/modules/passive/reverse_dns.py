"""Reverse DNS (PTR) enrichment.

PTR records turn discovered IPs back into names, and those names frequently reveal
hostnames no forward source listed — internal naming schemes, co-located services,
neighbouring assets. Any PTR that falls under a seed apex is promoted to an
in-scope host; the rest are recorded as leads. Passive (resolver queries only).
"""

from __future__ import annotations

import asyncio

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence
from voidrecon.core.module import Module, Phase, register
from voidrecon.utils import net

try:
    import dns.asyncresolver
    import dns.reversename

    _HAS_DNS = True
except Exception:  # pragma: no cover
    _HAS_DNS = False


@register
class ReverseDns(Module):
    name = "reverse_dns"
    phase = Phase.RESOLVE
    active = False
    description = "PTR lookups on discovered IPs to surface more hostnames"
    depends_on = ("dns_resolve",)

    async def run(self, ctx: RunContext) -> None:
        if not _HAS_DNS:
            self.log.warning("dnspython not installed — skipping reverse DNS")
            return
        ips = ctx.store.assets(kind=AssetKind.IP)
        if not ips:
            return
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 5.0
        resolver.timeout = 5.0
        sem = asyncio.Semaphore(int(ctx.config.get("opsec.max_concurrency", 20)))

        new_related = 0

        async def lookup(ip_asset):
            nonlocal new_related
            async with sem:
                try:
                    rev = dns.reversename.from_address(ip_asset.value)
                    answer = await resolver.resolve(rev, "PTR")
                except Exception:
                    return
                names = [str(r.target).rstrip(".").lower() for r in answer]
                if not names:
                    return
                ip_asset.attrs["ptr"] = names
                for name in names:
                    if not net.is_domain(name):
                        continue
                    related = ctx.scope.is_related(name)
                    kind = AssetKind.SUBDOMAIN if related else AssetKind.DOMAIN
                    asset = ctx.add_asset(kind, name, source=self.name,
                                          confidence=Confidence.LIKELY, ptr_of=ip_asset.value)
                    if asset:
                        asset.tags.add("ptr")
                        if related:
                            new_related += 1

        await asyncio.gather(*(lookup(a) for a in ips))
        self.log.info("reverse DNS over %d IPs; %d in-scope hostnames surfaced", len(ips), new_related)
