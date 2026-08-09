"""Organisation footprint mapping via ASN / netblock discovery.

Classic checklists start (and stop) at the given domain. A real intruder starts
by asking *what does this organisation own?* — which autonomous systems, which IP
ranges, which sibling brands. This module answers that from keyless public
sources (RIPEstat), turning a seed apex into ASNs and CIDR ranges that later
phases can expand into.

Everything here is passive: it queries internet routing registries, never the
target. Discovered ranges are recorded as leads and are only actively scanned if
they fall inside the declared scope.
"""

from __future__ import annotations

import asyncio
import socket

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence, Severity
from voidrecon.core.module import Module, Phase, register

_RIPESTAT = "https://stat.ripe.net/data"


@register
class AsnMap(Module):
    name = "asn_map"
    phase = Phase.SCOPE
    active = False
    description = "Map org ASNs and netblocks from seed domains (RIPEstat, keyless)"

    async def run(self, ctx: RunContext) -> None:
        seeds = ctx.scope.seeds
        if not seeds:
            self.log.info("no seed domains to map")
            return

        seen_asns: set[str] = set()
        for seed in seeds:
            ip = await self._resolve(seed)
            if not ip:
                self.log.debug("could not resolve seed %s for ASN mapping", seed)
                continue
            ctx.add_asset(AssetKind.IP, ip, source=self.name, confidence=Confidence.LIKELY,
                          note=f"apex A record for {seed}")
            info = await self._network_info(ctx, ip)
            if not info:
                continue
            asn = info.get("asn")
            prefix = info.get("prefix")
            if prefix:
                ctx.add_asset(AssetKind.CIDR, prefix, source=self.name,
                              origin_seed=seed, via="ripestat")
            if asn and asn not in seen_asns:
                seen_asns.add(asn)
                await self._expand_asn(ctx, asn, seed)

        if seen_asns:
            self.log.info("mapped %d ASN(s): %s", len(seen_asns), ", ".join(sorted(seen_asns)))

    async def _resolve(self, host: str) -> str | None:
        loop = asyncio.get_event_loop()
        try:
            infos = await loop.getaddrinfo(host, None, family=socket.AF_INET)
            return infos[0][4][0] if infos else None
        except (socket.gaierror, OSError, IndexError):
            return None

    async def _network_info(self, ctx: RunContext, ip: str) -> dict | None:
        data = await ctx.http.get_json(f"{_RIPESTAT}/network-info/data.json", params={"resource": ip})
        if not data or data.get("status") != "ok":
            return None
        d = data.get("data", {})
        asns = d.get("asns") or []
        return {"asn": (f"AS{asns[0]}" if asns else None), "prefix": d.get("prefix")}

    async def _expand_asn(self, ctx: RunContext, asn: str, seed: str) -> None:
        overview = await ctx.http.get_json(f"{_RIPESTAT}/as-overview/data.json", params={"resource": asn})
        holder = None
        if overview and overview.get("status") == "ok":
            holder = overview.get("data", {}).get("holder")
        ctx.add_asset(AssetKind.ASN, asn, source=self.name, holder=holder, origin_seed=seed)

        prefixes = await ctx.http.get_json(
            f"{_RIPESTAT}/announced-prefixes/data.json", params={"resource": asn}
        )
        count = 0
        if prefixes and prefixes.get("status") == "ok":
            for entry in prefixes.get("data", {}).get("prefixes", []):
                pfx = entry.get("prefix")
                if pfx:
                    ctx.add_asset(AssetKind.CIDR, pfx, source=self.name, asn=asn, holder=holder)
                    count += 1
        if count:
            ctx.add_finding(
                f"{asn} ({holder or 'unknown holder'}) announces {count} prefixes",
                module=self.name,
                severity=Severity.INFO,
                asset=asn,
                description=(
                    "Autonomous system linked to the target. The announced prefixes are "
                    "candidate attack surface — enumerate hosts within any range that is "
                    "in scope. Verify ownership before treating an ASN as the target's."
                ),
                evidence={"asn": asn, "holder": holder, "prefix_count": count},
                tags={"asn", "footprint"},
            )
