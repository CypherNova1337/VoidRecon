"""Certificate Transparency mining via crt.sh.

CT logs are one of the richest passive sources of subdomains: every TLS
certificate an organisation issues is public, and it routinely leaks internal,
staging, and pre-production hostnames long before they are linked anywhere.
This module pulls every logged certificate for each seed apex and extracts the
subject + SAN names.
"""

from __future__ import annotations

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence
from voidrecon.core.module import Module, Phase, register
from voidrecon.utils import net


@register
class CrtSh(Module):
    name = "crtsh"
    phase = Phase.PASSIVE
    active = False
    description = "Subdomains from Certificate Transparency logs (crt.sh)"

    async def run(self, ctx: RunContext) -> None:
        total = 0
        for seed in ctx.scope.seeds:
            found = await self._query(ctx, seed)
            total += found
            self.log.info("crt.sh: %d names for %s", found, seed)
        if total:
            self.log.info("crt.sh discovered %d subdomain observations", total)

    async def _query(self, ctx: RunContext, apex: str) -> int:
        data = await ctx.http.get_json(
            "https://crt.sh/", params={"q": f"%.{apex}", "output": "json"}
        )
        if not data:
            return 0
        names: set[str] = set()
        for row in data:
            for field in ("name_value", "common_name"):
                value = row.get(field) or ""
                for line in value.splitlines():
                    host = net.normalize_host(line)
                    if host and net.is_domain(host) and net.is_subdomain_of(host, apex):
                        names.add(host)
        for host in names:
            kind = AssetKind.DOMAIN if host == apex else AssetKind.SUBDOMAIN
            ctx.add_asset(kind, host, source=self.name, confidence=Confidence.LIKELY)
        return len(names)
