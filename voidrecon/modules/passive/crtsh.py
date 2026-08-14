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
        # crt.sh is the richest keyless source but routinely slow — give it a
        # generous timeout and a second attempt before writing it off, otherwise
        # a transient stall silently costs us the best source.
        outcome = None
        for attempt in range(2):
            outcome = await ctx.http.fetch(
                "https://crt.sh/", params={"q": f"%.{apex}", "output": "json"},
                timeout=60.0,
            )
            if outcome.ok or not outcome.failed:
                break
        names: set[str] = set()
        if outcome and outcome.ok and isinstance(outcome.json, list):
            for row in outcome.json:
                for field in ("name_value", "common_name"):
                    value = row.get(field) or ""
                    for line in value.splitlines():
                        host = net.normalize_host(line)
                        if host and net.is_domain(host) and net.is_subdomain_of(host, apex):
                            names.add(host)
        for host in names:
            kind = AssetKind.DOMAIN if host == apex else AssetKind.SUBDOMAIN
            ctx.add_asset(kind, host, source=self.name, confidence=Confidence.LIKELY)
        ctx.note_source("crt.sh", apex, outcome, len(names))
        return len(names)
