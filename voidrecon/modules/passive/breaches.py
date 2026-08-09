"""Breach correlation.

Known data breaches affecting a target's domain are direct leads: they suggest
credential-stuffing exposure and hint at which third-party services employees
use. This module queries Have I Been Pwned's public breaches-by-domain endpoint
(no key required) for each seed apex and records any breaches it finds. Fully
passive — it asks a third-party dataset about the domain, never the target.
"""

from __future__ import annotations

from voidrecon.core.context import RunContext
from voidrecon.core.models import Confidence, Severity
from voidrecon.core.module import Module, Phase, register


@register
class Breaches(Module):
    name = "breaches"
    phase = Phase.PASSIVE
    active = False
    description = "Known data breaches affecting the target domain (HaveIBeenPwned)"

    async def run(self, ctx: RunContext) -> None:
        for apex in ctx.scope.seeds:
            await self._check(ctx, apex)

    async def _check(self, ctx: RunContext, apex: str) -> None:
        data = await ctx.http.get_json(
            "https://haveibeenpwned.com/api/v3/breaches",
            params={"domain": apex},
            headers={"User-Agent": "VoidRecon"},
        )
        if not isinstance(data, list) or not data:
            return
        names = [b.get("Name") for b in data if b.get("Name")]
        total_accounts = sum(int(b.get("PwnCount", 0) or 0) for b in data)
        ctx.add_finding(
            f"{len(data)} known breach(es) reference {apex}",
            module=self.name,
            severity=Severity.MEDIUM,
            confidence=Confidence.LIKELY,
            asset=apex,
            description=(
                "Public breach records mention this domain. Employee/customer credentials "
                "may be circulating — a credential-stuffing and password-reuse risk. Review "
                "the named breaches and consider enforced resets / MFA where in scope."
            ),
            evidence={
                "breaches": names[:50],
                "total_pwned_accounts": total_accounts,
            },
            references=["https://haveibeenpwned.com/"],
            tags={"breach", "credentials"},
        )
        self.log.info("%s: %d breach(es), ~%d exposed accounts", apex, len(data), total_accounts)
