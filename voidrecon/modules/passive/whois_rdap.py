"""Domain registration intelligence via RDAP.

RDAP is the modern, structured successor to legacy WHOIS (which is being retired),
so VoidRecon queries it for each seed apex: registrar, registrant organisation
(when not redacted), creation/expiry dates, status flags, and authoritative
nameservers. This is core attribution — it confirms ownership and surfaces the
mail/DNS infrastructure an attacker maps early. Keyless and fully passive via the
rdap.org bootstrap.
"""

from __future__ import annotations

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence, Severity
from voidrecon.core.module import Module, Phase, register


def _vcard_field(entity: dict, field: str) -> str | None:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2:
        return None
    for item in vcard[1]:
        if isinstance(item, list) and item and item[0] == field:
            return item[3] if len(item) > 3 else None
    return None


def parse_rdap(data: dict) -> dict:
    """Extract the useful bits from an RDAP domain response."""
    out: dict = {"registrar": None, "registrant": None, "created": None,
                 "expires": None, "status": [], "nameservers": []}
    out["status"] = data.get("status", []) or []
    for ev in data.get("events", []) or []:
        action = ev.get("eventAction")
        if action == "registration":
            out["created"] = ev.get("eventDate")
        elif action in ("expiration", "expiry"):
            out["expires"] = ev.get("eventDate")
    for ent in data.get("entities", []) or []:
        roles = ent.get("roles", []) or []
        name = _vcard_field(ent, "fn") or _vcard_field(ent, "org")
        if "registrar" in roles and name and not out["registrar"]:
            out["registrar"] = name
        if "registrant" in roles and name and not out["registrant"]:
            out["registrant"] = name
    for ns in data.get("nameservers", []) or []:
        ldh = (ns.get("ldhName") or "").lower().rstrip(".")
        if ldh:
            out["nameservers"].append(ldh)
    return out


@register
class WhoisRdap(Module):
    name = "whois_rdap"
    phase = Phase.SCOPE
    active = False
    description = "Domain registration intel (registrar/registrant/dates/NS) via RDAP"

    async def run(self, ctx: RunContext) -> None:
        for apex in ctx.scope.seeds:
            data = await ctx.http.get_json(f"https://rdap.org/domain/{apex}",
                                           headers={"Accept": "application/rdap+json"})
            if not isinstance(data, dict):
                continue
            info = parse_rdap(data)
            ctx.add_asset(AssetKind.DOMAIN, apex, source=self.name,
                          confidence=Confidence.CONFIRMED,
                          registrar=info["registrar"], registrant=info["registrant"],
                          registered=info["created"], expires=info["expires"],
                          rdap_status=info["status"])
            for ns in info["nameservers"]:
                ctx.add_asset(AssetKind.DOMAIN, ns, source=self.name,
                              confidence=Confidence.LIKELY, role="nameserver")
            self.log.info("%s: registrar=%s registrant=%s NS=%d",
                          apex, info["registrar"], info["registrant"], len(info["nameservers"]))
            if info["registrant"]:
                ctx.add_finding(
                    f"Registrant organisation for {apex}: {info['registrant']}",
                    module=self.name, severity=Severity.INFO, asset=apex,
                    description=("Registrant identity is a strong pivot for reverse-WHOIS: other "
                                 "domains registered by the same organisation are likely in the same "
                                 "footprint (request scope expansion before testing them)."),
                    evidence={k: info[k] for k in ("registrar", "registrant", "created", "expires")},
                    tags={"whois", "attribution"},
                )
