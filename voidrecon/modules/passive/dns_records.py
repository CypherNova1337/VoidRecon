"""DNS records and email-security posture.

Beyond hostnames, an org's DNS reveals its mail infrastructure and — often —
weaknesses worth reporting on their own: a missing or permissive SPF record, a
DMARC policy set to ``p=none``, no CAA record. This module pulls MX/TXT/NS/CAA
for each seed apex, evaluates the email-authentication posture, and records the
supporting infrastructure. Fully passive (recursive-resolver queries only).
"""

from __future__ import annotations

import asyncio

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence, Severity
from voidrecon.core.module import Module, Phase, register

try:
    import dns.asyncresolver

    _HAS_DNS = True
except Exception:  # pragma: no cover
    _HAS_DNS = False

_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "dkim", "mail", "s1", "s2"]


def analyze_spf(txt_records: list[str]) -> tuple[str | None, Severity | None, str]:
    """Return (spf_record, severity_if_issue, note)."""
    spf = next((r for r in txt_records if r.lower().startswith("v=spf1")), None)
    if not spf:
        return None, Severity.MEDIUM, "No SPF record — the domain is easier to spoof in email."
    low = spf.lower()
    if "+all" in low:
        return spf, Severity.HIGH, "SPF ends in '+all' — permits any sender to spoof this domain."
    if "?all" in low:
        return spf, Severity.MEDIUM, "SPF uses '?all' (neutral) — provides no real protection."
    if "~all" in low:
        return spf, Severity.LOW, "SPF uses '~all' (softfail) — consider '-all' (hardfail)."
    if "-all" in low:
        return spf, None, "SPF present with '-all' (hardfail)."
    return spf, Severity.LOW, "SPF present but has no explicit 'all' mechanism."


def analyze_dmarc(txt_records: list[str]) -> tuple[str | None, Severity | None, str]:
    dmarc = next((r for r in txt_records if r.lower().startswith("v=dmarc1")), None)
    if not dmarc:
        return None, Severity.MEDIUM, "No DMARC record — spoofed mail is not rejected or reported."
    low = dmarc.lower().replace(" ", "")
    if "p=none" in low:
        return dmarc, Severity.LOW, "DMARC policy is 'p=none' — monitoring only, no enforcement."
    if "p=quarantine" in low:
        return dmarc, None, "DMARC policy is 'p=quarantine'."
    if "p=reject" in low:
        return dmarc, None, "DMARC policy is 'p=reject' (strong)."
    return dmarc, Severity.LOW, "DMARC present but policy unclear."


@register
class DnsRecords(Module):
    name = "dns_records"
    phase = Phase.PASSIVE
    active = False
    description = "MX/TXT/NS/CAA records + SPF/DMARC/DKIM email-security analysis"

    async def run(self, ctx: RunContext) -> None:
        if not _HAS_DNS:
            self.log.warning("dnspython not installed — skipping DNS records")
            return
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 5.0
        resolver.timeout = 5.0
        for apex in ctx.scope.seeds:
            await self._analyze_domain(ctx, resolver, apex)

    async def _q(self, resolver, name, rtype) -> list[str]:
        try:
            answer = await resolver.resolve(name, rtype)
            return [r.to_text().strip('"') for r in answer]
        except Exception:
            return []

    async def _analyze_domain(self, ctx: RunContext, resolver, apex: str) -> None:
        mx, txt, ns, caa, dmarc_txt = await asyncio.gather(
            self._q(resolver, apex, "MX"),
            self._q(resolver, apex, "TXT"),
            self._q(resolver, apex, "NS"),
            self._q(resolver, apex, "CAA"),
            self._q(resolver, f"_dmarc.{apex}", "TXT"),
        )
        domain_asset = ctx.add_asset(
            AssetKind.DOMAIN, apex, source=self.name, confidence=Confidence.CONFIRMED,
            mx=mx, ns=ns, caa=caa,
        )
        # NS as related infrastructure.
        for record in ns:
            host = record.rstrip(".")
            ctx.add_asset(AssetKind.DOMAIN, host, source=self.name,
                          confidence=Confidence.LIKELY, role="nameserver")

        # SPF
        spf, spf_sev, spf_note = analyze_spf(txt)
        if spf_sev:
            ctx.add_finding(f"Email spoofing risk (SPF) on {apex}", module=self.name,
                            severity=spf_sev, asset=apex, description=spf_note,
                            evidence={"spf": spf}, tags={"email", "spf"})
        # DMARC
        dmarc, dmarc_sev, dmarc_note = analyze_dmarc(dmarc_txt)
        if dmarc_sev:
            ctx.add_finding(f"Email spoofing risk (DMARC) on {apex}", module=self.name,
                            severity=dmarc_sev, asset=apex, description=dmarc_note,
                            evidence={"dmarc": dmarc}, tags={"email", "dmarc"})
        # CAA (absence is informational — any CA may issue).
        if not caa:
            ctx.add_finding(f"No CAA record on {apex}", module=self.name, severity=Severity.INFO,
                            asset=apex, description="No CAA record — any certificate authority may issue certs for this domain.",
                            tags={"dns", "caa"})
        # DKIM presence (best-effort common selectors).
        found_dkim = []
        for sel in _DKIM_SELECTORS:
            rec = await self._q(resolver, f"{sel}._domainkey.{apex}", "TXT")
            if any("v=dkim1" in r.lower() or "p=" in r.lower() for r in rec):
                found_dkim.append(sel)
        if domain_asset:
            domain_asset.attrs["dkim_selectors"] = found_dkim
            domain_asset.attrs["spf"] = spf
            domain_asset.attrs["dmarc"] = dmarc
        self.log.info("%s: MX=%d NS=%d SPF=%s DMARC=%s DKIM=%s",
                      apex, len(mx), len(ns), bool(spf), bool(dmarc), ",".join(found_dkim) or "-")
