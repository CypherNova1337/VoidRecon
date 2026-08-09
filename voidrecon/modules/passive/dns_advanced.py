"""Advanced DNS reconnaissance — zone transfer and SPF-chain mining.

Two long-standing techniques:

* **Zone transfer (AXFR):** ask each authoritative nameserver for the entire
  zone. It's almost always refused — but when a misconfigured server allows it,
  the attacker gets every record at once. VoidRecon tries it and, on success,
  ingests the lot.
* **SPF / include chains:** an SPF record enumerates the hosts and third parties
  allowed to send mail for the domain. Following ``include:``, ``a:``, ``mx:``,
  and ``ip4/ip6`` mechanisms reveals mail infrastructure and related domains.

Passive: it queries the domain's own nameservers and public TXT records, not the
web target.
"""

from __future__ import annotations

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence, Severity
from voidrecon.core.module import Module, Phase, register
from voidrecon.utils import net

try:
    import dns.asyncresolver
    import dns.query
    import dns.zone

    _HAS_DNS = True
except Exception:  # pragma: no cover
    _HAS_DNS = False


def parse_spf_mechanisms(spf: str) -> dict:
    """Extract includes, a/mx hostnames, and ip4/ip6 nets from an SPF record."""
    out = {"includes": [], "hosts": [], "ips": []}
    for tok in spf.split():
        tok = tok.strip()
        low = tok.lower()
        if low.startswith("include:") or low.startswith("+include:"):
            out["includes"].append(tok.split(":", 1)[1])
        elif low.startswith(("a:", "+a:", "mx:", "+mx:")):
            out["hosts"].append(tok.split(":", 1)[1])
        elif low.startswith(("ip4:", "ip6:", "+ip4:", "+ip6:")):
            out["ips"].append(tok.split(":", 1)[1])
        elif low.startswith("redirect="):
            out["includes"].append(tok.split("=", 1)[1])
    return out


@register
class DnsAdvanced(Module):
    name = "dns_advanced"
    phase = Phase.PASSIVE
    active = False
    description = "Zone-transfer (AXFR) attempts and SPF include-chain mining"

    async def run(self, ctx: RunContext) -> None:
        if not _HAS_DNS:
            self.log.warning("dnspython not installed — skipping advanced DNS")
            return
        from voidrecon.utils.resolvers import apply_resolvers

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 5.0
        apply_resolvers(resolver, ctx.config)
        for apex in ctx.scope.seeds:
            await self._axfr(ctx, resolver, apex)
            await self._spf_chain(ctx, resolver, apex, depth=0, seen=set())

    async def _axfr(self, ctx: RunContext, resolver, apex: str) -> None:
        try:
            ns_answer = await resolver.resolve(apex, "NS")
            nameservers = [str(r.target).rstrip(".") for r in ns_answer]
        except Exception:
            return
        for ns in nameservers:
            try:
                ns_ip_ans = await resolver.resolve(ns, "A")
                ns_ip = ns_ip_ans[0].address
            except Exception:
                continue
            try:
                # dns.query.xfr is synchronous; it fails fast when refused.
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, apex, lifetime=8.0))
            except Exception:
                continue
            names = [str(n) for n in zone.nodes.keys()]
            hosts = [f"{n}.{apex}" if n != "@" else apex for n in names]
            for h in hosts:
                h = net.normalize_host(h)
                if net.is_domain(h) and net.is_subdomain_of(h, apex):
                    kind = AssetKind.DOMAIN if h == apex else AssetKind.SUBDOMAIN
                    ctx.add_asset(kind, h, source=self.name, confidence=Confidence.CONFIRMED)
            ctx.add_finding(
                f"Zone transfer (AXFR) allowed by {ns} for {apex}",
                module=self.name, severity=Severity.HIGH, confidence=Confidence.CONFIRMED, asset=apex,
                description=("The nameserver permitted a full zone transfer, disclosing every DNS "
                             "record for the domain — a serious information-disclosure misconfiguration."),
                evidence={"nameserver": ns, "records": len(hosts)},
                tags={"axfr", "dns", "exposure"},
            )
            self.log.info("AXFR succeeded on %s (%d records)", ns, len(hosts))

    async def _spf_chain(self, ctx: RunContext, resolver, domain: str, depth: int, seen: set) -> None:
        if depth > 3 or domain in seen:
            return
        seen.add(domain)
        try:
            txt = [r.to_text().strip('"') for r in await resolver.resolve(domain, "TXT")]
        except Exception:
            return
        spf = next((t for t in txt if t.lower().startswith("v=spf1")), None)
        if not spf:
            return
        mech = parse_spf_mechanisms(spf)
        for host in mech["hosts"] + mech["includes"]:
            host = net.normalize_host(host)
            if not net.is_domain(host):
                continue
            related = ctx.scope.is_related(host)
            ctx.add_asset(AssetKind.DOMAIN if not related else AssetKind.SUBDOMAIN, host,
                          source=self.name, confidence=Confidence.LIKELY, via="spf")
        for inc in mech["includes"]:
            inc = net.normalize_host(inc)
            if net.is_domain(inc):
                await self._spf_chain(ctx, resolver, inc, depth + 1, seen)
        if mech["includes"] or mech["hosts"]:
            self.log.info("%s SPF -> %d includes, %d hosts", domain,
                          len(mech["includes"]), len(mech["hosts"]))
