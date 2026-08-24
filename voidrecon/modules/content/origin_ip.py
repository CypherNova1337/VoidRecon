"""Origin-IP discovery behind a WAF/CDN.

A CDN only protects the origin if the origin's real IP stays secret. Operators
routinely find it anyway — in historical DNS, in sibling records, or by simply
asking every discovered IP "are you serving this site?" via a spoofed Host
header. This module takes each WAF-fronted, in-scope host and tests the IPs
VoidRecon already discovered: a direct request to the IP carrying the target's
Host header that returns the same page is a likely origin, meaning the WAF can be
bypassed by hitting the origin directly.

Active and scope-gated. Uses a dedicated TLS-permissive client (origin certs
rarely match when addressed by IP).
"""

from __future__ import annotations

import asyncio

import httpx

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence, Severity
from voidrecon.core.module import Module, Phase, register
from voidrecon.modules.content.waf_detect import detect_waf
from voidrecon.utils.text import truncate


@register
class OriginIp(Module):
    name = "origin_ip"
    phase = Phase.CONTENT
    active = True
    description = "Find real origin IPs of WAF/CDN-fronted hosts (Host-header check)"
    depends_on = ("http_probe", "waf_detect")
    enabled_by_default = False  # opt-in: probes many IPs with spoofed Host headers

    async def run(self, ctx: RunContext) -> None:
        fronted = [
            a for a in ctx.store.assets()
            if a.attrs.get("waf") and "web" in a.tags and a.attrs.get("http_title") and ctx.can_touch(a.value)
        ]
        if not fronted:
            self.log.info("no WAF-fronted hosts with a baseline to test")
            return
        # Test the highest-value fronted hosts first, and cap how many — origins
        # are shared infrastructure, so probing every one of hundreds of hosts
        # against every IP is a days-long cross-product for no extra signal.
        fronted.sort(key=lambda a: a.score, reverse=True)
        max_hosts = int(ctx.config.get("modules.origin_ip.max_hosts", 15))
        fronted = fronted[:max_hosts]

        # Candidate origin IPs: everything discovered, minus the CDN IPs the
        # fronted hosts already resolve to.
        cdn_ips: set[str] = set()
        for a in fronted:
            cdn_ips.update(a.attrs.get("resolved_ips") or [])
        candidates = [a.value for a in ctx.store.assets(kind=AssetKind.IP) if a.value not in cdn_ips]
        max_candidates = int(ctx.config.get("modules.origin_ip.max_candidates", 100))
        candidates = candidates[:max_candidates]
        if not candidates:
            self.log.info("no candidate origin IPs to test")
            return

        probes = len(fronted) * len(candidates)
        self.log.info("testing up to %d candidate IPs against %d fronted host(s) (%d probes max)",
                      len(candidates), len(fronted), probes)
        # Origin checks don't need the full request timeout — a dead/firewalled IP
        # should fail fast, not burn 20s each. That single change is the difference
        # between minutes and days on a large IP set.
        probe_timeout = float(ctx.config.get("modules.origin_ip.probe_timeout", 6.0))
        sem = asyncio.Semaphore(min(int(ctx.config.get("opsec.max_concurrency", 20)), 20))
        found = 0
        solved: set[str] = set()   # hosts whose origin we've already located

        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=probe_timeout) as client:
            async def test(host_asset, ip):
                nonlocal found
                if host_asset.value in solved:   # stop probing a host once solved
                    return
                async with sem:
                    if host_asset.value in solved:
                        return
                    if await self._matches(ctx, client, host_asset, ip):
                        found += 1
                        solved.add(host_asset.value)

            tasks = [test(h, ip) for h in fronted for ip in candidates]
            await asyncio.gather(*tasks)
        self.log.info("origin discovery complete: %d candidate origin(s) found", found)

    async def _matches(self, ctx: RunContext, client, host_asset, ip: str) -> bool:
        hostname = host_asset.value
        baseline_title = (host_asset.attrs.get("http_title") or "").strip()
        fronting = set(host_asset.attrs.get("waf") or [])
        for scheme in ("https", "http"):
            await ctx.http._limiter.acquire()  # share the run's throttle
            try:
                resp = await client.get(f"{scheme}://{ip}/",
                                        headers={"Host": hostname, "User-Agent": "VoidRecon"})
            except Exception:
                continue
            if resp.status_code >= 500:
                continue
            # Critical: if the response still carries the CDN's own signature, this
            # IP is just another CDN edge, not the origin — a request to any CDN IP
            # with the target Host is served by the CDN. Skip those.
            cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
            if fronting & set(detect_waf(dict(resp.headers), cookies)):
                continue
            title = self._title(resp.text)
            if baseline_title and title and baseline_title.lower() == title.lower():
                ctx.add_finding(
                    f"Origin IP behind WAF: {hostname} -> {ip}",
                    module=self.name, severity=Severity.HIGH, confidence=Confidence.LIKELY,
                    asset=hostname,
                    description=(
                        f"Direct request to {ip} with Host: {hostname} returned the same page as the "
                        "WAF/CDN-fronted site. The origin appears reachable directly, allowing the "
                        "protection to be bypassed. Confirm and report the origin exposure."
                    ),
                    evidence={"host": hostname, "origin_ip": ip, "scheme": scheme,
                              "matched_title": truncate(title, 100)},
                    tags={"origin", "waf-bypass"},
                )
                a = ctx.store.get_asset(AssetKind.IP, ip)
                if a:
                    a.tags.add("origin-candidate")
                    a.attrs.setdefault("origin_for", []).append(hostname)
                return True
        return False

    def _title(self, body: str) -> str | None:
        import re

        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        return re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else None
