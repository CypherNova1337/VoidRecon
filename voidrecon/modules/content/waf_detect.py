"""WAF / CDN detection.

Knowing a host sits behind a WAF or CDN shapes everything downstream — it changes
how you probe, what evasions are pointless, and where the real origin might be
hiding. This module fingerprints common WAF/CDN vendors from response headers and
cookies (a single benign request per host) and tags the asset accordingly. Active
and scope-gated.
"""

from __future__ import annotations

import asyncio

from voidrecon.core.context import RunContext
from voidrecon.core.models import Confidence, Severity
from voidrecon.core.module import Module, Phase, register

# vendor -> {"headers": [(name, substr|None)], "cookies": [prefix], "server": [substr]}
_SIGNATURES = {
    "Cloudflare": {"headers": [("cf-ray", None), ("cf-cache-status", None)], "cookies": ["__cfduid", "__cf_bm"], "server": ["cloudflare"]},
    "Akamai": {"headers": [("x-akamai-transformed", None)], "cookies": ["ak_bmsc", "bm_sz"], "server": ["akamaighost"]},
    "Imperva/Incapsula": {"headers": [("x-iinfo", None), ("x-cdn", "incapsula")], "cookies": ["incap_ses", "visid_incap"], "server": []},
    "Sucuri": {"headers": [("x-sucuri-id", None), ("x-sucuri-cache", None)], "cookies": [], "server": ["sucuri"]},
    "AWS CloudFront/WAF": {"headers": [("x-amz-cf-id", None), ("x-amzn-requestid", None)], "cookies": [], "server": ["cloudfront", "awselb"]},
    "F5 BIG-IP": {"headers": [("x-waf-status", None)], "cookies": ["bigipserver", "ts01", "f5_cspm"], "server": ["big-ip", "bigip"]},
    "Barracuda": {"headers": [], "cookies": ["barra_counter_session"], "server": ["barracuda"]},
    "Fortinet FortiWeb": {"headers": [], "cookies": ["fortiwafsid"], "server": ["fortiweb"]},
    "Fastly": {"headers": [("x-served-by", "cache-"), ("fastly-io-info", None)], "cookies": [], "server": ["fastly"]},
    "ModSecurity": {"headers": [("x-mod-security", None)], "cookies": [], "server": ["mod_security", "modsecurity"]},
    "Wallarm": {"headers": [("x-wallarm-mode", None)], "cookies": [], "server": ["wallarm"]},
    "StackPath": {"headers": [("x-sp-edge", None)], "cookies": [], "server": ["stackpath"]},
}


def detect_waf(headers: dict, cookies: list[str]) -> list[str]:
    """Return the names of any WAF/CDN vendors whose signatures match."""
    lowered = {k.lower(): str(v).lower() for k, v in headers.items()}
    server = lowered.get("server", "")
    cookie_blob = " ".join(cookies).lower()
    matched: list[str] = []
    for vendor, sig in _SIGNATURES.items():
        hit = False
        for name, substr in sig["headers"]:
            if name in lowered and (substr is None or substr in lowered[name]):
                hit = True
                break
        if not hit and any(c in cookie_blob for c in sig["cookies"]):
            hit = True
        if not hit and any(s in server for s in sig["server"]):
            hit = True
        if hit:
            matched.append(vendor)
    return matched


@register
class WafDetect(Module):
    name = "waf_detect"
    phase = Phase.CONTENT
    active = True
    description = "Fingerprint WAF/CDN vendors from response headers and cookies"
    depends_on = ("http_probe",)

    async def run(self, ctx: RunContext) -> None:
        targets = [
            a for a in ctx.store.assets()
            if a.attrs.get("http_url") and "web" in a.tags and ctx.can_touch(a.value)
        ]
        if not targets:
            self.log.info("no in-scope web assets for WAF detection")
            return
        sem = asyncio.Semaphore(int(ctx.config.get("opsec.max_concurrency", 20)))

        async def worker(asset):
            async with sem:
                await self._detect(ctx, asset)

        await asyncio.gather(*(worker(a) for a in targets))
        behind = sum(1 for a in targets if a.attrs.get("waf"))
        self.log.info("WAF/CDN detection: %d/%d hosts behind a known vendor", behind, len(targets))

    async def _detect(self, ctx: RunContext, asset) -> None:
        resp = await ctx.http.get(asset.attrs["http_url"])
        if resp is None:
            return
        cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        vendors = detect_waf(dict(resp.headers), cookies)
        if vendors:
            asset.attrs["waf"] = vendors
            asset.tags.add("waf")
            ctx.add_finding(
                f"WAF/CDN detected on {asset.value}: {', '.join(vendors)}",
                module=self.name, severity=Severity.INFO, confidence=Confidence.LIKELY,
                asset=asset.value,
                description="Traffic is fronted by a WAF/CDN. Consider origin-IP discovery and expect filtering.",
                evidence={"vendors": vendors}, tags={"waf"},
            )
