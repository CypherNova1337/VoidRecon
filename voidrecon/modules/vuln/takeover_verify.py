"""Active subdomain-takeover verification.

Correlation flags dangling CNAMEs as *candidates*; this module confirms them.
For each subdomain whose CNAME points at a known SaaS/cloud provider, it fetches
the page and matches the provider's "unclaimed resource" fingerprint (the classic
can-i-take-over-xyz signatures). A match promotes the lead to a high-confidence
finding; a miss leaves it as a candidate. It only reads the response — it never
registers the third-party resource (which would be acting on the finding, not
verifying it).

Active and scope-gated.
"""

from __future__ import annotations

import asyncio

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence, Severity
from voidrecon.core.module import Module, Phase, register

# provider -> (cname substrings, response fingerprint substrings)
_FINGERPRINTS = {
    "AWS S3": (["s3.amazonaws.com", "s3-website"], ["NoSuchBucket", "The specified bucket does not exist"]),
    "GitHub Pages": ["github.io"],
    "Heroku": (["herokuapp.com", "herokudns.com"], ["No such app", "herokucdn.com/error-pages/no-such-app.html"]),
    "Fastly": (["fastly.net"], ["Fastly error: unknown domain"]),
    "Ghost": (["ghost.io"], ["The thing you were looking for is no longer here"]),
    "Shopify": (["myshopify.com"], ["Sorry, this shop is currently unavailable", "Only one step left"]),
    "Surge": (["surge.sh"], ["project not found"]),
    "Tumblr": (["domains.tumblr.com"], ["Whatever you were looking for doesn't currently exist"]),
    "Unbounce": (["unbouncepages.com"], ["The requested URL was not found on this server"]),
    "Pantheon": (["pantheonsite.io"], ["404 error unknown site"]),
    "Wordpress": (["wordpress.com"], ["Do you want to register"]),
    "Zendesk": (["zendesk.com"], ["Help Center Closed"]),
    "Readthedocs": (["readthedocs.io"], ["unknown to Read the Docs"]),
    "Netlify": (["netlify.app", "netlify.com"], ["Not Found - Request ID"]),
}
_GITHUB_FP = ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file"]


def match_takeover(cname: str, body: str) -> str | None:
    """Return the provider name if a takeover fingerprint matches, else None."""
    cname = (cname or "").lower()
    for provider, spec in _FINGERPRINTS.items():
        cnames, sigs = (spec if isinstance(spec, tuple) else (spec, _GITHUB_FP))
        if any(c in cname for c in cnames) and any(s.lower() in body.lower() for s in sigs):
            return provider
    return None


@register
class TakeoverVerify(Module):
    name = "takeover_verify"
    phase = Phase.VULN
    active = True
    description = "Verify subdomain-takeover candidates against provider fingerprints"
    depends_on = ("dns_resolve", "http_probe")

    async def run(self, ctx: RunContext) -> None:
        candidates = [
            a for a in ctx.store.assets(kind=AssetKind.SUBDOMAIN)
            if a.attrs.get("cname") and ctx.can_touch(a.value)
        ]
        if not candidates:
            self.log.info("no CNAME'd hosts to verify for takeover")
            return
        sem = asyncio.Semaphore(int(ctx.config.get("opsec.max_concurrency", 20)))
        confirmed = 0

        async def worker(asset):
            nonlocal confirmed
            async with sem:
                if await self._verify(ctx, asset):
                    confirmed += 1

        await asyncio.gather(*(worker(a) for a in candidates))
        self.log.info("takeover verification: %d confirmed of %d candidates", confirmed, len(candidates))

    async def _verify(self, ctx: RunContext, asset) -> bool:
        cname = asset.attrs.get("cname", "")
        for scheme in ("https", "http"):
            resp = await ctx.http.get(f"{scheme}://{asset.value}/")
            if resp is None:
                continue
            provider = match_takeover(cname, resp.text)
            if provider:
                asset.attrs["takeover_candidate"] = True
                asset.attrs["takeover_confirmed"] = provider
                asset.tags.add("takeover")
                ctx.add_finding(
                    f"Confirmed subdomain-takeover fingerprint: {asset.value} ({provider})",
                    module=self.name, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                    asset=asset.value,
                    description=(f"{asset.value} points to {provider} ({cname}) and the response carries "
                                 f"{provider}'s unclaimed-resource fingerprint. The subdomain is very "
                                 "likely takeoverable. Confirm ownership and report — do not claim the "
                                 "resource yourself unless the program authorises it."),
                    evidence={"cname": cname, "provider": provider, "url": f"{scheme}://{asset.value}/"},
                    references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
                    tags={"takeover", "exposure"},
                )
                return True
        return False
