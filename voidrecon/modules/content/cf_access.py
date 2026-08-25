"""Cloudflare Access enumeration.

Cloudflare Access (Zero Trust) fronts internal apps with an identity gate. It is
fingerprintable *without any credentials*: hitting a protected host redirects to
``https://<team>.cloudflareaccess.com/cdn-cgi/access/login/<host>`` and the login
URL carries a ``kid`` (the signing-key id) and a base64 ``meta`` blob (the app
descriptor — hostname, audience). None of that is secret; it is the public header
of the auth flow.

Grouping the discovered hosts by their Access ``kid``/team reveals the shape of
the org's Zero-Trust deployment: which hosts share one Access application/policy,
which team domain guards them, and where a stray host sits behind a different
(possibly weaker or misconfigured) policy. That map is the lead — it tells you
which gate to study and which hosts move together.

Active and scope-gated: one GET per candidate host, redirects not followed.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import re
from collections import defaultdict

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence, Severity
from voidrecon.core.module import Module, Phase, register

_LOGIN_RE = re.compile(
    r"https://([a-z0-9-]+)\.cloudflareaccess\.com/cdn-cgi/access/login/([^?\s\"']+)", re.I)
_ACCESS_HINT = re.compile(r"/cdn-cgi/access/|cloudflareaccess\.com", re.I)


def _b64url_json(segment: str) -> dict | None:
    """Decode one base64url JWT/meta segment to JSON. No signature check — this is
    public header data, decoded purely to read hostname/aud."""
    if not segment:
        return None
    seg = segment.split(".")
    # a JWT-like blob: take the payload (2nd part) if present, else the whole thing
    raw = seg[1] if len(seg) >= 2 else seg[0]
    raw += "=" * (-len(raw) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(raw.encode()).decode("utf-8", "replace"))
    except (binascii.Error, ValueError, json.JSONDecodeError):
        return None


@register
class CloudflareAccess(Module):
    name = "cf_access"
    phase = Phase.CONTENT
    active = True
    description = "Map Cloudflare Access (Zero Trust) gates and group hosts by policy (kid/team)"
    depends_on = ("http_probe",)
    enabled_by_default = True

    async def run(self, ctx: RunContext) -> None:
        # Candidate hosts: live web hosts we're allowed to touch. One light GET each.
        hosts = [
            a for a in ctx.store.assets(kind=AssetKind.SUBDOMAIN) + ctx.store.assets(kind=AssetKind.DOMAIN)
            if ("web" in a.tags or a.attrs.get("http_status")) and ctx.can_touch(a.value)
        ]
        if not hosts:
            self.log.info("no live in-scope web hosts to test for Cloudflare Access")
            return
        max_hosts = int(ctx.config.get("modules.cf_access.max_hosts", 500))
        hosts = hosts[:max_hosts]

        sem = asyncio.Semaphore(min(int(ctx.config.get("opsec.max_concurrency", 20)), 20))
        # kid -> list of (host, team, app_aud); also protected hosts with no kid seen.
        by_kid: dict[str, list[dict]] = defaultdict(list)
        by_team: dict[str, set[str]] = defaultdict(set)
        protected: list[str] = []

        async def check(asset):
            async with sem:
                info = await self._probe(ctx, asset.value)
            if not info:
                return
            protected.append(asset.value)
            asset.tags.add("cf-access")
            asset.attrs["cf_access"] = info
            if info.get("team"):
                by_team[info["team"]].add(asset.value)
            if info.get("kid"):
                by_kid[info["kid"]].append({"host": asset.value, **info})

        await asyncio.gather(*(check(h) for h in hosts))

        if not protected:
            self.log.info("no Cloudflare Access gates detected")
            return
        self.log.info("cloudflare access: %d protected host(s), %d policy group(s) by kid, %d team(s)",
                      len(protected), len(by_kid), len(by_team))

        # One finding per Access policy group (kid): the hosts that move together.
        for kid, members in by_kid.items():
            hosts_in = sorted({m["host"] for m in members})
            teams = sorted({m.get("team") for m in members if m.get("team")})
            auds = sorted({m.get("aud") for m in members if m.get("aud")})
            ctx.add_finding(
                f"Cloudflare Access policy group ({len(hosts_in)} host(s), kid {kid[:12]}…)",
                module=self.name, severity=Severity.INFO, confidence=Confidence.LIKELY,
                asset=hosts_in[0],
                description=(
                    "These hosts are gated by the same Cloudflare Access signing key (kid) — they "
                    "share one Access application/policy. Study the gate once and it applies to "
                    "all of them; a host that should be here but isn't (grouped under a different "
                    "kid) is worth a closer look for a weaker or misconfigured policy."
                ),
                evidence={"kid": kid, "team": teams, "aud": auds, "hosts": hosts_in[:100]},
                tags={"cf-access", "zero-trust", "attribution"},
            )

        # Hosts detected as protected but without a parsed kid (still useful signal).
        no_kid = sorted(set(protected) - {m["host"] for members in by_kid.values() for m in members})
        if no_kid:
            ctx.add_finding(
                f"Cloudflare Access detected on {len(no_kid)} host(s) (policy id not exposed)",
                module=self.name, severity=Severity.INFO, confidence=Confidence.LIKELY,
                asset=no_kid[0],
                description="Behind Cloudflare Access, but the login redirect did not expose a "
                            "policy kid to group on. Team domains still cluster them.",
                evidence={"hosts": no_kid[:100],
                          "teams": sorted(by_team)},
                tags={"cf-access", "zero-trust"},
            )

    async def _probe(self, ctx: RunContext, host: str) -> dict | None:
        """Return Access descriptor for a host, or None if not CF-Access-gated."""
        for scheme in ("https", "http"):
            resp = await ctx.http.get(f"{scheme}://{host}/",
                                      follow_redirects=False)
            if resp is None:
                continue
            location = resp.headers.get("location", "") or ""
            blob = location
            # 200-with-JS-redirect apps embed the login URL in the body instead.
            if not _ACCESS_HINT.search(location) and resp.status_code < 400:
                body = resp.text[:8000] if hasattr(resp, "text") else ""
                if _ACCESS_HINT.search(body):
                    blob = body
                else:
                    return None
            elif not _ACCESS_HINT.search(location):
                continue

            m = _LOGIN_RE.search(blob)
            info: dict = {"scheme": scheme}
            if m:
                info["team"] = m.group(1)
            # Pull kid / meta out of the login URL's query, wherever it sits
            # (Location header or embedded in the body) — the base regex stops at
            # '?', so read the params straight from the blob.
            kid_m = re.search(r"[?&]kid=([^&\s\"'>]+)", blob)
            if kid_m:
                info["kid"] = kid_m.group(1)
            meta_m = re.search(r"[?&]meta=([^&\s\"'>]+)", blob)
            meta = _b64url_json(meta_m.group(1)) if meta_m else None
            if isinstance(meta, dict):
                info["aud"] = meta.get("aud") or meta.get("audience")
                info.setdefault("kid", meta.get("kid"))
            return info
        return None
