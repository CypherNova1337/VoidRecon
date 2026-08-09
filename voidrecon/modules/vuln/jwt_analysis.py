"""JWT detection and analysis.

JSON Web Tokens turn up in cookies, response bodies, and headers, and their
header/payload are just base64url — readable without the key. This module finds
them on in-scope web assets, decodes them, and flags weaknesses: the ``alg:none``
downgrade, missing expiry, and interesting claims (roles/admin flags) worth
testing for tampering. It never forges tokens — it reads what's already exposed.
Active and scope-gated.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re

from voidrecon.core.context import RunContext
from voidrecon.core.models import Confidence, Severity
from voidrecon.core.module import Module, Phase, register

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{0,}")


def _b64url(part: str) -> dict | None:
    try:
        padded = part + "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8", "replace"))
    except Exception:
        return None


def decode_jwt(token: str) -> tuple[dict | None, dict | None]:
    parts = token.split(".")
    if len(parts) < 2:
        return None, None
    return _b64url(parts[0]), _b64url(parts[1])


def analyze_jwt(header: dict, payload: dict) -> tuple[Severity, list[str]]:
    issues: list[str] = []
    sev = Severity.INFO
    alg = str((header or {}).get("alg", "")).lower()
    if alg == "none":
        issues.append("alg:none (unsigned — trivially forgeable)")
        sev = Severity.HIGH
    elif alg.startswith("hs"):
        issues.append(f"symmetric alg {alg.upper()} (forgeable if the secret is weak/leaked)")
        sev = max(sev, Severity.LOW, key=lambda s: s.rank)
    if payload is not None and "exp" not in payload:
        issues.append("no 'exp' claim (token does not expire)")
        sev = max(sev, Severity.LOW, key=lambda s: s.rank)
    sensitive = [k for k in (payload or {}) if k.lower() in
                 ("role", "roles", "admin", "is_admin", "isadmin", "scope", "scopes", "permissions", "groups")]
    if sensitive:
        issues.append(f"authorization claims present: {', '.join(sensitive)}")
    return sev, issues


@register
class JwtAnalysis(Module):
    name = "jwt_analysis"
    phase = Phase.VULN
    active = True
    description = "Find and analyze JWTs (alg:none, no-expiry, authz claims)"
    depends_on = ("http_probe",)

    async def run(self, ctx: RunContext) -> None:
        targets = [a for a in ctx.store.assets()
                   if a.attrs.get("http_url") and "web" in a.tags and ctx.can_touch(a.value)]
        if not targets:
            self.log.info("no in-scope web assets for JWT analysis")
            return
        sem = asyncio.Semaphore(int(ctx.config.get("opsec.max_concurrency", 20)))
        seen: set[str] = set()

        async def worker(asset):
            async with sem:
                await self._scan(ctx, asset, seen)

        await asyncio.gather(*(worker(a) for a in targets))
        self.log.info("JWT analysis complete; %d unique token(s) examined", len(seen))

    async def _scan(self, ctx: RunContext, asset, seen: set) -> None:
        resp = await ctx.http.get(asset.attrs["http_url"])
        if resp is None:
            return
        blob = resp.text[:200_000]
        cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        blob += " " + " ".join(cookies)
        for token in set(_JWT_RE.findall(blob)):
            sig = token[:40]
            if sig in seen:
                continue
            seen.add(sig)
            header, payload = decode_jwt(token)
            if header is None:
                continue
            sev, issues = analyze_jwt(header, payload)
            if issues:
                ctx.add_finding(
                    f"JWT weakness on {asset.value}: {issues[0]}",
                    module=self.name, severity=sev, confidence=Confidence.CONFIRMED, asset=asset.value,
                    description="A JSON Web Token exposed by the app has notable properties worth testing.",
                    evidence={"alg": header.get("alg"), "issues": issues,
                              "claims": sorted((payload or {}).keys())[:20]},
                    tags={"jwt"},
                )
