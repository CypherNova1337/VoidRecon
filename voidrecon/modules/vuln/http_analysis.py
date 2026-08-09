"""HTTP security-posture analysis — headers, CORS, and cookies.

Cheap, high-signal checks that every serious recon pass should make on live web
assets: which security headers are missing, whether CORS reflects arbitrary
origins (especially with credentials), and whether session cookies lack the
Secure / HttpOnly / SameSite flags. One extra request per host (an ``Origin``
probe for CORS); active and scope-gated.
"""

from __future__ import annotations

import asyncio

from voidrecon.core.context import RunContext
from voidrecon.core.models import Confidence, Severity
from voidrecon.core.module import Module, Phase, register

_CORS_PROBE_ORIGIN = "https://voidrecon.example"

_SECURITY_HEADERS = {
    "strict-transport-security": "HSTS (Strict-Transport-Security)",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options (clickjacking)",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def missing_security_headers(headers: dict) -> list[str]:
    lowered = {k.lower() for k in headers}
    return [label for key, label in _SECURITY_HEADERS.items() if key not in lowered]


def evaluate_cors(sent_origin: str, headers: dict) -> tuple[Severity, str] | None:
    lowered = {k.lower(): v for k, v in headers.items()}
    acao = lowered.get("access-control-allow-origin")
    if not acao:
        return None
    creds = str(lowered.get("access-control-allow-credentials", "")).lower() == "true"
    if acao == sent_origin:
        if creds:
            return Severity.HIGH, ("CORS reflects an arbitrary Origin AND allows credentials — "
                                   "a malicious site can read authenticated responses.")
        return Severity.MEDIUM, "CORS reflects an arbitrary Origin (no credentials) — review exposure."
    if acao == "*" and creds:
        return Severity.MEDIUM, "CORS allows '*' with credentials (browsers block this, but it signals misconfig)."
    if acao == "null":
        return Severity.MEDIUM, "CORS allows the 'null' origin — exploitable from sandboxed iframes/data URIs."
    return None


def analyze_cookies(set_cookie_values: list[str]) -> list[str]:
    issues: list[str] = []
    for raw in set_cookie_values:
        name = raw.split("=", 1)[0].strip()
        low = raw.lower()
        flags = []
        if "secure" not in low:
            flags.append("Secure")
        if "httponly" not in low:
            flags.append("HttpOnly")
        if "samesite" not in low:
            flags.append("SameSite")
        if flags:
            issues.append(f"{name}: missing {', '.join(flags)}")
    return issues


@register
class HttpAnalysis(Module):
    name = "http_analysis"
    phase = Phase.VULN
    active = True
    description = "Analyze security headers, CORS, and cookie flags on web assets"
    depends_on = ("http_probe",)

    async def run(self, ctx: RunContext) -> None:
        targets = [
            a for a in ctx.store.assets()
            if a.attrs.get("http_url") and "web" in a.tags and ctx.can_touch(a.value)
        ]
        if not targets:
            self.log.info("no in-scope web assets to analyze")
            return
        sem = asyncio.Semaphore(int(ctx.config.get("opsec.max_concurrency", 20)))

        async def worker(asset):
            async with sem:
                await self._analyze(ctx, asset)

        await asyncio.gather(*(worker(a) for a in targets))
        self.log.info("analyzed HTTP security posture on %d hosts", len(targets))

    async def _analyze(self, ctx: RunContext, asset) -> None:
        url = asset.attrs["http_url"]
        resp = await ctx.http.get(url, headers={"Origin": _CORS_PROBE_ORIGIN})
        if resp is None:
            return
        headers = dict(resp.headers)

        missing = missing_security_headers(headers)
        if missing:
            asset.attrs["missing_headers"] = missing
            sev = Severity.LOW if len(missing) <= 2 else Severity.MEDIUM
            ctx.add_finding(
                f"Missing security headers on {asset.value} ({len(missing)})",
                module=self.name, severity=sev, confidence=Confidence.CONFIRMED, asset=asset.value,
                description="These response headers harden the app against common client-side attacks.",
                evidence={"missing": missing, "url": url}, tags={"headers"},
            )

        cors = evaluate_cors(_CORS_PROBE_ORIGIN, headers)
        if cors:
            sev, note = cors
            ctx.add_finding(
                f"CORS misconfiguration on {asset.value}", module=self.name, severity=sev,
                confidence=Confidence.CONFIRMED, asset=asset.value, description=note,
                evidence={"url": url, "acao": headers.get("access-control-allow-origin"),
                          "acac": headers.get("access-control-allow-credentials")},
                tags={"cors"},
            )

        set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        cookie_issues = analyze_cookies(set_cookies)
        if cookie_issues:
            ctx.add_finding(
                f"Insecure cookie flags on {asset.value}", module=self.name, severity=Severity.LOW,
                confidence=Confidence.CONFIRMED, asset=asset.value,
                description="Session cookies missing hardening flags may be exposed to theft or CSRF.",
                evidence={"url": url, "cookies": cookie_issues}, tags={"cookies"},
            )
