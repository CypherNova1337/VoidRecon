"""HTTP method auditing.

Servers frequently leave dangerous verbs enabled: ``PUT``/``DELETE`` (content
tampering), ``TRACE`` (cross-site tracing), or ``PATCH``. This module asks each
in-scope web origin what it allows (via ``OPTIONS``) and directly probes
``TRACE``, flagging anything risky. One or two requests per origin; active and
scope-gated.
"""

from __future__ import annotations

import asyncio

from voidrecon.core.context import RunContext
from voidrecon.core.models import Confidence, Severity
from voidrecon.core.module import Module, Phase, register

_RISKY = {"PUT", "DELETE", "PATCH", "TRACE", "CONNECT"}


def parse_allow(header: str) -> set[str]:
    return {m.strip().upper() for m in (header or "").split(",") if m.strip()}


@register
class HttpMethods(Module):
    name = "http_methods"
    phase = Phase.CONTENT
    active = True
    description = "Audit enabled HTTP methods (PUT/DELETE/TRACE/PATCH)"
    depends_on = ("http_probe",)

    async def run(self, ctx: RunContext) -> None:
        origins = []
        seen = set()
        for a in ctx.store.assets():
            url = a.attrs.get("http_url")
            if url and "web" in a.tags and ctx.can_touch(a.value) and url not in seen:
                seen.add(url)
                origins.append((a.value, url))
        if not origins:
            self.log.info("no in-scope web assets for method audit")
            return
        sem = asyncio.Semaphore(int(ctx.config.get("opsec.max_concurrency", 20)))

        async def worker(item):
            async with sem:
                await self._audit(ctx, *item)

        await asyncio.gather(*(worker(o) for o in origins))
        self.log.info("audited HTTP methods on %d origin(s)", len(origins))

    async def _audit(self, ctx: RunContext, host: str, url: str) -> None:
        resp = await ctx.http.request("OPTIONS", url)
        allowed: set[str] = set()
        if resp is not None:
            allowed = parse_allow(resp.headers.get("allow", "") or resp.headers.get("access-control-allow-methods", ""))
        # Directly confirm TRACE (some servers hide it from OPTIONS).
        trace = await ctx.http.request("TRACE", url)
        if trace is not None and trace.status_code == 200 and "TRACE" in (trace.text[:200].upper()):
            allowed.add("TRACE")
        risky = allowed & _RISKY
        if risky:
            for a in ctx.store.assets():
                if a.value == host and "web" in a.tags:
                    a.attrs["http_methods"] = sorted(allowed)
                    break
            sev = Severity.MEDIUM if {"PUT", "DELETE"} & risky else Severity.LOW
            ctx.add_finding(
                f"Risky HTTP methods enabled on {host}: {', '.join(sorted(risky))}",
                module=self.name, severity=sev, confidence=Confidence.CONFIRMED, asset=host,
                description=("The server advertises or accepts potentially dangerous HTTP methods. "
                             "PUT/DELETE may allow content tampering; TRACE enables cross-site tracing."),
                evidence={"url": url, "allowed": sorted(allowed)},
                tags={"http-methods"},
            )
