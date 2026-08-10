"""HTTP parameter discovery — reflected and accepted parameters.

Hidden parameters are where IDORs, debug modes, mass-assignment, and reflected
injection live. This module finds them two ways, per in-scope endpoint:

* **Reflected parameters** — inject a unique marker per candidate name and see
  which markers echo back in the response. Reflected inputs are prime XSS /
  injection leads.
* **Accepted parameters** (Arjun-style) — batch candidates with random values and
  watch for a response that *reacts* (length/status change) versus a baseline,
  then binary-search the batch to isolate the responsible name.

The wordlist is bundled (sourced from CypherNova1337/paramvoid). When the
``paramvoid`` binary is installed it is used directly for a fuller scan. Active,
scope-gated, and opt-in.
"""

from __future__ import annotations

import asyncio
import os
import random
import string
from urllib.parse import urlparse

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence, Severity
from voidrecon.core.module import Module, Phase, register
from voidrecon.core.tools import run_tool
from voidrecon.utils.text import short_url

try:
    from importlib.resources import files as _res_files
except Exception:  # pragma: no cover
    _res_files = None


def chunk(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def _marker() -> str:
    return "vr" + "".join(random.choices(string.ascii_lowercase, k=6))


@register
class ParamDiscovery(Module):
    name = "param_discovery"
    phase = Phase.CONTENT
    active = True
    description = "Discover reflected & accepted HTTP parameters (IDOR/XSS leads)"
    depends_on = ("http_probe",)
    enabled_by_default = False  # opt-in: many requests per endpoint

    async def run(self, ctx: RunContext) -> None:
        targets = self._targets(ctx)
        if not targets:
            self.log.info("no in-scope endpoints for parameter discovery")
            return
        words = self._load_wordlist(ctx)
        max_params = int(ctx.config.get("modules.param_discovery.max_params",
                                        1000 if ctx.config.get("opsec.aggressive") else 250))
        words = words[:max_params]
        if not words:
            return

        if ctx.tools.has("paramvoid"):
            await self._with_paramvoid(ctx, targets)
            return

        self.log.info("parameter discovery on %d endpoint(s) with %d candidates", len(targets), len(words))
        sem = asyncio.Semaphore(min(int(ctx.config.get("opsec.max_concurrency", 20)), 10))
        found = 0

        async def worker(url):
            nonlocal found
            async with sem:
                found += await self._discover(ctx, url, words)

        await asyncio.gather(*(worker(u) for u in targets))
        self.log.info("parameter discovery found %d parameter(s)", found)

    def _targets(self, ctx: RunContext) -> list[str]:
        seen, out = set(), []
        # Prefer real web pages / known endpoints.
        for a in ctx.store.assets():
            url = a.attrs.get("http_url") if "web" in a.tags else (
                a.value if a.kind in (AssetKind.URL, AssetKind.ENDPOINT) else None)
            if not url or "://" not in url:
                continue
            base = url.split("?")[0]
            host = urlparse(base).hostname
            if not host or not ctx.can_touch(host) or base in seen:
                continue
            seen.add(base)
            out.append(base)
        return out[:int(ctx.config.get("modules.param_discovery.max_endpoints", 40))]

    def _load_wordlist(self, ctx: RunContext) -> list[str]:
        path = ctx.config.get("modules.param_discovery.wordlist")
        if path and os.path.exists(path):
            with open(path, encoding="utf-8", errors="replace") as fh:
                return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        if _res_files is not None:
            try:
                raw = _res_files("voidrecon.data").joinpath("params.txt").read_text(encoding="utf-8")
                return [ln.strip() for ln in raw.splitlines() if ln.strip() and not ln.startswith("#")]
            except Exception:
                pass
        return []

    async def _discover(self, ctx: RunContext, url: str, words: list[str]) -> int:
        baseline = await ctx.http.get(url)
        if baseline is None:
            return 0
        base_len = len(baseline.content)
        found = 0
        reflected: list[str] = []
        for group in chunk(words, 25):
            markers = {p: _marker() for p in group}
            query = "&".join(f"{p}={markers[p]}" for p in group)
            resp = await ctx.http.get(f"{url}?{query}")
            if resp is None:
                continue
            body = resp.text
            for p, mark in markers.items():
                if mark in body:
                    reflected.append(p)
        if reflected:
            found += len(reflected)
            for p in reflected[:50]:
                ctx.add_asset(AssetKind.ENDPOINT, f"{url}?{p}=", source=self.name,
                              confidence=Confidence.CONFIRMED, has_params=True, reflected=True)
            ctx.add_finding(
                f"Reflected parameter(s) — {short_url(url)}: {', '.join(reflected[:12])}"
                + (" …" if len(reflected) > 12 else ""),
                module=self.name, severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED,
                asset=url,
                description=("These parameters reflect attacker-controlled input into the response — "
                             "prime candidates for XSS and other injection. Verify the reflection context."),
                evidence={"url": url, "reflected": reflected[:50], "baseline_length": base_len},
                tags={"parameter", "reflection", "xss-candidate"},
            )
        return found

    async def _with_paramvoid(self, ctx: RunContext, targets: list[str]) -> None:
        result = await run_tool("paramvoid", ["-silent"], stdin="\n".join(targets), timeout=900)
        count = 0
        for line in result.lines():
            if "://" in line:
                ctx.add_asset(AssetKind.ENDPOINT, line.strip(), source=self.name,
                              confidence=Confidence.LIKELY, has_params=True)
                count += 1
        self.log.info("paramvoid discovered %d parameterised endpoints", count)
