"""Content discovery — directory / file fuzzing.

Brute-forces a high-signal path list against each in-scope web origin to find the
things operators leave exposed: ``.git`` and ``.env`` files, backups, admin
panels, actuator endpoints, config dumps. Soft-404s are handled by baselining
each origin first (random paths) so a site that returns ``200`` for everything
doesn't drown the results in noise. Active, scope-gated, and opt-in.
"""

from __future__ import annotations

import asyncio
import os
import random
import string
from urllib.parse import urljoin, urlparse

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence, Severity
from voidrecon.core.module import Module, Phase, register

try:
    from importlib.resources import files as _res_files
except Exception:  # pragma: no cover
    _res_files = None

_INTERESTING = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}
# Paths that are notable regardless of how common — real leaks.
_SENSITIVE = (".git/", ".env", ".aws/", "id_rsa", "wp-config", "backup", ".sql",
              "actuator", "phpinfo", ".htpasswd", "credentials", "secrets", ".ssh/")


class _Baseline:
    """Captures how an origin responds to definitely-nonexistent paths."""

    def __init__(self):
        self.signatures: list[tuple[int, int]] = []  # (status, length bucket)
        self.wildcard_200 = False

    def add(self, status: int, length: int):
        self.signatures.append((status, length))
        if status == 200:
            self.wildcard_200 = True

    def looks_like_404(self, status: int, length: int) -> bool:
        for bstatus, blen in self.signatures:
            if status == bstatus and abs(length - blen) <= max(64, int(blen * 0.05)):
                return True
        return False


@register
class Fuzz(Module):
    name = "fuzz"
    phase = Phase.CONTENT
    active = True
    description = "Directory/file content discovery with soft-404 filtering"
    depends_on = ("http_probe",)
    enabled_by_default = False  # opt-in: many requests per host

    async def run(self, ctx: RunContext) -> None:
        origins = self._origins(ctx)
        if not origins:
            self.log.info("no in-scope web origins to fuzz")
            return
        words = self._load_wordlist(ctx)
        if not words:
            self.log.info("empty content-discovery wordlist")
            return
        self.log.info("fuzzing %d origins with %d paths each", len(origins), len(words))
        sem = asyncio.Semaphore(int(ctx.config.get("opsec.max_concurrency", 20)))
        total = 0
        for origin in origins:
            total += await self._fuzz_origin(ctx, origin, words, sem)
        self.log.info("content discovery found %d interesting paths", total)

    def _origins(self, ctx: RunContext) -> list[str]:
        seen, out = set(), []
        for a in ctx.store.assets():
            url = a.attrs.get("http_url")
            if not url or "web" not in a.tags or not ctx.can_touch(a.value):
                continue
            p = urlparse(url)
            origin = f"{p.scheme}://{p.netloc}"
            if origin not in seen:
                seen.add(origin)
                out.append(origin)
        return out

    def _load_wordlist(self, ctx: RunContext) -> list[str]:
        path = ctx.config.get("modules.fuzz.wordlist")
        if path and os.path.exists(path):
            with open(path, encoding="utf-8", errors="replace") as fh:
                return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        if _res_files is not None:
            try:
                raw = _res_files("voidrecon.data").joinpath("paths.txt").read_text(encoding="utf-8")
                return [ln.strip() for ln in raw.splitlines() if ln.strip() and not ln.startswith("#")]
            except Exception:
                pass
        return []

    async def _baseline(self, ctx: RunContext, origin: str) -> _Baseline:
        baseline = _Baseline()
        for _ in range(3):
            rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
            resp = await ctx.http.get(urljoin(origin + "/", rand))
            if resp is not None:
                baseline.add(resp.status_code, len(resp.content))
        return baseline

    async def _fuzz_origin(self, ctx: RunContext, origin: str, words, sem) -> int:
        baseline = await self._baseline(ctx, origin)
        found = 0

        async def probe(path):
            nonlocal found
            async with sem:
                url = urljoin(origin + "/", path)
                resp = await ctx.http.get(url)
                if resp is None or resp.status_code not in _INTERESTING:
                    return
                length = len(resp.content)
                # Skip soft-404s (matches the baseline for nonexistent paths).
                if resp.status_code in (200, 204) and baseline.looks_like_404(resp.status_code, length):
                    return
                sensitive = any(s in path.lower() for s in _SENSITIVE)
                ctx.add_asset(AssetKind.ENDPOINT, url, source=self.name,
                              confidence=Confidence.CONFIRMED, status=resp.status_code)
                found += 1
                if sensitive:
                    ctype = (resp.headers.get("content-type") or "").lower()
                    self._flag_sensitive(ctx, origin, url, resp.status_code, length, ctype)

        await asyncio.gather(*(probe(p) for p in words))
        return found

    def _flag_sensitive(self, ctx, origin, url, status, length, ctype):
        """A sensitive path is only *exposed* when it actually serves its content.

        A 401/403 means it exists but is access-controlled — that's the control
        working, not a leak. A redirect is a gate, not an exposure. And a 200 that
        returns HTML on a path like ``.env`` is almost always a SPA catch-all, not
        the real file. Only a 200 with non-HTML content is treated as exposure."""
        html_catchall = status in (200, 201) and "text/html" in ctype
        if status in (200, 201) and not html_catchall:
            ctx.add_finding(
                f"Sensitive path exposed: {url} ({status})",
                module=self.name, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                asset=origin,
                description="A high-value path (config/secret/backup/admin) served content — "
                            "review immediately and confirm what it exposes.",
                evidence={"url": url, "status": status, "length": length, "content_type": ctype},
                tags={"content-discovery", "exposure"},
            )
        elif status in (401, 403):
            ctx.add_finding(
                f"Sensitive path present but access-controlled: {url} ({status})",
                module=self.name, severity=Severity.INFO, confidence=Confidence.CONFIRMED,
                asset=origin,
                description="A high-value path exists but is gated (401/403). Not an exposure — "
                            "the access control is working. Noted as recon signal only.",
                evidence={"url": url, "status": status},
                tags={"content-discovery", "access-controlled"},
            )
        elif html_catchall:
            ctx.add_finding(
                f"Sensitive path returns HTML (likely SPA catch-all, not exposed): {url}",
                module=self.name, severity=Severity.INFO, confidence=Confidence.TENTATIVE,
                asset=origin,
                description="A 200 with an HTML body on a non-HTML path is almost always the app's "
                            "catch-all route, not the real file. Confirm the content-type before "
                            "treating it as exposure.",
                evidence={"url": url, "status": status, "content_type": ctype},
                tags={"content-discovery"},
            )
        # redirects / 405 / 500 on a sensitive path are not exposures — not flagged.
