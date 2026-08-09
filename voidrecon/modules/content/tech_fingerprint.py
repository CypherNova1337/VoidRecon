"""Deep technology fingerprinting.

The probe phase does a cheap first pass; this module goes deeper, matching each
live web asset against a curated Wappalyzer-style dataset of headers, cookies,
HTML markers, and generator meta tags (with ``implies`` chains, e.g. Next.js ⇒
React ⇒ Node.js). The enriched technology list feeds asset scoring and the native
CVE correlation. Active and scope-gated.
"""

from __future__ import annotations

import asyncio
import json
import re

from voidrecon.core.context import RunContext
from voidrecon.core.module import Module, Phase, register

try:
    from importlib.resources import files as _res_files
except Exception:  # pragma: no cover
    _res_files = None


def match_fingerprints(fingerprints: list[dict], headers: dict, cookies: list[str], html: str) -> set[str]:
    """Return the set of detected technology names (with implied ones expanded)."""
    lowered = {k.lower(): str(v).lower() for k, v in headers.items()}
    cookie_blob = " ".join(cookies).lower()
    html_l = html.lower()
    detected: set[str] = set()
    implies_map: dict[str, list[str]] = {}

    for fp in fingerprints:
        name = fp.get("name")
        if not name:
            continue
        implies_map[name] = fp.get("implies", [])
        hit = False
        for needle in fp.get("html", []):
            if needle.lower() in html_l:
                hit = True
                break
        if not hit:
            for pattern in fp.get("html_regex", []):
                try:
                    if re.search(pattern, html, re.IGNORECASE):
                        hit = True
                        break
                except re.error:
                    continue
        if not hit and fp.get("meta_generator"):
            m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html, re.IGNORECASE)
            if m and fp["meta_generator"].lower() in m.group(1).lower():
                hit = True
        if not hit:
            for hname, hval in (fp.get("headers") or {}).items():
                actual = lowered.get(hname.lower())
                if actual is not None and (hval == "" or hval.lower() in actual):
                    hit = True
                    break
        if not hit:
            for cname in fp.get("cookies", []):
                if cname.lower() in cookie_blob:
                    hit = True
                    break
        if hit:
            detected.add(name)

    # Expand implies chains.
    queue = list(detected)
    while queue:
        cur = queue.pop()
        for imp in implies_map.get(cur, []):
            if imp not in detected:
                detected.add(imp)
                queue.append(imp)
    return detected


@register
class TechFingerprint(Module):
    name = "tech_fingerprint"
    phase = Phase.CONTENT
    active = True
    description = "Deep technology fingerprinting from a curated dataset"
    depends_on = ("http_probe",)

    def _load(self) -> list[dict]:
        if _res_files is None:
            return []
        try:
            raw = _res_files("voidrecon.data").joinpath("fingerprints.json").read_text(encoding="utf-8")
            return json.loads(raw).get("fingerprints", [])
        except Exception as exc:  # noqa: BLE001
            self.log.warning("could not load fingerprint dataset: %s", exc)
            return []

    async def run(self, ctx: RunContext) -> None:
        fingerprints = self._load()
        if not fingerprints:
            return
        targets = [
            a for a in ctx.store.assets()
            if a.attrs.get("http_url") and "web" in a.tags and ctx.can_touch(a.value)
        ]
        if not targets:
            self.log.info("no in-scope web assets to fingerprint")
            return
        sem = asyncio.Semaphore(int(ctx.config.get("opsec.max_concurrency", 20)))

        async def worker(asset):
            async with sem:
                await self._fingerprint(ctx, asset, fingerprints)

        await asyncio.gather(*(worker(a) for a in targets))
        enriched = sum(1 for a in targets if a.attrs.get("technologies"))
        self.log.info("deep fingerprinting: %d/%d hosts enriched", enriched, len(targets))

    async def _fingerprint(self, ctx: RunContext, asset, fingerprints) -> None:
        resp = await ctx.http.get(asset.attrs["http_url"])
        if resp is None:
            return
        cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        detected = match_fingerprints(fingerprints, dict(resp.headers), cookies, resp.text[:300_000])
        if detected:
            existing = set(asset.attrs.get("technologies") or [])
            asset.attrs["technologies"] = sorted(existing | detected)
