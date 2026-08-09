"""Vulnerability-hint classification of discovered URLs.

Recon produces a mountain of URLs and endpoints; the value is knowing which few
to test first. Using parameter-pattern sets distilled from gf, this module sorts
every parameterised endpoint into candidate buckets — SQLi, XSS, SSRF, LFI, RCE,
open-redirect, SSTI, IDOR, debug — so an operator walks straight to the promising
inputs. Pure classification of data already collected: it sends no traffic.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlparse

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence, Severity
from voidrecon.core.module import Module, Phase, register

try:
    from importlib.resources import files as _res_files
except Exception:  # pragma: no cover
    _res_files = None

_SEV = {"low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH}


def classify(params: set[str], categories: dict) -> dict[str, list[str]]:
    """Return {category: [matching params]} for the given parameter names."""
    out: dict[str, list[str]] = {}
    lowered = {p.lower() for p in params}
    for cat, spec in categories.items():
        hits = sorted(lowered & {p.lower() for p in spec.get("params", [])})
        if hits:
            out[cat] = hits
    return out


@register
class VulnHints(Module):
    name = "vuln_hints"
    phase = Phase.VULN
    active = False  # classifies collected data; sends no requests
    description = "Classify parameterised URLs into vuln candidate buckets (gf-style)"

    def _load(self) -> dict:
        if _res_files is None:
            return {}
        try:
            raw = _res_files("voidrecon.data").joinpath("gf_patterns.json").read_text(encoding="utf-8")
            return json.loads(raw).get("categories", {})
        except Exception as exc:  # noqa: BLE001
            self.log.warning("could not load gf patterns: %s", exc)
            return {}

    async def run(self, ctx: RunContext) -> None:
        categories = self._load()
        if not categories:
            return
        buckets: dict[str, set[str]] = {}
        seen = 0
        for asset in ctx.store.assets(kind=AssetKind.URL) + ctx.store.assets(kind=AssetKind.ENDPOINT):
            parsed = urlparse(asset.value)
            if not parsed.query:
                continue
            params = set(parse_qs(parsed.query).keys())
            if not params:
                continue
            seen += 1
            matches = classify(params, categories)
            if matches:
                asset.attrs["vuln_hints"] = sorted(matches)
                for cat in matches:
                    asset.tags.add(f"{cat}-candidate")
                    buckets.setdefault(cat, set()).add(asset.value)

        for cat, urls in buckets.items():
            spec = categories.get(cat, {})
            ctx.add_finding(
                f"{len(urls)} {cat.upper()} candidate endpoint(s)",
                module=self.name, severity=_SEV.get(spec.get("severity", "low"), Severity.LOW),
                confidence=Confidence.TENTATIVE,
                description=(f"Endpoints carrying parameters commonly associated with {cat.upper()}. "
                             "Prioritised testing leads — not confirmed vulnerabilities."),
                evidence={"category": cat, "urls": sorted(urls)[:60], "count": len(urls)},
                tags={"vuln-hint", cat},
            )
        if buckets:
            self.log.info("classified %d parameterised URLs into %d vuln buckets", seen, len(buckets))
