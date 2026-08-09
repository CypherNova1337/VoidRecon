"""Native CVE correlation.

Matches product/version fingerprints already collected during probing against a
bundled signature dataset (``voidrecon/data/cve_signatures.json``) — no network
traffic, no external scanner. It parses versions out of ``Server`` headers,
``X-Powered-By`` / ``X-Jenkins`` / generator headers, and detected technologies,
then flags any that fall inside a known-CVE version range.

This is deliberately conservative and honest: it only fires when a *version* is
known and lands in range, and every hit is advisory — confirm before reporting.
The dataset is a curated starter set, not an exhaustive feed; extend it freely.
"""

from __future__ import annotations

import json
import re

from voidrecon.core.context import RunContext
from voidrecon.core.models import Confidence, Severity
from voidrecon.core.module import Module, Phase, register
from voidrecon.utils.versions import in_range

try:
    from importlib.resources import files as _res_files
except Exception:  # pragma: no cover
    _res_files = None

_SEV = {
    "info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
    "high": Severity.HIGH, "critical": Severity.CRITICAL,
}
# product<sep>version, e.g. "Apache/2.4.49", "nginx 1.17.6", "PHP/7.4.3"
_PRODUCT_VER_RE = re.compile(r"([A-Za-z][A-Za-z0-9._+\- ]*?)[/ ]v?(\d+(?:\.\d+)+[a-z]?)")
# Headers whose product is implied by the header name itself.
_HEADER_PRODUCTS = {
    "x-jenkins": "jenkins",
    "x-aspnet-version": "asp.net",
}


def merge_signatures(base: list[dict], extra: list[dict]) -> list[dict]:
    """Merge two signature lists by product name; ``extra`` wins on CVE-id clashes."""
    by_product: dict[str, dict] = {s.get("product", "").lower(): dict(s) for s in base}
    for sig in extra:
        key = sig.get("product", "").lower()
        if not key:
            continue
        if key not in by_product:
            by_product[key] = dict(sig)
            continue
        merged = by_product[key]
        merged["match"] = sorted(set(merged.get("match", [])) | set(sig.get("match", [])))
        cves = {c.get("id"): c for c in merged.get("cves", [])}
        for cve in sig.get("cves", []):
            cves[cve.get("id")] = cve  # user/extra wins
        merged["cves"] = list(cves.values())
    return list(by_product.values())


@register
class CveMatch(Module):
    name = "cve_match"
    phase = Phase.VULN
    active = False  # works off collected fingerprints; sends no traffic
    description = "Correlate fingerprinted product versions to known CVEs (local dataset)"
    depends_on = ("http_probe",)

    def _load(self) -> list[dict]:
        signatures: list[dict] = []
        # Bundled dataset.
        if _res_files is not None:
            try:
                raw = _res_files("voidrecon.data").joinpath("cve_signatures.json").read_text(encoding="utf-8")
                signatures = json.loads(raw).get("signatures", [])
            except Exception as exc:  # noqa: BLE001
                self.log.warning("could not load bundled CVE dataset: %s", exc)
        # User override / auto-refreshed dataset (merged by product; user wins).
        try:
            from voidrecon.core.paths import user_cve_dataset

            user_path = user_cve_dataset()
            if user_path.exists():
                user_sigs = json.loads(user_path.read_text(encoding="utf-8")).get("signatures", [])
                signatures = merge_signatures(signatures, user_sigs)
                self.log.info("merged %d user CVE signature group(s) from %s", len(user_sigs), user_path)
        except Exception as exc:  # noqa: BLE001
            self.log.debug("no user CVE dataset merged: %s", exc)
        return signatures

    async def run(self, ctx: RunContext) -> None:
        signatures = self._load()
        if not signatures:
            return
        hits = 0
        for asset in ctx.store.assets():
            pairs = self._extract_pairs(asset)
            if not pairs:
                continue
            for name, version in pairs:
                hits += self._match(ctx, asset, name, version, signatures)
        self.log.info("CVE correlation: %d version-based match(es) across %d signatures",
                      hits, len(signatures))

    def _extract_pairs(self, asset) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        strings: list[str] = []
        if asset.attrs.get("http_server"):
            strings.append(str(asset.attrs["http_server"]))
        for tech in asset.attrs.get("technologies") or []:
            strings.append(str(tech))
        fp = asset.attrs.get("fp_headers") or {}
        for hkey, product in _HEADER_PRODUCTS.items():
            if fp.get(hkey):
                v = re.search(r"\d+(?:\.\d+)+[a-z]?", str(fp[hkey]))
                if v:
                    pairs.append((product, v.group(0)))
        for hkey in ("x-powered-by", "x-generator", "generator"):
            if fp.get(hkey):
                strings.append(str(fp[hkey]))
        for s in strings:
            for m in _PRODUCT_VER_RE.finditer(s):
                pairs.append((m.group(1).strip().lower(), m.group(2)))
        return pairs

    def _match(self, ctx, asset, name, version, signatures) -> int:
        count = 0
        name = name.lower()
        for sig in signatures:
            if any(x in name for x in sig.get("exclude", [])):
                continue
            if not any(tok in name for tok in sig.get("match", [])):
                continue
            for cve in sig.get("cves", []):
                if in_range(version, cve.get("min"), cve.get("max")):
                    ctx.add_finding(
                        f"{cve['id']}: {cve.get('title', sig['product'])} ({sig['product']} {version})",
                        module=self.name,
                        severity=_SEV.get(str(cve.get("severity", "medium")).lower(), Severity.MEDIUM),
                        confidence=Confidence.TENTATIVE,
                        asset=asset.value,
                        description=(
                            f"Fingerprinted {sig['product']} {version} falls within the affected "
                            f"range for {cve['id']}. Confirm the exact build and exploitability "
                            "before reporting — banners can be spoofed or back-patched."
                        ),
                        evidence={"product": sig["product"], "version": version, "cve": cve["id"]},
                        references=[cve["ref"]] if cve.get("ref") else [],
                        tags={"cve", cve["id"]},
                    )
                    count += 1
        return count
