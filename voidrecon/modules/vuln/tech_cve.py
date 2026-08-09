"""Vulnerability correlation (extension point + nuclei orchestration).

Maps what we know about a host — technologies, versions, exposed services — to
known-issue signatures. The template-based engine (``nuclei``) is orchestrated
now when installed, scanning only in-scope web assets. A native correlation layer
that matches fingerprinted product/versions against a local CVE dataset is
planned; its interface lives here so the VULN phase is scheduled today.

Active and scope-gated.
"""

from __future__ import annotations

import json

from voidrecon.core.context import RunContext
from voidrecon.core.models import Confidence, Severity
from voidrecon.core.module import Module, Phase, register
from voidrecon.core.tools import run_tool

_SEV = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "unknown": Severity.INFO,
}


@register
class TechCve(Module):
    name = "tech_cve"
    phase = Phase.VULN
    active = True
    description = "Correlate assets to known issues (nuclei) and flag risky tech"
    depends_on = ("http_probe",)
    enabled_by_default = False  # opt-in: template scanning is louder

    async def run(self, ctx: RunContext) -> None:
        # Native, zero-traffic heuristic: flag notably risky fingerprints already known.
        self._flag_risky_tech(ctx)

        if not ctx.tools.has("nuclei"):
            self.log.info("nuclei not installed — skipping template scan (native CVE matching planned)")
            return
        await self._run_nuclei(ctx)

    def _flag_risky_tech(self, ctx: RunContext) -> None:
        risky = {"phpmyadmin", "adminer", "jenkins", "grafana", "kibana", "gitlab"}
        for asset in ctx.store.assets():
            techs = {str(t).lower() for t in (asset.attrs.get("technologies") or [])}
            title = (asset.attrs.get("http_title") or "").lower()
            hit = risky & (techs | {title})
            if hit or any(r in title for r in risky):
                ctx.add_finding(
                    f"Sensitive application exposed on {asset.value}",
                    module=self.name, severity=Severity.MEDIUM, asset=asset.value,
                    description="A management/admin application was fingerprinted — review exposure and authentication.",
                    evidence={"technologies": sorted(techs), "title": title},
                    tags={"exposed-app"},
                )

    async def _run_nuclei(self, ctx: RunContext) -> None:
        urls = [
            a.attrs["http_url"]
            for a in ctx.store.assets()
            if a.attrs.get("http_url") and "web" in a.tags and ctx.can_touch(a.value)
        ]
        if not urls:
            self.log.info("no in-scope web assets for nuclei")
            return
        result = await run_tool(
            "nuclei",
            ["-silent", "-jsonl", "-severity", "low,medium,high,critical", "-list", "-"],
            stdin="\n".join(urls),
            timeout=900,
        )
        count = 0
        for line in result.lines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = row.get("info", {})
            sev = _SEV.get(str(info.get("severity", "info")).lower(), Severity.INFO)
            ctx.add_finding(
                info.get("name") or row.get("template-id", "nuclei finding"),
                module=self.name, severity=sev, confidence=Confidence.LIKELY,
                asset=row.get("host"),
                description=info.get("description", ""),
                evidence={"matched": row.get("matched-at"), "template": row.get("template-id")},
                references=info.get("reference") or [],
                tags={"nuclei"},
            )
            count += 1
        self.log.info("nuclei produced %d findings", count)
