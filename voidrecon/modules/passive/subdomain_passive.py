"""Aggregated passive subdomain enumeration.

Cross-references a spread of free, keyless OSINT sources so no single source's
blind spots or rate limits leave a gap — the more sources agree on a host, the
higher our confidence. Optional API-key sources (SecurityTrails, VirusTotal) are
folded in automatically when configured. If the ``subfinder`` binary is present,
its output is merged too (hybrid model).

All sources here are passive: they query third-party datasets about the target,
never the target itself.
"""

from __future__ import annotations

import asyncio
import json

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence
from voidrecon.core.module import Module, Phase, register
from voidrecon.core.tools import run_tool
from voidrecon.utils import net


@register
class PassiveSubdomains(Module):
    name = "passive_subs"
    phase = Phase.PASSIVE
    active = False
    description = "Aggregate passive subdomain sources (certspotter, OTX, anubis, hackertarget, urlscan, +keys)"

    async def run(self, ctx: RunContext) -> None:
        for seed in ctx.scope.seeds:
            hosts = await self._gather(ctx, seed)
            confirmed = 0
            for host in hosts:
                if not (net.is_domain(host) and net.is_subdomain_of(host, seed)):
                    continue
                kind = AssetKind.DOMAIN if host == seed else AssetKind.SUBDOMAIN
                ctx.add_asset(kind, host, source=self.name, confidence=Confidence.LIKELY)
                confirmed += 1
            self.log.info("passive sources: %d subdomains for %s", confirmed, seed)

    async def _gather(self, ctx: RunContext, apex: str) -> set[str]:
        tasks = [
            self._certspotter(ctx, apex),
            self._otx(ctx, apex),
            self._anubis(ctx, apex),
            self._hackertarget(ctx, apex),
            self._urlscan(ctx, apex),
            self._securitytrails(ctx, apex),
            self._virustotal(ctx, apex),
            self._censys(ctx, apex),
            self._subfinder(ctx, apex),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        out: set[str] = set()
        for res in results:
            if isinstance(res, set):
                out |= res
        return out

    # ---- keyless sources --------------------------------------------------
    async def _certspotter(self, ctx: RunContext, apex: str) -> set[str]:
        data = await ctx.http.get_json(
            "https://api.certspotter.com/v1/issuances",
            params={"domain": apex, "include_subdomains": "true", "expand": "dns_names"},
        )
        out: set[str] = set()
        if isinstance(data, list):
            for row in data:
                for name in row.get("dns_names", []) or []:
                    out.add(net.normalize_host(name))
        return out

    async def _otx(self, ctx: RunContext, apex: str) -> set[str]:
        data = await ctx.http.get_json(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{apex}/passive_dns"
        )
        out: set[str] = set()
        if isinstance(data, dict):
            for row in data.get("passive_dns", []) or []:
                host = row.get("hostname")
                if host:
                    out.add(net.normalize_host(host))
        return out

    async def _anubis(self, ctx: RunContext, apex: str) -> set[str]:
        data = await ctx.http.get_json(f"https://jldc.me/anubis/subdomains/{apex}")
        if isinstance(data, list):
            return {net.normalize_host(h) for h in data if h}
        return set()

    async def _hackertarget(self, ctx: RunContext, apex: str) -> set[str]:
        text = await ctx.http.get_text(
            "https://api.hackertarget.com/hostsearch/", params={"q": apex}
        )
        out: set[str] = set()
        if text and "error" not in text.lower() and "api count" not in text.lower():
            for line in text.splitlines():
                host = line.split(",", 1)[0].strip()
                if host:
                    out.add(net.normalize_host(host))
        return out

    async def _urlscan(self, ctx: RunContext, apex: str) -> set[str]:
        data = await ctx.http.get_json(
            "https://urlscan.io/api/v1/search/", params={"q": f"page.domain:{apex}", "size": 1000}
        )
        out: set[str] = set()
        if isinstance(data, dict):
            for row in data.get("results", []) or []:
                host = (row.get("page") or {}).get("domain")
                if host:
                    out.add(net.normalize_host(host))
        return out

    # ---- optional key-based sources --------------------------------------
    async def _securitytrails(self, ctx: RunContext, apex: str) -> set[str]:
        key = ctx.source_key("securitytrails_api_key")
        if not key:
            return set()
        data = await ctx.http.get_json(
            f"https://api.securitytrails.com/v1/domain/{apex}/subdomains",
            headers={"APIKEY": key},
        )
        out: set[str] = set()
        if isinstance(data, dict):
            for sub in data.get("subdomains", []) or []:
                out.add(net.normalize_host(f"{sub}.{apex}"))
        return out

    async def _virustotal(self, ctx: RunContext, apex: str) -> set[str]:
        key = ctx.source_key("virustotal_api_key")
        if not key:
            return set()
        data = await ctx.http.get_json(
            f"https://www.virustotal.com/api/v3/domains/{apex}/subdomains",
            headers={"x-apikey": key},
            params={"limit": 1000},
        )
        out: set[str] = set()
        if isinstance(data, dict):
            for row in data.get("data", []) or []:
                host = row.get("id")
                if host:
                    out.add(net.normalize_host(host))
        return out

    async def _censys(self, ctx: RunContext, apex: str) -> set[str]:
        api_id = ctx.source_key("censys_api_id")
        api_secret = ctx.source_key("censys_api_secret")
        if not (api_id and api_secret):
            return set()
        out: set[str] = set()
        cursor = None
        for _ in range(5):  # bounded pagination
            params = {"q": apex, "per_page": 100}
            if cursor:
                params["cursor"] = cursor
            resp = await ctx.http.get(
                "https://search.censys.io/api/v2/hosts/search",
                params=params, auth=(api_id, api_secret),
            )
            if resp is None or resp.status_code >= 400:
                break
            try:
                data = resp.json()
            except Exception:
                break
            result = data.get("result", {})
            for hit in result.get("hits", []) or []:
                for name in hit.get("dns", {}).get("names", []) or hit.get("names", []) or []:
                    out.add(net.normalize_host(name))
                for cert in hit.get("names", []) or []:
                    out.add(net.normalize_host(cert))
            cursor = (result.get("links", {}) or {}).get("next")
            if not cursor:
                break
        return out

    # ---- hybrid: external tool -------------------------------------------
    async def _subfinder(self, ctx: RunContext, apex: str) -> set[str]:
        if not ctx.tools.has("subfinder"):
            return set()
        result = await run_tool("subfinder", ["-silent", "-d", apex, "-oJ"], timeout=180)
        out: set[str] = set()
        if result.ok:
            for line in result.lines():
                try:
                    row = json.loads(line)
                    host = row.get("host") or row.get("input")
                    if host:
                        out.add(net.normalize_host(host))
                except json.JSONDecodeError:
                    out.add(net.normalize_host(line))
        return out
