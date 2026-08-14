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
import re

from voidrecon.core.context import RunContext
from voidrecon.core.http import Outcome
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
            self._rapiddns(ctx, apex),
            self._subdomain_center(ctx, apex),
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

    @staticmethod
    def _clean(hosts, apex: str) -> set[str]:
        out = set()
        for h in hosts:
            h = net.normalize_host(h)
            if h and net.is_domain(h) and net.is_subdomain_of(h, apex):
                out.add(h)
        return out

    # ---- keyless sources --------------------------------------------------
    async def _certspotter(self, ctx: RunContext, apex: str) -> set[str]:
        o = await ctx.http.fetch(
            "https://api.certspotter.com/v1/issuances",
            params={"domain": apex, "include_subdomains": "true", "expand": "dns_names"},
        )
        names: set[str] = set()
        if o.ok and isinstance(o.json, list):
            for row in o.json:
                names.update(row.get("dns_names", []) or [])
        out = self._clean(names, apex)
        ctx.note_source("certspotter", apex, o, len(out))
        return out

    async def _otx(self, ctx: RunContext, apex: str) -> set[str]:
        o = await ctx.http.fetch(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{apex}/passive_dns"
        )
        names: set[str] = set()
        if o.ok and isinstance(o.json, dict):
            for row in o.json.get("passive_dns", []) or []:
                if row.get("hostname"):
                    names.add(row["hostname"])
        out = self._clean(names, apex)
        ctx.note_source("otx", apex, o, len(out))
        return out

    async def _anubis(self, ctx: RunContext, apex: str) -> set[str]:
        o = await ctx.http.fetch(f"https://jldc.me/anubis/subdomains/{apex}")
        names = set(o.json) if o.ok and isinstance(o.json, list) else set()
        out = self._clean(names, apex)
        ctx.note_source("anubis", apex, o, len(out))
        return out

    async def _hackertarget(self, ctx: RunContext, apex: str) -> set[str]:
        o = await ctx.http.fetch(
            "https://api.hackertarget.com/hostsearch/", params={"q": apex}, want="text"
        )
        names: set[str] = set()
        text = o.text or ""
        # hackertarget returns 200 with an error/quota body — treat as rate-limited.
        if o.ok and ("api count" in text.lower() or "error" in text.lower()):
            o = Outcome("rate_limited", o.http_status)
        elif o.ok:
            for line in text.splitlines():
                host = line.split(",", 1)[0].strip()
                if host:
                    names.add(host)
        out = self._clean(names, apex)
        ctx.note_source("hackertarget", apex, o, len(out))
        return out

    async def _urlscan(self, ctx: RunContext, apex: str) -> set[str]:
        o = await ctx.http.fetch(
            "https://urlscan.io/api/v1/search/", params={"q": f"page.domain:{apex}", "size": 1000}
        )
        names: set[str] = set()
        if o.ok and isinstance(o.json, dict):
            for row in o.json.get("results", []) or []:
                host = (row.get("page") or {}).get("domain")
                if host:
                    names.add(host)
        out = self._clean(names, apex)
        ctx.note_source("urlscan", apex, o, len(out))
        return out

    async def _rapiddns(self, ctx: RunContext, apex: str) -> set[str]:
        # Keyless HTML source; parse hostnames out of the results table.
        o = await ctx.http.fetch(
            f"https://rapiddns.io/subdomain/{apex}", params={"full": "1"}, want="text"
        )
        names: set[str] = set()
        if o.ok and o.text:
            names = set(re.findall(r"<td>([A-Za-z0-9_.-]+\.%s)</td>" % re.escape(apex), o.text))
        out = self._clean(names, apex)
        ctx.note_source("rapiddns", apex, o, len(out))
        return out

    async def _subdomain_center(self, ctx: RunContext, apex: str) -> set[str]:
        o = await ctx.http.fetch("https://api.subdomain.center/", params={"domain": apex})
        names = set(o.json) if o.ok and isinstance(o.json, list) else set()
        out = self._clean(names, apex)
        ctx.note_source("subdomain.center", apex, o, len(out))
        return out

    # ---- optional key-based sources --------------------------------------
    async def _securitytrails(self, ctx: RunContext, apex: str) -> set[str]:
        key = ctx.source_key("securitytrails_api_key")
        if not key:
            ctx.note_no_key("securitytrails", apex)
            return set()
        o = await ctx.http.fetch(
            f"https://api.securitytrails.com/v1/domain/{apex}/subdomains",
            headers={"APIKEY": key},
        )
        names: set[str] = set()
        if o.ok and isinstance(o.json, dict):
            for sub in o.json.get("subdomains", []) or []:
                names.add(f"{sub}.{apex}")
        out = self._clean(names, apex)
        ctx.note_source("securitytrails", apex, o, len(out))
        return out

    async def _virustotal(self, ctx: RunContext, apex: str) -> set[str]:
        key = ctx.source_key("virustotal_api_key")
        if not key:
            ctx.note_no_key("virustotal", apex)
            return set()
        o = await ctx.http.fetch(
            f"https://www.virustotal.com/api/v3/domains/{apex}/subdomains",
            headers={"x-apikey": key},
            params={"limit": 1000},
        )
        names: set[str] = set()
        if o.ok and isinstance(o.json, dict):
            for row in o.json.get("data", []) or []:
                if row.get("id"):
                    names.add(row["id"])
        out = self._clean(names, apex)
        ctx.note_source("virustotal", apex, o, len(out))
        return out

    async def _censys(self, ctx: RunContext, apex: str) -> set[str]:
        api_id = ctx.source_key("censys_api_id")
        api_secret = ctx.source_key("censys_api_secret")
        if not (api_id and api_secret):
            ctx.note_no_key("censys", apex)
            return set()
        names: set[str] = set()
        cursor = None
        last: Outcome = Outcome("unreachable")
        for _ in range(5):  # bounded pagination
            params = {"q": apex, "per_page": 100}
            if cursor:
                params["cursor"] = cursor
            last = await ctx.http.fetch(
                "https://search.censys.io/api/v2/hosts/search",
                params=params, auth=(api_id, api_secret),
            )
            if not last.ok or not isinstance(last.json, dict):
                break
            result = last.json.get("result", {})
            for hit in result.get("hits", []) or []:
                names.update(hit.get("dns", {}).get("names", []) or [])
                names.update(hit.get("names", []) or [])
            cursor = (result.get("links", {}) or {}).get("next")
            if not cursor:
                break
        out = self._clean(names, apex)
        ctx.note_source("censys", apex, last, len(out))
        return out

    # ---- hybrid: external tool -------------------------------------------
    async def _subfinder(self, ctx: RunContext, apex: str) -> set[str]:
        if not ctx.tools.has("subfinder"):
            return set()   # not installed — not a source failure, so stay silent
        result = await run_tool("subfinder", ["-silent", "-d", apex, "-oJ"], timeout=180)
        names: set[str] = set()
        if result.ok:
            for line in result.lines():
                try:
                    row = json.loads(line)
                    host = row.get("host") or row.get("input")
                    if host:
                        names.add(host)
                except json.JSONDecodeError:
                    names.add(line)
        out = self._clean(names, apex)
        ctx.store.record_source("subfinder", apex, "ok" if out else "empty", count=len(out))
        return out
