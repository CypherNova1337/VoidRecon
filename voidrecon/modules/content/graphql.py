"""GraphQL deep analysis.

Where ``api_discovery`` only notes that a GraphQL endpoint exists, this module
works it: a full introspection dump (types, queries, and — the interesting part —
mutations, flagging destructive/administrative ones), and, when introspection is
disabled, **field-suggestion harvesting** — GraphQL's "Did you mean X" error
hints leak real field names, so a handful of deliberately wrong queries recover
schema detail even with introspection off. Active and scope-gated.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence, Severity
from voidrecon.core.module import Module, Phase, register

_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1", "/query", "/gql"]
_INTROSPECTION = {"query": "query{__schema{queryType{name} mutationType{name} "
                           "types{name kind fields{name}}}}"}
_SUGGEST_RE = re.compile(r'Did you mean ["\']?([A-Za-z0-9_]+)["\']?', re.IGNORECASE)
_SENSITIVE_MUT = ("delete", "remove", "drop", "create", "update", "set", "grant",
                  "admin", "reset", "password", "role", "permission", "invite", "disable", "enable")


def parse_suggestions(text: str) -> set[str]:
    return set(_SUGGEST_RE.findall(text or ""))


@register
class GraphQL(Module):
    name = "graphql"
    phase = Phase.CONTENT
    active = True
    description = "GraphQL introspection dump + field-suggestion harvesting"
    depends_on = ("http_probe",)
    enabled_by_default = False  # opt-in

    async def run(self, ctx: RunContext) -> None:
        endpoints = self._endpoints(ctx)
        if not endpoints:
            self.log.info("no in-scope endpoints for GraphQL analysis")
            return
        sem = asyncio.Semaphore(int(ctx.config.get("opsec.max_concurrency", 20)))

        async def worker(url):
            async with sem:
                await self._analyze(ctx, url)

        await asyncio.gather(*(worker(u) for u in endpoints))
        self.log.info("GraphQL analysis over %d endpoint(s)", len(endpoints))

    def _endpoints(self, ctx: RunContext) -> list[str]:
        urls = set()
        # Known GraphQL endpoints found earlier.
        for a in ctx.store.assets(kind=AssetKind.ENDPOINT):
            if a.attrs.get("kind_hint") == "graphql":
                host = urlparse(a.value).hostname
                if host and ctx.can_touch(host):
                    urls.add(a.value)
        # Plus conventional paths on each web origin.
        seen = set()
        for a in ctx.store.assets():
            u = a.attrs.get("http_url")
            if not u or "web" not in a.tags or not ctx.can_touch(a.value):
                continue
            p = urlparse(u)
            origin = f"{p.scheme}://{p.netloc}"
            if origin in seen:
                continue
            seen.add(origin)
            for path in _PATHS:
                urls.add(origin + path)
        return list(urls)

    async def _analyze(self, ctx: RunContext, url: str) -> None:
        resp = await ctx.http.request("POST", url, json=_INTROSPECTION,
                                      headers={"Content-Type": "application/json"})
        if resp is None or resp.status_code >= 500:
            return
        try:
            data = resp.json()
        except Exception:
            return
        schema = (data.get("data") or {}).get("__schema") if isinstance(data, dict) else None
        if schema:
            await self._dump_schema(ctx, url, schema)
        elif isinstance(data, dict) and ("errors" in data or "data" in data):
            # Endpoint speaks GraphQL but introspection is off — harvest suggestions.
            await self._harvest(ctx, url)

    async def _dump_schema(self, ctx: RunContext, url: str, schema: dict) -> None:
        types = schema.get("types") or []
        mut_type = (schema.get("mutationType") or {}).get("name")
        mutations = []
        for t in types:
            if t.get("name") == mut_type:
                mutations = [f.get("name") for f in (t.get("fields") or []) if f.get("name")]
        sensitive = sorted({m for m in mutations if any(s in m.lower() for s in _SENSITIVE_MUT)})
        ctx.add_asset(AssetKind.ENDPOINT, url, source=self.name, confidence=Confidence.CONFIRMED,
                      kind_hint="graphql")
        ctx.add_finding(
            f"GraphQL introspection enabled: {url} ({len(types)} types, {len(mutations)} mutations)",
            module=self.name, severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED,
            asset=urlparse(url).hostname,
            description=("Full schema is exposed via introspection. Review the mutations for "
                         "destructive/administrative operations reachable without proper authz."),
            evidence={"url": url, "types": len(types), "mutations": mutations[:60],
                      "sensitive_mutations": sensitive},
            tags={"graphql", "introspection"},
        )

    async def _harvest(self, ctx: RunContext, url: str) -> None:
        found: set[str] = set()
        probes = [{"query": "query{" + p + "}"} for p in ("thisFieldDoesNotExist", "usr", "admn", "acount")]
        for probe in probes:
            resp = await ctx.http.request("POST", url, json=probe,
                                          headers={"Content-Type": "application/json"})
            if resp is not None:
                found |= parse_suggestions(resp.text)
        if found:
            ctx.add_asset(AssetKind.ENDPOINT, url, source=self.name, confidence=Confidence.LIKELY,
                          kind_hint="graphql")
            ctx.add_finding(
                f"GraphQL field names leaked via suggestions: {url}",
                module=self.name, severity=Severity.LOW, confidence=Confidence.LIKELY,
                asset=urlparse(url).hostname,
                description=("Introspection is disabled, but GraphQL 'Did you mean' error suggestions "
                             "leak real field names — the schema can be reconstructed incrementally."),
                evidence={"url": url, "suggested_fields": sorted(found)[:40]},
                tags={"graphql", "suggestion-leak"},
            )
