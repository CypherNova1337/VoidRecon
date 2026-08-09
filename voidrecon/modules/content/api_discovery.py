"""API and specification discovery.

APIs are where the interesting bugs live, and their surface is often self-
documenting if you know where to look: Swagger/OpenAPI specs, exposed API-doc
UIs, GraphQL endpoints with introspection left on, and ``.well-known`` metadata.
This module probes a curated set of those paths on each in-scope web host and
records what it finds. Active and scope-gated.
"""

from __future__ import annotations

import asyncio
import json
from urllib.parse import urlparse

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence, Severity
from voidrecon.core.module import Module, Phase, register

_SPEC_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json", "/openapi.yaml",
    "/v2/api-docs", "/v3/api-docs", "/api-docs", "/api/swagger.json",
    "/swagger-ui.html", "/swagger-ui/", "/api/docs", "/docs/", "/redoc",
    "/.well-known/security.txt", "/.well-known/openid-configuration",
]
_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]
_INTROSPECTION = {"query": "{__schema{queryType{name}}}"}


@register
class ApiDiscovery(Module):
    name = "api_discovery"
    phase = Phase.CONTENT
    active = True
    description = "Discover API specs, docs, and GraphQL introspection"
    depends_on = ("http_probe",)
    enabled_by_default = False  # opt-in: adds targeted requests per host

    async def run(self, ctx: RunContext) -> None:
        origins = self._origins(ctx)
        if not origins:
            self.log.info("no in-scope web origins for API discovery")
            return
        sem = asyncio.Semaphore(int(ctx.config.get("opsec.max_concurrency", 20)))
        found = 0

        async def worker(origin):
            nonlocal found
            async with sem:
                found += await self._probe(ctx, origin)

        await asyncio.gather(*(worker(o) for o in origins))
        self.log.info("API discovery over %d origins; %d artifacts found", len(origins), found)

    def _origins(self, ctx: RunContext) -> list[str]:
        seen = set()
        origins = []
        for a in ctx.store.assets():
            url = a.attrs.get("http_url")
            if not url or "web" not in a.tags or not ctx.can_touch(a.value):
                continue
            p = urlparse(url)
            origin = f"{p.scheme}://{p.netloc}"
            if origin not in seen:
                seen.add(origin)
                origins.append(origin)
        return origins

    async def _probe(self, ctx: RunContext, origin: str) -> int:
        found = 0
        for path in _SPEC_PATHS:
            url = origin + path
            resp = await ctx.http.get(url)
            if resp is None or resp.status_code >= 400:
                continue
            body = resp.text[:5000]
            is_spec = any(k in body for k in ('"swagger"', '"openapi"', '"paths"')) or path.endswith((".json", ".yaml"))
            ctx.add_asset(AssetKind.ENDPOINT, url, source=self.name,
                          confidence=Confidence.CONFIRMED, kind_hint="api_spec")
            found += 1
            if path.endswith("security.txt"):
                ctx.add_finding(f"security.txt published on {origin}", module=self.name,
                                severity=Severity.INFO, asset=origin,
                                description="A security.txt contact policy is published.",
                                evidence={"url": url}, tags={"well-known"})
            elif is_spec:
                ctx.add_finding(f"Exposed API specification: {url}", module=self.name,
                                severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED, asset=origin,
                                description="An API spec is publicly reachable — it maps the full API surface for testing.",
                                evidence={"url": url}, tags={"api", "swagger"})
            else:
                ctx.add_finding(f"Exposed API docs UI: {url}", module=self.name,
                                severity=Severity.LOW, asset=origin,
                                description="An interactive API documentation UI is publicly reachable.",
                                evidence={"url": url}, tags={"api", "docs"})

        for path in _GRAPHQL_PATHS:
            url = origin + path
            resp = await ctx.http.request("POST", url, json=_INTROSPECTION,
                                          headers={"Content-Type": "application/json"})
            if resp is None or resp.status_code >= 400:
                continue
            try:
                data = resp.json()
            except Exception:
                continue
            if isinstance(data, dict) and "__schema" in json.dumps(data.get("data", {})):
                found += 1
                ctx.add_asset(AssetKind.ENDPOINT, url, source=self.name,
                              confidence=Confidence.CONFIRMED, kind_hint="graphql")
                ctx.add_finding(f"GraphQL introspection enabled: {url}", module=self.name,
                                severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED, asset=origin,
                                description=("GraphQL introspection is enabled, exposing the full schema "
                                             "(types, queries, mutations) to any client."),
                                evidence={"url": url}, tags={"graphql", "api"})
        return found
