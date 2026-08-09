"""GitHub code-search dorking.

Source code is where organisations leak the most: hardcoded API endpoints,
internal hostnames, credentials in commit history, config files pushed by
mistake. This module runs a curated set of dorks against GitHub's code-search
API for each seed apex, surfacing repositories and files that mention the target
so an operator can review them for secrets and internal surface.

Requires a GitHub token (``VOIDRECON_SOURCES_GITHUB_TOKEN`` or
``sources.github_token``); without one the code-search API is unavailable and the
module skips cleanly. VoidRecon only reads public search results — it never
clones or stores repository contents automatically.
"""

from __future__ import annotations

import asyncio

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence, Severity
from voidrecon.core.module import Module, Phase, register

# Query fragments appended to the target term. Kept high-signal and conservative.
_DORKS = [
    "",                       # any mention
    "password",
    "api_key OR apikey OR secret",
    "filename:.env",
    "filename:config",
    "extension:yml OR extension:yaml",
    "aws_access_key_id OR aws_secret_access_key",
    "authorization bearer",
    "private_key",
]


@register
class GithubDork(Module):
    name = "github_dork"
    phase = Phase.PASSIVE
    active = False
    description = "Find target mentions & leaked config in public code (GitHub search)"
    enabled_by_default = True

    async def run(self, ctx: RunContext) -> None:
        token = ctx.source_key("github_token")
        if not token:
            self.log.info("no github token configured — skipping (set VOIDRECON_SOURCES_GITHUB_TOKEN)")
            return
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        for seed in ctx.scope.seeds:
            await self._search_seed(ctx, seed, headers)

    async def _search_seed(self, ctx: RunContext, apex: str, headers: dict) -> None:
        repos: set[str] = set()
        flagged = 0
        for dork in _DORKS:
            q = f'"{apex}" {dork}'.strip()
            data = await ctx.http.get_json(
                "https://api.github.com/search/code",
                headers=headers,
                params={"q": q, "per_page": 30},
            )
            if not data or "items" not in data:
                continue
            for item in data["items"]:
                repo = (item.get("repository") or {})
                full = repo.get("full_name")
                html_url = item.get("html_url")
                if full:
                    repos.add(full)
                # A hit on a secret-flavoured dork is worth a lead.
                if dork and dork not in ("password",) and html_url:
                    flagged += 1
                    ctx.add_finding(
                        f"GitHub code mentions {apex} near '{dork}'",
                        module=self.name,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.TENTATIVE,
                        asset=apex,
                        description=(
                            "A public file references the target alongside a sensitive "
                            "keyword. Manually review for real credentials or internal "
                            "endpoints — search hits are not confirmed leaks."
                        ),
                        evidence={"query": q, "url": html_url, "repo": full},
                        references=[html_url],
                        tags={"github", "leak-candidate"},
                    )
            # Respect GitHub search secondary rate limits.
            await asyncio.sleep(2.0)

        for repo in repos:
            ctx.add_asset(
                AssetKind.CODE_REPO, f"github.com/{repo}", source=self.name,
                confidence=Confidence.TENTATIVE, repo=repo,
            )
        if repos:
            self.log.info("github: %d repos mention %s (%d secret-flavoured hits)", len(repos), apex, flagged)
