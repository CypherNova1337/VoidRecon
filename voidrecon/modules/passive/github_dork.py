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
        # repo -> {"hits": {url,...}, "dorks": {dork,...}, "owned": bool}
        repos: dict[str, dict] = {}
        apex_label = apex.split(".")[0].lower()
        for dork in _DORKS:
            q = f'"{apex}" {dork}'.strip()
            data = await ctx.http.get_json(
                "https://api.github.com/search/code", headers=headers,
                params={"q": q, "per_page": 30},
            )
            if isinstance(data, dict) and data.get("items"):
                for item in data["items"]:
                    repo = item.get("repository") or {}
                    full = repo.get("full_name")
                    if not full or self._is_noise(full, repo):
                        continue
                    rec = repos.setdefault(full, {"hits": set(), "dorks": set(), "owner": full.split("/")[0].lower()})
                    if item.get("html_url"):
                        rec["hits"].add(item["html_url"])
                    if dork:
                        rec["dorks"].add(dork)
            await asyncio.sleep(2.0)  # respect search secondary rate limits

        secret_repos = 0
        for full, rec in repos.items():
            ctx.add_asset(AssetKind.CODE_REPO, f"github.com/{full}", source=self.name,
                          confidence=Confidence.TENTATIVE, repo=full)
            # Screen: only flag repos that hit a *secret-flavoured* dork, and rank
            # repos owned by (or named after) the target higher.
            secret_dorks = {d for d in rec["dorks"] if d and d != "password"}
            if not secret_dorks:
                continue
            owned = apex_label in rec["owner"] or apex_label in full.split("/")[-1].lower()
            secret_repos += 1
            ctx.add_finding(
                f"GitHub: {full} references {apex} near secrets ({', '.join(sorted(secret_dorks)[:3])})",
                module=self.name,
                severity=Severity.MEDIUM if owned else Severity.LOW,
                confidence=Confidence.TENTATIVE, asset=apex,
                description=("A public repo references the target alongside sensitive keywords"
                             + (" and appears to belong to the target org" if owned else "")
                             + ". Review the matched files for real credentials/endpoints — "
                             "search hits are leads, not confirmed leaks."),
                evidence={"repo": full, "dorks": sorted(secret_dorks), "urls": sorted(rec["hits"])[:8],
                          "url": next(iter(sorted(rec["hits"])), None)},
                references=sorted(rec["hits"])[:5], tags={"github", "leak-candidate"},
            )
        if repos:
            self.log.info("github: %d repo(s) mention %s (%d flagged after screening)",
                          len(repos), apex, secret_repos)

    @staticmethod
    def _is_noise(full: str, repo: dict) -> bool:
        if repo.get("fork"):
            return True
        low = full.lower()
        noise = ("seclist", "wordlist", "payload", "dork", "bugbounty-targets", "awesome-",
                 "public-suffix", "top1million", "top-1m", "crt.sh", "domains-", "-domains",
                 "certstream", "commoncrawl", "phishing", "blocklist", "blacklist", "hosts")
        return any(n in low for n in noise)
