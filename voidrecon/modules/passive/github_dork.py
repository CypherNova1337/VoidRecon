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
from voidrecon.utils.text import find_secrets, truncate

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
            # text-match returns the matched code fragment so we can show what was found.
            "Accept": "application/vnd.github.text-match+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        for seed in ctx.scope.seeds:
            await self._search_seed(ctx, seed, headers)

    async def _search_seed(self, ctx: RunContext, apex: str, headers: dict) -> None:
        # repo -> {hits, dorks, fragments, owner}
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
                    rec = repos.setdefault(full, {"hits": set(), "dorks": set(),
                                                  "fragments": [], "owner": full.split("/")[0].lower()})
                    if item.get("html_url"):
                        rec["hits"].add(item["html_url"])
                    if dork:
                        rec["dorks"].add(dork)
                    for tm in item.get("text_matches", []) or []:
                        frag = (tm.get("fragment") or "").strip()
                        if frag and frag not in rec["fragments"]:
                            rec["fragments"].append(frag)
            await asyncio.sleep(2.0)  # respect search secondary rate limits

        flagged = 0
        for full, rec in repos.items():
            ctx.add_asset(AssetKind.CODE_REPO, f"github.com/{full}", source=self.name,
                          confidence=Confidence.TENTATIVE, repo=full)
            secret_dorks = {d for d in rec["dorks"] if d and d != "password"}
            if not secret_dorks:
                continue
            # What was actually found: scan the matched code fragments for real secrets.
            real_secrets = []
            for frag in rec["fragments"]:
                real_secrets.extend(label for label, _ in find_secrets(frag))
            real_secrets = sorted(set(real_secrets))
            # Ownership: only the repo *owner* matching the org counts — a community
            # repo merely named "hytale-*" does NOT belong to the target.
            owned = apex_label == rec["owner"] or apex_label in rec["owner"].split("-")

            if real_secrets:
                sev, what = Severity.HIGH, f"live secret(s): {', '.join(real_secrets[:4])}"
            elif owned:
                sev, what = Severity.MEDIUM, f"secret-flavoured matches ({', '.join(sorted(secret_dorks)[:2])})"
            else:
                sev, what = Severity.LOW, f"third-party repo mentions {apex} ({', '.join(sorted(secret_dorks)[:2])})"
            flagged += 1

            sample = truncate(rec["fragments"][0], 240) if rec["fragments"] else "(no snippet returned)"
            ctx.add_finding(
                f"GitHub — {what}: {full}",
                module=self.name, severity=sev, confidence=Confidence.TENTATIVE, asset=apex,
                description=(f"Matched in `{full}`" + (" (target-owned)" if owned else " (third-party)")
                            + ". What matched:\n" + sample
                            + "\nReview the file(s) — search hits are leads, not confirmed leaks."),
                evidence={"repo": full, "owned": owned, "secret_types": real_secrets,
                          "matched_dorks": sorted(secret_dorks), "snippet": sample,
                          "urls": sorted(rec["hits"])[:6]},
                references=sorted(rec["hits"])[:4],
                tags={"github", "leak-candidate"} | ({"secret"} if real_secrets else set()),
            )
        if repos:
            self.log.info("github: %d repo(s) mention %s (%d flagged, %d with live secrets)",
                          len(repos), apex, flagged,
                          sum(1 for r in repos.values() if any(find_secrets(fr) for fr in r["fragments"])))

    @staticmethod
    def _is_noise(full: str, repo: dict) -> bool:
        if repo.get("fork"):
            return True
        low = full.lower()
        noise = ("seclist", "wordlist", "payload", "dork", "bugbounty-targets", "awesome-",
                 "public-suffix", "top1million", "top-1m", "crt.sh", "domains-", "-domains",
                 "certstream", "commoncrawl", "phishing", "blocklist", "blacklist", "hosts")
        return any(n in low for n in noise)
