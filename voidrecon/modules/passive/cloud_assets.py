"""Cloud storage discovery — S3 / GCS / Azure buckets.

Object storage is where organisations spill data: public backups, database dumps,
config archives, and internal documents left in a misconfigured bucket. Attackers
guess bucket names from the org's identity and permutations of common suffixes,
then check each against the cloud provider's public endpoints.

This module builds candidate names from the seed domains (and ASN holder, if
known), probes AWS S3, Google Cloud Storage, and Azure Blob, and flags any bucket
that exists — loudly if it is publicly readable. Requests go to the cloud
providers, never the target, so this runs in the passive phase and needs no keys.
"""

from __future__ import annotations

import asyncio
import re

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence, Severity
from voidrecon.core.module import Module, Phase, register

# Suffix/prefix affixes combined with each base name.
_AFFIXES = [
    "", "dev", "development", "prod", "production", "stage", "staging", "test",
    "qa", "uat", "backup", "backups", "bak", "old", "archive", "assets", "static",
    "media", "images", "img", "uploads", "upload", "files", "data", "db", "dump",
    "dumps", "logs", "public", "private", "internal", "cdn", "www", "web", "app",
    "api", "config", "secret", "secrets", "temp", "tmp", "s3",
]
_LISTING_KEY_RE = re.compile(r"<Key>([^<]+)</Key>")


@register
class CloudAssets(Module):
    name = "cloud_assets"
    phase = Phase.PASSIVE
    active = False
    description = "Discover S3/GCS/Azure buckets from org name permutations"
    enabled_by_default = False  # opt-in: generates many speculative requests

    async def run(self, ctx: RunContext) -> None:
        bases = self._base_names(ctx)
        if not bases:
            self.log.info("no base names to permute for cloud discovery")
            return
        candidates = self._permute(bases)
        self.log.info("probing %d bucket-name candidates across S3/GCS/Azure", len(candidates))

        sem = asyncio.Semaphore(int(ctx.config.get("opsec.max_concurrency", 20)))
        found = 0

        async def probe(name):
            nonlocal found
            async with sem:
                for checker in (self._check_s3, self._check_gcs, self._check_azure):
                    hit = await checker(ctx, name)
                    if hit:
                        found += 1

        await asyncio.gather(*(probe(n) for n in candidates))
        self.log.info("cloud discovery complete: %d bucket(s) found", found)

    def _base_names(self, ctx: RunContext) -> set[str]:
        names: set[str] = set()
        for seed in ctx.scope.seeds:
            label = seed.split(".")[0]
            if label:
                names.add(label.lower())
            names.add(seed.replace(".", "-").lower())
        for asn in ctx.store.assets(kind=AssetKind.ASN):
            holder = (asn.attrs.get("holder") or "").lower()
            token = re.split(r"[^a-z0-9]+", holder)[0] if holder else ""
            if len(token) >= 3:
                names.add(token)
        return {n for n in names if 3 <= len(n) <= 40}

    def _permute(self, bases: set[str]) -> list[str]:
        out: set[str] = set()
        for base in bases:
            for affix in _AFFIXES:
                if not affix:
                    out.add(base)
                    continue
                out.add(f"{base}-{affix}")
                out.add(f"{base}{affix}")
                out.add(f"{affix}-{base}")
        # S3 naming: lowercase, digits, hyphens, dots; 3-63 chars.
        return [n for n in out if re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", n)]

    async def _record(self, ctx, name, provider, url, public, keys=None):
        asset = ctx.add_asset(
            AssetKind.CLOUD_RESOURCE, url, source=self.name,
            confidence=Confidence.CONFIRMED, provider=provider, bucket=name,
            access="public" if public else "private",
        )
        if asset:
            asset.tags.add("cloud")
            asset.tags.add("public" if public else "private")
        if public:
            ctx.add_finding(
                f"Public {provider} bucket: {name}",
                module=self.name, severity=Severity.HIGH, asset=url,
                description=(
                    f"The {provider} bucket '{name}' is publicly listable/readable. Review its "
                    "contents for sensitive data. Do not download beyond what is needed to "
                    "confirm exposure, and stay within program scope."
                ),
                evidence={"url": url, "sample_keys": (keys or [])[:15]},
                tags={"cloud", "exposure"},
            )

    async def _check_s3(self, ctx: RunContext, name: str) -> bool:
        url = f"https://{name}.s3.amazonaws.com/"
        resp = await ctx.http.get(url)
        if resp is None:
            return False
        if resp.status_code == 200 and "<ListBucketResult" in resp.text:
            keys = _LISTING_KEY_RE.findall(resp.text)
            await self._record(ctx, name, "AWS S3", url, public=True, keys=keys)
            return True
        if resp.status_code == 403 and "AccessDenied" in resp.text:
            await self._record(ctx, name, "AWS S3", url, public=False)
            return True
        return False

    async def _check_gcs(self, ctx: RunContext, name: str) -> bool:
        url = f"https://storage.googleapis.com/{name}/"
        resp = await ctx.http.get(url)
        if resp is None:
            return False
        if resp.status_code == 200 and "<ListBucketResult" in resp.text:
            keys = _LISTING_KEY_RE.findall(resp.text)
            await self._record(ctx, name, "Google Cloud Storage", url, public=True, keys=keys)
            return True
        if resp.status_code == 403 and ("AccessDenied" in resp.text or "does not have" in resp.text):
            await self._record(ctx, name, "Google Cloud Storage", url, public=False)
            return True
        return False

    async def _check_azure(self, ctx: RunContext, name: str) -> bool:
        # Azure storage account names: 3-24 lowercase alphanumerics only.
        acct = re.sub(r"[^a-z0-9]", "", name)
        if not (3 <= len(acct) <= 24):
            return False
        url = f"https://{acct}.blob.core.windows.net/?comp=list"
        resp = await ctx.http.get(url)
        if resp is None:
            return False
        if resp.status_code in (200, 400, 403, 409):
            public = resp.status_code == 200 and "<EnumerationResults" in resp.text
            await self._record(ctx, acct, "Azure Blob", url, public=public)
            return True
        return False
