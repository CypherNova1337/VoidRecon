"""Active DNS enumeration — wordlist brute-force and permutations.

Passive sources only know the names that leaked somewhere. Brute-forcing fills
the gaps: resolve ``<word>.<apex>`` for a curated wordlist, plus altdns-style
mutations of the subdomains already found. Resolution goes through recursive
resolvers (not the target), so it stays in the resolve tier — but it is
higher-volume, so it is opt-in (and enabled automatically in aggressive mode).

Wildcard DNS is handled correctly: for each apex we first resolve several random
names; if they answer, the apex is a wildcard and we discard any candidate that
merely resolves to the wildcard address set — otherwise brute-forcing a wildcard
domain yields thousands of phantom "hosts".
"""

from __future__ import annotations

import asyncio
import os
import random
import string

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence
from voidrecon.core.module import Module, Phase, register
from voidrecon.utils import net
from voidrecon.utils.permute import permute_from_known, wordlist_candidates

try:
    import dns.asyncresolver

    _HAS_DNS = True
except Exception:  # pragma: no cover
    _HAS_DNS = False

try:
    from importlib.resources import files as _res_files
except Exception:  # pragma: no cover
    _res_files = None


@register
class DnsBrute(Module):
    name = "dns_brute"
    phase = Phase.RESOLVE
    active = False  # resolves via public resolvers, not the target
    description = "Brute-force + permute subdomains and resolve them (wildcard-aware)"
    depends_on = ("crtsh", "passive_subs")
    enabled_by_default = False  # opt-in: higher volume than passive resolution

    async def run(self, ctx: RunContext) -> None:
        if not _HAS_DNS:
            self.log.warning("dnspython not installed — skipping brute force")
            return

        words = self._load_wordlist(ctx)
        if not words:
            self.log.info("empty wordlist — nothing to brute force")
            return

        aggressive = bool(ctx.config.get("opsec.aggressive"))
        max_candidates = int(ctx.config.get("modules.dns_brute.max_candidates",
                                            50000 if aggressive else 15000))
        do_permute = bool(ctx.config.get("modules.dns_brute.permutations", True))

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 5.0
        resolver.timeout = 5.0
        sem = asyncio.Semaphore(int(ctx.config.get("opsec.max_concurrency", 20)))

        total_found = 0
        for apex in ctx.scope.seeds:
            wildcard_ips = await self._detect_wildcard(resolver, apex)
            if wildcard_ips:
                self.log.info("%s uses wildcard DNS (%s) — filtering phantom hits",
                              apex, ",".join(sorted(wildcard_ips)))

            candidates = wordlist_candidates(apex, words)
            if do_permute:
                known = [a.value for a in ctx.store.assets(kind=AssetKind.SUBDOMAIN)
                         if net.is_subdomain_of(a.value, apex)]
                candidates |= permute_from_known(known, apex, words)
            # Drop anything already known so we only spend queries on new names.
            existing = {a.value for a in ctx.store.assets(kind=AssetKind.SUBDOMAIN)}
            candidates = [c for c in candidates if c not in existing]
            if len(candidates) > max_candidates:
                self.log.info("%s: capping %d candidates to %d", apex, len(candidates), max_candidates)
                candidates = candidates[:max_candidates]

            self.log.info("brute-forcing %d candidates for %s", len(candidates), apex)
            found = await self._resolve_all(ctx, resolver, sem, candidates, wildcard_ips)
            total_found += found
            self.log.info("dns_brute: %d new live hosts for %s", found, apex)

        if total_found:
            self.log.info("dns_brute discovered %d new hosts total", total_found)

    def _load_wordlist(self, ctx: RunContext) -> list[str]:
        path = ctx.config.get("modules.dns_brute.wordlist")
        if path and os.path.exists(path):
            with open(path, encoding="utf-8", errors="replace") as fh:
                return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        if _res_files is not None:
            try:
                raw = _res_files("voidrecon.data").joinpath("subdomains.txt").read_text(encoding="utf-8")
                return [ln.strip() for ln in raw.splitlines() if ln.strip() and not ln.startswith("#")]
            except Exception:
                pass
        return []

    async def _detect_wildcard(self, resolver, apex: str) -> set[str]:
        ips: set[str] = set()
        for _ in range(3):
            rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
            try:
                answer = await resolver.resolve(f"{rand}.{apex}", "A")
                ips.update(r.address for r in answer)
            except Exception:
                pass
        return ips

    async def _resolve_all(self, ctx, resolver, sem, candidates, wildcard_ips) -> int:
        found = 0

        async def resolve_one(host):
            nonlocal found
            async with sem:
                try:
                    answer = await resolver.resolve(host, "A")
                except Exception:
                    return
                ips = [r.address for r in answer]
                if not ips:
                    return
                # Wildcard filter: if every answer is a wildcard IP, it's a phantom.
                if wildcard_ips and set(ips).issubset(wildcard_ips):
                    return
                asset = ctx.add_asset(
                    AssetKind.SUBDOMAIN, host, source=self.name,
                    confidence=Confidence.CONFIRMED, resolved_ips=ips,
                )
                if asset:
                    asset.tags.add("live")
                    asset.tags.add("brute")
                    for ip in ips:
                        ctx.add_asset(AssetKind.IP, ip, source=self.name, resolved_from=host)
                    found += 1

        await asyncio.gather(*(resolve_one(c) for c in candidates))
        return found
