"""SQL-injection candidate confirmation.

Goes a step past classifying a parameter as SQLi-shaped: it actually probes.
Error-based detection injects a quote and looks for database error signatures;
boolean-based detection compares an always-true condition (should match the
baseline) against an always-false one (should differ). A positive on either is a
strong, reportable candidate. Benign payloads only — it confirms, it doesn't dump
data. Active, scope-gated, opt-in.
"""

from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence, Severity
from voidrecon.core.module import Module, Phase, register

_SQL_ERRORS = [
    "you have an error in your sql syntax", "warning: mysqli", "warning: mysql_",
    "unclosed quotation mark after the character string", "quoted string not properly terminated",
    "pg_query", "postgresql", "org.postgresql.util.psqlexception", "sqlstate[",
    "microsoft odbc", "microsoft ole db provider for sql server", "odbc sql server driver",
    "ora-01756", "ora-00933", "ora-00921", "oracle error", "sqlite3::", "sqlite_error",
    "syntax error at or near", "supplied argument is not a valid mysql", "mysql_fetch",
    "db2 sql error", "sybase message",
]


def sql_error(body: str) -> str | None:
    low = body.lower()
    for sig in _SQL_ERRORS:
        if sig in low:
            return sig
    return None


@register
class SqliProbe(Module):
    name = "sqli_probe"
    phase = Phase.VULN
    active = True
    description = "Confirm SQL injection (error-based + boolean) on parameters"
    depends_on = ("http_probe",)
    enabled_by_default = False  # opt-in

    async def run(self, ctx: RunContext) -> None:
        targets = self._targets(ctx)
        if not targets:
            self.log.info("no parameterised endpoints for SQLi probing")
            return
        cap = int(ctx.config.get("modules.sqli_probe.max_targets", 200))
        targets = targets[:cap]
        self.log.info("SQLi-probing %d parameter(s)", len(targets))
        sem = asyncio.Semaphore(int(ctx.config.get("opsec.max_concurrency", 20)))
        found = 0

        async def worker(item):
            nonlocal found
            async with sem:
                if await self._probe(ctx, *item):
                    found += 1

        await asyncio.gather(*(worker(t) for t in targets))
        self.log.info("SQLi probing complete: %d candidate(s)", found)

    def _targets(self, ctx: RunContext):
        from voidrecon.utils.params import is_static_path, worth_injecting

        out, seen = [], set()
        for a in ctx.store.assets(kind=AssetKind.URL) + ctx.store.assets(kind=AssetKind.ENDPOINT):
            parsed = urlparse(a.value)
            if not parsed.query:
                continue
            # Static assets (/_next/data/*.json, *.js, *.map, …) have no database
            # behind them — probing them only manufactures FPs off SPA rehydration.
            if is_static_path(a.value):
                continue
            host = parsed.hostname
            if not host or not ctx.can_touch(host):
                continue
            for p, vals in parse_qs(parsed.query).items():
                # Analytics/OAuth/presentation params are not SQL sinks — don't
                # waste a probe or risk a false positive on them (e.g. utm_source).
                if not worth_injecting(p):
                    continue
                key = (a.value.split("?")[0], p)
                if key not in seen:
                    seen.add(key)
                    out.append((a.value, p, (vals or [""])[0]))
        return out

    def _mutate(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    async def _probe(self, ctx: RunContext, url: str, param: str, value: str) -> bool:
        # Baseline first — needed to prove any signal is *injection-induced*.
        base = await ctx.http.get(self._mutate(url, param, value))
        if base is None:
            return False
        base_low = base.text.lower()

        # Error-based: a DB error must appear ONLY after injecting a quote. If the
        # signature is already in the baseline it's page content (a data company's
        # marketing page mentions "PostgreSQL"/"Oracle error"), not an injection.
        err_resp = await ctx.http.get(self._mutate(url, param, value + "'"))
        if err_resp is not None:
            sig = sql_error(err_resp.text)
            if sig and sig not in base_low:      # differential: new, injection-induced
                self._report(ctx, url, param, "error-based",
                             {"signature": sig, "differential": True})
                return True
        # Boolean-based, but only on a *stable* endpoint. SPA pages (Next.js data,
        # client-rehydrated apps) return different byte counts on identical requests;
        # a naive true/false length diff there is pure noise. So: (1) confirm the
        # baseline is reproducible, (2) require true≈baseline AND false clearly
        # different, (3) require that pattern to repeat — a one-off diff isn't SQLi.
        base_samples = await self._sample_lens(ctx, url, param, value, n=3)
        if base_samples is None:
            return False
        base_len = sum(base_samples) / len(base_samples)
        noise = max(256, base_len * 0.06)
        if (max(base_samples) - min(base_samples)) > noise:
            self.log.debug("sqli: %s?%s endpoint is non-deterministic — skipping boolean", url, param)
            return False

        for true_p, false_p in ((f"{value} AND 1=1", f"{value} AND 1=2"),
                                (f"{value}' AND '1'='1", f"{value}' AND '1'='2")):
            t_lens = await self._sample_lens(ctx, url, param, true_p, n=2)
            f_lens = await self._sample_lens(ctx, url, param, false_p, n=2)
            if t_lens is None or f_lens is None:
                continue
            # Each payload must itself be reproducible (self-consistent lengths).
            if (max(t_lens) - min(t_lens)) > noise or (max(f_lens) - min(f_lens)) > noise:
                continue
            tl = sum(t_lens) / len(t_lens)
            fl = sum(f_lens) / len(f_lens)
            # True tracks the baseline, False departs from it by well over the noise
            # floor, and (implicitly) both were stable across repeats.
            if abs(tl - base_len) <= noise and abs(tl - fl) > max(512, base_len * 0.15):
                self._report(ctx, url, param, "boolean-based",
                             {"baseline": round(base_len), "true_len": round(tl),
                              "false_len": round(fl), "reproduced": True})
                return True
        return False

    async def _sample_lens(self, ctx: RunContext, url: str, param: str, value: str,
                           n: int = 2) -> list[int] | None:
        """Content lengths for the same request repeated ``n`` times, or None if any
        request fails. Lets the caller tell a stable endpoint from a noisy SPA."""
        lens: list[int] = []
        for _ in range(n):
            r = await ctx.http.get(self._mutate(url, param, value))
            if r is None:
                return None
            lens.append(len(r.content))
        return lens

    def _report(self, ctx, url, param, technique, evidence):
        from voidrecon.utils.text import short_url
        ctx.add_finding(
            f"SQL injection candidate ({technique}) in '{param}' — {short_url(url)}",
            module=self.name, severity=Severity.HIGH, confidence=Confidence.TENTATIVE,
            asset=urlparse(url).hostname,
            description=(f"The parameter shows {technique} SQL-injection behaviour. Confirm manually with "
                         "a proper tool (e.g. sqlmap) within scope before reporting."),
            evidence={"url": url, "param": param, "technique": technique, **evidence},
            tags={"sqli", "injection"},
        )
