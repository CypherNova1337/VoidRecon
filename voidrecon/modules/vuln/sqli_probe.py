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
        out, seen = [], set()
        for a in ctx.store.assets(kind=AssetKind.URL) + ctx.store.assets(kind=AssetKind.ENDPOINT):
            parsed = urlparse(a.value)
            if not parsed.query:
                continue
            host = parsed.hostname
            if not host or not ctx.can_touch(host):
                continue
            for p, vals in parse_qs(parsed.query).items():
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
        # Error-based.
        err_resp = await ctx.http.get(self._mutate(url, param, value + "'"))
        if err_resp is not None:
            sig = sql_error(err_resp.text)
            if sig:
                self._report(ctx, url, param, "error-based", {"signature": sig})
                return True
        # Boolean-based (numeric + string contexts).
        base = await ctx.http.get(self._mutate(url, param, value))
        if base is None:
            return False
        base_len = len(base.content)
        for true_p, false_p in ((f"{value} AND 1=1", f"{value} AND 1=2"),
                                (f"{value}' AND '1'='1", f"{value}' AND '1'='2")):
            t = await ctx.http.get(self._mutate(url, param, true_p))
            f = await ctx.http.get(self._mutate(url, param, false_p))
            if t is None or f is None:
                continue
            tl, fl = len(t.content), len(f.content)
            # True ~ baseline, False clearly different → boolean SQLi.
            if abs(tl - base_len) <= max(64, base_len * 0.02) and abs(tl - fl) > max(128, base_len * 0.1):
                self._report(ctx, url, param, "boolean-based",
                             {"baseline": base_len, "true_len": tl, "false_len": fl})
                return True
        return False

    def _report(self, ctx, url, param, technique, evidence):
        ctx.add_finding(
            f"SQL injection candidate ({technique}): {url} (parameter '{param}')",
            module=self.name, severity=Severity.HIGH, confidence=Confidence.TENTATIVE,
            asset=urlparse(url).hostname,
            description=(f"The parameter shows {technique} SQL-injection behaviour. Confirm manually with "
                         "a proper tool (e.g. sqlmap) within scope before reporting."),
            evidence={"url": url, "param": param, "technique": technique, **evidence},
            tags={"sqli", "injection"},
        )
