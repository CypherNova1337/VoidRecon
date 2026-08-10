"""The Advisor — turns findings into a prioritised, actionable plan.

Recon output is only useful if you know what to do with it. The Advisor reads the
whole datastore the way a seasoned operator would and produces a ranked list of
concrete next steps — what to look at, why it matters, which assets, and a
ready-to-run VoidRecon command. It is heuristic and always on (no key, no
network); when the optional LLM layer is enabled its narrative augments this plan
rather than replacing it.
"""

from __future__ import annotations

from voidrecon.core.models import AssetKind
from voidrecon.intel.scoring import top_assets

# (rank, tag-match, action, why, command-template)  — higher rank = more urgent.
_RULES = [
    (95, "takeover", "Verify subdomain takeovers",
     "Dangling records may be claimable for full subdomain control.",
     "voidrecon run {seed} --active --only dns_resolve,takeover_verify"),
    (92, "secret", "Review leaked secrets",
     "Secret-like strings were found in JS/source — validate and report if live.",
     None),
    (90, "exposure", "Investigate exposed sensitive paths/services",
     "Config/backup/admin/database exposures are often directly impactful.",
     None),
    (88, "cloud", "Inspect exposed cloud buckets",
     "Public object storage frequently holds sensitive data.",
     None),
    (85, "axfr", "Harvest the transferred zone",
     "A successful AXFR hands you the full internal DNS map.",
     None),
    (80, "introspection", "Map the GraphQL schema and abuse mutations",
     "Full schema access exposes privileged mutations to test for authz gaps.",
     None),
    (75, "ssti", "Confirm server-side template injection",
     "SSTI commonly escalates to RCE.", None),
    (70, "sqli", "Confirm and exploit SQL injection candidates",
     "Parameter set / error signatures suggest SQLi.", None),
    (65, "open-redirect", "Weaponise open redirects",
     "Useful for phishing and OAuth token theft.", None),
    (62, "xss", "Confirm reflected XSS candidates",
     "Reflected, unencoded input reaches an HTML sink.", None),
    (60, "cve", "Validate version-based CVE matches",
     "Fingerprinted versions fall in known-vulnerable ranges.", None),
    (55, "cors", "Test the CORS misconfiguration",
     "Arbitrary-origin + credentials can leak authenticated data.", None),
    (50, "waf-bypass", "Hit the origin directly to bypass the WAF",
     "A reachable origin IP defeats the CDN/WAF protections.", None),
    (45, "user-enum", "Leverage enumerated users",
     "Valid usernames enable targeted password attacks.", None),
    (40, "auth-gate", "Attack authentication surfaces",
     "Login/admin gates are high-value; test authn/authz and defaults.", None),
]


# Attack-path chains: when these tag-sets co-occur, suggest the combined play.
_CHAINS = [
    ({"secret"}, "Leaked secrets → authenticate to the exposed service/API and pivot."),
    ({"user-enum", "auth-gate"}, "Enumerated users + a login gate → targeted password / default-cred attack."),
    ({"exposure", "auth-gate"}, "Exposed config/backup + a login gate → recover credentials, then log in."),
    ({"introspection"}, "GraphQL schema exposed → walk mutations for unauthenticated privileged actions."),
    ({"waf-bypass"}, "Reachable origin → replay attacks straight at the origin, skipping the WAF/CDN."),
    ({"takeover"}, "Claimable subdomain → host content on a trusted origin (cookie theft, phishing, CSP bypass)."),
    ({"sqli"}, "SQLi candidate → confirm with sqlmap in-scope, then assess data exposure."),
    ({"ssti"}, "SSTI candidate → build the engine-specific payload toward RCE."),
]


def _sev_counts(store) -> dict:
    out: dict[str, int] = {}
    for f in store.findings():
        out[f.severity.value] = out.get(f.severity.value, 0) + 1
    return out


def summarize(ctx) -> str:
    """A generated, key-free natural-language read of the engagement (multi-paragraph)."""
    store = ctx.store
    c = store.counts()
    sev = _sev_counts(store)
    findings = store.findings()
    target = ", ".join(ctx.scope.seeds) or "the target"
    lines: list[str] = []

    # 1) Surface.
    surface = [f"{c[k]} {label}" for k, label in
               (("subdomain", "subdomains"), ("ip", "IPs"), ("service", "open services"),
                ("url", "live web assets"), ("endpoint", "endpoints"), ("cloud_resource", "cloud resources"))
               if c.get(k)]
    live = sum(1 for a in store.assets(AssetKind.SUBDOMAIN) if a.attrs.get("resolved_ips"))
    lines.append(f"Across {target}, VoidRecon mapped " + (", ".join(surface) if surface else "no surface")
                 + (f" ({live} hosts resolve live)" if live else "") + ".")

    # 2) Risk posture with named high findings.
    if sev:
        breakdown = ", ".join(f"{sev[s]} {s}" for s in ("critical", "high", "medium", "low", "info") if sev.get(s))
        lines.append(f"Findings: {breakdown}.")
    highs = [f for f in findings if f.severity.rank >= 3]
    if highs:
        from voidrecon.utils.text import truncate
        named = "; ".join(truncate(f.title, 90) for f in sorted(highs, key=lambda f: -f.severity.rank)[:5])
        lines.append(f"Most urgent: {named}.")

    # 3) Where to look first.
    top = top_assets(store, limit=5, kinds={AssetKind.SUBDOMAIN, AssetKind.DOMAIN})
    if top:
        lines.append("Highest-priority hosts to review: "
                     + ", ".join(f"{a.value} ({a.score:.0f})" for a in top) + ".")

    # 4) Attack paths from co-occurring signals.
    tags = {t for f in findings for t in f.tags}
    plays = [msg for needed, msg in _CHAINS if needed <= tags]
    if plays:
        lines.append("Likely attack paths — " + " ".join(f"({i+1}) {p}" for i, p in enumerate(plays[:5])))
    elif not highs:
        lines.append("No high-severity findings yet; work down the prioritised hosts and enable the "
                     "opt-in active modules (fuzzing, param discovery, injection probes) on the juiciest.")

    return " ".join(lines).strip()


def recommend(ctx, limit: int = 12) -> list[dict]:
    store = ctx.store
    findings = store.findings()
    tags_present: dict[str, list[str]] = {}
    for f in findings:
        for tag in f.tags:
            tags_present.setdefault(tag, [])
            if f.asset:
                tags_present[tag].append(f.asset)

    seed = ctx.scope.seeds[0] if ctx.scope.seeds else "target"
    recs: list[dict] = []
    for rank, tag, action, why, cmd in _RULES:
        assets = tags_present.get(tag)
        if not assets and tag not in tags_present:
            continue
        uniq = sorted({a for a in assets if a})[:8]
        recs.append({
            "priority": rank,
            "action": action,
            "why": why,
            "targets": uniq,
            "command": cmd.format(seed=seed) if cmd else None,
        })

    # Always include a "review the top surface" recommendation.
    top = top_assets(store, limit=8, kinds={AssetKind.SUBDOMAIN, AssetKind.DOMAIN})
    if top:
        recs.append({
            "priority": 30,
            "action": "Manually review the highest-scoring hosts first",
            "why": "These assets scored highest for juiciness (dev/admin/API/exposed signals).",
            "targets": [f"{a.value} ({a.score:.0f})" for a in top],
            "command": None,
        })

    recs.sort(key=lambda r: -r["priority"])
    return recs[:limit]
