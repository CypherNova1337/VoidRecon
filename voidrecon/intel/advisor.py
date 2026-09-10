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


def _prune_command(command: str | None, done: set[str]) -> str | None:
    """Drop modules that already ran from an ``--only a,b,c`` command.

    If every named module is already complete, the command is pointless — return
    None so the recommendation shows without a stale 're-run this' line."""
    if not command or "--only" not in command or not done:
        return command
    parts = command.split("--only", 1)
    head, rest = parts[0], parts[1].strip()
    mods_str = rest.split()[0] if rest else ""
    tail = rest[len(mods_str):]
    remaining = [m for m in mods_str.split(",") if m and m not in done]
    if not remaining:
        return None
    return f"{head}--only {','.join(remaining)}{tail}".rstrip()


def summarize(ctx) -> str:
    """A generated, key-free natural-language read of the engagement.

    Delegates to the Analyst, which reasons over the scored surface and the
    findings landed on each host. Kept as a thin entry point for backward
    compatibility."""
    from voidrecon.intel import analyst

    return analyst.analyze(ctx)["summary"]


_CONF_RANK = {"tentative": 0, "likely": 1, "confirmed": 2}


def recommend(ctx, limit: int = 12) -> list[dict]:
    store = ctx.store
    findings = store.findings()
    tags_present: dict[str, list[str]] = {}
    tag_conf: dict[str, int] = {}   # best confidence seen for each tag
    for f in findings:
        cr = _CONF_RANK.get(f.confidence.value, 0)
        for tag in f.tags:
            tags_present.setdefault(tag, [])
            if f.asset:
                tags_present[tag].append(f.asset)
            tag_conf[tag] = max(tag_conf.get(tag, -1), cr)

    seed = ctx.scope.seeds[0] if ctx.scope.seeds else "target"
    done = set(getattr(store, "completed_modules", set()) or set())
    recs: list[dict] = []
    for rank, tag, action, why, cmd in _RULES:
        assets = tags_present.get(tag)
        if not assets and tag not in tags_present:
            continue
        uniq = sorted({a for a in assets if a})[:8]
        # A step backed only by tentative evidence must never lead the playbook —
        # demote it below every confirmed-signal step (and the review step).
        priority = rank - 60 if tag_conf.get(tag, 2) == 0 else rank
        recs.append({
            "priority": priority,
            "action": action,
            "why": why,
            "targets": uniq,
            # Don't tell the operator to run modules that already ran this session.
            "command": _prune_command(cmd.format(seed=seed), done) if cmd else None,
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
