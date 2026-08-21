"""The Analyst — VoidRecon's built-in reasoning layer (keyless, always on).

Scoring says *which* host to look at; correlation emits raw joins. The Analyst is
the part that reasons like an operator: for each promising target it fuses the
host's own signals (name tokens, HTTP posture, tech) with the findings actually
landed on it, recognises multi-signal *attack chains* that only make sense when
several things co-occur on the same host, and writes a concrete, evidence-grounded
brief — what this host is, why it matters, and the exact play to run next.

It needs no API key and makes no network calls, so it is always available and
never rate-limited. When the optional LLM layer is enabled it is *seeded* with the
Analyst's chains and dossiers, so the model refines real reasoning instead of
starting from a flat asset list.
"""

from __future__ import annotations

from voidrecon.core.models import AssetKind
from voidrecon.intel.scoring import _findings_by_asset, top_assets
from voidrecon.utils.text import truncate

# Attack chains recognised from the *combined* signal set on a single host. Each
# chain fires only when every required signal is present together — that
# co-occurrence is the insight a flat finding list misses.
# (name, required-signals, impact 0-100, the play, optional command template)
_CHAINS: list[tuple[str, set[str], int, str, str | None]] = [
    ("Leaked credential → authenticated access",
     {"secret", "auth-gate"}, 92,
     "A secret leaks on a host that also gates access. Validate the secret against "
     "the login/API — a live key walks you straight past the gate.", None),
    ("Exposed config/backup → credential recovery → login",
     {"exposure", "auth-gate"}, 88,
     "Exposed config/backup next to a login gate. Recover credentials from the "
     "exposure, then authenticate — a very common full-access chain.", None),
    ("SQLi on a privileged surface",
     {"sqli", "admin"}, 86,
     "A SQL-injection candidate on an admin/privileged host. Confirm carefully "
     "in-scope; behind an admin panel the blast radius is high.",
     "sqlmap -u '{url}' --batch --risk 2 --level 3"),
    ("SQLi behind an auth gate",
     {"sqli", "auth-gate"}, 82,
     "SQLi candidate on an authenticated surface — reachable once you clear the "
     "gate, and authenticated endpoints are often less hardened.",
     "sqlmap -u '{url}' --batch"),
    ("SSTI → RCE on an app host",
     {"ssti"}, 84,
     "SSTI candidate — build the engine-specific payload; template injection "
     "escalates to remote code execution more often than not.", None),
    ("GraphQL introspection → privileged mutations",
     {"introspection"}, 80,
     "GraphQL schema is exposed. Walk the mutations for unauthenticated or "
     "under-authorised privileged actions.", None),
    ("Subdomain takeover → trusted-origin abuse",
     {"takeover"}, 85,
     "Claimable dangling record. If the backing resource is unclaimed you can host "
     "content on a trusted origin (cookie theft, phishing, CSP bypass). Verify the "
     "provider's claim status before reporting.", None),
    ("Origin exposure → WAF bypass",
     {"waf-bypass"}, 70,
     "The origin IP is reachable behind the CDN/WAF. Replay attacks straight at the "
     "origin, skipping the edge protections.", None),
    ("Reflected XSS on a juicy host",
     {"xss", "auth-gate"}, 60,
     "Reflected, unencoded input on an authenticated surface — session-scoped XSS "
     "is worth more than an anonymous reflection.", None),
    ("Exposed admin surface",
     {"admin", "auth-gate"}, 58,
     "An admin/management surface presenting a login. Test default creds, authn "
     "bypass, and IDOR once past it.", None),
]

# Host-name tokens (from the score reasons) worth treating as reasoning signals.
_TOKEN_SIGNALS = {
    "admin", "api", "graphql", "auth", "sso", "login", "oauth", "dev", "staging",
    "test", "internal", "vpn", "jenkins", "gitlab", "vault", "backup", "debug",
    "payment", "billing", "db", "database", "panel", "dashboard",
}


def _signals(asset, findings) -> set[str]:
    """The fused signal vocabulary for one host: finding tags + name tokens +
    HTTP/enrichment posture. This is what the chains match against."""
    sig: set[str] = set()
    for f in findings:
        sig |= {str(t) for t in f.tags}
    for reason in asset.attrs.get("score_reasons", []) or []:
        if reason.startswith("keyword:"):
            token = reason.split(":", 1)[1].split("(", 1)[0]
            if token in _TOKEN_SIGNALS:
                sig.add("admin" if token in ("panel", "dashboard") else token)
    st = asset.attrs.get("http_status")
    if st in (401, 403):
        sig.add("auth-gate")
    if asset.attrs.get("secrets_found"):
        sig.add("secret")
    if asset.attrs.get("takeover_candidate"):
        sig.add("takeover")
    if asset.attrs.get("origin_ip") or asset.attrs.get("waf_bypass"):
        sig.add("waf-bypass")
    return sig


def _finding_url(findings) -> str | None:
    for f in findings:
        u = (f.evidence or {}).get("url")
        if u:
            return str(u)
    return None


def _chains_for(signals: set[str], url: str | None) -> list[dict]:
    plays = []
    for name, need, impact, how, cmd in _CHAINS:
        if need <= signals:
            plays.append({
                "name": name,
                "impact": impact,
                "how": how,
                "command": (cmd.format(url=url) if cmd and url else None),
                "signals": sorted(need),
            })
    plays.sort(key=lambda p: -p["impact"])
    return plays


def _dossier(asset, findings) -> dict:
    signals = _signals(asset, findings)
    url = _finding_url(findings)
    chains = _chains_for(signals, url)
    sevs = sorted({f.severity.value for f in findings}, key=lambda s: -_rank(s))
    top_finding = max(findings, key=lambda f: f.severity.rank) if findings else None

    # A human descriptor of what this host *is*.
    role_bits = [t for t in ("admin", "api", "graphql", "auth", "vpn", "internal",
                             "dev", "staging", "jenkins", "gitlab", "vault", "payment")
                 if t in signals]
    posture = []
    if "auth-gate" in signals:
        posture.append("behind an auth gate")
    if asset.attrs.get("http_title"):
        posture.append(f"“{truncate(str(asset.attrs['http_title']), 40)}”")
    descriptor = (", ".join(role_bits) + " host") if role_bits else f"{asset.kind.value}"

    # The brief: one grounded sentence a hunter can act on.
    parts = [f"{asset.value} (score {asset.score:.0f}) — {descriptor}"]
    if posture:
        parts.append(" " + ", ".join(posture))
    if findings:
        parts.append(f"; {len(findings)} finding(s)")
        if top_finding:
            parts.append(f", top: [{top_finding.severity.value.upper()}] "
                         f"{truncate(top_finding.title, 80)}")
    parts.append(".")
    if chains:
        parts.append(f" Play → {chains[0]['how']}")
    brief = "".join(parts)

    return {
        "asset": asset.value,
        "kind": asset.kind.value,
        "score": round(asset.score, 2),
        "signals": sorted(signals),
        "severities": sevs,
        "findings": [
            {"title": f.title, "severity": f.severity.value, "tags": sorted(f.tags)}
            for f in sorted(findings, key=lambda f: -f.severity.rank)[:6]
        ],
        "chains": chains,
        "brief": brief,
        "worth": bool(chains or findings or asset.score >= 25),
    }


def _rank(sev_value: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(sev_value, 0)


def _lookup_or_synth(store, key: str, findings):
    """Return the stored asset for a finding-bearing host, or a lightweight
    stand-in scored from its findings — so a host we found a bug on is reasoned
    about even if no discovery module recorded it as an asset."""
    from voidrecon.core.models import Asset

    for kind in (AssetKind.SUBDOMAIN, AssetKind.DOMAIN, AssetKind.URL, AssetKind.IP):
        found = store.get_asset(kind, key)
        if found is not None:
            return found
    best = max(findings, key=lambda f: f.severity.rank) if findings else None
    score = {"critical": 60, "high": 45, "medium": 25, "low": 10, "info": 3}.get(
        best.severity.value, 5) if best else 5
    return Asset(kind=AssetKind.SUBDOMAIN, value=key, score=float(score))


def analyze(ctx, limit: int = 10) -> dict:
    """Produce the battle plan: ranked target dossiers, the standout plays, and a
    grounded natural-language read of the whole engagement."""
    store = ctx.store
    idx = _findings_by_asset(store)
    kinds = {AssetKind.SUBDOMAIN, AssetKind.DOMAIN, AssetKind.URL, AssetKind.IP}

    # Candidate hosts: the top-scored assets, plus every host a finding names
    # (findings are evidence — never let one fall out for want of a scored asset).
    candidates: dict[str, object] = {}
    for asset in top_assets(store, limit=limit * 3, kinds=kinds):
        candidates.setdefault(asset.value.lower(), asset)
    for key, findings in idx.items():
        if key not in candidates:
            candidates[key] = _lookup_or_synth(store, key, findings)

    dossiers: list[dict] = []
    for key, asset in candidates.items():
        findings = idx.get(asset.value.lower(), []) or idx.get(key, [])
        d = _dossier(asset, findings)
        if d["worth"]:
            dossiers.append(d)
    dossiers.sort(key=lambda d: -d["score"])
    targets = dossiers[:limit]

    # The standout plays across the whole surface, de-duplicated by name and
    # attributed to the host they fire on.
    plays: list[dict] = []
    seen = set()
    for t in targets:
        for c in t["chains"]:
            key = (c["name"], t["asset"])
            if key in seen:
                continue
            seen.add(key)
            plays.append({**c, "asset": t["asset"]})
    plays.sort(key=lambda p: -p["impact"])

    focus = [t["asset"] for t in targets[:6]]
    summary = _summary(ctx, targets, plays)
    return {"summary": summary, "targets": targets, "plays": plays[:8], "focus": focus}


def _summary(ctx, targets: list[dict], plays: list[dict]) -> str:
    store = ctx.store
    c = store.counts()
    target_name = ", ".join(ctx.scope.seeds) or "the target"
    lines: list[str] = []

    surface = [f"{c[k]} {label}" for k, label in
               (("subdomain", "subdomains"), ("ip", "IPs"), ("service", "open services"),
                ("url", "live web assets"), ("endpoint", "endpoints"),
                ("cloud_resource", "cloud resources")) if c.get(k)]
    live = sum(1 for a in store.assets(AssetKind.SUBDOMAIN) if a.attrs.get("resolved_ips"))
    lines.append(f"Across {target_name}, VoidRecon mapped "
                 + (", ".join(surface) if surface else "no surface")
                 + (f" ({live} resolve live)" if live else "") + ".")

    sev: dict[str, int] = {}
    for f in store.findings():
        sev[f.severity.value] = sev.get(f.severity.value, 0) + 1
    if sev:
        breakdown = ", ".join(f"{sev[s]} {s}" for s in
                              ("critical", "high", "medium", "low", "info") if sev.get(s))
        lines.append(f"Findings: {breakdown}.")

    if plays:
        best = plays[0]
        lines.append(f"Highest-value play: {best['name']} on {best['asset']} — {best['how']}")

    if targets:
        head = "; ".join(f"{t['asset']} ({t['score']:.0f})" for t in targets[:5])
        lines.append(f"Start here: {head}.")
    else:
        lines.append("No high-priority targets stood out yet — enable the opt-in active "
                     "modules (fuzz, param_discovery, injection probes) on the top hosts and re-run.")

    return " ".join(lines).strip()
