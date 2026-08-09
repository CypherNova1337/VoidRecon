"""Heuristic asset scoring — the always-on "smart" layer.

The score answers one question an attacker constantly asks: *which of these
hundreds of assets should I look at first?* It rewards the things that
disproportionately lead to real findings — forgotten/dev/staging hosts, admin
and API surfaces, exposed infra, dangling records — and it works with zero
network calls or API keys.

Scores are additive signals capped into a 0–100 band, stored on
``asset.score`` and mirrored into ``asset.attrs['score_reasons']`` for
explainability.
"""

from __future__ import annotations

import re

from voidrecon.core.models import Asset, AssetKind, ScopeState
from voidrecon.core.store import DataStore

# Tokens in a hostname that hint at soft, forgotten, or high-value surface.
_JUICY_TOKENS = {
    "dev": 12, "development": 12, "stage": 12, "staging": 12, "test": 11,
    "testing": 11, "qa": 10, "uat": 10, "sandbox": 10, "demo": 8, "beta": 8,
    "preprod": 12, "pre-prod": 12, "internal": 15, "intranet": 15, "corp": 12,
    "admin": 16, "administrator": 16, "root": 10, "manage": 10, "management": 10,
    "api": 12, "apis": 12, "graphql": 13, "rest": 8, "gateway": 9, "gw": 6,
    "auth": 13, "sso": 13, "login": 11, "oauth": 12, "idp": 12, "account": 9,
    "vpn": 12, "remote": 10, "citrix": 11, "rdp": 11, "ssh": 8,
    "jenkins": 15, "gitlab": 14, "git": 10, "jira": 11, "confluence": 12,
    "grafana": 12, "kibana": 13, "prometheus": 11, "consul": 12, "vault": 15,
    "k8s": 12, "kube": 12, "kubernetes": 12, "docker": 10, "registry": 11,
    "s3": 10, "storage": 8, "backup": 14, "bak": 12, "old": 12, "legacy": 13,
    "deprecated": 12, "temp": 10, "tmp": 10, "new": 6, "v1": 5, "v2": 5,
    "db": 12, "database": 12, "sql": 11, "mysql": 11, "postgres": 11, "redis": 11,
    "mongo": 11, "elastic": 12, "es": 4, "phpmyadmin": 16, "adminer": 16,
    "portal": 8, "dashboard": 10, "panel": 12, "cpanel": 13, "webmail": 10,
    "mail": 6, "smtp": 6, "ftp": 9, "files": 8, "upload": 10, "uploads": 10,
    "payment": 12, "pay": 9, "billing": 11, "invoice": 9, "checkout": 10,
    "secret": 14, "secrets": 14, "config": 11, "env": 12, "debug": 13,
    "status": 6, "health": 5, "metrics": 8, "monitor": 8, "monitoring": 8,
}

_ENV_RE = re.compile(r"\b(dev|stage|staging|test|qa|uat|preprod)\b")


def score_asset(asset: Asset) -> tuple[float, list[str]]:
    reasons: list[str] = []
    score = 0.0

    if asset.kind in (AssetKind.SUBDOMAIN, AssetKind.DOMAIN, AssetKind.URL, AssetKind.ENDPOINT):
        host = asset.value.lower()
        labels = re.split(r"[.\-_]", host)
        matched = set()
        for token, weight in _JUICY_TOKENS.items():
            if token in labels and token not in matched:
                score += weight
                matched.add(token)
                reasons.append(f"keyword:{token}(+{weight})")
        # Deep subdomains (many labels) are often internal/forgotten.
        depth = asset.value.count(".")
        if depth >= 3:
            bonus = min((depth - 2) * 3, 12)
            score += bonus
            reasons.append(f"depth:{depth}(+{bonus})")

    # Enrichment-driven signals ------------------------------------------------
    attrs = asset.attrs
    if attrs.get("takeover_candidate"):
        score += 30
        reasons.append("dangling/takeover(+30)")
    ports = attrs.get("open_ports") or []
    if ports:
        interesting = {21, 22, 23, 445, 1433, 2375, 3306, 3389, 5432, 5601, 6379, 8080, 8443, 9000, 9200, 27017}
        hit = [p for p in ports if p in interesting]
        if hit:
            bump = min(len(hit) * 4, 16)
            score += bump
            reasons.append(f"risky_ports:{hit}(+{bump})")
    status = attrs.get("http_status")
    if status in (401, 403):
        score += 6
        reasons.append("auth_gate(+6)")
    if status in (500, 502, 503):
        score += 4
        reasons.append("server_error(+4)")
    title = (attrs.get("http_title") or "").lower()
    for token in ("login", "admin", "dashboard", "sign in", "swagger", "api", "phpmyadmin", "grafana", "kibana", "jenkins"):
        if token in title:
            score += 5
            reasons.append(f"title:{token}(+5)")
            break
    techs = attrs.get("technologies") or []
    if any("wordpress" in str(t).lower() for t in techs):
        score += 4
        reasons.append("wordpress(+4)")
    if attrs.get("secrets_found"):
        score += 25
        reasons.append("secrets_in_content(+25)")
    if attrs.get("wildcard_origin"):
        score -= 5
        reasons.append("wildcard_origin(-5)")

    # Scope shaping ------------------------------------------------------------
    if asset.scope_state == ScopeState.OUT_OF_SCOPE:
        score *= 0.3
        reasons.append("out_of_scope(x0.3)")
    elif asset.scope_state == ScopeState.IN_SCOPE:
        score += 3
        reasons.append("in_scope(+3)")

    score = max(0.0, min(score, 100.0))
    return round(score, 2), reasons


def score_store(store: DataStore) -> None:
    for asset in store.iter_assets():
        score, reasons = score_asset(asset)
        asset.score = score
        if reasons:
            asset.attrs["score_reasons"] = reasons


def top_assets(store: DataStore, limit: int = 25, kinds=None) -> list[Asset]:
    assets = store.assets()
    if kinds:
        kinds = set(kinds)
        assets = [a for a in assets if a.kind in kinds]
    return sorted(assets, key=lambda a: a.score, reverse=True)[:limit]
