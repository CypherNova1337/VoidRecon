"""Correlation engine — turn scattered observations into leads.

Individual data points are cheap; the value is in the joins an attacker makes:
"these twelve hosts all resolve to one forgotten IP", "this apex has a dangling
CNAME to a deprovisioned SaaS", "this netblock is dense with staging boxes".
This module derives such leads from what the store already knows, emitting
:class:`Finding` records without any additional network traffic.
"""

from __future__ import annotations

from collections import defaultdict

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence, ScopeState, Severity

# CNAME targets that commonly indicate a subdomain-takeover opportunity when the
# backing resource is unclaimed. This is a lead list, not a confirmation.
_TAKEOVER_FINGERPRINTS = {
    "s3.amazonaws.com": "AWS S3",
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "herokudns.com": "Heroku",
    "cloudfront.net": "AWS CloudFront",
    "azurewebsites.net": "Azure App Service",
    "cloudapp.net": "Azure",
    "trafficmanager.net": "Azure Traffic Manager",
    "fastly.net": "Fastly",
    "ghost.io": "Ghost",
    "wordpress.com": "WordPress",
    "pantheonsite.io": "Pantheon",
    "surge.sh": "Surge",
    "bitbucket.io": "Bitbucket",
    "readthedocs.io": "Read the Docs",
    "helpscoutdocs.com": "HelpScout",
    "zendesk.com": "Zendesk",
    "unbouncepages.com": "Unbounce",
    "netlify.app": "Netlify",
    "netlify.com": "Netlify",
}


def correlate(ctx: RunContext) -> None:
    _cluster_by_ip(ctx)
    _flag_takeover_candidates(ctx)
    _dense_netblocks(ctx)
    _cluster_by_favicon(ctx)
    _cluster_by_tracker(ctx)
    _out_of_scope_leads(ctx)


def _cluster_by_ip(ctx: RunContext) -> None:
    by_ip: dict[str, list[str]] = defaultdict(list)
    for asset in ctx.store.assets(kind=AssetKind.SUBDOMAIN):
        for ip in asset.attrs.get("resolved_ips", []) or []:
            by_ip[ip].append(asset.value)
    for ip, hosts in by_ip.items():
        if len(hosts) >= 5:
            ctx.add_finding(
                f"{len(hosts)} hosts share IP {ip}",
                module="correlate",
                severity=Severity.INFO,
                asset=ip,
                description=(
                    "Many hostnames collapse to a single origin. Shared hosting or a "
                    "reverse proxy — probe for virtual-host routing and host-header "
                    "based access to sibling apps."
                ),
                evidence={"ip": ip, "hosts": sorted(hosts)[:50], "count": len(hosts)},
                tags={"vhost", "cluster"},
            )


def _flag_takeover_candidates(ctx: RunContext) -> None:
    for asset in ctx.store.assets(kind=AssetKind.SUBDOMAIN):
        cname = (asset.attrs.get("cname") or "").lower().rstrip(".")
        if not cname:
            continue
        for fp, provider in _TAKEOVER_FINGERPRINTS.items():
            if cname.endswith(fp):
                resolves = bool(asset.attrs.get("resolved_ips"))
                asset.attrs["takeover_candidate"] = True
                ctx.add_finding(
                    f"Potential subdomain takeover: {asset.value} -> {provider}",
                    module="correlate",
                    severity=Severity.HIGH if not resolves else Severity.MEDIUM,
                    confidence=Confidence.TENTATIVE,
                    asset=asset.value,
                    description=(
                        f"CNAME points to {provider} ({cname}). If the backing resource "
                        "is unclaimed the subdomain may be takeoverable. Verify the "
                        "provider's claim status before reporting — do not register "
                        "third-party resources without authorization."
                    ),
                    evidence={"cname": cname, "provider": provider, "resolves": resolves},
                    references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
                    tags={"takeover"},
                )
                break


def _dense_netblocks(ctx: RunContext) -> None:
    from ipaddress import ip_network

    cidrs = [a.value for a in ctx.store.assets(kind=AssetKind.CIDR)]
    if not cidrs:
        return
    ips = [a.value for a in ctx.store.assets(kind=AssetKind.IP)]
    for cidr in cidrs:
        try:
            net = ip_network(cidr, strict=False)
        except ValueError:
            continue
        inside = [ip for ip in ips if _safe_in(ip, net)]
        if len(inside) >= 3:
            ctx.add_finding(
                f"Owned netblock {cidr} hosts {len(inside)} discovered IPs",
                module="correlate",
                severity=Severity.INFO,
                asset=cidr,
                description="An org-owned range with live assets — expand active scanning here (in scope only).",
                evidence={"cidr": cidr, "ips": inside[:50]},
                tags={"netblock"},
            )


def _safe_in(ip: str, net) -> bool:
    from ipaddress import ip_address

    try:
        return ip_address(ip) in net
    except ValueError:
        return False


def _cluster_by_favicon(ctx: RunContext) -> None:
    by_hash: dict[int, list[str]] = defaultdict(list)
    for asset in ctx.store.assets():
        fh = asset.attrs.get("favicon_hash")
        if fh is not None:
            by_hash[fh].append(asset.value)
    for fh, hosts in by_hash.items():
        if len(hosts) >= 2:
            ctx.add_finding(
                f"{len(hosts)} hosts share favicon hash {fh}",
                module="correlate",
                severity=Severity.INFO,
                description=(
                    "Identical favicons across hosts indicate shared infrastructure or "
                    "cloned deployments (staging/shadow copies). Pivot on this hash in "
                    "Shodan/Censys to find further assets across the internet."
                ),
                evidence={"favicon_hash": fh, "hosts": sorted(hosts)[:50]},
                tags={"favicon", "cluster"},
            )


def _cluster_by_tracker(ctx: RunContext) -> None:
    by_tracker: dict[str, list[str]] = defaultdict(list)
    for asset in ctx.store.assets():
        for tracker in asset.attrs.get("trackers") or []:
            by_tracker[tracker].append(asset.value)
    for tracker, hosts in by_tracker.items():
        if len(set(hosts)) >= 2:
            ctx.add_finding(
                f"Shared analytics/tracking ID links {len(set(hosts))} hosts ({tracker})",
                module="correlate",
                severity=Severity.INFO,
                description=(
                    "Multiple hosts embed the same tracking identifier — strong evidence they "
                    "belong to the same organisation. Use this to confirm ownership of hosts "
                    "whose names don't obviously relate, and as a lead for scope expansion."
                ),
                evidence={"tracker": tracker, "hosts": sorted(set(hosts))[:50]},
                tags={"tracker", "cluster", "attribution"},
            )


def _out_of_scope_leads(ctx: RunContext) -> None:
    oos = ctx.store.assets(scope_state=ScopeState.OUT_OF_SCOPE)
    related = [a for a in oos if a.kind in (AssetKind.SUBDOMAIN, AssetKind.DOMAIN)]
    if len(related) >= 1:
        ctx.add_finding(
            f"{len(related)} out-of-scope assets discovered (possible expansion targets)",
            module="correlate",
            severity=Severity.INFO,
            description=(
                "Assets tied to the target but outside the declared scope — acquisitions, "
                "third parties, or sibling brands. Not probed by VoidRecon. Consider "
                "requesting scope expansion from the program before touching them."
            ),
            evidence={"assets": [a.value for a in related][:100]},
            tags={"scope-expansion"},
        )
