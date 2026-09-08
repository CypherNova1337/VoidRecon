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
    _verify_bucket_ownership(ctx)
    _oauth_flow_intel(ctx)
    _dense_netblocks(ctx)
    _cluster_by_favicon(ctx)
    _cluster_by_tracker(ctx)
    _out_of_scope_leads(ctx)


def _oauth_flow_intel(ctx: RunContext) -> None:
    """Turn harvested OAuth authorization URLs into in-scope recon.

    The crawler picks up links like ``accounts.google.com/o/oauth2/auth?client_id=…
    &redirect_uri=https://backstage.example.com/…``. That URL is a third party's,
    but it *leaks the target's own* OAuth client_id and the redirect URIs the app
    trusts — real, in-scope attack surface (redirect/token-theft testing). So we
    attribute it to the in-scope redirect host, never to the IdP."""
    from urllib.parse import parse_qs, urlsplit

    from voidrecon.utils import net

    _CID = ("client_id", "clientid", "client", "app_id", "appid")
    _RED = ("redirect_uri", "redirect_url", "redirect", "continue", "callback", "next", "return")
    flows: dict[str, dict] = {}
    for a in ctx.store.assets(kind=AssetKind.URL) + ctx.store.assets(kind=AssetKind.ENDPOINT):
        try:
            q = parse_qs(urlsplit(a.value).query)
        except Exception:
            continue
        cid = next((q[k][0] for k in _CID if q.get(k)), None)
        if not cid:
            continue
        redirs = [v for k in _RED for v in q.get(k, [])]
        rec = flows.setdefault(cid, {"redirect_uris": set(), "authorize": set(), "in_scope": set()})
        rec["authorize"].add(a.value.split("?")[0])
        for r in redirs:
            rec["redirect_uris"].add(r)
            h = net.host_from_url(r)
            if h and ctx.is_target_host(h):
                rec["in_scope"].add(h)

    for cid, rec in flows.items():
        in_scope = sorted(rec["in_scope"])
        if not in_scope:
            continue   # only worth reporting when it leaks an in-scope redirect target
        for h in in_scope:
            kind = AssetKind.DOMAIN if net.registrable_domain(h) == h else AssetKind.SUBDOMAIN
            ctx.add_asset(kind, h, source="oauth_intel", confidence=Confidence.LIKELY,
                          via_oauth_client=cid)
        ctx.add_finding(
            f"OAuth client config leaked: {len(in_scope)} in-scope redirect host(s) — {in_scope[0]}",
            module="correlate", severity=Severity.LOW, confidence=Confidence.LIKELY,
            asset=in_scope[0],
            description=("A harvested OAuth authorization URL exposes the target's client_id and the "
                         "redirect URIs it trusts. The in-scope redirect hosts are valid surface — "
                         "test them for open redirect / OAuth redirect-URI abuse and token theft."),
            evidence={"client_id": cid, "in_scope_redirect_hosts": in_scope,
                      "redirect_uris": sorted(rec["redirect_uris"])[:20],
                      "authorize_urls": sorted(rec["authorize"])[:5]},
            tags={"oauth-flow", "attribution"},
        )


def _verify_bucket_ownership(ctx: RunContext) -> None:
    """Provenance check for discovered cloud buckets.

    A bucket whose name matches the org proves nothing — squatters register those.
    Real ownership is shown by a *target host pointing at the bucket*: a subdomain
    whose CNAME resolves onto the bucket's storage host. This runs after DNS
    resolution, so CNAMEs are populated. When we find that link we upgrade the
    bucket to a confirmed, target-owned exposure."""
    buckets = [a for a in ctx.store.assets(kind=AssetKind.CLOUD_RESOURCE)
               if a.attrs.get("bucket")]
    if not buckets:
        return
    subs = ctx.store.assets(kind=AssetKind.SUBDOMAIN)

    def points_at(bucket_name: str, provider: str) -> str | None:
        for sub in subs:
            cname = (sub.attrs.get("cname") or "").lower().rstrip(".")
            if not cname:
                continue
            if provider == "AWS S3" and (
                    cname.startswith(f"{bucket_name}.s3") or
                    (bucket_name in cname and ".s3" in cname and "amazonaws" in cname)):
                return sub.value
            if provider == "Azure Blob" and cname.startswith(f"{bucket_name}.blob."):
                return sub.value
            if provider == "Google Cloud Storage" and "storage.googleapis.com" in cname and (
                    sub.value == bucket_name or sub.value.split(".")[0] == bucket_name.split(".")[0]):
                return sub.value
        return None

    for b in buckets:
        name = b.attrs.get("bucket")
        provider = b.attrs.get("provider") or "cloud"
        host = points_at(name, provider)
        if not host:
            continue
        # Confirmed the org's: a target host resolves onto this bucket.
        b.tags.discard("unverified-owner")
        b.tags.add("owned")
        b.attrs["ownership"] = "confirmed"
        b.attrs["provenance_host"] = host
        public = "public" in b.tags
        ctx.add_finding(
            f"Confirmed target-owned {provider} bucket: {name}",
            module="correlate",
            severity=Severity.HIGH if public else Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            asset=b.value,
            description=(
                f"The target host {host} CNAMEs onto this {provider} bucket, confirming the "
                "org owns it (not a name-squatter). "
                + ("It is also publicly listable — review for exposed data, in scope."
                   if public else "Access is restricted; note it as owned infrastructure.")
            ),
            evidence={"url": b.value, "bucket": name, "provider": provider,
                      "provenance_host": host, "ownership": "confirmed"},
            tags={"cloud", "exposure", "owned"} if public else {"cloud", "owned"},
        )


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
    """Flag CNAME-to-provider hosts as takeover *candidates* only.

    A CNAME to a SaaS/cloud provider is not a takeover — most point at live,
    claimed resources. Only ``takeover_verify`` (which matches the provider's
    "unclaimed resource" fingerprint over HTTP) may promote a candidate to a
    confirmed ``takeover``. Here we distinguish two verdicts so the report never
    calls a live host "claimable":

    * **dangling** — the name does not resolve (record absent): a real lead.
    * **live** — it resolves to provider infra: probably claimed; verify only.
    """
    for asset in ctx.store.assets(kind=AssetKind.SUBDOMAIN):
        if asset.attrs.get("takeover_confirmed"):
            continue  # takeover_verify already confirmed this one
        cname = (asset.attrs.get("cname") or "").lower().rstrip(".")
        if not cname:
            continue
        for fp, provider in _TAKEOVER_FINGERPRINTS.items():
            if cname.endswith(fp):
                resolves = bool(asset.attrs.get("resolved_ips"))
                asset.attrs["takeover_lead"] = provider   # NOT takeover_confirmed
                if resolves:
                    ctx.add_finding(
                        f"CNAME to {provider} (live — verify claim status, not obviously dangling): {asset.value}",
                        module="correlate", severity=Severity.INFO, confidence=Confidence.TENTATIVE,
                        asset=asset.value,
                        description=(
                            f"{asset.value} CNAMEs to {provider} ({cname}) and resolves to live "
                            "infrastructure — the resource is most likely claimed. This is a lead to "
                            "verify, not a takeover; check the provider's claim status before reporting."
                        ),
                        evidence={"cname": cname, "provider": provider, "resolves": True,
                                  "verdict": "live-verify"},
                        tags={"takeover-candidate"},
                    )
                else:
                    ctx.add_finding(
                        f"Dangling CNAME to {provider} (takeover candidate): {asset.value}",
                        module="correlate", severity=Severity.MEDIUM, confidence=Confidence.TENTATIVE,
                        asset=asset.value,
                        description=(
                            f"{asset.value} CNAMEs to {provider} ({cname}) but the name does not resolve "
                            "(record absent) — a classic dangling-record takeover candidate. Confirm the "
                            "backing resource is unclaimed (takeover_verify checks the provider fingerprint) "
                            "before reporting; do not register third-party resources without authorization."
                        ),
                        evidence={"cname": cname, "provider": provider, "resolves": False,
                                  "verdict": "dangling"},
                        references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
                        tags={"takeover-candidate", "dangling"},
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
