"""Attribution / scope false-positive fixes: don't treat things that aren't the
target's own surface as the target's — OS-gated CVEs, wildcard fan-out, platform
tenants, out-of-wildcard hosts, third-party repo secrets, unverified buckets."""

from __future__ import annotations

import asyncio

from voidrecon.core.config import Config
from voidrecon.core.context import RunContext
from voidrecon.core.models import Asset, AssetKind, Finding, Severity
from voidrecon.core.scope import Scope


def _ctx(seed="example.com"):
    return RunContext(Config.load(), Scope.from_lists([seed]))


# ---- 1. CVE OS gate + provenance -----------------------------------------
def test_windows_only_cve_does_not_fire_on_linux():
    from voidrecon.modules.vuln.cve_match import CveMatch

    ctx = _ctx()
    ctx.store.add_asset(Asset(AssetKind.SUBDOMAIN, "web.example.com",
                              attrs={"http_server": "Apache/2.4.59 (Ubuntu)",
                                     "technologies": ["PHP/8.3.0"]}))
    asyncio.run(CveMatch().run(ctx))
    assert not any("CVE-2024-4577" in f.title for f in ctx.store.findings())


def test_windows_only_cve_fires_on_windows_with_provenance():
    from voidrecon.modules.vuln.cve_match import CveMatch

    ctx = _ctx()
    ctx.store.add_asset(Asset(AssetKind.SUBDOMAIN, "web.example.com",
                              attrs={"http_server": "Microsoft-IIS/10.0",
                                     "technologies": ["PHP/8.3.0"]}))
    asyncio.run(CveMatch().run(ctx))
    hit = [f for f in ctx.store.findings() if "CVE-2024-4577" in f.title]
    assert hit
    assert hit[0].evidence["os_detected"] == "windows"
    assert hit[0].evidence["version_source"]          # provenance recorded


# ---- 2. wildcard-DNS collapse --------------------------------------------
def test_wildcard_hosts_collapse():
    from voidrecon.intel import correlate

    ctx = _ctx()
    for i in range(8):
        ctx.store.add_asset(Asset(AssetKind.SUBDOMAIN, f"h{i}.example.com",
                                  attrs={"resolved_ips": ["1.2.3.4"], "http_status": 200,
                                         "http_title": "Nothing here", "content_length": 512}))
    correlate._collapse_wildcard_hosts(ctx)
    wild = [a for a in ctx.store.assets(kind=AssetKind.SUBDOMAIN) if "wildcard" in a.tags]
    assert len(wild) == 7                              # 8 collapse to 1 representative
    assert any("Wildcard/catch-all" in f.title for f in ctx.store.findings())


# ---- 3. verify-scope for out-of-wildcard hosts ---------------------------
def test_out_of_wildcard_host_is_verify_scope():
    from voidrecon.intel import correlate, scoring

    ctx = _ctx()   # scope example.com
    ctx.store.add_asset(Asset(AssetKind.SUBDOMAIN, "community.other-brand.com"))  # UNKNOWN scope
    correlate._tag_verify_scope(ctx)
    a = ctx.store.get_asset(AssetKind.SUBDOMAIN, "community.other-brand.com")
    assert "verify-scope" in a.tags
    _, reasons = scoring.score_asset(a)
    assert any("verify_scope" in r for r in reasons)   # scored down


# ---- 5. platform tenancy --------------------------------------------------
def test_platform_tenant_detection_and_penalty():
    from voidrecon.intel import correlate, scoring
    from voidrecon.utils.tenants import platform_tenant

    assert platform_tenant("myblog.wordpress.com") == "WordPress.com"
    assert platform_tenant("app.example.com", "site-123.netlify.app") == "Netlify"
    assert platform_tenant("app.example.com") is None

    ctx = _ctx()
    ctx.store.add_asset(Asset(AssetKind.SUBDOMAIN, "blog.example.com",
                              attrs={"cname": "x.wordpress.com"}))
    correlate._tag_platform_tenants(ctx)
    a = ctx.store.get_asset(AssetKind.SUBDOMAIN, "blog.example.com")
    assert "platform-tenant" in a.tags and a.attrs["platform"] == "WordPress.com"
    _, reasons = scoring.score_asset(a)
    assert any("platform_tenant" in r for r in reasons)


def test_platform_tenant_excluded_from_analyst():
    from voidrecon.intel import analyst, scoring

    ctx = _ctx()
    ctx.store.add_asset(Asset(AssetKind.SUBDOMAIN, "blog.example.com",
                              tags={"platform-tenant"}, attrs={"http_status": 200}))
    ctx.store.add_finding(Finding("headers", severity=Severity.MEDIUM, module="http_analysis",
                                  asset="blog.example.com", tags={"headers"}))
    scoring.score_store(ctx.store)
    plan = analyst.analyze(ctx)
    assert all("blog.example.com" != t["asset"] for t in plan["targets"])


# ---- 6. advisor: don't recommend unverified buckets ----------------------
def test_advisor_skips_unverified_owner_bucket():
    from voidrecon.intel import advisor

    ctx = _ctx()
    ctx.store.add_finding(Finding("Public bucket (unverified)", severity=Severity.MEDIUM,
                                  module="cloud_assets", asset="https://x.s3.amazonaws.com/",
                                  tags={"cloud", "exposure", "unverified-owner"}))
    assert not any("cloud bucket" in r["action"].lower() for r in advisor.recommend(ctx))
    # a confirmed-owned bucket DOES earn the recommendation
    ctx.store.add_finding(Finding("Confirmed target-owned bucket", severity=Severity.HIGH,
                                  module="correlate", asset="https://y.s3.amazonaws.com/",
                                  tags={"cloud", "exposure", "owned"}))
    assert any("cloud bucket" in r["action"].lower() for r in advisor.recommend(ctx))
