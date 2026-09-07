"""Severity calibration + FP gates from the fivetran.com field review: weak
evidence must not read as HIGH, and must not feed attack plays or next-steps."""

from __future__ import annotations

import asyncio

from voidrecon.core.config import Config
from voidrecon.core.context import RunContext
from voidrecon.core.models import Asset, AssetKind, Finding, Severity
from voidrecon.core.scope import Scope


def _ctx(active=False):
    ov = {"opsec": {"allow_active": True}} if active else {}
    return RunContext(Config.load(overrides=ov), Scope.from_lists(["example.com"]))


# ---- sensitive-path gating (fuzz) ----------------------------------------
def test_sensitive_path_401_is_info_not_exposure():
    from voidrecon.modules.content.fuzz import Fuzz

    ctx = _ctx()
    Fuzz()._flag_sensitive(ctx, "https://example.com", "https://example.com/.env", 401, 20, "text/html")
    f = ctx.store.findings()[0]
    assert f.severity == Severity.INFO
    assert "exposure" not in f.tags        # a gated path is not an exposure
    assert "access-controlled" in f.tags


def test_sensitive_path_200_html_is_catchall_not_exposure():
    from voidrecon.modules.content.fuzz import Fuzz

    ctx = _ctx()
    Fuzz()._flag_sensitive(ctx, "https://example.com", "https://example.com/.git/HEAD", 200, 5000, "text/html")
    f = ctx.store.findings()[0]
    assert f.severity == Severity.INFO
    assert "exposure" not in f.tags


def test_sensitive_path_200_real_content_is_high_exposure():
    from voidrecon.modules.content.fuzz import Fuzz

    ctx = _ctx()
    Fuzz()._flag_sensitive(ctx, "https://example.com", "https://example.com/.env", 200, 300,
                           "text/plain")
    f = ctx.store.findings()[0]
    assert f.severity == Severity.HIGH
    assert "exposure" in f.tags


# ---- vuln_hints param semantics ------------------------------------------
def test_vuln_hints_ignores_oauth_and_utm():
    from voidrecon.modules.vuln.vuln_hints import VulnHints

    ctx = _ctx()
    # OAuth return URL + analytics — must NOT become RCE/SSRF/SQLi candidates
    ctx.store.add_asset(Asset(AssetKind.URL, "https://example.com/oauth2/return?code=abc&state=xyz"))
    ctx.store.add_asset(Asset(AssetKind.URL, "https://example.com/?utm_source=x&utm_medium=y"))
    asyncio.run(VulnHints().run(ctx))
    hint_findings = [f for f in ctx.store.findings() if "candidate endpoint" in f.title]
    assert hint_findings == []
    for a in ctx.store.assets(kind=AssetKind.URL):
        assert not a.attrs.get("vuln_hints")


def test_vuln_hints_still_flags_real_sink():
    from voidrecon.modules.vuln.vuln_hints import VulnHints

    ctx = _ctx()
    ctx.store.add_asset(Asset(AssetKind.URL, "https://example.com/page?redirect=/next&file=x"))
    asyncio.run(VulnHints().run(ctx))
    # at least one real candidate class should be produced, all capped at LOW
    hint_findings = [f for f in ctx.store.findings() if "candidate endpoint" in f.title]
    assert hint_findings
    assert all(f.severity == Severity.LOW for f in hint_findings)


# ---- advisor: don't recommend completed work ------------------------------
def test_next_steps_skips_completed_modules():
    from voidrecon.intel import advisor

    ctx = _ctx()
    ctx.store.add_finding(Finding("takeover", severity=Severity.HIGH, module="correlate",
                                  asset="x.example.com", tags={"takeover"}))
    ctx.store.add_asset(Asset(AssetKind.SUBDOMAIN, "x.example.com"))
    setattr(ctx.store, "completed_modules", {"takeover_verify", "dns_resolve"})
    recs = advisor.recommend(ctx)
    for r in recs:
        assert "takeover_verify" not in (r.get("command") or "")


# ---- report: findings grouped + capped by severity ------------------------
def test_report_caps_info_findings(tmp_path):
    from voidrecon.reporting.report import Reporter

    cfg = Config.load(overrides={"general": {"output_dir": str(tmp_path)}})
    ctx = RunContext(cfg, Scope.from_lists(["example.com"]))
    ctx.output_dir = tmp_path / "run"
    for i in range(200):
        ctx.store.add_finding(Finding(f"info finding {i}", severity=Severity.INFO,
                                      module="m", asset=f"h{i}.example.com"))
    md = Reporter(ctx, {}).render_markdown()
    assert "INFO (200)" in md                       # group header shows true total
    assert "more info finding(s) in `voidrecon.json`" in md  # long tail capped
    html = Reporter(ctx, {}).render_html()
    assert "sevgroup" in html and "omitted here" in html


# ---- SQLi: static paths + boolean stability -------------------------------
def test_sqli_skips_static_and_keeps_app_paths():
    from voidrecon.modules.vuln.sqli_probe import SqliProbe

    ctx = _ctx(active=True)
    ctx.store.add_asset(Asset(AssetKind.URL,
                              "https://example.com/static-assets/_next/data/ABC/docs/c.json?slug=x"))
    ctx.store.add_asset(Asset(AssetKind.URL,
                              "https://example.com/dashboard/add-connection?serviceId=5"))
    urls = [u for u, _, _ in SqliProbe()._targets(ctx)]
    assert any("add-connection" in u for u in urls)
    assert not any("_next" in u for u in urls)     # the embarrassing FP source is gone


def test_sqli_boolean_ignores_nondeterministic_endpoint():
    import itertools

    from voidrecon.modules.vuln.sqli_probe import SqliProbe

    ctx = _ctx(active=True)
    client = ctx.http
    counter = itertools.count()

    class _R:
        def __init__(self, n):
            self.content = b"x" * n
            self.text = ""
            self.status_code = 200

    async def fake_get(url, **kw):
        # identical requests return different lengths — SPA rehydration noise
        return _R(1000 + (next(counter) * 613) % 3000)

    client.get = fake_get
    fired = asyncio.run(SqliProbe()._probe(ctx, "https://example.com/x?id=1", "id", "1"))
    assert fired is False    # a wobbling endpoint must not read as boolean SQLi


def test_sqli_boolean_detects_stable_reproducible_differential():
    from urllib.parse import parse_qs, urlparse

    from voidrecon.modules.vuln.sqli_probe import SqliProbe

    ctx = _ctx(active=True)
    client = ctx.http

    class _R:
        def __init__(self, n):
            self.content = b"x" * n
            self.text = ""
            self.status_code = 200

    async def fake_get(url, **kw):
        v = parse_qs(urlparse(url).query).get("id", [""])[0]
        if "1=2" in v:            # always-false → clearly shorter, reproducibly
            return _R(1000)
        return _R(5000)           # baseline, quote, and always-true → full page

    client.get = fake_get
    fired = asyncio.run(SqliProbe()._probe(ctx, "https://example.com/x?id=1", "id", "1"))
    assert fired is True


# ---- third-party scope leak (OAuth redirect chain) ------------------------
def _scoped(seed="fivetran.com"):
    return RunContext(Config.load(), Scope.from_lists([seed]))


def test_is_target_host_rejects_off_domain():
    ctx = _scoped()
    assert ctx.is_target_host("api.fivetran.com")
    assert ctx.is_target_host("fivetran.com")
    assert not ctx.is_target_host("accounts.google.com")   # OAuth redirect target
    assert ctx.is_target_url("https://accounts.google.com/.well-known/openid-configuration") is False


def test_finding_on_off_domain_host_is_labeled_third_party():
    ctx = _scoped()
    f = ctx.add_finding("Exposed API specification: x", module="api_discovery",
                        asset="accounts.google.com")
    assert "third-party" in f.tags
    # an in-scope host is not labeled
    g = ctx.add_finding("real one", module="api_discovery", asset="api.fivetran.com")
    assert "third-party" not in g.tags


def test_intentional_offdomain_findings_not_relabeled():
    ctx = _scoped()
    # a scope-expansion lead is *meant* to name an external host — leave it alone
    f = ctx.add_finding("expansion lead", module="correlate", asset="acquired-co.com",
                        tags={"scope-expansion"})
    assert "third-party" not in f.tags


def test_analyst_excludes_off_domain_finding_host():
    from voidrecon.core.models import Finding
    from voidrecon.intel import analyst, scoring

    ctx = _scoped()
    ctx.store.add_finding(Finding("Exposed API specification",
                                  severity=Severity.MEDIUM, module="api_discovery",
                                  asset="accounts.google.com", tags={"third-party", "api"}))
    scoring.score_store(ctx.store)
    plan = analyst.analyze(ctx)
    assert all("google.com" not in t["asset"] for t in plan["targets"])


# ---- analyst: out-of-scope host never headlines a play --------------------
def test_analyst_excludes_out_of_scope():
    from voidrecon.core.models import ScopeState
    from voidrecon.intel import analyst, scoring

    ctx = _ctx()
    oos = Asset(AssetKind.SUBDOMAIN, "vendor.notours.com", scope_state=ScopeState.OUT_OF_SCOPE,
                attrs={"http_status": 401, "secrets_found": True})
    ctx.store.add_asset(oos)
    ctx.store.add_finding(Finding("leak", severity=Severity.HIGH, module="m",
                                  asset="vendor.notours.com", tags={"secret"}))
    scoring.score_store(ctx.store)
    plan = analyst.analyze(ctx)
    assert all(t["asset"] != "vendor.notours.com" for t in plan["targets"])
