from voidrecon.core.config import Config
from voidrecon.core.context import RunContext
from voidrecon.core.models import Asset, AssetKind, Finding, Severity
from voidrecon.core.scope import Scope
from voidrecon.intel import advisor
from voidrecon.modules.vuln.sqli_probe import sql_error


def _ctx():
    return RunContext(Config.load(), Scope.from_lists(["example.com"]))


def test_advisor_prioritises_takeover_over_generic():
    ctx = _ctx()
    ctx.store.add_finding(Finding("takeover!", severity=Severity.HIGH, module="m",
                                  asset="x.example.com", tags={"takeover"}))
    ctx.store.add_finding(Finding("cors", severity=Severity.MEDIUM, module="m",
                                  asset="y.example.com", tags={"cors"}))
    ctx.store.add_asset(Asset(AssetKind.SUBDOMAIN, "x.example.com"))
    recs = advisor.recommend(ctx)
    assert recs
    assert "takeover" in recs[0]["action"].lower()
    # A takeover rec carries a ready-to-run command.
    assert any(r.get("command") for r in recs)


def test_advisor_always_includes_review_step():
    ctx = _ctx()
    ctx.store.add_asset(Asset(AssetKind.SUBDOMAIN, "admin.example.com", score=40))
    recs = advisor.recommend(ctx)
    assert any("highest-scoring" in r["action"] for r in recs)


def test_sql_error_signatures():
    assert sql_error("... You have an error in your SQL syntax; check ...")
    assert sql_error("Warning: pg_query() failed")
    assert sql_error("everything is fine here") is None


def test_profiles_defined():
    from voidrecon.cli import PROFILES, _merge

    assert set(PROFILES) == {"passive", "quick", "standard", "deep", "stealth"}
    assert PROFILES["deep"]["modules"]["enabled"] == ["*"]
    assert PROFILES["passive"]["opsec"]["allow_active"] is False
    # merge: override wins, nested dicts merged.
    merged = _merge({"opsec": {"allow_active": True, "rps": 8}}, {"opsec": {"rps": 2}})
    assert merged["opsec"] == {"allow_active": True, "rps": 2}
