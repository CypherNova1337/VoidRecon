"""The Analyst — per-host reasoning, multi-signal attack chains, finding-aware
scoring. These lock in the behaviour that makes the built-in AI 'smart': it must
fuse a host's signals with the findings on it and surface chains that only exist
when several signals co-occur."""

from __future__ import annotations

from voidrecon.core.config import Config
from voidrecon.core.context import RunContext
from voidrecon.core.models import Asset, AssetKind, Finding, Severity
from voidrecon.core.scope import Scope
from voidrecon.intel import analyst, scoring


def _ctx():
    return RunContext(Config.load(), Scope.from_lists(["example.com"]))


def test_findings_lift_asset_score_above_name_hunch():
    ctx = _ctx()
    # a host that merely *looks* juicy by name
    ctx.store.add_asset(Asset(AssetKind.SUBDOMAIN, "admin.example.com"))
    # a plain host, but with a real HIGH finding on it
    ctx.store.add_asset(Asset(AssetKind.SUBDOMAIN, "www.example.com"))
    ctx.store.add_finding(Finding("SQLi", severity=Severity.HIGH, module="m",
                                  asset="www.example.com", tags={"sqli"}))
    scoring.score_store(ctx.store)
    admin = ctx.store.get_asset(AssetKind.SUBDOMAIN, "admin.example.com")
    www = ctx.store.get_asset(AssetKind.SUBDOMAIN, "www.example.com")
    # evidence (a landed finding) must outrank a name-based hunch
    assert www.score > admin.score


def test_multisignal_chain_requires_cooccurrence():
    ctx = _ctx()
    # secret + auth-gate on the SAME host => the credential-to-access chain
    ctx.store.add_asset(Asset(AssetKind.SUBDOMAIN, "api.example.com",
                              attrs={"http_status": 401, "secrets_found": True}))
    ctx.store.add_finding(Finding("leaked key", severity=Severity.HIGH, module="m",
                                  asset="api.example.com", tags={"secret"}))
    scoring.score_store(ctx.store)
    plan = analyst.analyze(ctx)
    names = {p["name"] for p in plan["plays"]}
    assert "Leaked credential → authenticated access" in names


def test_chain_absent_when_signals_split_across_hosts():
    ctx = _ctx()
    # secret on one host, auth-gate on another => the chain must NOT fire
    ctx.store.add_asset(Asset(AssetKind.SUBDOMAIN, "a.example.com",
                              attrs={"secrets_found": True}))
    ctx.store.add_asset(Asset(AssetKind.SUBDOMAIN, "b.example.com",
                              attrs={"http_status": 401}))
    ctx.store.add_finding(Finding("leak", severity=Severity.LOW, module="m",
                                  asset="a.example.com", tags={"secret"}))
    scoring.score_store(ctx.store)
    plan = analyst.analyze(ctx)
    names = {p["name"] for p in plan["plays"]}
    assert "Leaked credential → authenticated access" not in names


def test_sqli_chain_emits_runnable_command():
    ctx = _ctx()
    ctx.store.add_asset(Asset(AssetKind.SUBDOMAIN, "admin.example.com",
                              attrs={"http_status": 403}))
    ctx.store.add_finding(Finding("SQLi in id", severity=Severity.HIGH, module="m",
                                  asset="admin.example.com", tags={"sqli"},
                                  evidence={"url": "https://admin.example.com/x?id=1"}))
    scoring.score_store(ctx.store)
    plan = analyst.analyze(ctx)
    cmds = [p["command"] for p in plan["plays"] if p.get("command")]
    assert any("sqlmap" in c and "id=1" in c for c in cmds)


def test_finding_only_host_is_still_reasoned():
    # a host named only by a finding (no discovery module recorded it) must still
    # appear as a target — findings are evidence, not noise to drop
    ctx = _ctx()
    ctx.store.add_finding(Finding("takeover: ghost.example.com -> S3", severity=Severity.HIGH,
                                  module="correlate", asset="ghost.example.com", tags={"takeover"}))
    scoring.score_store(ctx.store)
    plan = analyst.analyze(ctx)
    assert any(t["asset"] == "ghost.example.com" for t in plan["targets"])
    assert "ghost.example.com" in plan["focus"]


def test_dossier_brief_is_grounded():
    ctx = _ctx()
    ctx.store.add_asset(Asset(AssetKind.SUBDOMAIN, "api.example.com",
                              attrs={"http_status": 401, "http_title": "Internal API"}))
    ctx.store.add_finding(Finding("SQLi", severity=Severity.HIGH, module="m",
                                  asset="api.example.com", tags={"sqli"}))
    scoring.score_store(ctx.store)
    plan = analyst.analyze(ctx)
    top = next(t for t in plan["targets"] if t["asset"] == "api.example.com")
    assert "api.example.com" in top["brief"]
    assert "auth gate" in top["brief"].lower()
    assert top["findings"] and top["findings"][0]["severity"] == "high"
