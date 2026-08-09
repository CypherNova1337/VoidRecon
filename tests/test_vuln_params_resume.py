from voidrecon.core.checkpoint import Checkpoint
from voidrecon.core.config import Config
from voidrecon.core.context import RunContext
from voidrecon.core.models import Asset, AssetKind, Finding, Severity
from voidrecon.core.scope import Scope
from voidrecon.modules.content.param_discovery import chunk
from voidrecon.modules.vuln.vuln_hints import classify

_CATS = {
    "sqli": {"severity": "medium", "params": ["id", "select", "query"]},
    "redirect": {"severity": "medium", "params": ["url", "next", "redirect"]},
    "idor": {"severity": "medium", "params": ["user_id", "account_id"]},
}


def test_classify_matches_categories():
    got = classify({"id", "url", "unrelated"}, _CATS)
    assert got["sqli"] == ["id"]
    assert got["redirect"] == ["url"]
    assert "idor" not in got


def test_classify_case_insensitive():
    got = classify({"ID", "Next"}, _CATS)
    assert "sqli" in got and "redirect" in got


def test_chunk():
    assert list(chunk([1, 2, 3, 4, 5], 2)) == [[1, 2], [3, 4], [5]]
    assert list(chunk([], 3)) == []


def _ctx(tmp_path):
    cfg = Config.load(overrides={"general": {"output_dir": str(tmp_path)}})
    ctx = RunContext(cfg, Scope.from_lists(["example.com"]))
    ctx.output_dir = tmp_path / "run"
    return ctx


def test_checkpoint_roundtrip(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.store.add_asset(Asset(AssetKind.SUBDOMAIN, "a.example.com", sources={"crtsh"},
                              attrs={"resolved_ips": ["1.2.3.4"]}))
    ctx.store.add_finding(Finding("something", severity=Severity.HIGH, module="m", asset="a.example.com"))
    cp = Checkpoint(tmp_path / "checkpoint.json")
    cp.save(ctx, {"crtsh", "passive_subs"})

    # Fresh context, restore into it.
    ctx2 = _ctx(tmp_path)
    data = cp.load()
    completed = Checkpoint.restore_store(ctx2, data)
    assert completed == {"crtsh", "passive_subs"}
    assert len(ctx2.store) == 1
    restored = ctx2.store.get_asset(AssetKind.SUBDOMAIN, "a.example.com")
    assert restored is not None and restored.attrs["resolved_ips"] == ["1.2.3.4"]
    assert len(ctx2.store.findings()) == 1


def test_null_monitor_is_safe():
    from voidrecon.reporting.live import NullMonitor

    with NullMonitor() as m:
        m.set_plan([])
        m.start_module("x")
        m.end_module("x", "done", 1.0, 5)
        m.set_totals({"subdomain": 3})
        m.set_phase("passive")
