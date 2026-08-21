from voidrecon.core.config import Config
from voidrecon.core.context import RunContext
from voidrecon.core.models import Asset, AssetKind, Finding, Severity
from voidrecon.core.scope import Scope
from voidrecon.intel import advisor
from voidrecon.utils.versions import is_newer


def test_is_newer():
    assert is_newer("0.2.0", "0.1.0")
    assert is_newer("0.1.1", "0.1.0")
    assert not is_newer("0.1.0", "0.1.0")
    assert not is_newer("0.1.0", "0.2.0")
    assert not is_newer("garbage", "0.1.0")


def test_advisor_summary_no_findings():
    ctx = RunContext(Config.load(), Scope.from_lists(["example.com"]))
    ctx.store.add_asset(Asset(AssetKind.SUBDOMAIN, "www.example.com", score=5))
    text = advisor.summarize(ctx)
    assert "example.com" in text
    assert isinstance(text, str) and len(text) > 10


def test_advisor_summary_surfaces_play():
    ctx = RunContext(Config.load(), Scope.from_lists(["example.com"]))
    ctx.store.add_finding(Finding("takeover", severity=Severity.HIGH, module="m",
                                  asset="x.example.com", tags={"takeover"}))
    ctx.store.add_finding(Finding("gql", severity=Severity.MEDIUM, module="m",
                                  asset="api.example.com", tags={"introspection"}))
    text = advisor.summarize(ctx)
    # The Analyst reasons the takeover chain even though no discovery module
    # recorded x.example.com as an asset — findings are evidence enough.
    assert "highest-value play" in text.lower()
    assert "x.example.com" in text


def test_notify_telegram_config_present():
    cfg = Config.load()
    # keys exist in the schema so setup/env can populate them
    assert "telegram_token" in cfg.section("notify")
    assert "telegram_chat_id" in cfg.section("notify")


def test_user_config_merges(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    cfgdir = tmp_path / "voidrecon"
    cfgdir.mkdir(parents=True)
    (cfgdir / "config.yaml").write_text("sources:\n  shodan_api_key: from-user-config\n")
    cfg = Config.load()
    assert cfg.get("sources.shodan_api_key") == "from-user-config"
