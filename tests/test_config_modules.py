from voidrecon.core.config import Config
from voidrecon.core.module import registry
from voidrecon.core.pipeline import load_all_modules


def test_config_defaults_and_dotted_get():
    cfg = Config.load()
    assert cfg.get("opsec.allow_active") is False
    assert cfg.get("general.output_dir") == "runs"
    assert cfg.get("nonexistent.key", "fallback") == "fallback"


def test_config_env_override(monkeypatch):
    monkeypatch.setenv("VOIDRECON_OPSEC_REQUESTS_PER_SECOND", "3.5")
    cfg = Config.load()
    assert cfg.get("opsec.requests_per_second") == 3.5


def test_config_overrides_merge():
    cfg = Config.load(overrides={"opsec": {"allow_active": True}})
    assert cfg.get("opsec.allow_active") is True


def test_all_modules_register_and_have_unique_names():
    load_all_modules()
    mods = registry.all()
    names = [m.name for m in mods]
    assert len(names) == len(set(names))
    assert "crtsh" in names
    assert "intelligence" in names


def _ctx(cfg):
    from voidrecon.core.context import RunContext
    from voidrecon.core.scope import Scope

    return RunContext(cfg, Scope.from_lists(["example.com"]))


def test_active_modules_gated_off_by_default():
    load_all_modules()
    ctx = _ctx(Config.load())
    active_mods = [m() for m in registry.all() if m.active]
    assert active_mods, "expected some active modules"
    assert all(not m.should_run(ctx) for m in active_mods)


def test_optin_module_does_not_run_in_plain_active_mode():
    load_all_modules()
    ctx = _ctx(Config.load(overrides={"opsec": {"allow_active": True}}))
    port_scan = registry.get("port_scan")()
    http_probe = registry.get("http_probe")()
    assert not port_scan.should_run(ctx)      # opt-in, not explicitly enabled
    assert http_probe.should_run(ctx)         # active but on by default


def test_optin_module_runs_when_explicitly_enabled():
    load_all_modules()
    ctx = _ctx(Config.load(overrides={
        "opsec": {"allow_active": True},
        "modules": {"enabled": ["port_scan"]},
    }))
    assert registry.get("port_scan")().should_run(ctx)


def test_aggressive_wildcard_enables_all_optin():
    load_all_modules()
    ctx = _ctx(Config.load(overrides={
        "opsec": {"allow_active": True, "aggressive": True},
        "modules": {"enabled": ["*"]},
    }))
    optin_active = [m() for m in registry.all() if m.active and not m.enabled_by_default]
    assert optin_active, "expected some opt-in active modules"
    assert all(m.should_run(ctx) for m in optin_active)


def test_disabled_beats_enabled():
    load_all_modules()
    ctx = _ctx(Config.load(overrides={
        "opsec": {"allow_active": True},
        "modules": {"enabled": ["*"], "disabled": ["port_scan"]},
    }))
    assert not registry.get("port_scan")().should_run(ctx)
