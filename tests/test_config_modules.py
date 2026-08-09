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


def test_active_modules_gated_off_by_default():
    load_all_modules()
    cfg = Config.load()
    from voidrecon.core.scope import Scope
    from voidrecon.core.context import RunContext

    ctx = RunContext(cfg, Scope.from_lists(["example.com"]))
    active_mods = [m() for m in registry.all() if m.active]
    assert active_mods, "expected some active modules"
    assert all(not m.should_run(ctx) for m in active_mods)
