"""Authenticated-session material reaches modules — including the few that run
their own HTTP client (open_redirect, vhost) instead of the shared one."""

from __future__ import annotations

from voidrecon.cli import _config_overrides, _run_namespace
from voidrecon.core.config import Config
from voidrecon.core.context import RunContext
from voidrecon.core.scope import Scope


def test_cli_flags_populate_auth_config():
    ns = _run_namespace(targets=["x.com"], header=["X-Api-Key: secret"],
                        cookie=["session=abc"], bearer="tok")
    ov = _config_overrides(ns)
    assert ov["auth"]["headers"] == {"X-Api-Key": "secret", "Authorization": "Bearer tok"}
    assert ov["auth"]["cookies"] == {"session": "abc"}


def test_auth_client_kwargs_carries_session():
    cfg = Config.load(overrides={"auth": {"headers": {"Authorization": "Bearer x"},
                                          "cookies": {"session": "abc"}}})
    ctx = RunContext(cfg, Scope.from_lists(["x.com"]))
    kw = ctx.auth_client_kwargs()
    assert kw == {"headers": {"Authorization": "Bearer x"}, "cookies": {"session": "abc"}}


def test_auth_client_kwargs_empty_without_session():
    ctx = RunContext(Config.load(), Scope.from_lists(["x.com"]))
    assert ctx.auth_client_kwargs() == {}
