"""Recon visibility: status-aware fetching + per-source health reporting.

These guard the fix for the 'sections silently come back zero' problem — a
rate-limit / block / timeout must be distinguishable from a genuinely empty
result, both in the datastore and in the rendered report.
"""

from __future__ import annotations

import pytest

from voidrecon.core.config import Config
from voidrecon.core.context import RunContext
from voidrecon.core.http import HttpClient, Outcome, _parse_retry_after
from voidrecon.core.scope import Scope
from voidrecon.reporting.report import Reporter


class _Resp:
    def __init__(self, status_code, *, payload=None, text="", headers=None):
        self.status_code = status_code
        self._payload = payload
        self.text = text
        self.headers = headers or {}

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


def _client_returning(*responses):
    """An HttpClient whose request() yields the given responses in order."""
    client = HttpClient(user_agent="test", retries=0)
    seq = list(responses)

    async def fake_request(method, url, **kwargs):
        return seq.pop(0) if seq else _Resp(200, payload=[])

    client.request = fake_request  # type: ignore[assignment]
    return client


@pytest.mark.asyncio
async def test_fetch_classifies_statuses():
    c = _client_returning(_Resp(200, payload=["a.example.com"]))
    o = await c.fetch("https://x")
    assert o.status == "ok" and o.json == ["a.example.com"]

    c = _client_returning(_Resp(200, payload=[]))
    assert (await c.fetch("https://x")).status == "empty"

    c = _client_returning(_Resp(403))
    assert (await c.fetch("https://x")).status == "forbidden"

    c = _client_returning(_Resp(404))
    assert (await c.fetch("https://x")).status == "not_found"

    c = _client_returning(_Resp(500))
    o = await c.fetch("https://x")
    assert o.status == "server_error" and o.failed

    # request() returning None (timeout/transport failure after its own retries)
    c = _client_returning(None)
    assert (await c.fetch("https://x")).status == "unreachable"


@pytest.mark.asyncio
async def test_fetch_retries_then_recovers_on_429():
    # first a 429, then a good page — the retry must win, not give up
    c = _client_returning(_Resp(429, headers={"Retry-After": "0"}),
                          _Resp(200, payload=["ok.example.com"]))
    o = await c.fetch("https://x", retry_on_429=2)
    assert o.status == "ok"


@pytest.mark.asyncio
async def test_fetch_gives_up_after_429_budget():
    c = _client_returning(_Resp(429, headers={"Retry-After": "0"}),
                          _Resp(429, headers={"Retry-After": "0"}))
    o = await c.fetch("https://x", retry_on_429=1)
    assert o.status == "rate_limited" and o.failed


def test_parse_retry_after():
    assert _parse_retry_after("5") == 5.0
    assert _parse_retry_after(None) is None
    assert _parse_retry_after("Wed, 21 Oct 2099 07:28:00 GMT") is None  # http-date unsupported


def test_note_source_downgrades_ok_zero_to_empty(tmp_path):
    cfg = Config.load(overrides={"general": {"output_dir": str(tmp_path)}})
    ctx = RunContext(cfg, Scope.from_lists(["example.com"]))
    ctx.note_source("otx", "example.com", Outcome("ok", 200, json=[]), count=0)
    ctx.note_source("crt.sh", "example.com", Outcome("ok", 200), count=12)
    ctx.note_source("hackertarget", "example.com", Outcome("rate_limited", 429), count=0)
    ctx.note_no_key("virustotal", "example.com")
    rows = ctx.store.source_health()
    by = {r["source"]: r for r in rows}
    assert by["otx"]["status"] == "empty"          # reached, nothing there
    assert by["crt.sh"]["status"] == "ok" and by["crt.sh"]["count"] == 12
    assert by["hackertarget"]["status"] == "rate_limited"
    assert by["virustotal"]["status"] == "no_key"


def test_report_shows_coverage_and_flags_failures(tmp_path):
    cfg = Config.load(overrides={"general": {"output_dir": str(tmp_path)}})
    ctx = RunContext(cfg, Scope.from_lists(["example.com"]))
    ctx.output_dir = tmp_path / "run"
    ctx.note_source("crt.sh", "example.com", Outcome("ok", 200), count=40)
    ctx.note_source("hackertarget", "example.com", Outcome("rate_limited", 429), count=0)
    reporter = Reporter(ctx, {})

    agg = {r["source"]: r for r in reporter._source_health()}
    assert agg["crt.sh"]["status"] == "ok"
    assert agg["hackertarget"]["status"] == "rate_limited"

    md = reporter.render_markdown()
    assert "Recon coverage" in md
    assert "RATE-LIMITED" in md
    assert "did not return data" in md  # the warning banner fires

    html = reporter.render_html()
    assert "Recon coverage" in html
    assert "cov-warn" in html


def test_report_no_coverage_section_when_empty(tmp_path):
    cfg = Config.load(overrides={"general": {"output_dir": str(tmp_path)}})
    ctx = RunContext(cfg, Scope.from_lists(["example.com"]))
    ctx.output_dir = tmp_path / "run"
    reporter = Reporter(ctx, {})
    assert reporter._source_health() == []
    assert "Recon coverage" not in reporter.render_markdown()
