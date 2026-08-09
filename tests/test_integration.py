"""Offline end-to-end test of the core pipeline: store -> intel -> report -> db.

No network is used. It exercises scoring, correlation, reporting (all formats),
SQLite persistence, and the dashboard builder against a hand-built datastore.
"""

from voidrecon.core import db
from voidrecon.core.config import Config
from voidrecon.core.context import RunContext
from voidrecon.core.models import Asset, AssetKind, Confidence
from voidrecon.core.scope import Scope
from voidrecon.intel import correlate as correlate_mod
from voidrecon.intel import scoring
from voidrecon.reporting.report import Reporter


def _ctx(tmp_path):
    cfg = Config.load(overrides={
        "opsec": {"allow_active": True},
        "auth": {"headers": {"Authorization": "Bearer test"}},
        "general": {"output_dir": str(tmp_path)},
    })
    ctx = RunContext(cfg, Scope.from_lists(["example.com"]))
    ctx.output_dir = tmp_path / "run"
    return ctx


def _seed_store(ctx):
    # A juicy dev/admin host, live.
    ctx.store.add_asset(Asset(AssetKind.SUBDOMAIN, "admin.dev.example.com",
                              sources={"crtsh"}, attrs={"resolved_ips": ["10.0.0.1"]},
                              confidence=Confidence.CONFIRMED))
    # Five hosts sharing an IP -> cluster finding.
    for i in range(5):
        ctx.store.add_asset(Asset(AssetKind.SUBDOMAIN, f"h{i}.example.com",
                                  sources={"passive_subs"}, attrs={"resolved_ips": ["203.0.113.9"]}))
    # A dangling CNAME -> takeover candidate.
    ctx.store.add_asset(Asset(AssetKind.SUBDOMAIN, "old.example.com",
                              sources={"passive_subs"}, attrs={"cname": "bucket.s3.amazonaws.com"}))


def test_scoring_and_correlation(tmp_path):
    ctx = _ctx(tmp_path)
    _seed_store(ctx)
    scoring.score_store(ctx.store)
    correlate_mod.correlate(ctx)
    scoring.score_store(ctx.store)

    admin = ctx.store.get_asset(AssetKind.SUBDOMAIN, "admin.dev.example.com")
    assert admin.score > 0
    titles = [f.title for f in ctx.store.findings()]
    assert any("share IP" in t for t in titles)          # cluster
    assert any("takeover" in t.lower() for t in titles)  # dangling CNAME


def test_reporting_all_formats(tmp_path):
    ctx = _ctx(tmp_path)
    _seed_store(ctx)
    scoring.score_store(ctx.store)
    reporter = Reporter(ctx, summary={"elapsed": 1.0})
    written = reporter.write_all(["json", "markdown", "html"])
    assert set(written) == {"json", "markdown", "html"}
    for path in written.values():
        assert path.exists() and path.stat().st_size > 0
    html = written["html"].read_text()
    assert "VoidRecon" in html and "admin.dev.example.com" in html


def test_auth_headers_flow_to_context(tmp_path):
    ctx = _ctx(tmp_path)
    assert ctx.auth_headers.get("Authorization") == "Bearer test"


def test_sqlite_persistence_roundtrip(tmp_path):
    import sqlite3

    ctx = _ctx(tmp_path)
    _seed_store(ctx)
    scoring.score_store(ctx.store)
    dbp = tmp_path / "voidrecon.db"
    assert db.persist_run(dbp, ctx, {"elapsed": 2.0}) is not None
    conn = sqlite3.connect(str(dbp))
    assert conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == len(ctx.store)
    conn.close()


def test_dashboard_builds_from_runs(tmp_path):
    from voidrecon.reporting.dashboard import build_dashboard

    ctx = _ctx(tmp_path)
    _seed_store(ctx)
    scoring.score_store(ctx.store)
    reporter = Reporter(ctx, summary={"elapsed": 1.0})
    reporter.write_all(["json"])
    html = build_dashboard([ctx.output_dir / "voidrecon.json"], "example.com")
    assert "VoidRecon Trends" in html
