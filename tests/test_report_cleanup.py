from voidrecon.core.config import Config
from voidrecon.core.context import RunContext
from voidrecon.core.models import Finding, Severity
from voidrecon.core.scope import Scope
from voidrecon.reporting.report import Reporter
from voidrecon.utils.text import short_url


def test_short_url_collapses_giant_query():
    u = "https://backend.accounts.hytale.com/self-service/login/browser?login_challenge=" + "x" * 500
    s = short_url(u)
    assert s.startswith("https://backend.accounts.hytale.com/self-service/login/browser?login_challenge=")
    assert len(s) <= 82
    assert "xxxxxxxxxx" not in s  # the giant token is collapsed


def test_short_url_no_query():
    assert short_url("https://a.example.com/path") == "https://a.example.com/path"


def test_report_deduplicates_where_to_test_and_refs(tmp_path):
    cfg = Config.load(overrides={"general": {"output_dir": str(tmp_path)}})
    ctx = RunContext(cfg, Scope.from_lists(["example.com"]))
    ctx.output_dir = tmp_path / "run"
    url = "https://github.com/x/y/blob/abc/config"
    ctx.store.add_finding(Finding(
        "GitHub — matched", severity=Severity.MEDIUM, module="github_dork", asset="example.com",
        evidence={"url": url, "urls": [url]}, references=[url], tags={"github"},
    ))
    reporter = Reporter(ctx, summary={"elapsed": 1.0})
    md = reporter.render_markdown()
    # The URL appears under "Where to test" but NOT again as a separate "Refs" line.
    assert "Where to test" in md
    assert "Refs:" not in md
    html = reporter.render_html()
    # exactly one anchor for that URL in the finding block
    assert html.count(f'href="{url}"') == 1


def test_report_short_title_in_findings(tmp_path):
    cfg = Config.load(overrides={"general": {"output_dir": str(tmp_path)}})
    ctx = RunContext(cfg, Scope.from_lists(["example.com"]))
    ctx.output_dir = tmp_path / "run"
    ctx.store.add_finding(Finding("SQL injection candidate in 'q' — https://a.example.com/s?q=…",
                                  severity=Severity.HIGH, module="sqli_probe", asset="a.example.com"))
    md = Reporter(ctx, {}).render_markdown()
    assert "SQL injection candidate in 'q'" in md
