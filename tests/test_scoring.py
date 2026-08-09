from voidrecon.core.models import Asset, AssetKind, ScopeState
from voidrecon.intel.scoring import score_asset


def test_juicy_keywords_raise_score():
    plain = Asset(AssetKind.SUBDOMAIN, "www.example.com")
    admin = Asset(AssetKind.SUBDOMAIN, "admin.example.com")
    assert score_asset(admin)[0] > score_asset(plain)[0]


def test_takeover_candidate_scores_high():
    a = Asset(AssetKind.SUBDOMAIN, "old.example.com", attrs={"takeover_candidate": True})
    score, reasons = score_asset(a)
    assert score >= 30
    assert any("takeover" in r for r in reasons)


def test_risky_ports_add_score():
    a = Asset(AssetKind.IP, "1.2.3.4", attrs={"open_ports": [6379, 3306]})
    score, reasons = score_asset(a)
    assert score > 0
    assert any("risky_ports" in r for r in reasons)


def test_out_of_scope_is_discounted():
    a = Asset(AssetKind.SUBDOMAIN, "admin.example.com", scope_state=ScopeState.OUT_OF_SCOPE)
    b = Asset(AssetKind.SUBDOMAIN, "admin.example.com", scope_state=ScopeState.IN_SCOPE)
    assert score_asset(a)[0] < score_asset(b)[0]


def test_score_capped_at_100():
    a = Asset(
        AssetKind.SUBDOMAIN,
        "admin.internal.vault.secret.dev.example.com",
        attrs={"takeover_candidate": True, "open_ports": [6379, 3306, 9200], "secrets_found": True},
    )
    assert score_asset(a)[0] <= 100.0
