from voidrecon.core.models import Asset, AssetKind, Confidence, Finding, ScopeState, Severity
from voidrecon.core.store import DataStore


def test_asset_key_and_merge():
    a = Asset(AssetKind.SUBDOMAIN, "Dev.Example.com", sources={"crtsh"}, attrs={"resolved_ips": ["1.1.1.1"]})
    b = Asset(AssetKind.SUBDOMAIN, "dev.example.com", sources={"passive_subs"},
              attrs={"resolved_ips": ["2.2.2.2"], "cname": "x"}, confidence=Confidence.CONFIRMED)
    assert a.key == b.key
    a.merge(b)
    assert a.sources == {"crtsh", "passive_subs"}
    assert set(a.attrs["resolved_ips"]) == {"1.1.1.1", "2.2.2.2"}
    assert a.attrs["cname"] == "x"
    assert a.confidence == Confidence.CONFIRMED


def test_store_dedupes_and_counts():
    store = DataStore()
    store.add_asset(Asset(AssetKind.SUBDOMAIN, "a.example.com", sources={"s1"}))
    store.add_asset(Asset(AssetKind.SUBDOMAIN, "a.example.com", sources={"s2"}))
    store.add_asset(Asset(AssetKind.IP, "1.2.3.4", sources={"s1"}))
    assert len(store) == 2
    counts = store.counts()
    assert counts["subdomain"] == 1
    assert counts["ip"] == 1


def test_store_findings_dedupe():
    store = DataStore()
    f1 = Finding("dup", module="m", asset="a.com")
    f2 = Finding("dup", module="m", asset="a.com")
    store.add_finding(f1)
    store.add_finding(f2)
    assert len(store.findings()) == 1


def test_severity_rank_ordering():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.INFO.rank


def test_scope_state_default_unknown():
    a = Asset(AssetKind.SUBDOMAIN, "x.example.com")
    assert a.scope_state == ScopeState.UNKNOWN
