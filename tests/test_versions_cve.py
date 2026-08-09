from voidrecon.core.models import Asset, AssetKind
from voidrecon.modules.vuln.cve_match import CveMatch
from voidrecon.utils.versions import in_range, parse_version


def test_parse_version():
    assert parse_version("2.4.49 (Ubuntu)") == ([2, 4, 49], "")
    assert parse_version("v1.0.1f") == ([1, 0, 1], "f")
    assert parse_version("nope") is None


def test_in_range_inclusive():
    assert in_range("2.4.49", "2.4.49", "2.4.50")
    assert in_range("2.4.50", "2.4.49", "2.4.50")
    assert not in_range("2.4.51", "2.4.49", "2.4.50")
    assert not in_range("2.4.48", "2.4.49", "2.4.50")


def test_in_range_open_ended():
    assert in_range("1.17.6", None, "1.17.6")      # max only
    assert not in_range("1.20.0", None, "1.17.6")
    assert in_range("9.0.0", "8.0.0", None)        # min only


def test_in_range_letter_suffix():
    assert in_range("1.0.1e", "1.0.1", "1.0.1f")
    assert not in_range("1.0.1g", "1.0.1", "1.0.1f")


def test_cve_extract_pairs_from_server_and_headers():
    mod = CveMatch()
    asset = Asset(
        AssetKind.SUBDOMAIN, "web.example.com",
        attrs={
            "http_server": "Apache/2.4.49 (Ubuntu)",
            "technologies": ["PHP/7.4.3"],
            "fp_headers": {"x-jenkins": "2.440", "x-powered-by": "PHP/7.4.3"},
        },
    )
    pairs = mod._extract_pairs(asset)
    products = {name: ver for name, ver in pairs}
    assert any("apache" in n for n in products)
    assert ("jenkins", "2.440") in pairs
    assert any("php" in n for n in products)
