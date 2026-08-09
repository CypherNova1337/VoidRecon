from voidrecon.modules.passive.dns_records import analyze_dmarc, analyze_spf
from voidrecon.utils.permute import permute_from_known, wordlist_candidates


def test_wordlist_candidates():
    out = wordlist_candidates("example.com", ["www", "api", "# comment", ""])
    assert "www.example.com" in out
    assert "api.example.com" in out
    assert len(out) == 2


def test_permute_from_known_generates_variants():
    out = permute_from_known(["api.example.com"], "example.com", ["dev", "staging"])
    assert "api-dev.example.com" in out
    assert "dev-api.example.com" in out
    assert "api1.example.com" in out
    assert "dev.api.example.com" in out
    assert all(c.endswith("example.com") for c in out)


def test_permute_ignores_unrelated_hosts():
    out = permute_from_known(["api.other.com"], "example.com", ["dev"])
    assert out == set()


def test_analyze_spf():
    assert analyze_spf([])[1] is not None                     # missing -> issue
    assert analyze_spf(["v=spf1 -all"])[1] is None            # hardfail -> ok
    _, sev, _ = analyze_spf(["v=spf1 +all"])
    assert sev is not None and sev.value == "high"
    _, sev, _ = analyze_spf(["v=spf1 ?all"])
    assert sev.value == "medium"


def test_analyze_dmarc():
    assert analyze_dmarc([])[1] is not None                   # missing
    assert analyze_dmarc(["v=DMARC1; p=reject"])[1] is None   # strong
    _, sev, _ = analyze_dmarc(["v=DMARC1; p=none"])
    assert sev.value == "low"
