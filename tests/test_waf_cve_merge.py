from voidrecon.modules.content.waf_detect import detect_waf
from voidrecon.modules.vuln.cve_match import merge_signatures


def test_detect_waf_by_header():
    assert "Cloudflare" in detect_waf({"CF-RAY": "abc", "Server": "cloudflare"}, [])
    assert "Sucuri" in detect_waf({"X-Sucuri-ID": "1"}, [])


def test_detect_waf_by_cookie():
    assert "Imperva/Incapsula" in detect_waf({}, ["visid_incap_123=abc; path=/"])
    assert "F5 BIG-IP" in detect_waf({}, ["BIGipServerpool=xyz"])


def test_detect_waf_none():
    assert detect_waf({"Server": "nginx"}, ["session=1"]) == []


def test_merge_signatures_new_product_appended():
    base = [{"product": "apache", "match": ["apache"], "cves": [{"id": "CVE-1"}]}]
    extra = [{"product": "nginx", "match": ["nginx"], "cves": [{"id": "CVE-2"}]}]
    merged = merge_signatures(base, extra)
    products = {s["product"] for s in merged}
    assert products == {"apache", "nginx"}


def test_merge_signatures_extends_existing_and_overrides_cve():
    base = [{"product": "apache", "match": ["apache"], "cves": [{"id": "CVE-1", "severity": "low"}]}]
    extra = [{"product": "apache", "match": ["httpd"],
              "cves": [{"id": "CVE-1", "severity": "critical"}, {"id": "CVE-9"}]}]
    merged = merge_signatures(base, extra)
    apache = next(s for s in merged if s["product"] == "apache")
    assert set(apache["match"]) == {"apache", "httpd"}
    ids = {c["id"]: c for c in apache["cves"]}
    assert ids["CVE-1"]["severity"] == "critical"   # extra wins
    assert "CVE-9" in ids
