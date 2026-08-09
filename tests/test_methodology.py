from voidrecon.modules.content.csp_mining import (
    extract_hosts_from_csp,
    extract_hosts_from_headers,
)
from voidrecon.modules.content.http_methods import parse_allow
from voidrecon.modules.passive.dns_advanced import parse_spf_mechanisms
from voidrecon.modules.passive.whois_rdap import parse_rdap
from voidrecon.modules.vuln.takeover_verify import match_takeover


def test_parse_spf_mechanisms():
    spf = "v=spf1 include:_spf.google.com a:mail.example.com ip4:203.0.113.0/24 ~all"
    m = parse_spf_mechanisms(spf)
    assert "_spf.google.com" in m["includes"]
    assert "mail.example.com" in m["hosts"]
    assert "203.0.113.0/24" in m["ips"]


def test_parse_rdap():
    data = {
        "status": ["client transfer prohibited"],
        "events": [{"eventAction": "registration", "eventDate": "2010-01-01"},
                   {"eventAction": "expiration", "eventDate": "2030-01-01"}],
        "entities": [
            {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Acme Registrar"]]]},
            {"roles": ["registrant"], "vcardArray": ["vcard", [["org", {}, "text", "Example Inc"]]]},
        ],
        "nameservers": [{"ldhName": "NS1.EXAMPLE.COM."}, {"ldhName": "ns2.example.com"}],
    }
    info = parse_rdap(data)
    assert info["registrar"] == "Acme Registrar"
    assert info["registrant"] == "Example Inc"
    assert info["created"] == "2010-01-01"
    assert "ns1.example.com" in info["nameservers"]


def test_match_takeover():
    assert match_takeover("foo.s3.amazonaws.com", "<Error>NoSuchBucket</Error>") == "AWS S3"
    assert match_takeover("x.herokuapp.com", "No such app") == "Heroku"
    assert match_takeover("x.github.io", "There isn't a GitHub Pages site here") == "GitHub Pages"
    assert match_takeover("x.s3.amazonaws.com", "totally normal page") is None
    assert match_takeover("", "") is None


def test_extract_hosts_from_csp():
    csp = "default-src 'self'; script-src https://cdn.example.com https://api.thirdparty.io; connect-src *.internal.example.com"
    hosts = extract_hosts_from_csp(csp)
    assert "cdn.example.com" in hosts
    assert "api.thirdparty.io" in hosts
    assert "internal.example.com" in hosts


def test_extract_hosts_from_headers():
    headers = {"Access-Control-Allow-Origin": "https://app.example.com",
               "Report-To": '{"endpoints":[{"url":"https://o.reports.example.net/x"}]}'}
    hosts = extract_hosts_from_headers(headers)
    assert "app.example.com" in hosts
    assert "o.reports.example.net" in hosts


def test_parse_allow():
    assert parse_allow("GET, POST, PUT, DELETE") == {"GET", "POST", "PUT", "DELETE"}
    assert parse_allow("") == set()
