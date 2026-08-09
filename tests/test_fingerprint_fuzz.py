from voidrecon.modules.content.fuzz import _Baseline
from voidrecon.modules.content.tech_fingerprint import match_fingerprints

_FPS = [
    {"name": "Nginx", "headers": {"server": "nginx"}},
    {"name": "WordPress", "html": ["/wp-content/"], "implies": ["PHP", "MySQL"]},
    {"name": "PHP", "headers": {"x-powered-by": "php"}},
    {"name": "Laravel", "cookies": ["laravel_session"], "implies": ["PHP"]},
    {"name": "jQuery", "html_regex": ["jquery[.-]([0-9.]+)?(?:\\.min)?\\.js"]},
]


def test_fingerprint_header_match():
    got = match_fingerprints(_FPS, {"Server": "nginx/1.18"}, [], "")
    assert "Nginx" in got


def test_fingerprint_html_and_implies():
    got = match_fingerprints(_FPS, {}, [], '<link href="/wp-content/style.css">')
    assert "WordPress" in got
    assert "PHP" in got and "MySQL" in got   # implied


def test_fingerprint_cookie_match():
    got = match_fingerprints(_FPS, {}, ["laravel_session=abc; Path=/"], "")
    assert "Laravel" in got and "PHP" in got


def test_fingerprint_regex_match():
    got = match_fingerprints(_FPS, {}, [], '<script src="/js/jquery-3.6.0.min.js">')
    assert "jQuery" in got


def test_fingerprint_no_match():
    assert match_fingerprints(_FPS, {"Server": "IIS"}, [], "<html></html>") == set()


def test_fuzz_baseline_soft404():
    b = _Baseline()
    b.add(200, 1000)
    assert b.looks_like_404(200, 1010)      # within 5%
    assert not b.looks_like_404(200, 5000)  # very different length
    assert not b.looks_like_404(404, 1000)  # different status not baselined here


def test_fuzz_baseline_wildcard_flag():
    b = _Baseline()
    b.add(200, 500)
    assert b.wildcard_200
