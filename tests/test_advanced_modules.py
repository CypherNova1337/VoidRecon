import base64
import json

from voidrecon.core.models import Severity
from voidrecon.modules.content.graphql import parse_suggestions
from voidrecon.modules.vuln.jwt_analysis import analyze_jwt, decode_jwt


def _jwt(header: dict, payload: dict) -> str:
    def enc(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc(header)}.{enc(payload)}.sig"


def test_parse_suggestions():
    text = 'Cannot query field "usr". Did you mean "user"? Did you mean \'users\'?'
    assert parse_suggestions(text) == {"user", "users"}
    assert parse_suggestions("") == set()


def test_decode_jwt():
    tok = _jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "123", "role": "admin"})
    header, payload = decode_jwt(tok)
    assert header["alg"] == "HS256"
    assert payload["role"] == "admin"
    assert decode_jwt("notajwt") == (None, None)


def test_analyze_jwt_alg_none_is_high():
    sev, issues = analyze_jwt({"alg": "none"}, {"sub": "1"})
    assert sev == Severity.HIGH
    assert any("alg:none" in i for i in issues)


def test_analyze_jwt_no_expiry_and_claims():
    sev, issues = analyze_jwt({"alg": "HS256"}, {"role": "admin", "sub": "1"})
    assert any("exp" in i for i in issues)
    assert any("authorization claims" in i for i in issues)
    assert sev.rank >= Severity.LOW.rank


def test_analyze_jwt_clean():
    sev, issues = analyze_jwt({"alg": "RS256"}, {"sub": "1", "exp": 9999999999})
    assert issues == []
    assert sev == Severity.INFO


def test_open_redirect_param_set():
    from voidrecon.modules.vuln.open_redirect import _REDIRECT_PARAMS
    assert "redirect_uri" in _REDIRECT_PARAMS
    assert "next" in _REDIRECT_PARAMS
