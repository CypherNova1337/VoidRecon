from voidrecon.modules.vuln.http_analysis import (
    analyze_cookies,
    evaluate_cors,
    missing_security_headers,
)

_ORIGIN = "https://voidrecon.example"


def test_missing_security_headers():
    missing = missing_security_headers({"Content-Type": "text/html"})
    assert "HSTS (Strict-Transport-Security)" in missing
    assert "Content-Security-Policy" in missing
    full = {
        "strict-transport-security": "max-age=1", "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY", "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer", "permissions-policy": "geolocation=()",
    }
    assert missing_security_headers(full) == []


def test_evaluate_cors_reflected_with_credentials_is_high():
    headers = {"Access-Control-Allow-Origin": _ORIGIN, "Access-Control-Allow-Credentials": "true"}
    sev, _ = evaluate_cors(_ORIGIN, headers)
    assert sev.value == "high"


def test_evaluate_cors_reflected_without_credentials_is_medium():
    sev, _ = evaluate_cors(_ORIGIN, {"Access-Control-Allow-Origin": _ORIGIN})
    assert sev.value == "medium"


def test_evaluate_cors_null_origin():
    sev, _ = evaluate_cors(_ORIGIN, {"Access-Control-Allow-Origin": "null"})
    assert sev.value == "medium"


def test_evaluate_cors_clean():
    assert evaluate_cors(_ORIGIN, {"Access-Control-Allow-Origin": "https://trusted.example"}) is None
    assert evaluate_cors(_ORIGIN, {}) is None


def test_analyze_cookies():
    issues = analyze_cookies(["session=abc; Path=/"])
    assert issues and "Secure" in issues[0] and "HttpOnly" in issues[0]
    assert analyze_cookies(["s=1; Secure; HttpOnly; SameSite=Lax"]) == []
