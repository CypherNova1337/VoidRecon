"""URL-parameter semantics.

A recon tool that files every query parameter into an injection class produces
noise: ``utm_source`` goes to an analytics pixel, an OAuth ``code``/``state`` is a
one-time flow token, a docs link's ``?type=sql`` is a content selector. None of
those are injection surfaces. These helpers let the probes and the candidate
classifier skip parameters that are known-benign for a given class before spending
a request — or a HIGH severity — on them.
"""

from __future__ import annotations

# Analytics / tracking / campaign params — never an injection surface of any kind.
ANALYTICS_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id",
    "utm_name", "utm_cid", "utm_reader", "utm_referrer", "utm_social", "utm_brand",
    "gclid", "gclsrc", "dclid", "fbclid", "msclkid", "yclid", "twclid", "igshid",
    "mc_cid", "mc_eid", "_ga", "_gl", "ref", "ref_src", "ref_url", "referrer",
    "source", "medium", "campaign", "spm", "vero_id", "s_kwcid", "mkt_tok",
    "hsa_acc", "hsa_cam", "hsa_grp", "hsa_ad", "hsa_src", "hsa_tgt", "hsa_kw",
}

# OAuth / OIDC / auth-flow control params. These are protocol plumbing (often
# single-use), not user-controlled sinks — an old ``code`` in an archived OAuth
# return URL is not an RCE/SSRF/SQLi candidate.
OAUTH_FLOW_PARAMS = {
    "code", "state", "scope", "response_type", "response_mode", "grant_type",
    "client_id", "client_secret", "nonce", "id_token", "access_token", "refresh_token",
    "token", "id_token_hint", "session_state", "auth", "authuser", "prompt",
    "redirect_uri", "redirect_url", "callback", "code_challenge", "code_challenge_method",
    "code_verifier", "login_hint", "acr_values", "request_uri",
}

# Pure presentation / navigation params — not injection surfaces.
PRESENTATION_PARAMS = {
    "lang", "locale", "hl", "language", "theme", "view", "tab", "page", "per_page",
    "sort", "order", "format", "fmt", "version", "v", "_", "cb", "cache", "t", "ts",
}


def is_analytics_param(name: str) -> bool:
    n = (name or "").lower()
    return n in ANALYTICS_PARAMS or n.startswith(("utm_", "hsa_", "pk_", "mtm_"))


def is_oauth_param(name: str) -> bool:
    return (name or "").lower() in OAUTH_FLOW_PARAMS


def is_benign_param(name: str) -> bool:
    """True for parameters that are not an injection surface for *any* class —
    analytics, auth-flow plumbing, and pure presentation controls."""
    n = (name or "").lower()
    return is_analytics_param(n) or is_oauth_param(n) or n in PRESENTATION_PARAMS


def worth_injecting(name: str) -> bool:
    """Whether a parameter is worth spending an active injection probe on."""
    return bool(name) and not is_benign_param(name)


# Path markers and extensions that mean "this is a static asset, not a
# database-backed endpoint." Framework data files (Next.js ``/_next/data/…json``,
# Nuxt ``/_nuxt/``) are the worst offenders: they respond to any query but have no
# DB behind them, and SPA rehydration makes their byte-length wobble between
# identical requests — which is exactly what naive boolean-SQLi detection misreads.
_STATIC_MARKERS = (
    "/_next/", "/_nuxt/", "/static/", "/static-assets", "/assets/", "/dist/",
    "/build/", "/_astro/", "/cdn-cgi/", "/wp-content/", "/wp-includes/",
)
_STATIC_EXTS = (
    ".js", ".mjs", ".cjs", ".css", ".map", ".json", ".xml", ".txt", ".woff",
    ".woff2", ".ttf", ".eot", ".otf", ".svg", ".png", ".jpg", ".jpeg", ".gif",
    ".ico", ".webp", ".avif", ".bmp", ".mp4", ".webm", ".mov", ".mp3", ".pdf",
    ".wasm",
)


def is_static_path(url_or_path: str) -> bool:
    """True if the URL/path points at a static asset (no server-side DB logic),
    so injection probing there is pure noise."""
    from urllib.parse import urlsplit

    try:
        path = urlsplit(url_or_path).path.lower()
    except Exception:
        path = (url_or_path or "").split("?", 1)[0].lower()
    if not path:
        return False
    if any(m in path for m in _STATIC_MARKERS):
        return True
    return path.endswith(_STATIC_EXTS)
