"""Text helpers: slugs, safe filenames, and secret-ish pattern detection."""

from __future__ import annotations

import math
import re
from collections import Counter

_SLUG_RE = re.compile(r"[^a-z0-9._-]+")

# High-signal secret patterns. The structurally-unambiguous ones (AKIA, ghp_, …)
# are strong on their own; the generic ``key = "value"`` pattern captures the
# value separately (group ``val``) so it can be screened for entropy/placeholders.
# Each entry is (label, compiled-regex, structural?).
SECRET_PATTERNS: list[tuple[str, re.Pattern, bool]] = [
    ("aws_access_key_id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), True),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), True),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"), True),
    ("github_pat", re.compile(r"\bghp_[0-9A-Za-z]{36}\b"), True),
    ("github_fine_grained", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{22,255}\b"), True),
    ("stripe_secret", re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b"), True),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), True),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), True),
    ("generic_secret_assign", re.compile(
        r"(?i)(?:api[_-]?key|secret|token|passwd|password|access[_-]?key)"
        r"['\"]?\s*[:=]\s*['\"](?P<val>[0-9A-Za-z\-_./+]{8,})['\"]"
    ), False),
]

# Dictionary words that betray a placeholder rather than a real credential.
_PLACEHOLDER_WORDS = {
    "your", "yours", "my", "our", "the", "example", "sample", "test", "testing",
    "dummy", "placeholder", "changeme", "change", "insert", "here", "todo", "fixme",
    "redacted", "hidden", "secret", "apikey", "api", "key", "token", "value", "none",
    "null", "nil", "foo", "bar", "baz", "abc", "somekey", "mykey", "enter", "replace",
    "add", "put", "fill", "notreal", "fake", "demo", "default", "xxxx", "xxxxx",
    "password", "passwd", "pass", "username", "user", "email", "goes", "string",
}
# Substrings/shapes that are never a live secret's value.
_PLACEHOLDER_RE = re.compile(
    r"(?ix)"
    r"^[<{\[(]| [<{\[(] |[>}\])]$|"          # wrapped in <>, {}, [], ()
    r"your[_-]?|_here\b|\bhere\b|"           # your_key, key_here
    r"x{4,}|\*{3,}|\.{3,}|_{3,}|-{3,}|"      # xxxx, ***, ..., ____, ----
    r"example|placeholder|changeme|redacted|dummy|sample|insert|<token>|123456"
)
# Public-by-design identifiers that look secret-ish but are not credentials.
_KNOWN_PUBLIC_RE = re.compile(
    r"(?i)\.apps\.googleusercontent\.com$|"   # Google OAuth client IDs are public
    r"^ya29\.|^AIzaSy[A-Za-z0-9_\-]{0,4}$"    # (short/truncated google keys → noise)
)


def slugify(text: str, maxlen: int = 80) -> str:
    text = text.strip().lower().replace(" ", "-")
    text = _SLUG_RE.sub("-", text).strip("-._")
    return (text or "target")[:maxlen]


def shannon_entropy(value: str) -> float:
    """Shannon entropy (bits/char). Real random secrets sit high (~4+); English
    placeholders and repeated characters sit low."""
    if not value:
        return 0.0
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in Counter(value).values())


def looks_like_real_secret(value: str, *, min_entropy: float = 3.0) -> bool:
    """Screen a candidate secret *value*: reject obvious placeholders, known-public
    identifiers, low-entropy strings, and dictionary-word fillers like
    ``your_api_key_here``."""
    v = (value or "").strip().strip("'\"")
    if len(v) < 8:
        return False
    if _PLACEHOLDER_RE.search(v) or _KNOWN_PUBLIC_RE.search(v):
        return False
    # If most word-tokens are dictionary/placeholder words, it's a template.
    tokens = [t for t in re.split(r"[_\-.\s]+", v.lower()) if t]
    if tokens and sum(1 for t in tokens if t in _PLACEHOLDER_WORDS) >= max(1, (len(tokens) + 1) // 2):
        return False
    if shannon_entropy(v) < min_entropy:
        return False
    if re.fullmatch(r"(.)\1{5,}", v):     # aaaaaaaa, 00000000
        return False
    return True


def find_secrets_classified(blob: str) -> list[tuple[str, str, bool]]:
    """Like :func:`find_secrets` but each hit carries a confidence flag:
    ``(label, snippet, high_confidence)``.

    ``high_confidence`` is True only for structurally-unambiguous vendor tokens
    (AKIA…, AIza…, ghp_…, sk_live_…, a private-key block, a JWT). The generic
    ``key = "value"`` match is *low* confidence even after entropy screening —
    minified bundles are full of high-entropy strings that are not credentials —
    so callers must not escalate it to HIGH or feed it into attack reasoning."""
    hits: list[tuple[str, str, bool]] = []
    for label, pattern, structural in SECRET_PATTERNS:
        for match in pattern.finditer(blob):
            snippet = match.group(0)
            if structural:
                # Even a real-shaped token is a template if it's padded with xxxx.
                if _PLACEHOLDER_RE.search(snippet):
                    continue
            else:
                value = match.groupdict().get("val") or snippet
                if not looks_like_real_secret(value):
                    continue
            if len(snippet) > 120:
                snippet = snippet[:117] + "..."
            hits.append((label, snippet, structural))
    return hits


def find_secrets(blob: str) -> list[tuple[str, str]]:
    """Return ``(label, matched_snippet)`` pairs for suspected secrets in ``blob``.

    Structural matches (AKIA…, ghp_…) still get a placeholder screen; the generic
    ``key = "value"`` match is additionally entropy-scored on its value, so
    ``api_key = "your_api_key_here"`` is rejected instead of flagged HIGH."""
    return [(label, snippet) for label, snippet, _ in find_secrets_classified(blob)]


def truncate(text: str, limit: int = 200) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def short_url(url: str, limit: int = 80) -> str:
    """A compact, readable form of a URL for titles/summaries.

    Keeps scheme://host/path and collapses a long query to '?…' so a single
    giant token (e.g. a login challenge) never floods the output.
    """
    from urllib.parse import urlparse

    try:
        p = urlparse(url)
    except Exception:
        return url[:limit]
    if not p.scheme:
        return url if len(url) <= limit else url[: limit - 1] + "…"
    base = f"{p.scheme}://{p.netloc}{p.path}"
    if p.query:
        first = p.query.split("&", 1)[0].split("=", 1)[0]
        base += f"?{first}=…" if first else "?…"
    return base if len(base) <= limit else base[: limit - 1] + "…"
