"""Text helpers: slugs, safe filenames, and secret-ish pattern detection."""

from __future__ import annotations

import re

_SLUG_RE = re.compile(r"[^a-z0-9._-]+")

# High-signal secret patterns used by JS/content mining. Deliberately conservative
# to keep false positives low; each entry is (label, compiled-regex).
SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key_id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b")),
    ("github_pat", re.compile(r"\bghp_[0-9A-Za-z]{36}\b")),
    ("github_fine_grained", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{22,255}\b")),
    ("stripe_secret", re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("generic_secret_assign", re.compile(
        r"(?i)(?:api[_-]?key|secret|token|passwd|password|access[_-]?key)"
        r"['\"]?\s*[:=]\s*['\"][0-9A-Za-z\-_./+]{12,}['\"]"
    )),
]


def slugify(text: str, maxlen: int = 80) -> str:
    text = text.strip().lower().replace(" ", "-")
    text = _SLUG_RE.sub("-", text).strip("-._")
    return (text or "target")[:maxlen]


def find_secrets(blob: str) -> list[tuple[str, str]]:
    """Return ``(label, matched_snippet)`` pairs for suspected secrets in ``blob``."""
    hits: list[tuple[str, str]] = []
    for label, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(blob):
            snippet = match.group(0)
            if len(snippet) > 120:
                snippet = snippet[:117] + "..."
            hits.append((label, snippet))
    return hits


def truncate(text: str, limit: int = 200) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
