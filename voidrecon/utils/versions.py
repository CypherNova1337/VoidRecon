"""Software version parsing and range comparison.

Deliberately tolerant: real-world version strings are messy ("2.4.49 (Ubuntu)",
"v1.0.1f", "8.3.7-dev"). We extract the leading dotted-numeric core plus an
optional trailing letter (for schemes like OpenSSL's ``1.0.1f``) and compare on
that, which is enough for CVE range matching.
"""

from __future__ import annotations

import re

_VER_RE = re.compile(r"v?(\d+(?:\.\d+)*)([a-z]?)", re.IGNORECASE)


def parse_version(value: str) -> tuple[list[int], str] | None:
    if not value:
        return None
    m = _VER_RE.search(value.strip())
    if not m:
        return None
    nums = [int(x) for x in m.group(1).split(".")]
    return nums, (m.group(2) or "").lower()


def _cmp(a: tuple[list[int], str], b: tuple[list[int], str]) -> int:
    an, asuf = a
    bn, bsuf = b
    width = max(len(an), len(bn))
    an = an + [0] * (width - len(an))
    bn = bn + [0] * (width - len(bn))
    if an != bn:
        return -1 if an < bn else 1
    if asuf == bsuf:
        return 0
    return -1 if asuf < bsuf else 1


def is_newer(candidate: str, current: str) -> bool:
    """True if ``candidate`` is a strictly newer version than ``current``."""
    a, b = parse_version(candidate), parse_version(current)
    if a is None or b is None:
        return False
    return _cmp(a, b) > 0


def in_range(version: str, minimum: str | None, maximum: str | None) -> bool:
    """Inclusive range check. Either bound may be omitted (open-ended)."""
    v = parse_version(version)
    if v is None:
        return False
    if minimum:
        mn = parse_version(minimum)
        if mn and _cmp(v, mn) < 0:
            return False
    if maximum:
        mx = parse_version(maximum)
        if mx and _cmp(v, mx) > 0:
            return False
    return True
