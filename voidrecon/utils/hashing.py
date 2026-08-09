"""Hashing helpers, including a Shodan-compatible favicon hash.

The favicon hash is the classic attacker pivot: compute the MurmurHash3 of a
site's base64-encoded favicon and you can ask Shodan/Censys "what else on the
internet serves this exact icon?" — instantly surfacing sibling infrastructure,
staging clones, and shadow assets that share the org's branding.

MurmurHash3 (x86, 32-bit) is implemented natively here so the pivot works with
zero third-party dependencies and produces the same signed integer as the
``mmh3`` package that Shodan expects.
"""

from __future__ import annotations

import base64
import hashlib


def murmur3_x86_32(data: bytes, seed: int = 0) -> int:
    """Pure-Python MurmurHash3 x86_32, returning a signed 32-bit int (mmh3-compatible)."""
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded_end = length & 0xFFFFFFFC  # largest multiple of 4 <= length

    for i in range(0, rounded_end, 4):
        k1 = (
            (data[i] & 0xFF)
            | ((data[i + 1] & 0xFF) << 8)
            | ((data[i + 2] & 0xFF) << 16)
            | ((data[i + 3] & 0xFF) << 24)
        )
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    k1 = 0
    tail = length & 0x03
    if tail == 3:
        k1 = (data[rounded_end + 2] & 0xFF) << 16
    if tail >= 2:
        k1 |= (data[rounded_end + 1] & 0xFF) << 8
    if tail >= 1:
        k1 |= data[rounded_end] & 0xFF
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    # to signed 32-bit
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def favicon_hash(content: bytes) -> int:
    """Shodan-style favicon hash: mmh3 of the base64 (with newlines) of the bytes."""
    b64 = base64.encodebytes(content)  # RFC 2045: 76-char lines + trailing newline
    return murmur3_x86_32(b64)


def sha256_hex(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()
