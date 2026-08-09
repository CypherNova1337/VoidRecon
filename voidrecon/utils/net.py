"""Domain / IP / URL parsing helpers.

Kept intentionally free of heavy dependencies. If ``tldextract`` is installed
(the ``full`` extra) we use it for accurate public-suffix handling; otherwise we
fall back to a compact built-in heuristic that covers the common multi-part TLDs.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

try:  # optional, accurate PSL handling
    import tldextract  # type: ignore

    _EXTRACT = tldextract.TLDExtract(suffix_list_urls=())  # offline, cached PSL
except Exception:  # pragma: no cover - fallback path
    _EXTRACT = None

# A small set of common two-label suffixes for the fallback path.
_COMPOUND_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "co.kr", "co.nz", "co.za",
    "com.au", "com.br", "com.cn", "com.mx", "com.tr", "com.sg", "com.hk",
    "net.au", "org.au", "gov.au", "edu.au", "com.ar", "com.co", "com.pl",
}

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_WILDCARD_RE = re.compile(r"^\*\.")


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def is_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value.strip(), strict=False)
        return "/" in value
    except ValueError:
        return False


def is_domain(value: str) -> bool:
    value = value.strip().rstrip(".")
    if is_ip(value):
        return False
    return bool(_DOMAIN_RE.match(value))


def normalize_host(value: str) -> str:
    """Lower-case, strip scheme/port/trailing dot, drop leading wildcard."""
    value = value.strip().lower().rstrip(".")
    if "://" in value:
        value = urlparse(value).hostname or value
    value = _WILDCARD_RE.sub("", value)
    if value.startswith("*."):
        value = value[2:]
    # strip a trailing :port if present on a bare host
    if ":" in value and not is_ip(value):
        host = value.rsplit(":", 1)[0]
        if is_domain(host):
            value = host
    return value


def registrable_domain(host: str) -> str:
    """Return the apex / registrable domain (e.g. ``a.b.example.co.uk`` -> ``example.co.uk``)."""
    host = normalize_host(host)
    if is_ip(host):
        return host
    if _EXTRACT is not None:
        ext = _EXTRACT(host)
        # tldextract renamed 'registered_domain' -> 'top_domain_under_public_suffix';
        # prefer the new attribute, fall back for older versions.
        reg = getattr(ext, "top_domain_under_public_suffix", None) or getattr(ext, "registered_domain", "")
        if reg:
            return reg
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    last_three = ".".join(labels[-3:])
    if last_two in _COMPOUND_TLDS:
        return last_three
    return last_two


def is_subdomain_of(host: str, parent: str) -> bool:
    host = normalize_host(host)
    parent = normalize_host(parent)
    return host == parent or host.endswith("." + parent)


def host_from_url(url: str) -> str | None:
    try:
        parsed = urlparse(url if "://" in url else "//" + url, scheme="http")
        return parsed.hostname
    except Exception:
        return None


def ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip.strip()) in ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return False


def dedupe_preserve(items) -> list:
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
