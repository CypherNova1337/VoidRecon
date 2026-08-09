"""Subdomain permutation generation (altdns / gotator style).

Given the subdomains already discovered, an attacker mutates them to guess the
ones that were never indexed anywhere: ``api`` seen -> try ``api-dev``,
``api2``, ``dev-api``, ``api.staging``. This module produces those candidates
from known hosts plus a word list; the caller resolves them and keeps whatever
actually exists.
"""

from __future__ import annotations

from voidrecon.utils import net


def _labels_under(host: str, apex: str) -> list[str]:
    host = net.normalize_host(host)
    apex = net.normalize_host(apex)
    if host == apex:
        return []
    if not host.endswith("." + apex):
        return []
    prefix = host[: -(len(apex) + 1)]
    return prefix.split(".")


def wordlist_candidates(apex: str, words) -> set[str]:
    """Direct ``word.apex`` candidates from a wordlist."""
    apex = net.normalize_host(apex)
    out = set()
    for w in words:
        w = w.strip().lower()
        if w and not w.startswith("#"):
            out.add(f"{w}.{apex}")
    return out


def permute_from_known(
    known_hosts,
    apex: str,
    words,
    *,
    numbers=(1, 2, 3),
    max_out: int = 20000,
) -> set[str]:
    apex = net.normalize_host(apex)
    words = [w.strip().lower() for w in words if w.strip() and not w.strip().startswith("#")]
    out: set[str] = set()

    def add(fqdn: str):
        if len(out) < max_out and net.is_domain(fqdn):
            out.add(fqdn)

    for host in known_hosts:
        labels = _labels_under(host, apex)
        if not labels:
            continue
        first = labels[0]
        rest = ".".join(labels[1:] + [apex]) if len(labels) > 1 else apex

        # Numeric mutations on the leading label (api -> api1, api2, dev01 ...).
        base_notrail = first.rstrip("0123456789")
        for n in numbers:
            add(f"{base_notrail}{n}.{rest}")
            add(f"{base_notrail}0{n}.{rest}")

        # Word joins on the leading label.
        for w in words:
            add(f"{w}-{first}.{rest}")
            add(f"{first}-{w}.{rest}")
            add(f"{w}{first}.{rest}")
            add(f"{first}{w}.{rest}")
            # Insert a new leftmost label.
            add(f"{w}.{host}")
    return out
