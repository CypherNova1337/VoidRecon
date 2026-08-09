"""Scope engine.

The scope engine is VoidRecon's conscience. Every asset the pipeline touches is
checked against it, and any module that performs *active* interaction MUST gate
on :meth:`Scope.allows_active`. Out-of-scope assets are still recorded (an
attacker maps them — they are leads, e.g. acquisitions or third parties) but are
tagged ``out_of_scope`` and never actively probed.

Scope rules support:

* apex domains and wildcards (``example.com`` covers all subdomains by default;
  ``*.example.com`` is explicit),
* explicit single hosts (``app.example.com``),
* IPs and CIDR ranges,
* out-of-scope exclusions that always win,
* URL entries (the host is extracted).

Rules can be supplied on the CLI, from a YAML/JSON file, or fetched/parsed from a
program policy. The matching logic is deliberately conservative: if a host is not
positively in scope, it is ``UNKNOWN`` (recorded, not probed), and if it matches
any exclusion it is ``OUT_OF_SCOPE``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from voidrecon.core.models import ScopeState
from voidrecon.utils import net


@dataclass
class ScopeRule:
    raw: str
    kind: str            # "domain" | "wildcard" | "host" | "ip" | "cidr"
    value: str
    include_subdomains: bool = True

    @classmethod
    def parse(cls, raw: str, *, wildcard_apex: bool = True) -> "ScopeRule | None":
        """Parse one scope entry. ``wildcard_apex`` treats a bare apex domain as
        covering its subdomains (the common bug-bounty convention)."""
        entry = raw.strip()
        if not entry or entry.startswith("#"):
            return None
        if "://" in entry:
            host = net.host_from_url(entry)
            if host:
                entry = host
        entry = entry.strip().lower().rstrip(".")

        if net.is_cidr(entry):
            return cls(raw, "cidr", entry)
        if net.is_ip(entry):
            return cls(raw, "ip", entry)
        if entry.startswith("*."):
            base = entry[2:]
            if net.is_domain(base):
                return cls(raw, "wildcard", base, include_subdomains=True)
            return None
        if net.is_domain(entry):
            # A bare apex vs a specific host: if it's a registrable apex, treat as
            # a domain (subdomains included when wildcard_apex); otherwise a host.
            apex = net.registrable_domain(entry)
            if entry == apex:
                return cls(raw, "domain", entry, include_subdomains=wildcard_apex)
            return cls(raw, "host", entry, include_subdomains=False)
        return None

    def matches_host(self, host: str) -> bool:
        host = net.normalize_host(host)
        if self.kind in ("domain", "wildcard"):
            if self.include_subdomains:
                return net.is_subdomain_of(host, self.value)
            return host == self.value
        if self.kind == "host":
            return host == self.value
        return False

    def matches_ip(self, ip: str) -> bool:
        if self.kind == "ip":
            return ip == self.value
        if self.kind == "cidr":
            return net.ip_in_cidr(ip, self.value)
        return False


@dataclass
class Scope:
    include: list[ScopeRule] = field(default_factory=list)
    exclude: list[ScopeRule] = field(default_factory=list)
    seeds: list[str] = field(default_factory=list)   # original apex targets
    program_url: str | None = None

    # ---- construction -----------------------------------------------------
    @classmethod
    def from_lists(
        cls,
        include: list[str] | None = None,
        exclude: list[str] | None = None,
        *,
        wildcard_apex: bool = True,
    ) -> "Scope":
        inc = [r for r in (ScopeRule.parse(x, wildcard_apex=wildcard_apex) for x in (include or [])) if r]
        exc = [r for r in (ScopeRule.parse(x, wildcard_apex=wildcard_apex) for x in (exclude or [])) if r]
        seeds = net.dedupe_preserve(
            net.registrable_domain(r.value) for r in inc if r.kind in ("domain", "wildcard", "host")
        )
        return cls(include=inc, exclude=exc, seeds=seeds)

    def add_include(self, entry: str, *, wildcard_apex: bool = True) -> bool:
        rule = ScopeRule.parse(entry, wildcard_apex=wildcard_apex)
        if rule and rule.raw not in {r.raw for r in self.include}:
            self.include.append(rule)
            if rule.kind in ("domain", "wildcard", "host"):
                apex = net.registrable_domain(rule.value)
                if apex not in self.seeds:
                    self.seeds.append(apex)
            return True
        return False

    # ---- evaluation -------------------------------------------------------
    def classify_host(self, host: str) -> ScopeState:
        host = net.normalize_host(host)
        if not host:
            return ScopeState.UNKNOWN
        if any(r.matches_host(host) for r in self.exclude):
            return ScopeState.OUT_OF_SCOPE
        if any(r.matches_host(host) for r in self.include):
            return ScopeState.IN_SCOPE
        return ScopeState.UNKNOWN

    def classify_ip(self, ip: str) -> ScopeState:
        if any(r.matches_ip(ip) for r in self.exclude):
            return ScopeState.OUT_OF_SCOPE
        if any(r.matches_ip(ip) for r in self.include):
            return ScopeState.IN_SCOPE
        return ScopeState.UNKNOWN

    def classify(self, value: str) -> ScopeState:
        if net.is_ip(value):
            return self.classify_ip(value)
        return self.classify_host(value)

    def allows_active(self, value: str) -> bool:
        """Only positively in-scope assets may be actively touched."""
        return self.classify(value) == ScopeState.IN_SCOPE

    def is_related(self, host: str) -> bool:
        """A host under one of our seed apexes — a candidate even if not an
        explicit include rule. Used to surface newly discovered subdomains."""
        host = net.normalize_host(host)
        return any(net.is_subdomain_of(host, seed) for seed in self.seeds)

    def summary(self) -> dict:
        return {
            "seeds": self.seeds,
            "include": [r.raw for r in self.include],
            "exclude": [r.raw for r in self.exclude],
            "program_url": self.program_url,
        }
