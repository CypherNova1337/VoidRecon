"""Core data models for VoidRecon.

Everything a recon run learns is represented as either an :class:`Asset`
(something that exists on the target's attack surface) or a :class:`Finding`
(something interesting or actionable about the surface). Both are lightweight,
JSON-serialisable dataclasses so the datastore, reporting, and intelligence
layers can all speak the same language.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AssetKind(str, Enum):
    """The category of an attack-surface asset."""

    ORGANIZATION = "organization"
    DOMAIN = "domain"          # apex / registrable domain
    SUBDOMAIN = "subdomain"
    IP = "ip"
    CIDR = "cidr"              # network range
    ASN = "asn"
    SERVICE = "service"        # host:port/proto
    URL = "url"
    ENDPOINT = "endpoint"      # API route / path discovered via crawl or JS
    TECHNOLOGY = "technology"
    CERTIFICATE = "certificate"
    CLOUD_RESOURCE = "cloud_resource"  # bucket, blob, function, etc.
    EMAIL = "email"
    CODE_REPO = "code_repo"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Confidence(str, Enum):
    TENTATIVE = "tentative"   # single weak signal
    LIKELY = "likely"         # corroborated / strong signal
    CONFIRMED = "confirmed"   # actively verified


class ScopeState(str, Enum):
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    UNKNOWN = "unknown"


def _now() -> float:
    return time.time()


@dataclass
class Asset:
    """A single element of the target's attack surface.

    ``value`` is the natural key for the asset (a hostname, an IP, a URL, an
    ASN string like ``AS15169``…). ``kind`` disambiguates. ``attrs`` is a free
    bag for module-specific enrichment (open ports, tech versions, http title…).
    """

    kind: AssetKind
    value: str
    sources: set[str] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)
    attrs: dict[str, Any] = field(default_factory=dict)
    scope_state: ScopeState = ScopeState.UNKNOWN
    confidence: Confidence = Confidence.LIKELY
    score: float = 0.0
    first_seen: float = field(default_factory=_now)
    last_seen: float = field(default_factory=_now)

    @property
    def key(self) -> str:
        """Stable identity used for de-duplication in the datastore."""
        return f"{self.kind.value}:{self.value.lower()}"

    def merge(self, other: "Asset") -> None:
        """Fold another observation of the same asset into this one."""
        self.sources |= other.sources
        self.tags |= other.tags
        for k, v in other.attrs.items():
            if k not in self.attrs or self.attrs[k] in (None, "", [], {}):
                self.attrs[k] = v
            elif isinstance(self.attrs[k], list) and isinstance(v, list):
                merged = self.attrs[k] + [x for x in v if x not in self.attrs[k]]
                self.attrs[k] = merged
        if other.confidence.value == "confirmed":
            self.confidence = Confidence.CONFIRMED
        elif other.confidence.value == "likely" and self.confidence == Confidence.TENTATIVE:
            self.confidence = Confidence.LIKELY
        if other.scope_state != ScopeState.UNKNOWN:
            self.scope_state = other.scope_state
        self.score = max(self.score, other.score)
        self.last_seen = _now()

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "value": self.value,
            "sources": sorted(self.sources),
            "tags": sorted(self.tags),
            "attrs": self.attrs,
            "scope_state": self.scope_state.value,
            "confidence": self.confidence.value,
            "score": round(self.score, 2),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Asset":
        return cls(
            kind=AssetKind(data["kind"]),
            value=data["value"],
            sources=set(data.get("sources", [])),
            tags=set(data.get("tags", [])),
            attrs=dict(data.get("attrs", {})),
            scope_state=ScopeState(data.get("scope_state", "unknown")),
            confidence=Confidence(data.get("confidence", "likely")),
            score=float(data.get("score", 0.0)),
            first_seen=float(data.get("first_seen", _now())),
            last_seen=float(data.get("last_seen", _now())),
        )


@dataclass
class Finding:
    """Something notable about the surface — an exposure, misconfig, or lead."""

    title: str
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.LIKELY
    asset: str | None = None          # related asset value
    module: str = ""
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    tags: set[str] = field(default_factory=set)
    created: float = field(default_factory=_now)

    @property
    def key(self) -> str:
        return f"{self.module}:{self.title}:{self.asset or ''}".lower()

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "asset": self.asset,
            "module": self.module,
            "description": self.description,
            "evidence": self.evidence,
            "references": self.references,
            "tags": sorted(self.tags),
            "created": self.created,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        return cls(
            title=data["title"],
            severity=Severity(data.get("severity", "info")),
            confidence=Confidence(data.get("confidence", "likely")),
            asset=data.get("asset"),
            module=data.get("module", ""),
            description=data.get("description", ""),
            evidence=dict(data.get("evidence", {})),
            references=list(data.get("references", [])),
            tags=set(data.get("tags", [])),
            created=float(data.get("created", _now())),
        )
