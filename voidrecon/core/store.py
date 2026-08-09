"""In-memory datastore with JSON persistence.

The store de-duplicates assets by their :attr:`Asset.key` and merges repeat
observations, so any number of modules can independently report the same
subdomain (from crt.sh, from passive DNS, from a wordlist) and the store keeps a
single enriched record with the union of sources.
"""

from __future__ import annotations

import json
import threading
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Iterator

from voidrecon.core.models import Asset, AssetKind, Finding, ScopeState


class DataStore:
    def __init__(self) -> None:
        self._assets: dict[str, Asset] = {}
        self._findings: dict[str, Finding] = {}
        self._lock = threading.RLock()

    # ---- assets -----------------------------------------------------------
    def add_asset(self, asset: Asset) -> Asset:
        with self._lock:
            existing = self._assets.get(asset.key)
            if existing:
                existing.merge(asset)
                return existing
            self._assets[asset.key] = asset
            return asset

    def add_assets(self, assets: Iterable[Asset]) -> list[Asset]:
        return [self.add_asset(a) for a in assets]

    def get_asset(self, kind: AssetKind, value: str) -> Asset | None:
        return self._assets.get(f"{kind.value}:{value.lower()}")

    def assets(
        self,
        kind: AssetKind | None = None,
        scope_state: ScopeState | None = None,
    ) -> list[Asset]:
        with self._lock:
            items = list(self._assets.values())
        if kind is not None:
            items = [a for a in items if a.kind == kind]
        if scope_state is not None:
            items = [a for a in items if a.scope_state == scope_state]
        return items

    def iter_assets(self) -> Iterator[Asset]:
        with self._lock:
            return iter(list(self._assets.values()))

    # ---- findings ---------------------------------------------------------
    def add_finding(self, finding: Finding) -> Finding:
        with self._lock:
            if finding.key not in self._findings:
                self._findings[finding.key] = finding
            return self._findings[finding.key]

    def findings(self) -> list[Finding]:
        with self._lock:
            return list(self._findings.values())

    # ---- stats / export ---------------------------------------------------
    def counts(self) -> dict[str, int]:
        out: dict[str, int] = defaultdict(int)
        for a in self._assets.values():
            out[a.kind.value] += 1
        out["findings"] = len(self._findings)
        return dict(out)

    def to_dict(self) -> dict:
        return {
            "assets": [a.to_dict() for a in self._assets.values()],
            "findings": [f.to_dict() for f in self._findings.values()],
            "counts": self.counts(),
        }

    def save_json(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, default=str)
        return path

    def __len__(self) -> int:
        return len(self._assets)
