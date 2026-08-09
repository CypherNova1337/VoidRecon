"""Historical diffing between runs.

Re-running recon on a schedule is how attackers catch the moment a new asset
appears — a fresh staging box, a just-published subdomain, a service that came
online. This module compares two run outputs (the ``voidrecon.json`` files) and
reports what changed: assets and findings that appeared or disappeared, and
notable score movements. It reads saved output only; it performs no recon.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RunDiff:
    new_assets: list[dict] = field(default_factory=list)
    removed_assets: list[dict] = field(default_factory=list)
    new_findings: list[dict] = field(default_factory=list)
    resolved_findings: list[dict] = field(default_factory=list)
    score_jumps: list[dict] = field(default_factory=list)
    old_label: str = ""
    new_label: str = ""

    def is_empty(self) -> bool:
        return not (self.new_assets or self.removed_assets or self.new_findings
                    or self.resolved_findings or self.score_jumps)


def load_run(path: str | Path) -> dict:
    p = Path(path)
    if p.is_dir():
        p = p / "voidrecon.json"
    with p.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def find_runs(output_dir: str | Path, target: str | None = None) -> list[Path]:
    """Return voidrecon.json paths under output_dir, newest last, optionally
    filtered to run directories whose name starts with the target slug."""
    base = Path(output_dir)
    if not base.exists():
        return []
    runs = []
    for child in base.iterdir():
        report = child / "voidrecon.json"
        if child.is_dir() and report.exists():
            if target and not child.name.startswith(target):
                continue
            runs.append(report)
    return sorted(runs, key=lambda p: p.stat().st_mtime)


def _index_assets(run: dict) -> dict[str, dict]:
    out = {}
    for a in run.get("store", {}).get("assets", []):
        out[f"{a.get('kind')}:{a.get('value','').lower()}"] = a
    return out


def _index_findings(run: dict) -> dict[str, dict]:
    out = {}
    for f in run.get("store", {}).get("findings", []):
        out[f"{f.get('module')}:{f.get('title')}:{f.get('asset') or ''}".lower()] = f
    return out


def diff_runs(old: dict, new: dict, *, score_delta: float = 15.0) -> RunDiff:
    old_a, new_a = _index_assets(old), _index_assets(new)
    old_f, new_f = _index_findings(old), _index_findings(new)
    diff = RunDiff(
        old_label=str(old.get("generated", "old")),
        new_label=str(new.get("generated", "new")),
    )
    diff.new_assets = [new_a[k] for k in new_a.keys() - old_a.keys()]
    diff.removed_assets = [old_a[k] for k in old_a.keys() - new_a.keys()]
    diff.new_findings = [new_f[k] for k in new_f.keys() - old_f.keys()]
    diff.resolved_findings = [old_f[k] for k in old_f.keys() - new_f.keys()]
    for k in new_a.keys() & old_a.keys():
        delta = float(new_a[k].get("score", 0)) - float(old_a[k].get("score", 0))
        if abs(delta) >= score_delta:
            diff.score_jumps.append({
                "asset": new_a[k].get("value"),
                "from": old_a[k].get("score"),
                "to": new_a[k].get("score"),
                "delta": round(delta, 1),
            })
    diff.new_assets.sort(key=lambda a: -float(a.get("score", 0)))
    diff.new_findings.sort(key=lambda f: f.get("severity", ""))
    return diff
