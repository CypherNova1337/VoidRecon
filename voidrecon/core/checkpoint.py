"""Run checkpointing for resumable engagements.

Long recon runs get interrupted — a dropped connection, a Ctrl-C, a container
recycle. After every module the pipeline snapshots the datastore and the set of
completed modules to ``<run_dir>/checkpoint.json``. ``voidrecon run --resume
<run_id>`` reloads that snapshot and continues from the next unfinished module,
so hours of work are never thrown away.
"""

from __future__ import annotations

import json
from pathlib import Path

from voidrecon.core.logging import get_logger
from voidrecon.core.models import Asset, Finding

log = get_logger("checkpoint")


class Checkpoint:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def save(self, ctx, completed: set[str]) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "run_id": ctx.run_id,
                "completed": sorted(completed),
                "scope": ctx.scope.summary(),
                "assets": [a.to_dict() for a in ctx.store.iter_assets()],
                "findings": [f.to_dict() for f in ctx.store.findings()],
            }
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, default=str), encoding="utf-8")
            tmp.replace(self.path)
        except Exception as exc:  # noqa: BLE001 - checkpointing must never break a run
            log.debug("checkpoint save failed: %s", exc)

    def load(self) -> dict | None:
        if not self.path.exists():
            return None
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            log.warning("could not read checkpoint %s: %s", self.path, exc)
            return None

    @staticmethod
    def restore_store(ctx, data: dict) -> set[str]:
        """Load assets/findings from a checkpoint into the context's store.

        Returns the set of already-completed module names.
        """
        for a in data.get("assets", []):
            try:
                ctx.store.add_asset(Asset.from_dict(a))
            except Exception:
                continue
        for f in data.get("findings", []):
            try:
                ctx.store.add_finding(Finding.from_dict(f))
            except Exception:
                continue
        return set(data.get("completed", []))


def find_run_dir(output_base: str | Path, run_id: str) -> Path | None:
    base = Path(output_base)
    candidate = base / run_id
    if (candidate / "checkpoint.json").exists():
        return candidate
    # Allow a prefix match if the exact id isn't given.
    if base.exists():
        for child in sorted(base.iterdir(), reverse=True):
            if child.is_dir() and child.name.startswith(run_id) and (child / "checkpoint.json").exists():
                return child
    return None
