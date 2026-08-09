"""The pipeline: load modules, run them phase-by-phase, then score and report.

The pipeline is intentionally resilient. A single module raising an exception
never aborts the run — the error is logged, recorded as an ``info`` finding, and
the engagement continues. This mirrors how a real operator works: one dead data
source doesn't stop the mapping.
"""

from __future__ import annotations

import importlib
import pkgutil
import time
import traceback
from typing import Iterable

from voidrecon.core.context import RunContext
from voidrecon.core.logging import get_logger
from voidrecon.core.module import Module, Phase, PHASE_NAMES, registry

log = get_logger("pipeline")


def load_all_modules() -> None:
    """Import every submodule under ``voidrecon.modules`` so registration runs."""
    import voidrecon.modules as modpkg

    for _finder, name, _ispkg in pkgutil.walk_packages(modpkg.__path__, modpkg.__name__ + "."):
        try:
            importlib.import_module(name)
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("failed to import module %s: %s", name, exc)


class Pipeline:
    def __init__(
        self,
        ctx: RunContext,
        *,
        phases: Iterable[Phase] | None = None,
        only: Iterable[str] | None = None,
    ):
        self.ctx = ctx
        self.phases = list(phases) if phases else None
        self.only = list(only) if only else None
        self._results: list[dict] = []

    def plan(self) -> list[Module]:
        load_all_modules()
        modules = registry.select(
            phases=self.phases,
            only=self.only,
            include_active=self.ctx.active_allowed or self.only is not None,
        )
        # Filter by per-module should_run so plan reflects reality.
        return [m for m in modules if m.should_run(self.ctx)]

    async def run(self) -> dict:
        modules = self.plan()
        if not modules:
            log.warning("no modules selected to run")
        current_phase = None
        for mod in modules:
            if mod.phase != current_phase:
                current_phase = mod.phase
                log.info("[bold cyan]=== phase: %s ===[/]", PHASE_NAMES[current_phase])
            await self._run_one(mod)

        summary = {
            "run_id": self.ctx.run_id,
            "elapsed": round(time.time() - self.ctx.started_at, 1),
            "counts": self.ctx.store.counts(),
            "modules": self._results,
            "scope": self.ctx.scope.summary(),
        }
        return summary

    async def _run_one(self, mod: Module) -> None:
        started = time.time()
        before = len(self.ctx.store)
        status = "ok"
        try:
            log.info("running [bold]%s[/] — %s", mod.name, mod.description or "")
            await mod.run(self.ctx)
        except Exception as exc:  # noqa: BLE001 - modules must never kill the run
            status = "error"
            log.error("module %s failed: %s", mod.name, exc)
            log.debug("%s", traceback.format_exc())
            self.ctx.add_finding(
                f"Module '{mod.name}' errored during run",
                module="pipeline",
                description=str(exc),
            )
        elapsed = round(time.time() - started, 1)
        gained = len(self.ctx.store) - before
        self._results.append(
            {
                "module": mod.name,
                "phase": PHASE_NAMES[mod.phase],
                "status": status,
                "elapsed": elapsed,
                "assets_added": gained,
            }
        )
        log.info("  %s finished in %ss (+%d assets)", mod.name, elapsed, gained)
