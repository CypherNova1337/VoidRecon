"""The pipeline: load modules, run them phase-by-phase, then score and report.

The pipeline is intentionally resilient. A single module raising an exception
never aborts the run — the error is logged, recorded as an ``info`` finding, and
the engagement continues. This mirrors how a real operator works: one dead data
source doesn't stop the mapping.
"""

from __future__ import annotations

import asyncio
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
        monitor=None,
        checkpoint=None,
        completed: set[str] | None = None,
    ):
        self.ctx = ctx
        self.phases = list(phases) if phases else None
        self.only = list(only) if only else None
        self.monitor = monitor
        self.checkpoint = checkpoint
        self.completed = set(completed or ())
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
        if self.monitor is not None:
            self.monitor.set_plan(modules)
        current_phase = None
        for mod in modules:
            if mod.phase != current_phase:
                current_phase = mod.phase
                log.info("[bold cyan]=== phase: %s ===[/]", PHASE_NAMES[current_phase])
                if self.monitor is not None:
                    self.monitor.set_phase(PHASE_NAMES[current_phase])
            if mod.name in self.completed:
                # Resumed run: this module already ran in the checkpointed session.
                if self.monitor is not None:
                    self.monitor.end_module(mod.name, "skipped", 0.0, 0)
                log.info("  %s already completed (resumed) — skipping", mod.name)
                continue
            await self._run_one(mod)
            if self.monitor is not None:
                self.monitor.set_totals(self.ctx.store.counts())
            if self.checkpoint is not None:
                self.completed.add(mod.name)
                self.checkpoint.save(self.ctx, self.completed)

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
        if self.monitor is not None:
            self.monitor.start_module(mod.name)
        # Expose what's already done so late-phase modules (the Analyst/advisor)
        # don't recommend re-running completed work.
        setattr(self.ctx.store, "completed_modules", set(self.completed))
        budget = self._module_budget(mod)
        try:
            log.info("running [bold]%s[/] — %s", mod.name, mod.description or "")
            # Every module runs under a wall-clock budget so a single stalled or
            # runaway module (e.g. a huge Host-header cross-product) can never hang
            # the whole engagement. Partial results already emitted are kept.
            if budget:
                await asyncio.wait_for(mod.run(self.ctx), timeout=budget)
            else:
                await mod.run(self.ctx)
        except (asyncio.TimeoutError, TimeoutError):
            status = "timeout"
            log.warning("module %s exceeded its %ss time budget — moving on "
                        "(raise modules.%s.timeout or opsec.module_timeout to allow longer)",
                        mod.name, int(budget), mod.name)
            self.ctx.add_finding(
                f"Module '{mod.name}' hit its {int(budget)}s time budget and was stopped",
                module="pipeline",
                description=("The module ran past its allotted time and was cut off so the run "
                             "could finish. Any results it produced before the cutoff are kept. "
                             "Increase its budget to let it run to completion."),
            )
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
        if self.monitor is not None:
            display = {"ok": "done", "timeout": "timeout"}.get(status, "error")
            self.monitor.end_module(mod.name, display, elapsed, gained)

    def _module_budget(self, mod: Module) -> float | None:
        """Wall-clock seconds a module may run before it is cut off. A per-module
        ``modules.<name>.timeout`` overrides the global ``opsec.module_timeout``;
        either set to 0 disables the budget for that scope."""
        per = self.ctx.config.get(f"modules.{mod.name}.timeout")
        if per is not None:
            try:
                return float(per) or None
            except (TypeError, ValueError):
                pass
        default = self.ctx.config.get("opsec.module_timeout", 7200)
        try:
            return float(default) or None
        except (TypeError, ValueError):
            return 7200.0
