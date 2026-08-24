"""A single stalled module must never hang the whole run — the pipeline cuts it
off at its wall-clock budget, records a timeout, and keeps going. This guards the
'origin_ip sat for 3 days' class of bug."""

from __future__ import annotations

import asyncio

import pytest

from voidrecon.core.config import Config
from voidrecon.core.context import RunContext
from voidrecon.core.module import Module, Phase
from voidrecon.core.pipeline import Pipeline
from voidrecon.core.scope import Scope


class _Hang(Module):
    name = "hang_test"
    phase = Phase.PASSIVE
    active = False
    description = "sleeps forever"

    async def run(self, ctx):
        await asyncio.sleep(3600)


class _Quick(Module):
    name = "quick_test"
    phase = Phase.PASSIVE
    active = False
    description = "returns immediately"

    async def run(self, ctx):
        ctx.add_asset(__import__("voidrecon.core.models", fromlist=["AssetKind"]).AssetKind.DOMAIN,
                      "ran.example.com", source="quick_test")


def _pipeline(budget):
    cfg = Config.load(overrides={"opsec": {"module_timeout": budget}})
    ctx = RunContext(cfg, Scope.from_lists(["example.com"]))
    return Pipeline(ctx), ctx


@pytest.mark.asyncio
async def test_module_budget_cuts_off_a_hang():
    pipe, ctx = _pipeline(budget=0.3)
    started = asyncio.get_event_loop().time()
    await pipe._run_one(_Hang())
    elapsed = asyncio.get_event_loop().time() - started
    assert elapsed < 5.0                     # cut off ~0.3s, not 3600s
    result = pipe._results[-1]
    assert result["module"] == "hang_test"
    assert result["status"] == "timeout"
    # a pipeline finding explains what happened
    assert any("time budget" in f.title for f in ctx.store.findings())


@pytest.mark.asyncio
async def test_budget_zero_disables_cutoff():
    pipe, ctx = _pipeline(budget=0)
    assert pipe._module_budget(_Quick()) is None
    await pipe._run_one(_Quick())
    assert pipe._results[-1]["status"] == "ok"


@pytest.mark.asyncio
async def test_per_module_override_beats_global():
    cfg = Config.load(overrides={"opsec": {"module_timeout": 7200},
                                 "modules": {"hang_test": {"timeout": 0.3}}})
    ctx = RunContext(cfg, Scope.from_lists(["example.com"]))
    pipe = Pipeline(ctx)
    assert pipe._module_budget(_Hang()) == 0.3
    await pipe._run_one(_Hang())
    assert pipe._results[-1]["status"] == "timeout"
