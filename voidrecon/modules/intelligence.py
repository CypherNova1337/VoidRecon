"""Intelligence phase — score, correlate, and (optionally) reason.

Runs after all data collection. It scores every asset, derives correlation
findings, and — when a model is configured — asks an LLM to reason over the
highest-priority surface. The LLM output is stashed on the context for the
reporter; nothing here contacts the target.
"""

from __future__ import annotations

from voidrecon.core.context import RunContext
from voidrecon.core.module import Module, Phase, register
from voidrecon.intel import advisor
from voidrecon.intel import correlate as correlate_mod
from voidrecon.intel import scoring
from voidrecon.intel.llm import LLMClient


@register
class Intelligence(Module):
    name = "intelligence"
    phase = Phase.INTEL
    active = False
    description = "Score, correlate, and (optionally) apply LLM analysis"

    async def run(self, ctx: RunContext) -> None:
        scoring.score_store(ctx.store)
        self.log.info("scored %d assets", len(ctx.store))

        correlate_mod.correlate(ctx)
        # Re-score so correlation-derived signals (e.g. takeover flags) are reflected.
        scoring.score_store(ctx.store)

        top = scoring.top_assets(ctx.store, limit=10)
        if top:
            self.log.info("top target: %s (score %.0f)", top[0].value, top[0].score)

        # Advisor: heuristic, always-on "what to do next" plan.
        advice = advisor.recommend(ctx)
        setattr(ctx.store, "advice", advice)
        if advice:
            self.log.info("advisor: %d recommended next step(s); top: %s",
                          len(advice), advice[0]["action"])

        llm = LLMClient(ctx)
        if llm.enabled:
            self.log.info("requesting LLM analysis (%s / %s)", llm.provider, llm.model)
            result = await llm.analyze()
            if result:
                ctx.store.__dict__.setdefault("_intel", {})
                # Stash on the store for the reporter to pick up.
                setattr(ctx.store, "llm_analysis", result)
                self.log.info("LLM analysis attached to report")
        else:
            self.log.debug("LLM analysis disabled or unconfigured")
