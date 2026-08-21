"""Provider-agnostic LLM analysis (optional).

The intelligence layer works fully without any model. When a provider *is*
configured, VoidRecon hands the model a compact, de-identified digest of the
highest-scoring assets and asks it to reason like a red-team lead: cluster the
surface, nominate the most promising attack paths, and flag anything the
heuristics under-weighted. The output is advisory only — it never triggers
network actions on its own.

Supported providers (selected via ``intel.llm_provider``):

* ``openai`` / ``openai_compatible`` — Chat Completions API shape.
* ``anthropic`` — Messages API shape.
* ``ollama`` — local models via ``/api/chat``.

No vendor SDKs are required; everything goes over plain HTTP through the shared
client, so keys stay in the environment and calls respect the run's timeouts.
"""

from __future__ import annotations

import json
import os

from voidrecon.core.context import RunContext
from voidrecon.core.logging import get_logger
from voidrecon.intel.scoring import top_assets

log = get_logger("llm")

_SYSTEM_PROMPT = (
    "You are a senior offensive-security analyst supporting an AUTHORIZED bug "
    "bounty engagement. You are given a digest of reconnaissance assets with "
    "heuristic priority scores, plus VoidRecon's own heuristic attack plan "
    "(per-host chains it already reasoned out). Build on that plan — confirm, "
    "correct, sharpen, and add anything the heuristics under-weighted; do not "
    "merely restate it. Respond with strict JSON only, matching this schema:\n"
    "{\n"
    '  "summary": "2-4 sentence overview of the surface",\n'
    '  "priority_targets": [{"asset": "host", "why": "reason", "suggested_checks": ["..."]}],\n'
    '  "clusters": [{"label": "theme", "assets": ["..."], "rationale": "..."}],\n'
    '  "overlooked": ["assets or patterns the numeric scoring may have under-weighted"]\n'
    "}\n"
    "Only recommend actions that are lawful and in-scope. Do not invent assets "
    "that are not in the digest. Return JSON, no prose, no code fences."
)


class LLMClient:
    def __init__(self, ctx: RunContext):
        self.ctx = ctx
        cfg = ctx.config
        self.provider = str(cfg.get("intel.llm_provider", "none")).lower()
        self.model = cfg.get("intel.llm_model", "")
        self.base_url = (cfg.get("intel.llm_base_url", "") or "").rstrip("/")
        key_env = cfg.get("intel.llm_api_key_env", "VOIDRECON_LLM_API_KEY")
        self.api_key = os.environ.get(key_env, "")

    @property
    def enabled(self) -> bool:
        if not self.ctx.config.get("intel.llm_enabled", False):
            return False
        if self.provider in ("none", ""):
            return False
        if self.provider in ("openai", "anthropic", "openai_compatible") and not self.api_key:
            log.warning("LLM enabled but no API key found; skipping model analysis.")
            return False
        if not self.model:
            log.warning("LLM enabled but no model configured; skipping model analysis.")
            return False
        return True

    def _digest(self) -> list[dict]:
        cap = int(self.ctx.config.get("intel.llm_max_assets", 60))
        assets = top_assets(self.ctx.store, limit=cap)
        digest = []
        for a in assets:
            digest.append(
                {
                    "asset": a.value,
                    "kind": a.kind.value,
                    "score": a.score,
                    "scope": a.scope_state.value,
                    "tags": sorted(a.tags),
                    "signals": a.attrs.get("score_reasons", []),
                    "http_status": a.attrs.get("http_status"),
                    "title": a.attrs.get("http_title"),
                    "tech": a.attrs.get("technologies"),
                }
            )
        return digest

    async def analyze(self) -> dict | None:
        if not self.enabled:
            return None
        digest = self._digest()
        if not digest:
            return None
        plan = getattr(self.ctx.store, "battle_plan", None) or {}
        heuristic_plan = {
            "plays": (plan.get("plays") or [])[:8],
            "targets": [
                {"asset": t["asset"], "score": t["score"], "signals": t["signals"],
                 "brief": t["brief"]}
                for t in (plan.get("targets") or [])[:12]
            ],
        }
        user_msg = (
            "Reconnaissance digest and VoidRecon's heuristic attack plan (JSON). "
            "Build on the plan and return the required JSON.\n\n"
            + json.dumps({"target": self.ctx.scope.seeds, "assets": digest,
                          "heuristic_plan": heuristic_plan}, default=str)
        )
        try:
            raw = await self._call(user_msg)
        except Exception as exc:  # noqa: BLE001
            log.warning("LLM call failed: %s", exc)
            return None
        if not raw:
            return None
        return _parse_json(raw)

    async def _call(self, user_msg: str) -> str | None:
        if self.provider in ("openai", "openai_compatible"):
            return await self._call_openai(user_msg)
        if self.provider == "anthropic":
            return await self._call_anthropic(user_msg)
        if self.provider == "ollama":
            return await self._call_ollama(user_msg)
        log.warning("unknown LLM provider: %s", self.provider)
        return None

    async def _call_openai(self, user_msg: str) -> str | None:
        base = self.base_url or "https://api.openai.com/v1"
        resp = await self.ctx.http.request(
            "POST",
            f"{base}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": user_msg},
                ],
                "temperature": 0.2,
            },
        )
        if resp is None or resp.status_code >= 400:
            log.warning("openai-compatible endpoint error: %s", getattr(resp, "status_code", "n/a"))
            return None
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    async def _call_anthropic(self, user_msg: str) -> str | None:
        base = self.base_url or "https://api.anthropic.com"
        resp = await self.ctx.http.request(
            "POST",
            f"{base}/v1/messages",
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            json={
                "model": self.model,
                "max_tokens": 2000,
                "system": _SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": user_msg}],
            },
        )
        if resp is None or resp.status_code >= 400:
            log.warning("anthropic endpoint error: %s", getattr(resp, "status_code", "n/a"))
            return None
        data = resp.json()
        parts = data.get("content", [])
        return "".join(p.get("text", "") for p in parts if p.get("type") == "text")

    async def _call_ollama(self, user_msg: str) -> str | None:
        base = self.base_url or "http://localhost:11434"
        resp = await self.ctx.http.request(
            "POST",
            f"{base}/api/chat",
            json={
                "model": self.model,
                "stream": False,
                "messages": [
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": user_msg},
                ],
            },
        )
        if resp is None or resp.status_code >= 400:
            log.warning("ollama endpoint error: %s", getattr(resp, "status_code", "n/a"))
            return None
        data = resp.json()
        return (data.get("message") or {}).get("content")


def _parse_json(raw: str) -> dict | None:
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        if raw.lower().startswith("json"):
            raw = raw[4:]
    start = raw.find("{")
    end = raw.rfind("}")
    if start == -1 or end == -1:
        return {"summary": raw[:2000]}
    try:
        return json.loads(raw[start : end + 1])
    except json.JSONDecodeError:
        return {"summary": raw[:2000], "parse_error": True}
