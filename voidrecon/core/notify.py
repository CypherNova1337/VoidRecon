"""Completion notifications to a Slack or Discord webhook.

Long recon runs are fire-and-forget; a webhook ping with the headline numbers and
the top findings means you learn the moment something worth looking at turns up.
The payload shape is detected from the URL (Discord vs Slack), and the message is
plain text so it renders anywhere. Sending is best-effort — a failed notification
never affects the run's result.
"""

from __future__ import annotations

from voidrecon.core.logging import get_logger
from voidrecon.core.models import Severity
from voidrecon.intel.scoring import top_assets

log = get_logger("notify")


def _rank(sev: str) -> int:
    try:
        return Severity(sev).rank
    except ValueError:
        return 0


def build_summary(ctx, summary: dict, *, max_findings: int = 8) -> str:
    counts = ctx.store.counts()
    seeds = ", ".join(ctx.scope.seeds) or "target"
    findings = sorted(ctx.store.findings(), key=lambda f: (-f.severity.rank, f.module))
    lines = [
        f"VoidRecon finished: {seeds}",
        f"run {ctx.run_id} in {summary.get('elapsed', '?')}s",
        "surface: " + ", ".join(f"{v} {k}" for k, v in counts.items() if v),
    ]
    top = top_assets(ctx.store, limit=3)
    if top:
        lines.append("top targets: " + ", ".join(f"{a.value}({a.score:.0f})" for a in top))
    if findings:
        lines.append("")
        lines.append("top findings:")
        for f in findings[:max_findings]:
            asset = f" [{f.asset}]" if f.asset else ""
            lines.append(f"  • [{f.severity.value.upper()}] {f.title}{asset}")
    return "\n".join(lines)


async def send(ctx, summary: dict) -> bool:
    import os

    webhook = os.environ.get("VOIDRECON_NOTIFY_WEBHOOK") or ctx.config.get("notify.webhook")
    if not webhook:
        return False

    min_sev = str(ctx.config.get("notify.min_severity", "high"))
    threshold = _rank(min_sev)
    has_qualifying = any(f.severity.rank >= threshold for f in ctx.store.findings())
    if threshold > 0 and not has_qualifying:
        log.debug("no findings at/above %s — skipping notification", min_sev)
        return False

    text = build_summary(ctx, summary)
    payload = {"content": text} if "discord.com" in webhook or "discordapp.com" in webhook else {"text": text}
    try:
        resp = await ctx.http.request("POST", webhook, json=payload,
                                      headers={"Content-Type": "application/json"})
        if resp is not None and resp.status_code < 400:
            log.info("notification sent")
            return True
        log.warning("notification webhook returned %s", getattr(resp, "status_code", "n/a"))
    except Exception as exc:  # noqa: BLE001
        log.warning("notification failed: %s", exc)
    return False
