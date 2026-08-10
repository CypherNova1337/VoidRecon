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
    tg_token = (os.environ.get("VOIDRECON_NOTIFY_TELEGRAM_TOKEN")
                or ctx.config.get("notify.telegram_token"))
    tg_chat = (os.environ.get("VOIDRECON_NOTIFY_TELEGRAM_CHAT_ID")
               or ctx.config.get("notify.telegram_chat_id"))
    if not (webhook or (tg_token and tg_chat)):
        return False

    min_sev = str(ctx.config.get("notify.min_severity", "high"))
    threshold = _rank(min_sev)
    if threshold > 0 and not any(f.severity.rank >= threshold for f in ctx.store.findings()):
        log.debug("no findings at/above %s — skipping notification", min_sev)
        return False

    text = build_summary(ctx, summary)
    sent = False
    if webhook:
        sent = await _send_webhook(ctx, webhook, text) or sent
    if tg_token and tg_chat:
        sent = await _send_telegram(ctx, tg_token, tg_chat, text) or sent
    return sent


async def _send_webhook(ctx, webhook: str, text: str) -> bool:
    payload = {"content": text} if ("discord.com" in webhook or "discordapp.com" in webhook) else {"text": text}
    try:
        resp = await ctx.http.request("POST", webhook, json=payload,
                                      headers={"Content-Type": "application/json"})
        if resp is not None and resp.status_code < 400:
            log.info("notification sent (webhook)")
            return True
        log.warning("notification webhook returned %s", getattr(resp, "status_code", "n/a"))
    except Exception as exc:  # noqa: BLE001
        log.warning("webhook notification failed: %s", exc)
    return False


async def _send_telegram(ctx, token: str, chat_id: str, text: str) -> bool:
    try:
        resp = await ctx.http.request(
            "POST", f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text[:4000], "disable_web_page_preview": True},
            headers={"Content-Type": "application/json"},
        )
        if resp is not None and resp.status_code < 400:
            log.info("notification sent (telegram)")
            return True
        log.warning("telegram returned %s", getattr(resp, "status_code", "n/a"))
    except Exception as exc:  # noqa: BLE001
        log.warning("telegram notification failed: %s", exc)
    return False
