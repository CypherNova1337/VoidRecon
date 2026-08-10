"""VoidRecon command-line interface.

Examples
--------
Passive-only recon (quiet, the default)::

    voidrecon run example.com

Add explicit scope and an out-of-scope exclusion::

    voidrecon run example.com --include "*.example.com" --exclude blog.example.com

Load scope from a file (one entry per line, or a JSON/YAML with include/exclude)::

    voidrecon run --scope-file program-scope.txt --url https://hackerone.com/example

Enable active probing (only touches positively in-scope, resolving hosts)::

    voidrecon run example.com --active

Run a single phase or a single module::

    voidrecon run example.com --phases passive
    voidrecon run example.com --only crtsh,passive_subs

List available modules / show effective scope::

    voidrecon modules
    voidrecon scope example.com --include "*.example.com"
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from voidrecon.core import db, history, notify
from voidrecon.core.checkpoint import Checkpoint, find_run_dir
from voidrecon.core.config import Config
from voidrecon.core.context import RunContext
from voidrecon.core.logging import set_console_level, setup_logging
from voidrecon.core.module import PHASE_NAMES, Phase, registry
from voidrecon.core.pipeline import Pipeline, load_all_modules
from voidrecon.core.program import import_program_scope
from voidrecon.core.scope import Scope
from voidrecon.reporting.live import LiveMonitor, NullMonitor
from voidrecon.reporting.report import Reporter
from voidrecon.version import __codename__, __version__

_PHASE_BY_NAME = {v: k for k, v in PHASE_NAMES.items()}

# One-word intensity presets (applied under explicit CLI flags, which still win).
_HEAVY = ["dns_brute", "fuzz", "vhost", "sourcemaps", "param_discovery", "spa_crawl",
          "screenshot", "cms_enum", "graphql", "injection_probe", "open_redirect",
          "cloud_assets", "wayback", "reverse_ip"]
PROFILES = {
    "passive": {"opsec": {"allow_active": False}},
    "quick": {"opsec": {"allow_active": True}, "modules": {"disabled": list(_HEAVY)}},
    "standard": {"opsec": {"allow_active": True}},
    "deep": {"opsec": {"allow_active": True}, "modules": {"enabled": ["*"]}},
    "stealth": {"opsec": {"allow_active": True, "requests_per_second": 2.0, "jitter": 0.6,
                          "max_concurrency": 5, "rotate_user_agents": True},
                "modules": {"disabled": ["dns_brute", "fuzz", "vhost", "port_scan",
                                         "param_discovery", "injection_probe"]}},
}


def _merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out

_BANNER = r"""
 __     __    _     _ ____
 \ \   / /__ (_) __| |  _ \ ___  ___ ___  _ __
  \ \ / / _ \| |/ _` | |_) / _ \/ __/ _ \| '_ \
   \ V / (_) | | (_| |  _ <  __/ (_| (_) | | | |
    \_/ \___/|_|\__,_|_| \_\___|\___\___/|_| |_|
"""


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="voidrecon",
        description="VoidRecon — adversary-minded reconnaissance for authorized engagements. (by VoidSec-Hub)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"VoidRecon {__version__} ({__codename__})")
    sub = p.add_subparsers(dest="command", required=True)

    # run -----------------------------------------------------------------
    run = sub.add_parser("run", help="Run a reconnaissance engagement")
    run.add_argument("targets", nargs="*", help="Seed apex domains / IPs / CIDRs (also treated as in-scope)")
    run.add_argument("-u", "--url", help="Program/policy URL (recorded for reference)")
    run.add_argument(
        "--import-scope", action="store_true",
        help="Fetch and merge scope from the --url program page (HackerOne API with creds, "
             "or best-effort parsing). Never probes the target.",
    )
    run.add_argument("-i", "--include", action="append", default=[], help="Add an in-scope entry (repeatable)")
    run.add_argument("-x", "--exclude", action="append", default=[], help="Add an out-of-scope entry (repeatable)")
    run.add_argument("-S", "--scope-file", help="File with scope entries (txt lines or JSON/YAML include/exclude)")
    run.add_argument("--active", action="store_true", help="Enable active modules (probing/scanning). Off by default.")
    run.add_argument(
        "-A", "--aggressive", action="store_true",
        help="Maximum-coverage recon: active mode + every opt-in module + heavier throughput. "
             "Loud and intrusive — requires confirmation (or --yes).",
    )
    run.add_argument("-y", "--yes", action="store_true", help="Skip the aggressive-mode confirmation prompt (for automation)")
    run.add_argument("-p", "--profile", choices=["passive", "quick", "standard", "deep", "stealth"],
                     help="Preset intensity: passive | quick | standard | deep | stealth")
    run.add_argument("--ai", action="store_true",
                     help="Enable LLM analysis (provider/model from env or config; heuristic advisor is always on)")
    run.add_argument("--phases", help="Comma list of phases to run: " + ", ".join(PHASE_NAMES.values()))
    run.add_argument("--only", help="Comma list of specific module names to run")
    run.add_argument("-c", "--config", help="Path to a config YAML file")
    run.add_argument("-o", "--output-dir", help="Base directory for run output (default: runs/)")
    run.add_argument("--rps", type=float, help="Requests per second (throttle)")
    run.add_argument("--concurrency", type=int, help="Max concurrent operations")
    run.add_argument("--timeout", type=float, help="Per-request timeout in seconds")
    run.add_argument("--no-verify-tls", action="store_true", help="Disable TLS verification (use with care)")
    run.add_argument("-H", "--header", action="append", default=[],
                     help="Auth/custom header sent on every active request, 'Name: value' (repeatable)")
    run.add_argument("--cookie", action="append", default=[],
                     help="Auth cookie 'name=value' sent on every active request (repeatable)")
    run.add_argument("--bearer", help="Shorthand for --header 'Authorization: Bearer <token>'")
    run.add_argument("--login-url", help="Login form URL — VoidRecon logs in via a browser and reuses the session")
    run.add_argument("--login-user", help="Username/email for --login-url")
    run.add_argument("--login-pass", help="Password for --login-url")
    run.add_argument("--formats", help="Report formats (comma): json,markdown,html")
    run.add_argument("--notify-webhook", help="Slack/Discord webhook URL for a completion summary")
    run.add_argument("--llm", action="store_true", help="Enable LLM analysis (requires provider config + key)")
    run.add_argument("--llm-provider", help="openai | anthropic | ollama | openai_compatible")
    run.add_argument("--llm-model", help="Model name for the selected provider")
    run.add_argument("--disable", action="append", default=[], help="Disable a module by name (repeatable)")
    run.add_argument("--resume", metavar="RUN_ID",
                     help="Resume an interrupted run by its id (reloads its checkpoint, skips completed modules)")
    run.add_argument("--no-live", action="store_true", help="Disable the live progress display")
    run.add_argument("--no-update-check", action="store_true", help="Skip the check for a newer version")
    run.add_argument("-v", "--verbose", action="store_true", help="Verbose (debug) logging")
    run.add_argument("-q", "--quiet", action="store_true", help="Only warnings and errors")
    run.add_argument("--no-banner", action="store_true", help="Suppress the banner")

    # wizard --------------------------------------------------------------
    sub.add_parser("wizard", help="Interactive guided setup (asks a few questions, then runs)")

    # setup ---------------------------------------------------------------
    sub.add_parser("setup", help="Interactively configure API keys & notifications (saved to user config)")

    # update --------------------------------------------------------------
    up = sub.add_parser("update", help="Check for / install the latest version")
    up.add_argument("--check", action="store_true", help="Only check, don't install")

    # modules -------------------------------------------------------------
    mods = sub.add_parser("modules", help="List available modules")
    mods.add_argument("--phase", help="Filter by phase")

    # diff ----------------------------------------------------------------
    df = sub.add_parser("diff", help="Diff two runs to see what changed (new/removed assets & findings)")
    df.add_argument("paths", nargs="*", help="Two run dirs/JSON files, or a target slug (uses latest two runs)")
    df.add_argument("-d", "--dir", default="runs", help="Base output directory to search (default: runs)")
    df.add_argument("--json", action="store_true", help="Emit the diff as JSON")

    # dashboard -----------------------------------------------------------
    dash = sub.add_parser("dashboard", help="Build an HTML trend dashboard across runs of a target")
    dash.add_argument("target", nargs="?", help="Target slug to filter runs (default: all)")
    dash.add_argument("-d", "--dir", default="runs", help="Base output directory (default: runs)")
    dash.add_argument("-o", "--output", help="Output HTML path (default: <dir>/dashboard.html)")

    # update-cve ----------------------------------------------------------
    uc = sub.add_parser("update-cve", help="Fetch/merge an external CVE signature dataset")
    uc.add_argument("url", help="URL to a JSON dataset ({\"signatures\": [...]})")

    # queue ---------------------------------------------------------------
    q = sub.add_parser("queue", help="Manage the distributed work queue")
    q.add_argument("action", choices=["add", "list", "clear"], help="Queue action")
    q.add_argument("targets", nargs="*", help="Targets to add (for 'add')")
    q.add_argument("--db", help="Queue DB path (default: <output_dir>/queue.db)")
    q.add_argument("--active", action="store_true", help="Run added jobs in active mode")
    q.add_argument("--aggressive", action="store_true", help="Run added jobs in aggressive mode")

    # worker --------------------------------------------------------------
    wk = sub.add_parser("worker", help="Run a queue worker (drains jobs; run several in parallel)")
    wk.add_argument("--db", help="Queue DB path (default: <output_dir>/queue.db)")
    wk.add_argument("--once", action="store_true", help="Process one job then exit")
    wk.add_argument("--poll", type=int, default=0, help="Seconds to wait for new jobs before exiting (0 = exit when empty)")
    wk.add_argument("--id", dest="worker_id", help="Worker identifier (default: host:pid)")

    # serve ---------------------------------------------------------------
    sv = sub.add_parser("serve", help="Browse the SQLite datastore in a local web UI")
    sv.add_argument("--db", help="Path to voidrecon.db (default: <output_dir>/voidrecon.db)")
    sv.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    sv.add_argument("--port", type=int, default=8787, help="Bind port (default: 8787)")

    # scope ---------------------------------------------------------------
    sc = sub.add_parser("scope", help="Parse and display effective scope without running")
    sc.add_argument("targets", nargs="*")
    sc.add_argument("-i", "--include", action="append", default=[])
    sc.add_argument("-x", "--exclude", action="append", default=[])
    sc.add_argument("-S", "--scope-file")
    sc.add_argument("--check", help="Classify a single host/IP against the scope")

    return p


def _load_scope_file(path: str) -> tuple[list[str], list[str]]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"scope file not found: {path}")
    text = p.read_text(encoding="utf-8")
    stripped = text.strip()
    include: list[str] = []
    exclude: list[str] = []
    if stripped.startswith("{"):
        import json

        data = json.loads(stripped)
        include = list(data.get("include", []))
        exclude = list(data.get("exclude", []))
    elif p.suffix in (".yaml", ".yml"):
        import yaml

        data = yaml.safe_load(stripped) or {}
        include = list(data.get("include", []))
        exclude = list(data.get("exclude", []))
    else:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("!") or line.lower().startswith("out:"):
                exclude.append(line.lstrip("!").split(":", 1)[-1].strip())
            else:
                include.append(line)
    return include, exclude


def _build_scope(args, wildcard_apex: bool) -> Scope:
    include = list(args.include)
    exclude = list(args.exclude)
    include += list(getattr(args, "targets", []) or [])
    if getattr(args, "scope_file", None):
        inc, exc = _load_scope_file(args.scope_file)
        include += inc
        exclude += exc
    scope = Scope.from_lists(include, exclude, wildcard_apex=wildcard_apex)
    if getattr(args, "url", None):
        scope.program_url = args.url
    return scope


def _config_overrides(args) -> dict:
    ov: dict = {"opsec": {}, "http": {}, "intel": {}, "general": {}, "modules": {}}
    if getattr(args, "active", False):
        ov["opsec"]["allow_active"] = True
    if getattr(args, "aggressive", False):
        # Aggressive = everything on. Active mode, all opt-in modules, and heavier
        # throughput. Explicit flags below still win (they are merged after).
        ov["opsec"]["aggressive"] = True
        ov["opsec"]["allow_active"] = True
        ov["opsec"].setdefault("requests_per_second", 25.0)
        ov["opsec"].setdefault("max_concurrency", 50)
        ov["opsec"].setdefault("jitter", 0.1)
        ov["modules"]["enabled"] = ["*"]
    # --only force-enables the named modules even if they are opt-in.
    if getattr(args, "only", None):
        names = [m.strip() for m in args.only.split(",") if m.strip()]
        existing = ov["modules"].get("enabled", [])
        if "*" not in existing:
            ov["modules"]["enabled"] = list(dict.fromkeys(existing + names))
    if getattr(args, "rps", None) is not None:
        ov["opsec"]["requests_per_second"] = args.rps
    if getattr(args, "concurrency", None) is not None:
        ov["opsec"]["max_concurrency"] = args.concurrency
    if getattr(args, "timeout", None) is not None:
        ov["opsec"]["timeout"] = args.timeout
    if getattr(args, "no_verify_tls", False):
        ov["http"]["verify_tls"] = False
    if getattr(args, "output_dir", None):
        ov["general"]["output_dir"] = args.output_dir
    if getattr(args, "llm", False) or getattr(args, "ai", False):
        ov["intel"]["llm_enabled"] = True
    if getattr(args, "llm_provider", None):
        ov["intel"]["llm_provider"] = args.llm_provider
    if getattr(args, "llm_model", None):
        ov["intel"]["llm_model"] = args.llm_model
    if getattr(args, "disable", None):
        ov["modules"]["disabled"] = list(args.disable)
    if getattr(args, "formats", None):
        ov["reporting"] = {"formats": [f.strip() for f in args.formats.split(",")]}
    if getattr(args, "notify_webhook", None):
        ov["notify"] = {"webhook": args.notify_webhook}
    # Authenticated-session material.
    headers: dict = {}
    for h in getattr(args, "header", None) or []:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    if getattr(args, "bearer", None):
        headers["Authorization"] = f"Bearer {args.bearer}"
    cookies: dict = {}
    for c in getattr(args, "cookie", None) or []:
        if "=" in c:
            k, v = c.split("=", 1)
            cookies[k.strip()] = v.strip()
    if headers or cookies:
        ov["auth"] = {}
        if headers:
            ov["auth"]["headers"] = headers
        if cookies:
            ov["auth"]["cookies"] = cookies
    return ov


def _confirm_aggressive(scope: Scope, assume_yes: bool) -> bool:
    """Show the aggressive-mode warning and require an explicit yes.

    Non-interactive sessions must pass --yes; we never assume consent from a
    pipe. Returns True if the run may proceed.
    """
    targets = ", ".join(scope.seeds) or "the provided scope"
    warning = f"""
{'=' * 68}
  ⚠  AGGRESSIVE MODE — LOUD, INTRUSIVE, HIGH-VOLUME RECON
{'=' * 68}
  This enables ACTIVE interaction with the target and EVERY opt-in
  module (HTTP probing, port scanning, crawling, JS mining, template
  scanning) at elevated request rates.

  Only in-scope, resolving assets are ever touched — but this WILL be
  noticed. It generates significant traffic and may trip rate limits,
  WAFs, or IDS/IPS.

  Target scope : {targets}

  Run this ONLY against assets you are explicitly authorized to test
  (an active bug bounty program or a signed engagement). You are
  responsible for staying within scope and the law.
{'=' * 68}
"""
    print(warning, file=sys.stderr)
    if assume_yes:
        print("  --yes supplied; proceeding.\n", file=sys.stderr)
        return True
    if not sys.stdin.isatty():
        print("  Non-interactive session: re-run with --yes to confirm aggressive mode.\n", file=sys.stderr)
        return False
    try:
        resp = input("  Type 'yes' to confirm you are authorized and want to proceed: ")
    except (EOFError, KeyboardInterrupt):
        print(file=sys.stderr)
        return False
    return resp.strip().lower() in ("y", "yes")


async def _run(args) -> int:
    from voidrecon.core.logging import get_logger

    profile_ov = PROFILES.get(getattr(args, "profile", None), {})
    overrides = _merge(profile_ov, _config_overrides(args))
    cfg = Config.load(args.config, overrides=overrides)
    wildcard_apex = bool(cfg.get("general.wildcard_apex", True))
    scope = _build_scope(args, wildcard_apex)

    if getattr(args, "import_scope", False):
        if not args.url:
            print("error: --import-scope requires --url", file=sys.stderr)
            return 2
        imported = await import_program_scope(args.url)
        for entry in imported.include:
            scope.add_include(entry, wildcard_apex=wildcard_apex)
        for entry in imported.exclude:
            from voidrecon.core.scope import ScopeRule

            rule = ScopeRule.parse(entry, wildcard_apex=wildcard_apex)
            if rule:
                scope.exclude.append(rule)
        if imported.ok:
            print(f"imported scope from {imported.platform} "
                  f"({len(imported.include)} in-scope, {len(imported.exclude)} out-of-scope): "
                  f"{imported.note}", file=sys.stderr)
        else:
            print(f"scope import: {imported.note}", file=sys.stderr)

    if not scope.include:
        print("error: no targets/scope provided. Give a domain or use --include/--scope-file/--import-scope.", file=sys.stderr)
        return 2

    level = "debug" if args.verbose else ("warning" if args.quiet else cfg.get("general.log_level", "info"))
    ctx = RunContext(cfg, scope)

    completed: set[str] = set()
    if getattr(args, "resume", None):
        run_dir = find_run_dir(cfg.get("general.output_dir", "runs"), args.resume)
        if not run_dir:
            print(f"error: no resumable run found for '{args.resume}'", file=sys.stderr)
            await ctx.aclose()
            return 2
        ctx.run_id = run_dir.name
        ctx.output_dir = run_dir

    ctx.output_dir.mkdir(parents=True, exist_ok=True)
    setup_logging(level, logfile=ctx.output_dir / "voidrecon.log")
    log = get_logger()

    checkpoint = Checkpoint(ctx.output_dir / "checkpoint.json")
    if getattr(args, "resume", None):
        data = checkpoint.load()
        if data:
            completed = Checkpoint.restore_store(ctx, data)
            log.info("resumed %s: restored %d assets, skipping %d completed modules",
                     ctx.run_id, len(ctx.store), len(completed))

    if not args.no_banner and not args.quiet:
        print(_BANNER)

    if not getattr(args, "no_update_check", False):
        from voidrecon.core import version_check

        newer = version_check.check()
        if newer:
            log.warning("[bold yellow]Update available:[/] VoidRecon %s is out "
                        "(running %s) — run 'voidrecon update'", newer, __version__)

    aggressive = bool(cfg.get("opsec.aggressive", False))
    if aggressive and not _confirm_aggressive(scope, args.yes):
        print("aborted: aggressive mode not confirmed.", file=sys.stderr)
        await ctx.aclose()
        return 3

    log.info("run id: [bold]%s[/]", ctx.run_id)
    log.info("seeds: %s", ", ".join(scope.seeds) or "—")
    if aggressive:
        log.info("mode: [bold red]AGGRESSIVE[/] — active + all opt-in modules, heavier throughput")
    else:
        log.info("active mode: %s", "[bold red]ON[/]" if ctx.active_allowed else "off (passive only)")
    tools = ctx.tools.available()
    if tools:
        log.info("external tools available: %s", ", ".join(sorted(tools)))

    # Authenticated login (scripted browser) — captured cookies feed active modules.
    login_cfg = dict(cfg.get("auth.login", {}) or {})
    for flag, key in (("login_url", "url"), ("login_user", "username"), ("login_pass", "password")):
        if getattr(args, flag, None):
            login_cfg[key] = getattr(args, flag)
    if login_cfg.get("url") and login_cfg.get("username") and login_cfg.get("password"):
        cfg.set("auth.login", login_cfg)
        from voidrecon.core.login import perform_login

        cookies = await perform_login(cfg)
        if cookies:
            merged = dict(cfg.get("auth.cookies", {}) or {})
            merged.update(cookies)
            cfg.set("auth.cookies", merged)
            log.info("authenticated session active (%d cookies)", len(cookies))
        else:
            log.warning("login produced no session — continuing unauthenticated")

    phases = None
    if args.phases:
        phases = []
        for name in args.phases.split(","):
            name = name.strip().lower()
            if name in _PHASE_BY_NAME:
                phases.append(_PHASE_BY_NAME[name])
            else:
                log.warning("unknown phase '%s' ignored", name)
        # Always allow intel to run so results are scored, unless narrowing to 'only'.
        if Phase.INTEL not in phases:
            phases.append(Phase.INTEL)

    only = [m.strip() for m in args.only.split(",")] if args.only else None

    # Live progress display (checklist) unless disabled / non-interactive / quiet.
    from voidrecon.core.logging import console as _log_console

    live_on = (not args.quiet and not getattr(args, "no_live", False)
               and sys.stdout.isatty() and _log_console is not None)
    monitor = LiveMonitor(console=_log_console, enabled=live_on) if live_on else NullMonitor()
    if live_on:
        set_console_level("warning")  # keep INFO chatter in the logfile, not over the table

    pipeline = Pipeline(ctx, phases=phases, only=only,
                        monitor=monitor, checkpoint=checkpoint, completed=completed)
    try:
        with monitor:
            summary = await pipeline.run()
        reporter = Reporter(ctx, summary)
        written = reporter.write_all(cfg.get("reporting.formats", ["json", "markdown", "html"]))
        await notify.send(ctx, summary)
    finally:
        await ctx.aclose()
    if live_on:
        set_console_level(level)  # restore for the final summary lines

    if cfg.get("general.sqlite", True):
        db_path = Path(cfg.get("general.output_dir", "runs")) / "voidrecon.db"
        if db.persist_run(db_path, ctx, summary):
            log.info("persisted run to %s", db_path)

    counts = ctx.store.counts()
    log.info("[bold green]done[/] in %ss — %s", summary["elapsed"],
             ", ".join(f"{v} {k}" for k, v in counts.items() if v))
    for fmt, path in written.items():
        log.info("report (%s): %s", fmt, path)

    # Advisor — the built-in analyst read + "what to do next" plan.
    advice = getattr(ctx.store, "advice", []) or []
    summary_txt = getattr(ctx.store, "advice_summary", "")
    if summary_txt and not args.quiet:
        print(f"\n\033[1mAnalyst read:\033[0m {summary_txt}")
    if advice and not args.quiet:
        print("\n\033[1mRecommended next steps:\033[0m")
        for i, rec in enumerate(advice[:5], 1):
            print(f"  {i}. {rec['action']}")
            if rec.get("command"):
                print(f"     → {rec['command']}")
    print(f"\nResults written to: {ctx.output_dir}")
    return 0


def _cmd_modules(args) -> int:
    load_all_modules()
    mods = registry.all()
    if args.phase:
        want = args.phase.strip().lower()
        mods = [m for m in mods if PHASE_NAMES[m.phase] == want]
    mods.sort(key=lambda m: (int(m.phase), m.name))
    print(f"VoidRecon modules ({len(mods)}):\n")
    cur = None
    for m in mods:
        if m.phase != cur:
            cur = m.phase
            print(f"[{PHASE_NAMES[cur]}]")
        flag = "active" if m.active else "passive"
        default = "" if m.enabled_by_default else " (opt-in)"
        print(f"  {m.name:<16} {flag:<8} {m.description}{default}")
    return 0


def _cmd_diff(args) -> int:
    paths = args.paths or []
    # Resolve two run files: explicit paths, or the latest two runs for a target slug.
    if len(paths) >= 2:
        old_path, new_path = paths[0], paths[1]
    elif len(paths) == 1 and (Path(paths[0]).exists()):
        # single explicit path -> diff against the previous run in its parent dir
        runs = history.find_runs(Path(paths[0]).parent.parent if Path(paths[0]).is_file() else args.dir)
        if len(runs) < 2:
            print("need at least two runs to diff", file=sys.stderr)
            return 2
        old_path, new_path = runs[-2], runs[-1]
    else:
        target = paths[0] if paths else None
        runs = history.find_runs(args.dir, target)
        if len(runs) < 2:
            print(f"need at least two runs to diff (found {len(runs)} in {args.dir})", file=sys.stderr)
            return 2
        old_path, new_path = runs[-2], runs[-1]

    diff = history.diff_runs(history.load_run(old_path), history.load_run(new_path))

    if args.json:
        import json as _json

        print(_json.dumps(diff.__dict__, indent=2, default=str))
        return 0

    print(f"Diff  {diff.old_label}  ->  {diff.new_label}\n")
    if diff.is_empty():
        print("  No changes.")
        return 0
    if diff.new_assets:
        print(f"  + {len(diff.new_assets)} new asset(s):")
        for a in diff.new_assets[:40]:
            print(f"      [{a.get('score',0):>3}] {a.get('kind')}: {a.get('value')}")
    if diff.removed_assets:
        print(f"  - {len(diff.removed_assets)} removed asset(s):")
        for a in diff.removed_assets[:40]:
            print(f"      {a.get('kind')}: {a.get('value')}")
    if diff.new_findings:
        print(f"  + {len(diff.new_findings)} new finding(s):")
        for f in diff.new_findings[:40]:
            print(f"      [{f.get('severity','info').upper()}] {f.get('title')}")
    if diff.resolved_findings:
        print(f"  - {len(diff.resolved_findings)} resolved finding(s)")
    if diff.score_jumps:
        print(f"  ~ {len(diff.score_jumps)} score change(s):")
        for s in diff.score_jumps[:40]:
            print(f"      {s['asset']}: {s['from']} -> {s['to']} ({s['delta']:+})")
    return 0


def _cmd_dashboard(args) -> int:
    from voidrecon.reporting.dashboard import build_dashboard

    runs = history.find_runs(args.dir, args.target)
    if not runs:
        print(f"no runs found in {args.dir}" + (f" for '{args.target}'" if args.target else ""), file=sys.stderr)
        return 2
    out = Path(args.output) if args.output else Path(args.dir) / "dashboard.html"
    out.write_text(build_dashboard(runs, args.target), encoding="utf-8")
    print(f"dashboard written to: {out} ({len(runs)} runs)")
    return 0


def _cmd_update_cve(args) -> int:
    import asyncio
    import json

    import httpx

    from voidrecon.core.paths import user_cve_dataset

    async def fetch() -> dict | None:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            try:
                resp = await client.get(args.url)
            except Exception as exc:  # noqa: BLE001
                print(f"error: could not fetch {args.url}: {exc}", file=sys.stderr)
                return None
        if resp.status_code >= 400:
            print(f"error: {args.url} returned {resp.status_code}", file=sys.stderr)
            return None
        try:
            return resp.json()
        except Exception as exc:  # noqa: BLE001
            print(f"error: response is not valid JSON: {exc}", file=sys.stderr)
            return None

    data = asyncio.run(fetch())
    if data is None:
        return 1
    sigs = data.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        print("error: dataset must be a JSON object with a non-empty 'signatures' array", file=sys.stderr)
        return 2
    dest = user_cve_dataset()
    dest.write_text(json.dumps({"signatures": sigs}, indent=2), encoding="utf-8")
    total_cves = sum(len(s.get("cves", [])) for s in sigs)
    print(f"saved {len(sigs)} signature group(s) / {total_cves} CVEs to {dest}")
    print("cve_match will merge these on the next run.")
    return 0


def _run_namespace(**over):
    """A fully-defaulted argparse-style namespace for programmatic runs (workers)."""
    import argparse

    defaults = dict(
        targets=[], url=None, import_scope=False, include=[], exclude=[], scope_file=None,
        active=False, aggressive=False, yes=True, phases=None, only=None, config=None,
        output_dir=None, rps=None, concurrency=None, timeout=None, no_verify_tls=False,
        header=[], cookie=[], bearer=None, login_url=None, login_user=None, login_pass=None,
        formats=None, notify_webhook=None, llm=False, llm_provider=None, llm_model=None,
        disable=[], resume=None, no_live=True, verbose=False, quiet=False, no_banner=True,
        profile=None, ai=False, no_update_check=True,
    )
    defaults.update(over)
    return argparse.Namespace(**defaults)


def _queue_db(args) -> str:
    cfg = Config.load(args.config if hasattr(args, "config") else None)
    return args.db or str(Path(cfg.get("general.output_dir", "runs")) / "queue.db")


def _cmd_queue(args) -> int:
    from voidrecon.core.queue import JobQueue

    q = JobQueue(_queue_db(args))
    if args.action == "add":
        if not args.targets:
            print("error: 'queue add' needs at least one target", file=sys.stderr)
            return 2
        n = q.add_many(args.targets, {"active": args.active, "aggressive": args.aggressive})
        print(f"queued {n} job(s). Start workers with: voidrecon worker")
        return 0
    if args.action == "list":
        jobs = q.list()
        if not jobs:
            print("queue is empty")
            return 0
        for j in jobs:
            print(f"  [{j['id']:>3}] {j['status']:<8} {j['target']}"
                  + (f"  ({j['error']})" if j.get("error") else ""))
        print(f"\nstats: {q.stats()}")
        return 0
    if args.action == "clear":
        print(f"cleared {q.clear()} job(s)")
        return 0
    return 1


async def _cmd_worker(args) -> int:
    import asyncio

    from voidrecon.core.queue import JobQueue

    q = JobQueue(_queue_db(args))
    worker_id = args.worker_id
    processed = 0
    idle_budget = args.poll
    print(f"worker started (db={q.db_path}); draining queue…")
    while True:
        job = q.claim(worker_id)
        if job is None:
            if args.once or idle_budget <= 0:
                break
            await asyncio.sleep(min(5, idle_budget))
            idle_budget -= 5
            continue
        idle_budget = args.poll
        print(f"\n=== job {job['id']}: {job['target']} ===")
        opts = job.get("options", {})
        run_args = _run_namespace(targets=[job["target"]],
                                  active=bool(opts.get("active") or opts.get("aggressive")),
                                  aggressive=bool(opts.get("aggressive")))
        try:
            rc = await _run(run_args)
            q.complete(job["id"], "done" if rc == 0 else "failed",
                       None if rc == 0 else f"exit {rc}")
            processed += 1
        except Exception as exc:  # noqa: BLE001
            q.complete(job["id"], "failed", str(exc))
            print(f"job {job['id']} failed: {exc}", file=sys.stderr)
        if args.once:
            break
    print(f"\nworker done — processed {processed} job(s). stats: {q.stats()}")
    return 0


def _cmd_setup(args) -> int:
    """Interactively collect API keys + notifications into the user config file."""
    try:
        import yaml
    except Exception:
        print("error: PyYAML is required for setup", file=sys.stderr)
        return 1
    from voidrecon.core.paths import user_data_dir

    print(_BANNER)
    print("VoidRecon setup — configure optional API keys & notifications.")
    print("Everything is optional; press Enter to skip. Values are saved to your user config.\n")

    def ask(label, secret=False):
        try:
            val = input(f"  {label}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return ""
        return val

    print("── OSINT / enrichment API keys ──")
    sources = {
        "github_token": ask("GitHub token (code dorking)"),
        "shodan_api_key": ask("Shodan API key (favicon pivot, host enrichment)"),
        "censys_api_id": ask("Censys API ID"),
        "censys_api_secret": ask("Censys API secret"),
        "securitytrails_api_key": ask("SecurityTrails API key"),
        "virustotal_api_key": ask("VirusTotal API key"),
    }
    print("\n── Notifications ──")
    notify = {
        "webhook": ask("Slack/Discord webhook URL"),
        "telegram_token": ask("Telegram bot token"),
        "telegram_chat_id": ask("Telegram chat id"),
    }
    print("\n── AI / LLM (optional; the heuristic Advisor always runs without this) ──")
    provider = ask("LLM provider [openai|anthropic|ollama|none]") or "none"
    intel = {}
    if provider not in ("", "none"):
        intel = {"llm_enabled": True, "llm_provider": provider,
                 "llm_model": ask("LLM model (e.g. gpt-4o-mini, llama3.1)")}
    print("\n── Out-of-band (blind SSRF) ──")
    oob_domain = ask("OOB domain (e.g. your interactsh domain)")

    cfg = {"sources": {k: v for k, v in sources.items() if v},
           "notify": {k: v for k, v in notify.items() if v}}
    if intel:
        cfg["intel"] = intel
    if oob_domain:
        cfg["oob"] = {"domain": oob_domain}
    cfg = {k: v for k, v in cfg.items() if v}

    dest = user_data_dir() / "config.yaml"
    existing = {}
    if dest.exists():
        try:
            existing = yaml.safe_load(dest.read_text()) or {}
        except Exception:
            existing = {}
    merged = {**existing, **cfg}
    for section, vals in cfg.items():
        if isinstance(vals, dict) and isinstance(existing.get(section), dict):
            merged[section] = {**existing[section], **vals}
    dest.write_text(yaml.safe_dump(merged, default_flow_style=False, sort_keys=False), encoding="utf-8")
    print(f"\nSaved to {dest}")
    print("HackerOne scope import uses env vars: VOIDRECON_SOURCES_HACKERONE_USERNAME / _TOKEN")
    print("These settings now apply automatically to every run.")
    return 0


def _cmd_update(args) -> int:
    import subprocess
    from pathlib import Path as _P

    from voidrecon.core import version_check

    latest = version_check.fetch_latest(timeout=6.0)
    if latest is None:
        print("could not determine the latest version (offline?).", file=sys.stderr)
    else:
        from voidrecon.utils.versions import is_newer
        if not is_newer(latest, __version__):
            print(f"VoidRecon is up to date (running {__version__}).")
            return 0
        print(f"Update available: {latest} (running {__version__}).")
    if getattr(args, "check", False):
        return 0

    from voidrecon.core.version_check import update_branch

    branch = update_branch()
    # Prefer 'git pull' inside a checkout, else pip upgrade from GitHub.
    repo_root = _P(__file__).resolve().parents[1]
    if (repo_root / ".git").exists():
        print(f"updating via git in {repo_root} (branch {branch}) …")
        return subprocess.call(["git", "-C", str(repo_root), "pull", "--ff-only"])
    print(f"updating via pip from GitHub (branch {branch}) …")
    return subprocess.call([sys.executable, "-m", "pip", "install", "--upgrade",
                            f"git+https://github.com/CypherNova1337/VoidRecon.git@{branch}"])


def _cmd_wizard(args) -> int:
    print(_BANNER)
    print("VoidRecon guided setup — press Enter to accept the [default].\n")
    try:
        target = input("  Target domain(s), space-separated: ").strip()
        if not target:
            print("no target given.", file=sys.stderr)
            return 2
        print("\n  Intensity:")
        print("    1) passive   (quiet OSINT only — always safe)")
        print("    2) quick     (active, fast, essentials)")
        print("    3) standard  (active, default depth)  [default]")
        print("    4) deep      (active, every module)")
        print("    5) stealth   (active, very slow & quiet)")
        choice = input("  Choose 1-5 [3]: ").strip() or "3"
        profile = {"1": "passive", "2": "quick", "3": "standard",
                   "4": "deep", "5": "stealth"}.get(choice, "standard")
        ai = input("  Enable AI/LLM analysis? (needs a key) [y/N]: ").strip().lower() in ("y", "yes")
        scope_extra = input("  Extra in-scope entries (optional, space-separated): ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\ncancelled", file=sys.stderr)
        return 130

    active = profile != "passive"
    print(f"\n→ voidrecon run {target} --profile {profile}" + (" --ai" if ai else ""))
    run_args = _run_namespace(
        targets=target.split(),
        include=scope_extra.split() if scope_extra else [],
        profile=profile, active=active, ai=ai,
        no_live=False, no_banner=True, yes=True,
    )
    return asyncio.run(_run(run_args))


def _cmd_serve(args) -> int:
    from voidrecon.reporting.webserver import serve

    cfg = Config.load()
    db_path = args.db or str(Path(cfg.get("general.output_dir", "runs")) / "voidrecon.db")
    try:
        serve(db_path, host=args.host, port=args.port)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def _cmd_scope(args) -> int:
    scope = _build_scope(args, wildcard_apex=True)
    print("Seeds:      ", ", ".join(scope.seeds) or "—")
    print("Include:    ", ", ".join(r.raw for r in scope.include) or "—")
    print("Exclude:    ", ", ".join(r.raw for r in scope.exclude) or "—")
    if args.check:
        state = scope.classify(args.check)
        active = scope.allows_active(args.check)
        print(f"\n{args.check}: {state.value} (active-allowed: {active})")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "run":
        try:
            return asyncio.run(_run(args))
        except KeyboardInterrupt:
            print("\ninterrupted", file=sys.stderr)
            return 130
    if args.command == "wizard":
        return _cmd_wizard(args)
    if args.command == "setup":
        return _cmd_setup(args)
    if args.command == "update":
        return _cmd_update(args)
    if args.command == "modules":
        return _cmd_modules(args)
    if args.command == "diff":
        return _cmd_diff(args)
    if args.command == "dashboard":
        return _cmd_dashboard(args)
    if args.command == "update-cve":
        return _cmd_update_cve(args)
    if args.command == "serve":
        return _cmd_serve(args)
    if args.command == "queue":
        return _cmd_queue(args)
    if args.command == "worker":
        try:
            return asyncio.run(_cmd_worker(args))
        except KeyboardInterrupt:
            print("\nworker interrupted", file=sys.stderr)
            return 130
    if args.command == "scope":
        return _cmd_scope(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
