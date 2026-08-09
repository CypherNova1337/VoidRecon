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

from voidrecon.core.config import Config
from voidrecon.core.context import RunContext
from voidrecon.core.logging import setup_logging
from voidrecon.core.module import PHASE_NAMES, Phase, registry
from voidrecon.core.pipeline import Pipeline, load_all_modules
from voidrecon.core.scope import Scope
from voidrecon.reporting.report import Reporter
from voidrecon.version import __codename__, __version__

_PHASE_BY_NAME = {v: k for k, v in PHASE_NAMES.items()}

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
    run.add_argument("-i", "--include", action="append", default=[], help="Add an in-scope entry (repeatable)")
    run.add_argument("-x", "--exclude", action="append", default=[], help="Add an out-of-scope entry (repeatable)")
    run.add_argument("-S", "--scope-file", help="File with scope entries (txt lines or JSON/YAML include/exclude)")
    run.add_argument("--active", action="store_true", help="Enable active modules (probing/scanning). Off by default.")
    run.add_argument("--phases", help="Comma list of phases to run: " + ", ".join(PHASE_NAMES.values()))
    run.add_argument("--only", help="Comma list of specific module names to run")
    run.add_argument("-c", "--config", help="Path to a config YAML file")
    run.add_argument("-o", "--output-dir", help="Base directory for run output (default: runs/)")
    run.add_argument("--rps", type=float, help="Requests per second (throttle)")
    run.add_argument("--concurrency", type=int, help="Max concurrent operations")
    run.add_argument("--timeout", type=float, help="Per-request timeout in seconds")
    run.add_argument("--no-verify-tls", action="store_true", help="Disable TLS verification (use with care)")
    run.add_argument("--formats", help="Report formats (comma): json,markdown,html")
    run.add_argument("--llm", action="store_true", help="Enable LLM analysis (requires provider config + key)")
    run.add_argument("--llm-provider", help="openai | anthropic | ollama | openai_compatible")
    run.add_argument("--llm-model", help="Model name for the selected provider")
    run.add_argument("--disable", action="append", default=[], help="Disable a module by name (repeatable)")
    run.add_argument("-v", "--verbose", action="store_true", help="Verbose (debug) logging")
    run.add_argument("-q", "--quiet", action="store_true", help="Only warnings and errors")
    run.add_argument("--no-banner", action="store_true", help="Suppress the banner")

    # modules -------------------------------------------------------------
    mods = sub.add_parser("modules", help="List available modules")
    mods.add_argument("--phase", help="Filter by phase")

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
    if getattr(args, "llm", False):
        ov["intel"]["llm_enabled"] = True
    if getattr(args, "llm_provider", None):
        ov["intel"]["llm_provider"] = args.llm_provider
    if getattr(args, "llm_model", None):
        ov["intel"]["llm_model"] = args.llm_model
    if getattr(args, "disable", None):
        ov["modules"]["disabled"] = list(args.disable)
    if getattr(args, "formats", None):
        ov["reporting"] = {"formats": [f.strip() for f in args.formats.split(",")]}
    return ov


async def _run(args) -> int:
    from voidrecon.core.logging import get_logger

    cfg = Config.load(args.config, overrides=_config_overrides(args))
    scope = _build_scope(args, bool(cfg.get("general.wildcard_apex", True)))
    if not scope.include:
        print("error: no targets/scope provided. Give a domain or use --include/--scope-file.", file=sys.stderr)
        return 2

    level = "debug" if args.verbose else ("warning" if args.quiet else cfg.get("general.log_level", "info"))
    ctx = RunContext(cfg, scope)
    ctx.output_dir.mkdir(parents=True, exist_ok=True)
    setup_logging(level, logfile=ctx.output_dir / "voidrecon.log")
    log = get_logger()

    if not args.no_banner and not args.quiet:
        print(_BANNER)
    log.info("run id: [bold]%s[/]", ctx.run_id)
    log.info("seeds: %s", ", ".join(scope.seeds) or "—")
    log.info("active mode: %s", "[bold red]ON[/]" if ctx.active_allowed else "off (passive only)")
    tools = ctx.tools.available()
    if tools:
        log.info("external tools available: %s", ", ".join(sorted(tools)))

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

    pipeline = Pipeline(ctx, phases=phases, only=only)
    try:
        summary = await pipeline.run()
    finally:
        await ctx.aclose()

    reporter = Reporter(ctx, summary)
    written = reporter.write_all(cfg.get("reporting.formats", ["json", "markdown", "html"]))

    counts = ctx.store.counts()
    log.info("[bold green]done[/] in %ss — %s", summary["elapsed"],
             ", ".join(f"{v} {k}" for k, v in counts.items() if v))
    for fmt, path in written.items():
        log.info("report (%s): %s", fmt, path)
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
    if args.command == "modules":
        return _cmd_modules(args)
    if args.command == "scope":
        return _cmd_scope(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
