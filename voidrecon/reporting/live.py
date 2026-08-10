"""Live terminal progress — a real-time checklist of what the run is doing.

Renders an updating table of every planned module grouped by phase, each with a
status glyph (pending / running / done / error / skipped), its elapsed time, and
how many assets it added — plus a header line of live totals (assets, findings by
severity, elapsed). Falls back to a no-op when Rich isn't available or output
isn't a TTY, so nothing breaks in pipes or CI.
"""

from __future__ import annotations

import time

try:
    from rich.console import Group
    from rich.live import Live
    from rich.table import Table
    from rich.text import Text

    _HAS_RICH = True
except Exception:  # pragma: no cover
    _HAS_RICH = False

_GLYPH = {
    "pending": ("○", "grey50"),
    "running": ("▶", "yellow"),
    "done": ("✔", "green"),
    "error": ("✖", "red"),
    "skipped": ("–", "grey50"),
}


class LiveMonitor:
    """Drives a Rich Live table. Safe to use even when Rich/TTY are unavailable."""

    def __init__(self, console=None, enabled: bool = True):
        self.enabled = enabled and _HAS_RICH
        self.console = console
        self._rows: list[dict] = []
        self._index: dict[str, dict] = {}
        self._live = None
        self._started = time.time()
        self._totals: dict = {}
        self._phase_label = ""

    # ---- lifecycle --------------------------------------------------------
    def __rich__(self):
        # Recomputed on every auto-refresh tick, so running timers keep moving
        # even while a long module (e.g. dns_brute) produces no events.
        return self._render()

    def __enter__(self):
        if self.enabled:
            # Pass self (not a static renderable) + auto-refresh so elapsed updates live.
            self._live = Live(self, console=self.console, refresh_per_second=4,
                              transient=False, auto_refresh=True)
            self._live.start()
        return self

    def __exit__(self, *exc):
        if self._live is not None:
            self._refresh()
            self._live.stop()
        return False

    # ---- updates ----------------------------------------------------------
    def set_plan(self, modules) -> None:
        self._rows = []
        self._index = {}
        for m in modules:
            row = {"name": m.name, "phase": m.phase_name, "active": m.active,
                   "status": "pending", "elapsed": 0.0, "assets": 0}
            self._rows.append(row)
            self._index[m.name] = row
        self._refresh()

    def start_module(self, name: str) -> None:
        row = self._index.get(name)
        if row:
            row["status"] = "running"
            row["_t0"] = time.time()
        self._refresh()

    def end_module(self, name: str, status: str, elapsed: float, assets: int) -> None:
        row = self._index.get(name)
        if row:
            row["status"] = status
            row["elapsed"] = elapsed
            row["assets"] = assets
        self._refresh()

    def set_totals(self, counts: dict) -> None:
        self._totals = dict(counts)
        self._refresh()

    def set_phase(self, label: str) -> None:
        self._phase_label = label
        self._refresh()

    # ---- rendering --------------------------------------------------------
    def _refresh(self) -> None:
        # State lives on self; auto-refresh re-renders via __rich__. Nudge for immediacy.
        if self._live is not None:
            try:
                self._live.refresh()
            except Exception:
                pass

    def _header(self):
        elapsed = time.time() - self._started
        t = self._totals
        parts = ["[bold cyan]VoidRecon[/] live", f"elapsed {elapsed:5.1f}s"]
        surface = " ".join(
            f"{t.get(k, 0)} {k}" for k in ("subdomain", "ip", "service", "url", "endpoint") if t.get(k)
        )
        if surface:
            parts.append(surface)
        if t.get("findings"):
            parts.append(f"[bold]{t['findings']} findings[/]")
        return Text.from_markup(" · ".join(parts))

    def _render(self):
        table = Table(expand=False, pad_edge=False, box=None, show_header=True, header_style="dim")
        table.add_column("", width=2)
        table.add_column("phase", style="cyan", no_wrap=True)
        table.add_column("module", no_wrap=True)
        table.add_column("time", justify="right", width=7)
        table.add_column("+assets", justify="right", width=8)
        last_phase = None
        for row in self._rows:
            glyph, color = _GLYPH.get(row["status"], ("○", "grey50"))
            phase = row["phase"] if row["phase"] != last_phase else ""
            last_phase = row["phase"]
            elapsed = f"{row['elapsed']:.1f}s" if row["status"] in ("done", "error") else (
                f"{time.time() - row['_t0']:.1f}s" if row.get("_t0") and row["status"] == "running" else "")
            assets = str(row["assets"]) if row["status"] in ("done", "error") and row["assets"] else ""
            name = f"[{color}]{row['name']}[/]" if row["status"] == "running" else row["name"]
            table.add_row(f"[{color}]{glyph}[/]", phase, name, elapsed, assets)
        return Group(self._header(), Text(""), table)


class NullMonitor:
    """No-op monitor used when live display is disabled."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def set_plan(self, modules): ...
    def start_module(self, name): ...
    def end_module(self, name, status, elapsed, assets): ...
    def set_totals(self, counts): ...
    def set_phase(self, label): ...
