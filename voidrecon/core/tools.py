"""Detection and safe invocation of external CLI tools.

VoidRecon is hybrid: it has native logic for everything essential, but when a
best-in-class tool is installed it will happily orchestrate it. Modules ask the
registry whether a tool is available and, if so, run it through :func:`run_tool`,
which handles argument lists, timeouts, and line-oriented output — never a shell
string, so there is no shell-injection surface.
"""

from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass

from voidrecon.core.logging import get_logger

log = get_logger("tools")

# Tools VoidRecon knows how to take advantage of, with a one-line role.
KNOWN_TOOLS: dict[str, str] = {
    "subfinder": "passive subdomain enumeration",
    "amass": "subdomain enumeration + graph",
    "assetfinder": "passive subdomain enumeration",
    "findomain": "passive subdomain enumeration",
    "httpx": "http probing / fingerprinting",
    "dnsx": "fast dns resolution",
    "naabu": "fast port scanning",
    "masscan": "internet-scale port scanning",
    "nmap": "service/version detection",
    "nuclei": "template-based scanning",
    "katana": "crawling",
    "gau": "url harvesting from archives",
    "waybackurls": "url harvesting from archives",
    "gospider": "crawling",
    "whois": "registration lookup",
    "gowitness": "screenshotting",
    # VoidSec-Hub tooling — used automatically when installed.
    "dns-helix": "fast DNS permutation scanner + resolver",
    "paramvoid": "HTTP parameter discovery",
    "sourcemapper": "javascript source-map extraction",
}


@dataclass
class ToolResult:
    tool: str
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def lines(self) -> list[str]:
        return [ln.strip() for ln in self.stdout.splitlines() if ln.strip()]


class ToolRegistry:
    """Discovers which external tools are on PATH once, then answers cheaply."""

    def __init__(self) -> None:
        self._available: dict[str, str] = {}
        self._scanned = False

    def scan(self) -> dict[str, str]:
        self._available = {}
        for name in KNOWN_TOOLS:
            path = shutil.which(name)
            if path:
                self._available[name] = path
        self._scanned = True
        return self._available

    def available(self) -> dict[str, str]:
        if not self._scanned:
            self.scan()
        return dict(self._available)

    def has(self, name: str) -> bool:
        if not self._scanned:
            self.scan()
        return name in self._available

    def first_available(self, *names: str) -> str | None:
        for name in names:
            if self.has(name):
                return name
        return None


async def run_tool(
    tool: str,
    args: list[str],
    *,
    stdin: str | None = None,
    timeout: float = 300.0,
) -> ToolResult:
    """Run ``tool`` with an argument list (no shell). Returns captured output."""
    cmd = [tool, *args]
    log.debug("running tool: %s", " ".join(cmd))
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return ToolResult(tool, 127, "", f"{tool} not found")
    try:
        out, err = await asyncio.wait_for(
            proc.communicate(stdin.encode() if stdin is not None else None),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        return ToolResult(tool, -1, "", f"{tool} timed out after {timeout}s")
    return ToolResult(
        tool,
        proc.returncode if proc.returncode is not None else -1,
        out.decode(errors="replace"),
        err.decode(errors="replace"),
    )
