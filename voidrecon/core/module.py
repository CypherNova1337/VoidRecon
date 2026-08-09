"""Module base class and registry.

A *module* is one unit of recon capability (crt.sh lookup, ASN mapping, JS
secret mining…). Modules declare which :class:`Phase` they belong to, whether
they are ``passive`` or ``active``, and which other modules they depend on. The
registry provides discovery and dependency-aware ordering; the pipeline runs them.

Writing a module is deliberately tiny::

    @register
    class MyModule(Module):
        name = "my_module"
        phase = Phase.PASSIVE
        active = False

        async def run(self, ctx: RunContext) -> None:
            ctx.add_asset(AssetKind.SUBDOMAIN, "found.example.com", source=self.name)
"""

from __future__ import annotations

from enum import IntEnum
from typing import Iterable, Type

from voidrecon.core.context import RunContext
from voidrecon.core.logging import get_logger


class Phase(IntEnum):
    """Ordered recon phases. Lower runs earlier."""

    SCOPE = 0        # scope expansion: org, ASN, related domains
    PASSIVE = 1      # quiet OSINT: certs, passive dns, archives, dorks
    RESOLVE = 2      # turn names into IPs/hosts (light, cache-friendly)
    ACTIVE = 3       # probing: http, ports, services (gated on allow_active)
    CONTENT = 4      # crawling, JS analysis, param/dir discovery
    VULN = 5         # correlation: CVEs, takeovers, misconfigs
    INTEL = 6        # scoring, correlation, LLM analysis
    REPORT = 7       # output


PHASE_NAMES = {
    Phase.SCOPE: "scope",
    Phase.PASSIVE: "passive",
    Phase.RESOLVE: "resolve",
    Phase.ACTIVE: "active",
    Phase.CONTENT: "content",
    Phase.VULN: "vuln",
    Phase.INTEL: "intel",
    Phase.REPORT: "report",
}


class Module:
    """Base class for all recon modules."""

    name: str = "module"
    phase: Phase = Phase.PASSIVE
    active: bool = False           # does it interact with the target directly?
    description: str = ""
    depends_on: tuple[str, ...] = ()
    enabled_by_default: bool = True

    def __init__(self) -> None:
        self.log = get_logger(self.name)

    async def run(self, ctx: RunContext) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def should_run(self, ctx: RunContext) -> bool:
        """Skip active modules unless active mode is on. Modules may override to
        add their own preconditions (e.g. an API key present)."""
        disabled = set(ctx.config.get("modules.disabled", []) or [])
        if self.name in disabled:
            return False
        if self.active and not ctx.active_allowed:
            return False
        return True

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Module {self.name} phase={PHASE_NAMES[self.phase]} active={self.active}>"


class ModuleRegistry:
    def __init__(self) -> None:
        self._modules: dict[str, Type[Module]] = {}

    def register(self, cls: Type[Module]) -> Type[Module]:
        if not getattr(cls, "name", None) or cls.name == "module":
            raise ValueError(f"Module {cls!r} must define a unique 'name'.")
        if cls.name in self._modules:
            raise ValueError(f"Duplicate module name: {cls.name}")
        self._modules[cls.name] = cls
        return cls

    def all(self) -> list[Type[Module]]:
        return list(self._modules.values())

    def get(self, name: str) -> Type[Module] | None:
        return self._modules.get(name)

    def select(
        self,
        *,
        phases: Iterable[Phase] | None = None,
        only: Iterable[str] | None = None,
        include_active: bool = True,
    ) -> list[Module]:
        """Instantiate and topologically order modules for a run."""
        wanted = set(only) if only else None
        phaseset = set(phases) if phases else None
        chosen: list[Type[Module]] = []
        for cls in self._modules.values():
            if wanted is not None and cls.name not in wanted:
                continue
            if phaseset is not None and cls.phase not in phaseset:
                continue
            if not include_active and cls.active:
                continue
            chosen.append(cls)
        ordered = self._topo_sort(chosen)
        return [cls() for cls in ordered]

    def _topo_sort(self, classes: list[Type[Module]]) -> list[Type[Module]]:
        by_name = {c.name: c for c in classes}
        visited: dict[str, int] = {}
        result: list[Type[Module]] = []

        def visit(cls: Type[Module]) -> None:
            state = visited.get(cls.name, 0)
            if state == 1:
                return  # in-progress cycle; break it gracefully
            if state == 2:
                return
            visited[cls.name] = 1
            for dep in cls.depends_on:
                if dep in by_name:
                    visit(by_name[dep])
            visited[cls.name] = 2
            result.append(cls)

        # Primary sort key is phase; dependencies refine within/around it.
        for cls in sorted(classes, key=lambda c: (int(c.phase), c.name)):
            visit(cls)
        # Stable re-sort by phase so dependency order never crosses phase order.
        result.sort(key=lambda c: int(c.phase))
        return result


# Global registry + decorator used by module files.
registry = ModuleRegistry()


def register(cls: Type[Module]) -> Type[Module]:
    return registry.register(cls)
