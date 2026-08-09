"""Lightweight port discovery.

Identifies which of a curated set of high-value TCP ports are open on in-scope
IPs. This is a courteous, native connect-scan (a TCP handshake, immediately
closed) capped to a small port list and rate-limited — enough to surface exposed
databases, admin services, and dev servers without behaving like a mass scanner.
When ``naabu`` or ``nmap`` is installed it is used instead for speed and accuracy.

Active and scope-gated: only IPs that are positively in scope are ever contacted,
and only when ``opsec.allow_active`` is set.
"""

from __future__ import annotations

import asyncio

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence, Severity
from voidrecon.core.module import Module, Phase, register
from voidrecon.core.tools import run_tool

# High-signal default ports. Override via modules.port_scan.ports in config.
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 2375, 3306, 3389, 5432, 5601, 5900, 6379, 8000, 8008,
    8080, 8443, 8888, 9000, 9200, 9300, 11211, 27017,
]

# Ports whose exposure is inherently noteworthy.
_SENSITIVE = {
    23: "Telnet", 445: "SMB", 1433: "MSSQL", 2375: "Docker API", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB", 5601: "Kibana",
}


@register
class PortScan(Module):
    name = "port_scan"
    phase = Phase.ACTIVE
    active = True
    description = "Discover open high-value ports on in-scope IPs"
    depends_on = ("dns_resolve",)
    enabled_by_default = False  # opt-in even within active mode

    async def run(self, ctx: RunContext) -> None:
        ips = [a for a in ctx.store.assets(kind=AssetKind.IP) if ctx.can_touch(a.value)]
        if not ips:
            self.log.info("no in-scope IPs to scan")
            return

        ports = ctx.config.get("modules.port_scan.ports", TOP_PORTS) or TOP_PORTS

        if ctx.tools.first_available("naabu", "nmap"):
            await self._scan_with_tool(ctx, ips, ports)
            return

        sem = asyncio.Semaphore(min(int(ctx.config.get("opsec.max_concurrency", 20)), 50))

        async def scan_ip(asset):
            open_ports = []
            for port in ports:
                async with sem:
                    await ctx.http._limiter.acquire()  # reuse the run's throttle
                    if await self._is_open(asset.value, port):
                        open_ports.append(port)
            if open_ports:
                self._record(ctx, asset, open_ports)

        await asyncio.gather(*(scan_ip(a) for a in ips))
        self.log.info("port scan complete over %d IPs", len(ips))

    async def _is_open(self, ip: str, port: int, timeout: float = 2.0) -> bool:
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except (asyncio.TimeoutError, OSError):
            return False

    def _record(self, ctx: RunContext, asset, open_ports: list[int]) -> None:
        asset.attrs["open_ports"] = sorted(set((asset.attrs.get("open_ports") or []) + open_ports))
        asset.tags.add("scanned")
        for port in open_ports:
            ctx.add_asset(
                AssetKind.SERVICE, f"{asset.value}:{port}", source=self.name,
                confidence=Confidence.CONFIRMED, ip=asset.value, port=port,
            )
            if port in _SENSITIVE:
                ctx.add_finding(
                    f"Exposed {_SENSITIVE[port]} on {asset.value}:{port}",
                    module=self.name, severity=Severity.HIGH, asset=asset.value,
                    description=(
                        f"{_SENSITIVE[port]} is reachable. Databases and admin services "
                        "should not be internet-exposed; verify authentication and access controls."
                    ),
                    evidence={"ip": asset.value, "port": port, "service": _SENSITIVE[port]},
                    tags={"exposure"},
                )

    async def _scan_with_tool(self, ctx: RunContext, ips, ports) -> None:
        ip_list = "\n".join(a.value for a in ips)
        by_ip = {a.value: a for a in ips}
        if ctx.tools.has("naabu"):
            port_arg = ",".join(str(p) for p in ports)
            result = await run_tool(
                "naabu", ["-silent", "-p", port_arg, "-json"], stdin=ip_list, timeout=600
            )
            import json

            for line in result.lines():
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                asset = by_ip.get(row.get("ip") or row.get("host"))
                if asset and row.get("port"):
                    self._record(ctx, asset, [int(row["port"])])
            self.log.info("naabu scan complete over %d IPs", len(ips))
